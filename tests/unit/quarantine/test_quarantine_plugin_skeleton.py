"""Quarantined-LLM plugin skeleton — PR-S3-4 Task 4 (spec §5.1, §5.3).

Covers three surfaces:

* The on-disk plugin manifest (``plugins/alfred_quarantined_llm/manifest.toml``)
  parses through :func:`alfred.plugins.manifest.parse_manifest` with the
  canonical PluginManifest v1 shape (``alfred.manifest_version=1``,
  ``subscriber_tier="system"``).
* The plugin module imports without side effects — specifically, the fd-3
  read happens in ``main()``, not at import-time (sec-007). A test/IDE/mypy
  pass that imports the module on a system without fd 3 open MUST NOT hang
  or sys.exit.
* The in-process ``handle_ingest`` / ``handle_extract`` skeleton round-trips
  a ContentHandle id through the in-process content cache and into
  :func:`plugins.alfred_quarantined_llm.provider_dispatch.dispatch_extraction`.

Why these tests live in ``tests/unit/quarantine/``: the quarantined-LLM
plugin is the load-bearing T3 boundary. Its skeleton's import-time hygiene
and dispatch round-trip are part of the same security surface as the
ExtractionResult shape tested next door.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from alfred.plugins.manifest import parse_manifest
from alfred.providers.base import ProviderCapability

# ---------------------------------------------------------------------------
# On-disk manifest — the canonical PluginManifest v1 shape.
# ---------------------------------------------------------------------------


def _manifest_path() -> Path:
    """Resolve the manifest path from the repo root (worktree-safe).

    The test file's location is stable relative to the worktree root:
    ``tests/unit/quarantine/test_*.py``. Resolving from ``__file__`` keeps
    the test runnable from any cwd without depending on a fixture for the
    repo root.
    """
    repo_root = Path(__file__).resolve().parents[3]
    return repo_root / "plugins" / "alfred_quarantined_llm" / "manifest.toml"


def test_quarantined_llm_manifest_file_exists() -> None:
    """The manifest.toml file MUST exist on disk so the supervisor can read
    it at handshake time (PR-S3-3a contract).
    """
    assert _manifest_path().is_file(), f"missing manifest at {_manifest_path()}"


def test_quarantined_llm_manifest_parses_through_canonical_parser() -> None:
    """The shipped manifest parses through :func:`parse_manifest` without
    bespoke pre-processing — same code path the supervisor uses.
    """
    raw = _manifest_path().read_text(encoding="utf-8")
    manifest = parse_manifest(raw)
    assert manifest.manifest_version == 1
    assert manifest.plugin_id == "alfred.quarantined-llm"
    assert manifest.subscriber_tier == "system"


def test_quarantined_llm_manifest_subscriber_tier_is_system() -> None:
    """``subscriber_tier="system"`` is load-bearing — the quarantined LLM is a
    privileged-host subscriber, NOT a user-plugin. A drift to ``user-plugin``
    here would silently downgrade the dispatch tier.
    """
    raw = _manifest_path().read_text(encoding="utf-8")
    manifest = parse_manifest(raw)
    assert manifest.subscriber_tier == "system"


def test_quarantined_llm_manifest_sandbox_profile_is_user_plugin() -> None:
    """``sandbox_profile="user-plugin"`` keeps the subprocess under the
    user-plugin sandbox even though the subscriber tier is ``system``. The
    two axes are independent (spec §4.3) — the subscriber tier governs
    capability-gate grants; the sandbox profile governs OS isolation.
    """
    raw = _manifest_path().read_text(encoding="utf-8")
    manifest = parse_manifest(raw)
    assert manifest.sandbox_profile == "user-plugin"


# ---------------------------------------------------------------------------
# Import-time hygiene — sec-007. fd-3 read happens in main() only.
# ---------------------------------------------------------------------------


def test_quarantine_plugin_module_imports_without_reading_fd3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sec-007: importing the plugin module MUST NOT call ``os.read(3, ...)``.

    The reviewer flagged this as High: if the fd-3 read lived at module
    scope, pytest collection, mypy, ruff, and any IDE Python language
    server would hang or exit-1 on a process without fd 3 open. The
    contract is: read-fd-3 lives in ``main()``, called only under
    ``if __name__ == "__main__":``.
    """
    calls: list[tuple[int, int]] = []

    real_read = __import__("os").read

    def _tracking_read(fd: int, n: int) -> bytes:
        calls.append((fd, n))
        if fd == 3:
            raise AssertionError("fd-3 read at import time violates sec-007")
        return real_read(fd, n)

    monkeypatch.setattr("os.read", _tracking_read)

    # Fresh import so the side-effect would fire if module-scope code
    # called ``os.read(3, ...)``.
    import plugins.alfred_quarantined_llm.quarantine_plugin as qp

    importlib.reload(qp)
    # No assertion on `calls` other than the AssertionError above firing if
    # fd 3 is ever read; the import succeeding without raising IS the test.


def test_quarantine_plugin_exposes_handle_ingest_and_handle_extract() -> None:
    """The plugin module's public surface is ``handle_ingest`` +
    ``handle_extract``. The orchestrator's MCP transport invokes these by
    name; renaming either is a wire-protocol break.
    """
    import plugins.alfred_quarantined_llm.quarantine_plugin as qp

    assert callable(qp.handle_ingest)
    assert callable(qp.handle_extract)


# ---------------------------------------------------------------------------
# handle_ingest / handle_extract round-trip — in-process content cache.
# ---------------------------------------------------------------------------


@pytest.fixture
def _clear_content_cache() -> None:
    """Reset the in-process content cache between tests.

    The Slice-3 skeleton uses an in-process dict; the production impl
    (PR-S3-5) swaps in Redis. Either way, tests must not bleed state.
    """
    import plugins.alfred_quarantined_llm.quarantine_plugin as qp

    qp._content_cache.clear()


@pytest.mark.asyncio
async def test_handle_ingest_stores_content_keyed_by_handle_id(
    _clear_content_cache: None,
) -> None:
    """``handle_ingest`` writes the supplied bytes/context under ``handle_id``.

    The skeleton caches in-process; the production impl reads from the
    plugin host's content store via Redis GETDEL. Both shapes are
    write-then-read under the same key.
    """
    import plugins.alfred_quarantined_llm.quarantine_plugin as qp

    await qp.handle_ingest("handle-abc", "hello world")
    assert qp._content_cache["handle-abc"] == b"hello world"


@pytest.mark.asyncio
async def test_handle_extract_delegates_to_dispatch_extraction(
    _clear_content_cache: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``handle_extract`` looks up the cached content, then delegates to
    :func:`plugins.alfred_quarantined_llm.provider_dispatch.dispatch_extraction`.

    The skeleton test pins only the delegation shape — the capability-
    branched dispatch logic itself is Task 5. We monkeypatch
    ``dispatch_extraction`` so this test stays scoped to the plugin
    entry-point's responsibility (cache lookup + delegation).
    """
    import plugins.alfred_quarantined_llm.provider_dispatch as pd
    import plugins.alfred_quarantined_llm.quarantine_plugin as qp

    await qp.handle_ingest("handle-xyz", '{"title": "hi"}')

    captured: dict[str, Any] = {}

    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"kind": "extracted", "data": {}, "extraction_mode": "native_constrained"}

    monkeypatch.setattr(pd, "dispatch_extraction", _fake_dispatch)

    fake_provider = AsyncMock()
    fake_provider.capabilities = lambda: frozenset(
        {ProviderCapability.NATIVE_CONSTRAINED_GENERATION}
    )

    result = await qp.handle_extract(
        handle_id="handle-xyz",
        schema_json='{"type":"object"}',
        schema_version=1,
        provider=fake_provider,
    )
    # The cached bytes flowed through to the dispatcher.
    assert captured["content"] == b'{"title": "hi"}'
    assert captured["schema_json"] == '{"type":"object"}'
    assert captured["schema_version"] == 1
    assert captured["provider"] is fake_provider
    assert result["extraction_mode"] == "native_constrained"


# ---------------------------------------------------------------------------
# fd-3 provider key read — sec-007 security boundary.
# ---------------------------------------------------------------------------


def _scripted_os_read(script: list[bytes]) -> Any:
    """Return an ``os.read``-compatible callable that returns each item in
    ``script`` on successive calls (regardless of fd / n).

    The framing helper reads fd 3 in a fixed sequence (4-byte header,
    length-N body, 1-byte trailing-emptiness probe). Tests script the
    exact byte sequence each branch should observe.
    """
    calls = iter(script)

    def _read(fd: int, n: int) -> bytes:
        # Signature mirrors os.read(fd, n) for monkeypatch parity; the
        # scripted form ignores both args and returns the next item.
        return next(calls)

    return _read


def test_fd3_read_returns_decoded_key_on_well_formed_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: 4-byte length header + N-byte UTF-8 key + empty trailer.

    The wire format pin (spec §5.3): big-endian 4-byte length, then the
    key bytes, then no trailing bytes. Decode returns the original key.
    """
    from plugins.alfred_quarantined_llm import quarantine_plugin as qp

    key = "sk-deepseek-abc123"
    header = len(key).to_bytes(4, "big")
    monkeypatch.setattr(
        "os.read",
        _scripted_os_read([header, key.encode(), b""]),
    )
    assert qp._read_provider_key_from_fd3() == key


def test_fd3_read_exits_when_header_is_short(monkeypatch: pytest.MonkeyPatch) -> None:
    """A short 4-byte header → ``sys.exit(1)`` before the MCP loop starts.

    Supervisor-side contract: the subprocess MUST fail loudly when the
    provider key isn't framed correctly, so the supervisor's
    child-died notification fires with a clear lifecycle state rather
    than a confused "started but never registered" gap.
    """
    from plugins.alfred_quarantined_llm import quarantine_plugin as qp

    monkeypatch.setattr("os.read", _scripted_os_read([b"\x00\x00"]))
    with pytest.raises(SystemExit) as exc_info:
        qp._read_provider_key_from_fd3()
    assert exc_info.value.code == 1


def test_fd3_read_exits_when_body_is_short(monkeypatch: pytest.MonkeyPatch) -> None:
    """The header lies about length → ``sys.exit(1)``.

    Defence against a supervisor-side framing bug or a partial-write
    race. The subprocess refuses to start the MCP loop without a
    complete key.
    """
    from plugins.alfred_quarantined_llm import quarantine_plugin as qp

    header = (10).to_bytes(4, "big")  # claim 10 bytes
    monkeypatch.setattr(
        "os.read",
        _scripted_os_read([header, b"short"]),  # actually 5 bytes
    )
    with pytest.raises(SystemExit) as exc_info:
        qp._read_provider_key_from_fd3()
    assert exc_info.value.code == 1


def test_fd3_read_exits_when_trailing_bytes_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """Trailing bytes after the framed key → ``sys.exit(1)``.

    Any garbage after the key signals a supervisor-side framing bug;
    we fail closed rather than try to recover and risk parsing a
    second message as the key.
    """
    from plugins.alfred_quarantined_llm import quarantine_plugin as qp

    key = "ok"
    header = len(key).to_bytes(4, "big")
    monkeypatch.setattr(
        "os.read",
        _scripted_os_read([header, key.encode(), b"garbage"]),
    )
    with pytest.raises(SystemExit) as exc_info:
        qp._read_provider_key_from_fd3()
    assert exc_info.value.code == 1


@pytest.mark.asyncio
async def test_handle_extract_passes_empty_bytes_when_handle_missing(
    _clear_content_cache: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown handle id → empty bytes flow to ``dispatch_extraction``.

    The skeleton MUST NOT raise on a missing handle_id — raising would
    crash the subprocess and bypass the audit row. Instead the missing
    handle yields empty bytes and lets the dispatcher's retry-exhaustion
    path produce a TypedRefusal that the audit-emit path can persist with
    result="refused" (Task 6 wires this in QuarantinedExtractor).
    """
    import plugins.alfred_quarantined_llm.provider_dispatch as pd
    import plugins.alfred_quarantined_llm.quarantine_plugin as qp

    captured: dict[str, Any] = {}

    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"kind": "typed_refusal", "reason": "cannot_extract"}

    monkeypatch.setattr(pd, "dispatch_extraction", _fake_dispatch)

    fake_provider = AsyncMock()
    fake_provider.capabilities = lambda: frozenset()

    result = await qp.handle_extract(
        handle_id="missing-handle",
        schema_json='{"type":"object"}',
        schema_version=1,
        provider=fake_provider,
    )
    assert captured["content"] == b""
    assert result["kind"] == "typed_refusal"
    assert result["reason"] == "cannot_extract"
