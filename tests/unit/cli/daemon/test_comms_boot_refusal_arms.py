"""Fail-closed refuse/audit arms of ``_comms_boot`` (#256 PR-3 100%-gate cover).

PR-3 extracted ``src/alfred/cli/daemon/_comms_boot.py`` from ``_commands.py``. The
per-file 100% line+branch gate #256 exists to enforce leaves these fail-closed arms
uncovered by the full-boot suite, because the full boot refuses EARLIER:

* the pure manifest parser :func:`_resolve_comms_adapter_wire_spec` raise arms
  (missing ``comms_mcp_module`` / missing-or-blank ``adapter_kind``) — the enabled
  ``alfred_comms_test`` manifest is well-formed, so the boot never trips them;
* the :func:`_build_comms_adapter_wiring` ``_refuse_boot`` arms — the daemon boot
  resolves the carrier kind (and, for the misconfigured-promoter case, builds the
  forwarded-inbound registry) BEFORE it reaches the per-adapter wiring, so both arms
  refuse upstream and these in-wiring copies never execute;
* the daemon-global control-plane peer-rejected auditor
  (:func:`_make_control_reject_auditor`) — a control-socket reject is an adversarial
  runtime event, not a boot-path event.

Each test drives the arm directly (hermetic — NO real subprocess / socket / Redis)
and asserts the ACTUAL fail-closed behaviour (the typed manifest error, the audited
``_BootRefusedError`` with the exact ``failure_reason``, the loud ``result="refused"``
control-reject row), never a coverage-only smoke.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from alfred.cli.daemon._boot_audit import _BootRefusedError
from alfred.cli.daemon._comms_boot import (
    _build_comms_adapter_wiring,
    _CommsAdapterManifestError,
    _CommsAdapterWireSpec,
    _make_control_reject_auditor,
    _resolve_comms_adapter_wire_spec,
    _UnknownAdapterKindError,
)

from .conftest import FakeAuditWriter


class _StubManifest:
    """Minimal stand-in for ``parse_manifest``'s result.

    ``_resolve_comms_adapter_wire_spec`` only reads ``comms_mcp_module`` before it
    raises on the two malformed-manifest arms under test (the ``plugin_id`` /
    ``sandbox.kind`` reads happen only on the success return, never reached here).
    """

    def __init__(self, *, comms_mcp_module: str | None) -> None:
        self.comms_mcp_module = comms_mcp_module


def _seed_manifest(tmp_path: Path, adapter_id: str, body: str) -> None:
    """Write a readable ``plugins/<adapter_id>/manifest.toml`` under ``tmp_path``.

    The parser resolves the path via ``repo_root()`` (patched to ``tmp_path``) and
    ``read_text``s it, then ``tomllib.loads`` the raw bytes — so the file must exist
    and, for the ``adapter_kind`` arm, carry real TOML.
    """
    plugin_dir = tmp_path / "plugins" / adapter_id
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "manifest.toml").write_text(body, encoding="utf-8")


# ── _resolve_comms_adapter_wire_spec raise arms (src 161, 167 + the 219-221 ctor) ──


def test_resolve_wire_spec_raises_when_comms_mcp_module_is_none(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A parsed manifest with ``comms_mcp_module is None`` raises naming that field.

    Covers src line 161 (the raise) + the ``_CommsAdapterManifestError`` ctor
    (219-221) — the ENABLED-adapter guard that refuses an adapter whose manifest
    declares no comms module (CLAUDE.md hard rule #7).
    """
    adapter_id = "alfred_comms_test"
    _seed_manifest(tmp_path, adapter_id, '[plugin]\nid = "alfred.comms-test"\n')
    monkeypatch.setattr("alfred.cli._launcher_spawn.repo_root", lambda: tmp_path)
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot.parse_manifest",
        lambda _raw: _StubManifest(comms_mcp_module=None),
    )

    with pytest.raises(_CommsAdapterManifestError) as excinfo:
        _resolve_comms_adapter_wire_spec(adapter_id)

    assert excinfo.value.adapter_id == adapter_id
    assert excinfo.value.field == "comms_mcp_module"
    # The ctor's message (line 219) names both the adapter and the missing field.
    assert adapter_id in str(excinfo.value)
    assert "comms_mcp_module" in str(excinfo.value)


def test_resolve_wire_spec_raises_when_adapter_kind_key_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A ``[comms_mcp]`` block present but missing ``adapter_kind`` raises (src 167).

    Drives the ternary's dict-present arm: ``comms_section`` is a dict, so
    ``.get("adapter_kind")`` returns ``None`` and the ``not isinstance(..., str)``
    guard fires.
    """
    adapter_id = "alfred_comms_test"
    _seed_manifest(
        tmp_path,
        adapter_id,
        '[plugin]\nid = "alfred.comms-test"\n[comms_mcp]\nmodule = "alfred_comms_test.main"\n',
    )
    monkeypatch.setattr("alfred.cli._launcher_spawn.repo_root", lambda: tmp_path)
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot.parse_manifest",
        lambda _raw: _StubManifest(comms_mcp_module="alfred_comms_test.main"),
    )

    with pytest.raises(_CommsAdapterManifestError) as excinfo:
        _resolve_comms_adapter_wire_spec(adapter_id)

    assert excinfo.value.adapter_id == adapter_id
    assert excinfo.value.field == "adapter_kind"


def test_resolve_wire_spec_raises_when_comms_mcp_section_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """No ``[comms_mcp]`` section at all still raises the adapter_kind arm (src 167).

    Drives the ternary's ``else`` arm: ``data.get("comms_mcp")`` is ``None`` (not a
    dict), so ``adapter_kind`` is ``None`` and the same fail-closed guard fires —
    proving the refusal is not conditional on the section merely existing.
    """
    adapter_id = "alfred_comms_test"
    _seed_manifest(tmp_path, adapter_id, '[plugin]\nid = "alfred.comms-test"\n')
    monkeypatch.setattr("alfred.cli._launcher_spawn.repo_root", lambda: tmp_path)
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot.parse_manifest",
        lambda _raw: _StubManifest(comms_mcp_module="alfred_comms_test.main"),
    )

    with pytest.raises(_CommsAdapterManifestError) as excinfo:
        _resolve_comms_adapter_wire_spec(adapter_id)

    assert excinfo.value.field == "adapter_kind"


def test_resolve_wire_spec_raises_on_unregistered_adapter_kind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A present-but-unregistered ``adapter_kind`` refuses fail-closed (#374).

    The manifest declares a syntactically-valid ``adapter_kind`` that is NOT a member
    of the host's closed vocabulary (``REQUIRED_CLASSIFIERS_BY_KIND``) — a typo'd or
    unregistered kind. Instead of silently treating it as an empty-classifier kind (a
    ``None`` promoter, no host classifiers), the resolver raises
    ``_UnknownAdapterKindError`` (a ``_CommsAdapterManifestError`` subtype the boot's
    refusal arms catch) so the daemon refuses boot (CLAUDE.md hard rules #5 + #7).
    """
    adapter_id = "alfred_comms_test"
    _seed_manifest(
        tmp_path,
        adapter_id,
        '[plugin]\nid = "alfred.comms-test"\n'
        '[comms_mcp]\nmodule = "alfred_comms_test.main"\nadapter_kind = "bogus_typo"\n',
    )
    monkeypatch.setattr("alfred.cli._launcher_spawn.repo_root", lambda: tmp_path)
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot.parse_manifest",
        lambda _raw: _StubManifest(comms_mcp_module="alfred_comms_test.main"),
    )

    with pytest.raises(_UnknownAdapterKindError) as excinfo:
        _resolve_comms_adapter_wire_spec(adapter_id)

    assert excinfo.value.adapter_id == adapter_id
    assert excinfo.value.adapter_kind == "bogus_typo"
    assert excinfo.value.field == "adapter_kind"
    # It IS a _CommsAdapterManifestError, so the existing except arms catch it.
    assert isinstance(excinfo.value, _CommsAdapterManifestError)
    assert "bogus_typo" in str(excinfo.value)


# ── _build_comms_adapter_wiring _refuse_boot arms (src 826-827, 864) ──


@pytest.mark.asyncio
async def test_build_wiring_refuses_when_wire_spec_resolution_raises(
    monkeypatch: pytest.MonkeyPatch,
    fake_audit_writer: FakeAuditWriter,
) -> None:
    """A manifest error inside ``_build_comms_adapter_wiring`` refuses the boot.

    Covers src 826-827: the ``except (OSError, ManifestError,
    _CommsAdapterManifestError)`` arm wrapping the in-wiring
    ``_resolve_comms_adapter_wire_spec`` call routes to an audited ``_refuse_boot``
    (exit 2, ``comms_adapter_spawn_failed``). Driven directly because the daemon
    boot resolves the carrier kind first, so this in-wiring copy never runs there.
    """

    def _boom(_adapter_id: str) -> _CommsAdapterWireSpec:
        raise _CommsAdapterManifestError(_adapter_id, "adapter_kind")

    monkeypatch.setattr("alfred.cli.daemon._comms_boot._resolve_comms_adapter_wire_spec", _boom)

    # settings / supervisor / graph are never touched before the raise at the first
    # statement of the try, so untyped placeholders are safe here.
    with pytest.raises(_BootRefusedError) as excinfo:
        await _build_comms_adapter_wiring(
            adapter_id="alfred_comms_test",
            settings=object(),  # type: ignore[arg-type]
            audit=fake_audit_writer,  # type: ignore[arg-type]
            gate=object(),
            supervisor=object(),  # type: ignore[arg-type]
            graph=object(),  # type: ignore[arg-type]
            boot_id="boot-826",
            environment_source="test",
        )

    assert excinfo.value.code == 2
    rows = fake_audit_writer.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert reasons == {"comms_adapter_spawn_failed"}


@pytest.mark.asyncio
async def test_build_wiring_refuses_when_classifier_kind_gets_none_promoter(
    monkeypatch: pytest.MonkeyPatch,
    fake_audit_writer: FakeAuditWriter,
) -> None:
    """A classifier-bearing wire kind whose promoter factory yields ``None`` refuses.

    Covers src 864: the boot-time mirror of the inbound M2 guard. With a resolved
    ``discord`` wire (``REQUIRED_CLASSIFIERS_BY_KIND['discord']`` is non-empty) and a
    ``_build_sub_payload_promoter`` faulted to ``None``, the in-wiring guard refuses
    fail-closed (exit 2, ``comms_promoter_misconfigured``) rather than parking a graph
    that would leak raw T3 sub-payloads to the orchestrator (CLAUDE.md hard rules #5+#7).
    Driven directly because the daemon boot refuses at the forwarded-inbound registry
    build first, so this per-adapter copy never runs there.
    """
    from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND

    # Guard the premise the arm depends on: discord IS classifier-bearing.
    assert REQUIRED_CLASSIFIERS_BY_KIND.get("discord")

    discord_wire = _CommsAdapterWireSpec(
        plugin_id="alfred.discord",
        adapter_kind="discord",
        module="alfred_discord.main",
        sandbox_kind="bwrap",
        manifest_path=Path("/nonexistent/plugins/alfred_discord/manifest.toml"),
        manifest_raw="",
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot._resolve_comms_adapter_wire_spec",
        lambda _adapter_id: discord_wire,
    )
    # The deterministic factory can only yield None for a classifier-bearing kind under
    # a structural drift; fault it to None to reach the fail-closed arm.
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot._build_sub_payload_promoter",
        lambda **_kwargs: None,
    )

    # graph.content_store is read when building the (faulted) promoter; supervisor is
    # only wrapped by the breaker tripper. Nothing else is touched before the refuse.
    graph = SimpleNamespace(content_store=object())
    supervisor = SimpleNamespace(shutdown_event=None)

    with pytest.raises(_BootRefusedError) as excinfo:
        await _build_comms_adapter_wiring(
            adapter_id="alfred_discord",
            settings=object(),  # type: ignore[arg-type]
            audit=fake_audit_writer,  # type: ignore[arg-type]
            gate=object(),
            supervisor=supervisor,  # type: ignore[arg-type]
            graph=graph,  # type: ignore[arg-type]
            boot_id="boot-864",
            environment_source="test",
        )

    assert excinfo.value.code == 2
    rows = fake_audit_writer.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert reasons == {"comms_promoter_misconfigured"}


@pytest.mark.asyncio
async def test_build_wiring_refuses_on_unregistered_adapter_kind(
    monkeypatch: pytest.MonkeyPatch,
    fake_audit_writer: FakeAuditWriter,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unregistered ``adapter_kind`` refuses via its OWN distinct audited reason (#374).

    ``_UnknownAdapterKindError`` is a ``_CommsAdapterManifestError`` subtype, but
    ``_build_comms_adapter_wiring`` catches it in a NARROW arm (before the generic one)
    and refuses fail-closed (exit 2) with the distinct ``comms_adapter_unknown_kind``
    reason — so forensics can tell a typo'd kind apart from a generic spawn refusal — AND
    the operator-facing message names the offending kind rather than the misleading
    "missing or malformed manifest" text (CLAUDE.md hard rule #7). The narrow arm MUST
    precede the generic subtype-catching one.
    """

    def _boom(_adapter_id: str) -> _CommsAdapterWireSpec:
        raise _UnknownAdapterKindError(_adapter_id, "bogus_typo")

    monkeypatch.setattr("alfred.cli.daemon._comms_boot._resolve_comms_adapter_wire_spec", _boom)

    with pytest.raises(_BootRefusedError) as excinfo:
        await _build_comms_adapter_wiring(
            adapter_id="alfred_comms_test",
            settings=object(),  # type: ignore[arg-type]
            audit=fake_audit_writer,  # type: ignore[arg-type]
            gate=object(),
            supervisor=object(),  # type: ignore[arg-type]
            graph=object(),  # type: ignore[arg-type]
            boot_id="boot-374",
            environment_source="test",
        )

    assert excinfo.value.code == 2
    rows = fake_audit_writer.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert reasons == {"comms_adapter_unknown_kind"}
    # The operator-facing refusal (stderr) NAMES the offending kind — not the misleading
    # generic "missing or malformed manifest" text (#374 devex fix).
    assert "bogus_typo" in capsys.readouterr().err


# ── _make_control_reject_auditor callback (src 1331-1333) ──


@pytest.mark.asyncio
async def test_control_reject_auditor_writes_loud_refused_row(
    fake_audit_writer: FakeAuditWriter,
) -> None:
    """The control-plane peer-rejected callback writes a loud ``refused`` audit row.

    Covers src 1331-1333: ``_make_control_reject_auditor``'s callback emits the
    daemon-GLOBAL ``daemon.control.peer_uid_rejected`` row (arch-M1 — no
    ``adapter_id``) via ``_emit_or_quarantine`` at ``result="refused"``. Invoked with
    both an int peer uid AND ``None`` to drive both arms of the ``peer_uid`` render.
    """
    auditor = _make_control_reject_auditor(fake_audit_writer)  # type: ignore[arg-type]

    await auditor(1234)
    await auditor(None)

    rows = fake_audit_writer.rows_for("DAEMON_CONTROL_PEER_REJECTED_FIELDS")
    assert len(rows) == 2
    for row in rows:
        assert row["event"] == "daemon.control.peer_uid_rejected"
        assert row["result"] == "refused"
        assert row["trust_tier_of_trigger"] == "T0"
        # The daemon-global control plane carries NO adapter_id (arch-M1).
        assert "adapter_id" not in row["subject"]
    # An int uid renders to its str; a None uid renders to "" (the two ternary arms).
    assert [row["subject"]["peer_uid"] for row in rows] == ["1234", ""]
