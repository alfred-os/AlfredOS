"""Whitelisted ALFRED_ENV passthrough to the plugin subprocess (arch-003 fix).

Covers two layers:

1. :func:`alfred.plugins._env_passthrough.alfred_env_for_subprocess` returns
   the parent's ``ALFRED_ENV`` (defaulting to ``"production"`` when unset
   / empty / whitespace).
2. The :class:`StdioTransport` spawn path threads that value into the
   subprocess's env so the documented dev-mode TLS escape hatch in
   :class:`alfred.plugins.web_fetch.tls_policy.TlsPolicy` actually fires
   when the operator set ``ALFRED_ENV=development`` on the parent.

The sec-011 / spec §5.3 invariant — the subprocess inherits a MINIMAL env
and never sees arbitrary parent vars — must still hold. The test
``test_spawn_does_not_leak_other_parent_env_keys`` is the load-bearing
regression guard: a future change that broadens the passthrough beyond
``ALFRED_ENV`` would fail it.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from alfred.plugins._env_passthrough import alfred_env_for_subprocess
from alfred.plugins.stdio_transport import StdioTransport

# ---------------------------------------------------------------------------
# Layer 1: pure-function tests on the passthrough helper.
# ---------------------------------------------------------------------------


def test_alfred_env_for_subprocess_returns_development_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ALFRED_ENV=development`` on the parent is surfaced to callers.

    The operator's documented dev escape hatch (spec §7.11) hinges on
    this value reaching the plugin subprocess so ``TlsPolicy`` honours
    ``skip_tls_verify=True``. arch-003 root cause: this passthrough was
    missing — the helper returned the default regardless of parent env.
    """
    monkeypatch.setenv("ALFRED_ENV", "development")
    assert alfred_env_for_subprocess() == "development"


def test_alfred_env_for_subprocess_defaults_to_production_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset ``ALFRED_ENV`` resolves to ``"production"`` (fail-closed default).

    Spec §7.11: a missing env var must NOT relax the TLS posture. The
    subprocess receives the explicit ``"production"`` literal so the
    policy refuses ``skip_tls_verify=True``.
    """
    monkeypatch.delenv("ALFRED_ENV", raising=False)
    assert alfred_env_for_subprocess() == "production"


def test_alfred_env_for_subprocess_defaults_to_production_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty / whitespace ``ALFRED_ENV`` is treated as unset.

    Mirrors :func:`alfred.bootstrap.gate_factory.is_production`'s
    treatment of the ``export ALFRED_ENV=`` shell-config foot-gun:
    a present-but-empty variable should not silently flip the security
    posture to a weaker setting.
    """
    monkeypatch.setenv("ALFRED_ENV", "")
    assert alfred_env_for_subprocess() == "production"
    monkeypatch.setenv("ALFRED_ENV", "   ")
    assert alfred_env_for_subprocess() == "production"


def test_alfred_env_for_subprocess_passes_through_other_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-empty, non-whitespace values pass through verbatim.

    Anything other than ``"development"`` still maps to a non-development
    posture in :class:`TlsPolicy` (the subprocess-side check refuses
    ``skip_tls_verify`` for any value other than ``"development"``).
    Passing the raw operator-set string through means an operator who
    typo'd ``"developement"`` sees the correct fail-closed behaviour
    rather than an opaque "production" string in audit logs that
    obscures their intent.
    """
    monkeypatch.setenv("ALFRED_ENV", "staging")
    assert alfred_env_for_subprocess() == "staging"


# ---------------------------------------------------------------------------
# Layer 2: integration with StdioTransport._spawn.
#
# These tests build a real subprocess via ``/bin/sh -c env`` and assert
# the resolved ``ALFRED_ENV`` reaches the child's environment. They also
# assert no OTHER parent-env key leaks — sec-011 / spec §5.3.
# ---------------------------------------------------------------------------


def _make_transport(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
    executable: str = "/bin/sh",
    args: list[str] | None = None,
) -> StdioTransport:
    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = None
    return StdioTransport(
        plugin_id="test.plugin",
        executable=executable,
        args=args if args is not None else ["-c", "env"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: hardcoded /bin/sh executable (not present on Windows)",
)
async def test_spawn_propagates_alfred_env_development(
    monkeypatch: pytest.MonkeyPatch,
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> None:
    """``ALFRED_ENV=development`` on the parent reaches the subprocess.

    arch-003 fix: without this passthrough, the subprocess's
    :class:`TlsPolicy` always saw ``ALFRED_ENV`` unset and rejected
    ``skip_tls_verify=True`` even in legitimate dev. The escape hatch
    never fired.
    """
    monkeypatch.setenv("ALFRED_ENV", "development")
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    await transport._spawn()
    assert transport._process is not None
    assert transport._process.stdout is not None
    stdout = await transport._process.stdout.read()
    await transport._process.wait()
    decoded = stdout.decode("utf-8", errors="replace")
    assert "ALFRED_ENV=development" in decoded


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: hardcoded /bin/sh executable (not present on Windows)",
)
async def test_spawn_defaults_alfred_env_to_production_when_parent_unset(
    monkeypatch: pytest.MonkeyPatch,
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> None:
    """Unset parent ``ALFRED_ENV`` surfaces as ``"production"`` in the child.

    Spec §7.11 fail-closed default: the subprocess MUST see an explicit
    production posture rather than rely on the child's own default
    handling — the child can read whatever value it wants, but the host
    is the authoritative gate so the env literal lands as
    ``ALFRED_ENV=production`` in the spawn.
    """
    monkeypatch.delenv("ALFRED_ENV", raising=False)
    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    await transport._spawn()
    assert transport._process is not None
    assert transport._process.stdout is not None
    stdout = await transport._process.stdout.read()
    await transport._process.wait()
    decoded = stdout.decode("utf-8", errors="replace")
    assert "ALFRED_ENV=production" in decoded


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: hardcoded /bin/sh executable (not present on Windows)",
)
async def test_spawn_does_not_leak_other_parent_env_keys(
    monkeypatch: pytest.MonkeyPatch,
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> None:
    """Only ``ALFRED_ENV`` crosses the boundary — no other parent vars leak.

    Load-bearing regression guard. A future change that widens the
    passthrough beyond ``ALFRED_ENV`` (e.g. adds ``HOME``, ``USER``,
    ``AWS_*``) would fail this test. The sec-011 / spec §5.3 invariant
    is that the subprocess sees the MINIMAL env plus the one whitelisted
    passthrough — nothing else.
    """
    # Plant a bouquet of common foot-gun env vars on the parent — the
    # spawn path must NOT let any of them through.
    monkeypatch.setenv("ALFRED_ENV", "development")
    monkeypatch.setenv("HOME", "/leaked/home")
    monkeypatch.setenv("USER", "leaked-user")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-LEAKED")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-LEAKED")

    transport = _make_transport(fake_audit_writer, fake_broker, stub_nonce)
    await transport._spawn()
    assert transport._process is not None
    assert transport._process.stdout is not None
    stdout = await transport._process.stdout.read()
    await transport._process.wait()
    decoded = stdout.decode("utf-8", errors="replace")
    # ALFRED_ENV crossed (intentionally).
    assert "ALFRED_ENV=development" in decoded
    # No leak markers.
    assert "/leaked/home" not in decoded
    assert "leaked-user" not in decoded
    assert "AKIA-LEAKED" not in decoded
    assert "sk-LEAKED" not in decoded
    # HOME / USER / AWS_* / OPENAI_API_KEY keys themselves must not appear.
    # /bin/sh prints `KEY=VALUE` lines so checking for the key= prefix is
    # the precise assertion.
    assert "HOME=" not in decoded
    assert "USER=" not in decoded
    assert "AWS_ACCESS_KEY_ID=" not in decoded
    assert "OPENAI_API_KEY=" not in decoded
