"""Adversarial wiring-smoke for the ``cap-2026-001`` corpus payload.

Asserts the **defense fired** at daemon boot: with NO first-party
DLP-subscriber grant live (an empty-grant :class:`RealGate` via
:func:`make_deny_all_gate`), the ADR-0026 fail-closed boot grant-assertion
MUST refuse the boot — exit 2 + a ``daemon.boot.failed`` audit row carrying
the ``quarantine_grant_missing`` reason — rather than continue past install
and construct a half-wired :class:`QuarantinedExtractor` whose mandatory
post-chain DLP scan never registered.

This is the release-blocking executable for the property
``test_daemon_quarantine_boot_infra.test_boot_refuses_when_first_party_grant_missing``
pins at the unit tier; the corpus entry makes the fail-closed boot-refusal a
release-blocker, not just a unit test (PR-S4-11b0 review SHOULD-FIX).

Uses a REAL :func:`make_deny_all_gate` (a :class:`RealGate` over an empty
:class:`GatePolicy`), NEVER a permissive always-allow shim — CLAUDE.md hard
rule #2: deny-path security tests assert against RealGate's deny path so a
RealGate regression cannot be hidden behind a test-side shim.

Mirrors the wiring-smoke pattern of
:mod:`tests.adversarial.hooks.test_hk_2026_002_registration_tier_rejection`.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_deny_all_gate
from tests.unit.cli.daemon.conftest import (
    FakeAuditWriter,
    apply_boot_success_patches,
)

_PAYLOAD_ID: Final[str] = "cap-2026-001"


@pytest.fixture
def boot_success_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[FakeAuditWriter]:
    """In-memory daemon-boot-success harness for this adversarial entry.

    The ``boot_success_env`` fixture itself lives in
    ``tests/unit/cli/daemon/conftest.py`` and is not visible across the
    adversarial package boundary, so this local fixture drives the SAME
    reusable :func:`apply_boot_success_patches` body — one source of truth
    for the boot-success harness, no duplicated monkeypatch wiring.
    """
    audit = FakeAuditWriter()
    restore = apply_boot_success_patches(monkeypatch, tmp_path, audit)
    yield audit
    restore()


@pytest.fixture
def boot_refuses_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus to the wiring-smoke payload.

    Fails loudly if the payload is missing/duplicated so a future rename or
    delete in the corpus surfaces here (drift-guard pattern shared with
    :func:`tests.adversarial.hooks.test_hk_2026_002_registration_tier_rejection.registration_tier_rejection_payload`).
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; expected at "
            "tests/adversarial/capability_bypass/"
            "boot_refuses_without_first_party_dlp_grant.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def _async_return(value: Any):  # type: ignore[no-untyped-def]
    async def _f(*_args: Any, **_kwargs: Any) -> Any:
        return value

    return _f


def _boot_failed_reason(writer: FakeAuditWriter) -> str | None:
    for r in writer.rows_for("DAEMON_BOOT_FAILED_FIELDS"):
        subject = r["subject"]
        if isinstance(subject, dict):
            return str(subject["failure_reason"])
    return None


def test_boot_refuses_without_first_party_dlp_grant(
    boot_refuses_payload: AdversarialPayload,
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    """An empty-grant RealGate at boot ⇒ the daemon REFUSES (exit 2 + audit).

    Drives the RAW-gate builder to a deny-all :class:`RealGate`; the ADR-0026
    boot grant-assertion in ``_start_async`` then refuses with
    ``quarantine_grant_missing``. The whole point is that the boot does NOT
    silently continue with a quarantine path that cannot wire its DLP scan.
    """
    # Payload-shape sanity: the corpus entry pins the deny fixture + the
    # refused outcome so a future edit that weakens it surfaces here.
    payload_fields = boot_refuses_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["gate_fixture"] == "make_deny_all_gate", (
        f"payload {_PAYLOAD_ID} must drive the deny-path RealGate fixture "
        "(make_deny_all_gate), never a permissive shim — CLAUDE.md hard rule #2"
    )
    assert boot_refuses_payload.expected_outcome == "refused"

    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # The defense under test: an empty-grant RealGate (no first-party DLP
    # grant). The boot assertion must turn this into a refusal.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_real_gate_for_daemon",
        _async_return(make_deny_all_gate()),
    )

    result = CliRunner().invoke(daemon_app, ["start"])

    # Exit 2 — the refusal contract (NOT 0, which would mean the daemon
    # booted with an unscanned quarantine path).
    assert result.exit_code == 2, (
        f"boot did not refuse with exit 2 (got {result.exit_code}); the "
        "first-party-DLP-grant-missing boot assertion failed to fire"
    )
    # The audit trail carries the loud, attributable failure reason.
    assert _boot_failed_reason(boot_success_env) == "quarantine_grant_missing", (
        "expected a daemon.boot.failed audit row with reason "
        "quarantine_grant_missing — the refusal must be audited (CLAUDE.md "
        "hard rule #7), not a silent exit"
    )
