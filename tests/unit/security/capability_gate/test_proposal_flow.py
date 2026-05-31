"""Spec §8.3: reviewer-gated proposal flow for high-blast capability grants.

``alfred plugin grant system <plugin> <hookpoint>`` MUST NOT mutate the
Postgres ``plugin_grants`` table directly. Instead the operator's grant
request becomes a ``proposal/policy-grant-<id>`` branch in
``/var/lib/alfred/state.git``; the reviewer-agent reviews; merge to main
triggers :meth:`RealGate.rebuild_from_state_git`, which is where the
``plugin_grants`` upsert happens.

Hard invariants pinned here:

* :func:`create_proposal_branch` calls ``_write_proposal_to_state_git``
  exactly once and does NOT call ``backend.upsert_grant`` — the grant is
  inert until the reviewer-agent merges.
* The function returns the branch name so the CLI layer can surface
  ``t("cli.plugin.grant.pending_review")`` with a trackable identifier.
* :data:`plugin.grant.requested` audit row emits with
  :data:`PLUGIN_GRANT_FIELDS` and carries the operator's user id +
  proposal-branch attribution (spec §8.5).
* err-005: ``audit_sink`` is required, not optional. A proposal with no
  audit row would let the reviewer-gated flow run silently — CLAUDE.md
  hard rule #7 forbids the silent path.
* The branch identifier is non-predictable (``secrets.token_hex``) so an
  adversary who learns one branch name cannot enumerate future
  proposals.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_backend() -> Any:
    """Return a stub backend whose ``upsert_grant`` is observable.

    The proposal flow MUST NOT touch the backend; spying lets us assert
    the non-call exactly.
    """
    backend = MagicMock()
    backend.upsert_grant = AsyncMock(return_value=None)
    return backend


def _make_no_op_sink() -> Any:
    """No-op audit sink for tests that don't assert on audit rows."""
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


def _make_spy_sink() -> tuple[Any, list[dict[str, Any]]]:
    """Return a ``(sink, emitted_rows)`` tuple capturing ``append_schema`` calls.

    Mirrors the ``AuditWriter.append_schema`` keyword-only signature:
    ``fields=frozenset[str]``, ``subject=dict`` plus metadata kwargs. The
    spy validates field-set symmetry locally so a future emit-site
    regression (typo'd key, missing key) surfaces here before the real
    AuditWriter ever sees the row.
    """
    emitted: list[dict[str, Any]] = []

    async def _append_schema(
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        subject: dict[str, Any],
        **_unused: Any,
    ) -> None:
        if set(subject.keys()) != fields:
            msg = (
                f"proposal-flow emit-site bug: subject keys "
                f"{sorted(subject.keys())!r} != declared fields "
                f"{sorted(fields)!r} for {schema_name}"
            )
            raise AssertionError(msg)
        emitted.append({"event": event, "schema_name": schema_name, **subject})

    sink = MagicMock()
    sink.append_schema = _append_schema
    return sink, emitted


async def test_create_proposal_does_not_write_grant_to_backend() -> None:
    """Creating a proposal MUST NOT call ``backend.upsert_grant``.

    Spec §8.3: the grant only becomes active after reviewer-agent
    approval merges the proposal branch. Writing to Postgres at proposal
    creation time would race the reviewer-gate flow and silently
    activate an unreviewed grant.
    """
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    with patch(
        "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
        new=AsyncMock(return_value="proposal/policy-grant-abc123"),
    ) as mock_write:
        proposal_id = await create_proposal_branch(
            plugin_id="test.plugin",
            subscriber_tier="system",
            hookpoint="tool.web.fetch",
            operator_user_id="operator@example.com",
            backend=backend,
            audit_sink=_make_no_op_sink(),
        )

    mock_write.assert_awaited_once()
    backend.upsert_grant.assert_not_awaited()
    assert proposal_id.startswith("proposal/policy-grant-")


async def test_create_proposal_returns_branch_name() -> None:
    """``create_proposal_branch`` returns the state.git branch name.

    The CLI layer uses this for ``alfred plugin grant status <branch>``
    tracking. Returning the branch name lets the operator follow the
    review without re-deriving the identifier.
    """
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    with patch(
        "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
        new=AsyncMock(return_value="proposal/policy-grant-deadbeef"),
    ):
        result = await create_proposal_branch(
            plugin_id="mypl",
            subscriber_tier="operator",
            hookpoint="tool.web.fetch",
            operator_user_id="op@example.com",
            backend=backend,
            audit_sink=_make_no_op_sink(),
        )

    assert result.startswith("proposal/policy-grant-")


async def test_create_proposal_emits_grant_requested_audit_row() -> None:
    """Spec §8.5: ``plugin.grant.requested`` audit row emits on proposal creation.

    err-005 fix: audit_sink is required. The row carries the full
    PLUGIN_GRANT_FIELDS payload — plugin_id, subscriber_tier, hookpoint,
    operator_user_id, proposal_branch, correlation_id — so the
    audit-graph can follow the proposal forward to merge / revocation.
    """
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    sink, emitted = _make_spy_sink()

    with patch(
        "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
        new=AsyncMock(return_value="proposal/policy-grant-xyz"),
    ):
        await create_proposal_branch(
            plugin_id="test.plugin",
            subscriber_tier="system",
            hookpoint="tool.web.fetch",
            operator_user_id="op@example.com",
            backend=backend,
            audit_sink=sink,
        )

    requested = [e for e in emitted if e["event"] == "plugin.grant.requested"]
    assert len(requested) == 1
    row = requested[0]
    assert row["plugin_id"] == "test.plugin"
    assert row["subscriber_tier"] == "system"
    assert row["hookpoint"] == "tool.web.fetch"
    assert row["operator_user_id"] == "op@example.com"
    assert row["proposal_branch"].startswith("proposal/policy-grant-")
    # correlation_id is a UUID4 str.
    assert isinstance(row["correlation_id"], str)
    uuid.UUID(row["correlation_id"])


async def test_create_proposal_branch_id_is_unpredictable() -> None:
    """Branch identifiers come from :func:`secrets.token_hex`, not :func:`uuid.uuid1`.

    An adversary who reads one branch name from the audit log must not
    be able to predict future proposal IDs (uuid1 / counter-based IDs
    would leak ordering). Spec §8.3's reviewer-gate flow assumes the
    branch namespace is collision-free AND unpredictable.

    The test does NOT make a statistical claim — it asserts the
    identifier shape is hex (token_hex output) and that two consecutive
    calls return distinct IDs. The cryptographic property is bought by
    using ``secrets``; we test we use it by shape, not entropy.
    """
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    with patch(
        "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
        new=AsyncMock(side_effect=lambda **kwargs: kwargs["branch_name"]),
    ):
        first = await create_proposal_branch(
            plugin_id="p",
            subscriber_tier="system",
            hookpoint="h",
            operator_user_id="op@example.com",
            backend=backend,
            audit_sink=_make_no_op_sink(),
        )
        second = await create_proposal_branch(
            plugin_id="p",
            subscriber_tier="system",
            hookpoint="h",
            operator_user_id="op@example.com",
            backend=backend,
            audit_sink=_make_no_op_sink(),
        )

    assert first != second
    # token_hex(8) is 16 hex chars; full prefix is "proposal/policy-grant-".
    assert first.startswith("proposal/policy-grant-")
    suffix = first.removeprefix("proposal/policy-grant-")
    assert len(suffix) == 16
    int(suffix, 16)  # Raises if not valid hex.


async def test_create_proposal_passes_content_tier_when_supplied() -> None:
    """``content_tier`` is propagated to the state.git writer when set.

    Some grants are content-tier-restricted (e.g. ``T3`` for the
    quarantined LLM). The CLI's ``--content-tier`` flag flows through
    here; the proposal must carry the restriction so the reviewer-agent
    can validate it.
    """
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    captured: dict[str, Any] = {}

    async def _capture(**kwargs: Any) -> str:
        captured.update(kwargs)
        return str(kwargs["branch_name"])

    with patch(
        "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
        new=_capture,
    ):
        await create_proposal_branch(
            plugin_id="quarantine.host",
            subscriber_tier="system",
            hookpoint="tag.T3",
            operator_user_id="op@example.com",
            backend=backend,
            audit_sink=_make_no_op_sink(),
            content_tier="T3",
        )

    assert captured["content_tier"] == "T3"
    assert captured["plugin_id"] == "quarantine.host"


async def test_create_proposal_default_content_tier_is_none() -> None:
    """``content_tier`` defaults to ``None`` (no content-tier restriction).

    Most grants are content-tier-agnostic. The default is None so the
    common-case caller does not have to pass an extra argument.
    """
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    captured: dict[str, Any] = {}

    async def _capture(**kwargs: Any) -> str:
        captured.update(kwargs)
        return str(kwargs["branch_name"])

    with patch(
        "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
        new=_capture,
    ):
        await create_proposal_branch(
            plugin_id="p",
            subscriber_tier="operator",
            hookpoint="h",
            operator_user_id="op@example.com",
            backend=backend,
            audit_sink=_make_no_op_sink(),
        )

    assert captured["content_tier"] is None


async def test_write_proposal_stub_raises_not_implemented() -> None:
    """CR-139 finding #5: the PR-S3-2 stub is fail-loud, not silent.

    Spec §6.4 / §8.3: the real state.git write lands in PR-S3-6
    alongside the CLI wiring. Until then, calling the stub MUST raise
    :class:`NotImplementedError` so a caller cannot accidentally emit
    ``plugin.grant.requested`` for a branch that was never durably
    written. Matches the err-002 shape used by
    :meth:`RealGate.rebuild_from_state_git`.
    """
    from alfred.security.capability_gate.proposals import (
        _write_proposal_to_state_git,
    )

    with pytest.raises(NotImplementedError, match=r"PR-S3-6"):
        await _write_proposal_to_state_git(
            branch_name="proposal/policy-grant-stubtest",
            plugin_id="p",
            subscriber_tier="operator",
            hookpoint="h",
            content_tier=None,
            operator_user_id="op@example.com",
        )


async def test_create_proposal_branch_unpatched_stub_propagates_raise() -> None:
    """Un-patched ``create_proposal_branch`` propagates the stub's raise.

    The audit row MUST NOT emit when the state.git write hasn't
    landed. Since :func:`_write_proposal_to_state_git` is fail-loud
    until PR-S3-6, an un-patched call to
    :func:`create_proposal_branch` MUST surface the
    :class:`NotImplementedError` directly to the caller and leave the
    audit sink untouched.
    """
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    sink, emitted = _make_spy_sink()

    with pytest.raises(NotImplementedError, match=r"PR-S3-6"):
        await create_proposal_branch(
            plugin_id="p",
            subscriber_tier="operator",
            hookpoint="h",
            operator_user_id="op@example.com",
            backend=backend,
            audit_sink=sink,
        )

    assert emitted == []
    backend.upsert_grant.assert_not_awaited()


async def test_create_proposal_audit_row_emitted_after_state_git_write() -> None:
    """Audit row emit happens AFTER the state.git write succeeds, not before.

    Ordering matters: a state.git write failure that already emitted the
    audit row would leave the operator believing the proposal exists
    when it does not. Spec §8.5 implies the audit row is the
    persistence-success signal.

    This test patches ``_write_proposal_to_state_git`` to raise and
    asserts no audit row was emitted.
    """
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    sink, emitted = _make_spy_sink()

    async def _failing_write(**_kwargs: Any) -> str:
        msg = "state.git temporarily unavailable"
        raise RuntimeError(msg)

    with (
        patch(
            "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
            new=_failing_write,
        ),
        pytest.raises(RuntimeError, match=r"state\.git temporarily unavailable"),
    ):
        await create_proposal_branch(
            plugin_id="p",
            subscriber_tier="operator",
            hookpoint="h",
            operator_user_id="op@example.com",
            backend=backend,
            audit_sink=sink,
        )

    # No audit row because state.git write failed.
    assert emitted == []
    backend.upsert_grant.assert_not_awaited()


def test_write_proposal_log_does_not_emit_operator_user_id() -> None:
    """CR-139 R2: the operational structlog event must NOT carry the
    raw ``operator_user_id`` (an email). PII discipline — the structlog
    redactor (alfred.cli._bootstrap._redact) scrubs secret-shaped strings
    via SecretBroker.redact + the generic API-key regex but does NOT
    scrub user identifiers. The full id is available in the audit-row
    fields where it belongs.
    """
    import asyncio

    import structlog.testing

    from alfred.security.capability_gate.proposals import (
        _write_proposal_to_state_git,
    )

    canonical_email = "alice@example.com"
    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises(NotImplementedError),
    ):
        asyncio.run(
            _write_proposal_to_state_git(
                branch_name="proposal/p1",
                plugin_id="alfred-foo",
                subscriber_tier="user-plugin",
                hookpoint="plugin.foo",
                content_tier="T2",
                operator_user_id=canonical_email,
            )
        )

    matched = [e for e in captured if e.get("event") == "capability_gate.proposal.write_attempted"]
    assert matched, f"structlog event was not captured; got {captured!r}"
    for event in matched:
        for key, value in event.items():
            assert value != canonical_email, (
                f"Raw operator_user_id leaked into operational log under field {key!r}: {event!r}"
            )
        # Length marker IS present so missing-id bugs stay diagnosable.
        assert event.get("operator_user_id_len") == len(canonical_email), (
            f"Expected operator_user_id_len={len(canonical_email)} in event; got {event!r}"
        )
