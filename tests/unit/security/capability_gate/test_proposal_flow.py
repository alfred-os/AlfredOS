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


async def test_write_proposal_shim_validates_payload() -> None:
    """ADR-0018 / Stage 4: the previous PR-S3-2 NotImplementedError stub
    is replaced with a thin shim into
    :class:`alfred.cli._state_git.StateGitProposalClient` (see
    :doc:`/docs/adr/0018-state-git-proposal-writer-consolidation`).

    Pydantic's Literal-bound ``subscriber_tier`` refuses anything
    outside the closed set, so a typo at the call site fails at the
    model boundary BEFORE the sync writer touches state.git. This test
    replaces the legacy ``NotImplementedError`` regression with the
    Pydantic-validation guarantee.
    """
    from pydantic import ValidationError

    from alfred.security.capability_gate.proposals import (
        _write_proposal_to_state_git,
    )

    with pytest.raises(ValidationError):
        await _write_proposal_to_state_git(
            branch_name="proposal/policy-grant-stubtest",
            plugin_id="p",
            subscriber_tier="not-a-tier",  # closed-set refusal
            hookpoint="h",
            content_tier=None,
            operator_user_id="op@example.com",
        )


async def test_create_proposal_branch_unpatched_shim_propagates_state_git_failure() -> None:
    """Un-patched ``create_proposal_branch`` surfaces a sync-writer failure.

    ADR-0018: the previous PR-S3-2 ``NotImplementedError`` stub is
    replaced with the asyncio shim into
    :class:`alfred.cli._state_git.StateGitProposalClient`. In a unit
    environment the default state.git path
    (``/var/lib/alfred/state.git``) does not exist, so the un-patched
    shim must propagate a :class:`StateGitError` (typed) — never let
    the audit row emit for a branch the writer could not durably
    persist. CLAUDE.md hard rule #7 forbids the silent skip.

    The original "NotImplementedError" surface is preserved as a
    structural invariant: the audit sink stays untouched on failure.
    """
    from alfred.cli._state_git import StateGitError
    from alfred.security.capability_gate.proposals import create_proposal_branch

    backend = _make_backend()
    sink, emitted = _make_spy_sink()

    with pytest.raises(StateGitError):
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


async def test_write_proposal_happy_path_returns_writer_branch(
    tmp_path: Any,
) -> None:
    """``_write_proposal_to_state_git`` returns the sync writer's branch on success.

    Pins the line 360 return path (after the prefix guard + Pydantic
    validation + ``asyncio.to_thread`` round-trip). The shim's contract
    is that the returned branch name ROUND-TRIPS the caller-supplied
    ``branch_name`` exactly — a deviation would split the audit-row
    branch field from the durably persisted state.git ref.

    Uses a real bare state.git repo so the sync writer succeeds end-to-end
    without monkeypatching :class:`StateGitProposalClient` itself.
    """
    # Build a bare state.git repo at the default path so the un-patched
    # StateGitProposalClient() default discovers it. We pin the writer's
    # constructor path explicitly via the ALFRED_STATE_GIT_PATH env
    # surface — see :class:`StateGitProposalClient` default handling.
    import subprocess
    from pathlib import Path

    from alfred.security.capability_gate.proposals import (
        _write_proposal_to_state_git,
    )
    from alfred.state.proposal_payloads import PluginGrantProposal

    repo: Path = tmp_path / "state.git"
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "--initial-branch=main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    # Seed a main branch so the writer can branch off it.
    work: Path = tmp_path / "seed"
    subprocess.run(  # noqa: S603
        ["git", "clone", str(repo), str(work)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    (work / "README").write_text("seed")
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "add", "."],  # noqa: S607
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(work),
            "commit",
            "-m",
            "seed",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
    )

    # Patch the StateGitProposalClient source so the lazy import inside
    # the shim picks up the temp-repo-bound subclass. The shim does
    # ``from alfred.cli._state_git import StateGitProposalClient`` at
    # call time, so patching at the source module is the binding seen.
    from unittest.mock import patch

    from alfred.cli._state_git import StateGitProposalClient as _RealClient

    expected_id = "deadbeefdeadbeef"
    expected_branch = f"proposal/{PluginGrantProposal.proposal_type}-{expected_id}"

    class _BoundClient(_RealClient):  # type: ignore[misc]
        """Subclass that pins the bare state.git path to our temp repo."""

        def __init__(self) -> None:
            super().__init__(state_git_path=repo)

    with patch(
        "alfred.cli._state_git.StateGitProposalClient",
        new=_BoundClient,
    ):
        branch = await _write_proposal_to_state_git(
            branch_name=expected_branch,
            plugin_id="alfred-foo",
            subscriber_tier="user-plugin",
            hookpoint="tool.web.fetch",
            content_tier=None,
            operator_user_id="op@example.com",
        )

    # The shim returns the writer's branch — must round-trip the
    # caller-supplied branch_name exactly.
    assert branch == expected_branch


async def test_write_proposal_rejects_branch_name_without_canonical_prefix() -> None:
    """``_write_proposal_to_state_git`` MUST refuse a branch_name that
    does not start with ``proposal/policy-grant-``.

    ADR-0018 R2: the audit row a peer caller has ALREADY emitted carries
    the branch name verbatim — a divergence between the audit-row
    branch and the state.git-writer branch would break the
    audit-graph join. Refusing at the shim boundary (rather than letting
    the sync writer compose its own derived name) preserves the
    invariant that the audit row is the persistence-success signal.

    The structural refusal is closed-set: any other prefix is a bug or a
    malicious tag that MUST NOT reach the sync writer. A Pydantic
    :class:`ValueError` is the right shape — peer callers catch the
    structured error and never observe a half-written branch.
    """
    from alfred.security.capability_gate.proposals import (
        _write_proposal_to_state_git,
    )

    with pytest.raises(ValueError, match=r"does not match expected prefix"):
        await _write_proposal_to_state_git(
            # Wrong prefix — e.g. an operator typo or an injected branch
            # name from a compromised peer caller.
            branch_name="proposal/web-allowlist-deadbeef",
            plugin_id="alfred-foo",
            subscriber_tier="user-plugin",
            hookpoint="tool.web.fetch",
            content_tier=None,
            operator_user_id="op@example.com",
        )


def test_write_proposal_log_does_not_emit_operator_user_id() -> None:
    """CR-139 R2: the operational structlog event must NOT carry the
    raw ``operator_user_id`` (an email). PII discipline — the structlog
    redactor (alfred.cli._bootstrap._redact) scrubs secret-shaped strings
    via SecretBroker.redact + the generic API-key regex but does NOT
    scrub user identifiers. The full id is available in the audit-row
    fields where it belongs.

    ADR-0018: the previous NotImplementedError stub is now the asyncio
    shim into the sync writer. In a unit environment the default
    state.git path does not exist, so the shim raises
    :class:`StateGitError` after the structlog event is emitted; the
    PII assertion checks the event payload, not the failure mode.
    """
    import asyncio

    import structlog.testing

    from alfred.cli._state_git import StateGitError
    from alfred.security.capability_gate.proposals import (
        _write_proposal_to_state_git,
    )

    canonical_email = "alice@example.com"
    with (
        structlog.testing.capture_logs() as captured,
        # The shim's downstream sync writer surfaces a StateGitError when
        # the default state.git path does not exist (PATH_MISSING). The
        # structlog event fires BEFORE the sync writer is invoked so the
        # PII discipline assertion still observes the event payload.
        pytest.raises(StateGitError),
    ):
        asyncio.run(
            _write_proposal_to_state_git(
                # Match the canonical ``proposal/policy-grant-<hex>``
                # prefix so the branch-name guard passes and execution
                # reaches the structlog emit + sync writer.
                branch_name="proposal/policy-grant-deadbeefdeadbeef",
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
