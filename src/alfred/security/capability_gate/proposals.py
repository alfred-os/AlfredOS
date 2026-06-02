"""Reviewer-gated proposal flow for capability-grant requests.

Spec §8.3 (PR-S3-2 Component G). Granting a hookpoint subscription —
particularly at the ``system`` subscriber tier — is a high-blast
operation: a system-tier grant gives the plugin orchestrator-level
attribution that the operator cannot rescind in the middle of a turn.
PRD §6.4's self-improvement rules require these changes go through:

1. A state.git ``proposal/policy-grant-<id>`` branch (this module
   writes it).
2. Reviewer-agent review of the proposal payload.
3. Explicit human approval (PRD §6.4 #4 — plugin install/remove).
4. Reviewer merges to ``main``, which triggers
   :meth:`alfred.security.capability_gate._gate.RealGate.rebuild_from_state_git`
   and the corresponding Postgres upsert.

This module is the entry point for step 1. The CLI surface
``alfred plugin grant <plugin-id> <tier> <hookpoint>`` (PR-S3-6) calls
:func:`create_proposal_branch` and surfaces
``t("cli.plugin.grant.pending_review")`` to the operator.

CRITICAL CONTRACT: :func:`create_proposal_branch` MUST NOT call
:meth:`alfred.security.capability_gate.backend.PostgresBackend.upsert_grant`.
The grant is inert until the reviewer-agent merges the branch.
Writing to Postgres at proposal-creation time would race the
reviewer-gate flow and silently activate an unreviewed grant — exactly
the silent privilege-escalation CLAUDE.md hard rule #2 forbids.

sec-007: this module does NOT ``import os`` — ``ALFRED_ENV`` reads
live in :mod:`alfred.bootstrap.gate_factory`.

ADR-0018 consolidation. The Stage-4 PR consolidates the dual state.git
writer surface: :func:`_write_proposal_to_state_git` was previously a
fail-loud :class:`NotImplementedError` stub awaiting PR-S3-6's gitpython
integration. The Stage-4 implementation replaces the stub with a thin
asyncio shim that constructs a :class:`PluginGrantProposal` and awaits
:func:`asyncio.to_thread` to call into
:class:`alfred.cli._state_git.StateGitProposalClient` — the canonical
sync writer. Both writers now produce the same on-disk shape
(``policies/grants/<plugin_id>/<grant_id>.json``); the round-trip
through :func:`._state_git_parser.parse_state_git_head` works by
construction.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import uuid
from typing import TYPE_CHECKING, Final, Literal, cast

import structlog

from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS
from alfred.hooks.registry import SYSTEM_ONLY_TIERS, HookRegistry, get_registry

# CR reviewer F1: the proposal flow and the gate share a single
# audit-sink Protocol. See ``_audit_protocols`` for the rationale; the
# proposal-flow audit-sink seam is the same shape as the gate's.
from ._audit_protocols import _AuditSink

if TYPE_CHECKING:
    from .backend import StorageBackend

_log = structlog.get_logger(__name__)

# Spec §14 hookpoint table — the four plugin.grant.* lifecycle events.
# Constants centralise the literals so the declaration site (this
# module) and any future invoke / subscribe site reference the same
# string; a typo on either end then fails at register_hookpoint's
# strict-declaration check instead of silently never matching.
HOOKPOINT_GRANT_REQUESTED: Final[str] = "plugin.grant.requested"
HOOKPOINT_GRANT_APPROVED: Final[str] = "plugin.grant.approved"
HOOKPOINT_GRANT_DENIED: Final[str] = "plugin.grant.denied"
HOOKPOINT_GRANT_REVOKED: Final[str] = "plugin.grant.revoked"

_GRANT_HOOKPOINTS: Final[tuple[str, ...]] = (
    HOOKPOINT_GRANT_REQUESTED,
    HOOKPOINT_GRANT_APPROVED,
    HOOKPOINT_GRANT_DENIED,
    HOOKPOINT_GRANT_REVOKED,
)

# CR-149 round-6: canonical proposal-id shape — 16 lowercase hex
# characters. Mirrors
# :data:`alfred.cli._state_git._PROPOSAL_ID_RE` so the async writer
# and the sync writer share a single validator surface; a future
# tightening of the id namespace lands in one place.
_PROPOSAL_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{16}$")


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Declare the four ``plugin.grant.*`` hookpoints (spec §14).

    Mirrors the Slice-2.5 :mod:`alfred.memory.episodic` /
    :mod:`alfred.identity._ingest` precedent: publishers declare at
    module-init time, and the per-call shim makes the declaration
    discoverable by tests that swap the global registry singleton with
    a fresh instance.

    Spec §14 (hookpoint table): the four ``plugin.grant.*`` events are
    post-only observability stages (no ``pre`` chain, no refusable
    tier set). Subscribers come from the system tier only because the
    grant-lifecycle observers run inside the supervisor process and
    must not be extendable by an untrusted plugin (a user-plugin
    subscriber of ``plugin.grant.approved`` would see every operator
    grant approval -- that's an exfiltration path on its own).

    CR-149 round-3: ``fail_closed=False`` — matches the spec §14
    hookpoint table, which classifies every ``plugin.grant.*`` row as
    ``fail_closed=False``. The trust-boundary audit row that pins the
    grant flow is emitted by the supervisor via
    :meth:`AuditWriter.append_schema` BEFORE any observer chain runs,
    so a crashing observer never hides the reviewer's decision from
    the audit log — the row is already durable. ``fail_closed=False``
    keeps an observer crash from stalling the privileged grant flow
    while the row stays recorded; the ``SYSTEM_ONLY_TIERS`` lock keeps
    untrusted code out of the chain regardless of the fail-closed
    setting. The earlier ``fail_closed=True`` choice
    (``sec-pr-s3-6-05``) was an override that drifted from the spec
    table — the round-3 reviewer pushed back and we follow the spec.

    Idempotent on equal metadata (:meth:`HookRegistry.register_hookpoint`
    semantics) -- re-importing under pytest test isolation is safe.

    Args:
        registry: The :class:`HookRegistry` to declare against.
            Defaults to :func:`get_registry`'s active singleton; tests
            pass the fresh registry explicitly to be unambiguous.
    """
    target = registry if registry is not None else get_registry()
    for hookpoint in _GRANT_HOOKPOINTS:
        target.register_hookpoint(
            name=hookpoint,
            subscribable_tiers=SYSTEM_ONLY_TIERS,
            refusable_tiers=frozenset(),
            fail_closed=False,
        )


async def create_proposal_branch(
    *,
    plugin_id: str,
    subscriber_tier: str,
    hookpoint: str,
    operator_user_id: str,
    backend: StorageBackend,
    audit_sink: _AuditSink,
    content_tier: str | None = None,
) -> str:
    """Queue a reviewer-gated capability-grant proposal.

    Writes a ``proposal/policy-grant-<id>`` branch into state.git via
    :func:`_write_proposal_to_state_git` and emits the
    ``plugin.grant.requested`` audit row. Does NOT touch the
    ``plugin_grants`` Postgres table; the eventual upsert happens
    inside :meth:`RealGate._apply_grants` after the reviewer merges.

    Identifier source: :func:`secrets.token_hex` (16 hex chars from 8
    random bytes). Cryptographically unpredictable per ``secrets`` —
    spec §8.3 implicitly requires this so an adversary who reads one
    branch name from the audit log cannot enumerate or predict future
    proposal IDs. ``uuid.uuid1`` would leak host MAC + timestamp;
    ``uuid.uuid4`` would also work but ``token_hex`` is the canonical
    Python ergonomic for "give me opaque random bytes as a string."

    Ordering: state.git write FIRST, audit row SECOND. If the state.git
    write fails, no audit row emits — the operator gets the raised
    exception and the audit log truthfully shows the proposal never
    landed. The alternative (audit-first) would leave the operator
    believing the proposal exists when the state.git write failed.

    Args:
        plugin_id: MCP plugin identifier (e.g. ``"alfred.web-fetch"``).
        subscriber_tier: ``"system" | "operator" | "user-plugin"`` —
            the hook-subscription axis, NOT a content trust tier
            (spec §4.3 two-axis naming rule).
        hookpoint: dotted action name (e.g. ``"tool.web.fetch"``).
        operator_user_id: canonical user_id of the human operator who
            requested the grant. Carried into the audit row for
            per-operator forensic attribution.
        backend: :class:`StorageBackend` — referenced only to enforce
            the contract that the proposal flow does NOT touch the
            backend. The argument is present so a future refactor that
            wires backend-side coordination (e.g. proposal-status
            cache) does not break the public signature.
        audit_sink: :class:`_AuditSink` — required per err-005.
            CLAUDE.md hard rule #7 forbids the silent audit path; a
            reviewer-gated grant proposal with no audit row leaves the
            flow undocumented.
        content_tier: optional ``T0/T1/T2/T3`` restriction.
            ``None`` = no content-tier restriction (the common case).
            Spec §4.3: orthogonal to subscriber_tier.

    Returns:
        The state.git branch name (``proposal/policy-grant-<hex>``).
        The CLI layer uses this for ``alfred plugin grant status
        <branch>``.

    Raises:
        Any exception from :func:`_write_proposal_to_state_git`.
        Currently the stub never raises; PR-S3-6's gitpython
        integration can surface :class:`OSError` /
        :class:`git.exc.GitError` here.
    """
    # secrets.token_hex(8) yields 16 hex characters — wide enough that
    # collision in a single state.git lifetime is statistically zero.
    # Spec §8.3's reviewer-gate flow assumes the branch namespace is
    # unpredictable; secrets is the canonical Python source. Keeping
    # the unused `backend` argument bound silences ruff ARG002
    # without removing the contract-defending parameter.
    _ = backend
    proposal_id = secrets.token_hex(8)
    branch_name = f"proposal/policy-grant-{proposal_id}"
    correlation_id = str(uuid.uuid4())

    _log.info(
        "capability_gate.proposal.creating",
        plugin_id=plugin_id,
        subscriber_tier=subscriber_tier,
        hookpoint=hookpoint,
        branch_name=branch_name,
    )

    # state.git write FIRST. A raised exception here MUST short-circuit
    # the audit emit — see test_create_proposal_audit_row_emitted_after_state_git_write.
    await _write_proposal_to_state_git(
        branch_name=branch_name,
        plugin_id=plugin_id,
        subscriber_tier=subscriber_tier,
        hookpoint=hookpoint,
        content_tier=content_tier,
        operator_user_id=operator_user_id,
    )

    # CR-149 round-7: ``plugin.grant.requested`` is the operator-typed
    # ingress and MUST land in the T1 swimlane of the audit graph (PRD
    # §7.1 + CLAUDE.md hard rule #3). The schema constant
    # :data:`PLUGIN_GRANT_REQUESTED_FIELDS` is the
    # :data:`PLUGIN_GRANT_FIELDS` superset that adds
    # ``trust_tier_of_trigger`` so :meth:`AuditWriter.append_schema`'s
    # symmetric-key check accepts the tag. Without the tag the row
    # round-trips into the T0 lane alongside the post-merge
    # ``plugin.grant.rebuilt`` row and the operator-attribution
    # forensic signal vanishes.
    await audit_sink.append_schema(
        fields=PLUGIN_GRANT_REQUESTED_FIELDS,
        schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
        event="plugin.grant.requested",
        actor_user_id=operator_user_id,
        subject={
            "plugin_id": plugin_id,
            "subscriber_tier": subscriber_tier,
            "hookpoint": hookpoint,
            "operator_user_id": operator_user_id,
            "proposal_branch": branch_name,
            "correlation_id": correlation_id,
            "trust_tier_of_trigger": "T1",
        },
        trust_tier_of_trigger="T1",
        result="requested",
        cost_estimate_usd=0.0,
        trace_id=correlation_id,
    )

    return branch_name


async def _write_proposal_to_state_git(
    *,
    branch_name: str,
    plugin_id: str,
    subscriber_tier: str,
    hookpoint: str,
    content_tier: str | None,
    operator_user_id: str,
) -> str:
    """Asynchronously write the proposal branch to ``/var/lib/alfred/state.git``.

    ADR-0018 async shim. The previous PR-S3-2 fail-loud
    :class:`NotImplementedError` stub is replaced here with a thin
    bridge to the canonical sync writer
    (:class:`alfred.cli._state_git.StateGitProposalClient`). The shim:

    1. Constructs a :class:`alfred.state.proposal_payloads.PluginGrantProposal`
       — Pydantic validation runs at construction so a typo at the
       call site fails BEFORE state.git is touched.
    2. Pre-derives the proposal id from ``branch_name`` so the sync
       writer produces the exact branch the caller already emitted
       into the audit row.
    3. Awaits :func:`asyncio.to_thread` so the synchronous git
       subprocess sequence runs off the event loop. The bridge is the
       single place async callers cross over to the sync writer; the
       sync surface itself remains the canonical writer (ADR-0018
       Decision 1, Option A).

    PII discipline (CR-139 R2 / sec-pr-s3-6 baseline): ``operator_user_id``
    is canonically an email and MUST NOT appear in the operational
    structlog stream. The structlog redactor does not scrub user
    identifiers; the function logs the length marker instead so an
    operator can still diagnose missing-id bugs without exposing the
    canonical id. The full id lives only in the audit-row fields where
    it belongs.

    The function remains a separate ``async def`` so the proposal-flow
    unit tests can patch it via :func:`unittest.mock.patch` (the
    sync-writer mocking is one layer deeper and noisier). The shim's
    body is small enough that the byte-equality test against
    :meth:`StateGitProposalClient.create_proposal_from_payload`
    suffices to pin the behavioural invariant.

    Args:
        branch_name: full branch name (``proposal/policy-grant-<hex>``)
            — the proposal id is parsed off the suffix so the sync
            writer's branch matches the audit row's exactly.
        plugin_id, subscriber_tier, hookpoint, content_tier,
            operator_user_id: proposal payload fields. Closed-set
            validation runs at the Pydantic model boundary; a bad
            value here raises :class:`pydantic.ValidationError`.

    Returns:
        The state.git branch name actually written by the sync writer.
        Round-trips ``branch_name`` on success — the two MUST match so
        the caller's audit-row branch field is the authoritative
        readout.

    Raises:
        pydantic.ValidationError: if any payload field is outside the
            closed set (typo on subscriber_tier, content_tier, ...).
        StateGitError: from the sync writer on subprocess failure
            (missing repo, push rejected, git binary missing).
    """
    from alfred.cli._state_git import StateGitProposalClient
    from alfred.state.proposal_payloads import PluginGrantProposal

    _log.info(
        "capability_gate.proposal.write_attempted",
        branch_name=branch_name,
        plugin_id=plugin_id,
        subscriber_tier=subscriber_tier,
        hookpoint=hookpoint,
        content_tier=content_tier,
        operator_user_id_len=len(operator_user_id),
    )

    # Pydantic's Literal-bound fields refuse anything outside the
    # closed set. The ``cast`` documents the runtime-safe narrowing —
    # ``subscriber_tier`` and ``content_tier`` are validated by the
    # CLI/manifest layer before reaching this shim, but the cast is
    # the explicit marker so a future caller bypassing that path
    # surfaces the assumption.
    payload = PluginGrantProposal(
        plugin_id=plugin_id,
        subscriber_tier=cast(Literal["system", "operator", "user-plugin"], subscriber_tier),
        hookpoint=hookpoint,
        content_tier=cast(Literal["T0", "T1", "T2", "T3"] | None, content_tier),
        operator_user_id=operator_user_id,
    )

    # Parse the proposal id off the caller-supplied branch name so the
    # sync writer materialises the exact branch the audit row already
    # references. A divergence here would break the audit-graph join.
    expected_prefix = f"proposal/{PluginGrantProposal.proposal_type}-"
    if not branch_name.startswith(expected_prefix):
        msg = (
            f"_write_proposal_to_state_git: branch_name {branch_name!r} "
            f"does not match expected prefix {expected_prefix!r}; refusing "
            "to write a branch the caller's audit row cannot find."
        )
        raise ValueError(msg)
    proposal_id = branch_name[len(expected_prefix) :]
    # CR-149 round-6: validate the suffix shape too. The prefix check
    # accepted anything starting with ``proposal/policy-grant-`` —
    # including an empty suffix, embedded ``/`` (which would escape
    # the canonical ref + grants-tree path), and non-hex characters.
    # On this PRD §7.1 + §8.3 trust-boundary surface a malformed ref
    # would desync the audit branch from the persisted ref, breaking
    # the audit-graph join. Pin the canonical
    # :func:`secrets.token_hex(8)` shape — 16 lowercase hex characters
    # — so the sync writer (which embeds ``proposal_id`` into both
    # the branch name and ``policies/grants/<plugin_id>/<id>.json``)
    # never sees an attacker-controlled or refactor-typo'd value.
    if _PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
        msg = (
            f"_write_proposal_to_state_git: branch_name {branch_name!r} "
            "must end with a 16-character lowercase hex proposal id "
            f"(got suffix {proposal_id!r})."
        )
        raise ValueError(msg)

    client = StateGitProposalClient()
    result = await asyncio.to_thread(
        client.create_proposal_from_payload,
        payload,
        proposal_id=proposal_id,
    )
    return result.branch


# Module-init declaration — spec §6.2 / #119 discipline: publishers
# declare at import time so subscribers registering at module-init
# elsewhere always find the metadata. Idempotent on equal metadata so
# re-importing under pytest test isolation is safe. The PR-S3-6 CLI
# wiring will additionally call :func:`declare_hookpoints` from its
# own entrypoint so a test fixture that swaps :func:`get_registry`'s
# singleton picks up the declaration too.
declare_hookpoints()
