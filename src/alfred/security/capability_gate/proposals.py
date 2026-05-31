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

Implementation status:

* :func:`create_proposal_branch` — PR-S3-2 ships the full proposal-
  creation flow: identifier generation, audit row, and the
  patch-friendly call to :func:`_write_proposal_to_state_git`.
* :func:`_write_proposal_to_state_git` — PR-S3-2 ships a fail-loud
  :class:`NotImplementedError` stub (CR-139 finding #5). PR-S3-6
  replaces the body with the gitpython integration that writes the
  branch into ``/var/lib/alfred/state.git``. The function is kept as
  a separate ``async def`` so the proposal-flow unit and integration
  tests can patch it cleanly; an un-patched call raises so a caller
  cannot accidentally emit ``plugin.grant.requested`` for a branch
  that was never durably written.
"""

from __future__ import annotations

import secrets
import uuid
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

import structlog

from alfred.audit.audit_row_schemas import PLUGIN_GRANT_FIELDS
from alfred.hooks.registry import SYSTEM_ONLY_TIERS, HookRegistry, get_registry

if TYPE_CHECKING:
    from alfred.security.capability_gate.backend import StorageBackend

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


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Declare the four ``plugin.grant.*`` hookpoints (spec §14).

    Mirrors the Slice-2.5 :mod:`alfred.memory.episodic` /
    :mod:`alfred.identity._ingest` precedent: publishers declare at
    module-init time, and the per-call shim makes the declaration
    discoverable by tests that swap the global registry singleton with
    a fresh instance.

    Spec §14 (hookpoint table): the four ``plugin.grant.*`` events are
    post-only observability stages (no ``pre`` chain, no refusable
    tier set), subscribers come from the system tier only because the
    grant-lifecycle observers run inside the supervisor process and
    must not be extendable by an untrusted plugin (a user-plugin
    subscriber of ``plugin.grant.approved`` would see every operator
    grant approval — that's an exfiltration path on its own), and
    ``fail_closed=False`` because a crashing observer must not stall
    a reviewer-approved grant.

    Idempotent on equal metadata (:meth:`HookRegistry.register_hookpoint`
    semantics) — re-importing under pytest test isolation is safe.

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


@runtime_checkable
class _AuditSink(Protocol):
    """Structural seam matching :meth:`AuditWriter.append_schema`.

    Mirrors the same Protocol the :class:`RealGate` audit emit path uses
    — production wires the real :class:`alfred.audit.log.AuditWriter`
    and tests inject a spy with the same shape. Kept private to this
    module so the proposal-flow public surface (just
    :func:`create_proposal_branch` + the stub) does not leak the audit
    subsystem's dependency graph.
    """

    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
    ) -> None:
        raise NotImplementedError  # pragma: no cover


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

    await audit_sink.append_schema(
        fields=PLUGIN_GRANT_FIELDS,
        schema_name="PLUGIN_GRANT_FIELDS",
        event="plugin.grant.requested",
        actor_user_id=operator_user_id,
        subject={
            "plugin_id": plugin_id,
            "subscriber_tier": subscriber_tier,
            "hookpoint": hookpoint,
            "operator_user_id": operator_user_id,
            "proposal_branch": branch_name,
            "correlation_id": correlation_id,
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
    """Write the proposal branch to ``/var/lib/alfred/state.git``.

    DEFERRED-STUB CONTRACT (PR-S3-2 + CR-139 finding #5):

    PR-S3-2 ships this function as a fail-loud
    :class:`NotImplementedError`. The real gitpython implementation
    lands alongside the CLI in PR-S3-6 (``alfred plugin grant``);
    until then, an un-patched call MUST NOT silently succeed: the
    previous structured-log stub returned the branch name unchanged
    and let :func:`create_proposal_branch` emit
    ``plugin.grant.requested`` for a branch that was never durably
    written. The audit row then pointed at a nonexistent branch,
    breaking the PRD §6.4 reviewer-gate flow and the audit-graph
    forensic-traversal guarantee.

    Matches the err-002 shape used by
    :meth:`RealGate.rebuild_from_state_git`: deferred state.git
    integration is loud, never silent (CLAUDE.md hard rule #7). Unit
    tests patch this function via
    :func:`unittest.mock.patch`; the integration tier (which exercises
    the un-patched path) asserts the raise.

    PR-S3-6 replaces the body with::

        repo = git.Repo("/var/lib/alfred/state.git")
        # ... branch + commit ...

    Args:
        branch_name: full branch name (``proposal/policy-grant-<hex>``).
        plugin_id, subscriber_tier, hookpoint, content_tier,
            operator_user_id: proposal payload — written into the
            state.git tree by the PR-S3-6 implementation.

    Raises:
        NotImplementedError: always, until PR-S3-6 wires gitpython.

    Returns:
        The post-fix function never returns under PR-S3-2; the return
        annotation is retained for the PR-S3-6 implementation, which
        will return the resolved branch ref name after the commit
        lands.
    """
    _log.info(
        "capability_gate.proposal.write_attempted",
        branch_name=branch_name,
        plugin_id=plugin_id,
        subscriber_tier=subscriber_tier,
        hookpoint=hookpoint,
        content_tier=content_tier,
        operator_user_id=operator_user_id,
    )
    msg = (
        "_write_proposal_to_state_git requires gitpython state.git "
        "integration (ships in PR-S3-6). Until then this function is a "
        "fail-loud stub; unit tests must patch it before calling "
        "create_proposal_branch."
    )
    raise NotImplementedError(msg)


# Module-init declaration — spec §6.2 / #119 discipline: publishers
# declare at import time so subscribers registering at module-init
# elsewhere always find the metadata. Idempotent on equal metadata so
# re-importing under pytest test isolation is safe. The PR-S3-6 CLI
# wiring will additionally call :func:`declare_hookpoints` from its
# own entrypoint so a test fixture that swaps :func:`get_registry`'s
# singleton picks up the declaration too.
declare_hookpoints()
