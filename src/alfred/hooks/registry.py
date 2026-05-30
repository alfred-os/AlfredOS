"""Hook subsystem registry — Slice-2.5 PR-A Task 6.

The :class:`HookRegistry` is the per-process source of truth for "which
async subscriber runs on which (hookpoint, kind)" at dispatch time.
Tasks 7-13 in this slice register against it via the ``@hook`` decorator
and look up against it from the dispatcher's ``_run_chain`` (Task 10).

Three pieces ship in this module:

* :class:`Subscriber` — a ``frozen=True, slots=True`` carrier holding
  the registered async callable plus the (hookpoint, kind, tier,
  origin_module, registration_seq) metadata the dispatcher needs.
* :class:`HookRegistry` — the keyed-and-ordered store. Constructor
  injects the :class:`alfred.hooks.capability.CapabilityGate` and the
  :class:`alfred.hooks.audit_sink.AuditSink`; the gate gates
  registrations, the sink is the public attribute the dispatcher reads
  for fault-row emissions (alfred-core-engineer-1 resolution).
* :func:`get_registry` / :func:`set_registry` — the module-level
  singleton accessor and swap surface. The @hook decorator registers
  against ``get_registry()``; tests swap a fresh registry in via
  :func:`set_registry` and restore the prior one on teardown (see
  ``tests/unit/hooks/conftest.py``).

Module constants — spec §0 verbatim:

* :data:`HOOK_CHAIN_DEADLINE_SECONDS` — the public per-CHAIN deadline
  the dispatcher wraps every chain in via ``asyncio.timeout(...)``.
  Task 9 owns the wrap; this slice ships the constant so the dispatcher
  imports it from one source of truth.
* :data:`_TIER_RANK` — module-private lookup table for tier-ordering.
  Lower rank runs first within a chain (``system`` → ``operator`` →
  ``user-plugin``).
* :data:`_EMPTY` — module-private shared empty tuple returned on every
  ``subscribers_for`` miss. The identity (not just equality) is what
  pins the no-allocation proof on the hot-path miss branch.

Forward-compat — arch-002 reload semantics (Slice 3): which registry
snapshot an in-flight chain resolves against during a future live
:func:`set_registry` swap is NOT addressed this slice. There is no live
reload in Slice 2.5 — today's only swap caller is the test fixture's
swap-and-restore. The invariant we ship is the narrower one: dropping
a registry instance drops its subscribers. Slice 3's reload subsystem
will layer the in-flight-chain-snapshot semantics over the same
:func:`set_registry` seam without source change here.

Design decision — sink emission on register-time refusal (Option A):

  :meth:`HookRegistry.register` is SYNCHRONOUS — it has no I/O, no
  ``await``, and is called by the ``@hook`` decorator at module import
  time before any event loop exists. The
  :class:`alfred.hooks.audit_sink.AuditSink` Protocol's ``emit`` method
  is async. Reconciling the two would mean either making register
  async (impossible — decorators don't await at import) or scheduling
  the emit on a task (which deadlock-risks bootstrap if no loop is
  running).

  We resolve this by NOT emitting an audit row at register time. A
  capability-gate refusal raises :class:`HookError` LOUDLY (CLAUDE.md
  hard rule #7), and the @hook decorator (Task 7) propagates the
  exception up. The refused registration leaves no trace in the
  registry — fail-closed. Audit rows for refusals are still emitted by
  the dispatcher at DISPATCH time (Tasks 9-12) when a hook denies an
  in-flight action; those emissions happen inside the async dispatcher
  and use ``await sink.emit(...)`` against ``get_registry().sink``.

  This trades audit-attribution at registration time for a clean sync
  register surface. The register-time failure mode is a developer-bug
  shape (sync function passed, wrong tier requested) and surfaces
  loudly through the raised exception — operators do not need an audit
  row for a startup-time configuration error that prevented the
  subscriber from ever running.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from itertools import count
from typing import Any, Final

import structlog

from alfred.hooks.audit_sink import AuditSink, StructlogAuditSink
from alfred.hooks.capability import CapabilityGate, DevGate
from alfred.hooks.context import HookContext, HookKind
from alfred.hooks.errors import (
    HookError,
    hookpoint_drift_message,
    hookpoint_not_declared_message,
    subscriber_must_be_async_message,
    unknown_tier_message,
)

# ──────────────────────────────────────────────────────────────────────
# Module constants — spec §0 verbatim
# ──────────────────────────────────────────────────────────────────────

HOOK_CHAIN_DEADLINE_SECONDS: Final[float] = 0.25
"""Per-chain dispatch deadline in seconds.

The dispatcher (Task 9) wraps every chain in
``asyncio.timeout(HOOK_CHAIN_DEADLINE_SECONDS)``. PUBLIC because the
dispatcher imports the constant directly — pinning it here keeps "one
source of truth" for any future tuning.
"""

_TIER_RANK: Final[dict[str, int]] = {
    "system": 0,
    "operator": 1,
    "user-plugin": 2,
}
"""Tier→rank lookup. Lower rank runs first within a chain.

Module-private because the only legitimate consumer is the in-process
sort in :meth:`HookRegistry.register`. A Slice-3 grant gate that needs
the same ordering imports the constant directly; the underscore is the
hint that it is not part of the registry's public API.
"""


# Forward type alias — the hook function signature. A subscriber is
# always an async callable that takes a :class:`HookContext` and
# returns either ``None`` (the common case — pure side-effect or
# refusal-via-raise) or a new :class:`HookContext` (for the
# carrier-rewrite case, ``pre`` only). PR-B's dispatcher narrows on
# the return shape; the registry stores them uniformly.
type HookFn = Callable[..., Awaitable[HookContext[Any] | None]]


# Module-level monotonic registration counter — ONE source for the
# ``Subscriber.registration_seq`` field across all registries in this
# process. Using :func:`itertools.count` lets us call ``next(...)``
# without holding a lock; CPython's GIL serialises the increment
# atomically. The counter does NOT reset across :meth:`HookRegistry.reset`
# calls — restart would only matter if two subscribers received the
# same seq, and the global counter guarantees uniqueness even across
# reset boundaries.
_seq_counter: count[int] = count()


# ──────────────────────────────────────────────────────────────────────
# Per-task re-entry tracking — used by Task 12's dispatcher
# ──────────────────────────────────────────────────────────────────────

_reentry: ContextVar[tuple[str, ...]] = ContextVar(
    "alfred_hooks_reentry",
    default=(),
)
"""Per-task tuple of ``action_id``s currently mid-dispatch.

Task 12's dispatcher appends the action id before invoking the chain
and pops it on exit; a re-entrant invoke on an action already in the
tuple is short-circuited with a ``HOOKS_REENTRY_BYPASS`` audit row.
The default ``()`` lets the first invoke at any task scope skip an
explicit ``.set(())``.

The ContextVar pattern (not a plain module global) mirrors
:data:`alfred.i18n.translator._active_lang` so concurrent dispatches
across asyncio tasks each see their own re-entry stack — asyncio
propagates ContextVars across ``await`` automatically.
"""


# ──────────────────────────────────────────────────────────────────────
# HookpointMeta — per-hookpoint declaration record (spec §6.2)
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class HookpointMeta:
    """Immutable per-hookpoint declaration carried by the registry.

    A publisher (e.g. :mod:`alfred.memory.episodic`) calls
    :meth:`HookRegistry.register_hookpoint` once at module-init time to
    record this metadata. Subscriber registrations on the same
    hookpoint then consult this record:

    * :attr:`subscribable_tiers` — the allow-list checked at register
      time (issue #119) AND re-checked at dispatch time
      (defense-in-depth against a publisher whose invoke-time arg
      drifts from the declaration). A subscriber whose ``tier`` is not
      in this set is refused at register time with a loud
      :data:`alfred.hooks.audit_sink.HOOKS_TIER_REJECTED` audit row.
    * :attr:`refusable_tiers` — the set of tiers whose
      :class:`alfred.hooks.errors.HookRefusal` propagates as a normal
      refusal on the ``pre`` chain (§6.5). Threaded through to
      :func:`alfred.hooks.invoke.invoke` so the dispatcher's refusal
      arm consults it.
    * :attr:`fail_closed` — the policy bit applied when a subscriber
      times out or raises an unexpected exception. Pinned at
      declaration so a typo at the call site cannot silently disarm
      the fail-closed contract on a security stage.

    Frozen + slots: same hot-path discipline as :class:`Subscriber`.
    The metadata is consulted on every register and every dispatch;
    constructor-only configuration keeps the value semantics clean and
    prevents a subscriber from rewriting the contract at runtime.

    Equality is field-wise (the dataclass default) so the registry can
    detect idempotent re-declaration via ``new == stored`` and
    conflicting re-declaration via ``new != stored``. ``frozenset``
    hashes by content so equality on the two tier-set fields matches
    intuition.

    Attributes:
        name: The dotted hookpoint identifier (e.g.
            ``"memory.episodic.record.before_db_write"``). Carried so
            error messages and audit rows attribute the declaration
            back to a grep-able name.
        subscribable_tiers: The tier allow-list. A subscriber whose
            ``tier`` is not in this set is refused at register time.
        refusable_tiers: The tier set whose :class:`HookRefusal` is
            authorized on the ``pre`` chain (§6.5). Threaded through
            the invoke dispatch on every pre-stage call.
        fail_closed: The policy bit. ``True`` raises
            :class:`HookError` on subscriber timeout / error; ``False``
            rewinds to the last-good ctx and continues the chain.
    """

    name: str
    subscribable_tiers: frozenset[str]
    refusable_tiers: frozenset[str]
    fail_closed: bool


# ──────────────────────────────────────────────────────────────────────
# Subscriber dataclass — spec §3.2
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Subscriber:
    """Immutable record of one registered hook subscriber.

    Carries the registered async callable plus the dispatch metadata
    the chain runner needs. ``frozen=True`` prevents mid-chain mutation
    of the registry's view of any subscriber; ``slots=True`` removes
    the per-instance ``__dict__`` so the hot path stays
    allocation-light.

    Attributes:
        hook_fn: The async callable. Typed as :data:`HookFn` —
            ``Callable[..., Awaitable[HookContext[Any] | None]]`` —
            because pre-hooks may return a rewritten carrier while
            post / error / cancel hooks return ``None``. The
            ``async`` shape is enforced at register time via
            :func:`inspect.iscoroutinefunction`; the runtime contract
            here is "always awaitable".
        hookpoint: The dotted hookpoint identifier the subscriber is
            wired to (e.g. ``"action.memory.episodic.record"``).
        kind: The lifecycle stage — one of ``"pre"`` / ``"post"`` /
            ``"error"`` / ``"cancel"`` (see
            :data:`alfred.hooks.context.HookKind`).
        tier: The trust tier the subscriber requested at registration.
            One of ``"system"`` / ``"operator"`` / ``"user-plugin"``;
            anything else is denied by the capability gate at
            register time.
        origin_module: ``hook_fn.__module__`` captured at register
            time. Slice-3's reload-by-module flow keys off this; the
            audit attribution for every fault row surfaces it as a
            row attribute.
        registration_seq: Monotonic registration counter value. Used
            as the same-tier tie-breaker in
            :meth:`HookRegistry.subscribers_for` so subscribers in the
            same tier dispatch in registration order.
    """

    hook_fn: HookFn
    hookpoint: str
    kind: HookKind
    tier: str
    origin_module: str
    registration_seq: int


# The shared empty tuple — same identity returned by every
# ``subscribers_for`` miss. The miss-path identity assertion in the
# test suite (``found is _EMPTY``) is the no-allocation pin. Defined
# after :class:`Subscriber` so the ``tuple[Subscriber, ...]`` annotation
# resolves cleanly under ``typing.get_type_hints(module)`` — placing it
# above the dataclass works at runtime via ``from __future__ import
# annotations`` but breaks runtime introspection.
_EMPTY: Final[tuple[Subscriber, ...]] = ()


# ──────────────────────────────────────────────────────────────────────
# Public tier-set constants — DevEx polish (#119 review Group F)
# ──────────────────────────────────────────────────────────────────────
#
# Named constants for the three tier-set combinations publishers reach
# for at module-init time. Re-exported from :mod:`alfred.hooks` so
# publishers spell their declarations declaratively (``OPEN_TIERS``
# rather than the inline ``frozenset({...})``).

OPEN_TIERS: Final[frozenset[str]] = frozenset({"system", "operator", "user-plugin"})
"""All three tiers — the open-hookpoint default.

Use for hookpoints with no special security posture (observability,
post-write notification, error-stage chains). A subscriber from any of
the three tiers may register; refusals from any tier propagate.
"""

SYSTEM_OPERATOR_TIERS: Final[frozenset[str]] = frozenset({"system", "operator"})
"""System + operator only — locks user-plugin tiers OUT.

Use for security-stage hookpoints where the action body MUST not be
extended by an untrusted third-party plugin (DLP redaction seam, trust
boundary enforcement, secret-broker substitution). A user-plugin
subscriber attempting to register against a hookpoint declared with
this set is refused at register time and emits
:data:`HOOKS_TIER_REJECTED`.
"""

SYSTEM_ONLY_TIERS: Final[frozenset[str]] = frozenset({"system"})
"""System tier only — the tightest gate.

Use for the most security-sensitive hookpoints (capability-gate
register-time consult, audit-log write authorization). Both operator
and user-plugin tiers are locked out. Typically paired with
``fail_closed=True`` for the timeout / unexpected-exception policy.
"""


# ──────────────────────────────────────────────────────────────────────
# HookRegistry — the per-process keyed-and-ordered store
# ──────────────────────────────────────────────────────────────────────


class HookRegistry:
    """Per-process keyed-and-ordered store of hook subscribers.

    The registry is the single source of truth at dispatch time for
    "which subscriber runs on which (hookpoint, kind)". The class
    exposes three surfaces:

    * :meth:`register` — synchronous, called by the ``@hook`` decorator
      (Task 7) at module import time. Validates the subscriber's shape,
      consults the capability gate, assigns a monotonic
      ``registration_seq``, and inserts the new
      :class:`Subscriber` into the per-(hookpoint, kind) bucket.
    * :meth:`subscribers_for` — synchronous, called by the dispatcher
      (Task 10) on the hot path. Returns the ordered tuple of
      subscribers for a (hookpoint, kind), or the :data:`_EMPTY`
      module singleton on a miss.
    * :meth:`reset` — synchronous, called by the
      :func:`tests.unit.hooks.conftest.fresh_registry` fixture between
      tests for isolation. NOT a production reload path — Slice 3's
      arch-002 reload work owns the real swap semantics.

    Both seams are constructor-injected:

    * ``gate`` — the capability gate consulted at register time. A
      refusal raises :class:`HookError` and leaves no trace in the
      registry. The dev-time default is :class:`DevGate`; Slice-3's
      operator-grant gate slots in here without source change.
    * ``sink`` — the public attribute the dispatcher reads for fault-row
      emissions. PR-A's default is a :class:`StructlogAuditSink` bound
      to ``structlog.get_logger("alfred.hooks")``; PR-B's DB-backed
      sink replaces this attribute at construction time. The
      alfred-core-engineer-1 hardening is that ``self.sink`` is the
      ONLY emission seam — dispatch reads ``get_registry().sink``, not
      a global.

    Design decision — register is sync, no audit on refusal:

      :meth:`register` does NOT emit an audit row on a gate refusal.
      The :class:`AuditSink` Protocol's ``emit`` is async; making
      ``register`` async would break decorator-at-import-time use; so
      ``register`` raises :class:`HookError` LOUDLY (CLAUDE.md hard
      rule #7) and the caller (Task 7's decorator) propagates the
      exception up. Audit rows for refusals are emitted at DISPATCH
      time by Tasks 9-12 — those happen inside the async dispatcher
      and use ``await self.sink.emit(...)``. See the module docstring
      for the full rationale.

    The registry instance itself is NOT frozen — :meth:`register` and
    :meth:`reset` mutate the internal ``_subscribers`` dict and the
    seq counter. The constructor is hand-rolled (not a dataclass)
    because the default :class:`StructlogAuditSink` needs a structlog
    logger that we lazily fetch at construction time — dataclass-level
    defaults evaluate at class-definition time, which is too early to
    bind a logger handle without risking import-cycle surprises.
    """

    gate: CapabilityGate
    sink: AuditSink
    chain_deadline_seconds: float
    strict_declarations: bool
    _subscribers: dict[tuple[str, HookKind], list[Subscriber]]
    _hookpoints: dict[str, HookpointMeta]

    def __init__(
        self,
        *,
        gate: CapabilityGate,
        sink: AuditSink | None = None,
        chain_deadline_seconds: float = HOOK_CHAIN_DEADLINE_SECONDS,
        strict_declarations: bool = True,
    ) -> None:
        """Construct a :class:`HookRegistry`.

        Args:
            gate: The capability gate consulted at register time.
                Keyword-only.
            sink: The :class:`AuditSink` the dispatcher emits fault
                rows through. Keyword-only; defaults to a fresh
                :class:`StructlogAuditSink` bound to
                ``structlog.get_logger("alfred.hooks")``.
            chain_deadline_seconds: Per-CHAIN deadline (Task 9). The
                dispatcher reads ``get_registry().chain_deadline_seconds``
                on every chain entry and wraps the walk in
                ``asyncio.timeout(...)`` against this value. Defaults to
                the module-level :data:`HOOK_CHAIN_DEADLINE_SECONDS`
                (0.25 seconds — the production default from spec §5).
                Keyword-only. INTENDED ONLY as a test-and-bootstrap seam:
                CI flake-free fault tests inject ``~0.01s`` so a
                never-firing ``asyncio.Event`` trips deterministically;
                PR-B's adversarial corpus tunes per-test; production
                code does NOT swap this at runtime. Slice 3's
                arch-002 reload subsystem owns the hot-reload semantics.
            strict_declarations: SECURITY-CRITICAL — production code
                paths MUST use ``True`` (the default). Setting this to
                ``False`` SILENTLY DISABLES BOTH halves of the #119
                enforcement: the register-time tier-allowlist check
                (this method) AND the dispatch-time defense-in-depth
                re-check (:func:`alfred.hooks.invoke._enforce_subscribable_tiers`).
                A subscriber whose tier is NOT in the publisher's
                declared ``subscribable_tiers`` registers cleanly and
                runs at dispatch — defeating the whole purpose of the
                security stage.

                This parameter exists ONLY as a transitional opt-out
                for the pre-#119 unit-test corpus, which registers
                against ad-hoc hookpoint names without an explicit
                :meth:`register_hookpoint` declaration. Tests that
                genuinely need the non-strict mode use the
                :func:`strict_registry`-or-:func:`fresh_registry`
                fixture composition.

                The non-strict opt-out literal MUST NOT appear
                anywhere in ``src/``. The CI lint at
                ``scripts/check_strict_declarations.py`` enforces this
                — adding the false-valued keyword literal anywhere in
                ``src/`` fails the build. Keyword-only.

        The sink default is lazily constructed inside ``__init__``
        rather than at the parameter default site because
        :class:`StructlogAuditSink` itself requires a logger argument
        (intentional — see its docstring). Building a fresh default
        per-registry also makes the test fixture's swap-and-restore
        observably distinct from the production singleton.
        """
        self.gate = gate
        self.sink = (
            sink
            if sink is not None
            else StructlogAuditSink(logger=structlog.get_logger("alfred.hooks"))
        )
        self.chain_deadline_seconds = chain_deadline_seconds
        self.strict_declarations = strict_declarations
        self._subscribers = {}
        self._hookpoints = {}

    def register_hookpoint(
        self,
        *,
        name: str,
        subscribable_tiers: frozenset[str],
        refusable_tiers: frozenset[str],
        fail_closed: bool,
    ) -> None:
        """Declare a hookpoint's per-hookpoint metadata (#119).

        Publishers MUST call this once at module-init time for every
        hookpoint they own BEFORE any subscriber registers against it.
        The stored :class:`HookpointMeta` is consulted by
        :meth:`register` (registration-time tier-allowlist check) and
        by :func:`alfred.hooks.invoke.invoke` (dispatch-time
        defense-in-depth re-check, commit 3 in this PR).

        Idempotent on equal metadata, strict on different metadata:

        * Calling ``register_hookpoint(name="x", subscribable_tiers=A, ...)``
          twice with identical args succeeds both times. This makes
          re-importing a publisher module (pytest test isolation,
          Slice-3's reload-by-module flow) safe.
        * Calling it with DIFFERENT args raises :class:`HookError`. Two
          shapes this defends against:

          - Publisher version drift — two versions of the same module
            land in one process and disagree on the metadata. Silent
            last-import-wins acceptance would be a surprise vector.
          - Publisher typo on a metadata field (e.g. flipping
            ``fail_closed`` on a security-tier hookpoint). Loud
            refusal forces the author to reconcile both sites.

        The error message attributes the hookpoint name + which field
        drifted so the operator can grep both declaration sites.

        Synchronous on purpose — the same module-init-time discipline
        as :meth:`register`. Publishers declare at import; no event
        loop required.

        Args:
            name: The dotted hookpoint identifier (e.g.
                ``"memory.episodic.record.before_db_write"``).
                Keyword-only — matches the rest of the registry's
                surface (``register``, the ``HookRegistry``
                constructor) so a silent argument-order regression at
                the call site is impossible (#119 review Group J).
            subscribable_tiers: The tier allow-list for subscriber
                registration. Keyword-only.
            refusable_tiers: The tier set whose :class:`HookRefusal`
                propagates as a normal refusal on the ``pre`` chain
                (§6.5). Keyword-only.
            fail_closed: The fail-closed policy for subscriber timeout
                / unexpected exception. Keyword-only.

        Raises:
            HookError: A previous declaration of ``name`` exists with
                metadata that does not equal the new declaration.
        """
        new_meta = HookpointMeta(
            name=name,
            subscribable_tiers=subscribable_tiers,
            refusable_tiers=refusable_tiers,
            fail_closed=fail_closed,
        )
        stored = self._hookpoints.get(name)
        if stored is not None and stored != new_meta:
            # Conflicting declaration — attribute the drift so the
            # operator can grep both sites. CLAUDE.md hard rule #7:
            # loud failure, no silent acceptance of "last import wins".
            # Message routes through :func:`alfred.hooks.errors.hookpoint_drift_message`
            # so the operator-facing text is i18n-localised (CLAUDE.md
            # i18n rule #1).
            raise HookError(hookpoint_drift_message(name=name, stored=stored, new=new_meta))
        self._hookpoints[name] = new_meta

    def hookpoint_meta(self, name: str) -> HookpointMeta | None:
        """Return the declared :class:`HookpointMeta` for ``name``, or
        ``None`` if no declaration exists.

        The dispatch-time defense-in-depth re-check (commit 3) consults
        this — a ``None`` return signals "publisher bypassed the
        ``register_hookpoint`` contract entirely", which is a publisher
        bug surfaced loudly via the audit row.

        Args:
            name: The dotted hookpoint identifier to look up.

        Returns:
            The stored :class:`HookpointMeta` instance, or ``None`` if
            no publisher has declared ``name``.
        """
        return self._hookpoints.get(name)

    def register(
        self,
        *,
        hook_fn: HookFn,
        hookpoint: str,
        kind: HookKind,
        tier: str,
    ) -> None:
        """Register a hook subscriber.

        Synchronous on purpose — the ``@hook`` decorator (Task 7)
        calls this at module import time, before any event loop
        exists. See the class docstring for the no-audit-on-refusal
        design decision.

        Validation order (each failure raises :class:`HookError`
        LOUDLY — no silent failure):

        1. ``hook_fn`` must be a coroutine function. A sync callable
           raises with the catalog-rendered
           ``hooks.subscriber_must_be_async`` message via
           :func:`alfred.hooks.errors.subscriber_must_be_async_message`.
        2. The capability gate must grant the requested ``tier``. A
           refusal raises :class:`HookError` and the registration
           leaves no trace.

        On success: assigns a fresh ``registration_seq`` from the
        module-level monotonic counter, captures
        ``hook_fn.__module__`` as ``origin_module``, and inserts the
        :class:`Subscriber` into the per-(hookpoint, kind) bucket,
        keeping the bucket sorted by
        ``(_TIER_RANK[tier], registration_seq)``.

        Args:
            hook_fn: The async callable to register. MUST be a
                coroutine function (``async def``); a sync callable
                raises at the call site here, not at dispatch.
            hookpoint: The dotted hookpoint identifier
                (e.g. ``"action.memory.episodic.record"``). The
                dispatcher keys lookup on the (hookpoint, kind) pair.
            kind: The lifecycle stage — one of the four
                :data:`alfred.hooks.context.HookKind` literals.
            tier: The trust tier the subscriber requests. One of
                ``"system"`` / ``"operator"`` / ``"user-plugin"``;
                anything else is denied by the gate.

        Raises:
            HookError: If ``hook_fn`` is not a coroutine function or
                the capability gate refuses the requested ``tier``.
        """
        if not inspect.iscoroutinefunction(hook_fn):
            # Hard rule #7 — loud refusal, i18n-rendered message.
            raise HookError(subscriber_must_be_async_message(name=hook_fn.__qualname__))

        # Tier validation BEFORE the gate consult, BEFORE any bucket
        # mutation. The sort step below keys on ``_TIER_RANK[s.tier]``
        # and would raise :class:`KeyError` for an unknown tier — but by
        # then we've already appended to the bucket, leaving the registry
        # in a partially-populated state on a failing register call.
        # That violates fail-closed (CLAUDE.md hard rule #7: no silent
        # failures, no partial commits in security paths) and fail-loud
        # (the operator sees a cryptic ``KeyError`` instead of an
        # explicit tier-validation message). Raising :class:`HookError`
        # up-front keeps the registry's invariant intact: a failed
        # register MUST leave no trace. The known-tier gate (operator
        # /user-plugin/system) is the same set ``DevGate`` knows about
        # — anything else is a developer-bug shape (typo, copy-paste
        # error) and surfaces here with attribution to ``hook_fn`` and
        # ``hookpoint``.
        if tier not in _TIER_RANK:
            raise HookError(
                unknown_tier_message(
                    tier=tier,
                    subscriber_name=hook_fn.__qualname__,
                    hookpoint=hookpoint,
                    valid_tiers=_TIER_RANK,
                )
            )

        # Strict-declaration gate (#119). A publisher MUST have
        # declared the hookpoint via :meth:`register_hookpoint` before
        # subscribers may register. Refusal surfaces a typo on the
        # publisher's hookpoint name (which would otherwise silently
        # disable the security stage by sending subscribers to a
        # never-invoked name). Permissive mode (``strict_declarations=
        # False``) is for the pre-#119 test corpus; production code
        # paths construct the singleton with the default ``True``.
        # Message routes through
        # :func:`alfred.hooks.errors.hookpoint_not_declared_message`,
        # which carries publisher/subscriber attribution + a
        # difflib-driven closest-match suggestion (Group F).
        if self.strict_declarations and hookpoint not in self._hookpoints:
            raise HookError(
                hookpoint_not_declared_message(
                    name=hookpoint,
                    declared_names=self._hookpoints.keys(),
                )
            )

        # Capability gate consult. The DevGate ignores plugin_id and
        # hookpoint this slice; Slice-3's grant gate consults all three.
        # Passing ``hook_fn.__module__`` as ``plugin_id`` is the
        # default attribution shape (a Slice-3 grant gate keyed by
        # plugin id will read it; the dev gate ignores it).
        if not self.gate.check(
            plugin_id=hook_fn.__module__,
            hookpoint=hookpoint,
            requested_tier=tier,
        ):
            # No audit row here — see class docstring (Option A).
            raise HookError(
                f"Capability gate refused tier {tier!r} for {hook_fn.__qualname__} "
                f"on hookpoint {hookpoint!r}."
            )

        sub = Subscriber(
            hook_fn=hook_fn,
            hookpoint=hookpoint,
            kind=kind,
            tier=tier,
            origin_module=hook_fn.__module__,
            registration_seq=next(_seq_counter),
        )

        bucket = self._subscribers.setdefault((hookpoint, kind), [])
        bucket.append(sub)
        # Sort on every insert so :meth:`subscribers_for` is a pure
        # lookup. The bucket is small per (hookpoint, kind) — N here
        # is "how many hooks subscribe to this stage", typically < 10
        # — so the O(N log N) on insert is irrelevant next to the
        # dispatcher's per-chain async overhead. ``_TIER_RANK[s.tier]``
        # is safe here because the tier-validation gate above rejected
        # any unknown tier before reaching this point.
        bucket.sort(key=lambda s: (_TIER_RANK[s.tier], s.registration_seq))

    def subscribers_for(
        self,
        hookpoint: str,
        kind: HookKind,
    ) -> tuple[Subscriber, ...]:
        """Return the ordered tuple of subscribers for (hookpoint, kind).

        Hot-path lookup called by the dispatcher (Task 10) once per
        action-stage. Returns:

        * The :data:`_EMPTY` module singleton on a miss — IDENTITY-stable
          across every miss so the dispatcher's miss branch pays no
          allocation. The test suite asserts ``result is _EMPTY``.
        * A frozen tuple snapshot of the bucket on a hit. The tuple
          is freshly built per call (the underlying list is mutable
          and the registry could grow between this call and the next);
          the dispatcher iterates the snapshot synchronously before
          first ``await`` so this is safe.

        Args:
            hookpoint: The dotted hookpoint identifier to look up.
            kind: The lifecycle stage to look up.

        Returns:
            Ordered tuple of :class:`Subscriber` instances, sorted by
            ``(_TIER_RANK[tier], registration_seq)``. Empty
            (:data:`_EMPTY` singleton) on a miss.
        """
        bucket = self._subscribers.get((hookpoint, kind))
        if not bucket:
            return _EMPTY
        return tuple(bucket)

    def reset(self) -> None:
        """Clear every registered subscriber AND every hookpoint
        declaration.

        Used by the :func:`tests.unit.hooks.conftest.fresh_registry`
        fixture for per-test isolation inside a single registry
        instance. NOT a production reload path — the
        registration_seq counter is module-level and continues
        monotonic across resets to preserve global uniqueness.

        The hookpoint declaration map is cleared too so a test that
        reuses a registry instance across declaration scenarios sees a
        clean slate. The two stores are conceptually a single
        invariant ("what this registry knows about hookpoints and the
        subscribers wired to them"); resetting one without the other
        would leave the registry in an inconsistent state where
        :meth:`hookpoint_meta` and :meth:`subscribers_for` disagree.
        """
        self._subscribers.clear()
        self._hookpoints.clear()


# ──────────────────────────────────────────────────────────────────────
# Module-level singleton accessors
# ──────────────────────────────────────────────────────────────────────

_registry: HookRegistry | None = None
"""The active per-process :class:`HookRegistry` singleton.

Lazily constructed on first :func:`get_registry` call. Swapped in and
out by :func:`set_registry` — the test fixture's
swap-and-restore is the only legitimate swap caller this slice.
Module-private; do not read directly.
"""


def get_registry() -> HookRegistry:
    """Return the active :class:`HookRegistry` singleton.

    Lazily constructs the default registry on first call — a
    :class:`HookRegistry` with a default :class:`DevGate` (deny
    ``system`` tier) and the registry's own default
    :class:`StructlogAuditSink` bound to
    ``structlog.get_logger("alfred.hooks")``.

    Subsequent calls return the same instance until
    :func:`set_registry` swaps it. The ``@hook`` decorator (Task 7)
    registers against the result of this call at module import time;
    the dispatcher (Task 10) reads ``get_registry().sink`` on every
    fault-row emission.
    """
    global _registry
    if _registry is None:
        _registry = HookRegistry(gate=DevGate())
    return _registry


def set_registry(registry: HookRegistry) -> None:
    """Install ``registry`` as the active singleton.

    The test fixture's swap-and-restore is the only legitimate caller
    this slice — production code does NOT swap registries at runtime
    (arch-002 reload semantics land in Slice 3). The contract: the
    next :func:`get_registry` call returns ``registry``; a subsequent
    :func:`set_registry` call swaps to whatever the caller passes.

    No event-loop hop, no notification — Slice 3's reload subsystem
    will layer the in-flight-chain-snapshot semantics over this same
    seam without source change here.
    """
    global _registry
    _registry = registry
