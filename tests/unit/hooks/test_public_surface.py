"""Tests for ``alfred.hooks`` — the public-surface lock (spec §3.1).

Pins the exact 16-symbol public surface of the hooks subsystem. The lock is
load-bearing for three independent reasons:

* **sec-008** — ``_invoke_internal`` is the privileged bypass path used by the
  re-entry guard's reentrant calls. It MUST NOT be exported. The Task-12
  runtime defensive guard (``_REENTRY_BYPASS_AUDIT_FIELDS``) is belt-and-braces;
  this test is the public-API lock that an external caller cannot import the
  bypass at all.
* **Stability contract** — PR-B's ``EpisodicAuditSink`` and the orchestrator's
  dispatch site both depend on the public surface staying exactly the spec'd
  shape. A spec-conforming downstream consumer should never need to import
  from ``alfred.hooks.invoke`` or ``alfred.hooks.registry`` — the top-level
  package is the contract.
* **Trust-boundary discipline** (CLAUDE.md §8) — the 100% line+branch coverage
  gate for the hooks subsystem (wired in CI alongside this PR) protects the
  invariants this test pins. The two together — public surface ∧ 100% — are
  the durable contract.

Spec verbatim (§3.1) lists 14 names; PR-S3-7 (spec §15.1) drops ``DevGate``
in the flag-day removal, leaving 13 base symbols. #119 review Group F adds 3
publisher-facing tier-set constants (``OPEN_TIERS``, ``SYSTEM_OPERATOR_TIERS``,
``SYSTEM_ONLY_TIERS``) bringing the post-PR-S3-7 total to 16. Anything else — ``Flow`` (only
reachable via ``invoking()`` per Task-13's M-3 discussion), ``Subscriber`` (the
registry's internal carrier; introspection callers reach into
``alfred.hooks.registry``), ``StructlogAuditSink`` (the default
implementation; PR-B replaces with ``EpisodicAuditSink`` and constructs via
``alfred.hooks.audit_sink``), and the six ``HOOKS_*`` event-name constants
(used by the dispatcher; downstream sinks import from
``alfred.hooks.audit_sink``) — stays out of ``__all__`` deliberately.
"""

from __future__ import annotations

import importlib
from typing import Final

import pytest

import alfred.hooks as hooks_pkg

# ──────────────────────────────────────────────────────────────────────
# The canonical 16-symbol public surface (spec §3.1 minus DevGate, plus
# #119 review Group F tier constants — post-PR-S3-7)
# ──────────────────────────────────────────────────────────────────────
#
# Sorted alphabetically — the canonical order ``ruff`` (RUF022) enforces on
# ``__all__``. Categories overlap (e.g. ``HookError`` is both a type and an
# exception); alphabetical removes the bikeshed and makes drift visible.
EXPECTED_PUBLIC_SURFACE: Final[frozenset[str]] = frozenset(
    {
        "AuditSink",
        "CapabilityGate",
        "HookContext",
        "HookError",
        "HookKind",
        "HookRefusal",
        "HookRegistry",
        "HookSubscriberError",
        "OPEN_TIERS",
        "SYSTEM_ONLY_TIERS",
        "SYSTEM_OPERATOR_TIERS",
        "get_registry",
        "hook",
        "invoke",
        "invoking",
        "set_registry",
    }
)


# ──────────────────────────────────────────────────────────────────────
# 1. ``__all__`` equals the 16-symbol post-PR-S3-7 surface, exactly
# ──────────────────────────────────────────────────────────────────────


def test_all_contains_exactly_the_spec_surface() -> None:
    """``alfred.hooks.__all__`` equals the 16-symbol public surface (post-PR-S3-7).

    Set-equality, not subset — adding a 17th symbol is a spec change
    and must fail this test. The reverse failure (missing a symbol)
    catches accidental deletion during refactors. The 16 symbols are
    13 base (spec §3.1's 14 minus ``DevGate``, removed in the PR-S3-7
    flag-day per spec §15.1) plus 3 tier-set constants (``OPEN_TIERS``,
    ``SYSTEM_OPERATOR_TIERS``, ``SYSTEM_ONLY_TIERS``) added in `#119`
    review Group F.
    """
    assert set(hooks_pkg.__all__) == EXPECTED_PUBLIC_SURFACE


def test_all_has_no_duplicates() -> None:
    """``__all__`` is a list with no duplicate entries.

    Duplicate entries would silently pass ``set(__all__) ==`` but would
    indicate a refactor mistake (e.g. moved a symbol and forgot to delete the
    old line). Length comparison catches it.
    """
    assert len(hooks_pkg.__all__) == len(set(hooks_pkg.__all__))
    assert len(hooks_pkg.__all__) == len(EXPECTED_PUBLIC_SURFACE)


# ──────────────────────────────────────────────────────────────────────
# 2. Every name in ``__all__`` actually imports
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(EXPECTED_PUBLIC_SURFACE))
def test_every_exported_name_resolves(name: str) -> None:
    """Each ``__all__`` entry resolves to a real attribute on the package.

    Catches the "added to ``__all__`` but forgot the re-export" failure mode:
    Python's wildcard-import machinery would silently surface an
    ``AttributeError`` only when somebody actually did ``from alfred.hooks
    import *``; pinning the lookup here makes drift loud at unit-test time.
    """
    assert hasattr(hooks_pkg, name), f"alfred.hooks does not re-export {name!r}"
    # Resolving via ``getattr`` exercises the import machinery (a missing
    # re-export raises ``AttributeError`` here even though ``__all__`` lists
    # the name).
    obj = getattr(hooks_pkg, name)
    assert obj is not None


# ──────────────────────────────────────────────────────────────────────
# 3. The re-exports are the same objects as the submodule originals
# ──────────────────────────────────────────────────────────────────────
#
# This is the "no accidental re-binding" invariant. ``from alfred.hooks
# import HookContext`` and ``from alfred.hooks.context import HookContext``
# MUST return the same object so isinstance/issubclass + ``is`` checks across
# the codebase remain consistent.


def test_reexports_are_identity_equal_to_submodule_origins() -> None:
    """Every re-exported symbol is the exact submodule object (``is``-equal).

    Pins the import shape: ``alfred.hooks.HookContext is
    alfred.hooks.context.HookContext``. A second binding (e.g. a wrapper
    class) would break ``isinstance(..., HookContext)`` for downstream
    callers that mixed import styles.
    """
    from alfred.hooks.audit_sink import AuditSink
    from alfred.hooks.capability import CapabilityGate
    from alfred.hooks.context import HookContext, HookKind
    from alfred.hooks.decorators import hook
    from alfred.hooks.errors import HookError, HookRefusal, HookSubscriberError
    from alfred.hooks.invoke import invoke, invoking
    from alfred.hooks.registry import (
        OPEN_TIERS,
        SYSTEM_ONLY_TIERS,
        SYSTEM_OPERATOR_TIERS,
        HookRegistry,
        get_registry,
        set_registry,
    )

    assert hooks_pkg.AuditSink is AuditSink
    assert hooks_pkg.CapabilityGate is CapabilityGate
    assert hooks_pkg.HookContext is HookContext
    assert hooks_pkg.HookKind is HookKind
    assert hooks_pkg.HookError is HookError
    assert hooks_pkg.HookRefusal is HookRefusal
    assert hooks_pkg.HookSubscriberError is HookSubscriberError
    assert hooks_pkg.HookRegistry is HookRegistry
    assert hooks_pkg.get_registry is get_registry
    assert hooks_pkg.set_registry is set_registry
    assert hooks_pkg.hook is hook
    assert hooks_pkg.invoke is invoke
    assert hooks_pkg.invoking is invoking
    assert hooks_pkg.OPEN_TIERS is OPEN_TIERS
    assert hooks_pkg.SYSTEM_OPERATOR_TIERS is SYSTEM_OPERATOR_TIERS
    assert hooks_pkg.SYSTEM_ONLY_TIERS is SYSTEM_ONLY_TIERS


# ──────────────────────────────────────────────────────────────────────
# 4. No private symbol is re-exported (sec-008)
# ──────────────────────────────────────────────────────────────────────
#
# These names are the privileged internals of the hooks subsystem. Exporting
# any of them collapses the trust boundary spec §6.9 and sec-008 establish:
#
# * ``_invoke_internal``    — the re-entry bypass path (sec-008 critical)
# * ``_run_pre`` / ``_run_post`` / ``_run_error`` / ``_run_cancel``
#                          — per-kind dispatch handlers (Tasks 8-11)
# * ``_run_chain``          — historical name; if it ever exists must not leak
# * ``_handle_chain_timeout`` — pre-chain deadline handler (Task 9)
# * ``_dispatch_by_kind``   — kind-fan-out (Task 12)
# * ``_spawn_subscriber``   — per-subscriber task spawner (Task 11)
# * ``_EMPTY``              — singleton empty-tuple sentinel (registry.py)
# * ``_TIER_RANK``          — tier ordering lookup (registry.py)
# * ``_reentry``            — ContextVar for the re-entry guard (registry.py)
# * ``_REFUSAL_AUDIT_FIELDS`` / ``_CHAIN_TIMEOUT_AUDIT_FIELDS`` /
#   ``_SUBSCRIBER_ERROR_AUDIT_FIELDS`` / ``_REENTRY_BYPASS_AUDIT_FIELDS``
#                          — audit schema constants (invoke.py); downstream
#                            sinks bind by event-name string, not by importing
#                            the schema.
# * ``_CLEANUP_DEADLINE_SECONDS`` — cleanup deadline private to invoke.py
# * ``_seq_counter``        — registration counter (registry.py)
PRIVATE_NAMES: Final[tuple[str, ...]] = (
    "_invoke_internal",
    "_run_pre",
    "_run_post",
    "_run_error",
    "_run_cancel",
    "_run_chain",
    "_handle_chain_timeout",
    "_dispatch_by_kind",
    "_spawn_subscriber",
    "_EMPTY",
    "_TIER_RANK",
    "_reentry",
    "_REFUSAL_AUDIT_FIELDS",
    "_CHAIN_TIMEOUT_AUDIT_FIELDS",
    "_SUBSCRIBER_ERROR_AUDIT_FIELDS",
    "_REENTRY_BYPASS_AUDIT_FIELDS",
    "_CLEANUP_DEADLINE_SECONDS",
    "_seq_counter",
)


@pytest.mark.parametrize("name", PRIVATE_NAMES)
def test_private_internals_not_exported(name: str) -> None:
    """No private symbol leaks through the top-level ``alfred.hooks`` namespace.

    Two layers of check:

    1. The symbol is not in ``__all__`` — wildcard imports cannot reach it.
    2. The symbol is not an attribute of the package — even direct
       ``from alfred.hooks import _invoke_internal`` fails with
       ``ImportError`` (the canonical Python import-error type for missing
       names from a package).

    The second check is the load-bearing one for sec-008: a malicious or
    careless plugin author MUST NOT be able to grab the bypass by typing its
    name.
    """
    assert name not in hooks_pkg.__all__, (
        f"{name!r} is private; must not appear in alfred.hooks.__all__"
    )
    assert not hasattr(hooks_pkg, name), (
        f"{name!r} leaked onto the alfred.hooks package namespace; "
        f"remove the re-export or rename the symbol"
    )


def test_invoke_internal_import_fails() -> None:
    """``from alfred.hooks import _invoke_internal`` raises ImportError.

    The sec-008 anchor test. ``__init__.py`` must not bind the bypass at the
    top-level package, so a ``from alfred.hooks import _invoke_internal``
    statement (which Python translates to
    ``getattr(alfred.hooks, '_invoke_internal')`` after the module loads)
    raises ``ImportError`` per
    https://docs.python.org/3/reference/import.html#submodules. We exercise
    the same import-machinery via :func:`importlib.import_module` +
    :func:`getattr` rather than a literal ``from ... import`` because ruff's
    naming-convention lints (N811/N813) fire on the ``as _unused`` alias
    pattern; the equivalent runtime check is cleaner.
    """
    mod = importlib.import_module("alfred.hooks")
    with pytest.raises(AttributeError):
        # ``from alfred.hooks import _invoke_internal`` is equivalent to
        # ``getattr(mod, '_invoke_internal')`` after the module loads; the
        # missing attribute raises ``AttributeError`` which the import
        # statement re-wraps as ``ImportError``. Asserting on the inner
        # ``AttributeError`` pins the same invariant without the alias.
        _ = mod._invoke_internal  # type: ignore[attr-defined]


# ──────────────────────────────────────────────────────────────────────
# 5. Non-exported public-ish helpers are NOT in ``__all__``
# ──────────────────────────────────────────────────────────────────────
#
# These exist as module-level public symbols on their submodules — callers
# who genuinely need them import from the submodule. But they are NOT in
# ``alfred.hooks.__all__``:
#
# * ``Flow``               — Task 13's M-3 decision pinned this as internal;
#                            ``invoking()`` is the public seam.
# * ``Subscriber``         — registry's internal dataclass; introspection
#                            callers import from ``alfred.hooks.registry``.
# * ``StructlogAuditSink`` — default implementation of the ``AuditSink``
#                            protocol; PR-B will replace with
#                            ``EpisodicAuditSink``. Constructing one
#                            requires the explicit submodule import.
# * Six ``HOOKS_*`` event-name constants — downstream sinks reference these
#                            via ``alfred.hooks.audit_sink``.
# * ``HOOK_CHAIN_DEADLINE_SECONDS`` — public per Task 6 docstring, but not
#                            in the spec §3.1 surface; subscribers who want
#                            to introspect the default deadline import from
#                            ``alfred.hooks.registry``.
NON_EXPORTED_PUBLIC_NAMES: Final[tuple[str, ...]] = (
    "Flow",
    "Subscriber",
    "HookpointMeta",
    "StructlogAuditSink",
    "HOOKS_REFUSAL",
    "HOOKS_CHAIN_TIMEOUT",
    "HOOKS_SUBSCRIBER_ERROR",
    "HOOKS_ERROR_SUPPRESSED",
    "HOOKS_UNAUTHORIZED_REFUSAL",
    "HOOKS_REENTRY_BYPASS",
    "HOOKS_TIER_REJECTED",
    "HOOK_CHAIN_DEADLINE_SECONDS",
)


@pytest.mark.parametrize("name", NON_EXPORTED_PUBLIC_NAMES)
def test_non_exported_public_names_not_in_all(name: str) -> None:
    """Public-ish helpers stay submodule-only by design.

    These names exist (and tests in other modules import them directly from
    their submodules), but the top-level ``alfred.hooks`` package
    deliberately does not re-export them. Pinning that decision here keeps
    the public surface tight against scope creep.
    """
    assert name not in hooks_pkg.__all__, (
        f"{name!r} is submodule-only by design; "
        f"remove from alfred.hooks.__all__ (see test docstring for rationale)"
    )


def test_flow_import_fails_at_top_level() -> None:
    """``from alfred.hooks import Flow`` raises ImportError.

    Task-13's security M-3 discussion pinned this: ``Flow`` is the internal
    receipt-pattern carrier; ``invoking()`` is the public seam. A direct
    import of ``Flow`` from the top-level package would let downstream code
    construct flows outside the context manager's lifecycle — defeating the
    cancel-before-error ordering guarantee. We exercise the import-machinery
    invariant via ``getattr`` rather than a literal ``from ... import ... as
    _unused`` because ruff's N811/N813 (naming-convention) lints fire on the
    alias form; the equivalent runtime check is cleaner.
    """
    mod = importlib.import_module("alfred.hooks")
    with pytest.raises(AttributeError):
        _ = mod.Flow  # type: ignore[attr-defined]


def test_subscriber_import_fails_at_top_level() -> None:
    """``from alfred.hooks import Subscriber`` raises ImportError.

    Downstream code that needs to introspect registered subscribers (tests,
    PR-B's audit sink) imports from ``alfred.hooks.registry`` directly. See
    :func:`test_flow_import_fails_at_top_level` for the rationale behind
    the ``getattr`` form.
    """
    mod = importlib.import_module("alfred.hooks")
    with pytest.raises(AttributeError):
        _ = mod.Subscriber  # type: ignore[attr-defined]


def test_structlog_audit_sink_import_fails_at_top_level() -> None:
    """``from alfred.hooks import StructlogAuditSink`` raises ImportError.

    The implementation is reached via ``alfred.hooks.audit_sink``. The
    public surface is the ``AuditSink`` Protocol; PR-B's
    ``EpisodicAuditSink`` will satisfy the same Protocol and replace the
    default at the dispatch site. See
    :func:`test_flow_import_fails_at_top_level` for the rationale behind
    the ``getattr`` form.
    """
    mod = importlib.import_module("alfred.hooks")
    with pytest.raises(AttributeError):
        _ = mod.StructlogAuditSink  # type: ignore[attr-defined]


def test_hooks_event_constants_import_fails_at_top_level() -> None:
    """``from alfred.hooks import HOOKS_REFUSAL`` raises ImportError.

    Audit-sink implementations bind event-name strings via the
    ``alfred.hooks.audit_sink`` submodule. The constants are not part of
    the spec §3.1 surface. See :func:`test_flow_import_fails_at_top_level`
    for the rationale behind the ``getattr`` form.
    """
    mod = importlib.import_module("alfred.hooks")
    with pytest.raises(AttributeError):
        _ = mod.HOOKS_REFUSAL  # type: ignore[attr-defined]


# ──────────────────────────────────────────────────────────────────────
# 6. Exported types resolve to the expected shapes (smoke checks)
# ──────────────────────────────────────────────────────────────────────


def test_exported_callables_are_callable() -> None:
    """Decorators / primitives / accessors are callable.

    Catches the failure mode where a re-export accidentally binds the
    submodule instead of the symbol (``from alfred.hooks.invoke import
    invoke`` vs ``from alfred.hooks import invoke as alfred.hooks.invoke``).
    """
    assert callable(hooks_pkg.hook)
    assert callable(hooks_pkg.invoke)
    assert callable(hooks_pkg.invoking)
    assert callable(hooks_pkg.get_registry)
    assert callable(hooks_pkg.set_registry)


def test_exported_classes_are_classes() -> None:
    """Type/exception/registry symbols are classes."""
    assert isinstance(hooks_pkg.HookContext, type)
    assert isinstance(hooks_pkg.HookError, type)
    assert isinstance(hooks_pkg.HookRefusal, type)
    assert isinstance(hooks_pkg.HookSubscriberError, type)
    assert isinstance(hooks_pkg.HookRegistry, type)


def test_exported_protocols_are_protocols() -> None:
    """``CapabilityGate`` and ``AuditSink`` are runtime-checkable Protocols.

    Both are declared with ``@runtime_checkable`` on their submodule
    definitions; the re-export must preserve the marker.
    """
    # ``Protocol`` subclasses set ``_is_protocol`` to True; the
    # ``runtime_checkable`` decorator additionally sets
    # ``_is_runtime_protocol``. Either marker is sufficient to confirm the
    # re-export didn't accidentally rebind to a non-Protocol object.
    assert getattr(hooks_pkg.CapabilityGate, "_is_protocol", False) is True
    assert getattr(hooks_pkg.AuditSink, "_is_protocol", False) is True


def test_hookkind_is_a_literal_alias() -> None:
    """``HookKind`` is the PEP-695 type alias from ``context.py``.

    ``HookKind`` is declared as ``type HookKind = Literal["pre", "post",
    "error", "cancel"]``. Python 3.12+ exposes PEP-695 aliases as
    ``typing.TypeAliasType`` instances at runtime; the re-export must
    preserve that.
    """
    from typing import TypeAliasType

    assert isinstance(hooks_pkg.HookKind, TypeAliasType)
