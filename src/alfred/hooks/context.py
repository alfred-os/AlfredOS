"""Immutable per-stage hook carrier — see spec §3.3.

The :class:`HookContext` is the value every hook sees at every stage. It
is intentionally tiny: an action identifier, a hookpoint identifier, the
typed input payload, the cross-system correlation id, the lifecycle
``kind`` (``pre``/``post``/``error``/``cancel``), and a freely-extensible
``metadata`` mapping for trace / span / persona / locale / per-tenant
breadcrumbs.

Design invariants — pinned by ``tests/unit/hooks/test_context.py``:

* **Frozen + slots.** No attribute set after construction; no ``__dict__``
  per-instance allocation. The carrier flies through the dispatcher on
  hot paths.
* **Value-typed copy helpers.** :meth:`with_input`, :meth:`with_metadata`,
  and :meth:`for_stage` return a new instance via :func:`dataclasses.replace`.
  The original is never mutated.
* **No shared mutable default.** ``metadata`` uses
  ``field(default_factory=dict)`` so two freshly-built contexts hold
  distinct dict objects — the spec's "never a shared mutable default"
  assertion. :meth:`with_metadata` merges into a fresh dict so mutating
  the returned mapping cannot reach back through an alias to the original.
* **PEP 695 generic.** ``HookContext[T]`` carries the typed input through
  the dispatcher unchanged so action callers can write
  ``HookContext[EpisodicRecordInput]`` and get full mypy/pyright narrowing
  in their hooks.

The ``Self`` returns on the copy helpers (PEP 673) keep subclass-friendly
typing free — a downstream that subclasses :class:`HookContext` to carry
additional fields will see its own subclass type back from each helper
without explicit type-arg annotation.

Forward-compat reservation (spec §13): a future value-returning-action
carrier will add ``output: TOutput | None`` here (or :func:`invoke` will
grow a ``result=`` kwarg mirroring its ``exc=``). The name ``output`` is
reserved for that addition; **no field is added this slice** — actions
ship as side-effect-only in Slice 2.5.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Literal, Self

# Exported by name. Task 14 finalises ``__all__`` on the package; this
# module deliberately keeps no module-level ``__all__`` of its own per
# the Task-1 spec.
type HookKind = Literal["pre", "post", "error", "cancel"]


@dataclass(frozen=True, slots=True)
class HookContext[T]:
    """Immutable per-stage carrier handed to every registered hook.

    Parameters mirror spec §3.3 verbatim. The ``kind`` field's annotation
    is the literal-typed set rather than the :data:`HookKind` alias so
    static checkers see the exact membership at the field-declaration
    site (the alias is exported for use in decorators, dispatchers, and
    the :func:`invoke` helper).

    Attributes:
        action_id: The fully-qualified action identifier
            (e.g. ``"memory.episodic.record"``). Stable across the
            registry; load-bearing for capability checks.
        hookpoint: Where in the action's lifecycle this stage fires
            (e.g. ``"memory.episodic.record.pre"``). Conventionally
            ``f"{action_id}.{kind}"`` but the dispatcher does not enforce
            that — sub-stage hookpoints are allowed.
        input: The typed input payload. Generic so callers retain
            narrowing through the dispatcher.
        correlation_id: Cross-system trace correlation id. Propagated
            into the audit row and every span derived from this hook
            invocation.
        kind: Lifecycle stage. ``pre`` (before the action body), ``post``
            (after success), ``error`` (after a raised exception), or
            ``cancel`` (the action was cancelled before its body ran).
        metadata: Freely-extensible breadcrumb mapping. Defaults to a
            fresh empty dict per instance via
            ``field(default_factory=dict)`` — never a shared mutable
            default. Typed as ``Mapping[str, object]`` so the field is
            read-only at the type level; the underlying object is a
            ``dict`` so :meth:`with_metadata`'s merge can build a new
            one cheaply.
    """

    action_id: str
    hookpoint: str
    input: T
    correlation_id: str
    kind: Literal["pre", "post", "error", "cancel"]
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Defensive copy: a caller that passes a mutable dict and then
        # mutates it after construction must NOT see the mutation
        # propagate into this frozen carrier. ``with_metadata`` already
        # builds a fresh dict on merge; this seals the OTHER ingress
        # path — the constructor itself. The ``object.__setattr__``
        # dance is the standard escape hatch for assigning to a field
        # of a ``frozen=True`` dataclass from inside ``__post_init__``
        # (see CPython's own docs on frozen dataclass init-time hooks).
        object.__setattr__(self, "metadata", dict(self.metadata))

    def with_input(self, new_input: T) -> Self:
        """Return a new context with ``input`` replaced.

        The carrier is frozen; this method is the canonical way for a
        ``pre`` hook to rewrite the payload before the action body runs
        (e.g. PII redaction). The original instance is untouched.
        """
        return replace(self, input=new_input)

    def with_metadata(self, **kv: object) -> Self:
        """Return a new context with extra metadata merged in.

        The merge builds a **fresh** dict — ``{**self.metadata, **kv}``
        — so mutating the returned mapping cannot reach back through an
        alias to the original carrier's metadata. New keys override
        existing keys of the same name (standard dict-unpack semantics).
        """
        return replace(self, metadata={**self.metadata, **kv})

    def for_stage(self, *, hookpoint: str, kind: HookKind) -> Self:
        """Return a NEW context retargeted to a stage. Frozen — never mutates."""
        return replace(self, hookpoint=hookpoint, kind=kind)
