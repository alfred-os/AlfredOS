"""Narrow read-only config Protocols for the security subsystem (#351).

Design: docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md. Consumers
depend on exactly the config fields they read; the real ``Settings`` satisfies these
structurally (PEP 544), so a test double is a trivial stub rather than a full
``Settings``. See docs/python-conventions.md "Config consumers depend on narrow
read-only Protocols".
"""

from __future__ import annotations

from typing import Protocol


class CommsAdapterGrantsConfig(Protocol):
    """The config surface ``comms_adapter_load_grants`` reads: the enabled comms adapters.

    Producer invariant (SECURITY-critical): ``Settings.comms_enabled_adapters`` is
    validated by ``_validate_comms_enabled_adapters`` (settings.py) — every id is
    charset-checked, rejected if it is a ``.``/``..`` traversal probe, proven CONTAINED
    under ``plugins/``, and proven to name a real ``plugins/<id>/manifest.toml``. The
    builder turns each id into a filesystem path and reads it, so callers MUST supply a
    value that has passed that validator (a plain stub bypasses it). The builder does NOT
    re-validate — it relies on this construction-time proof (ADR-0027 config-is-authorization)
    and fails LOUD on any manifest it cannot read (never a silent skip). Passing an
    unvalidated stub with a traversal-shaped id is a caller error, not a builder concern.

    NOTE: this guarantee is enforced at the ``Settings`` CONSTRUCTION site (the composition
    root builds a validated ``Settings``), NOT by this Protocol or by the ``tuple[str, ...]``
    type — a ``Settings.model_construct(...)`` or a raw stub bypasses the validator entirely.
    A future second consumer of this Protocol inherits NO validation from the type.
    """

    @property
    def comms_enabled_adapters(self) -> tuple[str, ...]: ...
