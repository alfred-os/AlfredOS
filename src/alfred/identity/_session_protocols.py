"""Shared structural protocols for operator-session collaborators (#153).

The host-side operator-session code has two emit surfaces — the resolver
(``alfred.identity._resolver``) and the CLI commands
(``alfred.cli.operator_session``). Both inject the same broker / audit-writer /
machine-id-provider collaborators. These ``*Like`` Protocols are the single
typed contract for those collaborators so neither surface falls back to a bare
``Any`` (cross-cutting LOW: strong typing at the trust boundary).
"""

from __future__ import annotations

from typing import Any, Protocol


class BrokerLike(Protocol):
    """The narrow slice of the secret broker the session code uses."""

    def get(self, name: str) -> str: ...


class MachineIdLike(Protocol):
    """A per-OS machine-id provider (``read_raw`` returns the raw bytes)."""

    async def read_raw(self) -> bytes: ...


class AuditLike(Protocol):
    """The ``AuditWriter.append_schema`` surface the session code calls.

    Mirrors :meth:`alfred.audit.log.AuditWriter.append_schema`; the optional
    kwargs carry their defaults via ``= ...`` so a structural match does not
    require the caller to pass them.
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
        actor_persona: str = ...,
        persona_id: str | None = ...,
        cost_actual_usd: float | None = ...,
        language: str = ...,
    ) -> None: ...


__all__ = ["AuditLike", "BrokerLike", "MachineIdLike"]
