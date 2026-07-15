"""Pure parser: launcher sandbox-refusal stderr bytes -> validated rows (#433).

``bin/alfred-plugin-launcher.sh`` is the sole producer of
``supervisor.plugin.sandbox_refused``; it ``printf``s the row as one JSON line
to stderr and ``exit 1``s. This module turns that stderr back into validated,
canonicalized :class:`SandboxRefusalRow` values so the core can persist them
(:mod:`alfred.security.sandbox_refusal_audit`). It lives in ``audit/`` next to
the schema it consumes (clean dependency direction; see ADR-0051). Pure — no
I/O, no audit-writer/hook/plugins imports — so it is 100% line+branch testable.

Trust posture: on a refusal the launcher exits BEFORE ``exec``ing the child, so
this stderr is launcher-authored (T0). Validation is defense in depth; #432
(closed reason vocabulary) and #437 (``policy_ref`` charset guard) already
constrain what the launcher writes. Drop policy is deliberately two-tier: a line
that is not JSON, not a JSON object, or not a ``sandbox_refused`` event is
SILENTLY skipped (it is expected non-refusal stderr — a human log line or a
different event), whereas a line that IS a ``sandbox_refused`` object but fails
deeper validation (unknown key, out-of-vocab ``reason``, missing required field)
is dropped LOUDLY via ``_log.warning`` — a malformed refusal row is a real
anomaly, benign interleaved output is not. Parsing never raises.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import structlog

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS, SANDBOX_REFUSED_REASONS

_log = structlog.get_logger(__name__)

_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"

# Optional members a launcher row may omit; canonicalized to "" so the subject
# carries the full symmetric key-set ``AuditWriter.append_schema`` requires.
# ``policy_ref`` is absent from every pre-``policy_ref``-resolution refusal.
_OPTIONAL_FIELDS: frozenset[str] = frozenset({"policy_ref"})


@dataclass(frozen=True, slots=True)
class SandboxRefusalRow:
    """One validated, canonicalized ``supervisor.plugin.sandbox_refused`` row."""

    plugin_id: str
    policy_ref: str
    host_os: str
    reason: str
    environment: str

    def as_subject(self) -> dict[str, str]:
        return {
            "plugin_id": self.plugin_id,
            "policy_ref": self.policy_ref,
            "host_os": self.host_os,
            "reason": self.reason,
            "environment": self.environment,
        }


def parse_launcher_refusal_rows(stderr: bytes) -> tuple[SandboxRefusalRow, ...]:
    """Extract validated ``sandbox_refused`` rows from raw launcher stderr.

    Line-oriented ``json.loads``; accepts only an object whose ``event`` is
    ``supervisor.plugin.sandbox_refused`` with keys ⊆ ``SANDBOX_REFUSED_FIELDS``
    and ``reason`` ∈ ``SANDBOX_REFUSED_REASONS``. Absent optional fields ->  "".
    Rejected lines are logged at warning. Never raises.
    """
    rows: list[SandboxRefusalRow] = []
    for line in stderr.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            candidate = json.loads(stripped)
        except ValueError:
            continue  # a human log line, not JSON — expected
        if not isinstance(candidate, dict) or candidate.get("event") != _REFUSED_EVENT:
            continue
        row = _validated_row(candidate)
        if row is not None:
            rows.append(row)
    return tuple(rows)


def _validated_row(candidate: dict[str, object]) -> SandboxRefusalRow | None:
    payload = {k: v for k, v in candidate.items() if k != "event"}
    unknown = payload.keys() - SANDBOX_REFUSED_FIELDS
    if unknown:
        _log.warning("audit.launcher_refusal.unknown_fields", unknown=sorted(unknown))
        return None
    if payload.get("reason") not in SANDBOX_REFUSED_REASONS:
        _log.warning("audit.launcher_refusal.unknown_reason", reason=payload.get("reason"))
        return None
    missing = (SANDBOX_REFUSED_FIELDS - _OPTIONAL_FIELDS) - payload.keys()
    if missing:
        _log.warning("audit.launcher_refusal.missing_fields", missing=sorted(missing))
        return None
    values = {field: str(payload.get(field, "")) for field in SANDBOX_REFUSED_FIELDS}
    return SandboxRefusalRow(**values)


__all__ = ["SandboxRefusalRow", "parse_launcher_refusal_rows"]
