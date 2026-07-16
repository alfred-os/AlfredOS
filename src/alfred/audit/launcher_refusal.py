"""Pure parser: launcher sandbox-refusal stderr bytes -> validated rows (#433).

``bin/alfred-plugin-launcher.sh`` is the sole producer of
``supervisor.plugin.sandbox_refused``; it ``printf``s the row as one JSON line
to stderr and ``exit 1``s. This module turns that stderr back into validated,
canonicalized :class:`SandboxRefusalRow` values so the core can persist them
(:mod:`alfred.security.sandbox_refusal_audit`). It lives in ``audit/`` next to
the schema it consumes (clean dependency direction; see ADR-0051). Pure — no
I/O, no audit-writer/hook/plugins imports — so it is 100% line+branch testable.

Trust posture: on a genuine refusal the launcher exits BEFORE ``exec``ing the
child, so that stderr is launcher-authored (T0). BUT this parser is also
reached from the quarantine-child drain on a CRASHED/WEDGED *exec'd* child
(:mod:`alfred.security.quarantine_child_io`) — the most adversary-facing
surface in the system — so it cannot assume its input is trustworthy. Every
field value is validated to be a plain ``str`` free of control/format
characters (frozenset ``{"Cc", "Cf"}`` via :mod:`unicodedata`) before it is
accepted; this is defense in depth on top of the drain-side gate
(:meth:`_SubprocessChildIO._log_child_stderr`) that only forwards raw stderr
here when the read_frame EOF happened BEFORE any frame was ever read (the
launcher-authored signal). #432 (closed reason vocabulary) and #437
(``policy_ref`` charset guard) already constrain what a real launcher writes,
so none of this rejects a legitimate row — it only drops adversarial/forged
ones. Drop policy is deliberately two-tier: a line that is not JSON, not a
JSON object, or not a ``sandbox_refused`` event is SILENTLY skipped (it is
expected non-refusal stderr — a human log line or a different event), whereas
a line that IS a ``sandbox_refused`` object but fails deeper validation
(unknown key, non-string field, unsafe field value, out-of-vocab ``reason``,
missing required field) is dropped LOUDLY via ``_log.warning`` — a malformed
refusal row is a real anomaly, benign interleaved output is not. Parsing
never raises.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass
from typing import cast

import structlog

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS, SANDBOX_REFUSED_REASONS

_log = structlog.get_logger(__name__)

_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"

# Unicode categories that reject a field value outright (sec-001/arch-001):
# ``Cc`` (C0/C1 controls incl. ``\n \r \t \x1b``) defeats forged audit-log
# rows / ANSI terminal escapes; ``Cf`` (format chars incl. bidi overrides
# U+202E, directional isolates, zero-width joiners) defeats display-spoofing
# of the persisted row / an operator's ``alfred audit log`` render. Mirrors
# ``quarantine_child_io._STRIPPED_UNICODE_CATEGORIES`` but this module
# REJECTS the row rather than de-fanging it in place — an audit row is a
# structured record, not a free-text diagnostic field, so a value carrying
# these characters is dropped wholesale instead of silently rewritten.
_UNSAFE_UNICODE_CATEGORIES: frozenset[str] = frozenset({"Cc", "Cf"})

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
    ``supervisor.plugin.sandbox_refused`` with keys ⊆ ``SANDBOX_REFUSED_FIELDS``,
    every present value a control/format-char-free ``str``, and ``reason`` ∈
    ``SANDBOX_REFUSED_REASONS``. Absent optional fields -> "". Rejected lines
    are logged at warning. Never raises — including on adversarial/non-string
    JSON shapes (a list/dict/number field value, or a non-hashable ``reason``).
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
    # CR-major-6/9: validate every PRESENT value is a plain str BEFORE the
    # reason-vocab membership check below — ``in`` on a non-hashable value
    # (a JSON list/dict) raises TypeError, and a bare number/null would
    # otherwise be silently coerced into an accepted audit field by str().
    non_string_fields = {k for k, v in payload.items() if not isinstance(v, str)}
    if non_string_fields:
        _log.warning("audit.launcher_refusal.invalid_field_types", fields=sorted(non_string_fields))
        return None
    if payload.get("reason") not in SANDBOX_REFUSED_REASONS:
        _log.warning("audit.launcher_refusal.unknown_reason", reason=payload.get("reason"))
        return None
    missing = (SANDBOX_REFUSED_FIELDS - _OPTIONAL_FIELDS) - payload.keys()
    if missing:
        _log.warning("audit.launcher_refusal.missing_fields", missing=sorted(missing))
        return None
    # sec-001/arch-001: reject any present value carrying a control/format
    # char (defends the SIGNED audit log + an operator's render against a
    # forged newline/ANSI/bidi payload — see module docstring). Every value
    # is a validated str by this point, so unicodedata.category is safe.
    unsafe_fields = {
        k
        for k, v in payload.items()
        if isinstance(v, str)
        and any(unicodedata.category(ch) in _UNSAFE_UNICODE_CATEGORIES for ch in v)
    }
    if unsafe_fields:
        _log.warning("audit.launcher_refusal.unsafe_field_value", fields=sorted(unsafe_fields))
        return None
    # Every present value passed the isinstance(v, str) gate above; an absent
    # optional field defaults to "" — both are real str at runtime, so the
    # cast (not a coercing str()) is what documents that to mypy.
    values = {field: cast(str, payload.get(field, "")) for field in SANDBOX_REFUSED_FIELDS}
    return SandboxRefusalRow(**values)


__all__ = ["SandboxRefusalRow", "parse_launcher_refusal_rows"]
