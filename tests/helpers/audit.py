"""Recording audit-sink test double for cross-suite use.

Mirrors ``tests/unit/hooks/conftest.py::SpyAuditSink`` but lives under
``tests/helpers`` so the adversarial suite (and any other test package)
can import it without reaching into another suite's conftest. Records
every ``emit(event, correlation_id, fields)`` call into ``records`` so
a test can assert which audit rows fired.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(slots=True)
class RecordingAuditSink:
    """Structural :class:`alfred.hooks.audit_sink.AuditSink` test double.

    The ``records`` list captures one entry per ``emit`` with a defensive
    copy of ``fields`` (so a caller that mutates the original mapping
    after the emit does not move the recorded snapshot).
    """

    records: list[dict[str, object]] = field(default_factory=list)

    async def emit(
        self,
        *,
        event: str,
        correlation_id: str,
        fields: Mapping[str, object],
    ) -> None:
        """Record one entry per call — same keyword-only seam as the
        production :meth:`alfred.hooks.audit_sink.AuditSink.emit`."""
        self.records.append(
            {
                "event": event,
                "correlation_id": correlation_id,
                "fields": dict(fields),
            }
        )
