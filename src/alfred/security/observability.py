"""Security-path Prometheus instrumentation.

Currently one metric, the quarantine capability revocation.

**Why this exists.** ``QuarantineStdioTransport._revoke_child_capability`` tears the
quarantined child down to revoke every gateway socket already sitting in its
SCM_RIGHTS queue. It is the correct fail-closed response to a broker failure, but it
is also terminal for the session: the child is spawned exactly ONCE, at daemon boot
(``_build_comms_inbound_extractor``), and there is no respawn scheduler (#455). After
a revoke, every later extraction returns ``provider_unavailable`` with its own
``egress.broker.refused`` row, and the quarantine path stays down until the daemon is
restarted.

The security lane made shipping the go-live without that scheduler conditional on the
revocation being *alertable*. Before this module it was a structlog line only, which
nothing in ``ops/`` can express a rule over — so an operator's first signal was comms
quietly failing to do anything.

.. warning::

   **Armed, not yet live.** This counter is registered in the CORE process, and
   nothing scrapes the core: ``ops/prometheus/prometheus.yml`` defines a single job
   for ``alfred-gateway:9464``, and ``start_metrics_server`` is called only from
   ``alfred gateway start``. The rule in ``ops/alerts/quarantine.yml`` is correct and
   promtool-verified, and begins firing the moment a core scrape target exists —
   tracked in #470. The detection path that works TODAY is the audit log; see
   ``docs/runbooks/quarantine-capability-revoked.md``.

Module-level construction mirrors :mod:`alfred.comms_mcp.observability` and
:mod:`alfred.supervisor.observability`: the :class:`~prometheus_client.Counter`
registers on the default :class:`~prometheus_client.CollectorRegistry` at import, so
the per-event path is a bare ``inc()`` and a duplicate-name regression surfaces
loudly at import time rather than at the first revoke.

No labels. The quarantine path is identity-blind by invariant (the §8.2 identity
invariant keeps the per-user identity host-side and out of the child), so there is no
per-user dimension to attach, and a per-extraction label would put unbounded
cardinality on a security-alerting series.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter

CAPABILITY_REVOKED_COUNTER: Final[Counter] = Counter(
    "alfred_quarantine_capability_revoked_total",
    "Quarantine-child capability revocations (child torn down, gateway sockets "
    "revoked). Terminal for the quarantine path until the daemon restarts — there "
    "is no respawn scheduler (#455).",
)

__all__ = ["CAPABILITY_REVOKED_COUNTER"]
