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

So the revoke increments a counter the alert rule in ``ops/alerts/quarantine.yml``
fires on. The counter is registered in the CORE process; ``alfred daemon start``
serves it on ``ALFRED_CORE_METRICS_PORT`` (9465), and the bundled
``ops/prometheus/prometheus.yml`` scrapes that endpoint alongside the gateway job
(#470), so the rule evaluates against a live, queryable series. It is also the
*sole metrics signal* for a cancel-path revoke
(:meth:`~alfred.security.quarantine_transport.QuarantineStdioTransport._revoke_child_capability`):
that path writes no ``egress.broker.refused`` audit row, so nothing else observes
it. See ``docs/runbooks/quarantine-capability-revoked.md`` for triage and
``docs/runbooks/observability-stack.md`` for reaching Prometheus/Grafana.

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
