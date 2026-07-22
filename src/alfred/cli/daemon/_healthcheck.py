"""`alfred daemon healthcheck` — metrics-endpoint liveness probe (#470).

Scope: liveness of the /metrics endpoint ONLY, not full data-plane readiness (spec §5.4). A
metrics-bind failure marks the container unhealthy with a DISTINCT operator message; because
nothing depends_on core health, this is observational — it makes the loud-and-continue bind
failure visible (CLAUDE.md hard rule 7) without wedging the stack. Mirrors
`alfred.cli.gateway._commands.healthcheck_gateway`'s "never a raw traceback" contract, but
narrower: no breaker-latch tier (the daemon has no equivalent back-pressure breaker gauge),
so this is single-tier liveness only.

Three distinct exit-1 branches (i18n-004): a bad ``ALFRED_CORE_METRICS_PORT`` value is a
CONFIG error (the port could never have been probed), an unreachable endpoint is a PROBE
failure (the port is well-formed but nothing usable answered), and a 200 that is not this
service's exposition is an IDENTITY failure (something answered, but it is not the core's
/metrics) — the operator copy for each is deliberately different, so `t()` is called against
three SEPARATE catalog keys rather than one shared message. The healthy arm echoes a line
too (uat-p1): the README tells a human to run this by hand, and a silent exit 0 is
indistinguishable from a broken command without inspecting ``$?``.
"""

from __future__ import annotations

from typing import Final

import structlog
import typer

from alfred.i18n import t
from alfred.observability.metrics_server import (
    CORE_METRIC_FAMILY_PREFIX,
    CORE_METRICS_DEFAULT_PORT,
    CORE_METRICS_PORT_ENV,
    declares_metric_family,
    fetch_metrics_text,
    resolve_metrics_port,
)

log = structlog.get_logger(__name__)

_EXIT_UNHEALTHY: Final[int] = 1

# The bad-port refusal quotes ``resolve_metrics_port``'s ValueError text so the operator sees
# the env var, the accepted range AND their own offending value (dx-001). That text embeds an
# operator-supplied env value, so it is length-bounded before it reaches the terminal — a
# pathological multi-megabyte ``ALFRED_CORE_METRICS_PORT`` must not become the whole message.
_DETAIL_MAX_CHARS: Final[int] = 200


def healthcheck_daemon() -> None:
    """Probe the core's /metrics exposition. Exit 0 healthy / 1 unhealthy; never a traceback.

    Three typed refusal arms, each with its OWN operator message (i18n-004):

    * A malformed ``ALFRED_CORE_METRICS_PORT`` (``ValueError`` from
      :func:`resolve_metrics_port`) is a config fault — the probe never had a port to dial.
    * An unreachable endpoint (``OSError`` from :func:`fetch_metrics_text`) is a live-probe
      fault — the port resolved fine but no VALID response came back: a bind failure, a
      not-yet-started server, a torn socket, a non-HTTP responder, or (CR-A) an HTTP answer
      that is not a ``200``, e.g. a 404 from something else squatting on the port or a 500
      from a wedged handler.
    * A ``200`` whose body is not this service's exposition is an identity fault (uat-p4).
      A transport-level probe cannot see the difference between the core's /metrics and any
      other 200 on the same port — UAT confirmed prose, an empty body and the GATEWAY's
      ``gateway_*`` exposition all read as HEALTHY, which is exactly the dead-metrics class
      #470 exists to eliminate. :func:`declares_metric_family` closes that: healthy now means
      "a Prometheus exposition declaring an ``alfred_`` family answered", not "something
      answered 200".

    Healthy echoes one line naming the port (uat-p1) — a hand-run probe must be legible
    without checking ``$?``; Docker discards healthcheck stdout, so the container probe is
    unaffected. Failure stays DELIBERATELY observational-only in scope: the data plane may
    still be serving fine even while /metrics is down.
    """
    try:
        port = resolve_metrics_port(CORE_METRICS_PORT_ENV, CORE_METRICS_DEFAULT_PORT)
    except ValueError as exc:
        detail = str(exc)[:_DETAIL_MAX_CHARS]
        log.warning("daemon.healthcheck.bad_port", error=repr(exc))
        typer.echo(t("daemon.healthcheck.bad_port", detail=detail))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    try:
        exposition = fetch_metrics_text(port)
    except OSError as exc:
        log.warning("daemon.healthcheck.metrics_unreachable", port=port, error=repr(exc))
        typer.echo(t("daemon.healthcheck.metrics_unreachable", port=port))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    if not declares_metric_family(exposition, CORE_METRIC_FAMILY_PREFIX):
        # No exception drives this arm (a well-formed 200 that is simply the wrong service), so
        # there is no cause to chain. Carry ``body_len`` — never the untrusted body itself — so
        # the identity refusal is as diagnosable as the sibling arms that log ``error=``.
        log.warning("daemon.healthcheck.not_core_exposition", port=port, body_len=len(exposition))
        typer.echo(t("daemon.healthcheck.not_core_exposition", port=port))
        raise typer.Exit(code=_EXIT_UNHEALTHY)
    typer.echo(t("daemon.healthcheck.healthy", port=port))


__all__ = ["healthcheck_daemon"]
