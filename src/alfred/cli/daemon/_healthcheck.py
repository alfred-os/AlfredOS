"""`alfred daemon healthcheck` — metrics-endpoint liveness probe (#470).

Scope: liveness of the /metrics endpoint ONLY, not full data-plane readiness (spec §5.4). A
metrics-bind failure marks the container unhealthy with a DISTINCT operator message; because
nothing depends_on core health, this is observational — it makes the loud-and-continue bind
failure visible (CLAUDE.md hard rule 7) without wedging the stack. Mirrors
`alfred.cli.gateway._commands.healthcheck_gateway`'s "never a raw traceback" contract, but
narrower: no breaker-latch tier (the daemon has no equivalent back-pressure breaker gauge),
so this is single-tier liveness only.

Two distinct exit-1 branches (i18n-004): a bad ``ALFRED_CORE_METRICS_PORT`` value is a
CONFIG error (the port could never have been probed), while an unreachable endpoint is a
PROBE failure (the port is well-formed but the exposition did not answer) — the operator
copy for each is deliberately different, so `t()` is called against two SEPARATE catalog
keys rather than a single shared message.
"""

from __future__ import annotations

from typing import Final

import structlog
import typer

from alfred.i18n import t
from alfred.observability.metrics_server import (
    CORE_METRICS_DEFAULT_PORT,
    CORE_METRICS_PORT_ENV,
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

    Two typed refusal arms, each with its OWN operator message (i18n-004):

    * A malformed ``ALFRED_CORE_METRICS_PORT`` (``ValueError`` from
      :func:`resolve_metrics_port`) is a config fault — the probe never had a port to dial.
    * An unreachable endpoint (``OSError`` from :func:`fetch_metrics_text`) is a live-probe
      fault — the port resolved fine but no VALID exposition came back: a bind failure, a
      not-yet-started server, a torn socket, a non-HTTP responder, or (CR-A) an HTTP answer
      that is not a ``200`` exposition, e.g. a 404 from something else squatting on the port
      or a 500 from a wedged handler. Those last two used to read as HEALTHY, which made this
      probe unable to fail for a whole class of the condition it exists to catch. This stays
      DELIBERATELY observational-only in scope: the data plane may still be serving fine even
      while /metrics is down.
    """
    try:
        port = resolve_metrics_port(CORE_METRICS_PORT_ENV, CORE_METRICS_DEFAULT_PORT)
    except ValueError as exc:
        detail = str(exc)[:_DETAIL_MAX_CHARS]
        log.warning("daemon.healthcheck.bad_port", error=repr(exc))
        typer.echo(t("daemon.healthcheck.bad_port", detail=detail))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    try:
        fetch_metrics_text(port)
    except OSError as exc:
        log.warning("daemon.healthcheck.metrics_unreachable", port=port, error=repr(exc))
        typer.echo(t("daemon.healthcheck.metrics_unreachable", port=port))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc


__all__ = ["healthcheck_daemon"]
