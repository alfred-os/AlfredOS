"""Back-compat shim — the exposition moved to alfred.observability.metrics_server (#470)."""

from alfred.observability.metrics_server import (
    fetch_metrics_text,
    resolve_metrics_port,
    start_metrics_server,
)

__all__ = ["fetch_metrics_text", "resolve_metrics_port", "start_metrics_server"]
