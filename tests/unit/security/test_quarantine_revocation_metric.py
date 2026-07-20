"""The quarantine capability-revocation is counted, not only logged.

The security lane made shipping #340 PR2b-golive WITHOUT a respawn scheduler (#455)
conditional on the revocation being alertable. Today it is a structlog line only::

    _log.error("security.quarantine_transport.capability_revoked")

A log line is not an alert signal: nothing in ``ops/`` can express a rule over it,
and structlog output does not reach Prometheus. The consequence is severe enough to
warrant one — the child is spawned exactly ONCE, at daemon boot, so after a revoke
every later extraction degrades to ``provider_unavailable`` and the quarantine path
stays DOWN until the daemon restarts. That is the correct fail-closed trade, but an
operator who does not know it happened experiences it as comms silently rotting.

So the revoke increments a counter the alert rule in ``ops/alerts/quarantine.yml``
fires on.

.. warning::

   The counter lives in the CORE, and nothing scrapes the core yet:
   ``ops/prometheus/prometheus.yml`` has a single job for ``alfred-gateway:9464``,
   and only ``alfred gateway start`` calls ``start_metrics_server``. The alert rule
   is therefore ARMED BUT NOT YET LIVE. Tracked in #470. Until it lands, the
   runbook's audit-log query is the detection path that actually works.
"""

from __future__ import annotations

from typing import Final

import pytest
from prometheus_client import REGISTRY

_METRIC: Final[str] = "alfred_quarantine_capability_revoked_total"


def _sample() -> float:
    """Current counter value, or 0.0 before the first increment."""
    value = REGISTRY.get_sample_value(_METRIC)
    return 0.0 if value is None else value


def test_the_counter_is_registered_at_import() -> None:
    """Module-level construction, mirroring the sibling observability modules.

    Registering at import makes a duplicate-name regression fail loudly at import
    time rather than at the first revoke — which, on this path, might be months in.
    """
    from alfred.security import observability

    assert observability.CAPABILITY_REVOKED_COUNTER is not None
    assert _sample() >= 0.0, "counter is not registered on the default registry"


def test_the_counter_carries_no_labels() -> None:
    """No label surface: the quarantine path is identity-blind by invariant (§8.2).

    A per-user or per-extraction label here would carry identity into a metric the
    host deliberately keeps identity out of, and would add unbounded cardinality on
    a security-alerting series.
    """
    from alfred.security import observability

    # A labelled Counter raises when incremented without labels; an unlabelled one
    # does not. Assert the shape directly rather than inferring it.
    assert observability.CAPABILITY_REVOKED_COUNTER._labelnames == ()


@pytest.mark.asyncio
async def test_revoking_the_child_capability_increments_the_counter() -> None:
    """The real revoke path moves the metric — not a hand-rolled increment in a test.

    Drives ``_revoke_child_capability`` with a child-IO double so the assertion is
    about the shipped call site. A counter wired to nothing would otherwise satisfy
    every test above.
    """
    from alfred.security.quarantine_transport import QuarantineStdioTransport

    closed: list[bool] = []

    class _ChildIO:
        async def aclose(self) -> None:
            closed.append(True)

    transport = object.__new__(QuarantineStdioTransport)
    transport._child_io = _ChildIO()  # type: ignore[attr-defined]

    before = _sample()
    await transport._revoke_child_capability()
    after = _sample()

    assert closed == [True], "the revoke must actually tear the child down"
    assert after == before + 1.0, (
        f"{_METRIC} did not increment on a real revoke "
        f"(before={before}, after={after}) — the alert would never fire"
    )


@pytest.mark.asyncio
async def test_a_failing_teardown_still_counts_the_revocation() -> None:
    """A revoke whose teardown FAILS is still a revocation, and still alertable.

    ``_revoke_child_capability`` logs a failed teardown loud and swallows it (HARD #7)
    so the caller's graceful typed refusal survives. If the counter sat after the
    teardown it would be skipped on exactly the paths most worth alerting on.
    """
    from alfred.security.quarantine_transport import QuarantineStdioTransport

    class _ExplodingChildIO:
        async def aclose(self) -> None:
            raise OSError("EBADF")

    transport = object.__new__(QuarantineStdioTransport)
    transport._child_io = _ExplodingChildIO()  # type: ignore[attr-defined]

    before = _sample()
    await transport._revoke_child_capability()  # must not raise
    assert _sample() == before + 1.0, (
        "a revocation whose teardown failed was not counted — the counter must be "
        "incremented BEFORE the teardown is attempted"
    )
