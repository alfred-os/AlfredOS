"""Per-orchestrator-action observability — Prometheus histogram + sub-span hooks.

This module ships two things (spec §7a.3):

* :data:`ACTION_DURATION_HISTOGRAM` — ``alfred_orchestrator_action_duration_seconds``
  Histogram. One observation per ``Orchestrator.handle_user_message`` turn,
  emitted on every outcome (``success`` / ``timeout`` / ``cancelled``).
  Labels: ``user_id_bucket`` (perf-001 bucketed hash, NOT raw user_id),
  ``action_outcome``, ``breaker_state``.

* :func:`span_web_fetch` / :func:`span_quarantine_extract` /
  :func:`span_hookchain` — sub-span context-manager helpers wrapping
  the orchestrator's per-phase dispatches. The implementations are
  intentionally no-op context managers in PR-S3-3b: OpenTelemetry is a
  Slice-4 dependency (no ADR landing it earlier), so the span surface
  ships as a forward-compatible shim that a future Slice-4 patch can
  swap to ``opentelemetry.trace.start_as_current_span`` without touching
  caller sites. Orchestrator code can already write
  ``with span_web_fetch():`` and the span tree materialises automatically
  once OTel is wired.

Bounded label cardinality (perf-001)
------------------------------------

The histogram's ``user_id_bucket`` label is the cardinality firewall.
Raw ``user_id`` is unbounded — a deployment with even a thousand users
would cross Prometheus's recommended ceiling on series-per-histogram
(~10K) once multiplied by ``action_outcome`` (3) and ``breaker_state``
(3). :func:`bucket_user_id` collapses raw ids into a fixed-size set of
hex buckets (:data:`_BUCKET_COUNT` = 256) via SHA-256.

Why a hash bucket and not the PR-S3-3a allowlist pattern? The allowlist
in :mod:`alfred.plugins._observability` is tuned for the plugin-id label
where operators WANT to see the actual plugin name on the first N
deployments and accept a single ``"other"`` bucket past the cap. Per-user
histograms are different: operators never want to read individual user
ids off Grafana, they want aggregate percentiles. A hash bucket gives
deterministic-but-anonymous distribution; the bucket count IS the
cardinality cap by construction (no allowlist drift, no warmup, no
overflow bucket).

Module-level histogram pattern
------------------------------

:class:`prometheus_client.Histogram` registers itself on the default
:class:`CollectorRegistry` at construction time; a second instantiation
with the same name raises ``Duplicated timeseries``. The histogram is
constructed once at module import so the orchestrator's per-turn
observation path is a pure ``labels(...).observe(...)`` call.

Sub-span shim (Slice-4 OTel migration path)
-------------------------------------------

The three ``span_*`` helpers return a :class:`contextlib.nullcontext`
instance — a no-op ``__enter__``/``__exit__`` pair. The plan calls for
``opentelemetry.trace.start_as_current_span`` here, but OpenTelemetry
is not yet a project dependency (CLAUDE.md forbids adding fourth-party
deps without an ADR; ADR-0007 lists the approved set, OTel is Slice-4).
Shipping the helpers as no-op shims now means:

* Orchestrator caller sites already use the helpers; the diff to flip
  on OTel becomes one-line per helper.
* Tests pin the contract (the helpers exist and are context-managers).
* No phantom dep — ``ruff`` / ``mypy`` / ``pyright`` stay clean without
  a stub install.

The Slice-4 patch removes ``contextlib`` here, adds the OTel import,
and points each helper at ``tracer.start_as_current_span(<name>)``.
Caller sites unchanged.
"""

from __future__ import annotations

import hashlib
from contextlib import AbstractContextManager, nullcontext
from typing import Final

from prometheus_client import Histogram

# perf-001: bounded label cardinality. 256 distinct buckets is a deliberate
# choice — high enough that a healthy single-household deployment (1-20
# users) maps 1:1 with high probability, low enough that even a 10k-user
# deployment caps series count at 256 x 3 x 3 = 2304 (well under
# prometheus_client's recommended 10k ceiling).
_BUCKET_COUNT: Final[int] = 256


def bucket_user_id(user_id: str) -> str:
    """Map ``user_id`` to one of :data:`_BUCKET_COUNT` stable hex buckets.

    SHA-256(user_id) mod ``_BUCKET_COUNT`` → 2-hex-digit string. The
    bucket count is the cardinality cap by construction; no allowlist,
    no overflow bucket. Deterministic across processes and restarts:
    the same ``user_id`` always lands in the same bucket so per-bucket
    p99 trends are stable across Prometheus scrapes.

    First-byte mod 256 is intentional (not a longer slice): we only need
    8 bits of entropy to pick from 256 buckets and the first byte of
    SHA-256 is already uniformly distributed across the byte range. Using
    more bytes would cost CPU on the hot path without changing the
    distribution.

    perf-001: this is the firewall against per-user series explosion in
    Prometheus. Callers MUST pass the raw ``user_id``; this function does
    the bucketing — never the caller. The histogram label is named
    ``user_id_bucket`` precisely so a misuse (passing raw id) shows up
    as a literal series name in Grafana.
    """
    digest = hashlib.sha256(user_id.encode()).digest()
    bucket = digest[0] % _BUCKET_COUNT  # first byte mod _BUCKET_COUNT
    return f"{bucket:02x}"


# perf-013 — ms-resolution buckets straddling the 30s deadline. The
# smallest non-inf bound (5ms) gives sub-5ms p50/p90 error on typical
# fast turns; the 30s bound mirrors the spec §10.5 default deadline so
# operators read the p99 of the deadline-hitting bucket directly. ``+Inf``
# is appended by prometheus_client automatically (the explicit
# ``float("inf")`` here is for self-documentation in the constant).
ACTION_DURATION_HISTOGRAM: Final[Histogram] = Histogram(
    "alfred_orchestrator_action_duration_seconds",
    "Duration of a single orchestrator action (one handle_user_message call).",
    labelnames=["user_id_bucket", "action_outcome", "breaker_state"],
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        30.0,
        float("inf"),
    ),
)


def record_action_duration(
    *,
    duration_seconds: float,
    user_id: str,
    action_outcome: str,
    breaker_state: str,
) -> None:
    """Observe one orchestrator action duration.

    Emitted on every outcome of ``Orchestrator.handle_user_message``:

    * ``success`` — the turn completed, the provider returned, the audit
      row landed.
    * ``timeout`` — :class:`alfred.supervisor.deadline.DeadlineWrapper`
      fired ``asyncio.timeout`` before the turn finished. Bound to the
      ``supervisor.action_timeout`` audit row by the same ``correlation_id``.
    * ``cancelled`` — operator-initiated cancel (not deadline-fired). Bound
      to the ``orchestrator.turn result=cancelled`` audit row.

    ``user_id`` is bucketed internally via :func:`bucket_user_id` before
    landing in the histogram label set (perf-001). Callers MUST pass the
    raw id; never thread the bucket form.

    ``breaker_state`` is the supervisor breaker's current state at the
    time of emission (``"CLOSED"`` / ``"OPEN"`` / ``"HALF_OPEN"``) — or
    ``"UNKNOWN"`` when the supervisor is not wired (early-bootstrap or
    test-only paths). Pinning the label inside the enum domain keeps the
    Grafana legend stable.
    """
    ACTION_DURATION_HISTOGRAM.labels(
        user_id_bucket=bucket_user_id(user_id),
        action_outcome=action_outcome,
        breaker_state=breaker_state,
    ).observe(duration_seconds)


def span_web_fetch() -> AbstractContextManager[None]:
    """Sub-span for ``tool.web.fetch`` dispatch (spec §7a.3).

    Returns a context manager so callers write ``with span_web_fetch():``.
    PR-S3-3b ships the no-op shim; Slice-4 swaps in
    ``opentelemetry.trace.start_as_current_span("tool.web.fetch")`` without
    touching caller sites. See module docstring for the migration rationale.
    """
    return nullcontext()


def span_quarantine_extract() -> AbstractContextManager[None]:
    """Sub-span for ``security.quarantined.extract`` dispatch (spec §7a.3).

    Same shape as :func:`span_web_fetch` — Slice-4 OTel migration shim.
    Wraps the quarantined-LLM structured-extraction call so the p99 of
    the T3 → T2 crossing becomes per-trace observable once OTel lands.
    """
    return nullcontext()


def span_hookchain() -> AbstractContextManager[None]:
    """Sub-span for ``hookchain_total`` (spec §7a.3).

    Wraps the orchestrator's complete pre-/post-action hook chain so the
    p99 of hook-mediated latency is per-trace observable. Distinct from
    the per-hookpoint spans the registry may emit independently — this is
    the rollup that lets operators answer "how much of the turn went to
    hooks?" without aggregating leaf spans manually. PR-S3-3b ships the
    no-op shim; Slice-4 wires real OTel.
    """
    return nullcontext()


__all__ = [
    "ACTION_DURATION_HISTOGRAM",
    "bucket_user_id",
    "record_action_duration",
    "span_hookchain",
    "span_quarantine_extract",
    "span_web_fetch",
]
