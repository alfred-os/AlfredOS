"""Spec-B (#288) catalog-key reservation.

G6-2a ships the ``gateway.adapter.*`` operator-facing status-reason keys ahead
of their G6-2b ``alfred status`` consumer. Without this reservation,
``pybabel extract`` sees no source reference for the new msgids and marks them
obsolete on the next ``pybabel update``, tripping the CI ``i18n catalog drift``
gate. Each ``t(...)`` here is a static reference Babel extracts; ``_register``
is never called at runtime. Follows the ``_slice_4_reserve`` pattern.
"""

from __future__ import annotations

from alfred.i18n import t


def _register() -> None:
    """Reference every Spec-B catalog key so pybabel sees them as used."""
    # Adapter status labels (G6-2b alfred status render site).
    t("gateway.adapter.status.up")
    t("gateway.adapter.status.down")
    t("gateway.adapter.status.crashed")
    t("gateway.adapter.status.breaker_open")
    # Adapter status-rejection reasons (G6-2a observer refusal; G6-2b surfaced).
    t("gateway.adapter.status_rejected.malformed_frame")
    t("gateway.adapter.status_rejected.epoch_mismatch")
    t("gateway.adapter.status_rejected.unknown_method")
    # Per-state render tokens for ``alfred daemon status`` (G6-2b-2c / #288 / ADR-0038).
    # DICT-dereferenced at the render call site (``_ADAPTER_STATE_KEYS[line.state]``), so
    # pybabel cannot see the literal there — reserve them here so they are not marked
    # obsolete on the next ``pybabel update`` (the catalog-drift gate).
    t("daemon.status.state.up")
    t("daemon.status.state.down")
    t("daemon.status.state.crashed")
    t("daemon.status.state.breaker_open")
    t("daemon.status.state.unknown")
    # G6-3 credential round-trip reasons (#288 / ADR-0036). ONLY the two reasons the
    # resolver renders to an operator via :func:`alfred.i18n.t` (an unknown-adapter /
    # missing-secret refusal message) are reserved — they are dict-dereferenced via the
    # closed-vocab ``_REASON_KEY`` map, so the literal is invisible to pybabel at the
    # call site. The other credential reasons (grant_mismatch / delivery_failed /
    # awaiting_core / spawn_aborted) are structlog ``reason=`` fields ONLY — never
    # rendered to an operator — so they carry NO catalog key (a dead reservation would
    # be an orphan the bidirectional drift gate rejects).
    t("gateway.adapter.credential.refused.unknown_adapter")
    t("gateway.adapter.credential.refused.missing_secret")
    # G6-4 per-adapter ingress-refusal reasons (#288 / ADR-0036). The closed-vocab set
    # an operator-facing renderer dereferences via ``reason_i18n_key`` (so the literal is
    # invisible to pybabel at the call site). All four are operator-renderable.
    t("gateway.ingress.refused.throttled_rate")
    t("gateway.ingress.refused.throttled_inflight")
    t("gateway.ingress.refused.global_cap_refused")
    t("gateway.ingress.refused.unknown_adapter")
