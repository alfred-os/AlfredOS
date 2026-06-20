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
