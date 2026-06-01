"""Supervisor integration tests.

These tests live above the unit tier because they wire together the
supervisor-side capability-gate monitor, the gate's backing-store
availability probe, and the audit writer in shapes that mirror
production wiring. They intentionally use AsyncMock / MagicMock
substitutes for the gate and audit sink (no real Postgres) — the goal
is to pin the supervisor-side coordination contract, not the gate's
own DB-backed behaviour (that lives in
``tests/integration/security/test_capability_gate_fail_closed.py``).
"""
