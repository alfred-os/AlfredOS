"""Audit-test-local conftest.

The ``audit_buffer`` fixture lives in ``tests/unit/conftest.py`` (one level
up) so the identity CLI tests (T14) and any future cross-subsystem caller
can consume it. pytest auto-discovers parent conftests, so callers in
``tests/unit/audit/`` pick it up transparently — this file is intentionally
empty save for documentation.
"""
