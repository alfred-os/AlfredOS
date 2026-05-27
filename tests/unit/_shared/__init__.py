"""Cross-test helpers that don't belong to any single subsystem.

Coverage exclusion is configured at the package level (``pyproject.toml``'s
coverage config already excludes ``tests/``). PR D1's
``test_no_direct_adapter_imports.py`` and PR C's ``test_no_direct_env_reads.py``
share :func:`import_violation._remediation_message` so both
boundary-enforcement tests produce identical failure-output shape (te-004).
"""
