"""Test-only helper package for the AlfredOS test suite.

Empty package marker so ``tests/helpers/`` is importable as
``tests.helpers``. Concrete helpers live in submodules:

* :mod:`tests.helpers.audit` — :class:`RecordingAuditSink` double.
* :mod:`tests.helpers.dlp` — :func:`identity_outbound_dlp` no-op helper.
* :mod:`tests.helpers.egress_doubles` — shared egress relay in-memory doubles
  (``_FireCounter``, ``_CannedResponse``, ``_FakeClient``, ``_FakeResponse``,
  ``make_fake_external_world``).
* :mod:`tests.helpers.gates` — :class:`CapabilityGate` test fixtures.
"""
