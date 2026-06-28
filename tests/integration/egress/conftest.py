"""Shared fixtures for ``tests/integration/egress/`` (Spec C G7-2c-2, #333).

``fake_external_world``
    Epic-wide fixture that substitutes the relay's injectable ``open_client``
    seam with a deterministic in-memory double.  Every test in the G7-2c-2 and
    C5 suites that needs to count upstream fires or control canned responses
    uses this single shared fixture rather than constructing their own doubles.

The ``_FakeClient`` / ``_FakeResponse`` shapes are defined in
``tests/helpers/egress_doubles`` and imported here; the adversarial conftest
(``tests/adversarial/dlp_egress/conftest.py``) imports from the same source,
guaranteeing both suites exercise identical doubles without duplication.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.helpers.egress_doubles import (
    _CannedResponse,
    _FakeClient,
    make_fake_external_world,
)


@pytest.fixture
def fake_external_world() -> tuple[
    Callable[[], _FakeClient],  # open_client_factory — inject as the relay's open_client seam
    Any,  # _FireCounter — shared fire counter
    _CannedResponse,  # mutable canned response holder
]:
    """Yield ``(open_client_factory, fire_counter, canned_response)``.

    * ``open_client_factory`` — a zero-argument callable returning a fresh
      ``_FakeClient`` bound to the shared ``fire_counter`` and
      ``canned_response``; inject it as the relay's ``open_client`` seam.
    * ``fire_counter`` — a ``_FireCounter`` whose ``.value`` increments each
      time the relay's ``send`` is called; tests assert on this to prove the
      upstream was (or was not) hit.
    * ``canned_response`` — a ``_CannedResponse`` whose fields can be mutated
      between test rounds (Scenario C swaps the body after TTL prune).

    Epic-wide (G7-2c-2 barrier test + C5 contention suite) — a single,
    deterministic shared fixture so the counter and canned response are never
    duplicated across test modules.
    """
    return make_fake_external_world()


__all__ = ["fake_external_world"]
