"""Verify the three Slice-4 hookpoints this PR owns are registered (#174).

Adapted to the real Slice-3/PR-S4-3 registry surface: the accessor is
``get_registry`` (not ``get_global_registry``), the metadata getter is
``hookpoint_meta``, and ``carrier_tier`` holds the ``T0`` class (not the
string "T0").
"""

from __future__ import annotations

import pytest

from alfred.hooks import get_registry
from alfred.security.tiers import T0


@pytest.fixture(autouse=True)
def _declare_daemon_hookpoints() -> None:
    """Declare the daemon hookpoints against the active registry.

    Importing the module runs its module-level ``declare_hookpoints()``,
    but the conftest registry-swap fixtures may install a fresh registry
    AFTER that import. Re-declaring against the live registry keeps the
    assertions independent of import ordering.
    """
    import alfred.cli.daemon

    alfred.cli.daemon.declare_hookpoints(get_registry())


@pytest.mark.parametrize(
    "name",
    [
        "daemon.boot.completed",
        "daemon.boot.failed",
        "proposal.dispatch.failed",
    ],
)
def test_hookpoint_declared(name: str) -> None:
    meta = get_registry().hookpoint_meta(name)
    assert meta is not None, f"{name} not declared"


@pytest.mark.parametrize(
    "name",
    [
        "daemon.boot.completed",
        "daemon.boot.failed",
        "proposal.dispatch.failed",
    ],
)
def test_hookpoint_carrier_tier_is_t0(name: str) -> None:
    meta = get_registry().hookpoint_meta(name)
    assert meta is not None
    assert meta.carrier_tier is T0


@pytest.mark.parametrize(
    "name",
    [
        "daemon.boot.completed",
        "daemon.boot.failed",
        "proposal.dispatch.failed",
    ],
)
def test_hookpoint_fail_closed_true(name: str) -> None:
    meta = get_registry().hookpoint_meta(name)
    assert meta is not None
    assert meta.fail_closed is True
