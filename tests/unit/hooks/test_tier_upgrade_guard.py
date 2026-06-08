"""Strict total-order tier-upgrade guard (PR-S4-3, ADR-0022 Critical 5).

Matrix (passes iff source_tier <= carrier_tier in strict total order
T0 < T1 < T2 < T3):

```
                carrier=T0   carrier=T1   carrier=T2   carrier=T3
  sub_tier=T0   PASS         PASS         PASS         PASS
  sub_tier=T1   REFUSE       PASS         PASS         PASS
  sub_tier=T2   REFUSE       REFUSE       PASS         PASS
  sub_tier=T3   REFUSE       REFUSE       REFUSE       PASS
```

The guard is a pure predicate (returns bool) — the audit row + the
``ReRaise()`` disposition on refusal live in the caller (``_run_error``).
"""

from __future__ import annotations

from typing import Literal

import pytest

from alfred.hooks.invoke import _enforce_substitute_tier
from alfred.security.tiers import T0, T1, T2, T3, TrustTier

Tier = Literal["T0", "T1", "T2", "T3"]


@pytest.mark.parametrize(
    ("carrier", "substitute", "should_pass"),
    [
        # carrier=T0 row
        (T0, "T0", True),
        (T0, "T1", False),
        (T0, "T2", False),
        (T0, "T3", False),
        # carrier=T1 row
        (T1, "T0", True),
        (T1, "T1", True),
        (T1, "T2", False),
        (T1, "T3", False),
        # carrier=T2 row
        (T2, "T0", True),
        (T2, "T1", True),
        (T2, "T2", True),
        (T2, "T3", False),
        # carrier=T3 row
        (T3, "T0", True),
        (T3, "T1", True),
        (T3, "T2", True),
        (T3, "T3", True),
    ],
)
def test_strict_total_order_matrix(
    carrier: type[TrustTier],
    substitute: Tier,
    should_pass: bool,  # noqa: FBT001
) -> None:
    """16-cell parametric matrix pins every (carrier, substitute) pair."""
    passed = _enforce_substitute_tier(carrier_tier=carrier, source_tier=substitute)
    assert passed is should_pass
