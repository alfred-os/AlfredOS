"""Unit tests for the plugin-side ``size_limit_bytes`` clamp (CR-146).

The plugin's module comment promises callers may *narrow* the 5 MiB
default but never *widen* it. The clamp helper enforces that ceiling
inside the subprocess so a buggy or compromised host-side caller
cannot make the plugin buffer arbitrary data into memory + Redis
beyond the hard cap.

Defence-in-depth shape: the host (``dispatch_web_fetch``) already caps
before dispatch; this is the subprocess-side belt-and-braces gate that
remains effective even if a capability-bypass exploit at the host
layer were to slip through.
"""

from __future__ import annotations

import pytest

from plugins.alfred_web_fetch.web_fetch_plugin import (  # type: ignore[import-not-found]
    _DEFAULT_SIZE_LIMIT_BYTES,
    _clamp_size_limit,
)


def test_clamp_accepts_value_at_default() -> None:
    """The default value itself passes through unchanged."""
    assert _clamp_size_limit(_DEFAULT_SIZE_LIMIT_BYTES) == _DEFAULT_SIZE_LIMIT_BYTES


def test_clamp_narrows_below_default() -> None:
    """A caller asking for a SMALLER cap gets exactly that — narrowing
    is the only legitimate transformation the param permits.
    """
    assert _clamp_size_limit(1024) == 1024
    assert _clamp_size_limit(1_000_000) == 1_000_000


def test_clamp_caps_at_hard_ceiling() -> None:
    """A caller asking for a LARGER cap is clamped down to the hard
    ceiling — widening is the attack class CR-146 closed.
    """
    assert _clamp_size_limit(_DEFAULT_SIZE_LIMIT_BYTES + 1) == _DEFAULT_SIZE_LIMIT_BYTES
    assert _clamp_size_limit(10 * _DEFAULT_SIZE_LIMIT_BYTES) == _DEFAULT_SIZE_LIMIT_BYTES
    # An obscenely large value — the kind a compromised caller might
    # use to OOM the subprocess — still clamps.
    assert _clamp_size_limit(2**62) == _DEFAULT_SIZE_LIMIT_BYTES


@pytest.mark.parametrize("bad_value", [0, -1, -1_000_000])
def test_clamp_rejects_non_positive(bad_value: int) -> None:
    """Zero and negatives are pathological configs — default rather
    than failing closed. A zero cap would have the same buffer-and-
    truncate semantics as default-zero everywhere else; defaulting
    keeps the contract "always have a sane positive limit".
    """
    assert _clamp_size_limit(bad_value) == _DEFAULT_SIZE_LIMIT_BYTES


@pytest.mark.parametrize(
    "bad_value",
    [
        None,
        "1024",  # str-form caller bug
        "garbage",  # raises ValueError under int()
        [1024],  # list — raises TypeError under int()
        {"size": 1024},  # dict — raises TypeError under int()
        object(),  # arbitrary non-coercible object — raises TypeError
    ],
)
def test_clamp_handles_non_int_types(bad_value: object) -> None:
    """Non-int param types coerce to the default rather than crashing
    the dispatch loop. The JSON-RPC framing layer (err-004) handles
    protocol-shape bugs loud; the param-value layer normalises silently
    because a malformed config is a quieter operator misconfiguration
    class.

    Note ``"1024"`` is a string that ``int()`` would happily parse —
    we explicitly do NOT do that here, because accepting string coercion
    would let a JSON unmarshaller bug ship a stringified larger number
    past the clamp. Fail-closed to the default.

    Actually, ``int("1024")`` succeeds and yields 1024 ≤ cap, so it
    passes through clamped — the test below verifies the boundary.
    """
    # ``int("1024")`` succeeds, then ≤ cap → returns 1024.
    # ``int("garbage")`` raises ValueError → returns default.
    # ``int(None)`` raises TypeError → returns default.
    result = _clamp_size_limit(bad_value)
    if bad_value == "1024":
        assert result == 1024
    else:
        assert result == _DEFAULT_SIZE_LIMIT_BYTES


def test_clamp_handles_float_via_int_truncation() -> None:
    """Floats truncate via ``int()`` (3.7 → 3, 1e9 → 1_000_000_000)
    and then go through the same clamp. Documenting the path so a
    future caller knows the contract is "int-or-coerce".
    """
    assert _clamp_size_limit(3.7) == 3
    assert _clamp_size_limit(float(_DEFAULT_SIZE_LIMIT_BYTES + 100)) == _DEFAULT_SIZE_LIMIT_BYTES
    # NaN / infinity raise OverflowError or ValueError under int();
    # both are covered by the ``except (TypeError, ValueError)`` arm
    # except OverflowError, which int(inf) raises and is NOT caught —
    # by design, because an OverflowError on a float cap is a
    # programmer bug worth surfacing rather than silently defaulting.
    with pytest.raises(OverflowError):
        _clamp_size_limit(float("inf"))
