"""#410 PR1 (fleet finding M-9): supervisor CLI engines carry the explicit CONTROL shape.

The three sync read helpers used to build create_engine(url, pool_pre_ping=True)
— an unconfigured default pool, the exact anti-pattern ADR-0062 claims cannot
recur. One helper, one pinned shape, one test.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from alfred.cli import supervisor as supervisor_mod


def test_control_engine_pins_the_explicit_control_pool_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = MagicMock(return_value=MagicMock(name="engine"))
    monkeypatch.setattr(supervisor_mod, "create_engine", captured)
    monkeypatch.setattr(
        supervisor_mod, "_resolve_database_url", lambda: "postgresql+psycopg2://x:y@h/db"
    )
    supervisor_mod._control_engine()
    kwargs = captured.call_args.kwargs
    assert kwargs["pool_size"] == 5
    assert kwargs["max_overflow"] == 10
    assert kwargs["pool_pre_ping"] is True


def test_no_bare_create_engine_call_sites_remain() -> None:
    """Default-deny the CLASS, not the three known sites: any supervisor.py
    call reaching create_engine without an explicit pool_size is a
    regression to the unconfigured-pool shape. Source-level scan — the
    lexical rule CAN decide this (a keyword argument's presence is a
    lexical fact), unlike runtime pool behaviour, which the kwargs test
    above covers."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(supervisor_mod))
    bare_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "create_engine"
        and "pool_size" not in {kw.arg for kw in node.keywords}
    ]
    assert bare_calls == [], (
        f"unconfigured create_engine call(s) at supervisor.py line(s) {bare_calls} — "
        "route through _control_engine() (ADR-0062)"
    )
