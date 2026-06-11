"""Guard: pytest-asyncio must stay in ``auto`` mode, or async tests rot silently.

This suite has ~1,200 ``async def test_`` functions; roughly half carry no
explicit ``@pytest.mark.asyncio`` marker and rely entirely on
``asyncio_mode = "auto"`` (``pyproject.toml`` ``[tool.pytest.ini_options]``).

The footgun: if that mode ever drifts to pytest-asyncio's own default
(``"strict"``) — a dependency bump changing defaults, a config refactor, a
copied ``pytest.ini`` — every *unmarked* async test stops being awaited.
pytest-asyncio collects the coroutine, never runs it, and the test reports
**green without ever evaluating a single assertion** (a false pass). For a
security-hardened project whose CI test gate is release-blocking, a whole class
of tests silently going vacuous is a real reliability hole.

This guard closes the root cause once, for every async test present and future,
instead of decorating 640 call sites that the next-written test would re-open.

CRITICAL — this guard is deliberately **synchronous** (``def``, not
``async def``). A sync test always executes regardless of the asyncio mode; an
async guard would itself vacuously pass under the very ``strict``-mode drift it
exists to detect, making it worse than useless. Do not convert it to ``async``.
"""

from __future__ import annotations

import pytest


def test_asyncio_mode_is_auto(pytestconfig: pytest.Config) -> None:
    """The resolved pytest-asyncio mode must be ``auto``.

    Reads the *effective* ini value (``getini``), so a flip from any source —
    ``pyproject.toml``, a stray ``pytest.ini``, a CLI ``-o`` override — trips
    the guard, not just an edit to the file we expect.
    """
    resolved = pytestconfig.getini("asyncio_mode")
    assert resolved == "auto", (
        "pytest-asyncio mode has drifted to "
        f"{resolved!r}; it must stay 'auto'. Under 'strict' mode every async "
        "test WITHOUT an explicit @pytest.mark.asyncio marker (~640 in this "
        "suite) is collected but never awaited — it passes vacuously, its "
        "assertions never run. Restore asyncio_mode = 'auto' in "
        "pyproject.toml, or mark every async test explicitly before changing "
        "the mode."
    )
