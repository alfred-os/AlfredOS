"""Put the plugin's ``src/`` on ``sys.path`` so ``import alfred_tui`` resolves.

``alfred_tui`` is a standalone uv package (``pyproject.toml`` declares
``packages = ["src/alfred_tui"]``). In-tree it is NOT pip-installed, so the
repo-root ``pythonpath = ["."]`` (which makes ``plugins.*`` importable) does
not by itself expose the bare ``alfred_tui`` top-level package the plugin's own
modules import each other by. This conftest prepends ``plugins/alfred_tui/src``
to ``sys.path`` for the plugin's test session, mirroring how the package would
resolve once installed as a wheel.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
