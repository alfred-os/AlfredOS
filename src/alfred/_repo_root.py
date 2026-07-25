"""Single source of truth for the in-tree repo root (#500).

Resolves the directory that ships ``plugins/``, ``bin/``, ``config/``, and
``alembic.ini`` — the runtime artifacts the running container / a source
checkout reads by PATH (as opposed to the installed ``alfred`` package, which
carries only Python code + the wheel-embedded ``_locale``).

WHY this is ONE module: in the shipped image ``alfred`` is installed
NON-editable into a PBS python prefix, so ``Path(__file__).parents[N]`` in any
``alfred.*`` module resolves under the interpreter's ``site-packages``, NOT the
repo root — and modules at different nesting depths overshoot by different
amounts. Routing every call site through this resolver removes that drift and
makes the installed image depend on an explicit deploy seam
(``ALFRED_REPO_ROOT``, set to ``/app`` by ``docker/alfred-core.Dockerfile``)
instead of ``__file__`` arithmetic. Dependency-free (``os`` + ``pathlib`` only)
so ``config/settings.py`` may import it during very-early boot without a cycle.

Trust model (ADR-0055): ``ALFRED_REPO_ROOT`` is a PROCESS-environment seam set
by whoever controls process launch (the Dockerfile / an operator). It is NOT a
T3-reachable or lower-trust source — no untrusted content can set it — so it
needs none of the ``/etc``-vs-env precedence machinery ADR-0053 gives
``environment``. It only relocates where in-tree artifacts are read from; the
manifest path-traversal containment guard re-anchors to the resolved root and is
unchanged.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Deploy-time seam. The Dockerfile sets it to ``/app`` (WORKDIR).
_REPO_ROOT_ENV = "ALFRED_REPO_ROOT"

#: Terminal container fallback (mirrors the ``/app`` fallback in
#: ``i18n/translator.py``): reached when neither the env seam nor a
#: marker-bearing source tree resolves.
_CONTAINER_ROOT = Path("/app")

#: The artifact whose presence distinguishes a source checkout / editable
#: install from an installed ``site-packages`` layout.
_ROOT_MARKER = "plugins"


def _resolve(env_value: str | None, module_path: Path) -> Path:
    """Pure resolution: explicit seam > marker-bearing source tree > ``/app``."""
    if env_value is not None and env_value.strip():
        return Path(env_value.strip())
    source_root = module_path.resolve().parents[2]
    if (source_root / _ROOT_MARKER).is_dir():
        return source_root
    return _CONTAINER_ROOT


def repo_root() -> Path:
    """Return the directory that ships ``plugins/``, ``bin/``, ``config/``."""
    return _resolve(os.environ.get(_REPO_ROOT_ENV), Path(__file__))
