"""AST static guard for :mod:`alfred.plugins._comms_child_env` (PR-S4-11a Wave 1).

Mirrors ``tests/unit/cli/test_launcher_spawn_env_scrub.py``, but scoped to the
WHOLE module: unlike ``_launcher_spawn`` (which legitimately reads the full host
env for the ``kind="none"`` operator-local TUI passthrough), the daemon-hosted
comms child env is SCRUBBED for every sandbox kind. The module therefore has no
sanctioned blanket-env read at all — a ``dict(os.environ)`` / ``os.environ.copy()``
/ ``os.getenv(...)`` anywhere in it is the #237 leak the daemon comms tightening
exists to prevent.
"""

from __future__ import annotations

import ast
import inspect

from alfred.plugins import _comms_child_env

_ENVIRON_NAMES = frozenset({"environ", "environb"})
_GETENV_NAMES = frozenset({"getenv", "getenvb"})


def _is_os_environ(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
        and node.attr in _ENVIRON_NAMES
    )


def _reads_full_env(source: str) -> bool:
    """True if ``source`` reads the host env outside the sanctioned allowlist.

    The ONLY sanctioned ``os.environ`` reads are the per-key subscript
    (``os.environ[name]``) and the membership test (``name in os.environ``).
    EVERY other shape is flagged — that closes the #237 foot-gun comprehensively
    rather than enumerating a fixed blocklist a future patch could route around:

    * ``dict(os.environ)`` / ``os.getenv(...)`` — the classic blanket copies;
    * ``os.environ.copy()`` / ``.items()`` / ``.values()`` / ``.get(...)`` — any
      attribute access on ``os.environ`` (a method call leaks more than one key);
    * ``return os.environ`` — a bare reference handing out the whole mapping;
    * ``{**os.environ}`` — dict-unpacking the whole mapping.
    """
    tree = ast.parse(source)
    # First pass: mark the os.environ nodes that ARE sanctioned (subscript value,
    # membership comparator) so the bare-reference sweep can exempt them.
    sanctioned: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and _is_os_environ(node.value):
            sanctioned.add(id(node.value))
        elif isinstance(node, ast.Compare):
            for comparator in node.comparators:
                if _is_os_environ(comparator):
                    sanctioned.add(id(comparator))

    for node in ast.walk(tree):
        # dict(os.environ)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "dict"
            and any(_is_os_environ(a) for a in node.args)
        ):
            return True
        # os.getenv(...) / os.getenvb(...)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr in _GETENV_NAMES
        ):
            return True
        # {**os.environ}
        if isinstance(node, ast.Dict) and any(
            key is None and _is_os_environ(value)
            for key, value in zip(node.keys, node.values, strict=True)
        ):
            return True
        # os.environ.<attr> — any attribute access (copy/items/values/keys/get/...)
        if isinstance(node, ast.Attribute) and _is_os_environ(node.value):
            return True
        # A bare ``os.environ`` reference anywhere other than a sanctioned
        # subscript value or membership comparator (e.g. ``return os.environ``).
        if _is_os_environ(node) and id(node) not in sanctioned:
            return True
    return False


def test_comms_child_env_module_reads_no_full_host_env() -> None:
    """The whole ``_comms_child_env`` module holds no blanket host-env read.

    Release-blocker: a future patch that re-introduces ``dict(os.environ)`` (or
    any bare-environ read) would re-leak the operator's secrets into a
    daemon-hosted, adversary-facing comms relay (#237).
    """
    source = inspect.getsource(_comms_child_env)
    assert not _reads_full_env(source), (
        "_comms_child_env reads the full host env — the daemon comms child env "
        "must be built from the explicit allowlist (#237)"
    )


def test_guard_helper_catches_full_env_read() -> None:
    """Self-test: the AST helper flags EVERY non-allowlisted host-env read.

    The blanket-copy classics plus the bypass shapes CodeRabbit flagged on PR
    #238 (bare reference, dict-unpacking, attribute-method access) — so the guard
    can never silently rot into "only blocks ``dict(os.environ)``".
    """
    # Blanket copies + single-shot reads.
    assert _reads_full_env("import os\ndef f():\n    return dict(os.environ)\n")
    assert _reads_full_env("import os\ndef f():\n    return os.environ.copy()\n")
    assert _reads_full_env("import os\ndef f():\n    return os.getenv('X')\n")
    # Bypass shapes: bare reference, dict-unpacking, attribute-method access.
    assert _reads_full_env("import os\ndef f():\n    return os.environ\n")
    assert _reads_full_env("import os\ndef f():\n    return {**os.environ}\n")
    assert _reads_full_env("import os\ndef f():\n    return os.environ.items()\n")
    assert _reads_full_env("import os\ndef f():\n    return os.environ.get('X')\n")
    # Sanctioned: a literal dict, and the allowlisted subscript + membership comp.
    assert not _reads_full_env("def f():\n    return {'PATH': '/usr/bin'}\n")
    assert not _reads_full_env(
        "import os\ndef f():\n    return {k: os.environ[k] for k in ('PATH',) if k in os.environ}\n"
    )
