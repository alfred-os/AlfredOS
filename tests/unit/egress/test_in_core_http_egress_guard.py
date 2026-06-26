"""Connectivity-free-core code ratchet (Spec C §7, epic #333).

Fails if any in-core module gains a NEW external-HTTP-egress client outside the
baseline allowlist. The kernel block (G7-3: core on alfred_internal-only +
internal:true) is the runtime **enforcement-of-record**; this AST guard is its
always-on, non-root, PR-level complement (mirrors the spawn/import guard in
tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py).

Caught (in EVERY binding form, at module scope OR function-local — the walk is
full-tree, symmetric across both checks):

* module imports of the provider SDKs / alt-HTTP libs (anthropic/openai/requests/aiohttp),
* httpx client constructions (``httpx.AsyncClient(...)``, aliased ``import httpx as h;
  h.AsyncClient(...)``) and ``from httpx import AsyncClient`` / ``Client`` (the import
  alone is the offence — the client class has no in-core use outside the egress seam).

NOT forbidden: ``import socket`` (unix-domain sockets are pervasive in-core) and a bare
``import httpx`` (used for ``httpx.Timeout``).

Accepted static-analysis limitations (the G7-3 kernel block, not this lint, is the
enforcement-of-record, so these are conscious gaps, not oversights): a DYNAMIC import
(``importlib.import_module("requests")`` — and ``importlib`` is already used in-core) and
other stdlib HTTP transports (``urllib.request``, ``http.client`` — the latter is already
imported by the gateway CLI) are out of scope here; the netns/network split catches them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "alfred"

# A module import of any of these external-HTTP libraries is forbidden in-core outside
# _IMPORT_ALLOWLIST. (httpx is intentionally absent — a bare ``import httpx`` is fine.)
_FORBIDDEN_IMPORT_MODULES: frozenset[str] = frozenset(
    {"anthropic", "openai", "requests", "aiohttp"}
)

# Files permitted to import a provider SDK today, each with the justification the failure
# message asks future contributors to supply (path -> reason). They wrap the SDK; G7-1
# injects a proxied http_client into the same wrappers.
_IMPORT_ALLOWLIST: dict[str, str] = {
    "providers/anthropic_native.py": "wraps the Anthropic SDK; G7-1 injects a proxied http_client",
    "providers/deepseek.py": "wraps the OpenAI/DeepSeek SDK; G7-1 injects a proxied http_client",
}

# Files permitted to import OR construct an httpx client (httpx.AsyncClient/Client).
# Empty today — no in-core code opens an httpx connection directly. G7-1 adds the
# sanctioned EgressClient module here (path -> reason).
_CONSTRUCT_ALLOWLIST: dict[str, str] = {}

# A broken _SRC_ROOT (a future dir-depth refactor or a src/ rename) would make rglob
# return [] and every guard pass vacuously. The real tree has ~240 files; floor it well
# below that so the ratchet fails loud rather than silently dying green.
_MIN_SRC_FILES = 100


def _rel(path: Path) -> str:
    return path.relative_to(_SRC_ROOT).as_posix()


def _imported_modules(tree: ast.Module) -> set[str]:
    """Every top-level module name imported ANYWHERE in the file.

    Walks the full tree (not just ``tree.body``), so a function-local ``import requests``
    is caught too — symmetric with the httpx construction check below.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module.split(".")[0])
    return names


def _imports_or_constructs_httpx_client(tree: ast.Module) -> bool:
    """True if the module pulls an httpx client into its namespace OR constructs one.

    Catches every binding form so the ratchet can't be bypassed:
      * ``from httpx import AsyncClient`` / ``Client`` (the import alone is the offence),
      * ``httpx.AsyncClient(...)`` and an aliased ``import httpx as h; h.AsyncClient(...)``,
        at module scope or function-local.
    A bare ``import httpx`` (for ``httpx.Timeout``) is NOT an offence on its own.
    """
    httpx_module_aliases: set[str] = {"httpx"}
    httpx_client_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "httpx" and alias.asname:
                    httpx_module_aliases.add(alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.module == "httpx":
            for alias in node.names:
                if alias.name in {"AsyncClient", "Client"}:
                    httpx_client_names.add(alias.asname or alias.name)
    if httpx_client_names:
        return True  # importing the client class in-core is itself the offence
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"AsyncClient", "Client"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in httpx_module_aliases
        ):
            return True
    return False


def _iter_src_files() -> list[Path]:
    return sorted(p for p in _SRC_ROOT.rglob("*.py"))


def test_src_root_resolves_and_is_nonempty() -> None:
    """Fail loud if _SRC_ROOT no longer points at the in-core tree (else the guards pass
    vacuously over zero files and the ratchet is dead while green)."""
    files = _iter_src_files()
    assert len(files) > _MIN_SRC_FILES, (
        f"src scan resolved only {len(files)} files at {_SRC_ROOT} — _SRC_ROOT is wrong; "
        "the egress ratchet would pass vacuously."
    )


def test_no_new_in_core_provider_sdk_import() -> None:
    """No in-core module imports a provider SDK / alt-HTTP lib outside the allowlist."""
    offenders: dict[str, set[str]] = {}
    for path in _iter_src_files():
        rel = _rel(path)
        if rel in _IMPORT_ALLOWLIST:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        bad = _imported_modules(tree) & _FORBIDDEN_IMPORT_MODULES
        if bad:
            offenders[rel] = bad
    assert not offenders, (
        "New in-core external-HTTP-egress import(s) detected outside the egress seam: "
        f"{offenders}. Route egress through the gateway proxy (Spec C); if this is the "
        "sanctioned seam, add the file to _IMPORT_ALLOWLIST with a justification."
    )


def test_no_in_core_httpx_client_import_or_construction() -> None:
    """No in-core module imports OR constructs httpx.AsyncClient/Client outside the allowlist."""
    offenders: list[str] = []
    for path in _iter_src_files():
        rel = _rel(path)
        if rel in _CONSTRUCT_ALLOWLIST:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _imports_or_constructs_httpx_client(tree):
            offenders.append(rel)
    assert not offenders, (
        "In-core httpx client import/construction outside the egress seam: "
        f"{sorted(offenders)}. The proxied client must be built only in the "
        "sanctioned EgressClient (G7-1); add that module to _CONSTRUCT_ALLOWLIST "
        "with a justification."
    )


def test_allowlist_entries_still_exist() -> None:
    """An allowlist entry that no longer exists is stale — fail so it gets pruned."""
    for rel in _IMPORT_ALLOWLIST.keys() | _CONSTRUCT_ALLOWLIST.keys():
        assert (_SRC_ROOT / rel).is_file(), f"stale allowlist entry: {rel}"


# --- self-proving guard logic (synthetic AST snippets; does not depend on the live tree) ---


@pytest.mark.parametrize(
    "src",
    [
        "import requests",
        "def f():\n    import requests",  # function-local — caught by the full-tree walk
        "from openai import AsyncOpenAI",
        "import anthropic",
        "if True:\n    import aiohttp",  # nested in a block
    ],
)
def test_imported_modules_flags_forbidden(src: str) -> None:
    assert _imported_modules(ast.parse(src)) & _FORBIDDEN_IMPORT_MODULES


@pytest.mark.parametrize(
    "src",
    [
        "import socket",
        "import httpx",  # bare httpx (Timeout) is allowed
        "from alfred.providers import deepseek",
    ],
)
def test_imported_modules_allows_benign(src: str) -> None:
    assert not (_imported_modules(ast.parse(src)) & _FORBIDDEN_IMPORT_MODULES)


@pytest.mark.parametrize(
    "src",
    [
        "import httpx\nc = httpx.AsyncClient()",
        "import httpx as h\nc = h.AsyncClient()",  # aliased module
        "from httpx import AsyncClient",  # import alone is the offence
        "from httpx import Client as C",  # aliased class
        "def f():\n    import httpx\n    return httpx.AsyncClient()",  # function-local
    ],
)
def test_httpx_guard_flags_client(src: str) -> None:
    assert _imports_or_constructs_httpx_client(ast.parse(src))


@pytest.mark.parametrize(
    "src",
    [
        "import httpx\nt = httpx.Timeout(1.0)",  # Timeout is fine
        "import socket\ns = socket.socket()",  # unix socket — not egress
        "from alfred.foo import AsyncClient\nc = AsyncClient()",  # not httpx's
    ],
)
def test_httpx_guard_allows_benign(src: str) -> None:
    assert not _imports_or_constructs_httpx_client(ast.parse(src))
