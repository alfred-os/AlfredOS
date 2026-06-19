"""Drift guard for the custom bwrap seccomp profile (#290).

``docker/seccomp/alfred-bwrap.json`` is a GENERATED artifact:
``scripts/gen_alfred_seccomp.py`` takes the vendored moby v24.0.0 default profile
and prepends the minimal namespace-syscall ALLOW bubblewrap needs. The committed
JSON is the source of truth the compose ``security_opt`` points at; if a
maintainer hand-edits it (or the generator changes) without regenerating, the
deployed profile silently diverges from what the script documents.

This test asserts the committed JSON is byte-identical to a fresh build from the
vendored default. It is OFFLINE — it reads the vendored base, never the network —
so it runs hermetically in CI. To fix a failure, run::

    python3 scripts/gen_alfred_seccomp.py

and commit the result (or, for a deliberate moby-default refresh,
``python3 scripts/gen_alfred_seccomp.py --download`` first).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_GENERATOR = _REPO_ROOT / "scripts" / "gen_alfred_seccomp.py"
_COMMITTED = _REPO_ROOT / "docker" / "seccomp" / "alfred-bwrap.json"
_VENDORED_DEFAULT = _REPO_ROOT / "scripts" / "vendor" / "moby-seccomp-default-v24.0.0.json"


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_alfred_seccomp", _GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_seccomp_profile_matches_generator() -> None:
    """The committed profile must equal a fresh build from the vendored default.

    A mismatch means someone hand-edited docker/seccomp/alfred-bwrap.json (or
    changed the generator) without regenerating — the deployed seccomp policy
    would no longer match what scripts/gen_alfred_seccomp.py documents (#290).
    """
    gen = _load_generator()
    default_profile = json.loads(_VENDORED_DEFAULT.read_text())
    rendered = gen.render(default_profile)
    committed = _COMMITTED.read_text()
    assert rendered == committed, (
        "docker/seccomp/alfred-bwrap.json is OUT OF SYNC with "
        "scripts/gen_alfred_seccomp.py. Run "
        "`python3 scripts/gen_alfred_seccomp.py` and commit the result."
    )


def test_userns_syscalls_present_in_committed_profile() -> None:
    """The committed profile must carry the namespace-syscall ALLOW delta (#290).

    Pins the actual security property the profile exists for: bwrap's namespace
    syscalls are ALLOWed. A regeneration that silently dropped the delta would
    re-break the dual-LLM spawn, and the byte-equality test alone would still
    pass (both sides would be wrong together).
    """
    gen = _load_generator()
    profile = json.loads(_COMMITTED.read_text())
    allowed: set[str] = set()
    for block in profile["syscalls"]:
        if block.get("action") == "SCMP_ACT_ALLOW":
            allowed.update(block.get("names", []))
    assert set(gen._USERNS_SYSCALLS) <= allowed, (
        "The committed seccomp profile is missing the bwrap namespace-syscall "
        f"ALLOW delta {sorted(set(gen._USERNS_SYSCALLS) - allowed)} (#290)."
    )
