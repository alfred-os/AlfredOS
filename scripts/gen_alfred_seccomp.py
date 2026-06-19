#!/usr/bin/env python3
"""Regenerate ``docker/seccomp/alfred-bwrap.json`` from Docker's default profile.

AlfredOS #290. The dual-LLM quarantine child runs under ``bubblewrap``, which
must build user/mount/pid namespaces. Docker's *default* seccomp profile blocks
the namespace syscalls (``clone``/``clone3``/``unshare``/...) unless the process
holds ``CAP_SYS_ADMIN`` — so the child cannot spawn as the non-root ``alfred``
user (see the #288/G6-0b probe matrix).

This script takes a pinned copy of Docker's default profile and PREPENDS one
unconditional ``SCMP_ACT_ALLOW`` rule for exactly the namespace syscalls
bubblewrap needs. Everything else in the default profile is preserved verbatim —
this is the *scalpel* alternative to ``seccomp=unconfined``.

Why pin a copy rather than read the live daemon's profile? An operator running
``bin/alfred-setup.sh`` offline (or in CI) must get a deterministic, reviewable
artifact. The committed JSON is the source of truth; this script documents how it
was produced and lets a maintainer refresh it against a newer Docker default.

Usage::

    # Refresh from the pinned Docker default (downloads it):
    python3 scripts/gen_alfred_seccomp.py

    # Or feed a local copy of Docker's default profile:
    python3 scripts/gen_alfred_seccomp.py --default-profile /path/to/default.json

The script is deterministic: re-running it on the same Docker default yields a
byte-identical ``docker/seccomp/alfred-bwrap.json``.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

# Pinned Docker default seccomp profile (moby v24.0.0). Pinning a tag (not
# ``master``) keeps the regeneration reproducible; bump deliberately when
# refreshing against a newer Docker Engine default.
_DEFAULT_PROFILE_URL = (
    "https://raw.githubusercontent.com/moby/moby/v24.0.0/profiles/seccomp/default.json"
)

# The namespace syscalls bubblewrap needs to assemble its sandbox as a non-root,
# non-CAP_SYS_ADMIN process. This is the ONLY delta over Docker's default.
_USERNS_SYSCALLS = [
    "clone",  # bwrap forks the sandboxed child with CLONE_NEWUSER|NEWNS|NEWPID|...
    "clone3",  # glibc may route fork() via clone3 on newer kernels (default ERRNOs it)
    "unshare",  # bwrap unshares the user / mount namespaces
    "setns",  # entering namespaces during sandbox assembly
    "mount",  # bind / tmpfs / proc mounts inside the new mount namespace
    "umount2",  # tearing down the old root after pivot_root
    "pivot_root",  # bwrap pivots into the sandbox root
    "keyctl",  # session-keyring isolation in the new user namespace
]

_PROFILE_COMMENT = (
    "AlfredOS custom seccomp profile (#290). Faithful copy of Docker's default "
    "profile (moby v24.0.0) PLUS an unconditional ALLOW for the namespace "
    "syscalls bubblewrap needs (clone/clone3/unshare/setns/mount/umount2/"
    "pivot_root/keyctl) so the dual-LLM quarantine child can build its sandbox "
    "as the non-root 'alfred' user without CAP_SYS_ADMIN. This is the SCALPEL "
    "alternative to 'seccomp=unconfined': every other Docker default deny is "
    "preserved. Regenerate with scripts/gen_alfred_seccomp.py."
)

_OUTPUT = Path(__file__).resolve().parent.parent / "docker" / "seccomp" / "alfred-bwrap.json"


def _load_default(path: str | None) -> dict[str, Any]:
    if path is not None:
        loaded = json.loads(Path(path).read_text())
    else:
        with urllib.request.urlopen(_DEFAULT_PROFILE_URL) as resp:  # noqa: S310 - pinned https tag URL
            loaded = json.loads(resp.read().decode("utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError(f"Docker default seccomp profile is not a JSON object: {type(loaded)!r}")
    return loaded


def build(default_profile: dict[str, Any]) -> dict[str, Any]:
    """Return the AlfredOS profile = default + the prepended userns ALLOW rule."""
    allow_userns = {
        "names": list(_USERNS_SYSCALLS),
        "action": "SCMP_ACT_ALLOW",
        "comment": (
            "AlfredOS #290: allow bwrap to build its user/mount/pid namespaces as "
            "a non-root, non-CAP_SYS_ADMIN process for the dual-LLM quarantine "
            "child. Minimal delta over docker-default — NOT seccomp=unconfined."
        ),
    }
    syscalls = [allow_userns, *default_profile.get("syscalls", [])]
    return {
        "_comment": _PROFILE_COMMENT,
        **{k: v for k, v in default_profile.items() if k != "syscalls"},
        "syscalls": syscalls,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--default-profile",
        help="Path to a local Docker default seccomp profile (else download the pinned tag).",
    )
    args = parser.parse_args()

    default_profile = _load_default(args.default_profile)
    profile = build(default_profile)
    _OUTPUT.write_text(json.dumps(profile, indent=2) + "\n")
    print(f"wrote {_OUTPUT} ({len(profile['syscalls'])} syscall blocks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
