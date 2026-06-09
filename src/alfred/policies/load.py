"""Pure load + parse + hash helpers for ``config/policies.yaml`` (ADR-0023).

These functions are deliberately side-effect-light so the watcher's ``_tick``
can run them inside ``asyncio.to_thread`` (closure perf-001) without touching
the event loop. They raise typed errors the watcher routes to the right
``CONFIG_RELOAD_REJECTED_FIELDS(reason=...)`` branch:

* :exc:`PolicyFileTooLarge` -> ``reason="parse_failure"`` (oversize guard)
* :exc:`FileNotFoundError` / :exc:`OSError` -> ``reason="file_vanished"`` /
  ``"stat_failed"`` (the watcher stats first, but the open-then-fstat path can
  also raise these and the watcher treats them the same way)
* :class:`yaml.YAMLError` -> ``reason="parse_failure"``
* Pydantic ``ValidationError`` -> ``reason="validation_failure"``

sec-1 closure (TOCTOU-safe load): :func:`load_yaml_bytes` opens the path with
``O_RDONLY | O_NOFOLLOW`` then ``fstat``s the already-open fd. An attacker who
swaps the inode (rename ``policies.yaml`` to a symlink pointing at attacker
content) between an external stat and our read cannot redirect us: ``O_NOFOLLOW``
refuses to open a symlink, and the size cap + read both consult the fd we
actually hold, never a path re-resolved a second time.
"""

from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path
from typing import Final

import yaml

from alfred.policies.model import PoliciesV1

MAX_POLICIES_BYTES: Final[int] = 256 * 1024
"""256 KB hard cap. ``config/policies.yaml`` is < 5 KB in practice; the cap
defends the YAML parser against an OOM payload (csb-2026-002)."""


class PolicyFileTooLarge(ValueError):  # noqa: N818 — name is part of the public contract (csb-2026-002)
    """The policies file (or raw bytes) exceeds :data:`MAX_POLICIES_BYTES`.

    Subclasses :class:`ValueError` so existing ``except ValueError`` callers
    in the watcher route it to the ``parse_failure`` branch, while a precise
    ``except PolicyFileTooLarge`` in tests can assert the oversize refusal.
    """


def load_yaml_bytes(path: Path, *, max_size: int = MAX_POLICIES_BYTES) -> bytes:
    """Read YAML bytes from ``path`` TOCTOU-safely with a hard size cap.

    Opens with ``O_RDONLY | O_NOFOLLOW`` (refuses symlinks), ``fstat``s the
    open fd, enforces the size cap against that authoritative stat, then reads
    exactly ``st_size`` bytes from the same fd. See module docstring (sec-1).

    Raises:
        FileNotFoundError: ``path`` does not exist.
        OSError: ``path`` is a symlink (``ELOOP`` under ``O_NOFOLLOW``) or any
            other open/stat/read failure. The watcher routes these to its
            ``file_vanished`` / ``stat_failed`` branches.
        PolicyFileTooLarge: the file exceeds ``max_size``.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        stat = os.fstat(fd)
        if stat.st_size > max_size:
            raise PolicyFileTooLarge(
                f"policies.yaml size {stat.st_size} exceeds max {max_size} bytes"
            )
        return os.read(fd, stat.st_size)
    finally:
        os.close(fd)


def parse_policies(raw: bytes, *, max_size_bytes: int) -> PoliciesV1:
    """Parse-validate raw YAML bytes to :class:`PoliciesV1`.

    Raises:
        PolicyFileTooLarge: ``raw`` exceeds ``max_size_bytes`` (defence in
            depth — the on-disk read already capped, but a caller handing raw
            bytes is re-checked).
        yaml.YAMLError: ``raw`` is not well-formed YAML
            (-> watcher ``reason="parse_failure"``).
        pydantic.ValidationError: the parsed mapping violates the model
            (-> watcher ``reason="validation_failure"``).
    """
    if len(raw) > max_size_bytes:
        raise PolicyFileTooLarge(f"raw policies bytes {len(raw)} exceed max {max_size_bytes} bytes")
    data = yaml.safe_load(raw) or {}
    return PoliciesV1.model_validate(data)


def compute_sha256(canonical_bytes: bytes) -> str:
    """Return the hex SHA-256 of ``canonical_bytes`` (the idempotency key)."""
    return sha256(canonical_bytes).hexdigest()


def canonical_bytes(model: PoliciesV1) -> bytes:
    """Return the canonical YAML serialization of ``model`` for hashing.

    Sorted keys + JSON-mode dump so two semantically-equal files that differ
    only in whitespace / key order hash identically — the SHA short-circuit
    (sec-007) collapses a no-op edit to nothing.
    """
    return yaml.safe_dump(model.model_dump(mode="json"), sort_keys=True).encode("utf-8")


__all__ = [
    "MAX_POLICIES_BYTES",
    "PolicyFileTooLarge",
    "canonical_bytes",
    "compute_sha256",
    "load_yaml_bytes",
    "parse_policies",
]
