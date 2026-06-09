"""Pure load + parse + hash helpers for ``config/policies.yaml`` (ADR-0023).

These functions are deliberately side-effect-light so the watcher's ``_tick``
can run them inside ``asyncio.to_thread`` (closure perf-001) without touching
the event loop. They raise typed errors the watcher routes to the right
``CONFIG_RELOAD_REJECTED_FIELDS(reason=...)`` branch:

* :exc:`PolicyFileTooLarge` -> ``reason="parse_failure"`` (oversize guard)
* :exc:`PolicyFileTruncated` -> ``reason="parse_failure"`` (concurrent-truncation
  guard: the file shrank between ``fstat`` and the final read)
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


class PolicyFileTruncated(ValueError):  # noqa: N818 — name is part of the public contract (sec-1)
    """The read returned fewer bytes than ``fstat`` reported (concurrent truncate).

    ``load_yaml_bytes`` loops until ``st_size`` bytes are read or EOF. If EOF
    arrives early the file was truncated under us between the ``fstat`` and the
    final read — refusing to parse a half-written file is safer than feeding the
    YAML parser an arbitrary prefix. Subclasses :class:`ValueError` so the
    watcher's existing ``except ValueError`` arm routes it to ``parse_failure``
    (a truncated file is not parseable; the watcher re-emits the rejection every
    tick until the writer finishes — sec-2).
    """


def load_yaml_bytes(path: Path, *, max_size: int = MAX_POLICIES_BYTES) -> bytes:
    """Read YAML bytes from ``path`` TOCTOU-safely with a hard size cap.

    Opens with ``O_RDONLY | O_NOFOLLOW`` (refuses symlinks), ``fstat``s the
    open fd, enforces the size cap against that authoritative stat, then reads
    exactly ``st_size`` bytes from the same fd. See module docstring (sec-1).

    The read loops until ``st_size`` bytes are accumulated or EOF: a single
    ``os.read`` may return a SHORT read (fewer than the requested bytes) on some
    filesystems or when interrupted by a signal, so a one-shot
    ``os.read(fd, st_size)`` could silently hand a truncated prefix to the
    parser. An early EOF (total read < ``st_size``) means the file was truncated
    concurrently — we refuse with :exc:`PolicyFileTruncated` rather than parse a
    half-written file.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        OSError: ``path`` is a symlink (``ELOOP`` under ``O_NOFOLLOW``) or any
            other open/stat/read failure. The watcher routes these to its
            ``file_vanished`` / ``stat_failed`` branches.
        PolicyFileTooLarge: the file exceeds ``max_size``.
        PolicyFileTruncated: the file shrank between ``fstat`` and the final
            read (concurrent truncation).
    """
    return load_yaml_bytes_with_stat(path, max_size=max_size)[0]


def load_yaml_bytes_with_stat(
    path: Path, *, max_size: int = MAX_POLICIES_BYTES
) -> tuple[bytes, os.stat_result]:
    """Like :func:`load_yaml_bytes` but also returns the authoritative fstat.

    sec-1 / CR round-3: the returned :class:`os.stat_result` is the ``fstat`` of
    the SAME open fd the bytes were read from — there is exactly ONE stat per
    load. Callers that need the file's mtime/size (e.g.
    :func:`alfred.policies.snapshot_ref.build_initial_snapshot` building the
    bootstrap snapshot) MUST reuse this result rather than re-``stat``-ing the
    path, which would reopen a TOCTOU window between the read and the restat.

    Raises:
        FileNotFoundError, OSError, PolicyFileTooLarge, PolicyFileTruncated:
            see :func:`load_yaml_bytes`.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        stat = os.fstat(fd)
        if stat.st_size > max_size:
            raise PolicyFileTooLarge(
                f"policies.yaml size {stat.st_size} exceeds max {max_size} bytes"
            )
        buf = bytearray()
        while len(buf) < stat.st_size:
            chunk = os.read(fd, stat.st_size - len(buf))
            if not chunk:  # EOF before st_size bytes -> concurrent truncation.
                raise PolicyFileTruncated(
                    f"policies.yaml shrank during read: got {len(buf)} of "
                    f"{stat.st_size} bytes (concurrent truncation)"
                )
            buf.extend(chunk)
        return bytes(buf), stat
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
    "PolicyFileTruncated",
    "canonical_bytes",
    "compute_sha256",
    "load_yaml_bytes",
    "load_yaml_bytes_with_stat",
    "parse_policies",
]
