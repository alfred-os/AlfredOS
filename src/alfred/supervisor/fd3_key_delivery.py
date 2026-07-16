"""Provider-key fd-3 delivery (spec §7.5, PR-S4-6 Component F — sec-3 keystone).

The Supervisor delivers the quarantined provider key to a sandboxed plugin
out-of-band over fd 3 (the launcher passes fd 3 through to the plugin via
bwrap's DEFAULT fd inheritance — no CLI flag; bwrap inherits open, non-CLOEXEC
fds into the sandboxed child. ``--sync-fd`` is bwrap's internal sync fd and is
NOT used here: pointing it at fd 3 would CONSUME the descriptor, severing the
channel (verified bwrap 0.8.0/0.9.0, #218). The launcher itself never reads
fd 3). The wire framing is a 4-byte big-endian length prefix followed by the
key bytes.

sec-3 (round-4) hardening:

* **Single atomic syscall.** The length prefix and the key bytes go in ONE
  :func:`os.writev` call. On POSIX a writev to a pipe of a payload below
  ``PIPE_BUF`` is atomic, so a reader never observes a torn frame and no
  second writer can interleave between prefix and body.

* **Refuse on partial / EAGAIN.** If ``writev`` returns fewer bytes than the
  full frame, or raises ``BlockingIOError`` / ``OSError``, the Supervisor
  REFUSES to spawn the plugin (raises :class:`ProviderKeyDeliveryError` with
  ``reason="provider_key_delivery_failed"``) rather than handing the plugin a
  truncated key. The ``provider_key_delivery_failed`` reason is RESERVED in
  the ``SANDBOX_REFUSED_REASONS`` vocabulary for a future writer of the
  ``SANDBOX_REFUSED_FIELDS`` audit row on this genuine-delivery-failure path
  (a #433 follow-up, tracked in ADR-0051's Follow-ups); it is not emitted by
  any code today (CLAUDE.md hard rule #7 — no silent failure on a security
  path, hence reserved rather than dropped, but not yet a live audit write).

* **Zeroize then collect.** The key is staged in a mutable ``bytearray`` and
  overwritten with NUL bytes the instant the writev returns — BEFORE
  ``gc.collect()`` — so the post-write residency window is as short as
  CPython allows.

Honest limitation (unchanged from §7.5): the key arrives at this function as
a Python ``str`` (interned, non-zeroizable). The brief residency window
between ``SecretBroker.get`` and this call is microseconds; ``gc.collect()``
is mitigation, not elimination. Slice-5 ``SecretBroker.get_bytes`` closes it.
"""

from __future__ import annotations

import gc
import os
import struct

_LENGTH_PREFIX = struct.Struct(">I")


class ProviderKeyDeliveryError(Exception):
    """fd-3 provider-key delivery failed (partial write / EAGAIN / OSError).

    ``reason`` is the closed-vocabulary refusal string RESERVED for a future
    ``SANDBOX_REFUSED_FIELDS`` audit-row writer on this genuine-delivery-
    failure path (a #433 follow-up, #444 — see ADR-0051's Follow-ups); no
    code writes that row today. Deliberately rooted at :class:`Exception`
    (not a transport error) so the spawn path can refuse loudly and
    uniformly.
    """

    def __init__(self, reason: str = "provider_key_delivery_failed") -> None:
        super().__init__(reason)
        self.reason = reason


def _zero_buffer(buffer: bytearray) -> None:
    """Overwrite every byte of ``buffer`` with NUL in place.

    A standalone helper (not inlined) so the delivery path's
    "zero-before-collect" ordering is independently patchable + assertable in
    the unit test.
    """
    buffer[:] = b"\x00" * len(buffer)


def deliver_provider_key_via_fd3(*, write_fd: int, key: str) -> None:
    """Write ``[len-prefix | key]`` to ``write_fd`` in one atomic writev.

    The caller MUST place the pipe's read end on fd **3** of the launcher
    child. The robust spawn pattern (verified in a docker bwrap repro): in the
    PARENT, ``os.dup2(read_fd, 3)`` (saving + restoring any existing parent fd
    3), then spawn with ``pass_fds=(3,)``. A ``preexec_fn`` that ``dup2``s onto
    fd 3 does NOT work — ``subprocess`` runs ``close_fds`` AFTER ``preexec_fn``,
    and the dup'd fd 3 (not in ``pass_fds``) is closed before exec, so the
    plugin's ``os.read(3)`` raises ``EBADF`` whenever the original ``read_fd``
    is not already 3 (e.g. under pytest / any process with several fds open).

    Args:
        write_fd: The write end of a pipe whose read end is fd 3 of the
            launcher subprocess (see the spawn-pattern note above). This
            function closes ``write_fd`` before it returns (and on every
            refusal path) — the caller owns only the read-end lifecycle.
        key: The provider key fetched via ``SecretBroker.get``.

    Raises:
        ProviderKeyDeliveryError: The writev was partial, raised EAGAIN, or
            failed at the OS level. The plugin MUST NOT be spawned.
    """
    key_buffer = bytearray(key.encode("utf-8"))
    length_prefix = _LENGTH_PREFIX.pack(len(key_buffer))
    expected = len(length_prefix) + len(key_buffer)
    try:
        try:
            written = os.writev(write_fd, [length_prefix, key_buffer])
        except (BlockingIOError, OSError) as exc:
            # EAGAIN on a would-block fd, or any lower-level write failure:
            # refuse rather than deliver a truncated key.
            raise ProviderKeyDeliveryError() from exc
        if written != expected:
            # Partial write — the plugin would read a truncated key. Refuse.
            raise ProviderKeyDeliveryError()
    finally:
        # Zeroize the mutable buffer BEFORE collecting, then drop the close
        # and the GC sweep in the finally so they run on success and refusal
        # alike (no fd leak, shortest residency window on both paths).
        _zero_buffer(key_buffer)
        os.close(write_fd)
        gc.collect()


__all__ = [
    "ProviderKeyDeliveryError",
    "deliver_provider_key_via_fd3",
]
