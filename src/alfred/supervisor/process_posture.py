"""Supervisor-side process posture (spec §7.5, PR-S4-6 Component E).

Two host-process hardening primitives the Supervisor applies at boot:

``disable_core_dumps()`` — sets ``RLIMIT_CORE`` to ``(0, 0)``. A core dump of
the Supervisor would contain the in-memory provider key (the brief residency
window between ``SecretBroker.get`` and the fd-3 write). Disabling core dumps
closes that exfiltration channel.

``try_mlockall()`` — Linux best-effort wrapper around the libc ``mlockall(2)``
syscall, pinning the Supervisor's pages so they cannot be swapped to disk
(another place the key could land). Failure — typically a missing
``CAP_IPC_LOCK`` inside a container — is reported as ``unavailable`` (the
caller emits the ``supervisor.boot.mlock_unavailable`` audit row) but is
NON-fatal: an operator without the capability still boots.

Both primitives ship the mechanism here; the daemon-boot emit-site wiring
(audit rows) is the caller's job (PR-S4-1 boot path).
"""

from __future__ import annotations

import ctypes
import os
import resource
import sys
from dataclasses import dataclass
from typing import Final, Literal

# mlockall(2) flags. MCL_CURRENT locks pages currently mapped; MCL_FUTURE
# locks pages mapped after the call. Both are wanted so the whole Supervisor
# heap stays resident.
_MCL_CURRENT: Final[int] = 1
_MCL_FUTURE: Final[int] = 2


@dataclass(frozen=True, slots=True)
class MlockResult:
    """Outcome of :func:`try_mlockall`.

    ``kind`` is ``"success"`` or ``"unavailable"``. ``errno_string`` carries a
    translated, PII-free reason when unavailable (e.g. the strerror text or
    "non-linux platform") so the caller's audit row is forensically useful.
    """

    kind: Literal["success", "unavailable"]
    errno_string: str = ""


def disable_core_dumps() -> None:
    """Set ``RLIMIT_CORE`` to ``(0, 0)`` — no core dumps. Idempotent."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def try_mlockall() -> MlockResult:
    """Best-effort ``mlockall(MCL_CURRENT | MCL_FUTURE)`` on Linux.

    Returns an :class:`MlockResult`; never raises. A non-Linux platform, a
    non-zero syscall return, or any ``OSError`` loading libc all yield
    ``kind="unavailable"`` so the caller can emit a loud-but-non-fatal audit
    row and proceed.
    """
    # Read into a str-annotated local so mypy does not statically narrow the
    # non-host branch away (the function must behave correctly on every OS,
    # not just the build host's) — mirrors select_machine_id_provider.
    platform: str = sys.platform
    if platform != "linux":
        return MlockResult(kind="unavailable", errno_string="non-linux platform")
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        rc = libc.mlockall(_MCL_CURRENT | _MCL_FUTURE)
    except OSError as exc:
        return MlockResult(kind="unavailable", errno_string=str(exc))
    if rc != 0:
        err = ctypes.get_errno()
        return MlockResult(kind="unavailable", errno_string=os.strerror(err))
    return MlockResult(kind="success")


__all__ = [
    "MlockResult",
    "disable_core_dumps",
    "try_mlockall",
]
