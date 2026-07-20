#!/usr/bin/env python3
"""bwrap dual-LLM quarantine-child spawn probe (#290 CI gate).

Decisive single-question probe: does the bwrap-sandboxed quarantine child spawn
+ complete its two-frame boot handshake when run under the PRODUCTION posture of
the ``alfred-core`` image — the non-root ``alfred`` user with only
``cap_add: [SETUID]`` (NOT root, NOT ``--privileged``) on x86-64 Linux?

**#340 PR2b-golive.** This probe used to assert a deterministic ECHO
(``result.data.text == context``) from the pre-golive 2b child. The golive cutover
DELETED that echo — the child now runs a REAL structured extraction against a real
provider over a brokered gateway socket — so the echo assertion became
unsatisfiable and this probe was a THIRD echo-dependent artifact (the two
integration ones were superseded in Tasks 6/14). It now spawns in the REAL golive
posture (``control_fd=True`` + provider config + egress config) and asserts the
``hello`` + ``ready`` boot handshake (#443) instead.

That is the RIGHT success criterion for this gate and a STRICTLY STRONGER spawn
proof than the echo was: ``spawn_quarantine_child_io`` returns only after the child
has exec'd under bwrap, imported ``alfred``, read its fd-3 key, emitted ``hello``,
built its provider factory, reconstructed the inherited fd-4 control channel, and
written ``ready``. No extraction is driven, so the probe needs NO gateway and NO
provider credential — the child performs no external IO at boot (``sbx-2026-024``),
which is exactly why an unreachable placeholder egress URL is correct here.

Originally the throwaway #288/G6-0b probe; promoted to a permanent artifact by
#290 because it is the only proof that exercises the *production deployability*
of the dual-LLM spawn (non-root + SETUID, the docker-compose posture). The
``integration-privileged`` CI job proves the spawn under ``sudo`` (root) with a
provisioned hermetic interpreter — that does NOT reflect the shipped container.

The CI validation job for #290 (``bwrap-userns-apparmor``) runs THIS probe inside
the built image as non-root ``alfred`` under the custom AppArmor + seccomp
profiles, with the host userns-restriction sysctl set RESTRICTIVE, to prove the
profiles (not a lax host) are what let the sandbox build. Since #290 Option B the
image's PRIMARY interpreter is a self-contained python-build-standalone under
``/opt/alfred-python`` (RUNPATH-linked → needs no ld.so.cache) with ``alfred``
installed NON-editable into it, set as ``ALFRED_QUARANTINE_CHILD_PYTHON`` in the
image ENV. The launcher ro-binds that prefix into the sandbox (the opt-in
``ALFRED_SANDBOX_BIND_INTERP_PREFIX`` flag ``_child_env`` sets), so the child execs
+ imports ``alfred`` from one bound, cache-independent prefix — the two orthogonal
#290 sub-causes (editable install + ld.so-cache interpreter) are fixed in the image
itself, leaving only the userns/AppArmor variable this gate isolates.

The probe drives the SAME production machinery the real-spawn path uses
(``spawn_quarantine_child_io``), but with NO postgres/redis/daemon and NO audit
layer — it isolates the spawn.

Prints exactly one machine-greppable result line and sets the exit code:

* ``QUARANTINE_SPAWN_PROBE_RESULT=OK``           -> exit 0 (child spawned + booted)
* ``QUARANTINE_SPAWN_PROBE_RESULT=FAILED:<why>`` -> exit 1 (refused / never booted)
"""

from __future__ import annotations

import asyncio
import os
import sys
import traceback
from dataclasses import dataclass

_RESULT_PREFIX = "QUARANTINE_SPAWN_PROBE_RESULT="

# Provider config for the spawn env. The child indexes both at boot
# (``_build_provider``) but makes NO provider call during the handshake, so these
# only have to be well-formed, not real. ``max_tokens`` must be > 0 or the child's
# §20.2 budget guard correctly refuses boot.
_PROBE_MODEL = "claude-haiku-4-5"
_PROBE_MAX_TOKENS = 1024

# The child reconstructs fd 4 at boot but dials NOTHING until an extraction, which
# this probe never drives (``sbx-2026-024``: no external IO at boot). An
# unreachable-but-well-formed ``host:port`` is therefore correct — it satisfies the
# spawn's fail-closed "control_fd=True REQUIRES an egress_config" guard without
# implying a reachable gateway.
_PROBE_EGRESS_PROXY_URL = "http://127.0.0.1:1"


@dataclass(frozen=True, slots=True)
class _ProbeEgressConfig:
    """Minimal :class:`alfred.egress._config_protocols.EgressProxyConfig` stub.

    Structural conformance only — the probe has no ``Settings``, and the spawn reads
    exactly one attribute off this surface.
    """

    egress_proxy_url: str | None = _PROBE_EGRESS_PROXY_URL


def _emit(result: str) -> int:
    """Print the single greppable result line; return the process exit code."""
    print(f"{_RESULT_PREFIX}{result}", flush=True)
    return 0 if result == "OK" else 1


def _assert_non_root_posture() -> str | None:
    """Refuse to "prove" anything if we are accidentally root.

    The whole point is the NON-root + SETUID posture. A root run would silently
    succeed for the wrong reason and give a false-positive answer, so bail loud.
    """
    if os.geteuid() == 0:
        return "running as root (euid 0) — probe must run as the non-root alfred user"
    uname = os.uname()
    if uname.sysname != "Linux":
        return f"not Linux (sysname={uname.sysname}) — production posture is x86-64 Linux"
    return None


async def _run_boot_handshake() -> str:
    """Spawn the real bwrap golive child + prove its two-frame boot handshake.

    Returns ``"OK"`` once the child is spawned + booted, else ``"FAILED:<reason>"``.

    ``spawn_quarantine_child_io`` performs the whole proof internally: it execs
    ``bin/alfred-plugin-launcher.sh`` (``kind="full"`` -> bwrap), delivers the key over
    fd 3, installs the control socket on fd 4, and then READS BOTH handshake frames
    (#443) before returning — ``hello`` (provenance: a real exec'd child) and ``ready``
    (liveness: provider factory built, fd-4 reconstructed, request loop serving). A
    child that never exec'd, or that refused boot, surfaces as a ``read_frame`` failure
    -> :class:`QuarantineChildSpawnError`. So a successful return IS the spawn proof;
    there is no separate round-trip to drive.

    Spawns in the REAL golive posture (``control_fd=True`` + provider/egress config),
    because that is the only posture the shipped child supports: ``_child_env`` sets the
    provider config ONLY on the ``control_fd=True`` path, so a bare ``control_fd=False``
    spawn of the real child module boots a child that refuses on unset config.
    """
    # Imported here so the module loads even if the import surface changes; an
    # import error is reported as a clear FAILED reason rather than a traceback
    # before the result line.
    from alfred.security.quarantine_child_io import (
        QuarantineChildSpawnError,
        spawn_quarantine_child_io,
    )

    child_io = None
    try:
        # The child scrubs the key after handing it to the frozen provider factory and
        # makes NO provider call during boot, so a placeholder key is correct here.
        # This is the REAL bwrap spawn.
        child_io = await spawn_quarantine_child_io(
            provider_key="g6-0b-probe-placeholder-key",
            control_fd=True,
            egress_config=_ProbeEgressConfig(),
            model=_PROBE_MODEL,
            max_tokens=_PROBE_MAX_TOKENS,
        )
    except QuarantineChildSpawnError as exc:
        # The launcher refused inside bwrap, the policy was inert, the userns setup was
        # denied, or a handshake frame never arrived — the failure this gate isolates.
        return f"FAILED:spawn_refused:{type(exc).__name__}:{exc}"
    except Exception as exc:
        return f"FAILED:spawn_raised:{type(exc).__name__}:{exc}"

    try:
        # Reaching here means both handshake frames were read inside the spawn.
        return "OK"
    finally:
        # Tear the bwrap child + control socket down even if aclose itself raises,
        # so the probe never leaks a sandboxed process into the CI runner.
        await child_io.aclose()


def main() -> int:
    posture_problem = _assert_non_root_posture()
    if posture_problem is not None:
        return _emit(f"FAILED:bad_posture:{posture_problem}")

    # Surface the exact spawn-relevant posture so the run log is self-explaining.
    print(
        f"[probe] euid={os.geteuid()} sysname={os.uname().sysname} "
        f"machine={os.uname().machine} sys.executable={sys.executable} "
        f"ALFRED_ENVIRONMENT={os.environ.get('ALFRED_ENVIRONMENT')!r} "
        f"ALFRED_QUARANTINE_CHILD_PYTHON={os.environ.get('ALFRED_QUARANTINE_CHILD_PYTHON')!r}",
        flush=True,
    )

    try:
        result = asyncio.run(_run_boot_handshake())
    except Exception:
        traceback.print_exc()
        result = "FAILED:probe_harness_raised"
    return _emit(result)


if __name__ == "__main__":
    raise SystemExit(main())
