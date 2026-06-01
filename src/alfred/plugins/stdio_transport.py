"""StdioTransport — MCP plugin stdio transport (spec §4.2, §5.3, §7.6).

The StdioTransport is the host-side wire between the privileged
orchestrator and an MCP plugin subprocess. It mediates every JSON-RPC
frame on both directions, applies the trust-boundary primitives the
adversarial suite covers, and shapes the response into the
``DispatchResult`` union the orchestrator branches on.

**Outbound pipeline (arch-001 / sec-010 — DLP scans placeholder frame FIRST):**

1. Serialize a JSON-RPC frame with ``{{secret:*}}`` placeholders intact.
2. ``OutboundDlp.scan(placeholder_frame)`` — placeholders are benign;
   no DLP rule fires on them.
3. ``SecretBroker.substitute(params)`` substitutes the real secrets
   AFTER DLP passes. Order rationale: routing plaintext secrets
   through DLP would create a secret-sink class of attack
   (rule-trip logs, ReDoS, downstream-classifier exfil) violating
   CLAUDE.md hard rules #1 + #5. See ADR-0017.
4. Build the final frame with substituted values.
5. Length-prefix and write to subprocess stdin.

**Inbound pipeline:**

* Length-prefixed read (4-byte BE header, max 10MB — perf-008).
* ``InboundContentScanner.scan`` in ``asyncio.to_thread`` (perf-012).
* Branch on method shape (sec-001 / core-006):

  - content-bearing → ``tag_t3_with_nonce(decoded, caller_token=nonce)`` →
    ``content_store.put(handle, tagged)`` → return ``ContentHandle``
  - control-plane → ``ControlResult`` (no T3 tagging, no store write)

The TaggedContent[T3] *wrapper* is what the content store persists
(rvw-004 / CR R3) — persisting raw bytes loses nonce + provenance and
silently downgrades T3 → untagged on retrieval.

**Subprocess hardening (spec §5.3):**

* Env scrubbing: the subprocess inherits a minimal env dict containing
  only ``PATH``, i18n vars, and a SINGLE whitelisted ``ALFRED_ENV``
  passthrough (arch-003 — needed for the documented dev-mode TLS
  escape hatch in ``web_fetch/tls_policy.py``). Never ``os.environ`` —
  read attempts are blocked by the AST guard in
  ``test_env_scrub_subprocess.py``; the ``ALFRED_ENV`` value is read
  in :mod:`alfred.plugins._env_passthrough`, the single sanctioned
  parent-env reader for the plugin sandbox boundary.
* fd-3 provider-key delivery: 4-byte big-endian length + N key bytes.
  Pipe fds are closed in ``finally`` so a spawn failure cannot leak
  them (rvw-pre-flight).
* ``kill()`` returns ``bool`` — the quarantine audit row records
  whether SIGKILL actually landed (CR R3 ``kill_succeeded`` field).

**Invariants enforced as explicit guards (err-013 — survives ``python -O``):**

* ``dispatch()`` before ``_spawn()`` raises ``RuntimeError``.
* ``tag_t3_with_nonce`` requires the injected nonce; a ``None`` slot
  raises ``NonceNotConfigured`` BEFORE touching the content store.
* Inbound frames > ``_MAX_INBOUND_FRAME_BYTES`` raise
  ``PluginProtocolError`` before consuming the body.

Constructor takes ``inbound_t3_nonce`` directly (core-008 — no module
global). DLP refusal raises ``DlpOutboundRefusedError`` so callers can
distinguish wire failures from invocation failures (arch-006 / err-011).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import json
import os
import struct
import time
import uuid
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

import structlog

from alfred.audit import audit_row_schemas
from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.plugins._env_passthrough import alfred_env_for_subprocess
from alfred.plugins._observability import (
    DISPATCH_DURATION,
    INBOUND_SCANNER_SCAN_DURATION,
    OUTBOUND_DLP_SCAN_DURATION,
    PLUGIN_SPAWN_DURATION,
    bucket_plugin_id,
)
from alfred.plugins.content_store_base import ContentStoreBase, InMemoryContentStore
from alfred.plugins.errors import DlpOutboundRefusedError
from alfred.plugins.inbound_scanner import CanaryTrip, InboundContentScanner
from alfred.plugins.transport import ControlResult, DispatchResult
from alfred.security.quarantine import ContentHandle
from alfred.security.tiers import CapabilityGateNonce, tag_t3_with_nonce

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Structural Protocols for the transport's collaborators.
#
# The transport binds to *structural* shapes rather than the concrete
# OutboundDlp / SecretBroker classes because:
#
# * ``alfred.security.dlp.OutboundDlp.scan(text: str) -> str`` is the
#   Slice-2 shape. Slice-3 evolves it to a bytes-aware refusing variant
#   that returns a Result object — the StdioTransport wants the new
#   shape NOW (it deals in JSON-RPC frames as bytes), and the bytes
#   adapter lands in PR-S3-5 alongside the canary registry. Until then
#   the structural Protocol lets the supervisor wire an adapter without
#   the transport hard-depending on the in-flux concrete class.
# * ``alfred.security.secrets.SecretBroker`` exposes ``get(name) -> str``
#   today. The orchestrator-level ``substitute(params) -> dict`` lands
#   alongside the plugin host (separate PR). The Protocol future-proofs
#   the transport against the broker's evolving surface.
#
# Both Protocols are ``runtime_checkable`` so the supervisor bootstrap
# can ``isinstance`` check without importing the concrete adapter.
# ---------------------------------------------------------------------------


@runtime_checkable
class _OutboundDlpResult(Protocol):
    """Structural shape for a DLP scan result.

    ``refused`` is the decision; ``rule_matched`` is a forensic-safe
    rule identifier (closed vocabulary) used in audit rows. Bytes
    themselves are never carried on the result — that would let DLP
    rule names leak T3 fragments into structured logs.
    """

    @property
    def refused(self) -> bool: ...

    @property
    def rule_matched(self) -> str | None: ...


@runtime_checkable
class _BytesAwareOutboundDlp(Protocol):
    """Structural shape for the bytes-aware outbound DLP the transport uses.

    The Slice-3 wire is JSON-RPC bytes, not strings; the scan operates
    on the placeholder-substituted frame before the broker fills in
    real secret values (arch-001 invariant).
    """

    def scan(self, frame: bytes, /) -> _OutboundDlpResult: ...


@runtime_checkable
class _SecretBrokerSubstitute(Protocol):
    """Structural shape for the broker's ``substitute`` surface.

    Async because PR-S3-5 backs substitution with a remote secret
    store. Slice-1 broker.get is synchronous; the substitute path is
    independently evolving — this Protocol decouples the transport.
    """

    async def substitute(self, params: dict[str, Any], /) -> dict[str, Any]: ...


# perf-008: 10MB hard cap on a single inbound frame. A plugin that claims a
# larger length is misbehaving (Slice-3 web-fetch tops out well below this)
# and the host refuses the frame BEFORE allocating the body buffer so a
# denial-of-service via "claim 4GB" cannot wedge the event loop.
_MAX_INBOUND_FRAME_BYTES: Final[int] = 10 * 1024 * 1024

# perf-012: outbound DLP scan offloads to a thread above this size. Below
# the threshold the in-loop call is faster than the thread-handoff overhead;
# above it the regex/NER scan dominates and would stall the event loop.
_OUTBOUND_DLP_THREAD_THRESHOLD: Final[int] = 4096

# Default close()-cooperative-wait timeout in seconds. Past this point the
# transport SIGKILLs the child. Five seconds matches the Slice-2 supervisor
# convention; the supervisor in PR-S3-3b owns the eventual policy knob.
_CLOSE_TIMEOUT_S: Final[float] = 5.0

# Methods whose responses are control-plane: no T3 tagging, no content store
# write. The set is closed for Slice 3 — any new control-plane method needs
# an explicit addition here so the security review surfaces it.
_CONTROL_PLANE_METHOD_PREFIXES: Final[frozenset[str]] = frozenset(
    {
        "lifecycle.",
        "adapter.health",
        "ping",
    }
)


class CanaryTripSecurityEvent(AlfredError):  # noqa: N818 - SECURITY EVENT is the spec-mandated name (§4.5)
    """SECURITY EVENT: canary token detected in plugin subprocess output.

    Spec §4.5 + §7.6 — a canary trip is NEVER a recoverable error.
    The orchestrator quarantines the plugin and emits a
    ``security.canary_tripped`` audit row. ``matched_token`` and
    ``plugin_id`` are forensic-safe (closed vocabularies); the raw
    frame is not carried.
    """

    def __init__(self, message: str, plugin_id: str, matched_token: str) -> None:
        super().__init__(message)
        self.plugin_id = plugin_id
        self.matched_token = matched_token


class NonceNotConfigured(AlfredError):  # noqa: N818 - name pinned by err-013 plan reference
    """Raised when StdioTransport is used before ``inbound_t3_nonce`` is set.

    err-013: explicit guard rather than ``assert`` — ``python -O`` strips
    asserts and this is the trust-boundary I/O path that gates the T3
    tagging. A silent passthrough would let raw bytes reach the
    orchestrator untagged.
    """


class PluginProtocolError(AlfredError):
    """Inbound frame exceeded the max size limit (perf-008).

    Distinct from :class:`alfred.plugins.errors.PluginProtocolViolation`
    (which covers post-handshake disallowed JSON-RPC methods); this one
    is a wire-level resource-bound violation that the transport
    enforces before consuming the body.
    """


def _is_control_plane(method: str) -> bool:
    """Return True if ``method`` is on the control-plane prefix list.

    Closed vocabulary check — adding a new control-plane method requires
    a manual edit of ``_CONTROL_PLANE_METHOD_PREFIXES`` so the security
    review pass surfaces the addition.
    """
    return any(method.startswith(prefix) for prefix in _CONTROL_PLANE_METHOD_PREFIXES)


def _write_all(fd: int, data: bytes) -> None:
    """Write the full ``data`` buffer to ``fd``, retrying on short writes + EINTR.

    ``os.write`` on a pipe may return a short count (signal-interrupted
    or buffer-bounded), which silently truncates the payload. On the
    provider-key delivery path that truncation corrupts a trust-boundary
    secret: the child reads a header claiming ``len(data)`` and then
    hits EOF (the parent closes the write end in a ``finally`` block).
    This helper loops until every byte has been written, retrying on
    ``InterruptedError`` (EINTR). CR on PR #140 MUST-FIX.

    ``OSError`` (other than EINTR) propagates so the caller's spawn-
    error path observes the failure and the pipe fds are cleaned up via
    the outer ``finally``.
    """
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except InterruptedError:
            # EINTR: a signal interrupted the syscall before any bytes
            # were written. Retry rather than propagate — the contract
            # is "deliver the full frame", and a spurious signal is not
            # a delivery failure.
            continue
        if n <= 0:  # pragma: no cover — POSIX guarantees n > 0 on success
            # ``os.write`` raises on error, so n == 0 is an unexpected
            # state. Raise loudly rather than spin-loop forever.
            raise OSError(f"_write_all: os.write returned {n} on fd={fd}; refusing to spin")
        view = view[n:]


class StdioTransport:
    """MCP stdio transport — dispatches JSON-RPC to a plugin subprocess.

    Constructor takes ``inbound_t3_nonce`` explicitly (core-008 — no
    module global, so test setups cannot cross-contaminate the nonce
    slot). DLP / scanner / broker / audit-writer are all dependency-
    injected; the transport never reaches for module-level globals.

    Implements the :class:`alfred.plugins.transport.PluginTransport`
    Protocol structurally (``runtime_checkable`` so the supervisor
    bootstrap can ``isinstance`` check without importing the concrete
    class).
    """

    def __init__(
        self,
        *,
        plugin_id: str,
        executable: str,
        args: list[str],
        audit_writer: AuditWriter,
        dlp: _BytesAwareOutboundDlp,
        scanner: InboundContentScanner,
        secret_broker: _SecretBrokerSubstitute,
        inbound_t3_nonce: CapabilityGateNonce,
        content_store: ContentStoreBase | None = None,
    ) -> None:
        self._plugin_id = plugin_id
        self._executable = executable
        self._args = args
        self._audit_writer = audit_writer
        self._dlp = dlp
        self._scanner = scanner
        self._broker = secret_broker
        # core-008: nonce is a constructor parameter, NOT a module global —
        # tests cannot cross-contaminate by patching a global slot, and the
        # supervisor passes the bootstrap nonce explicitly via DI.
        self._nonce = inbound_t3_nonce
        self._content_store: ContentStoreBase = content_store or InMemoryContentStore()
        self._process: asyncio.subprocess.Process | None = None

    async def _spawn(self, *, provider_key: bytes | None = None) -> None:
        """Spawn the subprocess with minimal env; deliver provider key on a pipe fd.

        Spec §5.3 invariants:

        * ``env=`` is built explicitly. No call site reads ``os.environ``
          (an AST guard in ``test_env_scrub_subprocess.py`` enforces this).
          The subprocess gets ``PATH``, ``LANG``/``LC_ALL`` pinned to
          ``C.UTF-8``, the whitelisted ``ALFRED_ENV`` passthrough
          (arch-003 fix — sourced via
          :func:`alfred.plugins._env_passthrough.alfred_env_for_subprocess`
          so the AST guard against host-env reads in this module stays
          intact), and an opt-in ``ALFRED_PROVIDER_KEY_FD`` entry
          naming the inherited pipe fd when ``provider_key`` is
          supplied — no other inherited credentials, no ``PYTHONPATH``,
          no ``HOME``.
        * If ``provider_key`` is supplied, the host writes a length-
          prefixed frame (4-byte BE header + N bytes) on an inherited
          pipe fd. The child reads the numeric fd from
          ``ALFRED_PROVIDER_KEY_FD`` and consumes the framed payload.
          The actual fd number is OS-assigned (pass_fds keeps the
          parent's fd open in the child rather than remapping to a
          fixed number); the env value is the integer ONLY — the
          plaintext key itself never appears in env. The write end
          stays in the parent and is closed after delivery so the child
          sees EOF.

        **Spec §5.3 deviation note.** Earlier drafts of the spec named
        "fd 3" as the convention. Forcing the child's fd to 3 requires
        either ``preexec_fn`` (which CPython warns is dangerous + breaks
        on macOS/Python 3.14 with asyncio's kqueue selector — fd 3 is
        already claimed by the loop selector) or a parent-side
        ``dup2`` that clobbers the same selector fd. Using the
        env-passed fd number preserves the *invariant* (key is out of
        band from env; the value lives only on the pipe) while remaining
        portable. The fd-3-as-wire-protocol convention can be honoured
        by plugins choosing to read the env var or to wrap to fd 3
        themselves.

        **Resource safety (rvw-pre-flight):** pipe fds allocated for
        key delivery are closed in a ``finally`` block so they cannot
        leak if ``create_subprocess_exec`` raises (e.g.
        ``FileNotFoundError`` when the executable is missing).
        """
        # Minimal env — never ``os.environ``. The AST guard in
        # tests/unit/plugins/test_env_scrub_subprocess.py is the
        # release-blocker against any future patch that re-introduces a
        # bare environ read here.
        #
        # ``LANG``/``LC_ALL`` are pinned to ``C.UTF-8`` (not inherited
        # from the host) so the child runs under a deterministic
        # UTF-8 locale regardless of what the parent process inherited.
        # CR on PR #140 caught the prior implementation: the module
        # docstring and ``_spawn`` docstring promised i18n env
        # forwarding, but only ``PATH`` was set — a plugin relying on
        # ``LANG``/``LC_ALL`` for locale-correct text handling would
        # silently run under the C locale. Pinning the values (rather
        # than reading from the parent's environ) keeps the env-scrub
        # invariant intact while delivering the documented contract.
        #
        # arch-003 fix: ``ALFRED_ENV`` is the SINGLE whitelisted
        # passthrough from the parent's environment. Plugin subprocesses
        # need it to honour the development escape hatch for TLS
        # verification (``web_fetch/tls_policy.py``) — without it the
        # subprocess always sees the env unset, defaults to
        # ``"production"``, and refuses ``skip_tls_verify=True`` even in
        # legitimate dev. The read is delegated to
        # :func:`alfred_env_for_subprocess` (in a sibling module) so the
        # AST guard against host-env reads in THIS file stays intact;
        # no other parent-env key leaks.
        minimal_env: dict[str, str] = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "ALFRED_ENV": alfred_env_for_subprocess(),
        }
        extra_fds: tuple[int, ...] = ()
        r_fd: int | None = None
        w_fd: int | None = None
        if provider_key is not None:
            # os.pipe() is a fast syscall (microseconds); no thread
            # offload needed. The read end is passed to the child via
            # pass_fds; the write end stays in the parent.
            r_fd, w_fd = os.pipe()
            # pass_fds requires the fd to be inheritable; ``inheritable=True``
            # is forced positionally because os.set_inheritable accepts no
            # keyword form for the bool.
            os.set_inheritable(r_fd, True)  # noqa: FBT003 - os.set_inheritable bool is positional only
            extra_fds = (r_fd,)
            minimal_env["ALFRED_PROVIDER_KEY_FD"] = str(r_fd)

        # Spawn-duration accounting: start the clock here; record the
        # outcome on every exit path so a ``FileNotFoundError`` on
        # missing executable observes ``spawn_failed`` while a successful
        # exec observes ``ok``. The manifest-handshake stage is in the
        # session — this observation covers the subprocess-exec slice
        # only. Spec §7a.1: budget p99 < 500 ms.
        spawn_start = time.monotonic()
        spawn_outcome = "ok"
        try:
            try:
                self._process = await asyncio.create_subprocess_exec(
                    self._executable,
                    *self._args,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=minimal_env,
                    pass_fds=extra_fds,
                )
                if provider_key is not None and w_fd is not None:
                    # 4-byte big-endian length + N key bytes (spec §5.3
                    # framing). The child reads exactly this much then
                    # sees EOF.
                    #
                    # ``os.write`` on a pipe is not guaranteed to write
                    # the full buffer in one call — a signal-interrupted
                    # or buffer-bounded write can return a short count,
                    # silently truncating the provider key. The child
                    # would then read a header claiming ``len(provider_key)``
                    # and immediately hit EOF (the parent closes ``w_fd``
                    # in the surrounding ``finally``), corrupting key
                    # delivery on a trust-boundary path. Loop until the
                    # full frame has been written, retrying on EINTR.
                    # CR on PR #140 MUST-FIX.
                    header = struct.pack(">I", len(provider_key))
                    _write_all(w_fd, header + provider_key)
            except Exception:
                spawn_outcome = "spawn_failed"
                raise
            finally:
                # Close both ends on every path — success and failure.
                # The child has its own dup of r_fd via pass_fds; the
                # parent's copies are no longer needed.
                # ``contextlib.suppress`` is used because a double-close
                # on a never-opened fd is the only failure mode and it is
                # benign — we don't want a close-after-failure to mask
                # the original spawn exception.
                if w_fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(w_fd)
                if r_fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(r_fd)
        finally:
            # perf-003: bucket open-vocabulary plugin_id through the
            # cardinality firewall so a runaway plugin fleet cannot leak
            # unbounded series into the Prometheus index.
            PLUGIN_SPAWN_DURATION.labels(
                plugin_id=bucket_plugin_id(self._plugin_id),
                outcome=spawn_outcome,
            ).observe(time.monotonic() - spawn_start)

    async def _read_length_prefixed(self) -> bytes:
        """Read one length-prefixed frame from stdout.

        Frame format: 4-byte big-endian length + N body bytes. Raises
        :class:`PluginProtocolError` if the declared length exceeds
        :data:`_MAX_INBOUND_FRAME_BYTES` (perf-008). Raises ``RuntimeError``
        if called before ``_spawn`` (err-013 — explicit guard, not
        ``assert``, so the trust-boundary check survives ``python -O``).
        """
        if self._process is None or self._process.stdout is None:
            raise RuntimeError(
                "_read_length_prefixed() called before _spawn(); transport state invariant violated"
            )
        header = await self._process.stdout.readexactly(4)
        length = struct.unpack(">I", header)[0]
        if length > _MAX_INBOUND_FRAME_BYTES:
            raise PluginProtocolError(
                f"Inbound frame from {self._plugin_id!r} exceeds "
                f"{_MAX_INBOUND_FRAME_BYTES} bytes (got length={length})"
            )
        return await self._process.stdout.readexactly(length)

    async def dispatch(
        self,
        method: str,
        params: dict[str, Any],
    ) -> DispatchResult:
        """Dispatch a JSON-RPC call; apply DLP on outbound, scan on inbound.

        Outbound order is DLP-then-broker per the ADR-0017 + spec §2.1
        rationale: routing plaintext secrets through DLP creates a
        secret-sink class of attack. See the module docstring.

        Returns one of the three :data:`DispatchResult` shapes:

        * :class:`ControlResult` for control-plane methods (lifecycle.*,
          adapter.health, ping) — no T3 tagging, no content store write.
        * :class:`ContentHandle` for content-bearing methods — the
          underlying ``TaggedContent[T3]`` is persisted in the content
          store; the orchestrator only sees the opaque handle.

        Raises:

        * :class:`DlpOutboundRefusedError` — outbound DLP refused the
          placeholder frame (audit row written before raising).
        * :class:`PluginProtocolError` — inbound frame exceeds the size cap.
        * :class:`CanaryTripSecurityEvent` — canary token detected in
          inbound bytes (no redact-and-continue — quarantine trigger).
        * ``RuntimeError`` — dispatch called before ``_spawn`` (err-013).
        * :class:`NonceNotConfigured` — content-bearing branch with no nonce.

        Observability (spec §7a.1 / perf-002 / perf-009): observes
        :data:`DISPATCH_DURATION` once per call with the outcome label set
        from the actual exit path; the per-stage histograms
        (:data:`OUTBOUND_DLP_SCAN_DURATION`,
        :data:`INBOUND_SCANNER_SCAN_DURATION`) observe inline at their
        respective stages so a slow DLP scan that triggers a refusal still
        records its scan latency.
        """
        # Dispatch-duration accounting: start the clock here, record once
        # at the exit path (try/finally below). ``method_shape`` is fixed
        # at the time of the call; ``outcome`` is set to the actual exit
        # path so a DLP-refused dispatch reports ``dlp_refused``.
        dispatch_start = time.monotonic()
        method_shape = "control" if _is_control_plane(method) else "content"
        outcome = "ok"
        try:
            # Step 1: serialise the placeholder frame for DLP. {{secret:*}}
            # placeholders are untouched until the broker substitutes them.
            placeholder_frame = json.dumps(
                {"jsonrpc": "2.0", "method": method, "params": params}
            ).encode("utf-8")

            # Step 2: outbound DLP on the placeholder frame. perf-012 —
            # frames over the threshold offload to a thread because the
            # regex/NER scan is O(n) on the frame size and would stall
            # the event loop. The DLP collaborator is structural:
            # ``scan(bytes) -> Result`` where Result has ``refused:
            # bool`` and ``rule_matched: str``. The Slice-3 DLP shim
            # adapts ``OutboundDlp.scan(str) -> str`` to this shape;
            # PR-S3-5 lands the full bytes-aware OutboundDlp.
            dlp_start = time.monotonic()
            if len(placeholder_frame) > _OUTBOUND_DLP_THREAD_THRESHOLD:
                dlp_result = await asyncio.to_thread(self._dlp.scan, placeholder_frame)
            else:
                dlp_result = self._dlp.scan(placeholder_frame)
            dlp_refused = bool(getattr(dlp_result, "refused", False))
            OUTBOUND_DLP_SCAN_DURATION.labels(
                outcome="refused" if dlp_refused else "allowed",
            ).observe(time.monotonic() - dlp_start)

            if dlp_refused:
                outcome = "dlp_refused"
                rule_matched = getattr(dlp_result, "rule_matched", "unknown") or "unknown"
                correlation_id = str(uuid.uuid4())
                # Audit the refusal BEFORE raising — the security path
                # must leave a trace even when the dispatch fails loud
                # (CLAUDE.md hard rule #7).
                await self._audit_writer.append_schema(
                    fields=audit_row_schemas.DLP_OUTBOUND_REFUSED_FIELDS,
                    schema_name="DLP_OUTBOUND_REFUSED_FIELDS",
                    event="security.dlp_outbound_refused",
                    actor_user_id=None,
                    subject={
                        "wire": "stdio_transport.outbound",
                        "direction": "outbound",
                        "scan_rule_matched": rule_matched,
                        "field_name": "frame",
                        "correlation_id": correlation_id,
                    },
                    trust_tier_of_trigger="T0",
                    result="refused",
                    cost_estimate_usd=0.0,
                    trace_id=correlation_id,
                )
                raise DlpOutboundRefusedError(
                    plugin_id=self._plugin_id,
                    rule_matched=rule_matched,
                )

            # Step 3: broker substitution — AFTER DLP, per ADR-0017
            # invariant. The broker is structural:
            # ``substitute(params) -> awaitable[dict]``.
            substituted_params = await self._broker.substitute(params)

            # Step 4: final frame with substituted values.
            final_frame = json.dumps(
                {"jsonrpc": "2.0", "method": method, "params": substituted_params}
            ).encode("utf-8")

            # Step 5: write to subprocess. err-013 — explicit guard, not
            # ``assert`` (which ``python -O`` strips), because this is a
            # trust-boundary I/O path. The catch-all ``except Exception``
            # below labels ``outcome`` for the histogram exit.
            if self._process is None or self._process.stdin is None:
                raise RuntimeError(
                    "dispatch() called before _spawn(); transport state invariant violated"
                )
            self._process.stdin.write(struct.pack(">I", len(final_frame)) + final_frame)
            await self._process.stdin.drain()

            # Step 6: read the inbound frame (length-prefixed, perf-008
            # cap).
            raw = await self._read_length_prefixed()

            # Step 7: inbound canary scan, offloaded to a thread to keep
            # the event loop responsive on regex-heavy frames.
            scan_start = time.monotonic()
            trip = await asyncio.to_thread(self._scanner.scan, raw)
            INBOUND_SCANNER_SCAN_DURATION.labels(
                outcome="canary_trip" if isinstance(trip, CanaryTrip) else "clean",
            ).observe(time.monotonic() - scan_start)
            if isinstance(trip, CanaryTrip):
                outcome = "canary_trip"
                # SECURITY EVENT — never recoverable. The supervisor
                # catches this and quarantines the subprocess; we surface
                # forensic attributes (plugin_id + matched_token) on the
                # exception.
                log.warning(
                    "canary_trip_on_inbound_frame",
                    plugin_id=self._plugin_id,
                    token=trip.matched_token,
                )
                raise CanaryTripSecurityEvent(
                    message=t("security.canary_tripped", url=f"plugin:{self._plugin_id}"),
                    plugin_id=self._plugin_id,
                    matched_token=trip.matched_token,
                )

            # Step 8: branch on method shape (sec-001 / core-006).
            if _is_control_plane(method):
                # Control-plane response: deserialise to ControlResult.
                # No T3 tagging, no content store write — these responses
                # carry status/health/lifecycle info, never user content.
                payload_raw = json.loads(raw).get("result", {})
                payload: dict[str, object] = (
                    dict(payload_raw) if isinstance(payload_raw, dict) else {}
                )
                return ControlResult(method=method, payload=payload)

            # Content-bearing branch: tag T3 and persist the WRAPPER in
            # the content store (rvw-004 / CR R3 fix). Persisting raw
            # bytes would lose the nonce + provenance and silently
            # downgrade T3 → untagged on retrieval.
            #
            # Explicit guard, not ``assert`` (err-013) — survives
            # ``python -O``. The catch-all ``except Exception`` below
            # labels ``outcome`` for the histogram exit.
            if self._nonce is None:
                raise NonceNotConfigured(
                    "StdioTransport inbound_t3_nonce must be set at construction"
                )
            # T3 content is a *string* on the TaggedContent model; decode
            # the inbound bytes with ``errors="replace"`` so non-UTF-8
            # sequences (binary blobs, images) don't crash the tagging
            # path — the downstream extractor handles binary handles via
            # the content store metadata.
            decoded = raw.decode("utf-8", errors="replace")
            tagged = tag_t3_with_nonce(
                decoded,
                source=f"plugin:{self._plugin_id}:{method}",
                caller_token=self._nonce,
            )
            handle = ContentHandle(
                id=str(uuid.uuid4()),
                source_url=f"plugin:{self._plugin_id}:{method}",
                fetch_timestamp=datetime.datetime.now(datetime.UTC),
            )
            self._content_store.put(handle, tagged)
            return handle
        except PluginProtocolError:
            outcome = "protocol_error"
            raise
        except (DlpOutboundRefusedError, CanaryTripSecurityEvent):
            # ``outcome`` was already set on the relevant branch above
            # (``dlp_refused`` / ``canary_trip``) — let the labelled
            # exception name propagate.
            raise
        except Exception:
            # Catch-all so the histogram still records the exit path
            # even when an unexpected exception fires (broker error,
            # process death mid-write, ``NonceNotConfigured`` from the
            # err-013 guard, etc.). The exception itself is re-raised;
            # this is observability, not error suppression.
            outcome = "error"
            raise
        finally:
            # perf-003: bucket open-vocabulary plugin_id through the
            # cardinality firewall (see ``bucket_plugin_id`` docstring).
            DISPATCH_DURATION.labels(
                plugin_id=bucket_plugin_id(self._plugin_id),
                method_shape=method_shape,
                outcome=outcome,
            ).observe(time.monotonic() - dispatch_start)

    async def kill(self) -> bool:
        """SIGKILL the subprocess; return whether the kill landed.

        Returns ``True`` if the kill signal was delivered to a live
        subprocess, ``False`` if the process was already dead (or never
        spawned). The caller's quarantine audit row reads this bool into
        the ``kill_succeeded`` field of
        :data:`PLUGIN_LIFECYCLE_QUARANTINED_FIELDS` so operators see the
        kill outcome regardless of the SIGKILL race result.

        Spec §4.6 + plan §1495-1526 (CR R3 fix): the audit row emits in
        every case — kill landed or not. The supervisor's try/finally
        around this call guarantees the emit; this method only reports
        the outcome.
        """
        if self._process is None:
            return False
        try:
            self._process.kill()
        except ProcessLookupError:
            # Race: the subprocess crashed between the decision and the
            # syscall. The audit row records kill_succeeded=False so
            # operators see "we tried but missed" rather than a silent
            # success.
            return False
        # Wait for the OS to reap so subsequent ``.returncode`` checks
        # don't race. Bounded so a stuck child can't wedge the
        # quarantine path forever.
        try:
            await asyncio.wait_for(self._process.wait(), timeout=_CLOSE_TIMEOUT_S)
        except TimeoutError:  # pragma: no cover — defensive; kill should reap
            return False
        return True

    async def close(self) -> None:
        """Gracefully shut down the subprocess.

        Closes stdin (giving the child a clean EOF), waits up to
        :data:`_CLOSE_TIMEOUT_S` for the child to exit, then SIGKILLs
        anything still running. Safe no-op if ``_spawn`` was never called.
        """
        if self._process is None:
            return
        if self._process.stdin is not None:
            self._process.stdin.close()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=_CLOSE_TIMEOUT_S)
        except TimeoutError:
            # Child ignored the cooperative close — escalate to SIGKILL.
            # We don't await the post-kill wait here because the
            # supervisor's cleanup-then-quarantine path may not have an
            # event-loop budget for it; the kill itself is fire-and-forget.
            self._process.kill()


__all__ = [
    "CanaryTripSecurityEvent",
    "NonceNotConfigured",
    "PluginProtocolError",
    "StdioTransport",
]
