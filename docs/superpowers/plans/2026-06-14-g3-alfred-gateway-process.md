# G3 — `alfred-gateway` Process (Comms-Resume Gateway, Spec A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This document covers the **G3 sub-epic decomposition** (4 PRs) followed by a **detailed task-by-task plan for the first PR (G3-1)**. PRs G3-2…G3-4 get their own detailed plans appended (or as sibling docs) when reached — their scope is fixed here; their step-level code is written against the merged reality of the prior PR. Plan twice-reviewed (architect + security) before implementation; their blocking findings are folded in.

**Goal:** Build the standalone always-up `alfred-gateway` process that fronts dial-in clients with a payload-blind, reconnect-capable relay to the core — the convergence of G0 (idempotency), G1 (lifecycle signal), and G2 (seq/ack codec) — without buffering/resume (G4) or egress proxy (Spec C).

**Architecture:** A separate Compose service terminates the client connection and relays opaque ADR-0025 payloads to the core over a shared-volume `0600` AF_UNIX socket. The gateway is the **first real seq/ack peer**: it echoes the `AlfredSeqAck/1` capability AND deframes/reframes (unlike the plain daemon-spawned plugins — see the "G2 lesson"). It consumes the core's `going_down`/`ready` lifecycle frames to drive a link-state machine and emits client control frames. It is a **T1 carrier** — T3 tagging stays in the core at `process_inbound_message`.

**Tech Stack:** Python 3.12+, asyncio, AF_UNIX sockets, Pydantic v2 wire models, structlog, Prometheus client, Docker Compose, pytest + hypothesis, mypy --strict + pyright.

---

## G3 sub-epic decomposition

G3 is a single row in the Spec A epic table (§8) but is a multi-PR sub-epic on the
scale of PR-S4-11c. It decomposes into four small, independently-reviewable PRs on a
linear critical path. Every PR is `#237`, full `/review-pr` fleet (security ALWAYS) +
CodeRabbit, plain `gh pr merge <n> --rebase --delete-branch`.

| PR | Scope | Depends on | Trust-boundary? |
| --- | --- | --- | --- |
| **G3-1** | Listener peer-auth: cross-platform `SO_PEERCRED` same-uid check on `CommsSocketListener.accept` (refuse a mismatched-uid peer without wedging a legitimate dial-in). | G2 (merged) | **Yes** — listener accept path. |
| **G3-2** | Core lifecycle wire-send: a `send_lifecycle_notification` seam on `CommsPluginRunner` + the core actually SENDING `ready`/`going_down` frames over the comms wire (alongside the G1 audit rows), epoch carried in the handshake, a mandatory transport write-lock, and the peer-auth-reject daemon audit row. | G3-1 | **Yes** — core→peer wire. |
| **G3-3** | The `alfred-gateway` process: `GatewayCoreLink` (dial + dial-side peer-auth + fake-clock reconnect/backoff + epoch-reconciling handshake + seq/ack deframe/reframe + lifecycle consume) + `GatewayClientListener` (stable kernel) + pure relay loop + control frames + Prometheus metrics + `alfred gateway` CLI. *(Split candidate below.)* | G3-2 | **Yes** — always-up T1 carrier. |
| **G3-4** | Deployment: configurable runtime/socket dir (`ALFRED_COMMS_RUNTIME_DIR`, fail-closed validation) + separate `restart: unless-stopped` `alfred-gateway` Compose service (`depends_on` core WITHOUT `service_healthy`) + shared `alfred_run` volume + long-running `alfred-core` daemon service + two-tier healthcheck + `ops/grafana/gateway.json` + `ops/alerts/gateway.yml` + Prometheus scrape + compose-invariant tests + ADR-0032/0033 amendments + README/setup. | G3-3 | **Yes** — env-driven socket relocation. |

**Explicitly deferred to G4 (NOT in G3):** `ReplayBuffer`, un-acked retention, replay-on-reconnect, the cap/TTL/breaker/back-pressure, buffer zeroing/`MADV_DONTDUMP`, gateway-local durable audit + reconcile, and the no-operator-input-loss guarantee. G3 reconnects and re-handshakes, but a frame in flight across a core gap is **dropped** in G3 (the relay is pure). G3's control frames announce the gap; G4 makes it lossless.

**Explicitly deferred to G5 (NOT in G3):** re-pointing `alfred chat` at the gateway, deleting the #259 direct-dial path, and the PTY survival smoke. In G3 the gateway is built, Compose'd, and integration-tested standalone; the existing `comms-tui.sock` direct path (#259) keeps working untouched in parallel.

### Cross-cutting decisions (apply to every G3 PR)

1. **Payload-blind.** The gateway parses ONLY the out-of-band seq header (G2 `decode_seq_frame`). It never `json.loads` the inner payload. The JSON-RPC `id` survives end-to-end inside the opaque payload (G2 guarantee). T3 stays in the core. *(The out-of-band LIFECYCLE frame the gateway DOES parse is schema-validated via the G1 Pydantic models — fail-loud, never `json.loads`-and-trust; security review F3.)*
2. **Peer-auth is cross-platform best-effort + FS-perms-of-record.** The `0600` socket under a `0700` dir ALREADY enforces same-uid (only the owner can `connect()`). `SO_PEERCRED` (Linux) is defense-in-depth ON TOP. macOS dev hosts lack `SO_PEERCRED` → the check degrades to the FS-perms guarantee + a `structlog` line; it never fail-closes on a platform that cannot answer (that would break the mac dev loop). The Linux CI gate proves the `SO_PEERCRED` path.
3. **Lifecycle frames are id-less JSON-RPC notifications** carrying NO T3 (`epoch` is non-secret boot metadata; `reason` is the closed `Literal`). A peer that does not understand them MUST ignore them (verified for the #259 TUI in G3-2). The canonical wire method name is pinned in ONE exported constant (G3-2 — the merged G1 code uses `daemon.lifecycle.*`, the spec prose said `core.lifecycle.*`; reconcile to a single name before the gateway consumer is written — architect C1).
4. **Loud link transitions in G3; the durable AUDIT guarantee lands with G4.** Every link-state change (core EOF/crash, `going_down`, each retry-dial, `ready`/restored, malformed-frame-reject, peer-auth-reject) is **loud** — `structlog` + a Prometheus counter. The gateway process has no audit sink in G3 (the gateway-local durable audit append + reconcile is explicitly a G4 mechanism, spec §6); claiming an *audited* guarantee G3 can't keep would be a paper-gate (the G2 lesson). **Core-side** rejects (the listener peer-auth reject) DO get a daemon audit row, because the daemon has an injected audit writer — that row is an explicit G3-2 task, not G3-1 (the listener is a dependency-light library). A malformed frame is never ack-and-dropped (seq not advanced; link teardown + reconnect).
5. **Commit hygiene (CI-gated — bake into every commit):** Conventional Commit subject containing `#237`, ending with the trailer `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`. Every `*.md` is markdownlint MD032-clean (blank line around every list/table). Stage explicit paths (never `git add -A`). `make check` before every push. No `--no-verify`, no `--admin`.

### G3-3 split candidate

If G3-3 grows past ~600 diff lines, cut it along the stable-kernel seam (NOT by line count) so the shared seq/ack state stays whole in one PR (architect M2):

- **G3-3a** = `GatewayClientListener` + `link_state` machine + control-frame derivation (the stable kernel — independently testable, no core dial).
- **G3-3b** = `GatewayCoreLink` + the relay + seq/ack deframe/reframe + the non-root in-process wire-contract test (keeps the deframe/reframe end-to-end in one change).

---

## PR G3-1 — Listener peer-auth (cross-platform SO_PEERCRED)

**Goal:** Harden `CommsSocketListener.accept` with a cross-platform same-uid peer check — refuse a mismatched-uid peer without wedging a legitimate dial-in — without changing any default behaviour.

**Why first:** Smallest, most self-contained, purely additive, and clearly trust-boundary. It establishes the accept-side auth posture the spec requires (§4 "the core authenticates the gateway via `SO_PEERCRED` on accept", §6 "both directions") while the existing #259 TUI path keeps working byte-for-byte (a same-uid peer passes). The `ALFRED_COMMS_RUNTIME_DIR` shared-volume relocation is deliberately **deferred to G3-4** — introducing an attacker-shaped env override two PRs before its only consumer would silently invalidate the existing `bind()` chmod/symlink-safety invariant (security review M3); it lands with the shared-volume mount it serves, behind fail-closed validation, where it is end-to-end testable.

> **Scope correction (architect H3):** the socket listener serves ONLY the foreground-TUI / gateway dial-in (ADR-0031). Daemon-spawned adapters (Discord, the reference plugin) reach the host over the **stdio pipe** (`CommsStdioTransport`), NOT this socket — so accept-side peer-auth cannot reject a legitimately-spawned bwrap adapter (it never touches this path). The both-direction requirement's *dial side* (gateway authenticates the core after `connect`) is a separate `dial_comms_socket` change in **G3-3** (security review F1) — do not drop it.

### Files

- Modify: `src/alfred/plugins/comms_socket_transport.py` — add `_resolve_peer_uid()` + `_peer_uid_authorized()`; call the peer check in `accept()`'s `_on_connect`.
- Modify: `src/alfred/i18n/_slice_4_reserve.py` (+ `SLICE_4_KEYS`) + `locale/en/LC_MESSAGES/alfred.po` / `.mo` (repo-root `locale/`, per `pyproject.toml` `output_dir`) — one new key `comms.socket.peer_uid_rejected`.
- Test: `tests/unit/plugins/test_comms_socket_transport.py` — peer-auth predicate accept/reject/unknown.
- Test: `tests/adversarial/comms/test_gateway_socket_peer_auth.py` — same-uid served; impostor-then-legitimate sequence (impostor refused, future stays unresolved, legitimate peer then resolves).
- Modify: `docs/adr/0032-gateway-comms-resume-transport.md` — record the cross-platform peer-auth posture.

### Design notes (read before Task 1)

- Peer check lives in `accept()`'s `_on_connect` callback, BEFORE the `_accepted` future is set. On reject: close the writer, log `comms.socket.peer_uid_rejected`, and DO NOT resolve the future (the accept keeps waiting for a legitimate peer — a rejected impostor must not be served, and must not wedge a legitimate dial-in).
- `writer.get_extra_info("socket")` returns the **accepted child socket** (the per-connection socket), the correct source for the *connector's* peer creds. `SO_PEERCRED` on the *listening* socket would return our own creds and always pass — defeating the check. Pin this in a comment so a future refactor that threads `self._sock` doesn't silently neuter it (security review H2).
- `_resolve_peer_uid(sock)`: on Linux use `sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3I"))` → unpack `(pid, uid, gid)` as **unsigned** (`"3I"` — the kernel `struct ucred` is three unsigned ints). `getsockopt` may return FEWER bytes than requested → `struct.unpack` would raise `struct.error`; so length-guard the buffer AND catch `(OSError, struct.error)`, returning `None` (degrade to FS-perms) rather than letting the accept callback raise and wedge the listener (security review H1). No `SO_PEERCRED` / `sock is None` → `None`.

### Tasks

- [ ] **Task 1: Failing test — peer-auth predicate (accept same-uid / reject mismatch / accept unknown)**

**Files:** Test: `tests/unit/plugins/test_comms_socket_transport.py`

```python
import os


def test_peer_uid_same_uid_accepted():
    from alfred.plugins.comms_socket_transport import _peer_uid_authorized

    # SO_PEERCRED reports our own uid -> authorized.
    assert _peer_uid_authorized(reported_uid=os.getuid()) is True


def test_peer_uid_different_uid_rejected():
    from alfred.plugins.comms_socket_transport import _peer_uid_authorized

    assert _peer_uid_authorized(reported_uid=os.getuid() + 1) is False


def test_peer_uid_unknown_accepted_on_fs_perms():
    from alfred.plugins.comms_socket_transport import _peer_uid_authorized

    # A platform without SO_PEERCRED reports None -> the 0600/0700 FS perms are the
    # enforcement-of-record; the check degrades to accept rather than fail-closing
    # the mac dev loop.
    assert _peer_uid_authorized(reported_uid=None) is True
```

- [ ] **Step: Run to verify failure**

Run: `uv run pytest tests/unit/plugins/test_comms_socket_transport.py -k peer_uid -v`
Expected: FAIL (`_peer_uid_authorized` undefined).

- [ ] **Task 2: Implement `_resolve_peer_uid` + `_peer_uid_authorized`**

**Files:** Modify: `src/alfred/plugins/comms_socket_transport.py` — add `import os` and `import struct` to the top-of-file imports, then:

```python
# The kernel ``struct ucred`` returned by ``SO_PEERCRED`` is three UNSIGNED ints
# ``{ pid_t pid; uid_t uid; gid_t gid; }``; ``"3I"`` matches it (uid is unsigned).
_UCRED_STRUCT: Final[str] = "3I"


def _resolve_peer_uid(sock: socket.socket | None) -> int | None:
    """Return the connected peer's uid, or ``None`` when unknowable.

    Linux answers via ``SO_PEERCRED`` (kernel-attested ``(pid, uid, gid)``). A
    platform without it (macOS dev hosts) returns ``None`` — the 0600 socket under
    the 0700 runtime dir is the same-uid enforcement-of-record there; ``SO_PEERCRED``
    is defense-in-depth, not the only line. NEVER raises: ``getsockopt`` may return
    fewer bytes than requested (a short read makes ``struct.unpack`` raise
    ``struct.error``), and a closed/non-AF_UNIX socket raises ``OSError`` — both
    degrade to ``None`` (accept on FS perms) rather than crashing the accept
    callback and wedging the listener.
    """
    if sock is None or not hasattr(socket, "SO_PEERCRED"):
        return None
    width = struct.calcsize(_UCRED_STRUCT)
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, width)
        if len(creds) != width:
            return None
        _pid, uid, _gid = struct.unpack(_UCRED_STRUCT, creds)
    except (OSError, struct.error):
        return None
    return uid


def _peer_uid_authorized(*, reported_uid: int | None) -> bool:
    """True if the peer is the same uid as us, or unknowable (FS-perms-of-record).

    ``None`` (no ``SO_PEERCRED`` / short read) is authorized: the only peer that can
    ``connect`` a 0600 socket under a 0700 dir is the owner. A reported uid that
    mismatches ``os.getuid()`` is a genuine impostor (a same-uid race that re-bound
    or a wider-perm misconfig) and is refused.
    """
    return reported_uid is None or reported_uid == os.getuid()
```

- [ ] **Step: Run to verify pass**

Run: `uv run pytest tests/unit/plugins/test_comms_socket_transport.py -k peer_uid -v`
Expected: PASS.

- [ ] **Task 3: Wire the check into `accept()`'s `_on_connect` + add the i18n key**

**Files:** Modify: `src/alfred/plugins/comms_socket_transport.py`; `src/alfred/i18n/_slice_4_reserve.py`; `alfred.po`/`.mo`.

In `_on_connect`, BEFORE building the transport:

```python
        async def _on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            assert self._accepted is not None
            if self._accepted.done():
                writer.close()
                return
            # ``get_extra_info("socket")`` is the ACCEPTED CHILD socket (per-
            # connection), so SO_PEERCRED reads the CONNECTOR's creds. Never read
            # peer creds off ``self._sock`` (the listener) — that returns our own
            # uid and always passes, defeating the check.
            peer_uid = _resolve_peer_uid(writer.get_extra_info("socket"))
            if not _peer_uid_authorized(reported_uid=peer_uid):
                # A different-uid peer beat a legitimate dial-in to the socket
                # (stale-socket race / wider-perm misconfig). Refuse it loudly and
                # KEEP WAITING — do NOT resolve the future, so a legitimate same-uid
                # peer can still connect (CLAUDE.md hard rule #7: never ack-and-drop).
                log.warning(
                    "comms.socket.peer_uid_rejected",
                    adapter_id=self._adapter_id,
                    peer_uid=peer_uid,
                )
                writer.close()
                return
            self._accepted.set_result(
                CommsSocketTransport(
                    adapter_id=self._adapter_id,
                    reader=reader,
                    writer=writer,
                    max_line_bytes=self._max_line_bytes,
                )
            )
```

Add to `SLICE_4_KEYS` + the `.po`:

```text
msgid "comms.socket.peer_uid_rejected"
msgstr "Refused a comms socket peer with a mismatched uid ({peer_uid})."
```

(The DAEMON-side audit row for the rejection is an explicit G3-2 task — the daemon caller has the injected audit writer; G3-1's listener is a dependency-light library, so its loud surface is the `structlog` warning + the refusal. Decision 4 above.)

- [ ] **Step: Run + i18n compile**

Run: `uv run pybabel compile -d locale -D alfred 2>&1 | tail -2 && uv run pytest tests/unit/plugins/test_comms_socket_transport.py -v`
Expected: PASS. (Use plain `pybabel`; NEVER `--omit-header` — strips the header → fuzzy/skip.)

- [ ] **Task 4: Adversarial test — impostor refused without wedging; same-uid served**

**Files:** Test: `tests/adversarial/comms/test_gateway_socket_peer_auth.py`

This test proves the HEADLINE claim — refuse an impostor WITHOUT wedging a legitimate dial-in. A same-uid CI host can't spoof a foreign uid via real `SO_PEERCRED`, so monkeypatch `_resolve_peer_uid` to report a foreign uid for the first connection and our uid for the second, then assert the accept resolves to the SECOND transport (security review L3).

```python
"""Adversarial: a different-uid peer must not be served the comms socket.

The 0600/0700 FS perms already bar a cross-uid connect; this proves the
SO_PEERCRED defense-in-depth refuses an impostor that slipped past perms (a
same-uid-race re-bind or a wider-perm misconfig) WITHOUT wedging a legitimate
same-uid dial-in.
"""

import asyncio
import os

import pytest

from alfred.plugins import comms_socket_transport as cst
from alfred.plugins.comms_socket_transport import (
    CommsSocketListener,
    _peer_uid_authorized,
)


def test_impostor_uid_refused_legitimate_still_authorized():
    assert _peer_uid_authorized(reported_uid=os.getuid() + 4242) is False
    assert _peer_uid_authorized(reported_uid=os.getuid()) is True


@pytest.mark.asyncio
async def test_listener_serves_same_uid_peer(tmp_path, monkeypatch):
    # Real same-uid loopback: bind, dial, the accept resolves (peer uid == ours).
    monkeypatch.setattr(cst, "_runtime_dir", lambda: tmp_path)
    listener = CommsSocketListener(adapter_id="tui")
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        reader, writer = await asyncio.open_unix_connection(str(listener.path))
        transport = await asyncio.wait_for(accept_task, timeout=2.0)
        assert transport is not None
        writer.close()
        await writer.wait_closed()
        await transport.close()
    finally:
        await listener.aclose()


@pytest.mark.asyncio
async def test_impostor_refused_then_legitimate_resolves(tmp_path, monkeypatch):
    # First connection reports a FOREIGN uid (impostor) -> refused, future unresolved;
    # second connection reports OUR uid -> the accept resolves to the SECOND transport.
    monkeypatch.setattr(cst, "_runtime_dir", lambda: tmp_path)
    uids = iter([os.getuid() + 9999, os.getuid()])
    monkeypatch.setattr(cst, "_resolve_peer_uid", lambda _sock: next(uids))
    listener = CommsSocketListener(adapter_id="tui")
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        # Impostor: connects, is refused, the accept stays pending.
        r1, w1 = await asyncio.open_unix_connection(str(listener.path))
        await asyncio.sleep(0.1)
        assert not accept_task.done()
        # Legitimate: connects, the accept resolves.
        r2, w2 = await asyncio.open_unix_connection(str(listener.path))
        transport = await asyncio.wait_for(accept_task, timeout=2.0)
        assert transport is not None
        for w in (w1, w2):
            w.close()
        await transport.close()
    finally:
        await listener.aclose()
```

- [ ] **Step: Run the adversarial test**

Run: `uv run pytest tests/adversarial/comms/test_gateway_socket_peer_auth.py -v`
Expected: PASS (3 tests).

- [ ] **Task 5: ADR-0032 amendment + full gate + commit**

**Files:** Modify: `docs/adr/0032-gateway-comms-resume-transport.md` (add a "Peer authentication (G3-1)" subsection: FS-perms-of-record + Linux `SO_PEERCRED` defense-in-depth + the macOS-degrades-to-perms posture; note the dial-side check is G3-3; MD032-clean).

- [ ] **Step: Full quality gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit/plugins/test_comms_socket_transport.py tests/adversarial/comms/test_gateway_socket_peer_auth.py -q && npx markdownlint-cli2@0.14.0 docs/adr/0032-gateway-comms-resume-transport.md docs/superpowers/plans/2026-06-14-g3-alfred-gateway-process.md`
Expected: all green.

- [ ] **Step: Commit (per-file staging, Conventional + #237 + trailer)**

```bash
git add src/alfred/plugins/comms_socket_transport.py \
        src/alfred/i18n/_slice_4_reserve.py \
        locale/en/LC_MESSAGES/alfred.po \
        locale/en/LC_MESSAGES/alfred.mo \
        tests/unit/plugins/test_comms_socket_transport.py \
        tests/adversarial/comms/test_gateway_socket_peer_auth.py \
        docs/adr/0032-gateway-comms-resume-transport.md \
        docs/superpowers/plans/2026-06-14-g3-alfred-gateway-process.md
git commit -m "feat(comms): cross-platform SO_PEERCRED accept-side peer-auth on the comms listener (Spec A G3-1 / ADR-0032) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

### G3-1 acceptance

- A same-uid dial-in is served; a different-uid peer is refused without wedging the accept (the impostor-then-legitimate test passes).
- `make check` green; the new listener lines hit the per-file 100%-branch CI gate (the file is already under both python-job + combined gates — keep coverage at 100%, incl. the short-read / `None`-socket / unknown-uid branches).
- No behaviour change on the #259 default path (a same-uid peer passes; no env override introduced).

---

## PR G3-2 — Core lifecycle wire-send (scope fixed; detailed plan written when reached)

**Goal:** Make the core actually SEND `ready` / `going_down` as id-less JSON-RPC notification frames over the comms wire (the G1 models exist but are unsent), so the G3-3 gateway can consume them; carry the boot `epoch` in the handshake.

**Key tasks (blocking findings from the architect review folded in):**

- **Pin ONE canonical wire method name** (architect C1). The merged G1 code emits `daemon.lifecycle.ready` / `daemon.lifecycle.going_down` (audit-row events + i18n keys); the spec prose said `core.lifecycle.*`. Export a single `Final` constant (in `comms_mcp/protocol.py` or `lifecycle_epoch.py`) that BOTH the core send and the gateway consume import — decide deliberately (keep `daemon.lifecycle.*` to avoid catalog churn, or rename + update the spec). Never leave two names in flight.
- **Mandatory transport write-lock** (architect C2 — confirmed: the runner is single-*reader* but has NO single-writer guard; `send_request` and a new lifecycle-send both call `transport.send`, which `await`s `drain()` between frames → byte-interleaved units corrupt the seq codec, and on a seq wire `_send_seq` mutates non-atomically). Add an `asyncio.Lock` around the entire `encode → write → drain → seq-increment` critical section in `CommsSocketTransport.send` (and the stdio sibling). Ship with an ordering/property test. NOT optional.
- Add `CommsPluginRunner.send_lifecycle_notification(notification: ReadyNotification | GoingDownNotification)` — serialises an id-less frame, writes it via the now-locked `transport.send`.
- **`going_down` drain-ordering contract** (architect H1 — confirmed: `_emit_going_down` fires in the shutdown `finally` BEFORE `supervisor.stop()` reaps the pump; the transport is still open at that point but the wire-send must land THERE). Pin: write the `going_down` frame inside the existing `if ready_emitted:` block, before `supervisor.stop()` and before the listener reap; a wire-send failure there is logged-not-fatal (the audit row already committed). Add a test asserting the `going_down` frame is observable on the peer before the listener closes.
- **Resolve the #259 TUI tolerance question UP FRONT** (architect H2) — a 10-minute read of the TUI dispatch path + one test. If the TUI ignores an unknown id-less notification → send unconditionally (delete the per-carrier complexity). If it does NOT → a per-carrier gate is a first-class task with its own test. Do NOT ship a runtime branch discovered mid-implementation; decide before coding.
- **Peer-auth-reject daemon audit row** (security review M1, decision 4) — the daemon caller emits `comms.socket.peer_uid_rejected` as an audit row (it has the audit writer); the listener surfaces the rejection so the daemon can observe it. Adversarial test asserts the row.
- Widen `LifecycleReason` only if a real `restart` intent-producer lands here (likely keep `shutdown`).
- ADR-0033 amendment: record the wire-send (G1 = audit-only; G3 = audit + frame).

---

## PR G3-3 — The `alfred-gateway` process (scope fixed; detailed plan written when reached)

**Goal:** The gateway process: a pure, reconnect-capable, payload-blind relay between a dial-in client and the core.

**New module:** `src/alfred/gateway/` — `core_link.py` (`GatewayCoreLink`), `client_listener.py` (`GatewayClientListener`), `relay.py` (the pump wiring), `link_state.py` (the `UP/DOWN_SIGNALLED/DOWN_CRASH/REDIALING` machine + control-frame derivation), `metrics.py` (Prometheus), `__main__.py` / a `alfred gateway` CLI command.

**Key tasks:**

- `GatewayClientListener` — reuse the `CommsSocketListener` 0600/0700 + G3-1 peer-auth posture for the client-facing socket (`comms-gateway.sock`); terminate the client connection; emit `link.reconnecting`/`restored`/`unavailable` control frames.
- `GatewayCoreLink` — `dial_comms_socket` to the core; a **fake-clock-injectable** reconnect/backoff loop (initial ≥100–250 ms, exp to a 2–5 s ceiling, full jitter, **never a 0-delay first retry**); the epoch-reconciling handshake (reject a `ready`/handshake whose epoch mismatches the retained high-water; reconcile new-core `seq=0`); **client-side `SO_PEERCRED` check on the dialed core socket** (gateway authenticates the core — the both-direction dial side G3-1 deferred; same `(OSError, struct.error)` + length-guard discipline; security review F1); consume `going_down`/`ready` → drive `link_state`.
- **Validate the lifecycle frame, don't trust it** (security review F3): the consumed `ready`/`going_down` frame is parsed via the G1 Pydantic models (epoch pinned to 32-hex, `reason` a closed `Literal`) — fail-loud on a malformed frame; a forged `ready` past peer-auth/epoch must be rejected + audited (false `restored` banner is an attack surface), NOT acted on. The epoch CHECK ships in G3-3 even though the buffer-flush it guards is G4 (security review F2; spec §6 corpus (c)).
- **Seq/ack: the gateway is the first real peer.** It echoes `AlfredSeqAck/1` in its handshake AND `decode_seq_frame` on the core leg / `encode_seq_frame` on the re-send (deframe/reframe), assigning its own per-leg `seq` and a real `cumulative_ack` via `SeqDedupWindow` — NOT the `a=0` placeholder the plain plugins emit. (G2 lesson: never advertise a codec you don't implement.)
- The relay loop: `client→core` and `core→client` as two pumped directions, opaque payload forwarded byte-for-byte, `id` preserved. **No buffering** — a frame in flight across a core gap is dropped in G3 (G4 adds the `ReplayBuffer`).
- Metrics: `gateway_core_link_up`, `gateway_reconnect_attempts_total`, `gateway_core_unavailable_seconds`, `gateway_peer_auth_rejected_total` (security review M2; the buffer-depth/cap metrics are G4).
- **Non-root in-process test that proves the wire contract** (G2 lesson / #245 paper-gate hazard): an in-process gateway↔fake-core test that exercises deframe/reframe + reconnect WITHOUT requiring the root-only launcher gate.
- **Payload-blindness assertion** (security review F4): an adversarial/property test that the relay forwards a payload bearing a canary T3 marker byte-for-byte and the canary trips ONLY in the core (spec §6 corpus (a)) — the concrete proof of hard rule #5 across the new carrier.

**Coverage:** `GatewayClientListener` bind + core-frame ingest/containment to 100% branch (trust-boundary); ≥80% relay/core-link.

---

## PR G3-4 — Deployment (scope fixed; detailed plan written when reached)

**Goal:** Ship the gateway as a separate always-up Compose service whose readiness is independent of core liveness, and relocate the gateway↔core socket onto the shared volume.

**Key tasks:**

- **Configurable runtime dir + fail-closed validation** (security review M3 — the substantive deferred item). Add `ALFRED_COMMS_RUNTIME_DIR` to `_runtime_dir()`. Because the override moves the socket dir off `$HOME`, the existing unconditional `bind()` `chmod(0700)` (which a load-bearing comment claims is symlink-safe BECAUSE the parent is owner-only `$HOME`) is no longer safe — `chmod` follows symlinks. So: require an ABSOLUTE path; `lstat` the resolved dir and **refuse boot** (loud, audited) if it is a symlink or not owned by `os.getuid()`; update/delete the now-false symlink-safety comment. Tests: override path used; relative path refused; symlinked/non-owner dir refused; whitespace-only env → default (branch coverage). Document `ALFRED_COMMS_RUNTIME_DIR` as an operator-trust (T1) knob that fails closed.
- `docker-compose.yaml`: a new `alfred-gateway` service (`restart: unless-stopped`, `build` the core image, `command: ["gateway"]`, `depends_on` core **WITHOUT** `service_healthy`, shared `alfred_run` volume mounted, `ALFRED_COMMS_RUNTIME_DIR` pointed at it); a **long-running `alfred-core` daemon service** (today's `alfred-core` is one-shot — a flag-day; architect M3) running `alfred daemon start` with `restart: unless-stopped` + the shared volume; two-tier gateway healthcheck (liveness = client listener bindable; readiness = core-link up OR (G4) buffering; only wedged-past-breaker = unhealthy — in G3, readiness = listener bindable + link-attempting).
- A named `alfred_run` Docker volume.
- `ops/grafana/gateway.json` + `ops/alerts/gateway.yml` (`GatewayCoreUnavailable`; the buffer/breaker alerts are G4-gated placeholders) + a Prometheus scrape entry — none exist yet (PRD §7.5 promise).
- `tests/unit/test_compose_invariants.py`: gateway service present, `restart: unless-stopped`, NO `service_healthy` on the core dep, shared volume mounted, and (devops-010) the gateway does **NOT** carry `SETUID` (only `alfred-core` does in Spec A — adapter-hosting/Spec B revisits this).
- README quickstart + `bin/alfred-setup.sh`: provision `alfred_run`; migrate the one-shot `alfred-core` consumers; note `alfred chat` still dials the core directly until G5 (the interim no-resume window).
- ADR-0032/0033 finalisation; ADR-0032 status → Accepted if the fleet agrees. ADR amendments ride the same `/review-pr` fleet (security always) as the PR they land in (security review L3).

---

## Self-review (G3-1)

- **Spec coverage:** §4/§6 SO_PEERCRED both-directions → G3-1 (core-accept side) + G3-3 (gateway-dial side, explicitly cross-referenced). §7 shared-volume socket → G3-4 (`ALFRED_COMMS_RUNTIME_DIR` with fail-closed validation). G4/Spec-C firmly out (decisions + deferral lists). ✓
- **Placeholders:** none in G3-1 — every step has real code/commands. PRs G3-2…G3-4 are intentionally scope-only (detailed plans written against merged reality when reached, per the header), but each blocking review finding is captured as a named task so nothing is lost. ✓
- **Type consistency:** `_resolve_peer_uid(sock: socket.socket | None) -> int | None`, `_peer_uid_authorized(*, reported_uid: int | None) -> bool`, `_UCRED_STRUCT: Final[str]` — names/signatures match across Tasks 1–4. The adversarial test monkeypatches `cst._runtime_dir` / `cst._resolve_peer_uid` (module-level names that exist). ✓
- **Review findings folded:** security H1 (`struct.error` + length-guard + `"3I"`), H2 (accepted-child-socket comment), L3 (impostor-then-legitimate test), M3 (override deferred to G3-4 w/ fail-closed validation); architect H3 (stdio-vs-socket scope correction), C1/C2/H1/H2 (→ G3-2 named tasks), F1–F4 (→ G3-3 named tasks), M1/decision-4 (audit-guarantee wording). ✓
