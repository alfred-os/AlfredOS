# G6-7-2 — CommsPluginRunner inbound-disposition seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Factor an injectable **inbound disposition** into the `CommsPluginRunner` single-reader pump so the daemon dispatch-runner (default) and the future gateway forward-runner (G6-7-3) can share the read/crash/EOF/teardown mechanics while routing notifications differently — and harden the G6-7-1 structural-error summary so it never surfaces an attacker-controlled extra-key name (the G6-7-1 carry-item).

**Architecture:** The per-notification routing logic currently inlined in `CommsPluginRunner._route_notification` (+ its `_route_spawn_request` helper) is moved verbatim into a new default disposition object, `SessionDispatchDisposition`, behind a narrow `InboundDisposition` Protocol in a new module `src/alfred/plugins/inbound_disposition.py`. `CommsPluginRunner.__init__` gains an optional `inbound_disposition` param that defaults to a `SessionDispatchDisposition` built from the runner's own session/resolver — so every existing call site is byte-for-byte unchanged. `_route_notification` shrinks to a one-line delegator to the injected disposition (retaining the direct-call test API and keeping the pump and `_spawn_notification_dispatch` literally unchanged). The gateway forward disposition (G6-7-3) is a *different* implementation of the same Protocol, with no session. Separately, `inbound_reparse._structural_summary` is hardened to redact the `loc` of `extra_forbidden` pydantic errors (the only attacker-key leak vector for this schema).

**Tech Stack:** Python 3.14, asyncio, Pydantic v2, structlog, pytest. AlfredOS comms-MCP host runner (`src/alfred/plugins/`, `src/alfred/comms_mcp/`).

---

## Context the engineer needs (read before starting)

- **ADR-0039** (`docs/adr/0039-gateway-adapter-inbound-bridge.md`) — Decision item 1 + the "Negative / costs" bullet: "The `CommsPluginRunner` single-reader pump must grow an injectable inbound disposition (a refactor of the most-tested I/O module; mitigated by keeping the existing session-dispatch the default disposition — behaviour-preserving, gated by a byte-for-byte-unchanged test)."
- **Spec** (`docs/superpowers/specs/2026-06-21-gateway-adapter-inbound-bridge-design.md`) §5 G6-7-2 row: "Refactor the single-reader pump to take an injectable inbound disposition; the existing session-dispatch becomes the default disposition (behaviour-preserving; gated by a test asserting the daemon stdio path is byte-for-byte unchanged)."
- **The seam today:** `src/alfred/plugins/comms_runner.py`
  - `_spawn_notification_dispatch` (L652-673) schedules `ensure_future(self._route_notification(method, params, wire_seq=wire_seq))`. **This stays unchanged.**
  - `_route_notification` (L790-864): the per-notification routing — (a) credential `spawn_request` interception when a resolver is wired → `_route_spawn_request`; (b) else `session._on_post_handshake_method(method, params_mapping, wire_seq=wire_seq)`; (c) the `AdapterStatusAuditWriteError` SEC-1 escalation arm; (d) the blanket `except Exception` catch-and-continue. Never raises (fire-and-forget contract).
  - `_route_spawn_request` (L866-951): the G6-3 credential round-trip — validate `SpawnRequest`, call resolver, send `CORE_ADAPTER_SPAWN_GRANT` via `self.send_notification`, with `AdapterCredentialAuditWriteError`/`AdapterCredentialError`/send-fault arms. Never raises.
  - `_request_restart` (L979-997): reads `self._session._supervisor`; stays on the runner.
  - `_route_transport_crash` (L953-977): synthesizes `adapter.crashed` straight to `session._on_post_handshake_method`. **STAYS on the runner unchanged** — it is NOT part of this seam (the gateway's session-less crash path is G6-7-3's concern, and rerouting it would change the `crash_route_failed` log key, breaking byte-for-byte).
- **Direct-call test surface (load-bearing):** `tests/unit/plugins/test_comms_runner_credential_route.py` and `tests/unit/plugins/test_comms_runner.py` call `runner._route_notification(...)` **directly** (≈14 sites). The delegator (Task 2) keeps these passing unchanged.
- **Carry-item target:** `src/alfred/comms_mcp/inbound_reparse.py:46-61` `_structural_summary`. `InboundMessageNotification` (`protocol.py:322-353`) is `extra="forbid"` (via `_WireModel`); its only free-form field is `body: Mapping[str, object]` which accepts ANY keys/values, so the **only** attacker-key leak vector is `extra_forbidden` (top-level or nested, e.g. `addressing_signal.<key>`). No `dict[str, ConstrainedType]` field exists, so no non-extra_forbidden loc carries an attacker key.
- **No i18n changes:** the moved code uses structlog keys + an internal `InboundBodyMalformedError` message, not `t()`. No catalog edits.
- **Conventions:** modern Python 3.12+ idioms, frozen/immutable where stateless, `mypy --strict` + `pyright`, no `Any` without justification, structlog with closed-vocab keys, no secrets/T3 in logs (hard rules #5/#7). Comments only where WHY is non-obvious.

## File structure

| File | Responsibility |
| --- | --- |
| `src/alfred/plugins/inbound_disposition.py` (**NEW**) | The `InboundDisposition` Protocol + the default `SessionDispatchDisposition` (moved `_route_notification`/`_route_spawn_request` logic) + the `_CredentialResolverLike` Protocol relocated here + the two restart-reason constants. Trust-boundary-adjacent → both plugins-subsystem ci.yml 100% gate sites. |
| `src/alfred/plugins/comms_runner.py` (modify) | `__init__` gains `inbound_disposition: InboundDisposition \| None = None`; default-constructs `SessionDispatchDisposition`; `_route_notification` becomes a one-line delegator; `_route_spawn_request` deleted (moved); imports the moved symbols from `inbound_disposition`. |
| `src/alfred/comms_mcp/inbound_reparse.py` (modify) | `_structural_summary` redacts `extra_forbidden` loc (carry-item). |
| `tests/unit/plugins/test_inbound_disposition.py` (**NEW**) | Direct unit tests of `SessionDispatchDisposition` + the seam (default identity, injected-disposition routing, byte-for-byte daemon path). |
| `tests/unit/comms_mcp/test_inbound_reparse.py` (modify) | Add the extra-key-redaction assertions for the carry-item. |
| `tests/unit/plugins/test_comms_runner.py`, `test_comms_runner_credential_route.py` (unchanged behaviour; may need import-path touch-ups only if symbols move) | The byte-for-byte gate — must stay green with no behavioural edits. |
| `.github/workflows/ci.yml` (modify) | Register `inbound_disposition.py` in every plugins-subsystem per-file 100% gate site (hashFiles guards + `--include` lists). |

---

## Task 0: Carry-item — redact attacker extra-keys in the structural summary

**Files:**

- Modify: `src/alfred/comms_mcp/inbound_reparse.py:46-61`
- Test: `tests/unit/comms_mcp/test_inbound_reparse.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/comms_mcp/test_inbound_reparse.py` (adapt the existing envelope/body builders in that file; the body must be valid JSON with a forbidden extra top-level key plus a known-field error so both branches are asserted):

```python
def test_structural_summary_redacts_extra_forbidden_key_name() -> None:
    """An attacker-controlled extra key NAME must never reach the error string.

    G6-7-2 carry-item (UAT on #311): ``extra_forbidden@<key>`` surfaced the body's
    top-level key name. Redact the loc for ``extra_forbidden`` (the key is T3-derived)
    while keeping schema-known field paths for every other error type (spec §3.3).
    """
    # Valid JSON object, wrong/missing known field (schema path kept) + a forbidden
    # extra key (name redacted). adapter_id matches the envelope so we reach the body
    # parse, not the mismatch arm.
    body = (
        b'{"adapter_id":"discord","s3cr3t_smuggled_key":"leak",'
        b'"inbound_id":"i1","platform_user_id":"u1"}'
    )
    envelope = _envelope(adapter_id="discord", body=body)  # existing helper in this file

    with pytest.raises(InboundBodyMalformedError) as excinfo:
        reparse_forwarded_inbound(envelope)

    message = str(excinfo.value)
    assert "s3cr3t_smuggled_key" not in message  # attacker key NAME redacted
    assert "extra_forbidden" in message            # the TYPE still surfaces (debug aid)
    assert "<redacted>" in message                 # explicit redaction marker
    # A schema-known missing field path is still surfaced (not redacted):
    assert "missing@" in message
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_inbound_reparse.py::test_structural_summary_redacts_extra_forbidden_key_name -v`
Expected: FAIL — current `_structural_summary` emits `extra_forbidden@s3cr3t_smuggled_key`, so `"s3cr3t_smuggled_key" not in message` fails (and `<redacted>` is absent).

- [ ] **Step 3: Implement the redaction**

Replace `_structural_summary` (`inbound_reparse.py:46-61`) with:

```python
def _structural_summary(exc: ValidationError) -> str:
    """A LEAK-SAFE one-line summary of why an inbound body failed validation.

    Built from ONLY the closed structural shape of each pydantic error — the
    error-type code and a leak-safe ``loc`` rendering — plus the error count. The
    raw ``input`` / ``msg`` / ``ctx`` values are DROPPED here on purpose: they echo
    the untrusted T3 body and must never reach an exception string the core might
    log (spec §3.3 — no payload in error attrs).

    The ``loc`` of an ``extra_forbidden`` error ENDS in the unexpected key NAME, which
    is attacker-supplied T3 (G6-7-2 carry-item: UAT on #311 saw ``extra_forbidden@<key>``
    surface a body's top-level key name). That whole ``loc`` is redacted to
    ``<redacted>``. Every OTHER pydantic error type carries a schema-known field path
    in ``loc`` (a field must be DECLARED to be validated), which is safe to surface as
    an actionable debug aid (missing vs type-error vs decode). ``InboundMessageNotification``
    has no ``dict[str, ConstrainedType]`` field (``body`` accepts any object), so
    ``extra_forbidden`` is the sole attacker-key vector; a future constrained-dict field
    would need this redaction broadened.
    """
    errors = exc.errors(include_url=False)
    parts: list[str] = []
    for error in errors:
        error_type = error["type"]
        if error_type == "extra_forbidden":
            parts.append(f"{error_type}@<redacted>")
        else:
            parts.append(f"{error_type}@{'.'.join(str(segment) for segment in error['loc'])}")
    return f"{len(errors)} error(s): {', '.join(parts)}"
```

- [ ] **Step 4: Run test to verify it passes + no regression**

Run: `uv run pytest tests/unit/comms_mcp/test_inbound_reparse.py -v`
Expected: PASS (new test + all existing). If an existing test asserted the literal `extra_forbidden@<key>` form, update it to `extra_forbidden@<redacted>` (search the file).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/inbound_reparse.py tests/unit/comms_mcp/test_inbound_reparse.py
git commit -m "$(cat <<'EOF'
fix(comms): redact attacker extra-key names in inbound structural summary (Spec B G6-7-2, #309)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 1: Define the `InboundDisposition` Protocol + `SessionDispatchDisposition` default

**Files:**

- Create: `src/alfred/plugins/inbound_disposition.py`
- Test: `tests/unit/plugins/test_inbound_disposition.py`

The disposition is the per-notification routing strategy. The default carries ALL the session-coupling so a session-LESS gateway disposition (G6-7-3) is constructible on the same Protocol. It calls back to the runner ONLY via two narrow async callables (`send_notification`, `request_restart`) so transport + supervisor access stays on the runner.

- [ ] **Step 1: Write the failing test (Protocol + default routing happy path)**

Create `tests/unit/plugins/test_inbound_disposition.py`. Reuse the fakes from `tests/unit/plugins/test_comms_runner.py` / `test_comms_runner_credential_route.py` (a fake session exposing `_on_post_handshake_method` + `_supervisor`, a recording handler). Minimal first test:

```python
import pytest

from alfred.plugins.inbound_disposition import InboundDisposition, SessionDispatchDisposition


@pytest.mark.asyncio
async def test_default_disposition_routes_notification_to_session() -> None:
    """A non-spawn-request notification is dispatched through the session arm."""
    session = _FakeSession()  # records _on_post_handshake_method(method, params, wire_seq)
    disposition = SessionDispatchDisposition(
        session=session,
        credential_resolver=None,
        adapter_id="discord",
        send_notification=_unused_send,      # async, asserts NOT called here
        request_restart=_unused_restart,     # async, asserts NOT called here
    )
    assert isinstance(disposition, InboundDisposition)  # structural Protocol check

    await disposition.dispatch("inbound.message", {"k": "v"}, wire_seq=7)

    assert session.calls == [("inbound.message", {"k": "v"}, 7)]
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_inbound_disposition.py -v`
Expected: FAIL — module `alfred.plugins.inbound_disposition` does not exist.

- [ ] **Step 3: Create the module (move the routing logic verbatim)**

Create `src/alfred/plugins/inbound_disposition.py`. Move `_route_notification`'s body + the whole `_route_spawn_request` from `comms_runner.py` **verbatim** (rename `self.send_notification` → `self._send_notification`, `self._request_restart` → `self._request_restart` callback, `self._session` → `self._session`, `self._adapter_id` → `self._adapter_id`, `self._credential_resolver` → `self._credential_resolver`). Relocate `_CredentialResolverLike` and the two restart-reason constants here (comms_runner re-imports them). Structure:

```python
"""The injectable inbound-notification disposition seam (Spec B G6-7-2, #309).

The ``CommsPluginRunner`` single-reader pump (read / crash / EOF / teardown) is shared
by the daemon dispatch-runner and the gateway forward-runner (G6-7-3); only the
PER-NOTIFICATION routing differs. That routing is this module's ``InboundDisposition``.
The default :class:`SessionDispatchDisposition` is the behaviour-preserving daemon path
(session dispatch + the G6-3 credential round-trip + the SEC-1 audit-write escalation);
the gateway forward disposition (G6-7-3) is a session-LESS sibling implementation.

Every ``dispatch`` body runs FIRE-AND-FORGET (the pump schedules it via
``ensure_future`` whose done-callback never retrieves the result), so it MUST NOT
raise: every terminal disposition — including a non-skippable failed-audit-write —
is handled by a loud escalation here, never by propagation (there is no awaiter).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

import structlog

from alfred.comms_mcp.errors import (
    AdapterCredentialAuditWriteError,
    AdapterCredentialError,
    AdapterStatusAuditWriteError,  # confirm canonical import path during impl
)
from alfred.comms_mcp.protocol import (
    CORE_ADAPTER_SPAWN_GRANT,
    GATEWAY_ADAPTER_SPAWN_REQUEST,
    SpawnGrant,
    SpawnRequest,
)
from alfred.plugins.errors import CommsProtocolError  # confirm path
from alfred.plugins.session import AlfredPluginSession

log = structlog.get_logger(__name__)

_STATUS_AUDIT_UNWRITABLE_RESTART_REASON = "status_audit_unwritable"
_CREDENTIAL_AUDIT_UNWRITABLE_RESTART_REASON = "credential_audit_unwritable"


class _CredentialResolverLike(Protocol):
    async def resolve(self, request: SpawnRequest) -> SpawnGrant: ...


class _SendNotification(Protocol):
    async def __call__(self, method: str, params: Mapping[str, object]) -> None: ...


class _RequestRestart(Protocol):
    async def __call__(self, *, reason: str) -> None: ...


@runtime_checkable
class InboundDisposition(Protocol):
    """Routes ONE child notification. MUST NOT raise (fire-and-forget contract)."""

    async def dispatch(
        self, method: str, params: object, *, wire_seq: int | None = None
    ) -> None: ...


class SessionDispatchDisposition:
    """The default daemon disposition: dispatch through the ``AlfredPluginSession``.

    Behaviour-IDENTICAL to the pre-G6-7-2 ``CommsPluginRunner._route_notification`` +
    ``_route_spawn_request`` (the same code, moved). Holds the session + the G6-3
    credential resolver; calls back to the runner ONLY for transport send + restart.
    """

    def __init__(
        self,
        *,
        session: AlfredPluginSession,
        credential_resolver: _CredentialResolverLike | None,
        adapter_id: str,
        send_notification: _SendNotification,
        request_restart: _RequestRestart,
    ) -> None:
        self._session = session
        self._credential_resolver = credential_resolver
        self._adapter_id = adapter_id
        self._send_notification = send_notification
        self._request_restart = request_restart

    async def dispatch(
        self, method: str, params: object, *, wire_seq: int | None = None
    ) -> None:
        # <<< verbatim body of the old _route_notification, with the substitutions
        #     above; the spawn-request arm calls self._route_spawn_request(...) >>>
        ...

    async def _route_spawn_request(self, params: Mapping[str, object] | None) -> None:
        # <<< verbatim body of the old _route_spawn_request, with self._send_notification
        #     replacing self.send_notification and self._request_restart the callback >>>
        ...
```

**Import-cycle rule:** `inbound_disposition.py` MUST NOT import `comms_runner`. `comms_runner` imports FROM `inbound_disposition` (the Protocol, `SessionDispatchDisposition`, `_CredentialResolverLike`, the two restart-reason constants). Confirm `AlfredPluginSession` imports cleanly here (it is already imported by comms_runner; importing it in a module comms_runner imports is fine as long as session.py does not import inbound_disposition — it does not).

- [ ] **Step 4: Run to verify the happy-path test passes**

Run: `uv run pytest tests/unit/plugins/test_inbound_disposition.py -v`
Expected: PASS.

- [ ] **Step 5: Add the moved-behaviour unit tests (parity with the runner tests)**

Port the disposition-relevant assertions so the new module reaches 100% on its own (the per-file gate requires it). Cover, calling `disposition.dispatch(...)` / `disposition._route_spawn_request(...)` directly:

1. spawn-request interception when a resolver is wired → resolver called, grant sent via `send_notification`;
2. malformed `SpawnRequest` → loud drop, no grant;
3. `AdapterCredentialError` → loud drop, no grant;
4. `AdapterCredentialAuditWriteError` → `request_restart` called (SEC arm), no grant, no raise;
5. `AdapterCredentialAuditWriteError` + `request_restart` raises → logged, no raise;
6. send-fault (`OSError`/`CommsProtocolError`) on the grant → loud drop, no raise;
7. `AdapterStatusAuditWriteError` from the session arm → `request_restart` called, no raise;
8. status-audit + restart raises → logged, no raise;
9. blanket handler `Exception` from the session arm → swallowed, reader survives (no raise);
10. spawn-request method but resolver is `None` → falls through to the session arm (NOT intercepted).

Each must assert `dispatch` returns `None` and never raises (fire-and-forget). Use the existing fakes' shapes from `test_comms_runner_credential_route.py`.

- [ ] **Step 6: Run the full new-module suite**

Run: `uv run pytest tests/unit/plugins/test_inbound_disposition.py -v`
Expected: PASS (all).

- [ ] **Step 7: Commit**

```bash
git add src/alfred/plugins/inbound_disposition.py tests/unit/plugins/test_inbound_disposition.py
git commit -m "$(cat <<'EOF'
feat(comms): InboundDisposition seam + SessionDispatchDisposition default (Spec B G6-7-2, #309)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 2: Wire the seam into `CommsPluginRunner` (default-construct + delegator)

**Files:**

- Modify: `src/alfred/plugins/comms_runner.py` (`__init__` ~206-272; `_route_notification` 790-864 → delegator; delete `_route_spawn_request` 866-951; update imports + remove now-moved constants/`_CredentialResolverLike`)
- Test: existing `tests/unit/plugins/test_comms_runner.py` + `test_comms_runner_credential_route.py` must stay green unchanged (byte-for-byte gate)

- [ ] **Step 1: Run the existing runner suites GREEN first (baseline)**

Run: `uv run pytest tests/unit/plugins/test_comms_runner.py tests/unit/plugins/test_comms_runner_credential_route.py -q`
Expected: PASS — capture this as the byte-for-byte baseline. (No code change yet.)

- [ ] **Step 2: Add the seam param + default construction to `__init__`**

In `CommsPluginRunner.__init__`, add a keyword param and build the default disposition AFTER the runner's own attrs (`send_notification`, `_request_restart`, `_session`, `_adapter_id`, `_credential_resolver`) exist:

```python
        inbound_disposition: InboundDisposition | None = None,
```

…and at the end of `__init__`:

```python
        self._inbound_disposition: InboundDisposition = inbound_disposition or SessionDispatchDisposition(
            session=session,
            credential_resolver=credential_resolver,
            adapter_id=adapter_id,
            send_notification=self.send_notification,
            request_restart=self._request_restart,
        )
```

Add the import:

```python
from alfred.plugins.inbound_disposition import (
    InboundDisposition,
    SessionDispatchDisposition,
)
```

Remove from `comms_runner.py` the now-moved `_CredentialResolverLike` definition and the two restart-reason constants; re-import the constants from `inbound_disposition` if any other runner code still references them (e.g. `_request_restart` callers pass the reason — the SEC-1 arms now live in the disposition, so the runner likely no longer needs them; verify with grep and delete if unreferenced).

- [ ] **Step 3: Shrink `_route_notification` to a delegator; delete `_route_spawn_request`**

Replace the whole `_route_notification` body (790-864) with:

```python
    async def _route_notification(
        self, method: str, params: object, *, wire_seq: int | None = None
    ) -> None:
        """Route one notification via the injected inbound disposition.

        The per-notification routing strategy (default: ``SessionDispatchDisposition``
        — session dispatch + the G6-3 credential round-trip + the SEC-1 audit-write
        escalation) lives in :mod:`alfred.plugins.inbound_disposition`. This thin
        delegator keeps the pump (``_spawn_notification_dispatch`` schedules THIS
        coroutine fire-and-forget) byte-for-byte unchanged; the disposition owns the
        never-raise contract.
        """
        await self._inbound_disposition.dispatch(method, params, wire_seq=wire_seq)
```

Delete `_route_spawn_request` (866-951) entirely (moved to the disposition). Leave `_route_transport_crash` and `_request_restart` exactly as they are.

- [ ] **Step 4: Run the byte-for-byte gate**

Run: `uv run pytest tests/unit/plugins/test_comms_runner.py tests/unit/plugins/test_comms_runner_credential_route.py -q`
Expected: PASS, identical set to Step 1. The direct `runner._route_notification(...)` calls now forward to the default disposition → same observable behaviour. If a credential-route test imported a moved symbol (e.g. `GATEWAY_ADAPTER_SPAWN_REQUEST`) from `comms_runner`, repoint the import to its canonical `protocol` home (no behavioural change).

- [ ] **Step 5: Type-check + lint**

Run: `uv run mypy src/alfred/plugins/comms_runner.py src/alfred/plugins/inbound_disposition.py && uv run ruff check src/alfred/plugins/`
Expected: clean. (`mypy --strict`; no `Any`.)

- [ ] **Step 6: Commit**

```bash
git add src/alfred/plugins/comms_runner.py
git commit -m "$(cat <<'EOF'
refactor(comms): route CommsPluginRunner notifications via injectable disposition (Spec B G6-7-2, #309)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 3: Explicit seam tests (default identity + injection + byte-for-byte)

**Files:**

- Test: `tests/unit/plugins/test_inbound_disposition.py` (add) and/or `tests/unit/plugins/test_comms_runner.py` (add)

- [ ] **Step 1: Write the seam tests**

```python
@pytest.mark.asyncio
async def test_runner_defaults_to_session_dispatch_disposition() -> None:
    """A runner built with no disposition uses SessionDispatchDisposition (default)."""
    runner = _make_runner()  # the existing helper, no inbound_disposition arg
    assert isinstance(runner._inbound_disposition, SessionDispatchDisposition)


@pytest.mark.asyncio
async def test_injected_disposition_receives_notifications_via_pump() -> None:
    """An injected disposition — not the session — receives pumped notifications."""
    received: list[tuple[str, object, int | None]] = []

    class _SpyDisposition:
        async def dispatch(self, method, params, *, wire_seq=None):
            received.append((method, params, wire_seq))

    runner = _make_runner(inbound_disposition=_SpyDisposition())
    # drive one notification frame through the real pump (reuse the _FakeTransport
    # queue pattern from test_comms_runner.py: enqueue handshake-ack then one
    # notification then clean EOF), then run().
    await _run_one_notification(runner, method="inbound.message", params={"k": 1}, wire_seq=3)

    assert received == [("inbound.message", {"k": 1}, 3)]
    # And the session was NOT used for that notification (byte-for-byte isolation):
    assert runner._session.post_handshake_calls == []  # adapt to the fake's recorder
```

- [ ] **Step 2: Run to verify (red then green)**

Run: `uv run pytest tests/unit/plugins/test_inbound_disposition.py -k "seam or disposition or injected or default" -v`
Expected: PASS after Task 2 is in place (these assert the wiring Task 2 added).

- [ ] **Step 3: Commit**

```bash
git add tests/unit/plugins/test_inbound_disposition.py
git commit -m "$(cat <<'EOF'
test(comms): pin inbound-disposition seam (default identity + injection) (Spec B G6-7-2, #309)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 4: CI per-file 100% coverage gates + full quality bar

**Files:**

- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Find every plugins-subsystem gate site**

Run: `grep -n "comms_runner.py" .github/workflows/ci.yml`
The plugins-subsystem gate is DUPLICATED (python-job + coverage-gates job): each occurrence has a `hashFiles('...comms_runner.py...') != ''` guard in its `if:` AND a `--include='...comms_runner.py,...'` list. That is up to FOUR edit points (2 guards + 2 include lists). Confirm by reading the surrounding `coverage report --include` blocks.

- [ ] **Step 2: Add `inbound_disposition.py` to every site**

For each plugins-subsystem gate occurrence, add `src/alfred/plugins/inbound_disposition.py` to BOTH the `hashFiles(...)` guard (so the gate fires when only this file changes) AND the matching `--include='...'` list. Keep alphabetical/existing ordering.

- [ ] **Step 3: Reproduce the EXACT gate locally (full unit run — scoped runs under-cover)**

Run (mirrors the CI gate; a scoped run will falsely show <100% on a file imported elsewhere):

```bash
uv run coverage run -m pytest tests/unit -q
uv run coverage report --include='src/alfred/plugins/inbound_disposition.py' --fail-under=100
uv run coverage report --include='src/alfred/plugins/comms_runner.py' --fail-under=100
```

Expected: both report 100% line+branch. If `inbound_disposition.py` is <100%, add the missing-branch test to `test_inbound_disposition.py` (every exception arm + the resolver-None fall-through + the not-a-SpawnGrant guard).

- [ ] **Step 4: Full quality bar**

Run:

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit -q
```

Expected: all green. Then re-run `pybabel update -i locale/en/LC_MESSAGES/alfred.po ... --check` style drift gate ONLY if any `t()` call-site line shifted — this slice adds none, but `comms_runner.py` line numbers shifted, so re-run `pybabel update` (refresh `#:` refs) + recompile if any `t()` call survives in the edited region (verify with `grep -n "t(" src/alfred/plugins/comms_runner.py`).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "$(cat <<'EOF'
ci(comms): gate inbound_disposition.py at per-file 100% coverage (Spec B G6-7-2, #309)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Self-review checklist (run after implementation, before /review-pr)

1. **Spec coverage:** injectable disposition (Tasks 1-2) ✓; session-dispatch default (Task 1) ✓; behaviour-preserving / byte-for-byte gate (Task 2 Step 4 + Task 3) ✓; carry-item structural-error redaction (Task 0) ✓.
2. **Placeholder scan:** the two `<<< verbatim body >>>` markers in Task 1 Step 3 are MOVE instructions, not placeholders — the source is `comms_runner.py:790-951`; the engineer copies it verbatim with the documented substitutions. No `extra="forbid"` model changed.
3. **Type consistency:** `InboundDisposition.dispatch(self, method: str, params: object, *, wire_seq: int | None = None)` is the single signature used by the Protocol, the default, the delegator, and the spy. `SessionDispatchDisposition.__init__` kwargs match the runner's default-construction call exactly.
4. **No new trust surface:** the credential/audit/T3 handling is MOVED, not changed; `_route_transport_crash` + `_request_restart` stay on the runner; no secrets/T3 in logs; `extra="forbid"` preserved.
5. **Import cycle:** `inbound_disposition` ← `comms_runner` only (one direction). Verified `session.py` does not import `inbound_disposition`.

## After all tasks green

1. Run the self-review checklist above.
2. FULL `/review-pr` fleet (ALL always-include reviewers + the comms/core conditional engineers) — NOT a scoped subset.
3. Fold findings.
4. `alfred-uat` (API-contract UAT for this pure-refactor/data slice) with the PR number + an acceptance brief.
5. Push → CodeRabbit cloud → merge (`gh pr merge --rebase`). NEVER `--admin`/`--no-verify`.
6. Record the merge to memory.
