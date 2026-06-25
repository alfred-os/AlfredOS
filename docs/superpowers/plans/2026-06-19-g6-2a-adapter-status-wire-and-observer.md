# G6-2a — Adapter-status wire models + core-side status observer/auditor

- **Issue:** #288
- **Spec:** [`docs/superpowers/specs/2026-06-18-spec-b-adapter-inversion-design.md`](../specs/2026-06-18-spec-b-adapter-inversion-design.md) — §3 (status notifications + the G3 anti-forgery lesson), §4 (core-side adapter-status observer/auditor), §6 (audit non-skippable; a malformed/forged status frame is never silently dropped — it is refused, audited, triggers link scrutiny), §9 (G6-2 row).
- **Status:** Plan draft — not yet plan-reviewed, not yet implemented.

## Goal

Ship the **first half** of the Spec B §9 G6-2 row in isolation: the `gateway.adapter.{up,down,crashed,breaker_open}` **status-notification wire models** (Pydantic, frozen, `extra="forbid"`, closed-vocab `adapter_id`, epoch on the liveness-asserting `up` frame) **plus** the **core-side adapter-status observer/auditor** that consumes them, Pydantic-validates, **epoch-reconciles**, writes one audit row per transition, surfaces the latest per-adapter status for a future `alfred status`, and **refuses forged / malformed / epoch-mismatched frames LOUDLY** (audited, never silent-drop).

This is the **"core observes" contract, in isolation** — exercised by a **fake gateway emitting synthetic frames**. The observer is a **standalone validated consumer** with non-skipped unit tests; its forgery/malformed/epoch-mismatch refusal is pure validation logic that needs no root, so it runs on the required unit job (closing the G2/#245 paper-gate hazard at the source).

### What this is NOT (deferred — see the Scope-boundary note)

`GatewayAdapterSupervisor`, the per-adapter lifecycle machine, relocating `CommsPluginRunner`/`CommsStdioTransport` into the gateway host role, spawn / handshake / crash / backoff / breaker mechanics, and per-adapter metrics are **G6-2b**. The credential round-trip is **G6-3**. The ingress gate, leg scheduler, per-leg `ReplayBuffer`, and global aggregate cap are **G6-4**. The real Discord flag-day (Compose service deletion, secret relocation, the live gateway→core status leg wiring + the gateway-side emitters) is **G6-5**. The adversarial corpus is **G6-6**.

**Live wiring of the gateway→core status leg rides G6-2b** (the supervisor is the producer of these frames; until it exists there is no on-the-wire emitter). G6-2a therefore wires the observer into the daemon boot graph as a **constructed-but-frame-source-absent registered consumer** is **explicitly NOT done here** — instead the observer is delivered as a standalone, fully-unit-tested consumer object, and the daemon-boot wiring (`_build_comms_boot_graph`) is left untouched. This is a deliberate decision to avoid a paper gate: there is no live frame source in G6-2a, so wiring the observer into boot would create a consumer with zero exercised live path. The observer's validation/refusal IS exercised — by non-skipped unit tests against synthetic frames. The boot-graph registration lands in G6-2b alongside the supervisor that produces the frames.

## Architecture

```
[fake gateway / G6-2b real supervisor]
        │  gateway.adapter.{up,down,crashed,breaker_open}  (id-less JSON-RPC notification)
        │     up:          {adapter_id, epoch}
        │     down:        {adapter_id, reason}
        │     crashed:     {adapter_id, error_class, detail}
        │     breaker_open:{adapter_id, retry_after_seconds}
        ▼
AdapterStatusObserver.observe(method, params)          ← core-side, NEW module
        │
        ├─ Pydantic-validate params against the method's model  (extra="forbid")
        │     malformed → refuse: audit gateway.adapter.status_rejected + return (NO state change)
        ├─ epoch-reconcile (up only) against expected_epoch     (G3 anti-forgery)
        │     mismatch  → refuse: audit gateway.adapter.status_rejected + return (NO state change)
        ├─ unknown method → refuse: audit gateway.adapter.status_rejected + return
        ▼
   accept: audit gateway.adapter.{up,down,crashed,breaker_open}
        + record latest status in an in-memory per-adapter snapshot (for alfred status, G6-2b+)
```

- The **wire models** live in `src/alfred/comms_mcp/protocol.py` alongside the existing `*Notification` models (`InboundMessageNotification`, `CrashedNotification`, the `daemon.lifecycle.*` / `link.*` frames), reusing `_WireModel`, `AdapterId`, and the `ReadyNotification` 32-hex epoch rule. The four canonical wire-method-name constants live there too, next to `DAEMON_LIFECYCLE_READY` etc., so the audit-event-name == the wire-method-name by construction (the existing architect-L-1 no-drift discipline).
- The **observer** is a pure-ish stateful machine (`src/alfred/comms_mcp/adapter_status_observer.py`): one public coroutine `observe(method, params)` that validates → reconciles → audits → records. It takes an injected `AuditWriter`, an injected `expected_epoch` provider, and a fake-clock-free monotonic timestamp source (UTC `datetime` via an injected `now` callable, default `lambda: datetime.now(UTC)`), mirroring the existing emit-site `occurred_at` convention.
- The **audit field-set constants** live in `src/alfred/audit/audit_row_schemas.py` (the `Slice-4`/Spec-B block), one per accepted transition + one for the rejection, consumed via `AuditWriter.append_schema`.
- **i18n**: any operator-facing string (the rejection log subject is structured, NOT operator-facing; the only `t()` need is the reason text surfaced for a future `alfred status` line and the rejection's operator-facing reason) routes through `t()`. New keys land in the catalog + a Spec-B reserve file mirroring `_slice_4_reserve.py`, and are pinned by a catalog test.

## Tech stack

- Pydantic v2 (`ConfigDict(frozen=True, extra="forbid")`, `Literal` closed vocab, `Field` constraints, `model_validate`, `ValidationError`).
- `pytest` (+ `pytest.raises` / structured-subject assertions); no testcontainers needed — the observer takes a fake `AuditWriter` capturing appended rows. No root, no launcher, no bwrap → runs on the **required non-root unit job**.
- `structlog` for the loud-refuse log line (no T3, no raw wire field echoed in the message body — method name + structured fields only, mirroring `core_link._consume_ready`).
- `alfred.i18n.t` + `pybabel extract/update/compile --check`.
- `mypy --strict` + `pyright` + `ruff check`/`ruff format`.

## File structure

**New files:**

- `src/alfred/comms_mcp/adapter_status_observer.py` — the `AdapterStatusObserver` class + `AdapterStatusSnapshot` frozen record + `AdapterStatusRejected` typed error / refusal-reason `Literal`.
- `src/alfred/i18n/_spec_b_reserve.py` — pybabel reservation for the new Spec-B `gateway.adapter.*` operator-facing keys (mirror of `_slice_4_reserve.py`).
- `tests/unit/comms_mcp/test_adapter_status_models.py` — wire-model encode/validate + `extra="forbid"` + closed-vocab + epoch-format tests.
- `tests/unit/comms_mcp/test_adapter_status_observer.py` — happy-path-per-transition + malformed-refusal + epoch-mismatch-refusal + unknown-method-refusal + snapshot-record tests.
- `tests/unit/test_catalog_spec_b_keys.py` — every Spec-B `t()` key resolves to a non-bare value (mirror of `test_catalog_slice_4_keys.py`).

**Modified files:**

- `src/alfred/comms_mcp/protocol.py` — add the four status models + the four wire-method-name constants + `__all__` entries.
- `src/alfred/audit/audit_row_schemas.py` — add the five field-set constants (four accepted + one rejected) in the Spec-B block.
- `locale/en/LC_MESSAGES/alfred.po` (+ compiled `alfred.mo`) — the new `gateway.adapter.*` operator-facing keys.

**Untouched (deliberately — deferred to G6-2b):** `src/alfred/cli/daemon/_commands.py` (`_build_comms_boot_graph`), `src/alfred/gateway/*` (the producer side), `src/alfred/cli/gateway/*` (the `alfred status` surface).

---

## Task 1 — Status wire models + method-name constants (the wire contract)

**Files:** `src/alfred/comms_mcp/protocol.py`, `tests/unit/comms_mcp/test_adapter_status_models.py`.

### 1a. Write the failing test

Create `tests/unit/comms_mcp/test_adapter_status_models.py`:

```python
"""G6-2a (#288): gateway.adapter.* status wire models.

These are the gateway -> core adapter-status notifications (Spec B §3). They
mirror the existing comms_mcp wire discipline: frozen, ``extra="forbid"``,
closed-vocab ``adapter_id``, and the ``ReadyNotification`` 32-hex epoch rule on
the liveness-asserting ``up`` frame. A typo'd or smuggled wire field is a loud
``ValidationError`` here, at the boundary — never silent drift.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_BREAKER_OPEN,
    GATEWAY_ADAPTER_CRASHED,
    GATEWAY_ADAPTER_DOWN,
    GATEWAY_ADAPTER_UP,
    AdapterBreakerOpenNotification,
    AdapterCrashedNotification,
    AdapterDownNotification,
    AdapterUpNotification,
)

_EPOCH = "0" * 32  # 32 lowercase hex chars — the ReadyNotification rule.


def test_method_name_constants_are_canonical() -> None:
    assert GATEWAY_ADAPTER_UP == "gateway.adapter.up"
    assert GATEWAY_ADAPTER_DOWN == "gateway.adapter.down"
    assert GATEWAY_ADAPTER_CRASHED == "gateway.adapter.crashed"
    assert GATEWAY_ADAPTER_BREAKER_OPEN == "gateway.adapter.breaker_open"


def test_up_accepts_known_adapter_and_valid_epoch() -> None:
    model = AdapterUpNotification(adapter_id="discord", epoch=_EPOCH)
    assert model.adapter_id == "discord"
    assert model.epoch == _EPOCH


def test_up_rejects_unknown_adapter_kind() -> None:
    with pytest.raises(ValidationError):
        AdapterUpNotification(adapter_id="telegram", epoch=_EPOCH)


def test_up_rejects_malformed_epoch() -> None:
    for bad in ("", "Z" * 32, "0" * 31, "0" * 33, "00FF" + "0" * 28):
        with pytest.raises(ValidationError):
            AdapterUpNotification(adapter_id="discord", epoch=bad)


def test_models_are_frozen_and_forbid_extra() -> None:
    up = AdapterUpNotification(adapter_id="discord", epoch=_EPOCH)
    with pytest.raises(ValidationError):
        up.adapter_id = "tui"  # type: ignore[misc]  # frozen
    with pytest.raises(ValidationError):
        AdapterUpNotification(adapter_id="discord", epoch=_EPOCH, smuggled="x")  # type: ignore[call-arg]


def test_down_carries_closed_reason_vocab() -> None:
    model = AdapterDownNotification(adapter_id="discord", reason="operator")
    assert model.reason == "operator"
    with pytest.raises(ValidationError):
        AdapterDownNotification(adapter_id="discord", reason="meltdown")  # type: ignore[arg-type]


def test_crashed_requires_nonempty_error_class() -> None:
    AdapterCrashedNotification(adapter_id="discord", error_class="RuntimeError", detail="")
    with pytest.raises(ValidationError):
        AdapterCrashedNotification(adapter_id="discord", error_class="", detail="x")


def test_breaker_open_requires_nonnegative_retry() -> None:
    AdapterBreakerOpenNotification(adapter_id="discord", retry_after_seconds=0)
    with pytest.raises(ValidationError):
        AdapterBreakerOpenNotification(adapter_id="discord", retry_after_seconds=-1)
```

### 1b. Run to fail

```
uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py -q
```

Expected: `ImportError: cannot import name 'GATEWAY_ADAPTER_UP' from 'alfred.comms_mcp.protocol'` (collection error) — the symbols do not exist yet.

### 1c. Minimal implementation

In `src/alfred/comms_mcp/protocol.py`, after the `CrashedNotification` class (the plugin→host notifications block, ~L383) and **before** the host→outward lifecycle block, add:

```python
# ---------------------------------------------------------------------------
# Gateway -> core adapter-status notifications (Spec B G6-2a / #288 / ADR-0036)
#
# DIRECTION: gateway -> core. The gateway (the adapter child's supervising
# parent, Spec B) OBSERVES the adapter lifecycle and reports each transition to
# the core as an id-less notification. The core never COMMANDS the lifecycle; it
# consumes these via ``AdapterStatusObserver`` (adapter_status_observer.py),
# Pydantic-validates, epoch-reconciles, and audits. The PRODUCER (the
# GatewayAdapterSupervisor) + the live wire leg land in G6-2b; G6-2a ships ONLY
# the wire contract + the core-side consumer, exercised against synthetic frames.
#
# ANTI-FORGERY (Spec B §3, the G3 lesson): never trust a raw frame. ``up``
# asserts liveness, so it carries the per-core-boot ``epoch`` (same 32-hex rule
# as ``ReadyNotification``); the observer rejects an ``up`` whose epoch != the
# core's expected epoch — a forged ``up`` while dark is a false-liveness attack.
# Every model is frozen + ``extra="forbid"`` + closed-vocab ``adapter_id``, so a
# forged/typo'd field is a loud ValidationError at the boundary, never a silent
# state change. These frames carry NO T3 message body — only non-secret
# supervision metadata (adapter_id, epoch, closed-vocab reason, error class).
# ---------------------------------------------------------------------------

GATEWAY_ADAPTER_UP: Final[str] = "gateway.adapter.up"
GATEWAY_ADAPTER_DOWN: Final[str] = "gateway.adapter.down"
GATEWAY_ADAPTER_CRASHED: Final[str] = "gateway.adapter.crashed"
GATEWAY_ADAPTER_BREAKER_OPEN: Final[str] = "gateway.adapter.breaker_open"

AdapterDownReason = Literal["operator", "supervisor", "config_reload", "shutdown"]
"""Closed vocabulary for a planned/observed adapter-down transition.

Mirrors ``LifecycleStopRequest.reason`` (the host-side stop reasons) so the
down-notification's reason and the stop request's reason share one vocabulary.
A crash is NOT a down — it is the distinct ``gateway.adapter.crashed`` frame.
"""


class AdapterUpNotification(_WireModel):
    """Gateway->core: an adapter reached the ``up`` (serving) state.

    Carries the per-core-boot ``epoch`` (same 32-hex rule as
    :class:`ReadyNotification`) so the observer can reject a false-liveness
    forgery (an ``up`` asserted against a stale/foreign epoch). ``up`` is the
    only status frame that asserts liveness, so it is the only one epoch-bound.
    """

    adapter_id: AdapterId
    epoch: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")


class AdapterDownNotification(_WireModel):
    """Gateway->core: an adapter left the serving state for a known reason."""

    adapter_id: AdapterId
    reason: AdapterDownReason


class AdapterCrashedNotification(_WireModel):
    """Gateway->core: the gateway observed the adapter child process exit.

    This is the gateway's PROCESS-level crash signal (authoritative for
    host-supervision/audit, Spec B §3) — distinct from the in-child
    :class:`CrashedNotification` (the adapter's own code-level error). ``detail``
    is redacted by the gateway before it crosses the wire; the core re-scrubs it
    before any audit row carries it (mirrors :class:`CrashedNotification`).
    """

    adapter_id: AdapterId
    error_class: str = Field(min_length=1)
    detail: str


class AdapterBreakerOpenNotification(_WireModel):
    """Gateway->core: the gateway opened the per-adapter circuit breaker."""

    adapter_id: AdapterId
    retry_after_seconds: int = Field(ge=0)
```

Add the four constants and four class names to `__all__` (keep its existing sorted-ish ordering: constants block, then class block).

### 1d. Run to pass

```
uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py -q
```

Expected: all tests pass.

### 1e. Commit

```
feat(comms): gateway.adapter.* status wire models + method-name constants (#288)

Spec B §3 G6-2a: the four gateway->core adapter-status notifications
(up/down/crashed/breaker_open), frozen + extra="forbid" + closed-vocab
adapter_id, with the ReadyNotification 32-hex epoch rule on the
liveness-asserting `up` frame. Wire contract only; the producer + live leg
land in G6-2b.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
```

---

## Task 2 — Audit field-set constants for each transition + the rejection

**Files:** `src/alfred/audit/audit_row_schemas.py`, `tests/unit/comms_mcp/test_adapter_status_observer.py` (the audit-schema assertions land here in Task 3; this task adds the constants + a focused constants test).

### 2a. Write the failing test

Append to `tests/unit/comms_mcp/test_adapter_status_models.py` (the constants are wire-contract-adjacent; keep them in the same suite):

```python
def test_status_audit_field_sets_exist_and_carry_join_keys() -> None:
    from alfred.audit.audit_row_schemas import (
        GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS,
        GATEWAY_ADAPTER_CRASHED_FIELDS,
        GATEWAY_ADAPTER_DOWN_FIELDS,
        GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS,
        GATEWAY_ADAPTER_UP_FIELDS,
    )

    # Every accepted-transition row joins on adapter_id + occurred_at.
    for fields in (
        GATEWAY_ADAPTER_UP_FIELDS,
        GATEWAY_ADAPTER_DOWN_FIELDS,
        GATEWAY_ADAPTER_CRASHED_FIELDS,
        GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS,
    ):
        assert "adapter_id" in fields
        assert "occurred_at" in fields

    assert GATEWAY_ADAPTER_UP_FIELDS == frozenset({"adapter_id", "epoch", "occurred_at"})
    assert GATEWAY_ADAPTER_DOWN_FIELDS == frozenset({"adapter_id", "reason", "occurred_at"})
    assert GATEWAY_ADAPTER_CRASHED_FIELDS == frozenset(
        {"adapter_id", "error_class", "detail_redacted", "occurred_at"}
    )
    assert GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS == frozenset(
        {"adapter_id", "retry_after_seconds", "occurred_at"}
    )
    # The rejection row never carries the raw frame — only a closed-vocab reason
    # + the method that was refused + the observed adapter_id ("" when unparseable).
    assert GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS == frozenset(
        {"adapter_id", "rejected_method", "rejection_reason", "occurred_at"}
    )
```

### 2b. Run to fail

```
uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py::test_status_audit_field_sets_exist_and_carry_join_keys -q
```

Expected: `ImportError: cannot import name 'GATEWAY_ADAPTER_UP_FIELDS' from 'alfred.audit.audit_row_schemas'`.

### 2c. Minimal implementation

In `src/alfred/audit/audit_row_schemas.py`, in the Slice-4/Spec-B block (after `COMMS_SOCKET_PEER_REJECTED_FIELDS`, ~L749), add:

```python
# ---------------------------------------------------------------------------
# gateway.adapter.* status family (Spec B G6-2a / #288 / ADR-0036)
# ---------------------------------------------------------------------------
#
# The core-side AdapterStatusObserver writes ONE audit row per ACCEPTED status
# transition the gateway reports, plus a ``status_rejected`` row on every
# refused frame (malformed / forged-epoch / unknown-method). A malformed/forged
# status frame is NEVER silently dropped (Spec B §6) — the rejection row is the
# loud audit. The producer (GatewayAdapterSupervisor) + the live wire leg land in
# G6-2b; these constants ship now so the observer is fully testable in isolation.
#
# ``adapter_id`` is the closed-vocab adapter kind (the join key). ``occurred_at``
# is the observer's UTC ISO timestamp. ``crashed.detail`` is RE-SCRUBBED by the
# observer before it lands as ``detail_redacted`` (the wire ``detail`` is never
# persisted raw — sec discipline mirrors the proposal-dispatch redaction family).
# The rejection row carries NO raw frame field — only the refused method, a
# closed-vocab reason, and the observed ``adapter_id`` ("" when it could not be
# parsed) — so a forged frame can never smuggle bytes into the audit log.

GATEWAY_ADAPTER_UP_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "epoch",
        "occurred_at",
    }
)

GATEWAY_ADAPTER_DOWN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "reason",
        "occurred_at",
    }
)

GATEWAY_ADAPTER_CRASHED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "error_class",
        "detail_redacted",
        "occurred_at",
    }
)

GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "retry_after_seconds",
        "occurred_at",
    }
)

GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # The observed adapter_id; "" when the frame was unparseable (so a forged
        # adapter kind cannot be persisted as if it were a known one).
        "adapter_id",
        # The wire method that was refused (gateway.adapter.* or an unknown string).
        "rejected_method",
        # Closed-vocab rejection reason (see AdapterStatusObserver._RejectionReason).
        "rejection_reason",
        "occurred_at",
    }
)
```

If `audit_row_schemas.py` has an `__all__`, add the five names; otherwise they are module-level `Final` constants imported by name (the file's convention — confirm at implementation time and match it).

### 2d. Run to pass

```
uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py::test_status_audit_field_sets_exist_and_carry_join_keys -q
```

Expected: pass.

### 2e. Commit

```
feat(audit): gateway.adapter.* status + status_rejected audit field-sets (#288)

Spec B §6 G6-2a: five Final[frozenset[str]] field-sets the core-side
AdapterStatusObserver writes — one per accepted transition
(up/down/crashed/breaker_open) plus status_rejected for every refused frame.
The rejection row carries no raw frame bytes; crashed.detail lands re-scrubbed
as detail_redacted.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
```

---

## Task 3 — Core-side `AdapterStatusObserver` (validate → reconcile → audit → record)

**Files:** `src/alfred/comms_mcp/adapter_status_observer.py`, `tests/unit/comms_mcp/test_adapter_status_observer.py`.

This is the **security boundary**. Happy + malformed-refusal + epoch-mismatch-refusal + unknown-method-refusal are mandatory first-class tests with real assertions.

### 3a. Write the failing test

Create `tests/unit/comms_mcp/test_adapter_status_observer.py`:

```python
"""G6-2a (#288): core-side adapter-status observer/auditor (Spec B §4/§6).

The observer is the core's consumer of the gateway's ``gateway.adapter.*``
status notifications. It Pydantic-validates each frame, epoch-reconciles ``up``
(the G3 anti-forgery lesson), writes one audit row per ACCEPTED transition, and
records the latest per-adapter status for ``alfred status``. A malformed /
forged-epoch / unknown-method frame is REFUSED LOUDLY — audited as
``gateway.adapter.status_rejected``, never silently dropped (Spec B §6).

These tests drive a FAKE gateway: synthetic frame dicts straight into
``observe``. No root, no launcher, no bwrap — they run on the required non-root
unit job, so the forgery-refusal contract is gated, not skipped (G2/#245
paper-gate lesson).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.adapter_status_observer import (
    AdapterStatusObserver,
    AdapterStatusSnapshot,
)

_EPOCH = "a" * 32
_OTHER_EPOCH = "b" * 32
_FIXED_NOW = datetime(2026, 6, 19, 12, 0, 0, tzinfo=UTC)


class _FakeAudit:
    """Captures append_schema calls so tests assert the audited contract."""

    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))


def _make_observer(audit: _FakeAudit) -> AdapterStatusObserver:
    return AdapterStatusObserver(
        audit=audit,  # type: ignore[arg-type]  # structural _AuditWriterLike
        expected_epoch=lambda: _EPOCH,
        now=lambda: _FIXED_NOW,
    )


@pytest.mark.asyncio
async def test_up_with_matching_epoch_is_accepted_and_audited() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    await obs.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH})

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.up"
    assert row["schema_name"] == "GATEWAY_ADAPTER_UP_FIELDS"
    assert row["result"] == "success"
    assert row["subject"] == {
        "adapter_id": "discord",
        "epoch": _EPOCH,
        "occurred_at": _FIXED_NOW.isoformat(),
    }
    snap = obs.latest("discord")
    assert isinstance(snap, AdapterStatusSnapshot)
    assert snap.state == "up"


@pytest.mark.asyncio
async def test_down_crashed_breaker_open_each_audit_their_family() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    await obs.observe("gateway.adapter.down", {"adapter_id": "discord", "reason": "operator"})
    await obs.observe(
        "gateway.adapter.crashed",
        {"adapter_id": "discord", "error_class": "RuntimeError", "detail": "boom"},
    )
    await obs.observe(
        "gateway.adapter.breaker_open",
        {"adapter_id": "discord", "retry_after_seconds": 30},
    )

    events = [r["event"] for r in audit.rows]
    assert events == [
        "gateway.adapter.down",
        "gateway.adapter.crashed",
        "gateway.adapter.breaker_open",
    ]
    crashed = audit.rows[1]["subject"]
    assert "detail" not in crashed  # raw wire field never persisted
    assert "detail_redacted" in crashed
    assert obs.latest("discord").state == "breaker_open"


@pytest.mark.asyncio
async def test_malformed_frame_is_refused_and_audited_not_dropped() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    # Missing required ``epoch`` for ``up``.
    await obs.observe("gateway.adapter.up", {"adapter_id": "discord"})

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.status_rejected"
    assert row["schema_name"] == "GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS"
    assert row["result"] == "refused"
    assert row["subject"]["rejection_reason"] == "malformed_frame"
    assert row["subject"]["rejected_method"] == "gateway.adapter.up"
    # No accepted state recorded for a refused frame.
    assert obs.latest("discord") is None


@pytest.mark.asyncio
async def test_forged_epoch_up_is_refused_and_audited() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    # Well-formed frame, but the epoch is a different (stale/foreign) core boot.
    await obs.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _OTHER_EPOCH})

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.status_rejected"
    assert row["result"] == "refused"
    assert row["subject"]["rejection_reason"] == "epoch_mismatch"
    assert row["subject"]["adapter_id"] == "discord"
    # The forged liveness assertion did NOT mark the adapter up.
    assert obs.latest("discord") is None


@pytest.mark.asyncio
async def test_unknown_method_is_refused_and_audited() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    await obs.observe("gateway.adapter.teleport", {"adapter_id": "discord"})

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.status_rejected"
    assert row["subject"]["rejection_reason"] == "unknown_method"
    assert row["subject"]["rejected_method"] == "gateway.adapter.teleport"
    # Unparseable adapter kind is recorded as "" — never as a known kind.
    assert row["subject"]["adapter_id"] == ""


@pytest.mark.asyncio
async def test_unknown_adapter_kind_in_known_method_is_malformed_refusal() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    # "telegram" is not in adapter_kind for this build → AdapterId rejects it.
    await obs.observe("gateway.adapter.up", {"adapter_id": "telegram", "epoch": _EPOCH})

    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.status_rejected"
    assert row["subject"]["rejection_reason"] == "malformed_frame"
    # adapter_id could not be validated → "" in the audit row.
    assert row["subject"]["adapter_id"] == ""
```

### 3b. Run to fail

```
uv run pytest tests/unit/comms_mcp/test_adapter_status_observer.py -q
```

Expected: `ModuleNotFoundError: No module named 'alfred.comms_mcp.adapter_status_observer'`.

### 3c. Minimal implementation

Create `src/alfred/comms_mcp/adapter_status_observer.py`:

```python
"""Core-side observer/auditor for gateway-reported adapter status (Spec B §4/§6).

The gateway is the adapter child's supervising parent (Spec B); it OBSERVES the
adapter lifecycle and reports each transition to the core as a
``gateway.adapter.*`` notification. The core never COMMANDS the lifecycle — it
consumes these here, Pydantic-validates, epoch-reconciles ``up`` (the G3
anti-forgery lesson: never trust a raw frame; a forged ``up`` while dark is a
false-liveness attack), writes one audit row per ACCEPTED transition, and
records the latest per-adapter status for ``alfred status``.

A malformed / forged-epoch / unknown-method frame is REFUSED LOUDLY — audited as
``gateway.adapter.status_rejected``, never silently dropped (Spec B §6,
CLAUDE.md hard rule #7). The rejection row carries NO raw frame field.

G6-2a ships this consumer in ISOLATION, exercised against synthetic frames. The
PRODUCER (GatewayAdapterSupervisor) + the live gateway->core status leg + the
daemon-boot registration land in G6-2b.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal, Protocol

import structlog
from pydantic import ValidationError

from alfred.audit.audit_row_schemas import (
    GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS,
    GATEWAY_ADAPTER_CRASHED_FIELDS,
    GATEWAY_ADAPTER_DOWN_FIELDS,
    GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS,
    GATEWAY_ADAPTER_UP_FIELDS,
)
from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_BREAKER_OPEN,
    GATEWAY_ADAPTER_CRASHED,
    GATEWAY_ADAPTER_DOWN,
    GATEWAY_ADAPTER_UP,
    AdapterBreakerOpenNotification,
    AdapterCrashedNotification,
    AdapterDownNotification,
    AdapterUpNotification,
)
from alfred.security.redaction import scrub  # confirm the canonical scrubber name at impl time

log = structlog.get_logger(__name__)

AdapterState = Literal["up", "down", "crashed", "breaker_open"]
_RejectionReason = Literal["malformed_frame", "epoch_mismatch", "unknown_method"]


class _AuditWriterLike(Protocol):
    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, object],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class AdapterStatusSnapshot:
    """The latest observed status for one adapter (for ``alfred status``)."""

    adapter_id: str
    state: AdapterState
    occurred_at: datetime


# The transition family is fully described by (model, audit-fields, schema-name).
_TRANSITIONS: Final[
    Mapping[str, tuple[type, frozenset[str], str, AdapterState]]
] = {
    GATEWAY_ADAPTER_UP: (AdapterUpNotification, GATEWAY_ADAPTER_UP_FIELDS, "GATEWAY_ADAPTER_UP_FIELDS", "up"),
    GATEWAY_ADAPTER_DOWN: (AdapterDownNotification, GATEWAY_ADAPTER_DOWN_FIELDS, "GATEWAY_ADAPTER_DOWN_FIELDS", "down"),
    GATEWAY_ADAPTER_CRASHED: (
        AdapterCrashedNotification,
        GATEWAY_ADAPTER_CRASHED_FIELDS,
        "GATEWAY_ADAPTER_CRASHED_FIELDS",
        "crashed",
    ),
    GATEWAY_ADAPTER_BREAKER_OPEN: (
        AdapterBreakerOpenNotification,
        GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS,
        "GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS",
        "breaker_open",
    ),
}


class AdapterStatusObserver:
    """Validate, epoch-reconcile, audit, and record gateway adapter-status frames."""

    def __init__(
        self,
        *,
        audit: _AuditWriterLike,
        expected_epoch: Callable[[], str],
        now: Callable[[], datetime],
    ) -> None:
        self._audit = audit
        self._expected_epoch = expected_epoch
        self._now = now
        self._latest: dict[str, AdapterStatusSnapshot] = {}

    def latest(self, adapter_id: str) -> AdapterStatusSnapshot | None:
        """The most recent ACCEPTED status for ``adapter_id``, or None."""
        return self._latest.get(adapter_id)

    async def observe(self, method: object, params: object) -> None:
        """Consume one gateway adapter-status frame: validate -> reconcile -> audit.

        NEVER raises on a bad frame — a malformed / forged / unknown frame is a
        loud, audited refusal, not an exception that could unwind the gateway
        link pump. The ONLY raise path is a genuine audit-write failure (which
        MUST be loud — CLAUDE.md hard rule #7 — and is the caller's to handle).
        """
        transition = _TRANSITIONS.get(method) if isinstance(method, str) else None
        if transition is None:
            await self._reject(method, "", "unknown_method")
            return

        model_cls, fields, schema_name, state = transition
        raw_params = params if isinstance(params, Mapping) else {}
        try:
            parsed = model_cls.model_validate(raw_params)
        except ValidationError:
            # No exc detail logged/persisted — it could echo a malformed wire
            # field (CLAUDE.md hard rule #5/#7). The method name is the triage key.
            await self._reject(method, "", "malformed_frame")
            return

        if isinstance(parsed, AdapterUpNotification) and parsed.epoch != self._expected_epoch():
            # THE FORGERY DEFENSE (Spec B §3, the G3 lesson): an ``up`` against a
            # stale/foreign epoch is a false-liveness assertion. Refuse — no record.
            await self._reject(method, parsed.adapter_id, "epoch_mismatch")
            return

        await self._accept(parsed, fields, schema_name, str(method), state)

    async def _accept(
        self,
        parsed: object,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        state: AdapterState,
    ) -> None:
        occurred_at = self._now()
        subject = self._subject_for(parsed, occurred_at)
        await self._audit.append_schema(
            fields=fields,
            schema_name=schema_name,
            event=event,
            actor_user_id=None,
            subject=subject,
            trust_tier_of_trigger="T1",
            result="success",
            cost_estimate_usd=0.0,
            trace_id=occurred_at.isoformat(),
        )
        adapter_id = str(subject["adapter_id"])
        self._latest[adapter_id] = AdapterStatusSnapshot(
            adapter_id=adapter_id, state=state, occurred_at=occurred_at
        )

    @staticmethod
    def _subject_for(parsed: object, occurred_at: datetime) -> dict[str, object]:
        ts = occurred_at.isoformat()
        if isinstance(parsed, AdapterUpNotification):
            return {"adapter_id": parsed.adapter_id, "epoch": parsed.epoch, "occurred_at": ts}
        if isinstance(parsed, AdapterDownNotification):
            return {"adapter_id": parsed.adapter_id, "reason": parsed.reason, "occurred_at": ts}
        if isinstance(parsed, AdapterCrashedNotification):
            # The wire ``detail`` is RE-SCRUBBED before it lands as detail_redacted;
            # the raw field is never persisted (mirrors CrashedNotification handling).
            return {
                "adapter_id": parsed.adapter_id,
                "error_class": parsed.error_class,
                "detail_redacted": scrub(parsed.detail),
                "occurred_at": ts,
            }
        if isinstance(parsed, AdapterBreakerOpenNotification):
            return {
                "adapter_id": parsed.adapter_id,
                "retry_after_seconds": parsed.retry_after_seconds,
                "occurred_at": ts,
            }
        msg = f"unhandled status model {type(parsed).__name__}"  # defensive — unreachable
        raise AssertionError(msg)

    async def _reject(
        self, method: object, adapter_id: str, reason: _RejectionReason
    ) -> None:
        occurred_at = self._now()
        log.warning(
            "gateway.adapter.status_rejected",
            rejected_method=str(method),
            rejection_reason=reason,
            adapter_id=adapter_id,
        )
        await self._audit.append_schema(
            fields=GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS,
            schema_name="GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS",
            event="gateway.adapter.status_rejected",
            actor_user_id=None,
            subject={
                "adapter_id": adapter_id,
                "rejected_method": str(method),
                "rejection_reason": reason,
                "occurred_at": occurred_at.isoformat(),
            },
            trust_tier_of_trigger="T1",
            result="refused",
            cost_estimate_usd=0.0,
            trace_id=occurred_at.isoformat(),
        )


__all__ = [
    "AdapterState",
    "AdapterStatusObserver",
    "AdapterStatusSnapshot",
]
```

**Implementation notes for the implementer:**

- Confirm the canonical redaction helper at implementation time: search `src/alfred/security/` for the scrubber the comms path already uses for `CrashedNotification.detail` (the host "re-scrubs it before any audit row carries it" per protocol.py L376-378). Use that exact symbol; do not introduce a new redactor. If the existing path scrubs via a method on a class rather than a free function, inject it as a dependency rather than importing a free `scrub`.
- Confirm the `append_schema` `trace_id`/`actor_user_id`/`trust_tier_of_trigger`/`cost_estimate_usd` argument expectations against `AuditWriter.append_schema` (src/alfred/audit/log.py L105) — the signature is fixed; the `_AuditWriterLike` Protocol must match it structurally so `mypy --strict` accepts the real writer. `trust_tier_of_trigger="T1"` is correct: these are carrier-control frames, not T3 message bodies (Spec B §6 — the gateway is payload-blind; status frames carry only supervision metadata).
- `result="refused"` must match the audit `result` CHECK vocabulary. **Verify the allowed `result` values** (memory notes a CHECK constraint: `"success"` not `"ok"`); if `"refused"` is not an allowed value, use the existing refusal value (e.g. the value `DLP_OUTBOUND_REFUSED` / `COMMS_SOCKET_PEER_REJECTED` rows use) and update the test assertion to match. This is a **precursor check the implementer MUST run** before writing the row.

### 3d. Run to pass

```
uv run pytest tests/unit/comms_mcp/test_adapter_status_observer.py -q
```

Expected: all tests pass.

### 3e. Commit

```
feat(comms): core-side AdapterStatusObserver — validate, epoch-reconcile, audit, refuse (#288)

Spec B §4/§6 G6-2a: the core consumer of gateway.adapter.* status frames.
Pydantic-validates each frame, epoch-reconciles `up` (the G3 anti-forgery
lesson), audits one row per accepted transition, records the latest per-adapter
snapshot, and refuses malformed/forged-epoch/unknown-method frames loudly
(audited gateway.adapter.status_rejected, never silently dropped). Exercised
against synthetic frames on the required non-root unit job; the producer + live
leg + boot wiring land in G6-2b.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
```

---

## Task 4 — i18n keys for the operator-facing status reasons + catalog gate

**Files:** `src/alfred/i18n/_spec_b_reserve.py`, `locale/en/LC_MESSAGES/alfred.po` (+ `alfred.mo`), `tests/unit/test_catalog_spec_b_keys.py`.

**Scope of operator-facing strings in G6-2a:** the observer's structured log + audit rows are NOT operator-facing prose (they are machine-keyed events + structured subjects, so no `t()`). The operator-facing strings are the **human-readable status-reason labels** a future `alfred status` line will render from a snapshot/rejection. To keep the i18n contract honest and avoid a later retrofit, G6-2a ships the catalog keys (the reserve pattern, mirroring `_slice_4_reserve.py`) so the strings exist + are gated now, and the `alfred status` consumer (G6-2b) calls `t()` at the render site.

The keys (closed set, one per state + one per rejection reason):

- `gateway.adapter.status.up`
- `gateway.adapter.status.down`
- `gateway.adapter.status.crashed`
- `gateway.adapter.status.breaker_open`
- `gateway.adapter.status_rejected.malformed_frame`
- `gateway.adapter.status_rejected.epoch_mismatch`
- `gateway.adapter.status_rejected.unknown_method`

### 4a. Write the failing test

Create `tests/unit/test_catalog_spec_b_keys.py`:

```python
"""Every Spec-B (#288) ``t()`` key resolves to a non-bare value.

Mirrors ``test_catalog_slice_4_keys.py``. G6-2a ships the gateway.adapter.*
operator-facing status-reason keys ahead of their G6-2b ``alfred status``
consumer; the reserve file (``alfred.i18n._spec_b_reserve``) keeps pybabel from
marking them obsolete, and this test enforces no orphan key in the catalog.
"""

from __future__ import annotations

from alfred.i18n import t

SPEC_B_KEYS: tuple[str, ...] = (
    "gateway.adapter.status.up",
    "gateway.adapter.status.down",
    "gateway.adapter.status.crashed",
    "gateway.adapter.status.breaker_open",
    "gateway.adapter.status_rejected.malformed_frame",
    "gateway.adapter.status_rejected.epoch_mismatch",
    "gateway.adapter.status_rejected.unknown_method",
)


def test_every_spec_b_key_resolves_non_bare() -> None:
    for key in SPEC_B_KEYS:
        value = t(key)
        assert value, f"{key!r} resolved to an empty string"
        assert value != key, f"{key!r} fell through to its own key (missing catalog entry)"
```

### 4b. Run to fail

```
uv run pytest tests/unit/test_catalog_spec_b_keys.py -q
```

Expected: `AssertionError: 'gateway.adapter.status.up' fell through to its own key (missing catalog entry)` — the keys are not in the catalog yet.

### 4c. Minimal implementation

Create `src/alfred/i18n/_spec_b_reserve.py` (mirror of `_slice_4_reserve.py`):

```python
"""Spec-B (#288) catalog-key reservation.

G6-2a ships the ``gateway.adapter.*`` operator-facing status-reason keys ahead
of their G6-2b ``alfred status`` consumer. Without this reservation,
``pybabel extract`` sees no source reference for the new msgids and marks them
obsolete on the next ``pybabel update``, tripping the CI ``i18n catalog drift``
gate. Each ``t(...)`` here is a static reference Babel extracts; ``_register``
is never called at runtime. Follows the ``_slice_4_reserve`` pattern.
"""

from __future__ import annotations

from alfred.i18n import t


def _register() -> None:
    """Reference every Spec-B catalog key so pybabel sees them as used."""
    # Adapter status labels (G6-2b alfred status render site).
    t("gateway.adapter.status.up")
    t("gateway.adapter.status.down")
    t("gateway.adapter.status.crashed")
    t("gateway.adapter.status.breaker_open")
    # Adapter status-rejection reasons (G6-2a observer refusal; G6-2b surfaced).
    t("gateway.adapter.status_rejected.malformed_frame")
    t("gateway.adapter.status_rejected.epoch_mismatch")
    t("gateway.adapter.status_rejected.unknown_method")
```

Then add the msgids to `locale/en/LC_MESSAGES/alfred.po` via the established workflow (do NOT hand-edit raw — use pybabel, preserving the header per the memory note: never `--omit-header`):

```
uv run pybabel extract -F babel.cfg -k t -o locale/alfred.pot src/alfred
uv run pybabel update -i locale/alfred.pot -d locale --no-fuzzy-matching
```

Then fill the seven `msgstr` English values in `locale/en/LC_MESSAGES/alfred.po`, e.g.:

```
msgid "gateway.adapter.status.up"
msgstr "up"

msgid "gateway.adapter.status.down"
msgstr "down"

msgid "gateway.adapter.status.crashed"
msgstr "crashed"

msgid "gateway.adapter.status.breaker_open"
msgstr "circuit breaker open"

msgid "gateway.adapter.status_rejected.malformed_frame"
msgstr "rejected: malformed status frame"

msgid "gateway.adapter.status_rejected.epoch_mismatch"
msgstr "rejected: status frame epoch mismatch (possible forgery)"

msgid "gateway.adapter.status_rejected.unknown_method"
msgstr "rejected: unknown status method"
```

Compile:

```
uv run pybabel compile -d locale
```

**Implementer note:** confirm the exact `locale/` layout + the `pybabel` invocation the repo's pre-commit/CI uses (`.pre-commit-config.yaml` + the `i18n catalog drift` CI gate). The commands above match `babel.cfg` (`keywords = t`, `**.py` pattern) and the memory note on header preservation; reconcile with the actual pre-commit hook before running.

### 4d. Run to pass

```
uv run pytest tests/unit/test_catalog_spec_b_keys.py -q
uv run pybabel compile --check -d locale   # the CI drift gate's check form
```

Expected: the catalog test passes; the compile-check reports no drift.

### 4e. Commit

```
feat(i18n): gateway.adapter.* status-reason catalog keys + Spec-B reserve (#288)

Spec B G6-2a: the operator-facing status + status-rejection reason keys the
G6-2b `alfred status` consumer will render through t(). Reserve file mirrors
_slice_4_reserve so pybabel does not orphan them; test_catalog_spec_b_keys gates
no-orphan-key.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
```

---

## Task 5 — Full quality gate + self-review pass

**No new code.** Run the complete gate and fix any mechanical breakage before the PR.

### 5a. Run the gates

```
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py tests/unit/comms_mcp/test_adapter_status_observer.py tests/unit/test_catalog_spec_b_keys.py -q
uv run pytest tests/unit -q   # full unit suite — the required non-root job
```

Expected: all green. The observer's forgery/malformed/epoch-mismatch tests are in `tests/unit` (no root, no skipif) → the trust-boundary contract is gated, not skipped.

### 5b. Confirm the catalog test floor (if the repo gates Spec-B keys centrally)

If a central catalog test (like `test_catalog_slice_4_keys.py`) is the canonical gate rather than a per-spec file, fold `SPEC_B_KEYS` into it instead of `tests/unit/test_catalog_spec_b_keys.py` — confirm which at implementation time and match the repo convention (do not create a parallel gate if the existing one is meant to grow).

### 5c. Commit (only if 5a/5b required a mechanical fix)

```
chore(comms): mypy/ruff/catalog reconciliation for G6-2a status observer (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
```

---

## Self-review

### Spec coverage (Spec B §3, §4, §6, §9 G6-2 first half)

- **§3 status notifications `gateway.adapter.{up,down,crashed,breaker_open}`, Pydantic-validated core-side** → Task 1 (models) + Task 3 (observer validates). ✅
- **§3 the G3 anti-forgery lesson ("a forged 'up' must be refused")** → Task 1 (`up` carries the 32-hex epoch) + Task 3 (`epoch_mismatch` refusal + `test_forged_epoch_up_is_refused_and_audited`). ✅
- **§4 core-side adapter-status observer/auditor (new)** → Task 3 (`AdapterStatusObserver`, new module). ✅
- **§4 "surfaces the status (for `alfred status` later)"** → Task 3 (`latest()` + `AdapterStatusSnapshot`); the render site is G6-2b. ✅ (snapshot recorded; render deferred, stated.)
- **§6 audit non-skippable; malformed/forged never silently dropped — refused, audited, triggers link scrutiny** → Task 2 (`status_rejected` field-set) + Task 3 (every refusal path audits + logs `warning`; `test_malformed_frame_is_refused_and_audited_not_dropped`). "Triggers link scrutiny" beyond the loud audit + metric is a supervisor behavior → G6-2b (the supervisor consumes the observer); the audit-and-loud-log obligation is met here. ✅ (stated boundary.)
- **§9 G6-2 row, first half = wire contract + core-side consumer** → all four tasks; supervisor/lifecycle/relocation/metrics deferred. ✅

### Placeholder scan

No `TBD`, no `...` stub bodies (the Protocol `...` is a method signature, not a placeholder), no `pass`-only refusal paths, no fabricated symbol that the implementer cannot resolve. Two explicit **implementer precursor checks** are flagged inline (the redaction-helper symbol; the audit `result` CHECK vocabulary) rather than guessed — these are verifications, not placeholders.

### Type / name consistency

- Wire models: `AdapterUpNotification` / `AdapterDownNotification` / `AdapterCrashedNotification` / `AdapterBreakerOpenNotification` — consistent across Tasks 1, 3, and tests.
- Method constants: `GATEWAY_ADAPTER_{UP,DOWN,CRASHED,BREAKER_OPEN}` — consistent across protocol.py, observer, and `_TRANSITIONS`.
- Field-set constants: `GATEWAY_ADAPTER_{UP,DOWN,CRASHED,BREAKER_OPEN}_FIELDS` + `GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS` — consistent across Task 2, the observer, and the model test.
- Audit `event` == wire-method string == catalog-key stem `gateway.adapter.*` — no drift by construction (mirrors the existing `DAEMON_LIFECYCLE_READY` discipline).
- Rejection reasons `malformed_frame` / `epoch_mismatch` / `unknown_method` — consistent across `_RejectionReason`, the catalog keys, and the observer tests.
- `AdapterDownReason` reuses the `LifecycleStopRequest.reason` vocabulary (`operator`/`supervisor`/`config_reload`/`shutdown`) — one vocabulary, no divergence.
- `crashed` persists `detail_redacted` (never raw `detail`) — consistent between Task 2 field-set, Task 3 `_subject_for`, and the observer test.

### Paper-gate guard (the G2/#245 lesson)

The observer's validation/refusal contract is **pure validation logic** (no root, no launcher, no bwrap) and lives in `tests/unit/` with **no `skipif`** → it runs on the required non-root unit job. The forgery-refusal property is therefore **gated, not green-because-skipped**. This is the explicit reason G6-2a does **not** wire the observer into the daemon boot graph (there is no live frame source yet — a boot-wired consumer with no exercised live path would be a paper gate). Live wiring lands in G6-2b with the producing supervisor.

## Scope-boundary note (what is deferred)

- **G6-2b (the next PR):** `GatewayAdapterSupervisor`; the per-adapter lifecycle state machine; relocating/sharing `CommsPluginRunner` + `CommsStdioTransport` into the gateway host role; spawn / handshake / crash-detection / bounded-backoff restart / per-adapter circuit breaker; the gateway-side **emitters** of `gateway.adapter.*` frames; the **live gateway→core status leg** + the observer's **registration into the daemon boot graph** (`_build_comms_boot_graph` / the core-link consume path); per-adapter metrics; the `alfred status` **render site** that calls `t()` on the keys G6-2a reserved; "link scrutiny" escalation beyond the loud audit.
- **G6-3:** `GatewayAdapterCredentialClient` + `CoreAdapterCredentialResolver` (`spawn_request`/`spawn_grant`, fd-3 delivery, transient-hold, zero-after-write, await-core-on-outage). Not touched here.
- **G6-4:** `PerAdapterIngressGate`, `GatewayLegScheduler`, per-leg `ReplayBuffer` under the global aggregate cap, ingress back-pressure metrics. Not touched here.
- **G6-5:** the Discord flag-day (delete the Compose service, relocate the secret path, migrate the test suite, setup-script + migration runbook). Not touched here.
- **G6-6:** the adversarial corpus (incl. the release-blocking status-forgery refusal corpus entry §6(f)). G6-2a ships the **unit-level** forgery refusal; the adversarial-suite entry is G6-6.
- **ADR-0036** is authored in G6-1 (per §9); G6-2a references it but does not write it.

## Plan-review corrections (MUST apply — architect + security + test-engineer, 2026-06-19)

The plan-review fleet cleared the design (paper-gate avoidance sound, 2a/2b split sound, no blocking redesign) and resolved the precursor checks. Apply these corrections during implementation — they OVERRIDE the corresponding earlier text:

1. **Scrubber symbol + length bound (sec-2 major / TE-1 high — REAL BUG).** The Task 3c example `from alfred.security.redaction import scrub` is WRONG — that symbol does not exist. Use the canonical host-side crash-detail scrubber **`redact_secret_shapes` from `alfred.security.dlp`** (the one used at `src/alfred/comms_mcp/handlers.py:338`), and apply the SAME length bound it uses: `redact_secret_shapes(detail[:_MAX_CRASH_DETAIL_LEN])` (reuse the existing `_MAX_CRASH_DETAIL_LEN` constant — confirm its module; do NOT introduce a new bound). Unbounded attacker-controlled `detail` into an audit row is the vuln. **Add a real DLP test** in `test_adapter_status_observer.py`: put a synthetic secret shape (e.g. a fake token built from fragments per the push-protection memory rule) in `crashed.detail`, assert the persisted `detail_redacted` does NOT contain it (a no-op scrub must fail the test) AND that an over-long detail is truncated.

2. **Audit field name: `detail_redacted` — APPLIED (TE high; the original draft used `redacted_detail`).** Match the existing repo convention for the scrubbed-crash-detail field (the in-child `CrashedNotification` audit row uses `detail_redacted`). Update `GATEWAY_ADAPTER_CRASHED_FIELDS`, `_subject_for`, and the test assertions to `detail_redacted`. Keep `occurred_at` as the family-wide timestamp across all four transitions (the new `gateway.adapter.*` family is internally consistent; do NOT special-case `crashed` to `crashed_at`) — but VERIFY this doesn't collide with a differently-named existing expectation; if the audit layer expects a specific timestamp field name, match it.

3. **`trust_tier_of_trigger` (TE/sec medium).** `"T1"` diverges from the existing comms/control audit rows. Match the value the **`daemon.lifecycle.*` / `link.*` core-owned control-frame audit rows** use (these are the closest analog — core-owned supervision signals, not T3 message bodies; likely `"T0"`). Confirm the exact value at `audit_row_schemas.py` / the daemon-lifecycle emit sites and use it for ALL `gateway.adapter.*` rows (accepted + rejected).

4. **`trace_id` = `adapter_id`, not the timestamp (sec minor).** In both `_accept` and `_reject`, pass `trace_id=adapter_id` (the per-adapter correlation handle), not `occurred_at.isoformat()`. For the rejection path where `adapter_id` may be `""`, confirm the audit layer accepts an empty `trace_id` or use a sentinel; match the convention the peer-rejected row uses.

5. **Forged-downgrade / carrier-auth rationale (sec-1 major).** Keep the spec-faithful **`up`-only epoch binding** (the spec §3 states "up is the only status frame that asserts liveness, so it is the only one epoch-bound"). But the plan MUST now state explicitly — in the Architecture section, the `AdapterDownNotification`/`AdapterCrashedNotification`/`AdapterBreakerOpenNotification` docstrings, and as a one-line note flagged for an ADR-0036 follow-up annotation (ride G6-2b) — the carrier-auth posture: *the gateway→core leg's `0600` + `SO_PEERCRED` + per-boot-epoch envelope (Spec A) authenticates frame origin and anti-replays cross-boot, so the non-`up` status frames rely on the carrier for origin-auth + replay-defense; the `up` payload-epoch is the ADDITIONAL application-level false-liveness-replay defense §6(f) mandates. A forged-downgrade's blast radius is low — the core only OBSERVES (it issues no lifecycle directive), so a forged `down/crashed` mutates only the `alfred status` snapshot + an audit row, never an actuation.* Add a test docstring note that 2a's fake-gateway unit suite proves the application-level validation only; the carrier-auth of the live status leg is proven by G6-2b's live-leg integration test + the existing Spec A link-auth tests. (Do NOT epoch-bind down/crashed/breaker_open — that would deviate from the locked spec contract.)

6. **Crash de-dup correlation (arch-1 medium).** Spec §3 requires the core to de-dup the two coexisting crash signals (in-child `CrashedNotification` vs gateway `AdapterCrashedNotification`) by correlating on `adapter_id` + a host-restart sequence. This de-dup is a **core-side join owned by G6-2b** (the in-child frame arrives via the relay/session; the gateway frame via the status leg; the host-restart sequence is the 2b supervisor's per-adapter restart counter — none exist in 2a). Document this explicitly in the `AdapterCrashedNotification` docstring + the Scope-boundary note. Because 2a ships NO producer, the frozen `AdapterCrashedNotification` can be extended additively in 2b (a `host_restart_seq`/incarnation field) with zero live-contract risk if the join needs it — state this so the freeze is not mistaken for a permanent omission.

7. **Missing refusal/coverage tests (TE medium).** Add to `test_adapter_status_observer.py`: (a) `params` not a `Mapping` (e.g. a list / None) → `malformed_frame` refusal; (b) an `epoch` field smuggled onto a non-`up` frame (down/crashed/breaker_open) → `extra="forbid"` → `malformed_frame` refusal; (c) snapshot-overwrite: `up` then `down` for the same adapter → `latest()` reflects `down` (last-accepted-wins).

8. **Peer-auth deferral (arch-2 low).** State explicitly in the Scope-boundary note that the gateway→core leg's peer-auth (SO_PEERCRED / 0600) is established by Spec A and is NOT re-implemented or re-tested in 2a.

9. **Catalog reverse-drift scan (TE-6 low).** The parallel `test_catalog_spec_b_keys.py` is the right call (the slice-4 gate doesn't scan `gateway.adapter.`), but add a **reverse-drift scan** matching `test_catalog_slice_4_keys.py`'s bidirectional discipline (assert no `gateway.adapter.*`-prefixed msgid exists in the catalog that is NOT in `SPEC_B_KEYS`), so an orphaned catalog key is caught too.

## Precursor gaps / spec-code mismatches found while verifying anchors

1. **The gateway→core status leg does not exist yet.** `src/alfred/gateway/core_link.py` only consumes `daemon.lifecycle.*` from the core and sends `link.*` to the **client** — there is no gateway→core `gateway.adapter.*` emit path, and the daemon's `_build_comms_boot_graph` has no status-frame consumer. This is **expected** (the producer is G6-2b) and is why G6-2a delivers the observer as a standalone consumer rather than boot-wiring it. Stated explicitly in the plan to avoid a paper gate.
2. **Naming collision risk: `CrashedNotification` (plugin→host, in-child) vs `AdapterCrashedNotification` (gateway→core, process-level).** Spec B §3 explicitly notes "two crash signals coexist." The plan names the new model `AdapterCrashedNotification` (matching the spec's §3 vocabulary) and documents the distinction in the model docstring. The implementer must NOT rename or merge the existing `CrashedNotification`.
3. **Audit `result` CHECK vocabulary.** Project memory notes a `result` CHECK constraint (`"success"` not `"ok"`). The plan uses `result="refused"` for the rejection row and flags it as a **precursor check** in Task 3c — the implementer must confirm `"refused"` is allowed (or match the value the existing `COMMS_SOCKET_PEER_REJECTED` / `DLP_OUTBOUND_REFUSED` refusal rows use) and adjust the test assertion. The peer-rejected row (`COMMS_SOCKET_PEER_REJECTED_FIELDS`) is the closest existing analog to copy from.
4. **Redaction helper symbol unconfirmed.** protocol.py L376-378 states the host "re-scrubs" `CrashedNotification.detail` before audit, but the exact scrubber symbol/location is not pinned in the read anchors. Task 3c flags this as a **precursor check** (search `src/alfred/security/` for the existing comms-detail scrubber; reuse it, do not introduce a new one — possibly inject it rather than import a free function).
5. **Catalog location.** The `.po` is at repo-root `locale/en/LC_MESSAGES/alfred.po`, NOT under `src/alfred/`. `babel.cfg` uses `keywords = t` + `**.py`. The plan's pybabel commands match this; the implementer must reconcile with the actual pre-commit hook + the `i18n catalog drift` CI gate before running (and never `--omit-header` per the memory note).
6. **Central vs per-spec catalog test.** The repo gates Slice-4 keys via a single `test_catalog_slice_4_keys.py` with a `SLICE_4_KEYS` tuple. The plan creates a parallel `test_catalog_spec_b_keys.py` for isolation but flags (Task 5b) that folding `SPEC_B_KEYS` into the existing canonical gate may be the repo's preferred convention — confirm at implementation time.
