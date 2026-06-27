# G6-7-1 — Inbound-forward envelope model + core re-parse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **PLAN-DOC IS LOCAL/UNTRACKED.** This file lives at `docs/superpowers/plans/2026-06-21-g6-7-1-inbound-envelope-reparse.md` but MUST NEVER be `git add`-ed (it is gitignore + markdownlint-gated per the #309 plan-doc rule). Every `git add` in this plan names ONLY source / test / ci files — never this `.md`. Do not markdown-link this file from any tracked doc.

**Goal:** Ship the pure data layer of the gateway→core inbound bridge — the `gateway.adapter.inbound` Pydantic envelope model + a pure core-side re-parse function that turns an opaque T3 body blob back into the UNCHANGED `InboundMessageNotification` and enforces the envelope==body `adapter_id` equality check (the F3 mitigation's data-layer half) — with zero runtime wiring.

**Architecture:** The envelope is the gateway↔core wire contract, so it lives next to every other comms wire model in `src/alfred/comms_mcp/protocol.py` (where the existing `gateway.adapter.*` status models already live — §4 of the spec names this file). The envelope is **body-opaque**: it carries the gateway-supplied out-of-band `adapter_id` plus the T3 body as an opaque `bytes`/`str` member it NEVER introspects. The re-parse is a pure, deterministic core-side function in a new leaf module `src/alfred/comms_mcp/inbound_reparse.py`: opaque body bytes → `InboundMessageNotification.model_validate(...)`, plus a typed loud refusal when the body-derived `adapter_id` does not equal the envelope `adapter_id`, and a typed loud refusal when the body is unparseable. No leg/admission wiring (deferred to G6-7-4); no gateway runner (G6-7-3).

**Tech Stack:** Python 3.12+, Pydantic v2 (frozen, `extra="forbid"`), `mypy --strict` + `pyright`, pytest + hypothesis. No async (the model + re-parse are pure). No i18n strings (no operator-facing copy in this slice — wire method names + audit-row vocabulary are NOT `t()` strings; the loud-refusal error carries no localized text).

## Global Constraints

- **Language/typing:** Python 3.12+, PEP 604 unions (`X | Y`), PEP 585 generics, no `Optional`, no `typing.List`. No `Any` without justification. `mypy --strict` + `pyright` clean.
- **Wire models:** every comms-MCP wire model is `ConfigDict(frozen=True, extra="forbid")` and every closed-vocab field is `Literal`/validated, never bare `str` (protocol.py module rule, lines 19-21).
- **Payload-blindness (hard rule #5):** the envelope model and any gateway-side code NEVER `json.loads` / parse / log the opaque T3 body. Only the CORE re-parse function reads it (core-side, the trusted boundary). The envelope member is `bytes | str`, opaque.
- **Fail-loud (hard rule #7):** envelope==body mismatch and a malformed/unparseable body each raise a typed loud error rooted at `CommsMcpError` — NEVER a silent drop and NEVER a bare `ValueError` swallowed. The disposition (ack-to-drain vs refusal) is wired in later slices; THIS slice raises + tests the typed error.
- **Byte-stability / determinism:** the re-parse is deterministic on identical body bytes (SEC-309-2) so G0 dedup on `(adapter_id, inbound_id)` can never be a silent no-op. Pinned by a test.
- **Scope fence:** NO reverse-outbound model (cut per spec §3.4). NO registered-leg / K4 admission (deferred to G6-7-4). NO gateway forward-runner, NO core receive route, NO dispatch ordering. Pure data layer only.
- **Commit subjects:** `type(scope): description (Spec B G6-7-1, #309)`. Body ends with the trailer line `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`.
- **Plan-doc:** never `git add` this `.md`; never markdown-link it.

---

## Grounding facts (cited against `main`, locked before execution)

These are the exact shapes the tasks below depend on. They are facts about the
current tree, not decisions — verify them with the cited commands if in doubt.

- **The re-parse TARGET model** is `alfred.comms_mcp.protocol.InboundMessageNotification`
  (`src/alfred/comms_mcp/protocol.py:322-353`), frozen + `extra="forbid"`, fields:
  `adapter_id: AdapterId` (closed-vocab `Annotated[str, AfterValidator(_check_adapter_kind)]` — `"discord"`/`"tui"`/`"alfred_comms_test"`),
  `inbound_id: InboundId` (`Field(min_length=1, max_length=255)`),
  `platform_user_id: PlatformUserId` (`Field(min_length=1, max_length=512)`),
  `body: Mapping[str, object]` (the raw adapter-specific blob — T3),
  `sub_payload_refs: tuple[str, ...]`,
  `received_at: AwareDatetime` (tz-aware enforced),
  `addressing_signal: InboundAddressingSignal` (`Literal["dm","mention","channel","thread"]`),
  `wire_seq: int | None = Field(default=None, ge=0)`.
- **How the body is parsed today** (`src/alfred/plugins/session.py:809`):
  `InboundMessageNotification.model_validate(raw)` — the WHOLE `raw` dict (a fresh copy of the JSON-RPC `params`) IS the notification. So the "body" the gateway forwards opaque is the JSON-serialized `params` object, and the **body-derived `adapter_id` = `InboundMessageNotification.model_validate(<parsed-body>).adapter_id`** — `adapter_id` is a top-level field of the notification, NOT a nested derivation. There is no separate "derive adapter_id" transform; re-validation IS the derivation.
- **Existing wire-method-name constant pattern** lives in `protocol.py` as module-level `Final[str]` (e.g. `GATEWAY_ADAPTER_UP: Final[str] = "gateway.adapter.up"`, protocol.py:427) and in `adapter_credential_protocol.py` (`GATEWAY_ADAPTER_SPAWN_REQUEST: Final[str] = "gateway.adapter.spawn_request"`, line 61). The new method constant `GATEWAY_ADAPTER_INBOUND` follows the `protocol.py` convention (it sits beside the `GATEWAY_ADAPTER_*` family).
- **Error hierarchy** is rooted at `alfred.comms_mcp.errors.CommsMcpError` (`src/alfred/comms_mcp/errors.py`), itself an `AlfredError`. New typed errors subclass `CommsMcpError`.
- **CI per-file 100% gates** have TWO sites in `.github/workflows/ci.yml`: the python-job "Gateway kernel trust-boundary 100%…" `--include` list (line ~294) and the `coverage-gates` "…(combined)" `--include` list (line ~1347). `protocol.py` is NOT currently in either gate (it is covered by the comms_mcp tier). See the §"CI gate decision" note below — the new `inbound_reparse.py` is a trust-boundary file and IS added to both.

---

## File Structure

| File | Create / Modify | Responsibility after this slice |
| --- | --- | --- |
| `src/alfred/comms_mcp/protocol.py` | Modify | Add `GATEWAY_ADAPTER_INBOUND: Final[str] = "gateway.adapter.inbound"` (beside the `GATEWAY_ADAPTER_*` family) + the `GatewayAdapterInboundEnvelope` frozen model (out-of-band `adapter_id: AdapterId` + opaque `body: bytes \| str`), and export both in`**all**`. The model NEVER introspects`body`. |
| `src/alfred/comms_mcp/errors.py` | Modify | Add `InboundReparseError(CommsMcpError)` (base for the two re-parse refusals), `InboundEnvelopeBodyMismatchError(InboundReparseError)` (envelope==body adapter_id mismatch), `InboundBodyMalformedError(InboundReparseError)` (body un-parseable into `InboundMessageNotification`). Export in `__all__`. |
| `src/alfred/comms_mcp/inbound_reparse.py` | Create | The pure core-side re-parse: `reparse_forwarded_inbound(envelope) -> InboundMessageNotification`. Decodes the opaque body, `model_validate`s it into `InboundMessageNotification`, enforces envelope.adapter_id == body.adapter_id (else `InboundEnvelopeBodyMismatchError`), raises `InboundBodyMalformedError` on any decode/validation failure. **Trust-boundary leaf → both ci.yml per-file 100% gates.** |
| `tests/unit/comms/test_gateway_adapter_inbound_envelope.py` | Create | Envelope model: happy construct, frozen (mutation raises), `extra="forbid"` (rejects-extra), body-opaque (accepts `bytes` and `str`, never parsed), closed-vocab `adapter_id`. |
| `tests/unit/comms/test_inbound_reparse.py` | Create | Re-parse: happy body→exact `InboundMessageNotification`; envelope==body MATCH passes; MISMATCH→`InboundEnvelopeBodyMismatchError`; malformed body→`InboundBodyMalformedError`; byte-stability/determinism (same bytes → equal model twice). |
| `.github/workflows/ci.yml` | Modify | Add `src/alfred/comms_mcp/inbound_reparse.py` to BOTH per-file 100% `--include` lists + a new named gate step at each site (python-job ~294 region and coverage-gates ~1347 region) — four edit points total (two `--include` strings, two `hashFiles` guard lines / step headers). |

---

## CI gate decision

`inbound_reparse.py` is a **trust-boundary** module: it is the data-layer half of the
F3 forgery mitigation (the envelope==body equality check that makes the
spawn-binding-minted envelope id non-spoofable) and the core-side parser of an
opaque body the gateway never validated. Spec §4 marks the core-side disposition a
"Trust-boundary module → both ci.yml per-file 100% gates." The pure re-parse is the
first landed piece of that boundary, so it gets the gate now (Task 6). The envelope
model in `protocol.py` does NOT get its own per-file gate — `protocol.py` is a large
shared wire-model file covered by the comms_mcp coverage tier, and adding a single
new model to it does not change that file's gating posture (matching how the existing
`gateway.adapter.*` status models were added to `protocol.py` without a per-file gate).

---

## Tasks

### Task 1: The `gateway.adapter.inbound` method constant + envelope model

**Files:**

- Modify: `src/alfred/comms_mcp/protocol.py` (add constant + model near the `GATEWAY_ADAPTER_*` family, ~line 426-430; export in `__all__` ~line 664-713)
- Test: `tests/unit/comms/test_gateway_adapter_inbound_envelope.py`

**Interfaces:**

- Consumes: `AdapterId` (protocol.py:91), `_WireModel` (protocol.py:139).
- Produces:
  - `GATEWAY_ADAPTER_INBOUND: Final[str]` == `"gateway.adapter.inbound"`.
  - `class GatewayAdapterInboundEnvelope(_WireModel)` with fields `adapter_id: AdapterId` and `body: bytes | str`. Frozen, `extra="forbid"`, body opaque (never introspected).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/comms/test_gateway_adapter_inbound_envelope.py
"""Unit tests for the gateway.adapter.inbound envelope (Spec B G6-7-1, #309).

The envelope is the gateway->core wire contract for a forwarded hosted-adapter
inbound. It carries the gateway-supplied out-of-band ``adapter_id`` (the spawn
binding mints it in G6-7-3; this slice only MODELS it) plus the opaque T3 body
the gateway never parses. The model itself is body-opaque: it stores ``body`` as
an untouched ``bytes``/``str`` member and never introspects it.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_INBOUND,
    GatewayAdapterInboundEnvelope,
)


def test_method_constant_is_the_wire_name() -> None:
    assert GATEWAY_ADAPTER_INBOUND == "gateway.adapter.inbound"


def test_envelope_constructs_with_bytes_body() -> None:
    body = json.dumps({"adapter_id": "discord"}).encode("utf-8")
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=body)
    assert env.adapter_id == "discord"
    assert env.body == body


def test_envelope_accepts_str_body_unparsed() -> None:
    # The envelope is body-opaque: a str body is stored verbatim, never parsed.
    raw = '{"this is": "not parsed by the envelope"}'
    env = GatewayAdapterInboundEnvelope(adapter_id="tui", body=raw)
    assert env.body == raw


def test_envelope_is_frozen() -> None:
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=b"{}")
    with pytest.raises(ValidationError):
        env.adapter_id = "tui"  # type: ignore[misc]


def test_envelope_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        GatewayAdapterInboundEnvelope(
            adapter_id="discord",
            body=b"{}",
            smuggled="nope",  # type: ignore[call-arg]
        )


def test_envelope_rejects_unknown_adapter_kind() -> None:
    # adapter_id is the closed-vocab AdapterId; an unknown kind is a loud reject.
    with pytest.raises(ValidationError):
        GatewayAdapterInboundEnvelope(adapter_id="telegram", body=b"{}")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms/test_gateway_adapter_inbound_envelope.py -q`
Expected: FAIL — `ImportError: cannot import name 'GATEWAY_ADAPTER_INBOUND'` (and `GatewayAdapterInboundEnvelope`) from `alfred.comms_mcp.protocol`.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/comms_mcp/protocol.py`, add the constant immediately after
`GATEWAY_ADAPTER_BREAKER_OPEN` (line 430):

```python
# The wire method for a gateway-forwarded hosted-adapter inbound (Spec B G6-7-1,
# #309 / ADR-0039). The gateway wraps the opaque T3 body in this method-bearing
# envelope so the core's _route_notification discriminates it from a directly
# connected adapter's ``inbound.message`` by METHOD NAME (consistent with the
# ``gateway.adapter.spawn_request`` / ``gateway.adapter.*`` status discriminators),
# never by an adapter_id heuristic. The out-of-band ``adapter_id`` is gateway
# spawn-binding metadata (SEC-309-1) — the routing key; the core re-parses the
# opaque body for the authoritative G0 ``(adapter_id, inbound_id)``.
GATEWAY_ADAPTER_INBOUND: Final[str] = "gateway.adapter.inbound"
```

Then add the model immediately after `AdapterBreakerOpenNotification` (line 528),
inside the gateway->core section:

```python
class GatewayAdapterInboundEnvelope(_WireModel):
    """Gateway->core: a forwarded hosted-adapter inbound (Spec B G6-7-1, #309).

    The thin method-bearing envelope (method :data:`GATEWAY_ADAPTER_INBOUND`) the
    gateway wraps a hosted adapter child's ``inbound.message`` in so the opaque T3
    body can ride the leg to the core for re-parse + dispatch, WITHOUT the gateway
    parsing the body (hard rule #5).

    BODY-OPAQUE BY CONSTRUCTION. ``body`` is the child's ``inbound.message``
    ``params`` blob carried BYTE-FOR-BYTE (``bytes``) or verbatim (``str``); this
    model NEVER ``json.loads`` it. Only the core's
    :func:`alfred.comms_mcp.inbound_reparse.reparse_forwarded_inbound` reads it
    (core-side, the trusted boundary). Keeping the byte run untouched is what makes
    the embedded ``inbound_id`` stable across the leg's ReplayBuffer replay
    (SEC-309-2) so G0 dedup on ``(adapter_id, inbound_id)`` is never a no-op.

    ``adapter_id`` is the OUT-OF-BAND routing key the gateway supplies from its
    per-child SPAWN BINDING (SEC-309-1) — NEVER read from the body. It is the
    closed-vocab :data:`AdapterId` (``"discord"``/``"tui"``…), so a forged kind is
    a loud ValidationError at the boundary. The core (G6-7-4) re-derives the
    authoritative ``adapter_id`` from the re-parsed body and validates it EQUALS
    this envelope value (the §3.3 F3 mitigation; the data-layer half is
    :func:`reparse_forwarded_inbound`); equality alone is insufficient — the
    spawn-binding origin of this id is the real anti-forgery defense (SEC-309-1).
    """

    adapter_id: AdapterId
    body: bytes | str
```

Add `"GatewayAdapterInboundEnvelope"` and `"GATEWAY_ADAPTER_INBOUND"` to `__all__`
(keep the existing rough alphabetical grouping — `GATEWAY_ADAPTER_INBOUND` after
`GATEWAY_ADAPTER_DOWN`/before `GATEWAY_ADAPTER_STATUS_PREFIX`; the class after
`CrashedNotification`/before `GoingDownNotification`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms/test_gateway_adapter_inbound_envelope.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/protocol.py tests/unit/comms/test_gateway_adapter_inbound_envelope.py
git commit -m "feat(comms): add gateway.adapter.inbound envelope model (Spec B G6-7-1, #309)"
```

Commit body MUST end with the trailer line:
`MrReasonable <4990954+MrReasonable@users.noreply.github.com>`

---

### Task 2: The typed re-parse refusal errors

**Files:**

- Modify: `src/alfred/comms_mcp/errors.py` (add three errors + exports)
- Test: folded into Task 3's re-parse tests (the errors are only meaningful via the re-parse; per Task Right-Sizing, an isolated "import the error class" test is not worth its own reviewer gate). This task ships the error definitions so Task 3 can import them; its correctness is proven by Task 3's `pytest.raises` assertions.

**Interfaces:**

- Produces:
  - `class InboundReparseError(CommsMcpError)` — base for forwarded-inbound re-parse refusals.
  - `class InboundEnvelopeBodyMismatchError(InboundReparseError)` — envelope `adapter_id` != body-derived `adapter_id`.
  - `class InboundBodyMalformedError(InboundReparseError)` — opaque body could not be decoded/validated into `InboundMessageNotification`.

- [ ] **Step 1: Write minimal implementation** (no standalone test — Task 3 exercises these)

In `src/alfred/comms_mcp/errors.py`, after `PromoterRequiredError` (the last class
before `__all__`):

```python
class InboundReparseError(CommsMcpError):
    """A gateway-forwarded inbound failed the core-side re-parse (G6-7-1, #309).

    Base for the two loud refusals
    :func:`alfred.comms_mcp.inbound_reparse.reparse_forwarded_inbound` raises. Both
    are FAIL-LOUD (hard rule #7) — never a silent drop. The disposition the core
    attaches to each (the §3.3 K4-style forge refusal vs the §3.3/ARCH-309-3
    ack-to-drain on a malformed body) is wired in the receive slice (G6-7-4); this
    typed hierarchy is the data-layer contract those dispositions discriminate on.
    Carries NO raw T3 body on the exception (spec §5.6 — no payload in error attrs).
    """


class InboundEnvelopeBodyMismatchError(InboundReparseError):
    """The envelope ``adapter_id`` did not equal the body-derived ``adapter_id``.

    The F3 forgery mitigation's data-layer half (spec §3.3): the body stays the
    sole G0 authority, and an envelope whose routing id disagrees with the body it
    wraps is a forged-body/valid-leg mismatch — refused loud (the core maps this to
    a K4-style refusal + signed audit row in G6-7-4), never default-routed. Carries
    only the two closed-vocab adapter_id KINDS, never the body.
    """


class InboundBodyMalformedError(InboundReparseError):
    """The opaque forwarded body could not be re-parsed into an inbound.

    The core re-parses a body the gateway never validated; a decode failure
    (non-UTF-8 / non-JSON / not a top-level object) or an
    :class:`InboundMessageNotification` validation failure raises this. In G6-7-4
    the core maps it to a loud bounded-field audit drop that ACKs the leg frame to
    drain it (ARCH-309-3 — no infinite replay). Carries NO raw body (spec §5.6).
    """
```

Add `"InboundReparseError"`, `"InboundEnvelopeBodyMismatchError"`,
`"InboundBodyMalformedError"` to `__all__` (alphabetical with the existing entries).

- [ ] **Step 2: Run the comms error import smoke to verify it imports clean**

Run: `uv run python -c "from alfred.comms_mcp.errors import InboundReparseError, InboundEnvelopeBodyMismatchError, InboundBodyMalformedError; print('ok')"`
Expected: prints `ok` (no ImportError, no syntax error).

- [ ] **Step 3: Commit**

```bash
git add src/alfred/comms_mcp/errors.py
git commit -m "feat(comms): add forwarded-inbound re-parse error hierarchy (Spec B G6-7-1, #309)"
```

Commit body MUST end with the trailer line:
`MrReasonable <4990954+MrReasonable@users.noreply.github.com>`

---

### Task 3: The pure core-side re-parse function

**Files:**

- Create: `src/alfred/comms_mcp/inbound_reparse.py`
- Test: `tests/unit/comms/test_inbound_reparse.py`

**Interfaces:**

- Consumes: `GatewayAdapterInboundEnvelope` (Task 1), `InboundMessageNotification` (protocol.py:322), `InboundEnvelopeBodyMismatchError` + `InboundBodyMalformedError` (Task 2).
- Produces:
  - `def reparse_forwarded_inbound(envelope: GatewayAdapterInboundEnvelope) -> InboundMessageNotification` — decodes `envelope.body`, validates into `InboundMessageNotification`, enforces `notification.adapter_id == envelope.adapter_id`. Pure, deterministic, no I/O, no async.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/comms/test_inbound_reparse.py
"""Unit tests for the core-side forwarded-inbound re-parse (Spec B G6-7-1, #309).

The pure function that turns the gateway's opaque forwarded body back into the
UNCHANGED InboundMessageNotification and enforces the envelope==body adapter_id
equality (the F3 mitigation's data-layer half). No wiring, no leg/admission (that
is G6-7-4) — just the byte-stable, fail-loud re-parse.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.errors import (
    InboundBodyMalformedError,
    InboundEnvelopeBodyMismatchError,
)
from alfred.comms_mcp.inbound_reparse import reparse_forwarded_inbound
from alfred.comms_mcp.protocol import (
    GatewayAdapterInboundEnvelope,
    InboundMessageNotification,
)


def _valid_body(adapter_id: str = "discord") -> bytes:
    """A wire-shaped InboundMessageNotification params blob, JSON bytes."""
    return json.dumps(
        {
            "adapter_id": adapter_id,
            "inbound_id": "platform-msg-7",
            "platform_user_id": "user-42",
            "body": {"content": "hello alfred"},
            "sub_payload_refs": [],
            "received_at": datetime(2026, 6, 21, 12, 0, tzinfo=UTC).isoformat(),
            "addressing_signal": "dm",
        }
    ).encode("utf-8")


def test_happy_body_reparses_to_exact_inbound_notification() -> None:
    body = _valid_body("discord")
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=body)

    result = reparse_forwarded_inbound(env)

    assert isinstance(result, InboundMessageNotification)
    assert result.adapter_id == "discord"
    assert result.inbound_id == "platform-msg-7"
    assert result.platform_user_id == "user-42"
    assert result.body == {"content": "hello alfred"}
    assert result.sub_payload_refs == ()
    assert result.addressing_signal == "dm"


def test_envelope_equals_body_adapter_id_passes() -> None:
    body = _valid_body("tui")
    env = GatewayAdapterInboundEnvelope(adapter_id="tui", body=body)
    assert reparse_forwarded_inbound(env).adapter_id == "tui"


def test_envelope_body_adapter_id_mismatch_raises_loud() -> None:
    # Body says discord; envelope (spawn-binding) says tui -> forged-body refusal.
    body = _valid_body("discord")
    env = GatewayAdapterInboundEnvelope(adapter_id="tui", body=body)
    with pytest.raises(InboundEnvelopeBodyMismatchError):
        reparse_forwarded_inbound(env)


def test_non_json_body_raises_malformed() -> None:
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=b"\xff\xfenot json")
    with pytest.raises(InboundBodyMalformedError):
        reparse_forwarded_inbound(env)


def test_json_but_invalid_notification_raises_malformed() -> None:
    # Valid JSON object, but missing required InboundMessageNotification fields.
    env = GatewayAdapterInboundEnvelope(
        adapter_id="discord", body=b'{"adapter_id": "discord"}'
    )
    with pytest.raises(InboundBodyMalformedError):
        reparse_forwarded_inbound(env)


def test_non_object_top_level_json_raises_malformed() -> None:
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=b'"just a string"')
    with pytest.raises(InboundBodyMalformedError):
        reparse_forwarded_inbound(env)


def test_reparse_is_deterministic_on_identical_bytes() -> None:
    # Byte-stability (SEC-309-2): same bytes -> equal model every time, so G0
    # dedup on (adapter_id, inbound_id) can never be a silent no-op.
    body = _valid_body("discord")
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=body)
    first = reparse_forwarded_inbound(env)
    second = reparse_forwarded_inbound(env)
    assert first == second
    assert first.inbound_id == second.inbound_id == "platform-msg-7"


def test_str_body_reparses_identically_to_bytes_body() -> None:
    # The envelope accepts str or bytes; both decode to the same notification.
    body_bytes = _valid_body("discord")
    body_str = body_bytes.decode("utf-8")
    from_bytes = reparse_forwarded_inbound(
        GatewayAdapterInboundEnvelope(adapter_id="discord", body=body_bytes)
    )
    from_str = reparse_forwarded_inbound(
        GatewayAdapterInboundEnvelope(adapter_id="discord", body=body_str)
    )
    assert from_bytes == from_str
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms/test_inbound_reparse.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.comms_mcp.inbound_reparse'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/alfred/comms_mcp/inbound_reparse.py
"""Pure core-side re-parse of a gateway-forwarded inbound (Spec B G6-7-1, #309).

The data-layer half of the gateway->core inbound bridge (ADR-0039 option 1). The
gateway forwards a hosted adapter child's ``inbound.message`` as an opaque body
wrapped in a :class:`~alfred.comms_mcp.protocol.GatewayAdapterInboundEnvelope`
WITHOUT parsing the body (hard rule #5). This module is where the CORE — the
trusted boundary — turns that opaque body back into the UNCHANGED
:class:`~alfred.comms_mcp.protocol.InboundMessageNotification` and enforces the
F3 mitigation's data-layer half: the body-derived ``adapter_id`` MUST equal the
envelope ``adapter_id`` (spec §3.3). The body stays the sole G0 authority; the
envelope id is the gateway's spawn-binding routing key (SEC-309-1), and equality
makes a forged-body/valid-leg frame a loud refusal rather than a silent dispatch.

PURE + DETERMINISTIC. No I/O, no clock, no async, no global state. The same body
bytes always re-parse to an EQUAL notification (SEC-309-2), so G0 dedup on the
composite ``(adapter_id, inbound_id)`` can never be a silent no-op.

FAIL-LOUD (hard rule #7). A body that does not decode/validate raises
:class:`~alfred.comms_mcp.errors.InboundBodyMalformedError`; an envelope==body
``adapter_id`` mismatch raises
:class:`~alfred.comms_mcp.errors.InboundEnvelopeBodyMismatchError`. Neither carries
the raw T3 body on the exception (spec §5.6). The DISPOSITION (the K4-style forge
refusal vs the ARCH-309-3 ack-to-drain on a malformed body) is the core receive
slice's job (G6-7-4); this function only raises the typed contract.

SCOPE FENCE. This is NOT leg/registered-adapter admission (K4 — deferred to
G6-7-4) and NOT dispatch. It is the model + the equality check only.
"""

from __future__ import annotations

from pydantic import ValidationError

from alfred.comms_mcp.errors import (
    InboundBodyMalformedError,
    InboundEnvelopeBodyMismatchError,
)
from alfred.comms_mcp.protocol import (
    GatewayAdapterInboundEnvelope,
    InboundMessageNotification,
)


def reparse_forwarded_inbound(
    envelope: GatewayAdapterInboundEnvelope,
) -> InboundMessageNotification:
    """Re-parse a forwarded inbound's opaque body into its notification.

    Returns the validated :class:`InboundMessageNotification` the body encodes.
    Raises :class:`InboundBodyMalformedError` if the body is not a valid
    notification, or :class:`InboundEnvelopeBodyMismatchError` if the body's
    ``adapter_id`` does not equal ``envelope.adapter_id``.
    """
    # The CORE is the trusted parser of the T3 body. ``model_validate_json``
    # mirrors the production parse path (session.py:809's ``model_validate`` of the
    # JSON-RPC ``params``), accepting the byte run the envelope carried verbatim.
    try:
        notification = InboundMessageNotification.model_validate_json(envelope.body)
    except ValidationError as exc:
        # No raw body on the exception (spec §5.6); ``from None`` drops the
        # ValidationError context so a body fragment cannot leak via __cause__.
        raise InboundBodyMalformedError(
            "forwarded inbound body failed InboundMessageNotification validation"
        ) from None

    if notification.adapter_id != envelope.adapter_id:
        # F3 (spec §3.3): the body is authoritative; an envelope routing id that
        # disagrees with the body it wraps is a forged-body/valid-leg mismatch.
        # Only the two closed-vocab KINDS appear in the message, never the body.
        raise InboundEnvelopeBodyMismatchError(
            f"envelope adapter_id {envelope.adapter_id!r} != "
            f"body adapter_id {notification.adapter_id!r}"
        )

    return notification


__all__ = ["reparse_forwarded_inbound"]
```

Note: `del exc` is unnecessary; `from None` already severs the chain. If `ruff`'s
`B904`/`F841` flags the bound `exc` as unused, drop the `as exc` binding entirely:
`except ValidationError:`. Do that if lint complains (Step 4 of the quality task).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms/test_inbound_reparse.py -q`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/inbound_reparse.py tests/unit/comms/test_inbound_reparse.py
git commit -m "feat(comms): add pure core-side forwarded-inbound re-parse (Spec B G6-7-1, #309)"
```

Commit body MUST end with the trailer line:
`MrReasonable <4990954+MrReasonable@users.noreply.github.com>`

---

### Task 4: Wire `inbound_reparse.py` into both ci.yml per-file 100% gates

**Files:**

- Modify: `.github/workflows/ci.yml` (four edit points: a new named step + `--include` at the python-job gate region ~line 240-295, and the same at the `coverage-gates` combined region ~line 1312-1347)

**Interfaces:**

- Consumes: nothing (CI config).
- Produces: a merge-gating 100% line+branch coverage requirement on `src/alfred/comms_mcp/inbound_reparse.py` at both gate sites.

This task mirrors the existing per-file trust-boundary gate pattern (e.g. the
"Quarantine transport trust-boundary 100%…" step at ci.yml:186-203 and its
combined twin). Because `inbound_reparse.py` is a new comms_mcp trust-boundary
leaf (not a `gateway/` file), it gets its OWN named step at each site rather than
joining the gateway-kernel `--include` list — matching how `_bootstrap_grants.py`
and `quarantine_transport.py` each have a standalone named gate.

- [ ] **Step 1: Add the python-job gate step**

In `.github/workflows/ci.yml`, after the "Comms-adapter load-grants 100%…" step
(the step ending at line ~185, before "Quarantine transport trust-boundary…"),
insert:

```yaml
      - name: Forwarded-inbound re-parse trust-boundary 100% line+branch coverage
        # Spec B G6-7-1 (#309, ADR-0039): ``inbound_reparse.py`` is the core-side
        # data-layer half of the gateway->core inbound bridge's F3 forgery
        # mitigation — it re-parses an opaque body the gateway never validated and
        # enforces the envelope==body adapter_id equality. A coverage hole could
        # ship an un-exercised refusal branch (a forged-body mismatch or a
        # malformed body that is NOT raised loud), so 100% line+branch is the bar.
        # Fully covered by the unit tier (tests/unit/comms/test_inbound_reparse.py)
        # — pure function, no root, no Postgres. Named explicitly (two-gates
        # pattern) so a reviewer sees the boundary; keep the combined gate in sync.
        if: steps.check.outputs.has_py == 'true' && hashFiles('src/alfred/comms_mcp/inbound_reparse.py') != ''
        run: |
          uv run coverage report \
            --include='src/alfred/comms_mcp/inbound_reparse.py' \
            --fail-under=100
```

(Match the surrounding steps' exact indentation and `uv run coverage report`
invocation form — copy the structure of the "Quarantine transport…" step at
ci.yml:186-203 verbatim, changing only the name, comment, `hashFiles` path, and
`--include` path.)

- [ ] **Step 2: Add the combined coverage-gates step**

In the `coverage-gates:` job, after the analogous combined step for the comms /
quarantine files (locate the combined twin of the python-job step you added in
Step 1; it sits in the same relative position in the combined job, near the
"Gateway kernel trust-boundary 100%… (combined)" step at ci.yml:1312), insert the
SAME step with `(combined)` appended to the name:

```yaml
      - name: Forwarded-inbound re-parse trust-boundary 100% line+branch coverage (combined)
        # Combined twin of the python-job gate (two-gates pattern, Spec B G6-7-1,
        # #309). Keep the --include in lockstep with the python-job step.
        if: steps.check.outputs.has_py == 'true' && hashFiles('src/alfred/comms_mcp/inbound_reparse.py') != ''
        run: |
          uv run coverage report \
            --include='src/alfred/comms_mcp/inbound_reparse.py' \
            --fail-under=100
```

- [ ] **Step 3: Validate the workflow YAML parses**

Run: `uv run python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml valid')"`
Expected: prints `ci.yml valid` (no YAML parse error).

- [ ] **Step 4: Locally prove the gate is satisfiable (100% on the new file)**

Run:

```bash
uv run coverage run -m pytest tests/unit/comms/test_inbound_reparse.py -q
uv run coverage report --include='src/alfred/comms_mcp/inbound_reparse.py' --fail-under=100
```

Expected: the report shows `src/alfred/comms_mcp/inbound_reparse.py` at `100%` and the command exits 0 (no "Coverage failure: total … is less than 100").

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(comms): gate forwarded-inbound re-parse at 100% coverage (Spec B G6-7-1, #309)"
```

Commit body MUST end with the trailer line:
`MrReasonable <4990954+MrReasonable@users.noreply.github.com>`

---

### Task 5: Quality bar — lint, format, type-check, full unit tier

**Files:** none (verification only; fixups folded back into the relevant file + amended into the offending commit via `git commit --fixup` + autosquash if anything is wrong — see CLAUDE.md memory `procedural_in_branch_fixes.md`).

**Interfaces:** none.

- [ ] **Step 1: Lint + format check**

Run: `uv run ruff check src/alfred/comms_mcp/inbound_reparse.py src/alfred/comms_mcp/protocol.py src/alfred/comms_mcp/errors.py tests/unit/comms/test_inbound_reparse.py tests/unit/comms/test_gateway_adapter_inbound_envelope.py && uv run ruff format --check .`
Expected: `All checks passed!` and no format diff. If `ruff` flags the unused `as exc` binding in `inbound_reparse.py`, drop it (`except ValidationError:`) and re-run.

- [ ] **Step 2: Type-check (both checkers)**

Run: `uv run mypy src/ && uv run pyright src/alfred/comms_mcp/inbound_reparse.py src/alfred/comms_mcp/protocol.py src/alfred/comms_mcp/errors.py`
Expected: `Success: no issues found` (mypy) and `0 errors` (pyright). The `model_validate_json` accepts `str | bytes`, matching the envelope's `bytes | str` body, so no cast is needed.

- [ ] **Step 3: Run the two new test files**

Run: `uv run pytest tests/unit/comms/test_inbound_reparse.py tests/unit/comms/test_gateway_adapter_inbound_envelope.py -q`
Expected: PASS (14 passed total).

- [ ] **Step 4: Full unit tier (no regression — protocol.py + errors.py are widely imported)**

Run: `uv run pytest tests/unit -q`
Expected: all pass (no collection error, no regression in the comms / gateway / session suites that import `protocol.py`).

- [ ] **Step 5 (optional but recommended): `make check`**

Run: `make check`
Expected: lint + format + type + test all green. (Per project memory `feedback_make_check_before_push.md`, run this before any push.)

- [ ] **Step 6: No commit unless a fixup was needed**

If Steps 1-5 surfaced a fix, apply it and:

```bash
git add <the-fixed-file>
git commit --fixup=<sha-of-the-task-that-introduced-it>
git rebase -i --autosquash main   # non-interactive autosquash; resolves the fixup
```

If everything was green first time, this task produces no commit.

NEVER `git add docs/superpowers/plans/2026-06-21-g6-7-1-inbound-envelope-reparse.md`.

---

## Self-Review

**1. Spec coverage (G6-7-1 scope only — `docs/.../2026-06-21-gateway-adapter-inbound-bridge-design.md` §5 + §3.2/§3.3):**

| G6-7-1 requirement | Task |
| --- | --- |
| `gateway.adapter.inbound` envelope Pydantic model (method + out-of-band `adapter_id` + opaque body member) — §4, §5 G6-7-1 | Task 1 |
| Frozen Pydantic v2, strong-typed, payload-blind body (`bytes \| str`, never introspected) — Global Constraints, §3.2 | Task 1 (`_WireModel` frozen + `extra="forbid"`; body opaque; tests assert no parse) |
| `adapter_id` modeled as the spawn-binding routing key (enforcement = G6-7-3; modeled here) — SEC-309-1 | Task 1 (docstring states origin; closed-vocab `AdapterId`) |
| Pure `body → InboundMessageNotification` re-parse helper — §3.3, §5 G6-7-1 | Task 3 |
| Envelope==body `adapter_id` equality check; mismatch → typed loud refusal (F3 data-layer half) — §3.3 F3 | Task 3 (`InboundEnvelopeBodyMismatchError`) |
| Malformed/unparseable body → typed loud error (never silent drop) — hard rule #7, ARCH-309-3 | Task 3 (`InboundBodyMalformedError`) |
| Byte-stability / determinism on identical bytes — SEC-309-2 | Task 3 (`test_reparse_is_deterministic_on_identical_bytes`, `test_str_body_reparses_identically_to_bytes_body`) |
| Typed error hierarchy rooted at `CommsMcpError` — error conventions | Task 2 |
| Trust-boundary file → both ci.yml per-file 100% gates — §4 | Task 4 |
| Quality bar (ruff/format/mypy/pyright + per-file gate + full unit tier) — plan deliverable | Task 5 |

DEFERRED (correctly NOT in this plan, verified against §5): registered-leg/K4 RECEIVE admission (G6-7-4), per-`adapter_id` collaborator registry (G6-7-4), the core `_route_notification` arm + dispatch ordering (G6-7-4), the `GatewayInboundForwardRunner` + `forward_adapter_inbound` (G6-7-3), the `CommsPluginRunner` disposition seam (G6-7-2), resume/poison/back-pressure (G6-7-3/-5), any reverse-outbound model (cut, §3.4), all audit rows (those land with the wiring in G6-7-3/-4). No gap.

**2. Placeholder scan:** No "TBD"/"TODO"/"implement later"/"add appropriate…"/"similar to Task N". Every code step shows complete code; every command shows expected output. The one conditional ("if ruff flags `as exc`, drop it") is a concrete, resolvable instruction with the exact replacement shown — not a placeholder.

**3. Type consistency:**

- `GatewayAdapterInboundEnvelope(adapter_id: AdapterId, body: bytes | str)` — defined Task 1, consumed identically in Tasks 1+3 tests and Task 3 impl.
- `reparse_forwarded_inbound(envelope: GatewayAdapterInboundEnvelope) -> InboundMessageNotification` — defined Task 3, name + signature identical in test (Task 3 Step 1) and impl (Step 3).
- Errors `InboundReparseError` / `InboundEnvelopeBodyMismatchError` / `InboundBodyMalformedError` — defined Task 2, raised in Task 3 impl, asserted in Task 3 tests — names match exactly.
- `GATEWAY_ADAPTER_INBOUND` == `"gateway.adapter.inbound"` — defined + asserted Task 1; consistent with the existing `GATEWAY_ADAPTER_*` family.
- `InboundMessageNotification` field names used in `_valid_body` (Task 3) match protocol.py:333-353 exactly (`adapter_id, inbound_id, platform_user_id, body, sub_payload_refs, received_at, addressing_signal`; `wire_seq` omitted → defaults `None`).

No inconsistencies found.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-21-g6-7-1-inbound-envelope-reparse.md` (LOCAL/untracked — do not `git add` it). Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task (use the `alfred-python-developer` subagent for the Python tasks), review between tasks. Front-load the security/reviewer/test-engineer fleet before pushing (project memory: CR approves first-pass on security-boundary PRs when the internal fleet runs first).
2. **Inline Execution** — execute in this session via `superpowers:executing-plans`, batch with checkpoints.

Which approach?
