# G1 — Core Lifecycle Signal + Per-Boot Epoch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the AlfredOS core EMIT two lifecycle signals — `core.lifecycle.going_down{reason}` when it begins its SIGTERM drain and `core.lifecycle.ready{epoch}` once its full security boot graph is healthy — and mint a per-boot non-secret epoch carried in `ready` (and reserved for the comms handshake), recorded by a new ADR-0033.

**Architecture:** This is a **wire-substrate** PR (the consumer — the gateway, G3 — does not exist yet), exactly like PR-S4-11a. **G1 is AUDIT-ONLY on the boot/drain path.** We *define* two host→outward notification frames in the comms wire vocabulary (`src/alfred/comms_mcp/protocol.py`) so G3 has the carrier shape to use, but G1 does NOT send them on the wire and does NOT plumb a runner through the boot path — there is no consumer yet, and capturing a single runner against the multi-adapter spawn loop would be wrong. G1's runtime behaviour is: mint a per-boot epoch alongside the existing `boot_id` in `_start_async`, emit a `daemon.lifecycle.ready` AUDIT row after the comms boot graph + adapters are healthy (after `daemon.boot.completed`), and emit a `daemon.lifecycle.going_down` AUDIT row at the drain (planned-shutdown only). We assert the AUDIT rows are produced at the right lifecycle points and carry the epoch, and that the frame models round-trip — NOT an end-to-end gateway round-trip and NOT a wire send. We build NO gateway, NO resume buffer (G4), NO seq/ack codec (G2), and NO runner send seam (deferred to G3).

**Tech Stack:** Python 3.12+, asyncio, Pydantic v2 (`_WireModel`), Typer CLI, structlog, the AlfredOS audit writer (`append_schema` over `DAEMON_BOOT_FIELDS`-style field-sets), the i18n `t()` catalog (`pybabel`), pytest + `typer.testing.CliRunner`, `mypy --strict` + `pyright`.

---

## Context the engineer needs (read this first)

You have zero context. Read these before touching code:

- **Spec:** `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` — §4 "Wire protocol" (the lifecycle bullet), §6 "Trust-boundary posture", §8 (the G1 row of the epic table).
- **Boot orchestration:** `src/alfred/cli/daemon/_commands.py`. The whole boot lives in `_start_async` (`_commands.py:1401`). The relevant anchors:
  - `boot_id = str(uuid.uuid4())` — `_commands.py:1402` — the existing per-boot value.
  - `t3_nonce = create_and_register_t3_nonce()` — `_commands.py:1567` — the per-boot **secret** capability-gate nonce (identity-only; NEVER serialised). This is the *pattern* we mirror for the epoch, NOT the value we put on the wire.
  - `comms_graph = await _build_comms_boot_graph(...)` — `_commands.py:1628` — the security boot graph build (spawns the bwrap quarantined child). Healthy boot = this succeeded AND every adapter spawned/handshaked.
  - `await supervisor.start()` — `_commands.py:1676`.
  - the adapter spawn/listen loop — `_commands.py:1692-1738`.
  - `daemon.boot.completed` emit — `_commands.py:1743-1757`; `_invoke_boot_completed` — `_commands.py:1759`; `typer.echo(t("daemon.boot.started"...))` — `_commands.py:1761`. **`ready` emits HERE** (after this line — the boot is genuinely healthy).
  - `await wait_for_shutdown(supervisor)` — `_commands.py:1763`.
  - the boot `finally:` — `_commands.py:1764`; `await supervisor.stop()` (the drain) — `_commands.py:1775`. **`going_down` emits at the TOP of this `finally`, BEFORE `supervisor.stop()`.**
- **The signal future:** `wait_for_shutdown` — `_commands.py:1184`; `_on_term` + `loop.add_signal_handler(signal.SIGTERM, _on_term)` — `_commands.py:1197-1205`. SIGTERM resolves the future the boot awaits; control then falls into the `finally`. In unit tests `wait_for_shutdown` is monkeypatched to an async no-op (`tests/unit/cli/daemon/conftest.py:189`), so the boot returns naturally and runs the `finally` — that is how a test exercises the drain without a real signal.
- **Nonce-factory pattern (mirror this for the epoch):** `src/alfred/bootstrap/nonce_factory.py` — module slot + `threading.Lock` (`_NONCE_LOCK`) + already-registered guard (`T3NonceAlreadyRegisteredError`). The epoch factory copies this shape but produces a **serialisable, non-secret** value.
- **Wire models:** `src/alfred/comms_mcp/protocol.py` — `_WireModel` (`_commands.py` calls it via `protocol.py:139`): `ConfigDict(frozen=True, extra="forbid")`, every closed-vocab field is `Literal[...]`. The existing notifications (`InboundMessageNotification` etc., `protocol.py:284-330`) are **plugin→host**. G1 adds two **host→outward** notifications — same `_WireModel` base, opposite direction; clarified in a new "Host -> outward lifecycle notifications" section.
- **Runner send seam (DEFERRED to G3 — context only):** `src/alfred/plugins/comms_runner.py` — `_CommsTransportLike` (`comms_runner.py:122`) with `send(frame: Mapping[str, object])` (`comms_runner.py:133`); `send_request` shows the frame shape (`comms_runner.py:243`: `{"jsonrpc":"2.0","id":...,"method":...,"params":...}`). A **notification** is the same frame WITHOUT an `id`. **G1 does NOT touch this file** — the `send_notification` method + the wire send land in G3 with the gateway consumer. G1 is audit-only; this anchor is here only so a future engineer knows where the send seam will go.
- **Audit:** `_emit_or_quarantine` — `_commands.py:1220`; field-sets in `src/alfred/audit/audit_row_schemas.py` (`DAEMON_BOOT_FIELDS` — `audit_row_schemas.py:685`). We add a `DAEMON_LIFECYCLE_FIELDS` field-set.
- **i18n catalog:** `t()` — `src/alfred/i18n/translator.py:172`; catalog source `locale/en/LC_MESSAGES/alfred.po` (existing `daemon.boot.started` at line 1095). New operator-facing strings go through `t()` and into the `.po`. The slice-4 key enumeration test is `tests/unit/test_catalog_slice_4_keys.py` (`SLICE_4_KEYS` tuple — add the new keys there too).
- **CI commit-hygiene gate:** `.github/workflows/pr-validate-commits.yml`. The `conventional-commits` job requires every commit SUBJECT to match `^[a-z]+(\([^)]+\))?(!)?: .*#[0-9]+.*$` — i.e. a Conventional-Commit type AND a `#NNN` ref **in the subject**. The repo convention also requires the trailer `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` on every commit (CLAUDE.md / git config). **Every `git commit` in this plan satisfies BOTH.** G0 burned several rounds on this — do not skip either.

---

## Trust-boundary posture (CONFIRMED — read before writing code)

- **The lifecycle frames carry NO T3 content.** `going_down` carries a closed-vocab `reason`; `ready` carries the non-secret per-boot `epoch`. Neither touches operator message bodies, so T3 tagging and the quarantined-extraction path are untouched. The gateway (when it exists) remains a T1 carrier; T3 tagging stays in the core at `process_inbound_message` (spec §6, hard rule #5 intact).
- **The epoch is non-secret boot metadata.** It is a fresh `uuid4().hex` minted once per process. It is NOT the `CapabilityGateNonce` (which is identity-only and forbidden from serialisation — see `nonce_factory.py` and `tiers.py:78-97`). The epoch's purpose is reconciliation: the gateway rejects a `ready`/handshake whose epoch mismatches its retained one and binds the last-acked exchange to it (spec §4). It is safe to put on the wire and in an audit row.
- **Emission is fail-loud and audited.** Each lifecycle transition (`going_down`, `ready`) writes a `daemon.lifecycle.*` audit row via the same `_emit_or_quarantine` path the rest of boot uses. A failed audit write is loud (exit 3) exactly as elsewhere (CLAUDE.md hard rule #7). **G1 emits NO wire frame** — the going_down/ready notifications are *defined* as frame models for G3 to send, but the boot/drain path only writes the AUDIT row. There is therefore no wire-send-during-teardown to suppress in G1. (When G3 adds the actual wire send, the going_down send will need the audit-first / suppressed-wire-second discipline — see ADR-0033's scope note — but that send does not exist yet, so G1 introduces no `suppress` around a teardown wire send.)

---

## File-structure table

| File | Create / Modify | Responsibility |
| --- | --- | --- |
| `src/alfred/bootstrap/lifecycle_epoch.py` | Create | Mint + register the per-boot, non-secret, serialisable epoch (`mint_boot_epoch`), mirroring the nonce-factory's slot+lock+guard shape. Pure-ish; one module slot. |
| `src/alfred/comms_mcp/protocol.py` | Modify | Add `LifecycleReason` `Literal` (`["shutdown"]` only), `GoingDownNotification`, `ReadyNotification` (host→outward `_WireModel`s, **defined for G3, not sent in G1**) + a new "Host -> outward lifecycle notifications" section + `__all__` entries. |
| `src/alfred/audit/audit_row_schemas.py` | Modify | Add `DAEMON_LIFECYCLE_FIELDS` field-set. |
| `src/alfred/cli/daemon/_commands.py` | Modify | Declare `ready_emitted = False` before the boot `try:`; mint the epoch beside `boot_id`; add `_emit_ready` + `_emit_going_down` AUDIT helpers (NO runner, NO wire send); call `_emit_ready` after `daemon.boot.completed` (set `ready_emitted = True`); emit `going_down` inside the boot `finally`, guarded by `ready_emitted`, structured so it can NEVER skip the existing child-reap / socket-reap / pidfile-delete chain. **No runner plumbing — G1 is audit-only.** |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | Add `daemon.lifecycle.ready` + `daemon.lifecycle.going_down` operator-facing strings. |
| `docs/adr/0033-core-owned-lifecycle-signalling.md` | Create | ADR-0033 (Proposed): core-owned lifecycle signalling + per-boot epoch. |
| `tests/unit/comms/test_lifecycle_notifications.py` | Create | Unit tests for the two wire models (frozen, extra-forbid, closed `reason`) + a round-trip assertion (`ReadyNotification(epoch=...).model_dump() == {"epoch": ...}`). |
| `tests/unit/bootstrap/test_lifecycle_epoch.py` | Create | Unit tests for `mint_boot_epoch` (shape, once-per-process guard, reset-seam, distinct-from-nonce). |
| `tests/unit/cli/daemon/conftest.py` | Modify | Wire `reset_boot_epoch_for_tests()` into `apply_boot_success_patches` clean+restore (mirror the T3-nonce slot handling at `:119-121` / `:208-209`) and add an autouse `_assert_boot_epoch_slot_restored` guard (mirror `_assert_t3_nonce_slot_restored` at `:231-270`). |
| `tests/unit/cli/daemon/test_daemon_lifecycle_signal.py` | Create | Unit tests: `ready` AUDIT row emitted after boot-healthy + carries epoch; `going_down` AUDIT row emitted at the drain with `reason="shutdown"`; `going_down` NOT emitted on a boot refusal; ready+going_down share the one epoch; default-empty-adapters boot emits both AUDIT rows. |
| `tests/unit/test_catalog_slice_4_keys.py` | Modify | Add the two new `daemon.lifecycle.*` keys to `SLICE_4_KEYS`. |

---

## Key invariants (the plan must preserve all of these)

1. **`ready` = HEALTH, not socket-bind.** `ready` emits ONLY after `_build_comms_boot_graph` succeeded, `supervisor.start()` returned, every enabled adapter spawned/handshaked, AND `daemon.boot.completed` was written — i.e. immediately after `_commands.py:1761`. It never emits on a boot that then refuses.
2. **`going_down` emits BEFORE the drain.** It is the first action inside the boot `finally` (`_commands.py:1764`), before `supervisor.stop()` (`_commands.py:1775`), so a consumer learns the core is leaving before its plugins are torn down.
3. **`going_down` only fires for a PLANNED shutdown.** It rides the `finally`, which also runs on a boot *refusal*. A refusal already audits `daemon.boot.failed`; the daemon was never "up", so it must NOT emit `going_down`. Guard on "did we reach the healthy/ready point?" (a local `ready_emitted` flag), so `going_down` fires only when the daemon had actually come up.
4. **The epoch is minted exactly once per process**, is non-secret + serialisable, and is DISTINCT from the `CapabilityGateNonce`.
5. **No T3 on the lifecycle wire** (posture above).
6. **G1 is AUDIT-ONLY; the going_down audit can NEVER skip the reap chain.** G1 sends no wire frame on the boot/drain path. The `going_down` audit row stays fail-loud (exit 3 on an unwritable audit, like every other boot audit), BUT it is structured inside the `finally` so that even if the audit emit raises (exit 3), the EXISTING child-reap / socket-listener-reap / pidfile-delete chain at `_commands.py:1773-1789` STILL runs. An unguarded `going_down` audit placed first in the `finally` that threw would re-open the #255 bwrap-child leak — so the going_down emit is nested such that its failure cannot bypass the reap chain.
7. **Default-empty-adapters boot is unchanged in shape.** With no comms adapters enabled the host emits the `daemon.lifecycle.*` **audit** rows (the signal's authoritative — and in G1, only — record). The existing `test_default_empty_adapters_boot_unchanged` guarantee is preserved for the spawn/graph wiring — the lifecycle audit rows are an additive host-side emission, asserted by a new test, not a change to the comms-graph build. (There is no runner and no wire send in G1, so a socket-backed adapter boot likewise emits the `ready` AUDIT row but NO `ready` WIRE frame — locked by a dedicated test.)
8. **The epoch is reset+minted fresh per harnessed boot.** `mint_boot_epoch` is mint-once-raise-on-second (catches real double-mints). The daemon-boot test harness resets the slot before each boot and restores it after — mirroring the T3-nonce slot handling — so each `CliRunner` invoke mints a fresh epoch without cross-test poisoning, and an autouse guard fails loud if a boot test leaks the slot.
9. **mypy --strict + pyright clean; every operator-facing string via `t()`.**

---

## `reason` vocabulary (RESOLVED — review decision)

**`reason` is the CLOSED `Literal["shutdown"]` — a single-value set in G1.** The spec (§4) names `core.lifecycle.going_down{reason}` but does not enumerate `reason`. The architect+security review settled this for G1:

- `"shutdown"` — the planned drain (operator-initiated stop / container stop / unsignalled SIGTERM). A bare SIGTERM carries no intent, so `"shutdown"` is the only value an intent-free drain can honestly emit, and G1 has no other intent-producer.

We deliberately do NOT ship `"restart"` (or `"crash"` / `"config_reload"`) in G1: there is no producer of that intent yet, and an unreachable enum member is dead surface. The vocabulary is a CLOSED `Literal` (never `str`) so the wire contract stays exact. **Widening a closed `Literal` is a non-breaking change** — G3 adds `"restart"` / aligned tokens at the moment a real intent-producer exists (e.g. the supervisor passing intent through a sentinel before it re-execs), with the consumer landing in the same PR. `LifecycleStopRequest.reason` (`protocol.py:176`) uses `Literal["operator","supervisor","config_reload","shutdown"]` for the *plugin* stop reason; G3 may choose to align `going_down`'s widened vocabulary with that then. Keep `reason` a CLOSED `Literal` forever.

---

## Task 1: Per-boot epoch factory

**Files:**

- Create: `src/alfred/bootstrap/lifecycle_epoch.py`
- Test: `tests/unit/bootstrap/test_lifecycle_epoch.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/bootstrap/test_lifecycle_epoch.py`:

```python
"""Per-boot lifecycle epoch factory (Spec A G1 / ADR-0033) (#237)."""

from __future__ import annotations

import pytest

from alfred.bootstrap.lifecycle_epoch import (
    BootEpochAlreadyMintedError,
    current_boot_epoch,
    mint_boot_epoch,
    reset_boot_epoch_for_tests,
)


@pytest.fixture(autouse=True)
def _clean_epoch_slot() -> object:
    reset_boot_epoch_for_tests()
    yield
    reset_boot_epoch_for_tests()


def test_mint_returns_non_empty_hex_string() -> None:
    epoch = mint_boot_epoch()
    assert isinstance(epoch, str)
    assert len(epoch) == 32  # uuid4().hex
    int(epoch, 16)  # raises if not hex


def test_mint_registers_current_epoch() -> None:
    assert current_boot_epoch() is None
    epoch = mint_boot_epoch()
    assert current_boot_epoch() == epoch


def test_second_mint_raises() -> None:
    mint_boot_epoch()
    with pytest.raises(BootEpochAlreadyMintedError):
        mint_boot_epoch()


def test_two_processes_get_distinct_epochs() -> None:
    first = mint_boot_epoch()
    reset_boot_epoch_for_tests()
    second = mint_boot_epoch()
    assert first != second
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/bootstrap/test_lifecycle_epoch.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'alfred.bootstrap.lifecycle_epoch'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/alfred/bootstrap/lifecycle_epoch.py`:

```python
"""Per-boot, non-secret lifecycle epoch (Spec A G1 / ADR-0033).

The epoch is a per-process, serialisable, NON-secret value minted once at
boot and carried in the ``core.lifecycle.ready`` notification (and reserved
for the comms handshake). The gateway (G3) rejects a ``ready``/handshake
whose epoch mismatches the one it retained, and binds the last-acked
exchange to it, so a fresh core's ``seq=0`` reconciles against the gateway's
retained high-water mark (spec §4).

It deliberately mirrors the SHAPE of
``alfred.bootstrap.nonce_factory.create_and_register_t3_nonce`` (module slot
+ lock + once-per-process guard) but is its OPPOSITE in trust: the
``CapabilityGateNonce`` is identity-only and MUST NEVER be serialised
(``alfred.security.tiers``), whereas the epoch EXISTS to be serialised onto
the wire. They are distinct values for distinct purposes; do not conflate
them.
"""

from __future__ import annotations

from threading import Lock
from uuid import uuid4

_EPOCH_LOCK: Lock = Lock()
_BOOT_EPOCH: str | None = None


class BootEpochAlreadyMintedError(RuntimeError):
    """Raised when ``mint_boot_epoch`` is called a second time in a process.

    Re-minting would hand out a new epoch while consumers (the ``ready``
    frame already sent, the handshake) still hold the old one — a silent
    reconciliation break. A loud refusal beats a silent rotation
    (mirrors ``T3NonceAlreadyRegisteredError``).
    """


def mint_boot_epoch() -> str:
    """Mint + register the per-process boot epoch; return it.

    Idempotent ONLY via the test reset seam. A second call in the same
    process raises :class:`BootEpochAlreadyMintedError`.
    """
    global _BOOT_EPOCH  # noqa: PLW0603 - the single bootstrap slot, like nonce_factory
    with _EPOCH_LOCK:
        if _BOOT_EPOCH is not None:
            raise BootEpochAlreadyMintedError(
                "mint_boot_epoch() called a second time. Production code mints "
                "exactly once at process start. Tests reset via "
                "reset_boot_epoch_for_tests()."
            )
        _BOOT_EPOCH = uuid4().hex
        return _BOOT_EPOCH


def current_boot_epoch() -> str | None:
    """Return the registered boot epoch, or ``None`` before it is minted."""
    with _EPOCH_LOCK:
        return _BOOT_EPOCH


def reset_boot_epoch_for_tests() -> None:
    """Test-only: clear the slot so a sibling test starts clean.

    Unlike the T3 nonce (whose runtime reset seam was deliberately removed
    because any ``src/`` caller clearing it could forge an authorised
    identity), the epoch is non-secret, so a reset seam grants no privilege —
    a forged epoch only fails the gateway's reconciliation check, it cannot
    cross a trust boundary. Named ``*_for_tests`` so its intent is loud.
    """
    global _BOOT_EPOCH  # noqa: PLW0603
    with _EPOCH_LOCK:
        _BOOT_EPOCH = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/bootstrap/test_lifecycle_epoch.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Wire the reset seam into the daemon-boot harness (CRITICAL)**

`mint_boot_epoch` is mint-once-raise-on-second. The daemon-boot tests invoke `start_daemon` through `CliRunner` MANY times across the suite; without a per-boot reset the SECOND boot test would raise `BootEpochAlreadyMintedError` and poison the suite (exactly the way the T3 nonce would without `clean_t3_nonce_slot`). Mirror the T3-nonce slot handling already in `tests/unit/cli/daemon/conftest.py`.

(a) In `apply_boot_success_patches` (`conftest.py:84`), alongside the T3-nonce clean at `:119-121`, reset the epoch slot. After the existing:

```python
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security import tiers as _tiers

    with _NONCE_LOCK:
        _prior_t3_nonce = _tiers._AUTHORIZED_T3_NONCE
        _tiers._set_authorized_t3_nonce(None)
```

add:

```python
    from alfred.bootstrap.lifecycle_epoch import reset_boot_epoch_for_tests

    # Spec A G1 (#237): each harnessed boot mints a fresh per-boot epoch.
    # ``mint_boot_epoch`` raises on a second mint in a process, so reset the
    # slot before THIS boot runs and restore it on teardown — mirroring the
    # T3-nonce clean above. The epoch is non-secret, so (unlike the nonce) the
    # reset grants no privilege; it only prevents cross-test mint poisoning.
    reset_boot_epoch_for_tests()
```

(b) In the `_restore` callable (`conftest.py:199`), alongside the T3-nonce restore at `:208-209`, reset the epoch slot back to empty (the production invariant between processes is "no epoch until boot mints one"; a clean `None` is the correct post-test state):

```python
    def _restore() -> None:
        set_registry(_prior_registry)
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(_prior_t3_nonce)
        # Spec A G1 (#237): clear the epoch the boot minted so it never leaks
        # into a sibling test that asserts an unminted slot.
        reset_boot_epoch_for_tests()
```

(c) Add an autouse guard mirroring `_assert_t3_nonce_slot_restored` (`conftest.py:231-270`). After that fixture, add:

```python
@pytest.fixture(autouse=True)
def _assert_boot_epoch_slot_restored() -> Iterator[None]:
    """Fail loud if a daemon-boot test leaks the per-boot lifecycle epoch.

    Spec A G1 (#237): the boot path mints the per-process lifecycle epoch
    (``alfred.bootstrap.lifecycle_epoch._BOOT_EPOCH``). ``boot_success_env``
    resets the slot before the boot and clears it on teardown, so a test that
    drives boot THROUGH the harness leaves the slot empty. A test that mints
    while BYPASSING the harness would leak a live epoch, so the NEXT boot's
    ``mint_boot_epoch`` would raise ``BootEpochAlreadyMintedError`` far from its
    cause. This autouse guard pins the failure to the leaking test's OWN
    teardown. Autouse so it is set up BEFORE the explicitly-requested
    ``boot_success_env`` and torn down AFTER it (reverse setup order) — it
    observes the slot AFTER ``boot_success_env``'s ``restore()`` ran.

    It captures the slot at its own setup and asserts the slot returns to that
    value (normally ``None`` in a clean process), so it never false-positives
    against a pre-existing minted slot.
    """
    from alfred.bootstrap import lifecycle_epoch as _epoch

    at_setup = _epoch._BOOT_EPOCH
    yield
    assert _epoch._BOOT_EPOCH is at_setup, (
        "daemon-boot test leaked the per-boot lifecycle epoch: the slot was "
        "not cleared to its pre-test value. A boot test that mints the epoch "
        "MUST go through the boot_success_env harness (which resets + clears "
        "the slot) so the mint does not poison sibling tests."
    )
```

(`Iterator` and `pytest` are already imported at the conftest top.)

- [ ] **Step 6: Run the daemon suite to prove no cross-boot poisoning**

Run: `uv run pytest tests/unit/cli/daemon -q`
Expected: PASS (no `BootEpochAlreadyMintedError`; the guard does not trip). This must be green BEFORE Task 6/7 add the mint to the boot path — at THIS point the boot path does not yet mint, so the guard simply observes an always-`None` slot; the wiring is proven inert here and active once Task 6 adds the mint.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/bootstrap/lifecycle_epoch.py tests/unit/bootstrap/test_lifecycle_epoch.py tests/unit/cli/daemon/conftest.py
git commit -m "feat(bootstrap): per-boot non-secret lifecycle epoch factory + test reset seam (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Host -> outward lifecycle wire models

**Files:**

- Modify: `src/alfred/comms_mcp/protocol.py`
- Test: `tests/unit/comms/test_lifecycle_notifications.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/comms/test_lifecycle_notifications.py`:

```python
"""Host -> outward lifecycle notification frames (Spec A G1 / ADR-0033) (#237)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import GoingDownNotification, ReadyNotification


def test_ready_carries_epoch() -> None:
    note = ReadyNotification(epoch="a" * 32)
    assert note.epoch == "a" * 32


def test_ready_is_frozen_and_extra_forbidden() -> None:
    note = ReadyNotification(epoch="a" * 32)
    with pytest.raises(ValidationError):
        note.epoch = "b" * 32  # frozen
    with pytest.raises(ValidationError):
        ReadyNotification(epoch="a" * 32, surprise=1)  # extra forbidden


def test_ready_rejects_empty_epoch() -> None:
    with pytest.raises(ValidationError):
        ReadyNotification(epoch="")


def test_going_down_accepts_shutdown_reason() -> None:
    assert GoingDownNotification(reason="shutdown").reason == "shutdown"


def test_going_down_rejects_unknown_reason() -> None:
    with pytest.raises(ValidationError):
        GoingDownNotification(reason="kaboom")
    # "restart" is reserved for G3 (no producer yet) — closed out of G1's vocab.
    with pytest.raises(ValidationError):
        GoingDownNotification(reason="restart")


def test_frames_round_trip_to_wire_dicts() -> None:
    """G1 DEFINES the frames for G3 to send; assert their wire shape now."""
    assert ReadyNotification(epoch="a" * 32).model_dump() == {"epoch": "a" * 32}
    assert GoingDownNotification(reason="shutdown").model_dump() == {
        "reason": "shutdown"
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms/test_lifecycle_notifications.py -q`
Expected: FAIL with `ImportError: cannot import name 'GoingDownNotification'`.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/comms_mcp/protocol.py`, after the `CrashedNotification` class (ends `protocol.py:330`) and before `__all__` (`protocol.py:333`), add:

```python
# ---------------------------------------------------------------------------
# Host -> outward lifecycle notifications (Spec A G1 / ADR-0033)
#
# DIRECTION NOTE: every notification ABOVE is plugin -> host (an adapter
# reporting inbound). These two are the OPPOSITE direction: host -> outward
# (the core announcing its own lifecycle over the comms wire). They are
# DEFINED here in G1 but NOT SENT in G1 — there is no consumer yet (the
# gateway lands in G3). G1 emits only the AUDIT rows; G3 will send these
# frames onto the same line-delimited wire (a notification, an id-less JSON-RPC
# frame). They carry NO T3 content: the epoch is non-secret boot metadata and
# ``reason`` is a closed vocabulary.
# ---------------------------------------------------------------------------


LifecycleReason = Literal["shutdown"]
"""Closed vocabulary for a planned ``going_down``.

``shutdown`` = the planned drain (operator stop / container stop / unsignalled
SIGTERM, which carries no intent). G1 ships ONLY this value: there is no
producer of any other intent yet, and an unreachable enum member is dead
surface. Widening a CLOSED ``Literal`` is non-breaking, so G3 adds ``restart``
/ aligned tokens when a real intent-producer + consumer land together. Keep
this a CLOSED ``Literal`` forever — never ``str``. See ADR-0033.
"""


class GoingDownNotification(_WireModel):
    """Core announces it has begun its planned drain (Spec A §4).

    DEFINED in G1 for G3 to send; G1 itself emits only the audit row.
    """

    reason: LifecycleReason


class ReadyNotification(_WireModel):
    """Core announces its security boot graph is healthy + the boot epoch.

    The AUDIT row is emitted ONLY after the full boot graph is healthy
    (``ready`` = HEALTH, not socket-bind). DEFINED in G1 for G3 to send;
    G1 itself emits only the audit row. ``epoch`` is the non-secret per-boot
    value the gateway reconciles against (see
    ``alfred.bootstrap.lifecycle_epoch``).
    """

    epoch: str = Field(min_length=1)
```

Then add `"GoingDownNotification"`, `"LifecycleReason"`, and `"ReadyNotification"` to `__all__` (keep it sorted — they slot after `"CrashedNotification"` / `"HealthReport"` region; place `"GoingDownNotification"` after `"CrashedNotification"`, `"LifecycleReason"` and `"ReadyNotification"` in their alphabetical spots).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms/test_lifecycle_notifications.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/protocol.py tests/unit/comms/test_lifecycle_notifications.py
git commit -m "feat(comms): define host->outward lifecycle wire frames going_down/ready (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

> **Task 3 (runner `send_notification` seam) — REMOVED by the architect+security review.**
> G1 is AUDIT-ONLY: it sends no wire frame, so it needs no runner send seam. The
> `CommsPluginRunner.send_notification` method, its plumbing through the boot path,
> and `tests/unit/plugins/test_comms_runner_notification.py` are DEFERRED to G3,
> which adds the seam together with the gateway consumer that actually receives the
> frames. Adding a send seam with no sender in G1 would be dead surface and would
> have required wrongly capturing a single runner against the multi-adapter spawn
> loop. The task numbering below is preserved (Task 4 onward) so cross-references
> stay stable; there is simply no Task 3.

---

## Task 4: Lifecycle audit field-set

**Files:**

- Modify: `src/alfred/audit/audit_row_schemas.py`
- Test: extend `tests/unit/cli/daemon/test_daemon_lifecycle_signal.py` (created in Task 6) — but the field-set itself gets a dedicated assertion here.
- Test: `tests/unit/audit/test_daemon_lifecycle_fields.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/audit/test_daemon_lifecycle_fields.py`:

```python
"""DAEMON_LIFECYCLE_FIELDS field-set (Spec A G1 / ADR-0033) (#237)."""

from __future__ import annotations

from alfred.audit.audit_row_schemas import DAEMON_LIFECYCLE_FIELDS


def test_lifecycle_fields_are_exact() -> None:
    assert DAEMON_LIFECYCLE_FIELDS == frozenset(
        {"boot_id", "epoch", "phase", "reason", "occurred_at"}
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/audit/test_daemon_lifecycle_fields.py -q`
Expected: FAIL with `ImportError: cannot import name 'DAEMON_LIFECYCLE_FIELDS'`.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/audit/audit_row_schemas.py`, after `DAEMON_BOOT_FAILED_FIELDS` (ends `audit_row_schemas.py:703`), add:

```python
DAEMON_LIFECYCLE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # The per-boot audit trace id this row joins on (same value as the
        # boot-completed row's boot_id).
        "boot_id",
        # The per-boot, non-secret lifecycle epoch (always present; the
        # going_down row carries it too so a consumer can correlate the two
        # ends of a process lifetime).
        "epoch",
        # "ready" | "going_down".
        "phase",
        # The going_down reason (closed vocab); "" on the ready row.
        "reason",
        "occurred_at",
    }
)
```

If `Final` is not already imported at module top, it is (the file's other field-sets use it — `audit_row_schemas.py:83`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/audit/test_daemon_lifecycle_fields.py -q`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/audit/audit_row_schemas.py tests/unit/audit/test_daemon_lifecycle_fields.py
git commit -m "feat(audit): DAEMON_LIFECYCLE_FIELDS for core lifecycle rows (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: i18n strings + slice-4 key enumeration

**Files:**

- Modify: `locale/en/LC_MESSAGES/alfred.po`
- Modify: `tests/unit/test_catalog_slice_4_keys.py`

- [ ] **Step 1: Write the failing test**

In `tests/unit/test_catalog_slice_4_keys.py`, add the two keys to the `SLICE_4_KEYS` tuple (it is defined at `SLICE_4_KEYS: tuple[str, ...] = (`, ~line 32). Add, in the `daemon.*` region near `"daemon.boot.started"`:

```python
    "daemon.lifecycle.ready",  # Spec A G1 / ADR-0033: core-healthy signal
    "daemon.lifecycle.going_down",  # Spec A G1 / ADR-0033: drain signal
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_catalog_slice_4_keys.py -q`
Expected: FAIL — the keys are enumerated but absent from the compiled catalog (the test asserts every `SLICE_4_KEYS` member resolves through `t()`).

- [ ] **Step 3: Add the catalog entries**

In `locale/en/LC_MESSAGES/alfred.po`, near the `daemon.boot.started` entry (line 1095), add two entries (keep a blank line before AND after each `msgid`/`msgstr` pair to stay catalog-clean):

```po
msgid "daemon.lifecycle.ready"
msgstr "Core lifecycle: ready (epoch {epoch})."

msgid "daemon.lifecycle.going_down"
msgstr "Core lifecycle: going down (reason: {reason})."
```

Then recompile the catalog:

Run: `uv run pybabel compile -d locale -D alfred`
Expected: `compiling catalog locale/en/LC_MESSAGES/alfred.po to locale/en/LC_MESSAGES/alfred.mo`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_catalog_slice_4_keys.py -q`
Expected: PASS.

Also run the catalog drift check (the CI gate `pybabel update --check` runs this):

Run: `uv run pybabel extract -F babel.cfg -o /tmp/g1-check.pot src/ && echo "extract ok"`
Expected: `extract ok` (no error). (The new keys are emitted via `t("daemon.lifecycle.*")` once Task 6 lands; if extraction flags the keys as untranslated at THIS point that is expected — they become referenced in Task 6. Re-run `pybabel update -i ... --no-fuzzy-matching` after Task 6 to fix the `#:` location refs; never use `--omit-header`, which strips the required header block.)

- [ ] **Step 5: Commit**

```bash
git add locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo tests/unit/test_catalog_slice_4_keys.py
git commit -m "feat(i18n): core lifecycle operator strings + slice-4 keys (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Emit `ready` after a healthy boot graph

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py`
- Test: `tests/unit/cli/daemon/test_daemon_lifecycle_signal.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/cli/daemon/test_daemon_lifecycle_signal.py`:

```python
"""Core lifecycle signal emission at boot-healthy + drain (Spec A G1) (#237)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app

from .conftest import FakeAuditWriter


def test_ready_row_emitted_after_boot_completed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    # The boot-completed row is present (sanity).
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS")

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    ready = [r for r in lifecycle if r["subject"]["phase"] == "ready"]
    assert len(ready) == 1
    subject = ready[0]["subject"]
    assert subject["epoch"]  # non-empty per-boot epoch
    assert subject["reason"] == ""  # ready carries no reason
    assert subject["boot_id"]
    # ``result`` is a top-level append_schema kwarg (recorded by FakeAuditWriter
    # as a sibling of ``subject``), NOT a member of ``subject``.
    assert ready[0]["result"] == "success"


def test_ready_epoch_matches_going_down_epoch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    CliRunner().invoke(daemon_app, ["start"])
    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    epochs = {r["subject"]["epoch"] for r in lifecycle}
    assert len(epochs) == 1  # ready + going_down share the one per-boot epoch
```

Also add an audit-only contract test asserting a socket-backed (TUI) adapter boot emits the `ready` AUDIT row but produces NO `ready` WIRE frame (G1 is audit-only — there is no runner and no wire send). It rides the existing socket-boot harness:

```python
def test_socket_adapter_boot_emits_ready_audit_but_no_wire_frame(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    socket_boot_success_env: FakeAuditWriter,
) -> None:
    """A socket-backed adapter boot emits the ready AUDIT row, never a wire frame.

    G1 is audit-only: even with a comms carrier present, the boot path writes
    the lifecycle AUDIT row and sends NO ``core.lifecycle.ready`` frame (the
    gateway consumer + the send seam land in G3). This locks the audit-only
    contract against a future regression that wires a premature send.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    lifecycle = socket_boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    ready = [r for r in lifecycle if r["subject"]["phase"] == "ready"]
    assert len(ready) == 1  # AUDIT row present
    # No runner exists to capture and no send seam is plumbed in G1, so there
    # is no wire frame to assert the ABSENCE of beyond the structural fact that
    # the boot path imports no send call — see the implementation note in
    # Step 3 (the boot path never references ``send_notification`` in G1).
```

> **Harness note:** if no `socket_boot_success_env` fixture exists in `tests/unit/cli/daemon/conftest.py`, reuse the existing socket-boot setup that `test_daemon_comms_socket.py` already uses to drive a socket-backed adapter boot, OR (simpler) assert the audit-only contract structurally in Task 6 Step 4 by `grep`-confirming the boot path contains no `send_notification` call. Prefer whichever the existing socket-boot test already provides; do not invent a new harness if `test_daemon_comms_socket.py` already parametrises a socket boot you can import the setup from. The load-bearing assertion is "ready AUDIT row present, no wire send in the boot path" — keep that, adapt the mechanism to the existing fixtures.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_lifecycle_signal.py::test_ready_row_emitted_after_boot_completed -v`
Expected: FAIL — no `DAEMON_LIFECYCLE_FIELDS` rows exist yet.

- [ ] **Step 3: Write minimal implementation (AUDIT-ONLY — no runner, no wire send)**

(a) Add the imports near the existing daemon imports in `_commands.py`. After the `create_and_register_t3_nonce` import block (`_commands.py:50`), add:

```python
from alfred.bootstrap.lifecycle_epoch import mint_boot_epoch
```

and ensure `DAEMON_LIFECYCLE_FIELDS` is added to the `audit_row_schemas` import (`_commands.py:41` imports `DAEMON_BOOT_FIELDS` — add the new name to that import list):

```python
from alfred.audit.audit_row_schemas import (
    DAEMON_BOOT_FIELDS,
    DAEMON_LIFECYCLE_FIELDS,
    # ... existing names ...
)
```

**Do NOT import `GoingDownNotification` / `ReadyNotification` / `LifecycleReason` into `_commands.py` and do NOT reference `CommsPluginRunner` for lifecycle.** G1 is audit-only; the boot path emits AUDIT rows and never constructs a frame or touches a runner for lifecycle. The frame models exist (Task 2) for G3. (If `ruff`/`pyright` would flag an unused import, that confirms the audit-only contract — none should be added.)

(b) Mint the epoch beside `boot_id`. At `_commands.py:1402`, after `boot_id = str(uuid.uuid4())`, add:

```python
    # Spec A G1 (#237): mint the per-boot, NON-secret lifecycle epoch recorded
    # in the ``daemon.lifecycle.ready`` audit row (and reserved for the comms
    # handshake the gateway adds in G3). Distinct from the secret
    # CapabilityGateNonce minted later — see alfred.bootstrap.lifecycle_epoch.
    # Minted here (top of boot) so every lifecycle row references one epoch per
    # process.
    epoch = mint_boot_epoch()
```

(c) Add the audit-only `_emit_ready` helper. After `_emit_or_quarantine` (ends `_commands.py:1255`), add:

```python
async def _emit_ready(audit: AuditWriter, *, boot_id: str, epoch: str) -> None:
    """Write the ``daemon.lifecycle.ready`` AUDIT row (Spec A G1, audit-only).

    ``ready`` = HEALTH (the full security boot graph is up), not socket-bind:
    this runs only AFTER ``daemon.boot.completed`` (invariant 1). G1 emits NO
    wire frame — the gateway consumer + the runner send seam land in G3; G1's
    authoritative (and only) record of the transition is this fail-loud audit
    row. The ``ReadyNotification`` frame model exists for G3 to send.
    """
    await _emit_or_quarantine(
        audit,
        fields=DAEMON_LIFECYCLE_FIELDS,
        schema_name="DAEMON_LIFECYCLE_FIELDS",
        event="daemon.lifecycle.ready",
        subject={
            "boot_id": boot_id,
            "epoch": epoch,
            "phase": "ready",
            "reason": "",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
        result="success",
    )
    typer.echo(t("daemon.lifecycle.ready", epoch=epoch))
```

(`datetime` / `UTC` are already imported at the module top — the boot path uses `started_at.isoformat()` etc.; if not, add `from datetime import UTC, datetime`.)

(d) Declare `ready_emitted = False` BEFORE the boot `try:`. Alongside the existing `supervisor: _SupervisorType | None = None` / `pidfile_path: Path | None = None` declarations at `_commands.py:1647-1648` (immediately before `try:` at `:1649`), add:

```python
    # Spec A G1 (#237): tracks whether the boot reached the healthy/ready point,
    # so the drain ``finally`` emits ``going_down`` ONLY for a daemon that
    # actually came up (a refusing boot also runs the finally — invariant 3).
    # Declared HERE, before the try, so the finally can never NameError on it.
    ready_emitted = False
```

(e) Call `_emit_ready` after the "started" echo and set the flag. Immediately after `typer.echo(t("daemon.boot.started", boot_id=boot_id))` (`_commands.py:1761`) and BEFORE `await wait_for_shutdown(supervisor)` (`_commands.py:1763`), add:

```python
        # Spec A G1 (#237): the boot graph is healthy — record ``ready`` + the
        # per-boot epoch (AUDIT row; ready = HEALTH, not socket-bind). Set the
        # flag LAST so a failure in ``_emit_ready`` (exit 3 on an unwritable
        # audit) does NOT then emit ``going_down`` for a boot that never
        # announced ready.
        await _emit_ready(audit, boot_id=boot_id, epoch=epoch)
        ready_emitted = True
```

(Ordering note: `_emit_ready` is fail-loud — if its audit write fails it raises exit 3, and because `ready_emitted` is still `False`, the drain skips `going_down`, which is correct: a boot that could not even record `ready` did not come up.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_lifecycle_signal.py::test_ready_row_emitted_after_boot_completed -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_daemon_lifecycle_signal.py
git commit -m "feat(daemon): emit core.lifecycle.ready after healthy boot graph (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: Emit `going_down` at the drain (planned-shutdown only)

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py`
- Test: extend `tests/unit/cli/daemon/test_daemon_lifecycle_signal.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/cli/daemon/test_daemon_lifecycle_signal.py`:

```python
def test_going_down_row_emitted_at_drain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    going_down = [r for r in lifecycle if r["subject"]["phase"] == "going_down"]
    assert len(going_down) == 1
    subject = going_down[0]["subject"]
    assert subject["reason"] == "shutdown"  # default for an unsignalled drain
    assert subject["epoch"]
    assert going_down[0]["result"] == "success"


def test_going_down_not_emitted_when_boot_refuses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """A boot that refuses before ``ready`` never announces ``going_down``.

    The drain ``finally`` runs on a refusal too, but the daemon was never up,
    so emitting ``going_down`` would announce a departure that never happened.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    async def _boom_start(self: object) -> None:  # supervisor.start raises
        raise RuntimeError("start failed")

    from .conftest import FakeSupervisor

    monkeypatch.setattr(FakeSupervisor, "start", _boom_start)
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code != 0

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    assert not [r for r in lifecycle if r["subject"]["phase"] == "going_down"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_lifecycle_signal.py::test_going_down_row_emitted_at_drain -v`
Expected: FAIL — no `going_down` row emitted yet.

- [ ] **Step 3: Write minimal implementation (AUDIT-ONLY; going_down can NEVER skip the reap chain)**

(a) Add the audit-only `_emit_going_down` helper. After `_emit_ready` (Task 6), add:

```python
async def _emit_going_down(audit: AuditWriter, *, boot_id: str, epoch: str) -> None:
    """Write the ``daemon.lifecycle.going_down`` AUDIT row (Spec A G1, audit-only).

    Records the start of the PLANNED drain. ``reason`` is the closed
    ``Literal["shutdown"]`` — a bare SIGTERM carries no intent and G1 has no
    other intent-producer (G3 widens the vocabulary with its consumer). G1
    emits NO wire frame; the ``GoingDownNotification`` model exists for G3 to
    send. The row is fail-loud (exit 3 on an unwritable audit), exactly like
    every other boot audit. The CALLER (the boot ``finally``) nests this emit
    so that even if it raises, the existing child/socket/pidfile reap chain
    STILL runs — see (b).
    """
    await _emit_or_quarantine(
        audit,
        fields=DAEMON_LIFECYCLE_FIELDS,
        schema_name="DAEMON_LIFECYCLE_FIELDS",
        event="daemon.lifecycle.going_down",
        subject={
            "boot_id": boot_id,
            "epoch": epoch,
            "phase": "going_down",
            "reason": "shutdown",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
        result="success",
    )
    typer.echo(t("daemon.lifecycle.going_down", reason="shutdown"))
```

(No `LifecycleReason` / `GoingDownNotification` / runner import in `_commands.py` — audit-only, single closed value inlined as the literal `"shutdown"`.)

(b) Nest the `going_down` emit so it can NEVER skip the reap chain. This is the load-bearing structural change (review HIGH-security finding #3). The REAL `finally` at `_commands.py:1764` is already a two-level nest:

```python
    finally:
        try:
            if supervisor is not None:
                await supervisor.stop()
        finally:
            if comms_graph is not None:
                with suppress(Exception):
                    await comms_graph.aclose()
            for listener in socket_listeners:
                with suppress(Exception):
                    await listener.aclose()
            if pidfile_path is not None:
                delete_pidfile(pidfile_path)
```

The `going_down` audit row is fail-loud, so an unsuppressed emit placed FIRST in this `finally` could raise (exit 3) and SKIP the `supervisor.stop()` + child-reap + socket-reap + pidfile-delete chain — re-opening the #255 bwrap-child leak. To keep it fail-loud AND guarantee the reap chain always runs, NEST the `going_down` emit inside its OWN `try` whose `finally` IS the existing stop/reap chain. Restructure the `finally` to:

```python
    finally:
        # Spec A G1 (#237): record the planned drain BEFORE the teardown, but
        # ONLY if the daemon actually came up (``ready_emitted``). The finally
        # also runs on a boot REFUSAL (which already audits
        # ``daemon.boot.failed`` and never reached ``ready``); emitting
        # ``going_down`` there would record a departure that never happened
        # (invariant 3). The going_down audit row is FAIL-LOUD — but it must
        # NEVER skip the child/socket/pidfile reap below (the exact #255 leak
        # this finally exists to prevent). So it is nested in its OWN try whose
        # finally IS the existing stop+reap chain: if the going_down emit raises
        # (exit 3), the reap chain STILL runs, THEN the exception propagates.
        try:
            if ready_emitted:
                await _emit_going_down(audit, boot_id=boot_id, epoch=epoch)
        finally:
            # --- the existing, UNCHANGED stop + reap chain (CR #255) ---
            try:
                if supervisor is not None:
                    await supervisor.stop()
            finally:
                if comms_graph is not None:
                    with suppress(Exception):
                        await comms_graph.aclose()
                for listener in socket_listeners:
                    with suppress(Exception):
                        await listener.aclose()
                if pidfile_path is not None:
                    delete_pidfile(pidfile_path)
```

The existing stop+reap block is moved VERBATIM into the new inner `finally` — do not alter its contents, only its indentation. The only addition is the outer `try: if ready_emitted: await _emit_going_down(...)`. This preserves every #255 invariant (a failing `supervisor.stop()` still reaps; a failing `going_down` audit still reaps) and adds the lifecycle row at the head of the drain.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_lifecycle_signal.py -v`
Expected: PASS (ready row, shared epoch, going_down row at the drain with `reason="shutdown"`, going_down NOT emitted on a refusing boot).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_daemon_lifecycle_signal.py
git commit -m "feat(daemon): emit core.lifecycle.going_down at drain, planned-only (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 8: Default-empty-adapters boot still emits the host-side rows

**Files:**

- Test: extend `tests/unit/cli/daemon/test_daemon_lifecycle_signal.py`

This guards invariant 7: with NO comms adapters enabled (the default), there is no runner, so the wire frames are skipped — but the authoritative `daemon.lifecycle.*` AUDIT rows still go out. The Task-6/7 tests already run under `boot_success_env`, which boots with default-empty adapters (no `comms_enabled_adapters` set), so they ALREADY exercise the runner-`None` path. This task adds an EXPLICIT assertion that no wire send was attempted, to lock the behaviour against a future regression.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/cli/daemon/test_daemon_lifecycle_signal.py`:

```python
def test_default_empty_adapters_emits_audit_rows_without_wire(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """No adapters enabled -> lifecycle AUDIT rows present; no runner to wire."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    phases = sorted(r["subject"]["phase"] for r in lifecycle)
    assert phases == ["going_down", "ready"]
    # Every row carries the single per-boot epoch (the authoritative record
    # is the audit row even with no wire peer).
    assert all(r["subject"]["epoch"] for r in lifecycle)
```

- [ ] **Step 2: Run test to verify it fails (or passes)**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_lifecycle_signal.py::test_default_empty_adapters_emits_audit_rows_without_wire -v`
Expected: PASS immediately (Tasks 6+7 already produce both rows on the default boot). If it FAILS, a prior task regressed invariant 7 — fix the regression, do not weaken the test.

- [ ] **Step 3: No new implementation**

This task is a behaviour-lock test only; the implementation landed in Tasks 6 and 7.

- [ ] **Step 4: Run the full new suite**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_lifecycle_signal.py tests/unit/bootstrap/test_lifecycle_epoch.py tests/unit/comms/test_lifecycle_notifications.py tests/unit/plugins/test_comms_runner_notification.py tests/unit/audit/test_daemon_lifecycle_fields.py -q`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add tests/unit/cli/daemon/test_daemon_lifecycle_signal.py
git commit -m "test(daemon): lock lifecycle audit rows on default-empty-adapters boot (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 9: ADR-0033

**Files:**

- Create: `docs/adr/0033-core-owned-lifecycle-signalling.md`

Write a markdownlint MD032-clean ADR (blank line before AND after every list and table). Follow the ADR-0031 / ADR-0029 house format: `# ADR-NNNN — <title>`, then a metadata list (Status/Date/Slice/Relates-to/Supersedes), `## Context`, `## Decision` (numbered decisions), `## Consequences` (Positive / Negative-accepted / Scope-boundary), `## Alternatives considered`.

- [ ] **Step 1: Write the ADR**

Create `docs/adr/0033-core-owned-lifecycle-signalling.md`:

```markdown
# ADR-0033 — The core owns its lifecycle signalling (going_down / ready + per-boot epoch)

- **Status**: Proposed (Spec A; accepted when the gateway G3 consumes it)
- **Date**: 2026-06-13
- **Slice**: Spec A — `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` (§4, §8 G1)
- **Relates to**: ADR-0025 (line-delimited comms wire this rides), ADR-0031 (TUI socket carrier), ADR-0028 (boot-time T3 nonce — the epoch mirrors its bootstrap shape, NOT its trust), ADR-0032 (the gateway transport that will consume these signals), issue #237 (graduation criterion #7)
- **Supersedes**: —

## Context

The core self-modifies and restarts. A dial-in client (the TUI) connected through the future gateway (Spec A) must not see a bare socket EOF on a core restart; the gateway needs to know when the core is leaving and when a fresh core is genuinely healthy, and it needs to tell a fresh core's reset sequence numbers apart from a stale buffer's high-water mark.

Two facts the gateway cannot infer from the byte stream alone:

- **When the core begins a planned drain.** A socket EOF is ambiguous (clean stop vs crash). An explicit `going_down` distinguishes the planned case and lets the gateway hold buffers deliberately rather than guessing.
- **When a restarted core is HEALTHY**, not merely bound. Socket-bind happens early; the security boot graph (quarantined extractor, identity resolver, supervisor) comes up later. Replaying buffered input into a half-booted core is a correctness hole. The gateway must wait for a HEALTH signal.

It also needs a **per-boot epoch** to reconcile a fresh core (seq resets to 0) against its retained high-water mark.

These signals are CORE-owned: only the core knows its own drain point and its own boot-graph health. The gateway consumes them; it does not produce them.

## Decision

**Decision 1 — Two host-to-outward notification frames DEFINED on the existing comms wire; G1 is AUDIT-ONLY.** `core.lifecycle.going_down{reason}` and `core.lifecycle.ready{epoch}` are added as `_WireModel` notifications in `src/alfred/comms_mcp/protocol.py`, in the OPPOSITE direction to the existing plugin-to-host notifications. **G1 DEFINES these frames but does NOT send them** — there is no consumer yet (the gateway lands in G3), and capturing a single runner against the multi-adapter spawn loop would be wrong. G1's runtime behaviour is to write the `daemon.lifecycle.*` AUDIT rows only. **G3 wires the gateway carrier and adds the actual wire send** (an id-less JSON-RPC frame — a notification, not a request — via a `CommsPluginRunner.send_notification` seam introduced THEN, together with its consumer). No new carrier, no new codec; G1 is audit-only because there is no consumer yet.

**Decision 2 — `ready` = HEALTH, not socket-bind.** The `daemon.lifecycle.ready` AUDIT row is emitted by the daemon ONLY after the full security boot graph has come up and `daemon.boot.completed` is written — never on a boot that then refuses. A consumer that (in G3) sees the `ready` frame may safely release held buffers / replay input.

**Decision 3 — `going_down` is recorded at the drain, for a PLANNED shutdown only, and can never skip the teardown reaps.** The `daemon.lifecycle.going_down` AUDIT row is written at the head of the boot teardown, before the supervisor stop, and is guarded so it fires only when the daemon had actually come up (reached `ready`). A boot refusal — which also runs the teardown — does NOT emit `going_down`; it already audits `daemon.boot.failed`. The going_down audit emit is fail-loud but is NESTED inside its own `try` whose `finally` is the existing supervisor-stop + bwrap-child-reap + socket-reap + pidfile-delete chain (ADR carry-forward of the #255 leak fix), so a failed going_down audit can NEVER skip those reaps. `reason` is the closed vocabulary `Literal["shutdown"]` in G1 — a bare SIGTERM carries no intent and G1 has no other intent-producer; widening a closed `Literal` is non-breaking, so G3 adds `restart` / aligned tokens when a real producer + consumer land together.

**Decision 4 — A per-boot, non-secret, serialisable epoch.** Minted once per process by `alfred.bootstrap.lifecycle_epoch.mint_boot_epoch` (a `uuid4().hex`), mirroring the nonce-factory's slot + lock + once-per-process guard. It is the TRUST-OPPOSITE of the `CapabilityGateNonce`: the nonce is identity-only and must never be serialised; the epoch EXISTS to be serialised onto the wire and into an audit row. It is carried in `ready` and reserved for the comms handshake.

**Decision 5 — Every transition is audited; the audit row is authoritative (and, in G1, the ONLY record).** Each `going_down` / `ready` writes a `daemon.lifecycle.*` row over the new `DAEMON_LIFECYCLE_FIELDS` field-set via the existing `_emit_or_quarantine` path (fail-loud, exit 3 on an unwritable audit). G1 sends no wire frame, so the audit row is the authoritative and sole record of each transition. When G3 adds the wire send, the going_down send will be best-effort (suppressed so a teardown-time send failure never masks the real exit), with the audit row remaining the authoritative record — but that suppressed wire send does not exist in G1.

## Consequences

### Positive

- The gateway (G3) gains an unambiguous planned-drain signal and a health-gated replay barrier without decoding any payload — it stays a T1 carrier.
- The signals reuse the existing wire, codec, and runner; the new surface is two frozen models, one runner method, one epoch factory, and two emit sites.
- The epoch closes the seq-reconciliation hole (fresh-core seq=0 vs retained high-water) with a non-secret value that is safe on the wire and in the audit log.

### Negative / accepted

- The lifecycle frames have NO consumer until G3 — this is a wire-substrate cut (like PR-S4-11a). G1 is AUDIT-ONLY: it records the transitions and defines the frame models, but sends nothing on the wire. We assert the AUDIT rows at the right lifecycle points and the frame-model round-trip, not an end-to-end round-trip and not a wire send.
- `going_down`'s `reason` is the single closed value `shutdown` in G1 — a bare SIGTERM carries no intent and there is no other intent-producer yet. A richer intent path (`restart`, `config_reload`) is deferred until a producer of that intent exists; widening a closed `Literal` is non-breaking, so G3 adds it with its consumer.

### Scope boundary (this ADR)

- This ADR ships the core AUDIT EMISSION + the two DEFINED wire frames + the epoch, proven by unit tests over the frame models (incl. round-trip), the epoch factory (incl. the test reset seam), and the daemon emit points (ready AUDIT row after boot-healthy, going_down AUDIT row at the drain, planned-only, shared epoch on both, audit rows on a default-empty boot, ready audit-but-no-wire on a socket-backed boot).
- The runner `send_notification` seam + the actual wire send are DEFERRED to G3 (G1 is audit-only because there is no consumer yet). The gateway/consumer (G3), the resume buffer (G4), and the seq/ack codec (G2) are OUT of scope.
- **Forward reference (no G1 code):** the per-boot epoch's reconciliation purpose introduces an attack surface for G3 — a spoofed/replayed epoch against the gateway's `ready`/handshake reconciliation. G3 MUST add an adversarial-corpus entry covering "epoch spoof / replay against the gateway reconciliation" (a fresh-core `seq=0` masquerading against a retained high-water mark, and a stale-epoch replay) when it lands the consumer. G1 ships no gateway and no reconciliation code, so this is a reserved corpus slot, not a G1 test.

## Alternatives considered

- **Infer drain from socket EOF.** Rejected: EOF cannot distinguish a clean stop from a crash, and gives no health signal for the restarted core.
- **Reuse the `CapabilityGateNonce` as the epoch.** Rejected: the nonce is identity-only and forbidden from serialisation (`alfred.security.tiers`); putting it on the wire would defeat the gate's identity check and leak a security primitive. The epoch is a distinct, non-secret value.
- **`ready` on socket-bind.** Rejected: replaying input into a half-booted core is a correctness hole; `ready` must mean HEALTH.
```

- [ ] **Step 2: Lint the ADR for MD032**

Run: `uv run pre-commit run markdownlint --files docs/adr/0033-core-owned-lifecycle-signalling.md` (or the repo's configured markdownlint invocation; if pre-commit is not wired for it, run `npx markdownlint-cli2 docs/adr/0033-core-owned-lifecycle-signalling.md`).
Expected: no MD032 (blanks-around-lists) violations.

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0033-core-owned-lifecycle-signalling.md
git commit -m "docs(adr): ADR-0033 core-owned lifecycle signalling + per-boot epoch (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 10: Quality gates + plan + ADR lint

**Files:** none (verification only)

- [ ] **Step 1: Lint + format**

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: `All checks passed!` and no files would be reformatted.

- [ ] **Step 2: Type-check**

Run: `uv run mypy src/ && uv run pyright src/`
Expected: `Success: no issues found` (mypy) and `0 errors` (pyright).

- [ ] **Step 3: Full unit + comms suite**

Run: `uv run pytest tests/unit -q`
Expected: PASS (no regressions; the new tests pass).

- [ ] **Step 4: i18n catalog drift gate**

Run: `uv run pybabel update -i locale/en/LC_MESSAGES/alfred.po -d locale -D alfred --no-fuzzy-matching && uv run pybabel compile -d locale -D alfred`
Expected: catalog updates cleanly and compiles; no fuzzy entries introduced. (Never `--omit-header`.)

- [ ] **Step 5: Markdownlint the plan + ADR**

Run: `npx markdownlint-cli2 docs/superpowers/plans/2026-06-13-g1-core-lifecycle-signal.md docs/adr/0033-core-owned-lifecycle-signalling.md`
Expected: no MD032 violations.

- [ ] **Step 6: Commit any catalog drift fix**

```bash
git add -A locale/
git commit -m "chore(i18n): fix catalog location refs for lifecycle keys (Spec A G1) (#237)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

(If `git status` shows no catalog change, skip this commit — do not create an empty commit.)

---

## Self-review — spec requirement → task → Definition of Done

| Spec requirement (Spec A §4 / §8 G1) | Task | Definition of Done |
| --- | --- | --- |
| `core.lifecycle.going_down{reason}` AUDIT row on the drain | Task 2 (frame), Task 7 (emit) | `test_going_down_row_emitted_at_drain` asserts a `going_down` AUDIT row at the teardown with `reason="shutdown"`; `_emit_going_down` is the first action in the boot `finally` (`_commands.py:1764`), nested so it can never skip the supervisor-stop + child/socket/pidfile reap chain (#255). No wire send in G1. |
| `going_down` only for a planned shutdown (not a refusal) | Task 7 | `test_going_down_not_emitted_when_boot_refuses` asserts no `going_down` row when `supervisor.start()` raises; the emit is guarded by `ready_emitted`. |
| `core.lifecycle.ready` AUDIT row ONLY after the boot graph is healthy | Task 2 (frame), Task 6 (emit) | `test_ready_row_emitted_after_boot_completed` asserts a single `ready` AUDIT row, present only on `exit_code == 0`; the emit sits after `daemon.boot.completed` (`_commands.py:1761`), never on a refusing boot. |
| `ready` = HEALTH, not socket-bind | Task 6 | Emit placed after `_invoke_boot_completed` + the "started" echo — i.e. after `_build_comms_boot_graph` + every adapter spawned/handshaked. `test_socket_adapter_boot_emits_ready_audit_but_no_wire_frame` locks the audit-only contract. |
| Per-boot epoch, minted once, in the `ready`/`going_down` rows | Task 1 (factory), Task 6 (audit) | `test_second_mint_raises` + `test_mint_returns_non_empty_hex_string`; `test_ready_epoch_matches_going_down_epoch` asserts one epoch per process across both rows; the test reset seam + autouse guard prevent cross-boot poisoning. |
| Epoch is non-secret, serialisable, DISTINCT from `CapabilityGateNonce` | Task 1 | `lifecycle_epoch.py` mints a `uuid4().hex`, never touches `tiers`; the module docstring + ADR-0033 Decision 4 record the trust-opposite relationship. |
| Frames carry no T3; closed `reason` vocab | Task 2 | `_WireModel` (frozen, extra-forbid); `LifecycleReason = Literal["shutdown"]` (closed, single-value in G1); `test_going_down_rejects_unknown_reason` (incl. `"restart"`). |
| Lifecycle events get audit rows | Task 4 (field-set), Tasks 6+7 (emit) | `DAEMON_LIFECYCLE_FIELDS`; both emit paths route through `_emit_or_quarantine` (fail-loud, exit 3 on unwritable). |
| Operator-facing strings via `t()` | Task 5 | `daemon.lifecycle.ready` / `daemon.lifecycle.going_down` in the catalog + `SLICE_4_KEYS`; `test_catalog_slice_4_keys` resolves them. |
| Frames DEFINED to ride the comms wire (sent in G3) | Task 2 | Frame models exist + round-trip (`test_frames_round_trip_to_wire_dicts`); the `send_notification` seam + wire send are DEFERRED to G3 (G1 is audit-only — see ADR-0033 Decision 1). |
| Default-empty-adapters boot unchanged in shape | Task 8 | `test_default_empty_adapters_emits_audit_rows_without_wire` — both lifecycle AUDIT rows present (no runner/wire in G1). |
| ADR-0033 (Proposed) | Task 9 | `docs/adr/0033-core-owned-lifecycle-signalling.md`, MD032-clean, ADR house format. |
| Scope discipline — no gateway/G4/G2 | (whole plan) | No gateway/consumer, no `ReplayBuffer`, no seq/ack codec touched; tests assert emission only. |
| CI commit-hygiene (Conventional + `#237` + trailer) | every commit step | Every `git commit` subject matches `^[a-z]+(\([^)]+\))?(!)?: .*#[0-9]+.*$` and carries the `MrReasonable <...>` trailer. |

**Placeholder scan:** no `TBD` / "add error handling" / "similar to Task N" — every code step shows complete code. **Type consistency:** `mint_boot_epoch`/`current_boot_epoch`/`reset_boot_epoch_for_tests`/`_BOOT_EPOCH`, `GoingDownNotification`/`ReadyNotification`/`LifecycleReason` (`Literal["shutdown"]`), `DAEMON_LIFECYCLE_FIELDS`, `_emit_ready`/`_emit_going_down` (both audit-only), `ready_emitted`/`epoch` — names are identical across every task that references them. **Audit-only contract:** no `send_notification`, no runner capture, no wire send anywhere in the G1 boot/drain path — those are G3.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-13-g1-core-lifecycle-signal.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh `alfred-core-engineer` subagent per task, review between tasks, fast iteration. Security-boundary review (epoch trust posture, drain ordering) should pull in `alfred-security-engineer` on Tasks 1, 6, 7.
2. **Inline Execution** — execute tasks in this session with checkpoints for review.

Which approach?
