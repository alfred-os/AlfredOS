# G6-7-6 — Forwarded-inbound e2e proof + adversarial-corpus lane promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gateway-forwarded inbound bridge's two remaining `bridge-lands-first` obligations (ADR-0039 §Decision: G6-7-1..6) — (A) an **end-to-end composition proof** that exercises the REAL forwarded pipeline (real socket + real `GatewayForwardedInboundReceiver` + real `process_inbound_message(commit_at_dispatch_edge=True)` + real Postgres G0 idempotency + the real `forwarded_dispatch_attempts` poison ledger), not just the in-process direct-injection adversarial cases; and (B) **promote the adversarial corpus from an advisory paper-gate to a release-blocking required status check** (the `ci.yml:123-127` "governance follow-up, G6-6" the repo already flagged).

**Architecture:** The receive arm, the dispatched-edge ack, and the N=5 poison ceiling already exist and are 100%-unit + in-process-adversarially covered (G6-7-3/-4/-5). The durable store primitive + migration 0020 already have real-Postgres integration tests. What is **not** yet proven is (1) the COMPOSITION — the ceiling logic wired through the real receiver + the real `PostgresForwardedDispatchAttemptStore` (the adversarial suite uses a MOCK store), and (2) the forwarded frame surviving the real socket + seq codec into the real daemon HOST runner. (A) adds two integration tests gated by the already-required `Integration` check. (B) flips `adversarial.yml`'s `continue-on-error`, drops its `paths:` filter so the release-blocking security suite runs on EVERY PR (not just path-matched ones — the merge-gate footgun the manifest warns about), reconciles the now-redundant `tests/adversarial/comms` discrete step, and registers `Adversarial corpus` as a required check. (C) de-stales the G6-7-4 `test_poison_frame_replays_unboundedly_this_slice` guard now the ceiling exists and the leg is e2e-proven.

**Tech Stack:** Python 3.12+/asyncio, pytest + Testcontainers (real Postgres), SQLAlchemy 2.0 async, GitHub Actions YAML, `gh api` branch protection, markdownlint.

---

## Scope fence (what this slice is NOT)

- **NOT the privileged real-spawn proof.** The bwrap quarantine-child real spawn + the `integration-privileged` lane promotion to required is **G6-7-7**. This slice's e2e runs OFF the bwrap child (the in-proc echo double, exactly as `test_chat_gateway_socket_turn.py` does) on the non-root `Integration` runner. The bwrap-gated `tests/adversarial/sandbox_escape` corpus stays gated by `integration-privileged` (it `@_bwrap_required`-skips on the adversarial runner) — flipping `adversarial.yml` does NOT make those a gate; G6-7-7 does.
- **NOT the flag-day.** The gateway Discord leg stays **TEST-ONLY** until **G6-7-8** (delete the daemon-spawn path + Compose `alfred-discord` + secret cutover). This slice proves the forwarded path works end-to-end; it does NOT make a production Discord inbound traverse it.
- **NOT new ceiling/receiver logic.** No `src/alfred/comms_mcp/inbound.py`, `forwarded_inbound_receiver.py`, or `forwarded_dispatch_attempts.py` behaviour change. This slice is tests + CI gating + docs. If a test surfaces a real composition bug, fix it in a clearly-scoped commit and surface it (per the `feedback_fix_dont_dismiss` directive) — but the expectation is the composition is correct and the tests pass against the existing code.
- **NOT a re-proof of receive-side admission e2e (arch-003).** ADR-0039 item-3 (registered-leg / K4 receive-side refusal of a forged or unregistered envelope `adapter_id`) and item-4c (one-path-per-`adapter_id`) are **intentionally NOT re-covered over the real socket** in A1/A2 — they remain gated by the in-process adversarial corpus (G6-7-3/-4, `test_forwarded_inbound_admission.py`). A1's "real chain" framing covers the happy/poison data path, not forge/unregistered admission.
- **NOT a claim that the required `Adversarial corpus` check covers the bwrap escape payloads (sec-001).** The 6 `@_bwrap_required` `tests/adversarial/sandbox_escape` payloads (incl. `sbx-2026-012` fd-3 key-leak, `sbx-2026-013` live host-escape) **SKIP** on the non-root adversarial runner and are **NOT yet on any currently-required check** — `integration-privileged` is still Pending-required (`docs/ci/required-checks.md:70`); promoting it is **G6-7-7's** done-definition. This slice makes the **non-bwrap** corpus release-blocking and discloses this gap loudly (manifest row + ADR amendment + a reasoned-skip guard); it does NOT present the corpus as covering the escape payloads. Promoting `integration-privileged` here is out of scope (it requires the real-spawn lane to be a stable gate first — G6-7-7).

## Decision D-1 (for plan-review — architect + devops + test-engineer)

**How to make the adversarial corpus release-blocking.** Two mechanisms; this plan implements **Mechanism 1** (honoring the repo's stated `ci.yml:123-127` G6-6 intent). Plan-review should confirm or steer to Mechanism 2.

- **Mechanism 1 (this plan): promote the standalone `adversarial.yml`.** Remove `continue-on-error: true`; **drop the `paths:` filter** so the suite runs on every PR (manifest mitigation option 2 — a release-blocking security gate must gate every merge, and an unfiltered trigger removes the "off-path PR ⇒ required check never runs ⇒ merge blocked forever" footgun the `docs/ci/required-checks.md` perf-gate caveat documents); register `Adversarial corpus` as required; **remove** the now-redundant `tests/adversarial/comms` discrete step from the required `python` job (else two required checks run the comms corpus = the `domain_parallel_green_signal` hazard).
- **Mechanism 2 (alternative): fold the whole non-bwrap suite into the already-required `python` job.** Broaden the existing `tests/adversarial/comms` step to `tests/adversarial` (excluding `sandbox_escape`, which is `integration-privileged`'s), then delete `adversarial.yml`. Rides an already-required check — no new registration, no `paths:` footgun, single source of truth. Deviates from the repo's written G6-6 prescription.

The trade-off is cost/locality: Mechanism 1 keeps the suite in its own named check (clean PR-checklist legibility, the repo's stated intent) at the cost of one new required-check registration; Mechanism 2 avoids registration but lengthens the `python` job and silently deletes a workflow. **Recommendation: Mechanism 1**, because the repo author already prescribed it and a separately-named `Adversarial corpus` check is more legible than a buried pytest step. Task B0 measures suite wall-time + Docker-dependence first; if the unfiltered suite is heavy/flaky, plan-review reconsiders.

**Task B0 result (measured 2026-06-23 on the dev mac):** `uv run pytest tests/adversarial -q` → **235 passed, 6 skipped, 0 failed, ~38s wall-clock** (241 collected). The 6 skips are all `tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py` (`bwrap required` — cleanly skipped off-bwrap; gated by G6-7-7's `integration-privileged`). Some cases self-provision a Postgres/Redis testcontainer (`dlp_egress`/`state` legs — Docker is present on the CI `ubuntu-latest` runner, as it already is for the existing advisory `adversarial.yml` run). ~38s on an every-PR required gate is acceptable; no failures, no flake observed. This supports Mechanism 1 with the `paths:` filter dropped.

**PLAN-REVIEW VERDICT (2026-06-23, 5 reviewers — RESOLVED):** Mechanism 1 **CONFIRMED** by architect (arch-001) + devops (ops-001/002) — honors the repo's written `ci.yml` G6-6 intent, a separately-named check is more legible, and dropping the `paths:` filter fully closes the off-path footgun (cleaner than the companion-short-circuit at this ~38s cost). Folded fixes (see each task): the comms-step removal is **deferred to a post-merge follow-up** (sec-003 major + arch-005 + test-005 — no-gate-window); the `corpuscheck` false-branch now **fails the job** (ops-003); the bwrap `sandbox_escape` coverage gap is **disclosed loudly** in the manifest row + ADR + a reasoned-skip guard (sec-001 major); A1 locked to **option (b)** (arch-002 + test-006); A2 rewritten to the proven `test_poison_e2e` template with `pytest.raises` + the `_AlwaysFailOrchestrator` post-extract seam + content-free + G0-not-committed assertions (test-002/003/004 HIGH, sec-004, sec-005, sec-007); C1 corrected — the test uses a `_NonTrippingAttemptStore`, NOT no-store (test-001 HIGH); the manifest row documents the Docker dependence (arch-004/sec-006/ops-006).

## Grounded facts (use these; do not re-derive)

- **Forwarded receive wiring is hardcoded + always-on at boot.** `_FORWARDED_INBOUND_KINDS = ("discord",)` (`src/alfred/cli/daemon/_commands.py:364`); `_build_forwarded_inbound_registry` (`_commands.py:425-446`) builds a `_ForwardedCollaborators` per kind via `_build_sub_payload_promoter` (`_commands.py:312-345`); discord gets a real `SubPayloadPromoter` because `REQUIRED_CLASSIFIERS_BY_KIND["discord"] == frozenset({"discord_sub_payloads"})` (`src/alfred/comms_mcp/classifier_registry.py:38-44`). The registry is built whenever the comms boot graph is built — **no env var gates the discord kind**. So booting with only `alfred_tui` enabled STILL wires a discord-capable forwarded receiver.
- **The socket carrier (kind `"tui"`) auto-receives the receiver.** `_listen_socket_comms_adapter` → `_build_comms_runner(..., with_forwarded_inbound_receiver=True)` (`_commands.py:1432-1437`); the per-connection `BoundedSeqAckTracker` is bound onto the receiver at `_commands.py:1472-1481`. `_SOCKET_BACKED_ADAPTER_KIND = "tui"` (`_commands.py:453`).
- **Receiver ctor** (`src/alfred/comms_mcp/forwarded_inbound_receiver.py:148-166`): `GatewayForwardedInboundReceiver(*, registry, idempotency_store, attempt_store, audit_writer, dispatch=process_inbound_message)`; `set_ack_tracker(tracker)`; `async def receive(self, *, params, wire_seq)`.
- **Wire shape** (`src/alfred/gateway/core_link.py:1246-1252`): `forward_adapter_inbound` emits `json.dumps({"jsonrpc":"2.0","method": GATEWAY_ADAPTER_INBOUND, "params": envelope.model_dump(mode="json")}).encode()`. `GATEWAY_ADAPTER_INBOUND = "gateway.adapter.inbound"` (`src/alfred/comms_mcp/protocol.py:440`); `GatewayAdapterInboundEnvelope(adapter_id: AdapterId, body: bytes | str)` (`protocol.py:540-568`).
- **Routing** (`src/alfred/plugins/inbound_disposition.py:209-219` → `_route_forwarded_inbound` 264-294): a frame whose `method == GATEWAY_ADAPTER_INBOUND` is delegated to the receiver with the lifted leg `wire_seq`.
- **Real-Postgres store primitives ALREADY covered** (do NOT re-cover): `tests/integration/test_forwarded_dispatch_attempts_postgres.py` (atomic UPSERT increment / `attempt_count`), `tests/integration/test_migration_0020_forwarded_dispatch_attempts.py` (table + `result='poisoned'` CHECK). The GAP is the COMPOSITION through the receiver + `process_inbound_message`.
- **Reusable harness:** `tests/integration/cli/daemon/test_chat_gateway_socket_turn.py` (real daemon carrier + real gateway core leg + real Postgres, in-proc echo child double). The discord-bound-user seed pattern + `_ADAPTER_ID="alfred_comms_test"` lives in `tests/integration/cli/daemon/test_daemon_comms_inbound_turn.py:313-336` (`_seed_discord_bound_user`, `Platform.DISCORD`).
- **The ceiling constant** is `_FORWARDED_DISPATCH_ATTEMPT_CEILING = 5` (`src/alfred/comms_mcp/inbound.py`). Bound = at most 5 `quarantined_extract` calls per `(adapter_id, inbound_id)`; poison on the 6th attempt.

## File structure

| File | Responsibility | Action |
|---|---|---|
| `tests/integration/comms/test_forwarded_poison_ceiling_postgres.py` | A2: ceiling composition through the REAL receiver + REAL `PostgresForwardedDispatchAttemptStore` + REAL `PostgresInboundIdempotencyStore` against real Postgres | Create |
| `tests/integration/comms/__init__.py` | package marker (if absent) | Create-if-absent |
| `tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py` | A1: real-socket forwarded discord inbound → real daemon receive → dispatch → real Postgres T3-promotion + dispatched-edge commit | Create |
| `.github/workflows/adversarial.yml` | B: release-blocking (remove `continue-on-error`), unfiltered trigger | Modify |
| `.github/workflows/ci.yml:109-128` | B: remove the now-redundant `tests/adversarial/comms` step; update the G6-6 governance note to "done" | Modify |
| `docs/ci/required-checks.md` | B: add `Adversarial corpus` (Pending stub → promoted post-merge) | Modify |
| `tests/adversarial/comms/test_forwarded_inbound_admission.py` | C: de-stale `test_poison_frame_replays_unboundedly_this_slice` docstring/guard now the ceiling exists + the leg is e2e-proven | Modify |
| `docs/adr/0039-gateway-adapter-inbound-bridge.md` | D: dated G6-7-6 amendment (e2e proof + lane promotion) | Modify |
| `docs/subsystems/comms.md` | D: note the forwarded leg is now e2e-proven + adversarially gated (still test-only until G6-7-8) | Modify |

---

## Task B0: Baseline the adversarial suite (no code change)

**Files:** none (investigation that gates Decision D-1).

- [ ] **Step 1: Run the full suite as `adversarial.yml` would (clean, no explicit services)**

Run: `time uv run pytest tests/adversarial -q`
Record: pass/skip/fail counts + wall-clock + whether any test needed Docker/Postgres (testcontainers). The `sandbox_escape` corpus MUST skip cleanly (no bwrap on this host posture); confirm skips, not errors.

- [ ] **Step 2: Confirm green (no failures, only `@_bwrap_required` / host skips)**

Expected: all non-bwrap adversarial tests PASS; `tests/adversarial/sandbox_escape/*` SKIP. If anything FAILS or ERRORS, STOP — the suite is not gate-ready; surface to plan-review before flipping `continue-on-error`. A red required gate on `main` is the failure mode this step prevents.

- [ ] **Step 3: Record the wall-time + Docker-dependence in the plan-review brief**

If wall-time > ~3 min OR the suite needs Docker for a large fraction, re-evaluate Mechanism 1's "drop the paths filter / run on every PR" against Mechanism 2 (or a `paths`-kept + companion-short-circuit). Note it; do not change anything yet.

---

## Task A2: Poison-ceiling composition against real Postgres

**Files:**

- Create: `tests/integration/comms/test_forwarded_poison_ceiling_postgres.py`
- Create-if-absent: `tests/integration/comms/__init__.py`

This proves the N=5 ceiling composes correctly with the **real** durable `PostgresForwardedDispatchAttemptStore` (the adversarial suite proves the property with a MOCK store; the store-primitive integration test proves the store in isolation; neither proves the composition). Drive a deterministically-failing dispatch through the REAL receiver + REAL `process_inbound_message(commit_at_dispatch_edge=True)` + REAL Postgres idempotency + REAL attempt ledger, and assert the bound holds end-to-end.

- [ ] **Step 1: Create the package marker if missing**

Run: `test -f tests/integration/comms/__init__.py || : > tests/integration/comms/__init__.py`

- [ ] **Step 2: Write the failing test**

Create `tests/integration/comms/test_forwarded_poison_ceiling_postgres.py`:

```python
"""Integration: the forwarded poison ceiling composes correctly with REAL Postgres stores.

Spec B G6-7-6 (#309, ADR-0039 item 4b). The adversarial suite
(``tests/adversarial/comms/test_forwarded_inbound_poison.py``) proves the N=5 ceiling
with a MOCK ``attempt_store``; the store-primitive integration tests
(``test_forwarded_dispatch_attempts_postgres.py`` / ``test_migration_0020_*``) prove the
atomic UPSERT in isolation. NEITHER proves the COMPOSITION: the ceiling logic in
``process_inbound_message(commit_at_dispatch_edge=True)`` driven through the REAL
``GatewayForwardedInboundReceiver`` + the REAL ``PostgresForwardedDispatchAttemptStore``
+ the REAL ``PostgresInboundIdempotencyStore`` against a real Postgres testcontainer.

A deterministically-failing forwarded dispatch is re-delivered N+1 times (mirroring the
forwarding leg's replay). The REAL durable ledger MUST bound ``quarantined_extract`` to
exactly N=5 calls and dead-letter the 6th (``comms.inbound.poisoned`` audit row,
``result='poisoned'``), with the real ``forwarded_dispatch_attempts`` row showing the
monotone count. No socket here — this isolates the durable-store composition; the
real-socket leg is ``test_forwarded_inbound_gateway_to_core_turn.py``.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.comms_mcp.protocol import GatewayAdapterInboundEnvelope
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
from alfred.memory.forwarded_dispatch_attempts import PostgresForwardedDispatchAttemptStore
from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore
from alfred.memory.models import Base

pytestmark = pytest.mark.integration

_ADAPTER_ID = "discord"
_INBOUND_ID = "poison-compose-001"
_CEILING = 5  # bound to the production constant below in Step 5.
```

> **GROUNDING (test-eng test-002/003/004 — corrected):** A2 is `tests/adversarial/comms/test_forwarded_inbound_poison.py::test_poison_e2e_dead_letters_and_releases_stalled_high_water` **with the in-memory fakes swapped for real Postgres stores**. READ that test first — it is the exact composition minus real Postgres. Lift its harness verbatim from the shared spies + the poison module:
>
> - `from tests.unit.comms_mcp._inbound_spies import SpyOrchestrator, SpyAuditWriter, make_notification, ...` (the shared spy harness the poison test already imports).
> - The failure seam is **`_AlwaysFailOrchestrator(SpyOrchestrator)` whose `dispatch` raises `RuntimeError("poison frame")`** (poison test lines 161-167): `quarantined_extract` + `ingest` SUCCEED (real `SpyOrchestrator` increments `quarantined_extract_calls`), only **dispatch** raises — i.e. the failure is the **post-extract tail**, so `increment` fires and the ceiling engages. This is the injectable seam (rev-003 resolved: it rides the `orchestrator` collaborator, NOT a `src/` change). **NEVER force the failure with a permissive gate/extractor stub (sec-005)** — extract/identity/burst stay real; assert `orch.quarantined_extract_calls > 0` so a vacuous "failed before extract" pass is impossible.
> - Lift `_collaborators(...)` (poison lines 170-189) — `sub_payload_promoter=None`, a real `SpyIdentityResolver`, the `_AlwaysFailOrchestrator`, a `SpyBurstLimiter`, a `SpySecretBroker`, and ONE long-lived `_PreResolutionLimiter`. The production registry + real resolver/discord-promoter path is **A1's** job (the socket-chain test); A2 deliberately isolates the **durable-store composition** on the proven collaborator harness, so the only thing real beyond the receiver/pipeline are the three Postgres stores.
> - `_ADAPTER_ID` here is the poison test's reference kind (it uses an in-process plain-text kind so no real promoter is needed); keep that — A2 proves the ledger composition, not discord promotion. (A1 covers the real discord kind.)

- [ ] **Step 3: Write the boot helper (schema + real Postgres stores)**

Add a session-scope factory yielding the THREE real stores + a real `AuditWriter` (no user seed needed — the poison frame never resolves a user; it fails at dispatch):

```python
@asynccontextmanager
async def _real_stores(postgres_url: str) -> AsyncIterator[tuple[
    PostgresForwardedDispatchAttemptStore,
    PostgresInboundIdempotencyStore,
    AuditWriter,
    str,
]]:
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        attempt_store = PostgresForwardedDispatchAttemptStore(session_scope=session_scope)
        idempotency_store = PostgresInboundIdempotencyStore(session_scope=session_scope)
        sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
        yield attempt_store, idempotency_store, AuditWriter(session_factory=session_scope), sync_url
    finally:
        await engine.dispose()
```

> Build the receiver with the REAL stores: `GatewayForwardedInboundReceiver(registry={_ADAPTER_ID: _collaborators(orchestrator=orch)}, idempotency_store=<real PostgresInboundIdempotencyStore>, attempt_store=<real PostgresForwardedDispatchAttemptStore>, audit_writer=<real AuditWriter>)`, then `receiver.set_ack_tracker(BoundedSeqAckTracker())` (a REAL tracker, not the spy — so the drain-releases-high-water property is real). Note the real `AuditWriter` needs the `audit.hash_pepper` env set (`ALFRED_AUDIT.HASH_PEPPER`, ≥32 bytes) for the peppered `inbound_id_hash` — set it in a `_boot_env`-style fixture (mirror `test_chat_gateway_socket_turn._boot_env`).

- [ ] **Step 4: Write the assertion body (corrected — first N replays RAISE)**

```python
@pytest.mark.usefixtures("_boot_env")
async def test_poison_ceiling_bounds_extract_to_N_against_real_postgres(postgres_url: str) -> None:
    async with _real_stores(postgres_url) as (attempt_store, idem_store, audit, sync_url):
        orch = _AlwaysFailOrchestrator()
        tracker = BoundedSeqAckTracker()
        receiver = GatewayForwardedInboundReceiver(
            registry={_ADAPTER_ID: _collaborators(orchestrator=orch)},
            idempotency_store=idem_store,
            attempt_store=attempt_store,
            audit_writer=audit,
        )
        receiver.set_ack_tracker(tracker)
        params = _envelope_params(body=_body(inbound_id=_INBOUND_ID))

        # A healthy frame on seq 0 already drained; the poison rides seq 1 and WEDGES the
        # contiguous high-water at 0 on every failing replay.
        tracker.observe(0)
        assert tracker.cumulative_ack() == 0

        # The first N replays each FAIL dispatch LOUD (post-extract tail) — they MUST be
        # wrapped in pytest.raises (a bare await throws on delivery #1; test-002 fix).
        for _ in range(_CEILING):
            with pytest.raises(RuntimeError, match="poison frame"):
                await receiver.receive(params=params, wire_seq=1)
            assert tracker.cumulative_ack() == 0  # still wedged — poison seq un-observed

        # The (N+1)-th delivery: real-ledger attempt_count == N >= ceiling → dead-letter,
        # NO extract, drain-to-release (does NOT raise).
        await receiver.receive(params=params, wire_seq=1)

        # The extractor was charged EXACTLY N times across N+1 deliveries (real bound).
        assert orch.quarantined_extract_calls == _CEILING
        assert orch.dispatch_calls == _CEILING  # the (N+1)-th never reached dispatch

        # The REAL durable ledger reached the ceiling (>= N — "at least N" semantics).
        assert await attempt_store.attempt_count(adapter_id=_ADAPTER_ID, inbound_id=_INBOUND_ID) >= _CEILING

        # Exactly ONE real comms.inbound.poisoned Postgres row.
        rows = _fetch_audit_rows(sync_url, event="comms.inbound.poisoned")
        assert len(rows) == 1, rows
        assert rows[0]["result"] == "poisoned"

        # sec-004 — CONTENT-FREE (positively asserted, not assumed): the dead-letter row
        # carries the PEPPERED inbound_id hash only — no raw inbound_id, no body bytes.
        row_blob = json.dumps(rows[0], default=str)
        assert _INBOUND_ID not in row_blob, "raw inbound_id leaked into the poisoned row"
        assert "hello there" not in row_blob, "discord body leaked into the poisoned row"

        # sec-007 — G0 NEVER committed on the poison path: no committed-but-undispatched
        # inbound_idempotency row for (adapter, inbound_id) after N+1 poison replays.
        assert await idem_store.has_committed(adapter_id=_ADAPTER_ID, inbound_id=_INBOUND_ID) is False

        # The drain RELEASED the wedge: the real contiguous high-water advanced past seq 1.
        assert tracker.cumulative_ack() == 1
```

Add the `_fetch_audit_rows(sync_url, *, event)` helper (mirror `test_chat_gateway_socket_turn._fetch_t3_promotion_rows`, selecting `subject, trace_id, result, event` — NO raw-body column).

- [ ] **Step 5: Bind the ceiling constant so a production change can't silently drift the test**

```python
from alfred.comms_mcp.inbound import _FORWARDED_DISPATCH_ATTEMPT_CEILING
# at module top, replace the literal:
_CEILING = _FORWARDED_DISPATCH_ATTEMPT_CEILING
```

- [ ] **Step 6: Run the test (real Postgres via testcontainers)**

Run: `uv run pytest tests/integration/comms/test_forwarded_poison_ceiling_postgres.py -v`
Expected: PASS (1 test). If it ERRORS at fixture setup with `docker.errors.DockerException`, Docker isn't running — start it.

- [ ] **Step 7: Commit**

```bash
git add tests/integration/comms/__init__.py tests/integration/comms/test_forwarded_poison_ceiling_postgres.py
git commit -m "test(comms): forwarded poison ceiling composes with real Postgres stores (Spec B G6-7-6, #309)"
```

---

## Task A1: Real-socket forwarded discord inbound → core dispatch e2e

**Files:**

- Create: `tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py`

This proves a forwarded discord inbound survives the REAL socket carrier + seq codec into the REAL daemon HOST runner → `_route_forwarded_inbound` → receiver → `process_inbound_message(commit_at_dispatch_edge=True)` → real Postgres T3-promotion + dispatched-edge G0 commit. This is the charter's "exercises the REAL pipeline (not just direct injection)" proof. Reuse the daemon-boot + gateway-core-leg scaffold from `test_chat_gateway_socket_turn.py`; the novel part is producing a `gateway.adapter.inbound` frame for `adapter_id="discord"` and asserting the discord T3 row lands.

- [ ] **Step 1: Use option (b) — direct leg-write (PRESCRIBED, arch-002 + test-006)**

Plan-review (architect arch-002, test-eng test-006) locked the mechanism to **option (b)**: after the real gateway core leg reaches `GatewayLinkState.UP` (the `test_chat_gateway_socket_turn` handshake scaffold), write the `forward_adapter_inbound`-shaped JSON-RPC notification frame onto the leg via the same `write_leg_unit` seq path the TUI leg uses. This drives the REAL socket + REAL seq codec + REAL daemon receive arm against real Postgres — the only novel coverage A1 adds over the existing direct-path socket proof.

**Option (a) — registering a real per-adapter discord gateway leg (`build_adapter_leg`/`_register_adapter_legs`) + driving `core_link.forward_adapter_inbound` — is OUT OF SCOPE.** That re-exercises G6-7-3's FORK-D gateway-side per-adapter leg registry + replay buffer, which is **already adversarially covered** (the C1 e2e pump proof in `test_forwarded_inbound_admission.py`); building that scaffold here is over-reach into G6-7-3 territory for marginal coverage and risks a heavy/flaky daemon+gateway+per-adapter-leg harness on the required `Integration` gate. State in the test docstring that the gateway-side forward *production* is intentionally not re-covered here.

To build the option-(b) frame byte-faithfully, mirror `core_link.py:1246-1252`: `json.dumps({"jsonrpc":"2.0","method": GATEWAY_ADAPTER_INBOUND, "params": GatewayAdapterInboundEnvelope(adapter_id="discord", body=<opaque discord InboundMessageNotification json str>).model_dump(mode="json")}).encode()`, then write it as a leg unit on the UP core leg (the seq codec wraps it).

- [ ] **Step 2: Write the failing test scaffold (reuse the harness)**

Create `tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py`. Copy the boot/teardown scaffold from `test_chat_gateway_socket_turn.py` (the `_EchoingChildDouble`, `_RecordingSupervisor`, `_boot_gate_with_tui_load_grant`, `_boot_audit_writer`, `_boot_env`, `_wait_for`, the daemon-carrier + gateway-core-leg boot in the `try:` block, and the `finally:` reaping). CHANGES from the original:

- Seed a **DISCORD**-bound user (`Platform.DISCORD`) so the resolver maps the forwarded discord inbound to `alice`. **NOTE (rev-004):** `_seed_discord_bound_user` lives ONLY in `test_daemon_comms_inbound_turn.py:313-336` — NOT in the chat-gateway harness (which has the non-discord `_seed_bound_user`). Import/adapt the discord seed from `test_daemon_comms_inbound_turn.py`, and pull the boot scaffold from `test_chat_gateway_socket_turn.py`; the two come from different files.
- The ACT step is NOT a cohost keystroke — it is the forwarded-frame injection from Step 1 with `adapter_id="discord"` and an opaque discord-shaped body (a valid `InboundMessageNotification` JSON the discord promoter accepts; reuse the discord body shape from `test_daemon_comms_inbound_turn.py`).
- The ASSERT polls a **discord** T3-promotion row (`_fetch_t3_promotion_rows`, asserting `actor_user_id` resolves to the seeded discord user) — proving the forwarded frame reached `process_inbound_message` and promoted to T3 over the real chain.

```python
@pytest.mark.skipif(_LAUNCHER_REQUIRES_ROOT, reason="parity with the launcher-spawn legs")
@pytest.mark.usefixtures("_boot_env")
async def test_forwarded_discord_inbound_reaches_core_dispatch_over_real_socket(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REAL chain: gateway forward_adapter_inbound('discord', body) -> comms-tui.sock ->
    daemon HOST runner -> _route_forwarded_inbound -> receiver -> process_inbound_message
    (commit_at_dispatch_edge=True) -> real Postgres T3-promotion + dispatched-edge commit.

    The in-process adversarial suite drives the receiver directly / over an in-memory
    transport; this is the FIRST exercise of a forwarded frame over a REAL socket + the
    real seq codec into the real daemon receive arm against real Postgres. Do NOT weaken.
    """
    # ... harness boot (copied scaffold) ...
    # ACT: inject the forwarded discord frame (Step 1 mechanism).
    # ASSERT: a discord T3-promotion row lands (forwarded frame dispatched over the real chain).
    await _wait_for(lambda: bool(_fetch_t3_promotion_rows(sync_url)), _TIMEOUT_S)
    rows = _fetch_t3_promotion_rows(sync_url)
    assert rows, "forwarded discord inbound never reached core dispatch"
```

- [ ] **Step 3: Assert the dispatched-edge G0 commit landed on `(discord, inbound_id)`**

Add an assertion that reads the real `inbound_idempotency` row for `(adapter_id="discord", inbound_id=<the forwarded id>)` and confirms it is committed (the dispatched-edge commit fired AFTER successful dispatch — the forwarded-path G0 semantic). Add a `_fetch_inbound_idempotency(sync_url, *, adapter_id, inbound_id)` helper.

- [ ] **Step 4: Run it (real Postgres)**

Run: `uv run pytest tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py -v`
Expected: PASS. If the forwarded frame is silently dropped (no T3 row before timeout), the injection mechanism (Step 1) put a non-notification frame on the wire — re-check the JSON-RPC `method`/`params` shape against `core_link.py:1246-1252`.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py
git commit -m "test(comms): real-socket forwarded discord inbound reaches core dispatch e2e (Spec B G6-7-6, #309)"
```

---

## Task C1: De-stale the G6-7-4 unbounded-replay guard

**Files:**

- Modify: `tests/adversarial/comms/test_forwarded_inbound_admission.py` (the `test_poison_frame_replays_unboundedly_this_slice` function ~line 726)

Follow-up #4 from the G6-7-5 merge. The test's docstring says "until G6-7-5 lands the ceiling" — now stale (the ceiling shipped). **CORRECTION (test-eng test-001 — my original premise was FACTUALLY WRONG):** this test does NOT build a receiver "without an `attempt_store`". `_build_receiver` (admission file line 234-251) defaults `attempt_store` to a **`_NonTrippingAttemptStore`** (admission file line 175) whose `attempt_count` is **fixed at 0** — so the ceiling is *threaded in* but **deliberately never trips** (the count never reaches N). It replays unbounded because the count is pinned at 0 by the non-tripping fake, NOT because the store is absent. The correct de-stale: this case isolates the receive-boundary **un-observed-on-failure replay contract** with a non-tripping ledger (the ceiling intentionally inert here); the real ceiling is covered by `test_forwarded_inbound_poison.py` + the new real-Postgres composition test. DO NOT rename it to `..._without_attempt_store` (that encodes a false invariant).

- [ ] **Step 1: Confirm the test still passes as-is (no behaviour change)**

Run: `uv run pytest "tests/adversarial/comms/test_forwarded_inbound_admission.py::test_poison_frame_replays_unboundedly_this_slice" -v`
Expected: PASS (the `_NonTrippingAttemptStore` keeps `attempt_count` at 0, so the ceiling never trips and the frame replays unbounded — that is the contract this case pins).

- [ ] **Step 2: Rewrite ONLY the docstring (no rename, no behaviour change)**

Replace the stale `"""KNOWN-THIS-SLICE (G6-7-4): ... until G6-7-5 lands the ceiling ..."""` docstring. Keep the function name `test_poison_frame_replays_unboundedly_this_slice` (renaming risks breaking any `-k`/xref; the body is unchanged). The new docstring must state: the ceiling SHIPPED (G6-7-5); this case deliberately threads a **non-tripping** attempt ledger (`_NonTrippingAttemptStore`, count fixed at 0) to isolate the un-observed-on-failure replay/drain contract WITHOUT the ceiling engaging; the BOUNDED behaviour (real ceiling trips at N=5) is proven by `test_forwarded_inbound_poison.py` (in-memory ledger) and composed against real Postgres by `tests/integration/comms/test_forwarded_poison_ceiling_postgres.py` (G6-7-6).

```python
async def test_poison_frame_replays_unboundedly_this_slice() -> None:
    """With a NON-tripping attempt ledger, a poison frame replays unbounded (isolation case).

    The N=5 poison ceiling SHIPPED in G6-7-5. This case deliberately threads
    ``_NonTrippingAttemptStore`` (``attempt_count`` fixed at 0) so the ceiling is wired
    into the dispatched-edge pipeline but NEVER trips here — isolating the
    un-observed-on-failure replay + drain contract (every delivery raises, never commits,
    never observes; the high-water never advances past the poison seq). The BOUNDED
    behaviour (the real ledger trips the ceiling at N=5 → dead-letter + drain) is proven in
    ``test_forwarded_inbound_poison.py`` (in-memory ledger) and composed against real
    Postgres in ``tests/integration/comms/test_forwarded_poison_ceiling_postgres.py``
    (G6-7-6). If a future change makes THIS frame stop replaying without a ceiling trip,
    this case fails loud and surfaces the regression.
    """
```

- [ ] **Step 3: Run the admission suite**

Run: `uv run pytest tests/adversarial/comms/test_forwarded_inbound_admission.py -q`
Expected: PASS (all cases; only a docstring/name change).

- [ ] **Step 4: Commit**

```bash
git add tests/adversarial/comms/test_forwarded_inbound_admission.py
git commit -m "test(comms): de-stale forwarded unbounded-replay guard now the ceiling exists (Spec B G6-7-6, #309)"
```

---

## Task B1: Flip the adversarial corpus to release-blocking + reconcile

**Files:**

- Modify: `.github/workflows/adversarial.yml`
- Modify: `.github/workflows/ci.yml` (the G6-6 governance note ONLY — the discrete comms step STAYS this PR; see Step 3)

> **SEQUENCING (sec-003 major + arch-005 + test-005 — the no-gate-window fix):** the discrete `tests/adversarial/comms` step in the required `python` job is the ONLY *currently-required* gate for the G6-3 credential corpus. `Adversarial corpus` is only **Pending-required** in this PR (the `gh api POST .../contexts` is post-merge). So this PR must **NOT remove the discrete step** — doing so opens a window (merge → post-merge promotion) where the credential corpus is gated by neither. The removal is a **post-merge follow-up PR**, landed only after `Adversarial corpus` is promoted to currently-required (see the Post-merge runbook). This PR makes `adversarial.yml` release-blocking + Pending-required and leaves the discrete step in place (a brief double-RUN, NOT a double-required-gate, until promotion — acceptable).

- [ ] **Step 1: Make `adversarial.yml` release-blocking + unfiltered + fail-closed on an empty corpus**

Edit `.github/workflows/adversarial.yml`:

- Remove the `continue-on-error: true` line (the `adversarial:` job, ~line 65) so a corpus failure blocks merge.
- Remove the `paths:` block under BOTH `pull_request:` and the `push:` trigger so the release-blocking security suite runs on EVERY PR (not just path-matched ones — the "off-path PR ⇒ required check never runs ⇒ merge blocked" footgun the `docs/ci/required-checks.md` perf-gate caveat documents). Keep `branches: [main]` + `types:`.
- **(ops-003 — close the corpuscheck paper-gate):** the `corpuscheck` step sets `has_corpus=false` + skips all downstream steps when `tests/adversarial/test_*.py` is absent. On a now-REQUIRED gate that is a green-because-skipped hazard: a layout change that breaks the `find` pattern silently passes the required check while gating nothing (`tests/adversarial` is permanent — 235 tests). Make the false branch **FAIL the job** (mirroring the `integration-privileged` precondition-step discipline + the Slice-1 `srccheck` removal note in required-checks.md): change the `else` arm to `echo "::error::adversarial corpus missing — required gate cannot run" && exit 1` instead of the `::notice::` skip. The downstream-step `if: steps.corpuscheck.outputs.has_corpus == 'true'` guards can stay (they are now dead-but-harmless), or simplify to unconditional since the job fails before them.
- **(sec-001(b) — reasoned-skip guard for the bwrap legs):** the 6 `tests/adversarial/sandbox_escape` payloads SKIP here (no bwrap) and are NOT yet on a currently-required check. To prevent them silently vanishing (deleted/renamed) while the gate stays green, run pytest with `-ra` (or `--strict-markers`) and add a step asserting the `sandbox_escape` corpus is COLLECTED-and-skipped, not absent: `uv run pytest tests/adversarial/sandbox_escape --collect-only -q | grep -q test_` (fail loud if zero collected). This makes "skipped with reason" verifiable, not assumed.
- Update the workflow header comment block: replace the "Slice 2 ships the corpus as ADVISORY … Slice 3 makes this release-blocking by REMOVING that line" paragraph with a note that Spec B G6-7-6 (#309) flipped it release-blocking + unfiltered + promoted `Adversarial corpus` to a required check (see `docs/ci/required-checks.md`), and that the bwrap-gated `sandbox_escape` legs skip here + are gated by `integration-privileged` (G6-7-7).

The resulting trigger:

```yaml
on:
  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened]
  push:
    branches: [main]
```

- [ ] **Step 2: Verify the YAML parses + the suite still selects**

Run: `uv run python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/adversarial.yml')); print('ok')"`
Expected: `ok`. Then re-confirm the local suite green (Task B0 Step 1 result still holds).

- [ ] **Step 3: Update the ci.yml governance note (DO NOT remove the comms step this PR)**

In `.github/workflows/ci.yml`, KEEP the `Comms credential adversarial corpus (release-blocking)` step (~lines 109-128). Update ONLY the "NOTE (governance follow-up, G6-6)" comment (~123-127) to record: `adversarial.yml` is now release-blocking + unfiltered and `Adversarial corpus` is being promoted to a required check (G6-7-6, #309); this discrete step is retained until that promotion lands to avoid a no-gate window for the credential corpus, then removed in a tracked post-merge follow-up (`docs/ci/required-checks.md`). This leaves a brief double-RUN of `tests/adversarial/comms` (here + `adversarial.yml`) but NOT a double-required-gate until promotion — the `domain_parallel_green_signal` cleanup is the follow-up PR's job.

> **(sec-002/ops-007 — verified, no gap):** `tests/adversarial/comms/` is pure in-process (no testcontainers/Postgres/root — confirmed by the security + devops reviewers), so it runs identically under both checks; the only reason to retain the discrete step this PR is the sequencing window above, not an env difference.

- [ ] **Step 4: Run the two workflows' local equivalents**

Run: `uv run pytest tests/adversarial -q` (the `adversarial.yml` gate) — green.
Run: `uv run pytest tests/unit -q` (sanity — the ci.yml comment-only edit didn't break collection).
Expected: both green.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/adversarial.yml .github/workflows/ci.yml
git commit -m "ci(adversarial): flip corpus to release-blocking + unfiltered, fail-closed on empty (Spec B G6-7-6, #309)"
```

---

## Task B2: Document the new required check (manifest)

**Files:**

- Modify: `docs/ci/required-checks.md`

Per the author-gating-workflow skill: the branch-protection POST happens AFTER merge (GitHub must have seen the check name run at least once). In-PR we land a **Pending** stub; the merge step runs `gh api POST .../contexts` + flips the stub.

- [ ] **Step 1: Add a Pending row**

Under `## Pending required (workflow merged, awaiting gh api POST .../contexts)`, add:

```markdown
| `Adversarial corpus` | `.github/workflows/adversarial.yml` | `adversarial` | **Spec B G6-7-6 (#309) — closes the `ci.yml:123-127` G6-6 governance follow-up.** The release-blocking adversarial security corpus (`uv run pytest tests/adversarial -v`), flipped from advisory (`continue-on-error` removed) and unfiltered (the `paths:` filter dropped so it gates EVERY PR; the `corpuscheck` false-branch now FAILS the job so an empty/moved corpus can't go green-because-skipped). **Requires Docker on the runner** — some legs self-provision a Postgres/Redis Testcontainer (`tests/adversarial/dlp_egress/`, `tests/adversarial/state/`), as the prior advisory run already did on `ubuntu-latest`; a Docker-absent runner FAILS the gate loud (it does not silently skip). **COVERAGE HONESTY (sec-001):** this check gates the **non-bwrap** corpus only — the 6 `@_bwrap_required` `tests/adversarial/sandbox_escape` payloads (incl. `sbx-2026-012` fd-3 key-leak, `sbx-2026-013` host-escape) SKIP here and are **NOT yet on any currently-required check**: `integration-privileged` runs them but is itself only Pending-required (this table, below), so its promotion to a merge gate is **G6-7-7's** done-definition. Until then a green `Adversarial corpus` does NOT certify the escape payloads. | This PR merges + the workflow runs on a subsequent PR (then `gh api POST .../contexts` + move to Currently required). |
```

- [ ] **Step 2: Update the `Integration` row note (the two new G6-7-6 integration tests gate there)**

Append to the `Integration` row's rationale a sentence: the Spec B G6-7-6 forwarded-inbound e2e proofs (`tests/integration/comms/test_forwarded_poison_ceiling_postgres.py` — the poison ceiling composed against real Postgres; `tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py` — a real-socket forwarded discord inbound reaching core dispatch) run under this aggregate `Integration` check.

- [ ] **Step 3: Lint the doc**

Run: `npx --yes markdownlint-cli2 docs/ci/required-checks.md` (or `make markdownlint` if defined). Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add docs/ci/required-checks.md
git commit -m "docs(ci): mark Adversarial corpus pending-required + note G6-7-6 e2e gates (Spec B G6-7-6, #309)"
```

---

## Task D1: ADR + subsystem-doc amendments

**Files:**

- Modify: `docs/adr/0039-gateway-adapter-inbound-bridge.md` (a dated `### 2026-06-23 — G6-7-6` block under `## Amendments`)
- Modify: `docs/subsystems/comms.md` (the "Spec B G6-7: the gateway adapter inbound bridge" section)

- [ ] **Step 1: Add the ADR amendment**

Under `## Amendments`, append a dated `### 2026-06-23 — G6-7-6: end-to-end composition proof + adversarial-corpus lane promotion` block recording:

  1. The forwarded path is now proven end-to-end over a real socket + real Postgres (the two new integration tests named), composing the receive arm + dispatched-edge commit + poison ceiling with the real durable stores. **Explicitly chain to the 2026-06-22 G6-7-5 amendment (arch-006):** that amendment closed PERF-309-1 with a *mock-store* proof and the durable store covered only in isolation; this A2 test is the **real-Postgres composition** that the mock-store proof deferred — the ceiling's coverage story is now end-to-end (in-memory ledger → real `PostgresForwardedDispatchAttemptStore` through the real receiver + `process_inbound_message`).
  2. The adversarial corpus is now a **required** merge gate (`adversarial.yml` release-blocking + unfiltered + fail-closed on empty; `Adversarial corpus` in `docs/ci/required-checks.md`), closing the `ci.yml:123-127` G6-6 governance follow-up.
  3. **COVERAGE HONESTY (sec-001):** the required `Adversarial corpus` check gates the **non-bwrap** corpus only — the 6 `@_bwrap_required` `sandbox_escape` payloads (`sbx-2026-012`/`-013`) SKIP on its non-root runner and are NOT yet on any currently-required check (`integration-privileged` is still Pending-required). Promoting that lane to required + the flag-day are **G6-7-7 / G6-7-8** — the gateway Discord leg stays TEST-ONLY until G6-7-8.
  4. **(ops-006 — flake diagnostic):** the now-unfiltered required gate depends on ambient Docker (Postgres/Redis Testcontainers in the `dlp_egress`/`state` legs); a future testcontainer/registry hiccup on the gate should be diagnosed as infra flake, not a corpus regression (the workflow fails loud on Docker-absence rather than silently skipping).

State the Decision body remains authoritative.

- [ ] **Step 2: Update `comms.md`**

In the G6-7 section, update the TEST-ONLY caveat: the forwarded leg is now **e2e-proven + adversarially gated on a required check**, but remains test-only until the G6-7-8 flag-day. Add a one-line pointer to the two new integration tests + the `Adversarial corpus` required gate.

- [ ] **Step 3: Lint the docs**

Run: `npx --yes markdownlint-cli2 docs/adr/0039-gateway-adapter-inbound-bridge.md docs/subsystems/comms.md`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0039-gateway-adapter-inbound-bridge.md docs/subsystems/comms.md
git commit -m "docs(comms): ADR-0039 G6-7-6 amendment + comms.md e2e/required-gate update (Spec B G6-7-6, #309)"
```

---

## Task E1: Full local gate before push

**Files:** none (verification).

- [ ] **Step 1: Lint + format + types**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/`
Expected: all clean. (The new tests are under `tests/`, not `src/`; mypy/pyright target `src/` — but ruff covers the tests. If the test files trip ruff, fix.)

- [ ] **Step 2: Unit + the trust-boundary coverage gates (no new trust module ⇒ no new ci.yml gate site)**

Run: `uv run pytest tests/unit -q`
Expected: green. NOTE: this slice adds NO new `src/alfred/**` trust module, so there is NO new per-file 100%-coverage ci.yml gate site to add (unlike prior G6-7 slices). Confirm no `src/` change crept in: `git diff --name-only origin/main...HEAD | grep '^src/' || echo "no src changes (expected)"`.

- [ ] **Step 3: The new integration tests + the adversarial suite**

Run: `uv run pytest tests/integration/comms/test_forwarded_poison_ceiling_postgres.py tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py tests/adversarial -q`
Expected: green (integration needs Docker; `sandbox_escape` skips).

- [ ] **Step 4: i18n drift gate (only if any `t()` call-site moved — unlikely)**

If any `src/alfred` `t()` call-site line shifted (this slice shouldn't touch `src/`), run `pybabel extract -F babel.cfg -o /tmp/p.pot src/alfred plugins && pybabel update -i /tmp/p.pot -l en -d locale --no-fuzzy-matching && pybabel compile -d locale` and verify clean. Otherwise skip.

- [ ] **Step 5: Autosquash check (no fixups left)**

Run: `git log --oneline origin/main..HEAD` — confirm clean conventional subjects, no `fixup!`.

---

## Post-merge runbook (the gate promotion — do NOT skip; sec-003 + ops-004)

After this PR merges and `adversarial.yml` has run at least once on a PR (so GitHub knows the `Adversarial corpus` check name):

1. **Promote to required:** `gh api -X POST repos/alfred-os/AlfredOS/branches/main/protection/required_status_checks/contexts -F 'contexts[]=Adversarial corpus'`. Verify: `gh api repos/alfred-os/AlfredOS/branches/main/protection --jq .required_status_checks.contexts` contains `Adversarial corpus`.
2. **Flip the manifest stub:** move the `Adversarial corpus` row from "Pending required" to "Currently required" in `docs/ci/required-checks.md` with `Active since 2026-06-2X` (a small follow-up docs PR).
3. **Remove the now-redundant discrete step (the deferred sec-003 cleanup):** ONLY NOW (after step 1 makes `Adversarial corpus` currently-required) open the follow-up PR that deletes the whole `Comms credential adversarial corpus (release-blocking)` step from `ci.yml`'s `python` job (+ its `hashFiles` guard + the governance comment), eliminating the `domain_parallel_green_signal` double-run. Sanity-check `coverage-gates` still hits 100% on `comms_mcp`/`gateway` after removal (ops-008 — it should; coverage-gates combines artifacts independently of that step).
4. **Step-6 gate validation (ops-004):** one-time, open a throwaway draft PR with a deliberately-failing adversarial change and confirm the `Adversarial corpus` check goes ✗ and the merge button is blocked; then close it. This is the author-gating-workflow Step 6 "looks-like-a-gate-isn't-a-gate" proof.

These are MERGE-TIME / post-merge actions recorded in the program-log memory entry, not in-PR commits.

---

## Self-review (run before plan-review dispatch)

1. **Spec coverage:** ADR-0039 §Decision "the bridge lands first (G6-7-1..6 …)" + the G6-5-assigned "adversarial-corpus / `adversarial.yml`-to-required" scope → (A) e2e composition (Tasks A1/A2), (B) lane promotion (Tasks B0/B1/B2), (C) follow-up #4 de-stale (Task C1), (D) docs (Task D1). The remaining bridge obligations (privileged real-spawn + lane promotion to required = G6-7-7; flag-day = G6-7-8) are explicitly out of scope.
2. **Placeholder scan:** the two integration tests carry a grounding NOTE + the exact harness/wiring file:lines to reuse rather than a fully-inlined 600-line copy — acceptable because the reference harness is named with exact paths and the novel deltas are spelled out with code; the engineer is not inventing shape. Plan-review should confirm this is concrete enough.
3. **Type consistency:** `_FORWARDED_DISPATCH_ATTEMPT_CEILING` (the production constant) is bound into A2; `GATEWAY_ADAPTER_INBOUND` / `GatewayAdapterInboundEnvelope` / `forward_adapter_inbound` shapes match `protocol.py:440/540-568` + `core_link.py:1246-1252`; `GatewayForwardedInboundReceiver` ctor matches `forwarded_inbound_receiver.py:148-166`.
4. **No-src-change invariant:** every task is tests + CI YAML + docs. If A1/A2 surface a real composition bug needing a `src/` fix, that is a clearly-scoped `fix(...)` commit (not folded silently) — and re-triggers the trust-boundary coverage gates.

## Plan-review dispatch (per the per-slice cadence)

Dispatch `superpowers:review-plan` with **alfred-architect + alfred-security-engineer (MIN) + alfred-test-engineer + alfred-devops-engineer** (it touches the adversarial corpus scope AND a gating CI workflow). Key questions for the panel:

- **Decision D-1:** Mechanism 1 (promote `adversarial.yml`) vs Mechanism 2 (fold into the `python` job + delete the workflow). Is dropping the `paths:` filter (run the whole suite on every PR) the right cost/safety trade vs a companion short-circuit? (devops + test-engineer)
- **A1 depth:** is the real-socket forward e2e worth the harness complexity over the existing in-process pump proof + the A2 composition proof, or is A2 + a lighter A1 (option (b) direct leg-write) sufficient? (architect + test-engineer)
- **Security:** does flipping `adversarial.yml` to required + unfiltered create any NEW bypass (e.g. a path where the suite is green-because-skipped on the runner)? Confirm `sandbox_escape` skips are not a silent gap (they are gated by G6-7-7's `integration-privileged`). (security)
- **Parallel-green:** confirm removing the `tests/adversarial/comms` discrete step leaves no required-check gap for the credential corpus. (test-engineer)
