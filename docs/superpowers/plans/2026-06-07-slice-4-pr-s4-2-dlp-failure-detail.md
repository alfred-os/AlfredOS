# PR-S4-2 — `OutboundDlp.scan` into `processed_proposals.failure_detail`

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename `_truncated_detail` → `_redacted_detail` in `src/alfred/state/dispatch_loop.py`, make the name truthful by running `OutboundDlp.scan(detail)` before the 512-char truncation, thread the scanner through `ProposalContext` matching the in-tree extractor-injection precedent, and emit **two disjoint audit constants** — `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` on success (with `dlp_redactions_count ≥ 0`) and `DLP_OUTBOUND_REFUSED_FIELDS` on refusal (which aborts the write). Adds two adversarial corpus entries under `dlp_egress`.

**Architecture:** `ProposalContext` (frozen dataclass at `src/alfred/state/dispatch_registry.py:148`) gains a `outbound_dlp: OutboundDlpProtocol` field. The new `OutboundDlpProtocol` is a structural Protocol over `OutboundDlp.scan` that lives next to the concrete class at `src/alfred/security/dlp.py` (no relocation; just a `Protocol` + `__all__` export). PR-S4-1's daemon-boot code already constructs the orchestrator's singleton `OutboundDlp` (Slice-3 wiring); PR-S4-2 only adds the threading argument at the `Supervisor` → `ProposalContext` boundary. Inside `_record_failure` the body becomes `redacted = ctx.outbound_dlp.scan(detail)` then `_redacted_detail(redacted)` (rename of `_truncated_detail`, body unchanged: `text[:512]`). On a DLP **refusal** (the canary-trip path) the underlying `HookRefusal` surfaces; the failure-row write aborts and `DLP_OUTBOUND_REFUSED_FIELDS` emits instead. The `STATE_PROPOSAL_PROCESSED_FIELDS` / `STATE_PROPOSAL_DISPATCH_FAILED_FIELDS` paths are NOT touched — the new constant `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` is a **sibling row** that emits in lockstep with the ledger insert, carrying `dlp_redactions_count` (≥0).

**Tech Stack:** Python 3.12+ · asyncio · Pydantic v2 · SQLAlchemy 2.0 async · structlog · pytest + testcontainers (Postgres) · pytest-asyncio · `pybabel extract --keywords=t` · coverage `--fail-under=100` on `src/alfred/state/dispatch_loop.py` (modified region only) and on the new `OutboundDlpProtocol`

**PR #205 round-2 review closures** (apply at implementation time):

1. **arch-001 BLOCKER (Supervisor.outbound_dlp kwarg)**: PR-S4-1 does NOT add `outbound_dlp` to `Supervisor.__init__`. PR-S4-2 itself MUST add the kwarg as part of Task A1: `outbound_dlp: OutboundDlpProtocol | None = None` (Optional default for Slice-3 callers that don't supply it; the real path constructs it in PR-S4-1's daemon `_construct_supervisor` helper which PR-S4-2 also extends to pass `outbound_dlp=OutboundDlp(...)`). The Supervisor stores it as `self._outbound_dlp` and threads it into `ProposalContext` at dispatch-context construction. Without this kwarg the plan AttributeErrors at runtime.

2. **sec-001 HIGH (audit truthfulness on success path)**: the `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` emit on the success path MUST set `result="dispatched_with_redactions"` (when `dlp_redactions_count > 0`) or `result="dispatched_clean"` (when `count == 0`). NOT `result="refused"` — that value is reserved for the `DLP_OUTBOUND_REFUSED_FIELDS` row on the actual refusal path. Disjoint constants stop being meaningful if both claim refusal.

3. **sec-002 HIGH (incomplete migration)**: spec §3.3 + sec-002 finding: the 3 OTHER `_truncated_detail` call sites at `src/alfred/state/dispatch_loop.py:671, 691, 725` MUST ALSO be migrated to scan-then-truncate. The rename without scan is the original #173 leak shape — fixing one site is half the work. Task D2 expands to cover all 4 sites; the rename is global; the body rewrite (scan-then-truncate) lands at every site. Coverage gate enforces 100% on all 4 modified regions.

4. **sec-003 HIGH (count-assertion overfit)**: the planted-secret test asserts:
   - `dlp_redactions_count >= 1` (NOT `== 1` — loosens the exact-match overfit per spec §3.3 `≥0` contract).
   - The redacted text **does NOT contain the planted `sk-` prefix nor the literal API key bytes** (assert by `assert "sk-" not in redacted and PLANTED_KEY not in redacted`). NOT a literal-token-match against the Slice-3 redactor's exact output format. This decouples the test from the redactor's internal token shape.

5. **err-001 HIGH (typed exceptions)**: `except Exception` clauses around `audit_writer.append_schema(...)` MUST be narrowed to `except AuditWriteError` (the Slice-3-shipped exception class at `src/alfred/audit/log.py:55`). Programmer errors (TypeError, ValueError from wrong-shape kwargs) MUST propagate.

6. **err-002 HIGH (transactional lockstep on success-path)**: the `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` emit and the `processed_proposals` ledger insert MUST land transactionally. Implementation: the audit emit happens inside the same SQLAlchemy session as the ledger insert; commit is atomic. On audit-emit failure the session rolls back; the dispatch loop sees the failure and retries on the next tick. Without this, a ledger row landing without its audit-row twin is silent divergence — class CLAUDE.md #7 violation. Task D2 spells out the transactional pattern; `tests/integration/test_dispatch_failure_audit_lockstep.py` (NEW, merge-blocking from S4-2 onwards) asserts the lockstep on a planted audit-writer-raises fixture.

7. **err-003 + sec-004 Medium (DLP scan exception semantics)**: any exception from `outbound_dlp.scan()` OTHER than `HookRefusal` MUST emit `PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS` (new constant — ships in PR-S4-0a alongside `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS`) and abort the ledger insert. `tests/unit/state/test_dlp_scan_regex_error.py` covers this branch.

8. **test-003 Medium (coverage gate completion)**: §6 test list expands to cover: (a) `failure_detail is None` — no scan call, no audit emit on the redacted path, ledger insert with `failure_detail=NULL`; (b) `audit_writer.append_schema` raises `AuditWriteError` after ledger insert — rollback exercised; (c) `audit_writer.append_schema` raises `AuditWriteError` on the refusal path — supervisor breaker trip exercised. All three branches needed for `--cov-fail-under=100 --cov-branch` to pass.

9. **arch-002 Medium (naming asymmetry)**: PR-S4-2's `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` vs PR-S4-9's `OUTBOUND_REDACTED_FIELDS` for semantically identical events is intentional — they sit on different wires (state-git dispatch vs comms outbound) and carry different field-sets. The naming asymmetry is acknowledged; the closure brings forward an ADR-worthy decision but doesn't require an ADR in Slice 4 (deferred to Slice-5 broker-hardening ADR).

10. **sec-004 Medium (canary fidelity)**: corpus entry `dlp-2026-006-dispatch_loop_failure_detail_canary_refused` ships with a `TODO: Slice-5 — re-validate against real canary mechanism once Slice-3's OutboundDlp.scan() actually raises HookRefusal on canary trip` comment. Tracked in §8 backlog.

---

## §1 Goal

This PR closes **issue #173** (the Slice-3 carryover that `_truncated_detail` was named-as-if-DLP-but-only-truncates) and implements spec §3.3 in full. It is **surgical**: it does NOT touch the boot threading mechanics (assumed delivered by PR-S4-1), the `String(512)` column shape on `ProcessedProposal.failure_detail`, the `dispatch_registry.PROPOSAL_HANDLERS` registry, or any handler body. The single Slice-4 invariant landing here is the **two-disjoint-constants** rule from spec §2.1 / §3.3 (sec-005 / arch-004 closure).

Spec anchors:

- **§2.1** — cross-cutting `OutboundDlp.scan` placement table (the wire-format ADR row that names `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` + `DLP_OUTBOUND_REFUSED_FIELDS` for this wire).
- **§3.3** — change-shape body (rename + scan-then-truncate + audit-on-both-paths + adversarial entries).
- **§9** — audit-row constants (the new `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` lands at PR-S4-0a; this PR imports it).

**Depends on:**

- **PR-S4-0a** (`audit_row_schemas.py` Slice-4 additions — defines `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS`; `payload_schema.py` `_PREFIX_TO_CATEGORY` includes `de → dlp_egress` and `_ID_PATTERN` accepts the `dlp-` prefix used by this PR's two corpus entries).
- **PR-S4-0b** (migrations + i18n catalog enumeration; this PR adds `t()` keys `state.dispatch.failure_detail_dlp_refused` and `state.dispatch.failure_detail_redacted_audit_emit_failed`).
- **PR-S4-1** (daemon boot + `Supervisor(state_git_path=…)` construction — the boot path is where the `OutboundDlp` singleton is threaded to `Supervisor`; PR-S4-2 only adds the field on `ProposalContext` and the wire-up inside `Supervisor.start()` between the singleton-receive and the `ProposalContext(…)` construction).

**Blocks:** PR-S4-11 (graduation — the `docs/subsystems/supervisor.md` update lists this PR's audit row in the dispatch-failure surface).

**Closes:** #173.

---

## §2 Fabricated-surfaces verification gate

Before any task starts, the implementer MUST `grep`-verify every symbol cited in this plan exists in the tree at the stated path. The verification record below was taken at plan-authoring time (2026-06-07) on branch `slice-4-plans`. Any drift between this gate and the live tree at implementation time is a **hard halt** — re-verify, update the plan via reviewer-gated proposal, do not improvise.

| Symbol | Cited path | Verified? | Notes |
|---|---|---|---|
| `class OutboundDlp` | `src/alfred/security/dlp.py:84` | **YES** | Constructor: `__init__(self, *, broker, audit)`. Public surface: `scan(text: str) -> str`. |
| `OutboundDlpProtocol` | `src/alfred/security/dlp.py` (new) | **NEW — does not yet exist** | This PR introduces it as a structural Protocol over `OutboundDlp.scan`. Flagged honestly per "If a cited symbol does NOT exist, mark explicitly" rule. |
| `class OutboundDlpExtractSubscriber` | `src/alfred/security/_extract_dlp_subscriber.py:70` | **YES** | The "quarantine extractor pattern" the spec refers to: constructor-inject `OutboundDlp` (no Protocol — concrete type). |
| `class ProposalContext` | `src/alfred/state/dispatch_registry.py:148` | **YES** | Frozen dataclass with `audit_writer`, `effects`, `logger`. Slots; mutation forbidden. |
| `_truncated_detail` | `src/alfred/state/dispatch_loop.py:964` | **YES** | Five call sites at lines 671, 691, 725, 749 (verified by `grep -n`). |
| Construction site `ProposalContext(…)` | `src/alfred/supervisor/core.py:358` | **YES** | Single construction site for the dispatch-cycle context — the wire-up point. |
| `DLP_OUTBOUND_REFUSED_FIELDS` | `src/alfred/audit/audit_row_schemas.py:586` | **YES (Slice-3)** | Reused verbatim. No re-definition in this PR. |
| `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` | `src/alfred/audit/audit_row_schemas.py` (lands in **PR-S4-0a**) | **NEW** | PR-S4-2 imports this constant; the field-list is defined in PR-S4-0a (see Cross-PR Contracts §4). If PR-S4-0a has not landed at implementation time, this PR halts. |
| `dlp_egress` category | `tests/adversarial/payload_schema.py:44` | **YES (Slice-3)** | `_PREFIX_TO_CATEGORY` at line 21 carries `"de": "dlp_egress"` (Slice-3 shipped). PR-S4-0a adds `"dlp": "dlp_egress"` if not already present — this PR's two corpus entries use the `dlp-` prefix per the spec quote. **Confirm the prefix mapping is present in PR-S4-0a's diff before merging.** |
| `_PATH_PREFIX_TO_PAYLOAD` | `src/alfred/state/dispatch_loop.py:152` | **YES** | Closed-vocab handler registry. Untouched by this PR. |
| `_record_failure` | `src/alfred/state/dispatch_loop.py:819` | **YES** | The single function that lands the `processed_proposals.failure_detail` write + audit-row emit. The body change lives here. |
| `_record_applied` | `src/alfred/state/dispatch_loop.py:756` | **YES** | Sibling function — the applied path. **Out of scope.** |

**Honest mark:** `OutboundDlpProtocol` does NOT exist in the tree today. The spec §3.3 line "Thread `OutboundDlpProtocol` through `ProposalContext`" is forward-looking; this PR creates the Protocol. The threading **pattern** the spec invokes ("matching `quarantine.py` extractor pattern") is in the tree at `OutboundDlpExtractSubscriber` (constructor-injection of the concrete `OutboundDlp`); this PR generalises that pattern to a structural Protocol because `ProposalContext` is a frozen dataclass field annotation — Protocols give us mypy-narrowed structural typing without binding the dispatch loop to the concrete class.

---

## §3 Architecture overview

```
src/alfred/security/dlp.py
    ├── class OutboundDlp                  (existing — UNCHANGED behaviour)
    └── class OutboundDlpProtocol          (NEW — structural Protocol with scan())
                                            │
                                            ▼  (annotation only)
src/alfred/state/dispatch_registry.py
    └── class ProposalContext
        ├── audit_writer: AuditWriter       (existing)
        ├── effects: ProposalEffectsProtocol (existing)
        ├── logger: structlog.BoundLogger   (existing)
        └── outbound_dlp: OutboundDlpProtocol  (NEW field)
                                            │
                                            ▼  (consumed at)
src/alfred/state/dispatch_loop.py
    ├── _truncated_detail → _redacted_detail (RENAMED — body UNCHANGED: text[:512])
    └── _record_failure(...)
        ├── scan attempt: ctx.outbound_dlp.scan(detail)
        │   ├── DLP CLEAN          → dlp_redactions_count = 0, write proceeds, emit
        │   │                        PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS
        │   ├── DLP REDACTED       → dlp_redactions_count = N>0 (count of stages
        │   │                        triggered as a proxy; see §5 contract),
        │   │                        write proceeds, emit
        │   │                        PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS
        │   └── DLP REFUSED        → HookRefusal propagates from scan(); write
        │                            ABORTS (the ProcessedProposal row is NOT
        │                            inserted); emit DLP_OUTBOUND_REFUSED_FIELDS;
        │                            supervisor breaker increments via the
        │                            existing audit-emit-failure path
        └── (truncate) _redacted_detail(scanned_text)   # text[:512]

src/alfred/supervisor/core.py
    └── Supervisor.start()
        └── ProposalContext(
                audit_writer=…,
                effects=self,
                logger=…,
                outbound_dlp=self._outbound_dlp,         # NEW arg (singleton from PR-S4-1 boot)
            )

tests/adversarial/dlp_egress/
    ├── dispatch-loop-failure-detail-leak/                  (NEW corpus entry)
    │   ├── manifest.yaml                                  id: dlp-2026-005
    │   └── payload.json
    └── dispatch-loop-failure-detail-canary-refused/        (NEW corpus entry)
        ├── manifest.yaml                                  id: dlp-2026-006
        └── payload.json
```

**Non-bypass invariant.** No call site in `dispatch_loop.py` may construct `OutboundDlp` locally — the singleton MUST be obtained from `ctx.outbound_dlp`. A `pytest` AST guard at `tests/unit/state/test_dispatch_loop_no_local_dlp_construct.py` enforces this. Without the guard a future refactor that drops `ctx.outbound_dlp` for a `lambda detail: detail` "test stub" silently disarms the boundary.

**Refusal semantics.** `OutboundDlp.scan` does not currently raise `HookRefusal`. Today it always returns redacted text, never aborts. The **refusal path** in this PR is wired by treating any `HookRefusal` raised by a future Slice-4 canary stage as the "DLP says no-write" signal. Because the canary stage is currently `return text` (the regression-guarded no-op stub at `dlp.py:140`), the refusal path is exercised exclusively by:

1. The unit test `test_dispatch_loop_failure_detail_canary_refused` which injects a stub DLP that raises `HookRefusal` to simulate Slice-3-pre-shipped canary behaviour.
2. The adversarial-corpus payload `dispatch-loop-failure-detail-canary-refused` which uses the same stub mechanism.

When Slice-3's canary stage lands real behaviour (Slice-3 §6 of `dlp.py` docstring already anticipates this), the refusal path activates against real inputs with no code change to `_record_failure`.

---

## §4 File structure

| File | Create / Modify / Test | Responsibility |
|---|---|---|
| `src/alfred/security/dlp.py` | **Modify** | Add `OutboundDlpProtocol` Protocol class + export from `__all__`. Body: a single `scan(text: str) -> str` method stub. No change to `OutboundDlp`. |
| `src/alfred/state/dispatch_registry.py` | **Modify** | Add `outbound_dlp: OutboundDlpProtocol` field to `ProposalContext`. Frozen+slots is preserved — the field is REQUIRED, no default. |
| `src/alfred/state/dispatch_loop.py` | **Modify** | Rename `_truncated_detail` → `_redacted_detail` (4 call sites + 1 def + module docstring + `__all__`). Change each call site from `_truncated_detail(text)` to `_redacted_detail(ctx.outbound_dlp.scan(text))`. Add the import of `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` + `DLP_OUTBOUND_REFUSED_FIELDS`. Wrap each `_record_failure(...)` call site in a `try / except HookRefusal` arm that emits `DLP_OUTBOUND_REFUSED_FIELDS` and aborts the row insert. |
| `src/alfred/supervisor/core.py` | **Modify** | Pass `outbound_dlp=self._outbound_dlp` to the `ProposalContext(…)` construction at line 358. (`self._outbound_dlp` is the singleton attribute PR-S4-1 lands.) |
| `tests/unit/state/test_dispatch_loop_failure_detail_dlp.py` | **Create** | Unit suite — see §6 for the eight cases including the planted-secret round-trip and the canary-refusal abort. |
| `tests/unit/state/test_dispatch_loop_no_local_dlp_construct.py` | **Create** | AST guard — `dispatch_loop.py` must not construct `OutboundDlp` locally. Allowed import: `from alfred.security.dlp import OutboundDlpProtocol` (type-only). |
| `tests/unit/state/test_proposal_context_outbound_dlp_field.py` | **Create** | `ProposalContext.outbound_dlp` is a required field; instantiation without it raises `TypeError`; type annotation is `OutboundDlpProtocol`. |
| `tests/unit/security/test_outbound_dlp_protocol.py` | **Create** | `OutboundDlp` satisfies `OutboundDlpProtocol` structurally (`isinstance` with `runtime_checkable`); a non-matching stub does NOT satisfy. |
| `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-leak/manifest.yaml` | **Create** | `id: dlp-2026-005`, `category: dlp_egress`, `ingestion_path: proposal_dispatch_failure`. |
| `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-leak/payload.json` | **Create** | Planted-API-key string in a malformed proposal blob's body that surfaces in `failure_detail` via `type(exc).__name__` → forced ValidationError carrier. |
| `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-canary-refused/manifest.yaml` | **Create** | `id: dlp-2026-006`, same category, same ingestion path. |
| `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-canary-refused/payload.json` | **Create** | Planted-canary token; the stub DLP raises `HookRefusal` on canary detect to simulate the refusal arm. |
| `tests/unit/audit/test_proposal_dispatch_failure_redacted_constant.py` | **Create** | `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` carries the required fields per §5 contract. |
| `locale/en/LC_MESSAGES/alfred.po` | **Modify** | Add the two new `t()` keys. |
| `docs/subsystems/security.md` | **Modify (one-line cross-ref)** | Add a single bullet under "DLP placement" pointing at this PR's wire (the full subsystem-doc update is PR-S4-11's responsibility). |

**Out of scope (do not touch in this PR):**

- The `String(512)` column shape on `ProcessedProposal.failure_detail`. The 512 cap is preserved verbatim.
- Threading mechanics from `Supervisor` boot down through arg-passing — PR-S4-1 delivers `self._outbound_dlp` on `Supervisor`; this PR only adds the kwarg at the `ProposalContext(…)` call site.
- `STATE_PROPOSAL_PROCESSED_FIELDS` and `STATE_PROPOSAL_DISPATCH_FAILED_FIELDS` schemas. They are unchanged; this PR adds a sibling row, not a field.
- The applied-path `_record_applied`. Untouched.
- The `_emit_cycle_skipped` function. Untouched.

---

## §5 Cross-PR contracts

### 5.1 `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` shape (PR-S4-0a defines; PR-S4-2 consumes)

Spec §9 enumerates this constant. The field-set this PR depends on:

```python
PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS: Final[frozenset[str]] = frozenset({
    "proposal_type",
    "proposal_id",
    "result",                  # mirrors the ledger result
    "failure_kind",            # mirrors the ledger failure_kind
    "framework_error_kind",
    "handler_version",
    "operator_user_id",
    "commit_sha",
    "correlation_id",
    "dlp_redactions_count",    # ≥0; 0 = clean scan, N>0 = redactions happened
    "pre_redaction_byte_len",  # forensic: byte-length of the failure_detail PRE-scan
    "post_redaction_byte_len", # forensic: byte-length POST-scan and POST-truncate
})
```

**Drift between PR-S4-0a's frozen-set and this PR's emit-site is a release blocker.** PR-S4-0a's test `tests/unit/audit/test_audit_constants_slice_4.py` asserts each name maps to a valid `AuditEntry` column; this PR's test `test_proposal_dispatch_failure_redacted_constant.py` asserts the same field-set is the one this PR emits.

### 5.2 `dlp_redactions_count` semantic

`OutboundDlp.scan` does NOT today return a count — it returns redacted text. The contract this PR commits to:

- **Clean scan** (`scanned == original`): `dlp_redactions_count = 0`.
- **Redacted scan** (`scanned != original`): `dlp_redactions_count = 1`. (Slice-4 ships a coarse-grained binary count. Per-stage redaction counts are a Slice-5+ enrichment; spec §3.3 commits only to `≥0` and the unit test asserts `==1`.)
- **Refused scan** (`HookRefusal` raised): no `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` emit; `DLP_OUTBOUND_REFUSED_FIELDS` emits instead.

The forensic byte-length fields surface from `len(pre.encode("utf-8"))` and `len(post.encode("utf-8"))` — same encoding pattern as `OutboundDlp._audit` already uses at `dlp.py:131` so the audit graph reads consistently across both surfaces.

### 5.3 `DLP_OUTBOUND_REFUSED_FIELDS` reuse (Slice-3 constant)

Reused verbatim. No re-definition. The field-set is whatever Slice-3 shipped — this PR does not modify it. The emit site populates each field as:

- `actor_persona`: `"supervisor"`.
- `event`: `"dlp.outbound_refused"` (Slice-3 wire vocab; see `audit_row_schemas.py:586`).
- `subject`: closed-vocab fields (`outbound_path: Literal["proposal_dispatch_failure"]`, `refusal_reason: Literal["canary_or_secret_in_failure_detail"]`).

### 5.4 Adversarial-corpus prefix contract (PR-S4-0a defines)

This PR's two corpus entries use the `dlp-` prefix. PR-S4-0a's `_PREFIX_TO_CATEGORY` table MUST contain `"dlp": "dlp_egress"`; if Slice-3 shipped only the `de-` prefix mapping, PR-S4-0a is responsible for adding `dlp-`. The verification gate above flags this — confirm at implementation time before opening the PR.

### 5.5 `OutboundDlpProtocol` shape

```python
# In src/alfred/security/dlp.py — appended below the existing OutboundDlp class
from typing import Protocol, runtime_checkable

@runtime_checkable
class OutboundDlpProtocol(Protocol):
    """Structural type for the outbound DLP scanner.

    Used by frozen dataclasses (ProposalContext) and other surfaces that
    need to annotate a DLP-scanner dependency without binding to the
    concrete OutboundDlp class. The concrete class satisfies this
    protocol by virtue of its scan() signature.

    The Protocol is intentionally narrow — the only stable surface is
    scan(). A consumer that needs broker-redaction or audit-sink access
    constructs OutboundDlp directly; everything else uses this Protocol.
    """

    def scan(self, text: str) -> str:
        # Body unreachable; Protocol stubs raise NotImplementedError
        # rather than return so coverage stays honest.
        raise NotImplementedError  # pragma: no cover
```

The Protocol lives in `dlp.py` (not in a sibling protocols module) so the import surface mirrors the pattern Slice-3 established for `_BrokerLike` and `_AuditSink` Protocols inside the same module. Mypy resolves the forward reference cleanly because the Protocol is defined after the class.

---

## §6 TDD task list

Numbered tasks are sequenced. Earlier tasks define the contract; later tasks implement against it. Each task names the failing test, the implementation file, and the run command.

### Component A — `OutboundDlpProtocol` (foundation)

- [ ] **Task A1 — Write failing tests for `OutboundDlpProtocol`.**

  **Files:** Create `tests/unit/security/test_outbound_dlp_protocol.py`.

  ```python
  # tests/unit/security/test_outbound_dlp_protocol.py
  from alfred.security.dlp import OutboundDlp, OutboundDlpProtocol


  def test_outbound_dlp_satisfies_protocol() -> None:
      """The concrete OutboundDlp class satisfies OutboundDlpProtocol structurally."""

      class _StubBroker:
          def redact(self, text: str) -> str:
              return text

      def _stub_audit(*, event: str, subject: object) -> None: ...  # noqa: ARG001

      dlp = OutboundDlp(broker=_StubBroker(), audit=_stub_audit)
      assert isinstance(dlp, OutboundDlpProtocol)


  def test_non_matching_stub_does_not_satisfy_protocol() -> None:
      """A stub missing scan() does NOT satisfy the protocol."""

      class _NotADlp:
          def redact(self, text: str) -> str: return text  # noqa: E704

      assert not isinstance(_NotADlp(), OutboundDlpProtocol)


  def test_protocol_runtime_checkable() -> None:
      """OutboundDlpProtocol is runtime_checkable (isinstance works)."""
      import typing
      assert getattr(OutboundDlpProtocol, "_is_runtime_protocol", False) is True

      # Sanity — a duck-typed stub with the right method passes.
      class _DuckScan:
          def scan(self, text: str) -> str: return text  # noqa: E704

      assert isinstance(_DuckScan(), OutboundDlpProtocol)
  ```

  Run:

  ```bash
  uv run pytest tests/unit/security/test_outbound_dlp_protocol.py -q 2>&1 | tail -5
  ```

  Expected: 3 failures (`ImportError` on `OutboundDlpProtocol`).

- [ ] **Task A2 — Implement `OutboundDlpProtocol` in `dlp.py`.**

  **Files:** Modify `src/alfred/security/dlp.py`.

  Append after `OutboundDlp` class:

  ```python
  @runtime_checkable
  class OutboundDlpProtocol(Protocol):
      """Structural type — see Cross-PR Contracts §5.5."""

      def scan(self, text: str) -> str:
          raise NotImplementedError  # pragma: no cover
  ```

  Add `"OutboundDlpProtocol"` to `__all__`. Add the import of `runtime_checkable` from `typing` (currently the file imports `Protocol` only).

  Run the same test:

  ```bash
  uv run pytest tests/unit/security/test_outbound_dlp_protocol.py -q 2>&1 | tail -5
  ```

  Expected: 3 passes.

### Component B — `ProposalContext.outbound_dlp` field

- [ ] **Task B1 — Write failing test for `ProposalContext.outbound_dlp` field.**

  **Files:** Create `tests/unit/state/test_proposal_context_outbound_dlp_field.py`.

  ```python
  # tests/unit/state/test_proposal_context_outbound_dlp_field.py
  import pytest
  import structlog

  from alfred.audit.writer import AuditWriter
  from alfred.security.dlp import OutboundDlpProtocol
  from alfred.state.dispatch_registry import ProposalContext


  def test_proposal_context_has_outbound_dlp_field() -> None:
      """ProposalContext.outbound_dlp is declared with OutboundDlpProtocol type."""
      import dataclasses
      fields = {f.name: f.type for f in dataclasses.fields(ProposalContext)}
      assert "outbound_dlp" in fields


  def test_proposal_context_outbound_dlp_required_no_default(
      audit_writer: AuditWriter,
      proposal_effects: object,  # ProposalEffectsProtocol fixture
  ) -> None:
      """Instantiation without outbound_dlp raises TypeError (required field)."""
      with pytest.raises(TypeError, match="outbound_dlp"):
          ProposalContext(
              audit_writer=audit_writer,
              effects=proposal_effects,  # type: ignore[arg-type]
              logger=structlog.get_logger("test"),
          )  # type: ignore[call-arg]


  def test_proposal_context_outbound_dlp_satisfies_protocol(
      audit_writer: AuditWriter,
      proposal_effects: object,
      outbound_dlp_stub: OutboundDlpProtocol,
  ) -> None:
      """Constructed instance round-trips the OutboundDlpProtocol assertion."""
      ctx = ProposalContext(
          audit_writer=audit_writer,
          effects=proposal_effects,  # type: ignore[arg-type]
          logger=structlog.get_logger("test"),
          outbound_dlp=outbound_dlp_stub,
      )
      assert isinstance(ctx.outbound_dlp, OutboundDlpProtocol)
  ```

  Use the existing `proposal_effects` fixture (Slice-3 shipped at `tests/unit/state/conftest.py`); add `outbound_dlp_stub` to that conftest as a fixture returning `OutboundDlp(broker=_FakeBroker(), audit=_capturing_sink)`.

  Run:

  ```bash
  uv run pytest tests/unit/state/test_proposal_context_outbound_dlp_field.py -q 2>&1 | tail -5
  ```

  Expected: 3 failures (the field does not exist yet).

- [ ] **Task B2 — Add `outbound_dlp` field to `ProposalContext`.**

  **Files:** Modify `src/alfred/state/dispatch_registry.py`.

  ```python
  from alfred.security.dlp import OutboundDlpProtocol  # ADD import

  @dataclass(frozen=True, slots=True)
  class ProposalContext:
      audit_writer: AuditWriter
      effects: ProposalEffectsProtocol
      logger: structlog.BoundLogger
      outbound_dlp: OutboundDlpProtocol   # NEW
  ```

  Update the module docstring's `ProposalContext` field list (lines 156-163) to include `outbound_dlp`. Update the `__all__` block if any drift; field is dataclass-introspected so the `Final` list at the bottom is unchanged.

  Run:

  ```bash
  uv run pytest tests/unit/state/test_proposal_context_outbound_dlp_field.py -q 2>&1 | tail -5
  ```

  Expected: 3 passes.

### Component C — `_truncated_detail` → `_redacted_detail` rename

- [ ] **Task C1 — Write failing rename test.**

  **Files:** Create test scaffold inside `tests/unit/state/test_dispatch_loop_failure_detail_dlp.py`.

  ```python
  def test_truncated_detail_was_renamed_to_redacted_detail() -> None:
      """The dishonest name is gone; the truthful name lives."""
      import alfred.state.dispatch_loop as dl
      assert not hasattr(dl, "_truncated_detail")
      assert hasattr(dl, "_redacted_detail")
      assert callable(dl._redacted_detail)


  def test_redacted_detail_truncates_to_512() -> None:
      """The function body is unchanged: text[:512]."""
      from alfred.state.dispatch_loop import _redacted_detail
      assert _redacted_detail("x" * 513) == "x" * 512
      assert _redacted_detail("hello") == "hello"
      assert _redacted_detail("") == ""
  ```

  Run:

  ```bash
  uv run pytest tests/unit/state/test_dispatch_loop_failure_detail_dlp.py -q -k 'truncated or redacted' 2>&1 | tail -5
  ```

  Expected: 2 failures (the new symbol doesn't exist; the old one still does).

- [ ] **Task C2 — Rename `_truncated_detail` → `_redacted_detail`.**

  **Files:** Modify `src/alfred/state/dispatch_loop.py`.

  1. Rename the def at line 964 + its docstring (per spec §3.3 the new name's docstring records the DLP-scan-then-truncate contract — see Task D2 for the docstring rewrite).
  2. Rename the 4 call sites at lines 671, 691, 725, 749. Body of `_redacted_detail` itself stays `return text[:512]` — the **DLP scan happens at the call sites**, not inside the truncate helper (a single-purpose helper is easier to test and audit-graph).
  3. Update the module docstring section at line 61-67 — the prose claiming "#173 wires `OutboundDlp.scan` at this boundary" is the surface this PR closes; rewrite to describe the landed wiring.
  4. Update `__all__` at the bottom of the file if `_truncated_detail` was exported (it is private; verify).

  Run:

  ```bash
  uv run pytest tests/unit/state/test_dispatch_loop_failure_detail_dlp.py -q -k 'truncated or redacted' 2>&1 | tail -5
  uv run pytest tests/unit/state/ -q  # regression: existing tests still pass
  ```

  Expected: rename tests pass; existing `dispatch_loop` tests still pass (call sites haven't started using `outbound_dlp` yet, so behaviour is identical).

### Component D — `OutboundDlp.scan` wiring at each call site

- [ ] **Task D1 — Write failing test for the planted-secret round-trip.**

  **Files:** Add to `tests/unit/state/test_dispatch_loop_failure_detail_dlp.py`.

  ```python
  import pytest
  from sqlalchemy import select
  from sqlalchemy.ext.asyncio import AsyncSession

  from alfred.audit.audit_row_schemas import (
      DLP_OUTBOUND_REFUSED_FIELDS,
      PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS,
  )
  from alfred.hooks.errors import HookRefusal
  from alfred.memory.models import ProcessedProposal
  from alfred.security.dlp import OutboundDlp
  from alfred.state.dispatch_loop import _record_failure


  @pytest.mark.asyncio
  async def test_failure_detail_planted_secret_is_redacted_and_count_emitted(
      proposal_context_with_real_dlp,  # fixture wires OutboundDlp w/ broker that knows [PROVIDER_KEY_PFX]DEADBEEF…
      ref_fixture,
      session_scope_fixture,
      captured_audit_rows,
  ) -> None:
      """A planted API-key in failure_detail is redacted before landing in the ledger;
      PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS emits with dlp_redactions_count==1."""
      planted = "[PROVIDER_KEY_PFX]DEADBEEF" + "X" * 40  # matches OutboundDlp's generic-key regex
      await _record_failure(
          proposal_context_with_real_dlp,
          ref_fixture,
          session_scope_fixture,
          result="failed_handler",
          failure_kind="handler_returned_failed",
          failure_detail=planted,
          operator_user_id=None,
          correlation_id="test-corr",
          framework_error_kind=None,
      )

      # Ledger row landed with redacted detail.
      async with session_scope_fixture() as session:
          row = (await session.execute(select(ProcessedProposal))).scalar_one()
      assert "[PROVIDER_KEY_PFX]DEADBEEF" not in row.failure_detail
      assert "[REDACTED:api-key-shape]" in row.failure_detail

      # PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS row emitted with count=1.
      redacted_rows = [r for r in captured_audit_rows
                       if r.schema_name == "PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS"]
      assert len(redacted_rows) == 1
      assert redacted_rows[0].subject["dlp_redactions_count"] == 1

      # NO refusal row.
      refusal_rows = [r for r in captured_audit_rows
                      if r.schema_name == "DLP_OUTBOUND_REFUSED_FIELDS"]
      assert refusal_rows == []


  @pytest.mark.asyncio
  async def test_failure_detail_clean_scan_emits_zero_count(
      proposal_context_with_real_dlp,
      ref_fixture,
      session_scope_fixture,
      captured_audit_rows,
  ) -> None:
      """A clean scan still emits PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS with count=0."""
      await _record_failure(
          proposal_context_with_real_dlp,
          ref_fixture,
          session_scope_fixture,
          result="failed_handler",
          failure_kind="handler_returned_failed",
          failure_detail="handler_returned_failed",  # closed-vocab; nothing to redact
          operator_user_id=None,
          correlation_id="test-corr",
          framework_error_kind=None,
      )
      redacted_rows = [r for r in captured_audit_rows
                       if r.schema_name == "PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS"]
      assert len(redacted_rows) == 1
      assert redacted_rows[0].subject["dlp_redactions_count"] == 0


  @pytest.mark.asyncio
  async def test_failure_detail_canary_refusal_aborts_write(
      proposal_context_with_refusing_dlp,  # fixture wires DLP whose scan raises HookRefusal
      ref_fixture,
      session_scope_fixture,
      captured_audit_rows,
  ) -> None:
      """A DLP refusal (HookRefusal) aborts the write entirely; DLP_OUTBOUND_REFUSED_FIELDS emits;
      no ProcessedProposal row lands."""
      await _record_failure(
          proposal_context_with_refusing_dlp,
          ref_fixture,
          session_scope_fixture,
          result="failed_handler",
          failure_kind="handler_returned_failed",
          failure_detail="some-detail-with-canary-XYZ",
          operator_user_id=None,
          correlation_id="test-corr",
          framework_error_kind=None,
      )

      # No ProcessedProposal row.
      async with session_scope_fixture() as session:
          rows = (await session.execute(select(ProcessedProposal))).scalars().all()
      assert rows == []

      # Refusal row emitted.
      refusal_rows = [r for r in captured_audit_rows
                      if r.schema_name == "DLP_OUTBOUND_REFUSED_FIELDS"]
      assert len(refusal_rows) == 1
      assert refusal_rows[0].subject["refusal_reason"] == "canary_or_secret_in_failure_detail"

      # NO success row.
      redacted_rows = [r for r in captured_audit_rows
                       if r.schema_name == "PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS"]
      assert redacted_rows == []


  @pytest.mark.asyncio
  async def test_failure_detail_dlp_truncation_after_scan(
      proposal_context_with_real_dlp,
      ref_fixture,
      session_scope_fixture,
      captured_audit_rows,
  ) -> None:
      """Scan happens BEFORE truncation; the 512-char cap is applied to the redacted text."""
      planted = "[PROVIDER_KEY_PFX]DEADBEEF" + "X" * 600  # > 512 chars; key shape at the head
      await _record_failure(
          proposal_context_with_real_dlp,
          ref_fixture,
          session_scope_fixture,
          result="failed_handler",
          failure_kind="handler_returned_failed",
          failure_detail=planted,
          operator_user_id=None,
          correlation_id="test-corr",
          framework_error_kind=None,
      )
      async with session_scope_fixture() as session:
          row = (await session.execute(select(ProcessedProposal))).scalar_one()
      assert len(row.failure_detail) == 512
      assert "[REDACTED:api-key-shape]" in row.failure_detail
  ```

  Fixtures `proposal_context_with_real_dlp`, `proposal_context_with_refusing_dlp`, `captured_audit_rows`, `ref_fixture`, `session_scope_fixture` go into `tests/unit/state/conftest.py`. `proposal_context_with_refusing_dlp` wires a stub whose `scan()` raises `HookRefusal(hook_id="dlp.outbound", action_id="state.proposal.failure_detail", reason="canary_or_secret_in_failure_detail", correlation_id="t-1")`.

  Run:

  ```bash
  uv run pytest tests/unit/state/test_dispatch_loop_failure_detail_dlp.py -q 2>&1 | tail -10
  ```

  Expected: 4 failures (the wire doesn't exist yet).

- [ ] **Task D2 — Wire `OutboundDlp.scan` + `HookRefusal` arms into `_record_failure`.**

  **Files:** Modify `src/alfred/state/dispatch_loop.py`.

  1. Import `HookRefusal` from `alfred.hooks.errors`.
  2. Import `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` and `DLP_OUTBOUND_REFUSED_FIELDS` from `alfred.audit.audit_row_schemas`.
  3. Inside `_record_failure`, before the `session_scope` block:

     ```python
     # DLP scan the failure_detail.  Spec §3.3 + §2.1.
     dlp_redactions_count = 0
     scanned_detail: str | None
     if failure_detail is None:
         scanned_detail = None
     else:
         try:
             scanned = ctx.outbound_dlp.scan(failure_detail)
         except HookRefusal as refusal:
             # Refusal path — abort the row insert + emit refusal audit row.
             try:
                 await ctx.audit_writer.append_schema(
                     fields=DLP_OUTBOUND_REFUSED_FIELDS,
                     schema_name="DLP_OUTBOUND_REFUSED_FIELDS",
                     event="dlp.outbound_refused",
                     actor_user_id=operator_user_id,
                     actor_persona="supervisor",
                     subject={
                         "outbound_path": "proposal_dispatch_failure",
                         "refusal_reason": "canary_or_secret_in_failure_detail",
                         "hook_id": refusal.hook_id,
                         "correlation_id": correlation_id,
                     },
                     trust_tier_of_trigger="T1",
                     result="refused",
                     cost_estimate_usd=0.0,
                     cost_actual_usd=0.0,
                     trace_id=correlation_id,
                 )
             except AuditWriteError as exc:
                 raise _PostHandlerAuditFailure(
                     "audit emit failed during DLP refusal"
                 ) from exc
             return  # ABORT the row insert
         else:
             if scanned != failure_detail:
                 dlp_redactions_count = 1
             scanned_detail = _redacted_detail(scanned)

     pre_byte_len = (
         len(failure_detail.encode("utf-8")) if failure_detail is not None else 0
     )
     post_byte_len = (
         len(scanned_detail.encode("utf-8")) if scanned_detail is not None else 0
     )
     ```

  4. Replace the existing `failure_detail=failure_detail` arg to the `ProcessedProposal(...)` constructor with `failure_detail=scanned_detail`.
  5. After the existing audit emit (the `STATE_PROPOSAL_PROCESSED_FIELDS` / `STATE_PROPOSAL_DISPATCH_FAILED_FIELDS` block), add the new sibling emit:

     ```python
     # PR-S4-2 sibling row: PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS.
     # Emits regardless of DLP outcome (count=0 for clean, ≥1 for redacted).
     # The refusal path returned earlier and never reaches here.
     try:
         await ctx.audit_writer.append_schema(
             fields=PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS,
             schema_name="PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS",
             event="state.proposal.failure_detail_redacted",
             actor_user_id=operator_user_id,
             actor_persona="supervisor",
             subject={
                 "proposal_type": ref.proposal_type,
                 "proposal_id": ref.proposal_id,
                 "result": result,
                 "failure_kind": failure_kind,
                 "framework_error_kind": framework_error_kind,
                 "handler_version": 1,
                 "operator_user_id": operator_user_id,
                 "commit_sha": ref.commit_sha,
                 "correlation_id": correlation_id,
                 "dlp_redactions_count": dlp_redactions_count,
                 "pre_redaction_byte_len": pre_byte_len,
                 "post_redaction_byte_len": post_byte_len,
             },
             trust_tier_of_trigger="T1",
             result="dispatched_with_redactions" if dlp_redactions_count > 0 else "dispatched_clean"  # round-2 closure 2,
             cost_estimate_usd=0.0,
             cost_actual_usd=0.0,
             trace_id=correlation_id,
         )
     except AuditWriteError as exc:
         raise _PostHandlerAuditFailure(
             "audit emit failed for PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS"
         ) from exc
     ```

  6. Update the module docstring at lines 61-67 to describe the landed contract (replace the "tracked at #173" prose with the active wiring).
  7. Update the `_redacted_detail` docstring to make explicit it is **only the truncation step** — the DLP scan happens at the call site, not inside this helper. State explicitly: "Callers MUST run `ctx.outbound_dlp.scan(text)` before passing text to this helper."

  Run:

  ```bash
  uv run pytest tests/unit/state/test_dispatch_loop_failure_detail_dlp.py -q 2>&1 | tail -10
  uv run pytest tests/unit/state/ -q  # regression check
  ```

  Expected: 4 new tests pass; all prior `dispatch_loop` tests pass (the rename + new arg propagate through fixtures the test conftest provides).

- [ ] **Task D3 — Update fixtures + existing dispatch-loop tests for the new `ProposalContext.outbound_dlp` field.**

  **Files:** Modify `tests/unit/state/conftest.py` and any test file that constructs `ProposalContext` directly.

  Every existing `ProposalContext(...)` construction in tests gains an `outbound_dlp=outbound_dlp_stub` argument. The stub is a `OutboundDlp(broker=_FakeBroker(), audit=_capturing_sink)` where `_FakeBroker.redact` is identity. This preserves the prior behaviour of those tests (no redactions, count=0).

  Run:

  ```bash
  uv run pytest tests/unit/state/ -q 2>&1 | tail -5
  ```

  Expected: full state suite passes.

### Component E — `Supervisor` wire-up

- [ ] **Task E1 — Write failing test for `Supervisor` threading.**

  **Files:** Create `tests/unit/supervisor/test_supervisor_threads_outbound_dlp_to_context.py`.

  ```python
  @pytest.mark.asyncio
  async def test_supervisor_threads_outbound_dlp_singleton_to_proposal_context(
      supervisor_with_real_dlp_singleton,
  ) -> None:
      """The Supervisor's _outbound_dlp singleton lands on every ProposalContext."""
      ctx = supervisor_with_real_dlp_singleton._build_proposal_context()
      assert ctx.outbound_dlp is supervisor_with_real_dlp_singleton._outbound_dlp
  ```

  Use the `_build_proposal_context` helper if it exists; otherwise the test exercises `Supervisor.start()` indirectly. The fixture `supervisor_with_real_dlp_singleton` constructs `Supervisor(state_git_path=…, outbound_dlp=outbound_dlp_singleton)` — the `outbound_dlp=` kwarg on `Supervisor.__init__` is PR-S4-1's responsibility (verify at implementation time; if PR-S4-1 has not landed the kwarg, halt and coordinate).

  Expected: 1 failure (the wire-up at `core.py:358` doesn't pass the kwarg yet).

- [ ] **Task E2 — Pass `outbound_dlp` at the `ProposalContext(…)` construction site.**

  **Files:** Modify `src/alfred/supervisor/core.py` around line 358.

  ```python
  ctx = ProposalContext(
      audit_writer=self._audit,
      effects=self,
      logger=self._log,
      outbound_dlp=self._outbound_dlp,   # NEW kwarg
  )
  ```

  Run:

  ```bash
  uv run pytest tests/unit/supervisor/test_supervisor_threads_outbound_dlp_to_context.py -q 2>&1 | tail -5
  uv run pytest tests/unit/supervisor/ -q
  ```

  Expected: passes; supervisor suite green.

### Component F — AST guards

- [ ] **Task F1 — Write the no-local-construction AST guard.**

  **Files:** Create `tests/unit/state/test_dispatch_loop_no_local_dlp_construct.py`.

  ```python
  import ast
  import pathlib


  def test_dispatch_loop_does_not_construct_outbound_dlp_locally() -> None:
      """dispatch_loop.py must not construct OutboundDlp — the singleton is threaded via ctx."""
      src = pathlib.Path("src/alfred/state/dispatch_loop.py").read_text()
      tree = ast.parse(src)
      for node in ast.walk(tree):
          if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
              assert node.func.id != "OutboundDlp", (
                  "Local OutboundDlp construction is forbidden — use ctx.outbound_dlp."
              )


  def test_dispatch_loop_imports_only_protocol_not_concrete() -> None:
      """The import surface is OutboundDlpProtocol (type-only); never the concrete class."""
      src = pathlib.Path("src/alfred/state/dispatch_loop.py").read_text()
      tree = ast.parse(src)
      for node in ast.walk(tree):
          if isinstance(node, ast.ImportFrom) and node.module == "alfred.security.dlp":
              names = {alias.name for alias in node.names}
              assert "OutboundDlp" not in names, "Import the Protocol, not the concrete class."
  ```

  Run:

  ```bash
  uv run pytest tests/unit/state/test_dispatch_loop_no_local_dlp_construct.py -q 2>&1 | tail -5
  ```

  Expected: passes immediately (the implementation in Task D2 imports `HookRefusal` and the audit constants, not `OutboundDlp`).

### Component G — Adversarial corpus

- [ ] **Task G1 — Write `dispatch-loop-failure-detail-leak` corpus entry.**

  **Files:** Create:
  - `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-leak/manifest.yaml`
  - `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-leak/payload.json`
  - `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-leak/test_dispatch_loop_failure_detail_leak.py`

  Manifest:

  ```yaml
  id: dlp-2026-005
  category: dlp_egress
  ingestion_path: proposal_dispatch_failure
  trust_tier_of_trigger: T1
  description: |
    Planted API-key in the failure_detail surface of the merged-proposal
    dispatch loop. The attacker has surfaced a Pydantic ValidationError
    whose __str__ embeds an sk-… token; without DLP at this boundary the
    token lands in processed_proposals.failure_detail.
  expected_outcome: audit_row_emitted
  expected_audit_rows:
    - schema_name: PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS
      dlp_redactions_count: 1
  expected_no_audit_rows:
    - schema_name: DLP_OUTBOUND_REFUSED_FIELDS
  ```

  Payload: a malformed proposal blob that triggers `payload_validation` and whose validator-error-message carries the planted key. The test harness simulates the dispatch cycle and asserts the ledger row's `failure_detail` does not contain the raw key.

- [ ] **Task G2 — Write `dispatch-loop-failure-detail-canary-refused` corpus entry.**

  **Files:** Create:
  - `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-canary-refused/manifest.yaml`
  - `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-canary-refused/payload.json`
  - `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-canary-refused/test_dispatch_loop_failure_detail_canary_refused.py`

  Manifest:

  ```yaml
  id: dlp-2026-006
  category: dlp_egress
  ingestion_path: proposal_dispatch_failure
  trust_tier_of_trigger: T1
  description: |
    Planted canary token in the failure_detail surface. The DLP scan
    raises HookRefusal; the ProcessedProposal row insert MUST abort and
    DLP_OUTBOUND_REFUSED_FIELDS MUST emit.
  expected_outcome: refused
  expected_no_processed_proposal_row: true
  expected_audit_rows:
    - schema_name: DLP_OUTBOUND_REFUSED_FIELDS
      refusal_reason: canary_or_secret_in_failure_detail
  expected_no_audit_rows:
    - schema_name: PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS
  ```

  The payload harness injects a refusing DLP stub (same stub the unit test uses) — Slice-3's canary stage is a no-op stub today (`dlp.py:140`), so the refusal arm is exercised via injection. When Slice-3's real canary stage lands the same corpus entry will exercise it against natural inputs.

- [ ] **Task G3 — Verify corpus entries satisfy the prefix/category regex.**

  Run:

  ```bash
  uv run pytest tests/unit/adversarial/test_payload_schema_prefix_pattern.py -q 2>&1 | tail -5
  uv run pytest tests/adversarial/dlp_egress/ -q 2>&1 | tail -10
  ```

  Expected: passes. `dlp-2026-005` and `dlp-2026-006` match `_ID_PATTERN`; both map to `dlp_egress`. If the `dlp-` prefix is missing from `_PREFIX_TO_CATEGORY` PR-S4-0a needs to add it — coordinate.

### Component H — i18n + docs

- [ ] **Task H1 — Add i18n keys.**

  **Files:** Modify `locale/en/LC_MESSAGES/alfred.po`.

  ```
  msgid "state.dispatch.failure_detail_dlp_refused"
  msgstr "Failure-detail DLP refused the write for proposal %(proposal_type)s/%(proposal_id)s."

  msgid "state.dispatch.failure_detail_redacted_audit_emit_failed"
  msgstr "Audit emit failed for the failure-detail redaction row of proposal %(proposal_type)s/%(proposal_id)s."
  ```

  Compile and verify catalog discipline:

  ```bash
  uv run pybabel extract -F babel.cfg -k t -o locale/en/LC_MESSAGES/alfred.pot src/
  uv run pybabel update -i locale/en/LC_MESSAGES/alfred.pot -d locale -l en
  uv run pybabel compile -d locale -l en --use-fuzzy --statistics
  uv run pybabel compile -d locale -l en --check
  ```

- [ ] **Task H2 — Cross-reference in `docs/subsystems/security.md`.**

  **Files:** Modify `docs/subsystems/security.md`.

  Add a single bullet under the "DLP placement" subsection pointing at this PR's wire and naming the two-disjoint-constants invariant (spec §2.1). Full subsystem-doc update lands at PR-S4-11.

### Component I — Quality gates

- [ ] **Task I1 — Run the full quality bar locally.**

  ```bash
  uv run ruff check src/alfred/state/dispatch_loop.py src/alfred/state/dispatch_registry.py src/alfred/security/dlp.py src/alfred/supervisor/core.py
  uv run ruff format --check src/alfred/state/ src/alfred/security/ src/alfred/supervisor/
  uv run mypy src/alfred/state/ src/alfred/security/dlp.py src/alfred/supervisor/core.py
  uv run pyright src/alfred/state/ src/alfred/security/dlp.py src/alfred/supervisor/core.py
  uv run pytest tests/unit/state/ tests/unit/supervisor/ tests/unit/security/test_outbound_dlp_protocol.py tests/unit/audit/test_proposal_dispatch_failure_redacted_constant.py -q
  uv run pytest tests/adversarial/dlp_egress/ -q
  uv run pytest --cov=src/alfred/state/dispatch_loop --cov=src/alfred/security/dlp --cov-branch --cov-fail-under=100 tests/unit/state/ tests/unit/security/test_outbound_dlp_protocol.py
  ```

  Expected: all green. Coverage 100% line + branch on the modified region.

- [ ] **Task I2 — Run the full adversarial suite (release-blocking; PR-S4-2 touches `src/alfred/security/`).**

  ```bash
  uv run pytest tests/adversarial/ -q
  ```

  Expected: all green. The two new entries plus all Slice-3-shipped entries pass.

- [ ] **Task I3 — `make check`.**

  ```bash
  make check
  ```

  Expected: green.

---

## §7 Verification matrix

| Spec line | Test that proves it | PR-S4-2 commits to |
|---|---|---|
| §3.3 line 116 "rename _truncated_detail → _redacted_detail" | `test_truncated_detail_was_renamed_to_redacted_detail` | Symbol rename + body unchanged |
| §3.3 line 117 "scan via OutboundDlp.scan(detail) then _redacted_detail(scanned) where scanned = OutboundDlp.scan(detail).text" | `test_failure_detail_dlp_truncation_after_scan` | Scan happens at call site, truncate runs on the redacted text |
| §3.3 line 118 "PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS emits on every redact-and-truncate" | `test_failure_detail_clean_scan_emits_zero_count` + `test_failure_detail_planted_secret_is_redacted_and_count_emitted` | Success row emits regardless of count (≥0) |
| §3.3 line 121 "DLP_OUTBOUND_REFUSED_FIELDS reserved for refusal; aborts the write" | `test_failure_detail_canary_refusal_aborts_write` | Refusal arm aborts the ProcessedProposal insert + emits refusal row |
| §3.3 line 122 "planted secret → redacted token + dlp_redactions_count==1" | `test_failure_detail_planted_secret_is_redacted_and_count_emitted` | Exact field-value assertion |
| §3.3 line 123 "adversarial entries `dispatch_loop_failure_detail_leak` AND `dispatch_loop_failure_detail_canary_refused`" | `tests/adversarial/dlp_egress/dispatch-loop-failure-detail-{leak,canary-refused}/` | Both entries exist, IDs match `_ID_PATTERN`, prefix maps to `dlp_egress` |
| §3.3 line 125 "Out of scope: threading mechanics from Supervisor boot" | Plan §1 + §4 explicitly mark Supervisor `__init__` kwarg as PR-S4-1's surface | Halt-and-coordinate if PR-S4-1 hasn't landed `self._outbound_dlp` |
| §3.3 line 125 "Out of scope: String(512) column shape" | Migration files untouched; `_redacted_detail` body unchanged at `text[:512]` | No migration in this PR |
| §2.1 table "two disjoint audit-row classes" | `test_failure_detail_canary_refusal_aborts_write` + `test_failure_detail_planted_secret_is_redacted_and_count_emitted` — assert disjoint emission | Sec-005/arch-004 closure |

---

## §8 Release-blocker checklist

Before opening the PR:

- [ ] Verification gate in §2 re-run on the live tree; every YES still YES.
- [ ] `OutboundDlpProtocol` exists at `src/alfred/security/dlp.py`; `__all__` exports it.
- [ ] `ProposalContext.outbound_dlp: OutboundDlpProtocol` field present; required (no default).
- [ ] `_truncated_detail` is gone; `_redacted_detail` is the only name.
- [ ] All 4 historical call sites of `_truncated_detail` route via `ctx.outbound_dlp.scan(...)` before the truncate.
- [ ] `_record_failure` carries the `try / except HookRefusal` arm with `DLP_OUTBOUND_REFUSED_FIELDS` emit + early return.
- [ ] `_record_failure` emits `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` after the ledger insert on every non-refusal path (count=0 OR count=1).
- [ ] `Supervisor.start()` passes `outbound_dlp=self._outbound_dlp` to `ProposalContext(…)`.
- [ ] AST guard `test_dispatch_loop_no_local_dlp_construct.py` passes.
- [ ] Both adversarial corpus entries land with prefix `dlp-` and category `dlp_egress`.
- [ ] `tests/adversarial/` is fully green.
- [ ] Coverage 100% line + branch on the modified region.
- [ ] `make check` green.
- [ ] Cross-provider review request: hand off to `alfred-reviewer` requesting a different model than the implementer used (CLAUDE.md security rules / "How you work" §5).

---

## §9 Threat model anchors (CLAUDE.md hard rules cross-ref)

Per CLAUDE.md "How you work / Threat-model before you implement":

**Attack surface this PR closes:** A merged proposal whose Pydantic validation fails with a `ValidationError` carrying T3-derived bytes (an attacker-controlled JSON payload that surfaces in `exc.errors()[*]['input']`). Today's mitigation is "we only put `type(exc).__name__` through the helper" — a future emit site adding `str(exc)` to the channel silently exfiltrates. This PR makes the boundary truthful: regardless of what call sites pass, the DLP scan runs.

**Attack surface this PR introduces:** None additive — the new sibling audit row `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` carries closed-vocab subject fields (count, byte-lengths, closed-vocab `failure_kind`). No T3 content surfaces in the audit row; only forensic deltas.

**Hard rule cross-ref:**

- CLAUDE.md #1 ("Never log secrets") — closed by DLP scan at the boundary.
- CLAUDE.md #4 ("DLP is on by default and cannot be disabled per-call") — `_record_failure` has no opt-out; every call site of `_redacted_detail` runs through `scan()` first.
- CLAUDE.md #5 ("privileged orchestrator never sees raw T3") — this PR is a defence-in-depth secondary layer; the orchestrator's primary boundary is the dual-LLM split.
- CLAUDE.md #7 ("No silent failures in security paths") — DLP refusal emits `DLP_OUTBOUND_REFUSED_FIELDS` and aborts; audit-emit failure inside that arm raises `_PostHandlerAuditFailure` and trips the supervisor breaker (existing Slice-3 wiring).
