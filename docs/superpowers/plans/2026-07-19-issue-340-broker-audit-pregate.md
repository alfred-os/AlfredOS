# #340 broker-audit pre-gate — EgressBrokerAuditor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the durable, signed, core-side per-call egress-audit rows for the SCM_RIGHTS broker (ADR-0050 Decision 7 — a hard PR2b pre-gate) as a `#444`-style normal-cadence PR ahead of the human-sign-off-gated golive cutover, so golive only *wires* an already-shipped auditor.

**Architecture:** A new `EgressBrokerAuditor` writes two egress-audit-family rows via the existing `AuditWriter.append_schema` + a T0 fail-closed hookpoint: a success row per brokered gateway target (`{destination, egress_id}`) and a refused row (`{destination, reason, egress_id}`, closed-vocab reason). It ships **dormant** — its only callers arrive in golive (which flips `control_fd=True`). The per-call success-row await is bounded so a hung `append_schema` cannot stall the extraction hot path (full 11-lens finding err-004/sec-006; distinct from #461's teardown case).

**Tech Stack:** Python 3.14+, Pydantic v2, structlog audit rows + hooks, `hashlib` (deterministic non-secret `egress_id`), pytest + `structlog.testing`, the adversarial harness.

## Global Constraints

- **Python floor `>=3.14.6`**; PEP 604/585/695 idioms; frozen models; `mypy --strict` + `pyright` clean; `ruff` clean.
- **HARD #7 — no silent failures in security paths.** A broker failure → a loud, durable, signed audit row + a `quarantine.transport_failed` typed refusal (wired in golive), never a swallow, never an unbounded hang.
- **This is an egress-audit family change ratified by spec §21** (the golive spec's `2026-07-11-issue-340-pr2b-golive-cutover-design.md` §21 fold-appendix) — **which must clear `alfred-reviewer` before this PR merges** (the architect does not self-approve).
- **100% line + branch coverage** on `src/alfred/egress/broker_audit.py` and any touched `audit_row_schemas.py` paths; a **named coverage gate** for `broker_audit.py` (it sits outside the `security/*` glob — full-fleet finding ops-001).
- **Adversarial suite is release-blocking** (audit / security path touched).
- **i18n:** the auditor writes structlog event keys + machine reason tokens (NOT `t()` scope); no operator-facing string is added here.
- **Commit subjects carry `#340` after the colon**; end with the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer; body "Part of #340", NO closing keyword.
- **Never `git stash`/`checkout`/`reset` to inspect base state** — use `git show <base>:<path>`.

**Authoritative refs:** the golive spec **§7 + §21** (the amendment ratifying this family) + **ADR-0050 Decision 7** + **ADR-0040 residual (vii)**. The full 11-lens `/review-plan` findings this PR resolves: ops-001 (no named coverage gate), sec-004/err-003 (broker-failure row underspecified), err-004/sec-006 (bound the new hot-path await), rev-003/arch-004/sec-005 (audit-family divergence → ratified here).

---

## File Structure

**New:**

- `src/alfred/egress/broker_audit.py` — `EgressBrokerAuditor` (success + failure rows + T0 fail-closed hookpoint + bounded await).
- `tests/unit/egress/test_broker_audit.py` — 100% unit coverage.
- `tests/adversarial/dlp_egress/de_2026_0NN_broker_failure_audited.yaml` — release-blocking: a broker failure yields a durable signed refused row, never a silent swallow.

**Modified:**

- `src/alfred/audit/audit_row_schemas.py` — `EGRESS_BROKER_SUCCESS_FIELDS`, `EGRESS_BROKER_REFUSED_FIELDS`, `EGRESS_BROKER_REFUSED_REASONS`; register in the exported schema roster.
- `src/alfred/egress/control_fd_broker.py` — `broker_connected_socket` returns `(host, port)` (behavior-neutral; the row's `destination` input; unused until golive).
- `tests/unit/audit/test_slice_4_audit_row_fields.py` — extend the bidirectional AST-walk roster + a reason-vocab binding test.
- `.github/workflows/ci.yml` — named 100% coverage gate for `broker_audit.py`.
- `docs/adr/0050-*.md` (Decision 7: mark the row now shipped) + `docs/adr/0040-*.md` residual (vii) note (the broker path now writes durable rows).
- The golive spec `2026-07-11-issue-340-pr2b-golive-cutover-design.md` already carries the §20 (`#443` two-frame-handshake reconciliation) and §21 (broker audit-row family) fold-appendices — this PR ships both for `alfred-reviewer` ratification.

---

## Task 1: Egress-broker audit schemas + closed reason vocab + drift-guards

**Files:**

- Modify: `src/alfred/audit/audit_row_schemas.py` (near `EGRESS_RELAY_REFUSED_FIELDS:1567`)
- Modify: `tests/unit/audit/test_slice_4_audit_row_fields.py`
- Test: `tests/unit/audit/test_egress_broker_reason_vocab.py` (create)

**Interfaces:**

- Produces: `EGRESS_BROKER_SUCCESS_FIELDS: Final[frozenset[str]] = frozenset({"destination", "egress_id"})`; `EGRESS_BROKER_REFUSED_FIELDS: Final[frozenset[str]] = frozenset({"destination", "reason", "egress_id"})`; `EGRESS_BROKER_REFUSED_REASONS: Final[frozenset[str]]` bound to `ControlFdBrokerError`'s six-member reason vocab. Consumed by Task 2's auditor.

- [ ] **Step 1: Write the failing drift-guard test** (bind the reason frozenset to the exception's vocab, #432 pattern)

```python
# tests/unit/audit/test_egress_broker_reason_vocab.py
import ast
from pathlib import Path

from alfred.audit.audit_row_schemas import EGRESS_BROKER_REFUSED_REASONS


def _controlfdbrokererror_reasons() -> set[str]:
    # Independently derive the reason vocab from the string literals ControlFdBrokerError
    # is raised with, so this test does NOT reuse EGRESS_BROKER_REFUSED_REASONS as its own oracle.
    src = Path("src/alfred/egress/control_fd_broker.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    reasons: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "ControlFdBrokerError":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    reasons.add(arg.value)
    # default reason on the bare-constructor path
    reasons.add("control_fd_broker_failed")
    return reasons


def test_broker_reason_vocab_matches_exception_source() -> None:
    assert EGRESS_BROKER_REFUSED_REASONS == _controlfdbrokererror_reasons()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/audit/test_egress_broker_reason_vocab.py -v`
Expected: FAIL (`ImportError: EGRESS_BROKER_REFUSED_REASONS`).

- [ ] **Step 3: Add the constants + register them**

```python
# src/alfred/audit/audit_row_schemas.py  (near EGRESS_RELAY_REFUSED_FIELDS)
EGRESS_BROKER_SUCCESS_FIELDS: Final[frozenset[str]] = frozenset({"destination", "egress_id"})
EGRESS_BROKER_REFUSED_FIELDS: Final[frozenset[str]] = frozenset({"destination", "reason", "egress_id"})
# Closed vocab bound to ControlFdBrokerError (spec §21.3; #432/#434-436 drift-guard pattern).
EGRESS_BROKER_REFUSED_REASONS: Final[frozenset[str]] = frozenset(
    {
        "gateway_unreachable",
        "sendmsg_failed",
        "ancillary_truncated",
        "expected_exactly_one_fd",
        "short_data_send",
        "control_fd_broker_failed",
    }
)
```

Register both `*_FIELDS` in the module's exported schema roster (mirror `EGRESS_RELAY_REFUSED_FIELDS`'s registration).

- [ ] **Step 4: Extend the AST-walk roster test**

In `test_slice_4_audit_row_fields.py`, add `EGRESS_BROKER_SUCCESS_FIELDS` + `EGRESS_BROKER_REFUSED_FIELDS` to the bidirectional roster (every `*_FIELDS` constant is walked ↔ every emitted subject's keys match) exactly as `EGRESS_RELAY_REFUSED_FIELDS` is handled.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/unit/audit/test_egress_broker_reason_vocab.py tests/unit/audit/test_slice_4_audit_row_fields.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/audit/audit_row_schemas.py tests/unit/audit/test_slice_4_audit_row_fields.py tests/unit/audit/test_egress_broker_reason_vocab.py
git commit -m "$(cat <<'EOF'
feat(security): #340 egress-broker audit schemas + closed reason vocab

Part of #340 (spec §21). Adds EGRESS_BROKER_SUCCESS_FIELDS / _REFUSED_FIELDS
(egress-audit family, mirroring EGRESS_RELAY_REFUSED_FIELDS) + a closed
EGRESS_BROKER_REFUSED_REASONS frozenset bound to ControlFdBrokerError's vocab via
an AST drift-guard (#432 pattern), plus the bidirectional AST-walk roster entries.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 2: `EgressBrokerAuditor` — success + failure rows + T0 hookpoint + bounded await

**Files:**

- Create: `src/alfred/egress/broker_audit.py`
- Test: `tests/unit/egress/test_broker_audit.py`
- Reference: `src/alfred/security/sandbox_refusal_audit.py` (the T0 fail-closed hookpoint pattern)

**Interfaces:**

- Consumes: `AuditWriter.append_schema` (`audit/log.py:105`, symmetric key validation); the Task-1 schemas; the hook `invoke(..., subscribable_tiers=SYSTEM_ONLY_TIERS, fail_closed=True)` pattern from `SandboxRefusalAuditor`.
- Produces: `EgressBrokerAuditor(audit_writer, *, audit_await_timeout_s: float = _AUDIT_AWAIT_TIMEOUT_S)` with `async record_broker_success(*, destination: str)` and `async record_broker_failure(*, destination: str, reason: str)`. Both write a signed T0 row + dispatch the fail-closed hookpoint. The success-row write is **bounded** by `asyncio.wait_for(audit_await_timeout_s)` (D3 — a hung `append_schema` on the extraction hot path must not stall it; on timeout it logs loud + re-raises so the caller fails closed, never silently). Consumed by golive's `broker_sockets` wiring.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/egress/test_broker_audit.py
import asyncio
import pytest
from alfred.egress.broker_audit import EgressBrokerAuditor


class _RecordingAuditWriter:
    def __init__(self, *, hang: bool = False) -> None:
        self.rows: list[dict] = []
        self._hang = hang
    async def append_schema(self, **kw) -> None:
        if self._hang:
            await asyncio.sleep(3600)
        self.rows.append(kw)


async def test_success_row_signed_t0_with_destination_and_egress_id() -> None:
    w = _RecordingAuditWriter()
    await EgressBrokerAuditor(w).record_broker_success(destination="gateway:8889")
    row = w.rows[-1]
    assert row["event"] == "egress.broker.connected"
    assert row["trust_tier_of_trigger"] == "T0"
    assert row["result"] == "success"
    assert set(row["subject"]) == row["fields"]        # symmetric key validation
    assert row["subject"]["destination"] == "gateway:8889"
    assert len(row["subject"]["egress_id"]) == 64      # sha256 hex, non-secret


async def test_failure_row_carries_closed_vocab_reason() -> None:
    w = _RecordingAuditWriter()
    await EgressBrokerAuditor(w).record_broker_failure(destination="gateway:8889", reason="gateway_unreachable")
    assert w.rows[-1]["result"] == "refused"
    assert w.rows[-1]["subject"]["reason"] == "gateway_unreachable"


async def test_bounded_await_fails_loud_not_silent() -> None:
    # A hung append_schema must not hang the extraction hot path forever (D3).
    w = _RecordingAuditWriter(hang=True)
    with pytest.raises((TimeoutError, asyncio.TimeoutError)):
        await EgressBrokerAuditor(w, audit_await_timeout_s=0.05).record_broker_success(destination="gateway:8889")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/egress/test_broker_audit.py -v`
Expected: FAIL (`ModuleNotFoundError: broker_audit`).

- [ ] **Step 3: Write the auditor**

```python
# src/alfred/egress/broker_audit.py
"""Durable, signed, core-side per-call egress-audit rows for the SCM_RIGHTS broker
(ADR-0050 Decision 7; golive spec §21; addresses ADR-0040 residual (vii)).

Egress-audit family (spec §21): a broker failure is an egress event, not a sandbox
refusal — the row carries `destination` (host:port), which SANDBOX_REFUSED_FIELDS
cannot hold. Ships dormant; golive is the only caller (it flips control_fd=True)."""
from __future__ import annotations

import asyncio
import hashlib
import uuid

import structlog

from alfred.audit.audit_row_schemas import (
    EGRESS_BROKER_REFUSED_FIELDS,
    EGRESS_BROKER_SUCCESS_FIELDS,
)
from alfred.audit.log import AuditWriter

_log = structlog.get_logger(__name__)
_CONNECTED_EVENT = "egress.broker.connected"
_REFUSED_EVENT = "egress.broker.refused"
# Bound the per-extraction hot-path await (spec §21.4 / D3; distinct from #461's
# teardown case): a hung append_schema must fail loud, never stall the extraction.
_AUDIT_AWAIT_TIMEOUT_S: float = 5.0


def _egress_id(destination: str) -> str:
    return hashlib.sha256(destination.encode("utf-8")).hexdigest()  # non-secret, deterministic


class EgressBrokerAuditor:
    def __init__(self, audit_writer: AuditWriter, *, audit_await_timeout_s: float = _AUDIT_AWAIT_TIMEOUT_S) -> None:
        self._audit = audit_writer
        self._timeout = audit_await_timeout_s

    async def record_broker_success(self, *, destination: str) -> None:
        await self._write(
            fields=EGRESS_BROKER_SUCCESS_FIELDS, schema_name="EGRESS_BROKER_SUCCESS_FIELDS",
            event=_CONNECTED_EVENT, result="success",
            subject={"destination": destination, "egress_id": _egress_id(destination)},
        )

    async def record_broker_failure(self, *, destination: str, reason: str) -> None:
        await self._write(
            fields=EGRESS_BROKER_REFUSED_FIELDS, schema_name="EGRESS_BROKER_REFUSED_FIELDS",
            event=_REFUSED_EVENT, result="refused",
            subject={"destination": destination, "reason": reason, "egress_id": _egress_id(destination)},
        )

    async def _write(self, *, fields, schema_name, event, result, subject) -> None:
        from alfred.hooks import SYSTEM_ONLY_TIERS
        from alfred.hooks.context import HookContext
        from alfred.hooks.invoke import invoke

        correlation_id = str(uuid.uuid4())
        try:
            await asyncio.wait_for(
                self._audit.append_schema(
                    fields=fields, schema_name=schema_name, event=event,
                    actor_user_id=None, actor_persona="supervisor", subject=subject,
                    trust_tier_of_trigger="T0", result=result, cost_estimate_usd=0.0,
                    cost_actual_usd=0.0, trace_id=correlation_id,
                ),
                timeout=self._timeout,
            )
        except TimeoutError:
            _log.error("egress.broker.audit_write_timeout", event=event, correlation_id=correlation_id)
            raise
        ctx: HookContext[dict[str, object]] = HookContext(
            action_id=event, hookpoint=event,
            input={"result": result, "correlation_id": correlation_id},
            correlation_id=correlation_id, kind="post",
        )
        await invoke(event, ctx, kind="post", subscribable_tiers=SYSTEM_ONLY_TIERS, fail_closed=True)
```

> **Coverage note (ops-001):** `broker_audit.py` is outside the `security/*` glob → Task 5 adds a **named** 100% line+branch coverage gate for it in `ci.yml` (otherwise a regression ships green).

- [ ] **Step 4: Run tests + coverage**

Run: `uv run pytest tests/unit/egress/test_broker_audit.py --cov=alfred.egress.broker_audit --cov-branch --cov-report=term-missing -v`
Expected: PASS at 100% line + branch (incl. the timeout branch + both row shapes).

- [ ] **Step 5: mypy/pyright**

Run: `uv run mypy src/alfred/egress/broker_audit.py && uv run pyright src/alfred/egress/broker_audit.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/egress/broker_audit.py tests/unit/egress/test_broker_audit.py
git commit -m "$(cat <<'EOF'
feat(security): #340 EgressBrokerAuditor — signed T0 broker rows, bounded await

Part of #340 (spec §21, ADR-0050 D7). Writes egress.broker.connected (success) +
egress.broker.refused (failure, closed-vocab reason) durable signed T0 rows via
append_schema + a fail-closed hookpoint; the hot-path await is bounded (wait_for)
so a hung write fails loud, not a silent stall (D3, distinct from #461). Ships
dormant — golive flips control_fd=True and calls it.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 3: `broker_connected_socket` returns `(host, port)` (behavior-neutral)

**Files:**

- Modify: `src/alfred/egress/control_fd_broker.py` (`broker_connected_socket:157`)
- Test: `tests/unit/egress/test_control_fd_broker.py` (extend)

**Interfaces:**

- Produces: `broker_connected_socket(*, parent_end, proxy_config) -> tuple[str, int]` — returns the resolved gateway `(host, port)` it brokered to (already computed via `_resolve_proxy_addr`), so golive's `broker_sockets` can pass the `destination` to `EgressBrokerAuditor.record_broker_success`. Behavior-neutral: the return value is unused until golive wires it.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/egress/test_control_fd_broker.py  (add)
async def test_broker_connected_socket_returns_destination(monkeypatch) -> None:
    # ... existing harness that stubs the executor connect+send ...
    host, port = await broker_connected_socket(parent_end=parent, proxy_config=_Cfg("http://gw:8889"))
    assert (host, port) == ("gw", 8889)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/egress/test_control_fd_broker.py::test_broker_connected_socket_returns_destination -v`
Expected: FAIL (returns `None`).

- [ ] **Step 3: Return the resolved addr**

```python
async def broker_connected_socket(*, parent_end: socket.socket, proxy_config: EgressProxyConfig) -> tuple[str, int]:
    host, port = _resolve_proxy_addr(proxy_config)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _connect_and_send, parent_end, host, port)
    return host, port
```

- [ ] **Step 4: Run the broker suite + coverage**

Run: `uv run pytest tests/unit/egress/test_control_fd_broker.py --cov=alfred.egress.control_fd_broker --cov-branch --cov-report=term-missing -v`
Expected: PASS at 100% (existing callers ignore the return; the docker probe unaffected).

- [ ] **Step 5: Confirm no live caller regresses**

Run: `uv run pytest tests/integration/test_quarantine_fd_broker_real_spawn.py -v` (docker/Linux lane; skips on macOS — trust Linux CI)
Expected: PASS/skip (PR2a probe path unchanged).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/egress/control_fd_broker.py tests/unit/egress/test_control_fd_broker.py
git commit -m "$(cat <<'EOF'
refactor(security): #340 broker_connected_socket returns the brokered (host, port)

Part of #340. Returns the resolved gateway destination (already computed) so the
golive wiring can supply it to the EgressBrokerAuditor success row. Behavior-neutral
— unused until golive.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 4: Release-blocking adversarial payload — a broker failure is audited, never swallowed

**Files:**

- Create: `tests/adversarial/dlp_egress/de_2026_0NN_broker_failure_audited.yaml` (next monotonic `de-` id)
- Modify: the paired executable test if the corpus category requires one (mirror the existing `de-*` egress payloads)
- Test: the adversarial corpus suite

**Interfaces:**

- Produces: a schema-valid `AdversarialPayload` (`extra="forbid"`) asserting that a broker `ControlFdBrokerError` produces a durable signed `egress.broker.refused` row (closed-vocab reason) + never a silent swallow — the HARD#7 audit-completeness invariant for the new egress path.

- [ ] **Step 1: Write the payload**

```yaml
# tests/adversarial/dlp_egress/de_2026_0NN_broker_failure_audited.yaml
id: de-2026-0NN            # next monotonic de- id (grep tests/adversarial/dlp_egress)
category: dlp_egress
threat: >-
  A gateway-socket broker failure on the quarantine egress path (unreachable gateway,
  SCM_RIGHTS send failure) could be swallowed silently, leaving no durable record that
  an extraction's egress was denied. This payload asserts the failure is written to the
  signed core audit log as a closed-vocab egress.broker.refused row (ADR-0050 D7,
  ADR-0040 residual (vii)), never a silent swallow (HARD #7).
ingestion_path: wire_format_deser
payload:
  attack: broker_failure_silent_swallow
  probe: ControlFdBrokerError('gateway_unreachable')
expected_outcome: caught_by_dlp
provenance: >-
  Authored with the #340 broker-audit pre-gate (golive spec §21): the durable signed
  egress-audit row for the SCM_RIGHTS broker lands ahead of the golive cutover.
references:
  - "src/alfred/egress/broker_audit.py (EgressBrokerAuditor)"
  - "docs/adr/0050-quarantine-child-scm-rights-reachability-broker.md (Decision 7)"
  - "docs/superpowers/specs/2026-07-11-issue-340-pr2b-golive-cutover-design.md (§21)"
```

(Adjust `ingestion_path`/`expected_outcome`/`category` to the closest valid enum members + the paired-test convention of the existing `de-*` corpus entries — confirm against `tests/adversarial/dlp_egress/` at implementation time. If the category requires an executable driver, add `test_de_2026_0NN_broker_failure_audited.py` that drives a failing broker through `EgressBrokerAuditor.record_broker_failure` and asserts the durable row via `structlog.testing.capture_logs` / the audit-writer double.)

- [ ] **Step 2: Run the corpus validator + the driver**

Run: `uv run pytest tests/adversarial/dlp_egress -k "broker_failure or corpus" -v`
Expected: PASS (id unique, prefix ↔ category, enums valid; the driver asserts the durable row).

- [ ] **Step 3: Confirm it is release-blocking** (registered by the corpus glob; not `out_of_scope`).

- [ ] **Step 4: Full adversarial suite** (non-bwrap runs locally; bwrap → Linux CI)

Run: `uv run pytest tests/adversarial -q`
Expected: PASS / bwrap-skips only.

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/dlp_egress/de_2026_0NN_broker_failure_audited.yaml
git commit -m "$(cat <<'EOF'
test(security): #340 adversarial — broker failure is durably audited, not swallowed

Part of #340. Release-blocking payload: a ControlFdBrokerError yields a signed
egress.broker.refused row (closed-vocab reason), never a silent swallow (HARD #7).

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 5: Named coverage gate + ADR touch + §21 ratification

**Files:**

- Modify: `.github/workflows/ci.yml` (named 100% gate for `broker_audit.py`)
- Modify: `docs/adr/0050-*.md` (Decision 7 now shipped), `docs/adr/0040-*.md` (residual (vii) note)
- Reference: the golive spec §21 (already committed) — this PR ships it for `alfred-reviewer` ratification

**Interfaces:** CI + docs only.

- [ ] **Step 1: Add the named coverage gate** in `ci.yml` — a 100% line+branch gate on `src/alfred/egress/broker_audit.py` (mirror the existing `control_fd_broker.py` named gate; ops-001 requires it because the file is outside the `security/*` coverage glob).

- [ ] **Step 2: Amend ADR-0050 Decision 7** — record that the per-call egress-audit row is now **shipped** (was "hard PR2b pre-gate; not yet wired"), with the egress-audit-family choice + the §21 amendment reference.

- [ ] **Step 3: Amend ADR-0040 residual (vii)** — the SCM_RIGHTS broker path now writes durable signed core-side rows (partial resolution of (vii) for this path; the full gateway-audit reconcile stays deferred).

- [ ] **Step 4: markdownlint the ADRs**

Run: `npx --yes markdownlint-cli2@0.22.1 "docs/adr/0050-*.md" "docs/adr/0040-*.md"`
Expected: 0 errors.

- [ ] **Step 5: Full gates**

Run: `make check`
Expected: exit 0 (unit + lint + format + mypy + pyright; the named `broker_audit.py` gate green; adversarial + bwrap legs on Linux CI).

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml docs/adr/0050-quarantine-child-scm-rights-reachability-broker.md docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md
git commit -m "$(cat <<'EOF'
ci(security): #340 named coverage gate for broker_audit + ADR-0050/0040 touch

Part of #340. Adds the named 100% line+branch gate for the out-of-security-glob
broker_audit.py (ops-001), marks ADR-0050 Decision 7 shipped (egress-audit family
per spec §21), and notes ADR-0040 residual (vii) now has durable core-side rows for
the broker path.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Self-Review

- **Coverage:** §21 (egress-audit family + drift-guard) → T1; ADR-0050 D7 durable row → T2/T5; ADR-0040 (vii) → T5; the bounded hot-path await (D3 / err-004 / sec-006) → T2; the named coverage gate (ops-001) → T5; the destination input → T3; adversarial audit-completeness → T4. ✓
- **Placeholder scan:** the only deferred specifics are the `de-` id and the exact corpus category/driver convention (T4) — flagged to confirm against the existing `dlp_egress` corpus at implementation time, not hand-waved. ✓
- **Type consistency:** `EgressBrokerAuditor.record_broker_success/failure` (T2) ↔ golive's wiring; `broker_connected_socket -> (host, port)` (T3) ↔ the `destination` input; `EGRESS_BROKER_*` names consistent T1↔T2↔T5. ✓
- **Ratification dependency:** this PR merges only after `alfred-reviewer` clears the §21 amendment (the architect authored it). Flagged in Global Constraints.

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-07-19-issue-340-broker-audit-pregate.md`. This is a normal-cadence PR (no human sign-off) that must merge **before** golive. After it merges, the golive plan rev.2's Task 10 shrinks to wiring the already-shipped `EgressBrokerAuditor`.

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, per-task security review on T1/T2/T4 (the audit-write + drift-guard tasks), opus whole-branch final.
2. **Inline Execution** — checkpoints for review.
