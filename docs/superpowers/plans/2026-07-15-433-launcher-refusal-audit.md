# #433 Launcher-Refusal Audit Persistence Implementation Plan (v2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist the `supervisor.plugin.sandbox_refused` audit row for the quarantine-child launcher path — parse the launcher's stderr JSON, write it via `append_schema`, and dispatch the registered `fail_closed` T0 hookpoint.

**Architecture:** A pure parser (`audit/launcher_refusal.py`) turns launcher stderr bytes into validated `SandboxRefusalRow`s. A reusable auditor (`security/sandbox_refusal_audit.py`) writes each via `append_schema` + dispatches the hookpoint. The refusal is intercepted at the **`read_frame`/`_log_child_stderr` drain** (a refused launcher exits pre-`exec`, so the child produces no frame → EOF → the drain already reads the stderr carrying the row). `_SubprocessChildIO` gains a narrow `SandboxRefusalRecorder` (default `None` = unchanged); `daemon_runtime` constructs the auditor from the `AuditWriter` it already holds and injects it.

**Tech Stack:** Python 3.14+, asyncio, structlog, frozen `@dataclass(frozen=True, slots=True)` value types, pytest, `mypy --strict` + `pyright`.

**Design spec:** `docs/superpowers/specs/2026-07-15-433-launcher-refusal-audit-design.md` (v2). This plan is **v2**, rewritten after the plan-review fleet found the v1 interception point (`ProviderKeyDeliveryError` arm) does not fire on a refusal — the fd-3 key `writev` buffers into the pipe and succeeds. See the spec's "Revision history".

## Global Constraints

- **Depends on merged #432 + #437.** Add or rename NO launcher reason; `test_sandbox_reason_vocab_sync` (#432) fails the build on drift. This PR adds none.
- **Security hard rules (CLAUDE.md).** No silent failures (#7): `append_schema`/`invoke`/parse failures are loud, never swallowed silently. Do not stub the capability/audit layer — use fixture doubles.
- **Trust-boundary coverage.** `audit/launcher_refusal.py`, `security/sandbox_refusal_audit.py`, and the new `_SubprocessChildIO` code require **100% line + branch**. The adversarial suite is release-blocking and MUST run locally (`src/alfred/security/` changes).
- **Typing.** `from __future__ import annotations`; PEP 604 unions; no unjustified `Any`; frozen value types. `mypy --strict` + `pyright` clean.
- **i18n.** No new `t()` strings expected (structlog event keys aren't `t()` scope; the audit event is reused). Run the pybabel drift check anyway.
- **Precursor invariant.** The default-`None` recorder path is behaviorally identical to today — every existing `quarantine_child_io` spawn test stays green untouched.
- **Interception is the `read_frame` drain, NOT the `ProviderKeyDeliveryError` arm and NOT a spawn-time probe** (spec §"The interception point"). Do not re-introduce v1's delivery-arm interception.
- **Commits:** conventional-commit subjects with a literal `#433` after the colon; end every commit body with the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer. No `git add -A`. Never `--no-verify`.

---

## File Structure

- **Create** `src/alfred/audit/launcher_refusal.py` — pure parser + `SandboxRefusalRow`. Consumes `audit_row_schemas`; no I/O, no audit/hook/plugins imports.
- **Create** `src/alfred/security/sandbox_refusal_audit.py` — `SandboxRefusalRecorder` Protocol + `SandboxRefusalAuditor` (append_schema + lazy-imported hookpoint dispatch).
- **Modify** `src/alfred/security/quarantine_child_io.py` — `refusal_recorder` param on `spawn_quarantine_child_io` + `_SubprocessChildIO`; a `_record_launcher_refusals` method called from `_log_child_stderr`.
- **Modify** `src/alfred/comms_mcp/daemon_runtime.py` — construct + inject the auditor.
- **Create** `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md`.
- **Modify** prose: `src/alfred/supervisor/fd3_key_delivery.py`, `docs/subsystems/supervisor.md`, `src/alfred/audit/audit_row_schemas.py`.
- **Create/extend** tests as each task specifies.

---

## Task 0: Empirically confirm the interception point (spike — no production code)

**Why:** v1 shipped a wrong interception point on a plausible-but-false timing assumption. Before writing any production code, PROVE that a real refusing launcher's refusal surfaces at `read_frame` (EOF) with the `sandbox_refused` row in the drained stderr — and that `deliver_provider_key_via_fd3` does NOT raise. If this is falsified, STOP and revise the spec.

**Files:** none committed (throwaway proof) — record the result in the PR description / a scratch note.

- [ ] **Step 1: Reproduce a refusal in a Linux+bwrap container (the real-spawn lane)**

The macOS dev host cannot run the real bwrap spawn (memory: arm64 hits #269, amd64 emulation = `exec format error`). Use a privileged Linux container, mirroring the existing docker real-spawn harness. Run a refusing launcher and observe where the refusal surfaces:

```bash
# In a debian:bookworm --privileged container with the repo + deps installed:
# Drive spawn_quarantine_child_io against a manifest that forces a pre-exec
# refusal (e.g. a missing [sandbox] block -> sandbox_block_missing), and log
# whether deliver_provider_key_via_fd3 raised vs read_frame raised.
```

Concretely: add a temporary assertion to the existing docker real-spawn test (the `Integration (privileged Linux, real spawn)` lane) that spawns with a refusing manifest and asserts: (a) `spawn_quarantine_child_io` returns WITHOUT raising (delivery buffered), (b) the first `read_frame` raises `QuarantineChildSpawnError`, (c) the child's stderr (drained) contains `"event":"supervisor.plugin.sandbox_refused"`.

- [ ] **Step 2: Record the verdict**

- If confirmed (delivery buffers; refusal at `read_frame`): proceed to Task 1.
- If falsified (delivery raises deterministically on a real refusal): STOP. The spec's interception point is wrong; re-open the A-vs-B decision. Do not build Tasks 1-6 on a false premise.

Note: the deterministic unit-level proof of the WIRING (below, Task 3) uses `_FakePopen` and does not need bwrap; Task 0 is specifically the REAL-launcher timing confirmation the review demanded.

---

## Task 1: Pure launcher-refusal parser (`audit/`)

**Files:**

- Create: `src/alfred/audit/launcher_refusal.py`
- Test: `tests/unit/audit/test_launcher_refusal.py`

**Interfaces:**

- Consumes: `SANDBOX_REFUSED_FIELDS`, `SANDBOX_REFUSED_REASONS` from `alfred.audit.audit_row_schemas`.
- Produces:
  - `@dataclass(frozen=True, slots=True) class SandboxRefusalRow` — `plugin_id: str`, `policy_ref: str`, `host_os: str`, `reason: str`, `environment: str`; `def as_subject(self) -> dict[str, str]` (exactly the five `SANDBOX_REFUSED_FIELDS` keys).
  - `def parse_launcher_refusal_rows(stderr: bytes) -> tuple[SandboxRefusalRow, ...]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/audit/test_launcher_refusal.py
"""Unit tests for the pure launcher sandbox-refusal stderr parser (#433)."""

from __future__ import annotations

import json

import pytest

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS
from alfred.audit.launcher_refusal import SandboxRefusalRow, parse_launcher_refusal_rows


def _row_json(**overrides: str) -> bytes:
    row = {
        "event": "supervisor.plugin.sandbox_refused",
        "plugin_id": "alfred.quarantined-llm",
        "reason": "sandbox_block_missing",
        "environment": "development",
        "host_os": "linux",
    }
    row.update(overrides)
    return (json.dumps(row) + "\n").encode("utf-8")


def test_single_valid_row_parsed_and_canonicalized() -> None:
    (row,) = parse_launcher_refusal_rows(_row_json())
    assert row.plugin_id == "alfred.quarantined-llm"
    assert row.reason == "sandbox_block_missing"
    assert row.host_os == "linux"
    assert row.environment == "development"
    assert row.policy_ref == ""  # absent -> canonicalized
    assert set(row.as_subject().keys()) == SANDBOX_REFUSED_FIELDS


def test_policy_ref_present_preserved() -> None:
    (row,) = parse_launcher_refusal_rows(_row_json(policy_ref="policies/sandbox/full.toml"))
    assert row.policy_ref == "policies/sandbox/full.toml"


def test_interleaved_human_lines_ignored() -> None:
    raw = (
        b"supervisor.sandbox.refused.sandbox_block_missing plugin_id=x\n"
        + _row_json()
        + b"policy-resolving\n"
    )
    assert len(parse_launcher_refusal_rows(raw)) == 1


def test_multiple_rows_in_order() -> None:
    raw = _row_json(reason="unknown_host_os") + _row_json(reason="policy_ref_missing")
    assert [r.reason for r in parse_launcher_refusal_rows(raw)] == [
        "unknown_host_os",
        "policy_ref_missing",
    ]


def test_blank_lines_skipped() -> None:
    raw = b"\n   \n" + _row_json() + b"\n\n"
    assert len(parse_launcher_refusal_rows(raw)) == 1


def test_malformed_json_line_dropped() -> None:
    raw = b'{"event":"supervisor.plugin.sandbox_refused", NOT JSON\n' + _row_json()
    assert len(parse_launcher_refusal_rows(raw)) == 1


def test_unknown_event_ignored() -> None:
    raw = (json.dumps({"event": "supervisor.plugin.sandbox_stub_used", "plugin_id": "x"}) + "\n").encode()
    assert parse_launcher_refusal_rows(raw) == ()


def test_out_of_vocab_reason_dropped() -> None:
    assert parse_launcher_refusal_rows(_row_json(reason="totally_made_up")) == ()


def test_missing_required_field_dropped() -> None:
    # A row missing a NON-optional field (host_os) is dropped (branch coverage).
    raw = (
        json.dumps(
            {
                "event": "supervisor.plugin.sandbox_refused",
                "plugin_id": "x",
                "reason": "sandbox_block_missing",
                "environment": "development",
            }
        )
        + "\n"
    ).encode()
    assert parse_launcher_refusal_rows(raw) == ()


def test_extra_unknown_key_dropped() -> None:
    assert parse_launcher_refusal_rows(_row_json(smuggled="oops")) == ()


def test_non_dict_json_ignored() -> None:
    assert parse_launcher_refusal_rows(b'["x"]\n42\n') == ()


def test_non_utf8_bytes_do_not_raise() -> None:
    assert len(parse_launcher_refusal_rows(b"\xff\xfe bad\n" + _row_json())) == 1


def test_empty_returns_empty() -> None:
    assert parse_launcher_refusal_rows(b"") == ()


def test_row_is_frozen() -> None:
    (row,) = parse_launcher_refusal_rows(_row_json())
    with pytest.raises((AttributeError, TypeError)):
        row.reason = "x"  # type: ignore[misc]
```

- [ ] **Step 2: Run to verify fail**

Run: `uv run pytest tests/unit/audit/test_launcher_refusal.py -q`
Expected: FAIL — `ModuleNotFoundError: alfred.audit.launcher_refusal`.

- [ ] **Step 3: Write the parser**

```python
# src/alfred/audit/launcher_refusal.py
"""Pure parser: launcher sandbox-refusal stderr bytes -> validated rows (#433).

``bin/alfred-plugin-launcher.sh`` is the sole producer of
``supervisor.plugin.sandbox_refused``; it ``printf``s the row as one JSON line
to stderr and ``exit 1``s. This module turns that stderr back into validated,
canonicalized :class:`SandboxRefusalRow` values so the core can persist them
(:mod:`alfred.security.sandbox_refusal_audit`). It lives in ``audit/`` next to
the schema it consumes (clean dependency direction; see ADR-0051). Pure — no
I/O, no audit-writer/hook/plugins imports — so it is 100% line+branch testable.

Trust posture: on a refusal the launcher exits BEFORE ``exec``ing the child, so
this stderr is launcher-authored (T0). Validation is defense in depth; #432
(closed reason vocabulary) and #437 (``policy_ref`` charset guard) already
constrain what the launcher writes. Any line that is not a well-formed,
closed-vocab ``sandbox_refused`` row is dropped LOUDLY, never silently.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import structlog

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS, SANDBOX_REFUSED_REASONS

_log = structlog.get_logger(__name__)

_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"

# Optional members a launcher row may omit; canonicalized to "" so the subject
# carries the full symmetric key-set ``AuditWriter.append_schema`` requires.
# ``policy_ref`` is absent from every pre-``policy_ref``-resolution refusal.
_OPTIONAL_FIELDS: frozenset[str] = frozenset({"policy_ref"})


@dataclass(frozen=True, slots=True)
class SandboxRefusalRow:
    """One validated, canonicalized ``supervisor.plugin.sandbox_refused`` row."""

    plugin_id: str
    policy_ref: str
    host_os: str
    reason: str
    environment: str

    def as_subject(self) -> dict[str, str]:
        return {
            "plugin_id": self.plugin_id,
            "policy_ref": self.policy_ref,
            "host_os": self.host_os,
            "reason": self.reason,
            "environment": self.environment,
        }


def parse_launcher_refusal_rows(stderr: bytes) -> tuple[SandboxRefusalRow, ...]:
    """Extract validated ``sandbox_refused`` rows from raw launcher stderr.

    Line-oriented ``json.loads``; accepts only an object whose ``event`` is
    ``supervisor.plugin.sandbox_refused`` with keys ⊆ ``SANDBOX_REFUSED_FIELDS``
    and ``reason`` ∈ ``SANDBOX_REFUSED_REASONS``. Absent optional fields ->  "".
    Rejected lines are logged at warning. Never raises.
    """
    rows: list[SandboxRefusalRow] = []
    for line in stderr.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            candidate = json.loads(stripped)
        except ValueError:
            continue  # a human log line, not JSON — expected
        if not isinstance(candidate, dict) or candidate.get("event") != _REFUSED_EVENT:
            continue
        row = _validated_row(candidate)
        if row is not None:
            rows.append(row)
    return tuple(rows)


def _validated_row(candidate: dict[str, object]) -> SandboxRefusalRow | None:
    payload = {k: v for k, v in candidate.items() if k != "event"}
    unknown = payload.keys() - SANDBOX_REFUSED_FIELDS
    if unknown:
        _log.warning("audit.launcher_refusal.unknown_fields", unknown=sorted(unknown))
        return None
    if payload.get("reason") not in SANDBOX_REFUSED_REASONS:
        _log.warning("audit.launcher_refusal.unknown_reason", reason=payload.get("reason"))
        return None
    missing = (SANDBOX_REFUSED_FIELDS - _OPTIONAL_FIELDS) - payload.keys()
    if missing:
        _log.warning("audit.launcher_refusal.missing_fields", missing=sorted(missing))
        return None
    values = {field: str(payload.get(field, "")) for field in SANDBOX_REFUSED_FIELDS}
    return SandboxRefusalRow(**values)


__all__ = ["SandboxRefusalRow", "parse_launcher_refusal_rows"]
```

- [ ] **Step 4: Run + 100% branch coverage**

Run: `uv run pytest tests/unit/audit/test_launcher_refusal.py -q`
Expected: PASS.

Run: `uv run pytest tests/unit/audit/test_launcher_refusal.py --cov=alfred.audit.launcher_refusal --cov-branch --cov-report=term-missing -q`
Expected: 100% line + branch (`Missing` empty).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/audit/launcher_refusal.py tests/unit/audit/test_launcher_refusal.py
git commit -m "feat(audit): #433 pure launcher sandbox-refusal stderr parser

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Reusable sandbox-refusal auditor

**Files:**

- Create: `src/alfred/security/sandbox_refusal_audit.py`
- Test: `tests/unit/security/test_sandbox_refusal_audit.py`

**Interfaces:**

- Consumes: `SandboxRefusalRow` (Task 1); `SANDBOX_REFUSED_FIELDS`; `AuditWriter.append_schema`; `alfred.hooks` (lazy).
- Produces:
  - `class SandboxRefusalRecorder(Protocol)` — `async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None`.
  - `class SandboxRefusalAuditor` — `__init__(self, *, audit_writer: AuditWriter)`; `async def record(self, rows) -> None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/security/test_sandbox_refusal_audit.py
"""Unit tests for the reusable sandbox-refusal auditor (#433)."""

from __future__ import annotations

from typing import Any

import pytest

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS
from alfred.audit.launcher_refusal import SandboxRefusalRow
from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor


class _FakeAudit:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


def _row(reason: str = "sandbox_block_missing") -> SandboxRefusalRow:
    return SandboxRefusalRow(
        plugin_id="alfred.quarantined-llm",
        policy_ref="",
        host_os="linux",
        reason=reason,
        environment="development",
    )


@pytest.fixture
def _fake_invoke(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    invoked: list[dict[str, Any]] = []

    async def _invoke(name: str, ctx: object, **kwargs: Any) -> object:
        invoked.append({"name": name, **kwargs})
        return ctx

    # invoke is lazily imported inside record(); patch it at its source module.
    monkeypatch.setattr("alfred.hooks.invoke.invoke", _invoke)
    return invoked


@pytest.mark.asyncio
async def test_record_writes_exact_schema_and_dispatches(_fake_invoke: list[dict[str, Any]]) -> None:
    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record((_row(),))
    assert len(audit.calls) == 1
    call = audit.calls[0]
    assert call["event"] == "supervisor.plugin.sandbox_refused"
    assert call["fields"] == SANDBOX_REFUSED_FIELDS
    assert set(call["subject"].keys()) == SANDBOX_REFUSED_FIELDS
    assert call["trust_tier_of_trigger"] == "T0"
    assert call["result"] == "refused"
    assert call["actor_user_id"] is None
    assert call["cost_estimate_usd"] == 0.0
    assert len(_fake_invoke) == 1
    assert _fake_invoke[0]["name"] == "supervisor.plugin.sandbox_refused"
    assert _fake_invoke[0]["fail_closed"] is True


@pytest.mark.asyncio
async def test_record_writes_every_row(_fake_invoke: list[dict[str, Any]]) -> None:
    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record(
        (_row("unknown_host_os"), _row("policy_ref_missing"))
    )
    assert [c["subject"]["reason"] for c in audit.calls] == ["unknown_host_os", "policy_ref_missing"]


@pytest.mark.asyncio
async def test_empty_rows_writes_nothing(_fake_invoke: list[dict[str, Any]]) -> None:
    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record(())
    assert audit.calls == []


@pytest.mark.asyncio
async def test_append_schema_failure_propagates(_fake_invoke: list[dict[str, Any]]) -> None:
    class _BoomAudit:
        async def append_schema(self, **kwargs: Any) -> None:
            raise RuntimeError("db down")

    with pytest.raises(RuntimeError, match="db down"):
        await SandboxRefusalAuditor(audit_writer=_BoomAudit()).record((_row(),))
```

- [ ] **Step 2: Run to verify fail**

Run: `uv run pytest tests/unit/security/test_sandbox_refusal_audit.py -q`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the auditor (lazy hooks import)**

```python
# src/alfred/security/sandbox_refusal_audit.py
"""Persist launcher sandbox-refusal rows + dispatch the fail-closed hookpoint (#433).

The reusable half of the launcher->core audit path (ADR-0051). Given validated
:class:`alfred.audit.launcher_refusal.SandboxRefusalRow` values, writes each as a
``supervisor.plugin.sandbox_refused`` audit row (symmetric ``SANDBOX_REFUSED_FIELDS``
key-set) and dispatches the registered ``fail_closed`` T0 hookpoint, mirroring
``cli/daemon/_boot_audit.py:_invoke_boot_failed``.

``alfred.hooks`` is imported lazily (function-local), mirroring ``_boot_audit.py``
and respecting the known ``hooks -> security.tiers`` back-import.

The quarantine-child spawn is the first adopter (dispatch happens at first
extraction, post-``Supervisor``, so the hookpoint is registered — ADR-0051); the
comms-adapter, gateway-adapter, and foreground-TUI producers adopt this same
auditor in the #433 follow-ups. ``record`` raising is the caller's contract to
handle (the quarantine drain guards it so it never masks the refusal).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Protocol

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS

if TYPE_CHECKING:
    from alfred.audit.launcher_refusal import SandboxRefusalRow
    from alfred.audit.log import AuditWriter


class SandboxRefusalRecorder(Protocol):
    """Narrow seam a launcher-spawn site calls to persist its refusals."""

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None: ...


_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"


class SandboxRefusalAuditor:
    """Writes ``sandbox_refused`` rows + dispatches the fail-closed hookpoint."""

    def __init__(self, *, audit_writer: AuditWriter) -> None:
        self._audit = audit_writer

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
        from alfred.hooks import SYSTEM_ONLY_TIERS
        from alfred.hooks.context import HookContext
        from alfred.hooks.invoke import invoke

        for row in rows:
            correlation_id = str(uuid.uuid4())
            await self._audit.append_schema(
                fields=SANDBOX_REFUSED_FIELDS,
                schema_name="SANDBOX_REFUSED_FIELDS",
                event=_REFUSED_EVENT,
                actor_user_id=None,
                actor_persona="supervisor",
                subject=row.as_subject(),
                trust_tier_of_trigger="T0",
                result="refused",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=correlation_id,
            )
            ctx: HookContext[dict[str, object]] = HookContext(
                action_id=_REFUSED_EVENT,
                hookpoint=_REFUSED_EVENT,
                input={"reason": row.reason, "correlation_id": correlation_id},
                correlation_id=correlation_id,
                kind="post",
            )
            await invoke(
                _REFUSED_EVENT,
                ctx,
                kind="post",
                subscribable_tiers=SYSTEM_ONLY_TIERS,
                fail_closed=True,
            )


__all__ = ["SandboxRefusalAuditor", "SandboxRefusalRecorder"]
```

Note: `Protocol` is at module scope (runtime, not `TYPE_CHECKING`) so it can be exported. The `HookContext(...)` field names + `invoke(...)` args MUST match `_boot_audit.py:_invoke_boot_failed` verbatim — copy them from there at build time; the core-engineer confirmed they match `hooks/context.py` + `hooks/invoke.py`.

- [ ] **Step 4: Run + coverage**

Run: `uv run pytest tests/unit/security/test_sandbox_refusal_audit.py -q`
Expected: PASS.

Run: `uv run pytest tests/unit/security/test_sandbox_refusal_audit.py --cov=alfred.security.sandbox_refusal_audit --cov-branch --cov-report=term-missing -q`
Expected: 100% line + branch.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/security/sandbox_refusal_audit.py tests/unit/security/test_sandbox_refusal_audit.py
git commit -m "feat(sandbox): #433 reusable sandbox-refusal auditor

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: Record refusals at the `read_frame` drain

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py` (`_SubprocessChildIO.__init__`, `_log_child_stderr`, `spawn_quarantine_child_io` signature + the returned instance)
- Test: `tests/unit/security/test_quarantine_child_io_refusal_audit.py`

**Interfaces:**

- Consumes: `SandboxRefusalRecorder` (Task 2, TYPE_CHECKING), `parse_launcher_refusal_rows` (Task 1, function-local import).
- Produces: `spawn_quarantine_child_io(..., refusal_recorder: SandboxRefusalRecorder | None = None)`; `_SubprocessChildIO` records parsed refusals during its stderr drain.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/security/test_quarantine_child_io_refusal_audit.py
"""The read_frame drain records launcher refusals (#433)."""

from __future__ import annotations

import pytest

import alfred.security.quarantine_child_io as child_io_mod
from alfred.audit.launcher_refusal import SandboxRefusalRow
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    _SubprocessChildIO,
)

_REFUSAL_ROW = (
    b'{"event":"supervisor.plugin.sandbox_refused","plugin_id":"alfred.quarantined-llm",'
    b'"reason":"sandbox_block_missing","environment":"development","host_os":"linux"}\n'
)


class _CapturingRecorder:
    def __init__(self) -> None:
        self.rows: list[SandboxRefusalRow] = []

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
        self.rows.extend(rows)


def _exited_fake(stderr: bytes):
    # Reuse the existing _FakePopen convention (test_quarantine_child_io.py:106):
    # empty stdout_frames -> read_frame hits EOF; preset returncode so the drain's
    # ``poll() is not None`` gate fires; stderr carries the refusal JSON.
    from tests.unit.security.test_quarantine_child_io import _FakePopen

    fake = _FakePopen(stdout_frames=[], stderr_bytes=stderr)
    fake.returncode = 1  # launcher exited (refusal) — poll() returns non-None
    return fake


@pytest.mark.asyncio
async def test_refusal_recorded_on_read_frame_eof() -> None:
    recorder = _CapturingRecorder()
    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW), refusal_recorder=recorder)
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == "sandbox_block_missing"


@pytest.mark.asyncio
async def test_default_none_records_nothing() -> None:
    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW))  # no recorder
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    # no crash, unchanged behavior


@pytest.mark.asyncio
async def test_record_failure_does_not_mask_refusal(caplog: pytest.LogCaptureFixture) -> None:
    class _BoomRecorder:
        async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
            raise RuntimeError("audit down")

    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW), refusal_recorder=_BoomRecorder())
    # The read_frame_failed QuarantineChildSpawnError STILL surfaces; the record
    # failure is logged loud, not raised.
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()


@pytest.mark.asyncio
async def test_clean_teardown_records_nothing() -> None:
    # stderr with no sandbox_refused row (child ran) -> aclose drains -> no record.
    recorder = _CapturingRecorder()
    fake = _exited_fake(b"some benign child log line\n")
    io = _SubprocessChildIO(fake, refusal_recorder=recorder)
    await io.aclose()
    assert recorder.rows == []
```

- [ ] **Step 2: Run to verify fail**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_refusal_audit.py -q`
Expected: FAIL — `_SubprocessChildIO.__init__()` has no `refusal_recorder` param.

- [ ] **Step 3: Add the param to `_SubprocessChildIO.__init__`**

In `__init__` (after `egress_config`):

```python
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        control_parent: socket.socket | None = None,
        egress_config: EgressProxyConfig | None = None,
        refusal_recorder: SandboxRefusalRecorder | None = None,
    ) -> None:
        ...
        self._egress_config = egress_config
        self._refusal_recorder = refusal_recorder
```

Add the TYPE_CHECKING import (in the existing type-only import area; add a `TYPE_CHECKING` block if none):

```python
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from alfred.security.sandbox_refusal_audit import SandboxRefusalRecorder
```

- [ ] **Step 4: Add `_record_launcher_refusals` + call it from `_log_child_stderr`**

Add the method (guarded, never raises):

```python
    async def _record_launcher_refusals(self, raw: bytes) -> None:
        """Parse launcher refusal rows from raw stderr + record them. Never raises.

        Called from the stderr drain (a refused launcher exits pre-``exec`` so the
        child produces no frame -> ``read_frame`` EOF -> this drain). Fully
        self-guarding (CLAUDE.md hard rule #7): an ``append_schema`` / ``invoke``
        failure is logged LOUD with an explicit ``error_class`` and swallowed, so
        it neither preempts the ``read_frame_failed`` ``QuarantineChildSpawnError``
        nor breaks ``_log_child_stderr``'s best-effort "never raises" contract.
        """
        if self._refusal_recorder is None:
            return
        try:
            from alfred.audit.launcher_refusal import parse_launcher_refusal_rows

            rows = parse_launcher_refusal_rows(raw)
            if rows:
                await self._refusal_recorder.record(rows)
        except Exception as exc:
            _log.error(
                "security.quarantine_child.refusal_record_failed",
                error_class=type(exc).__name__,
            )
```

In `_log_child_stderr`, after the existing sanitized-field log block (right after the `if sanitized is not None:` block, still inside the `try`):

```python
            if sanitized is not None:
                log = _log.error if failure else _log.warning
                log("security.quarantine_child.child_stderr", child_stderr=sanitized)
            await self._record_launcher_refusals(raw)   # NEW (#433)
```

- [ ] **Step 5: Add the param to `spawn_quarantine_child_io` + thread it to the instance**

Signature:

```python
async def spawn_quarantine_child_io(
    *,
    provider_key: str,
    control_fd: bool = False,
    child_module: str = _CHILD_MODULE,
    egress_config: EgressProxyConfig | None = None,
    refusal_recorder: SandboxRefusalRecorder | None = None,
) -> _SubprocessChildIO:
```

The final return:

```python
    return _SubprocessChildIO(
        process,
        control_parent=control_parent,
        egress_config=egress_config,
        refusal_recorder=refusal_recorder,
    )
```

Do NOT touch the `ProviderKeyDeliveryError` arm's logic (v1's interception is removed; the arm stays as-is — it handles genuine delivery failures, which are rare and out of #433 scope per the spec).

- [ ] **Step 6: Run tests + coverage + precursor invariant**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_refusal_audit.py -q`
Expected: PASS.

Run: `uv run pytest tests/unit/security/test_quarantine_child_io.py tests/unit/security/test_quarantine_child_io_control_fd.py -q`
Expected: PASS (all existing spawn tests green — default-`None` unchanged).

Run: `uv run pytest tests/unit/security/ -k quarantine_child_io --cov=alfred.security.quarantine_child_io --cov-branch --cov-report=term-missing -q`
Expected: the new `_record_launcher_refusals` lines (recorder-None early return, rows-present record, the `except` loud-log) all covered. The `except` branch is covered by `test_record_failure_does_not_mask_refusal`; the None early-return by `test_default_none_records_nothing`; the record-with-rows by `test_refusal_recorded_on_read_frame_eof`; the empty-rows-no-record by `test_clean_teardown_records_nothing`.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io_refusal_audit.py
git commit -m "feat(sandbox): #433 record launcher refusals at the read_frame drain

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Inject the auditor from `daemon_runtime`

**Files:**

- Modify: `src/alfred/comms_mcp/daemon_runtime.py` (`_build_comms_inbound_extractor`)
- Test: `tests/unit/comms_mcp/test_daemon_comms_spawn.py` (extend — this is where the existing `_fake_spawn(*, provider_key)` doubles live; the review pinned line ~393)

**Interfaces:**

- Consumes: `SandboxRefusalAuditor` (Task 2), the `audit_writer` already passed to `_build_comms_inbound_extractor`.
- Produces: the live spawn is called with a real recorder.

- [ ] **Step 1: Write the failing test (reuse the existing doubles + patch the SOURCE module)**

`spawn_quarantine_child_io` is a lazy import inside `_build_comms_inbound_extractor`, so it must be patched at its SOURCE module (`alfred.security.quarantine_child_io`), NOT on `daemon_runtime`, and WITHOUT `raising=False` (which would mask a wrong target). Reuse the existing `_fake_spawn(*, provider_key, ...)` fixture shape in `test_daemon_comms_spawn.py`.

```python
# Add to tests/unit/comms_mcp/test_daemon_comms_spawn.py
@pytest.mark.asyncio
async def test_extractor_injects_refusal_auditor(monkeypatch: pytest.MonkeyPatch, <existing fixtures>) -> None:
    from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor

    seen: dict[str, object] = {}

    async def _fake_spawn(*, provider_key: str, refusal_recorder: object = None, **_k: object) -> object:
        seen["refusal_recorder"] = refusal_recorder
        raise RuntimeError("stop after capturing kwargs")

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
    )
    with pytest.raises(RuntimeError, match="stop after capturing kwargs"):
        await _build_comms_inbound_extractor(
            audit_writer=<fixture audit writer>,
            outbound_dlp=<fixture>,
            secret_broker=<fixture>,
            staging=<fixture>,
        )
    assert isinstance(seen["refusal_recorder"], SandboxRefusalAuditor)
```

Locate the existing `_fake_spawn` / extractor-builder test in `test_daemon_comms_spawn.py` (the review pinned ~393) and reuse its fixtures verbatim rather than reconstructing them.

- [ ] **Step 2: Run to verify fail**

Run: `uv run pytest tests/unit/comms_mcp/test_daemon_comms_spawn.py -k refusal_auditor -q`
Expected: FAIL — `refusal_recorder` is `None` (not yet wired).

- [ ] **Step 3: Wire the auditor**

In `_build_comms_inbound_extractor`, before the spawn:

```python
    from alfred.security.quarantine_child_io import spawn_quarantine_child_io
    from alfred.security.quarantine_transport import QuarantineStdioTransport
    from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor

    provider_key = _resolve_provider_key(secret_broker)
    refusal_recorder = SandboxRefusalAuditor(audit_writer=audit_writer)
    # SINGLE await — the spawn owns the process-wide fd-3 clobber window and must
    # not race any other coroutine (auditor construction above is synchronous).
    child_io = await spawn_quarantine_child_io(
        provider_key=provider_key, refusal_recorder=refusal_recorder
    )
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/comms_mcp/test_daemon_comms_spawn.py -k refusal_auditor -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/daemon_runtime.py tests/unit/comms_mcp/test_daemon_comms_spawn.py
git commit -m "feat(sandbox): #433 inject the sandbox-refusal auditor at daemon boot

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: ADR-0051 + prose corrections + core-001 registry test

**Files:**

- Create: `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md`
- Modify: `src/alfred/supervisor/fd3_key_delivery.py` (docstring ~23-24)
- Modify: `docs/subsystems/supervisor.md` (~362-363)
- Modify: `src/alfred/audit/audit_row_schemas.py` (`NOTE (#433)` ~1194)
- Test: add the core-001 registry assertion to `tests/unit/security/test_sandbox_refusal_audit.py`

- [ ] **Step 1: core-001 registry test (prove the hookpoint is declared at dispatch)**

```python
@pytest.mark.asyncio
async def test_hookpoint_declared_when_supervisor_constructed() -> None:
    # Dispatch resolves the hookpoint against the real registry. It is registered
    # by Supervisor.__init__; the auditor fires at first-extraction (post-Supervisor),
    # so a constructed Supervisor means the hookpoint is declared. Assert the real
    # registry knows the hookpoint after a Supervisor is built.
    from alfred.hooks import get_registry
    # ... construct a Supervisor with fixture deps (reuse an existing supervisor
    # test fixture) ...
    assert "supervisor.plugin.sandbox_refused" in get_registry()  # membership per the registry API
```

Adapt the membership check to the real `HookRegistry` API (read `hooks/registry.py`); reuse an existing Supervisor-construction fixture. If the registry has no simple `__contains__`, assert via its declared-hookpoints accessor.

- [ ] **Step 2: Write ADR-0051**

Create `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md` following the `docs/adr/0050-*.md` structure. Content from the spec's "ADR-0051 outline" — Context / Decision / Consequences / Alternatives — and MUST record: the v1-vs-v2 interception correction (delivery buffers; refusal at `read_frame`), the A-vs-B decision (B: `read_frame` drain, not a spawn-time probe), parser placement in `audit/`, and the guarded-`record()` posture.

- [ ] **Step 3: Correct `fd3_key_delivery.py` prose (~23-24)**

The reason stays reserved in this PR. Reword to descriptive-reserved:

```text
  truncated key. On a partial write / EAGAIN the spawn refuses; the
  ``provider_key_delivery_failed`` reason is RESERVED for a future writer of the
  ``SANDBOX_REFUSED_FIELDS`` row on the genuine-delivery-failure path (a #433
  follow-up), and is not emitted today.
```

- [ ] **Step 4: Correct `supervisor.md` (~362-363)**

Add that a launcher sandbox refusal is persisted at first-extraction via the
`read_frame` drain (ADR-0051, #433); the `provider_key_delivery_failed` reason
remains reserved.

- [ ] **Step 5: Update the `NOTE (#433)` block in `audit_row_schemas.py` (~1194)**

Replace the "not yet persisted" NOTE:

```python
# NOTE (#433): the quarantine-child launcher path now persists this row. A refused
# launcher exits pre-exec, so the child produces no frame -> read_frame EOF ->
# ``_SubprocessChildIO._log_child_stderr`` drains the stderr,
# ``alfred.audit.launcher_refusal.parse_launcher_refusal_rows`` validates it, and
# ``alfred.security.sandbox_refusal_audit.SandboxRefusalAuditor`` writes it +
# dispatches the fail_closed T0 hookpoint (ADR-0051). The three other launcher
# producers (comms adapter, gateway adapter, foreground TUI) and the reserved
# ``provider_key_delivery_failed`` writer adopt the same auditor in #433 follow-ups.
```

- [ ] **Step 6: Lint docs + run the registry test + commit**

Run: `npx --yes markdownlint-cli2@0.22.1 "docs/adr/0051-*.md" "docs/subsystems/supervisor.md"`
Expected: 0 errors (use dash-consistent bullets — MD004 defaults to `consistent`).

Run: `uv run pytest tests/unit/security/test_sandbox_refusal_audit.py -q`
Expected: PASS.

```bash
git add docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md \
        src/alfred/supervisor/fd3_key_delivery.py docs/subsystems/supervisor.md \
        src/alfred/audit/audit_row_schemas.py tests/unit/security/test_sandbox_refusal_audit.py
git commit -m "docs(sandbox): #433 ADR-0051 + correct the refusal-audit prose

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Adversarial corpus entry + full gates + follow-ups

**Files:**

- Create: a REAL adversarial corpus entry under `tests/adversarial/sandbox_escape/` (payload YAML + test), following the existing entries there. Read `tests/adversarial/sandbox_escape/` first; do NOT duplicate `sbx_2026_008_fd3_partial_write`. Use payload id `sbx-2026-018`.

- [ ] **Step 1: Write the adversarial corpus entry**

Mirror the form of an existing `sandbox_escape` entry (YAML with category / threat / provenance + its test). The threat: a launcher refusal row whose field values contain injection bytes must not forge a second `sandbox_refused` audit event or smuggle an out-of-vocab reason. Assert via `parse_launcher_refusal_rows`:

```python
def test_embedded_json_in_value_does_not_forge_a_second_row() -> None:
    raw = (
        b'{"event":"supervisor.plugin.sandbox_refused",'
        b'"plugin_id":"x\\", \\"event\\": \\"forged",'
        b'"reason":"sandbox_block_missing","environment":"development","host_os":"linux"}\n'
    )
    rows = parse_launcher_refusal_rows(raw)
    assert len(rows) == 1 and rows[0].reason == "sandbox_block_missing"


def test_out_of_vocab_reason_cannot_slip_through() -> None:
    raw = (
        b'{"event":"supervisor.plugin.sandbox_refused","plugin_id":"x",'
        b'"reason":"__forged__","environment":"development","host_os":"linux"}\n'
    )
    assert parse_launcher_refusal_rows(raw) == ()
```

- [ ] **Step 2: Run the adversarial suite (release-blocking)**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS (incl. sbx-2026-018, registered + counted by the corpus harness).

- [ ] **Step 3: Vocab-sync + FULL unit suite (the #437 SLICE_4_KEYS lesson)**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q`
Expected: PASS (no launcher reason added).

Run: `uv run pytest tests/unit -q`
Expected: PASS, ≥ the assert-RAN floor. The new structlog keys use `audit.launcher_refusal.` / `security.quarantine_child.refusal_record_failed` (NOT a `supervisor.sandbox.` prefix), so `test_catalog_slice_4_keys` is unaffected — but confirm the full suite, not just touched modules.

- [ ] **Step 4: i18n drift + all quality gates**

Run: `pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins && pybabel update -i /tmp/alfred.pot -o locale/... -D alfred` — first CONFIRM the real catalog layout: `ls locale/` (the review found the v1 command's `src/alfred/locale` path was wrong). Use the repo's actual catalog dir + domain. Expected: no new untranslated msgids (this PR adds no `t()` string).

Run: `make check`
Expected: lint + format + `mypy --strict` + `pyright` + tests green. If piping to `tail`, check `$?`.

- [ ] **Step 5: Commit the adversarial entry**

```bash
git add tests/adversarial/sandbox_escape/  # the new entry's files (named paths only)
git commit -m "test(sandbox): #433 adversarial sbx-2026-018 refusal-row no-forge

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

- [ ] **Step 6: File the follow-up issues**

```bash
gh issue create --title "sandbox: persist sandbox_refused for the comms-adapter launcher producer" \
  --body "Adopt SandboxRefusalAuditor (ADR-0051, #433) in plugins/comms_stdio_transport.py."
gh issue create --title "sandbox: persist sandbox_refused for the gateway-adapter launcher producer" \
  --body "Adopt the shared SandboxRefusalAuditor (ADR-0051, #433) in gateway/adapter_child_factory.py."
gh issue create --title "sandbox: persist sandbox_refused for the foreground-TUI launcher producer" \
  --body "cli/_launcher_spawn.py inherits stderr today; add capture + adopt the auditor (ADR-0051, #433)."
gh issue create --title "sandbox: boot-time fail-closed quarantine health-check (option A)" \
  --body "Detect a quarantine sandbox refusal at boot (probe barrier) and refuse boot, rather than at first extraction. Separate operability concern deferred from #433 (ADR-0051 A-vs-B)."
gh issue create --title "sandbox: write the reserved provider_key_delivery_failed row on genuine fd-3 delivery failure" \
  --body "On a real (rare) fd-3 delivery failure, synthesize the reserved provider_key_delivery_failed sandbox_refused row. Dispatch would be pre-Supervisor -> needs the declare_hookpoints() fix (ADR-0051)."
```

- [ ] **Step 7: Open the PR**

```bash
git push -u origin 433-launcher-refusal-audit
gh pr create --title "feat(sandbox): #433 persist the sandbox_refused audit row (quarantine path)" \
  --body "<summary + design spec + ADR-0051 + the five follow-ups; note the v1->v2 interception correction>"
```

Then the full `/review-pr` fleet (security ALWAYS) + CodeRabbit (CLI + cloud) + alfred-uat, resolve every thread, plain `gh pr merge --rebase` (NEVER `--admin`).

---

## Self-Review (completed by plan author)

**Spec coverage:** Task 0 = empirical interception gate; Task 1 = parser in `audit/`; Task 2 = auditor (lazy hooks import, propagating `record`); Task 3 = `read_frame`-drain interception + recorder on `_SubprocessChildIO` (guarded record, never masks the refusal); Task 4 = daemon injection (correct source-module patch, no `raising=False`); Task 5 = ADR-0051 + prose (fd3 `supervisor/` path) + core-001 registry test; Task 6 = real `sandbox_escape/` corpus entry (not a dup) + fixed pybabel + full gates + 5 follow-ups. Every review finding maps to a task; the v1 Critical is eliminated (no delivery-arm interception).

**Placeholder scan:** the `<...>` in Tasks 4/5 tests are explicit "reuse the named existing fixture" handoffs (grep target given), not gaps. All production code is complete.

**Type consistency:** `SandboxRefusalRow`/`as_subject` (Task 1) used identically in Tasks 2/3/6; `SandboxRefusalRecorder.record(rows)` matches across Task 2 (def), Task 3 (`_refusal_recorder` field + `_record_launcher_refusals`), Task 4 (injection); `parse_launcher_refusal_rows` return type consistent; `SandboxRefusalAuditor(audit_writer=...)` matches Task 2 and Task 4. Import placement: parser in `audit/` (function-local in `quarantine_child_io`), hooks lazy in the auditor.
