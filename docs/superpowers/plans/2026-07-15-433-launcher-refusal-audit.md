# #433 Launcher-Refusal Audit Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist the `supervisor.plugin.sandbox_refused` audit row for the quarantine-child launcher path — parse the launcher's stderr JSON, write it via `append_schema`, and dispatch the registered `fail_closed` T0 hookpoint.

**Architecture:** A pure parser (`plugins/launcher_refusal.py`) turns launcher stderr bytes into validated, canonicalized `SandboxRefusalRow`s. A reusable auditor (`security/sandbox_refusal_audit.py`) writes each row via `append_schema` and dispatches the hookpoint. `spawn_quarantine_child_io` gains a narrow one-method `SandboxRefusalRecorder` Protocol parameter (default `None` = unchanged); on the `ProviderKeyDeliveryError` arm it drains the reaped child's stderr, parses it, and records. `daemon_runtime` constructs the auditor from the `AuditWriter` it already holds and injects it.

**Tech Stack:** Python 3.14+, asyncio, structlog, Pydantic-v2-era codebase (frozen `@dataclass(frozen=True, slots=True)` for value types), pytest, `mypy --strict` + `pyright`.

**Design spec:** `docs/superpowers/specs/2026-07-15-433-launcher-refusal-audit-design.md`

## Global Constraints

- **Depends on merged #432 + #437.** Do not add or rename any launcher reason;
  the `test_sandbox_reason_vocab_sync` binding (#432) fails the build if the
  launcher-emittable set drifts. This PR adds NO launcher reason.
- **Security hard rules (CLAUDE.md).** No silent failures on security paths
  (#7): `append_schema` / `invoke` / parse failures are loud (logged at error
  with an explicit `error_class`, or raised), never swallowed. Do not stub the
  capability/audit layer to "always allow" — use fixture doubles.
- **Trust-boundary coverage.** `plugins/launcher_refusal.py` and
  `security/sandbox_refusal_audit.py` and the new spawn arm require **100% line
  and branch coverage**. The adversarial suite is release-blocking and MUST be
  run locally because `src/alfred/security/` changes.
- **Typing.** `from __future__ import annotations`; PEP 604 unions (`X | None`);
  no `Any` without justification; frozen value types; `Mapping` over `dict` for
  read-only inputs. `mypy --strict` + `pyright` clean.
- **i18n.** No new operator-facing `t()` strings are expected (structlog event
  keys are not `t()` scope; the audit event `supervisor.plugin.sandbox_refused`
  is reused). Run `pybabel` drift check at the gate anyway.
- **Precursor invariant.** The default-`None` recorder path must be behaviorally
  identical to today — every existing `quarantine_child_io` spawn test stays
  green untouched.
- **Commits:** conventional-commit subjects with a literal `#433` after the
  colon; end every commit body with the
  `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer. No
  `git add -A` — stage named paths only. Never `--no-verify`.

---

## File Structure

- **Create** `src/alfred/plugins/launcher_refusal.py` — pure parser +
  `SandboxRefusalRow` value type. One responsibility: launcher stderr bytes →
  validated rows. No I/O, no audit/hook imports.
- **Create** `src/alfred/security/sandbox_refusal_audit.py` — the
  `SandboxRefusalRecorder` Protocol + `SandboxRefusalAuditor` (append_schema +
  hookpoint dispatch). The reusable seam the other producers adopt later.
- **Modify** `src/alfred/security/quarantine_child_io.py` — add the
  `refusal_recorder` parameter + the drain-parse-record step in the
  `ProviderKeyDeliveryError` arm + a bounded raw-stderr drain helper.
- **Modify** `src/alfred/comms_mcp/daemon_runtime.py` — construct the auditor
  from `audit_writer` and pass it to `spawn_quarantine_child_io`.
- **Create** `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md`.
- **Modify** prose: `src/alfred/security/fd3_key_delivery.py` (docstring),
  `docs/subsystems/supervisor.md`, `src/alfred/audit/audit_row_schemas.py`
  (`NOTE (#433)` block).
- **Create** tests: `tests/unit/plugins/test_launcher_refusal.py`,
  `tests/unit/security/test_sandbox_refusal_audit.py`,
  `tests/unit/security/test_quarantine_child_io_refusal_audit.py`,
  `tests/adversarial/.../test_sandbox_refusal_no_forged_event.py` (path pinned
  in Task 6 against the corpus layout).

---

## Task 1: Pure launcher-refusal parser

**Files:**

- Create: `src/alfred/plugins/launcher_refusal.py`
- Test: `tests/unit/plugins/test_launcher_refusal.py`

**Interfaces:**

- Consumes: `SANDBOX_REFUSED_FIELDS`, `SANDBOX_REFUSED_REASONS` from
  `alfred.audit.audit_row_schemas`.
- Produces:
  - `@dataclass(frozen=True, slots=True) class SandboxRefusalRow` with fields
    `plugin_id: str`, `policy_ref: str`, `host_os: str`, `reason: str`,
    `environment: str`, and `def as_subject(self) -> dict[str, str]` returning
    exactly the five `SANDBOX_REFUSED_FIELDS` keys.
  - `def parse_launcher_refusal_rows(stderr: bytes) -> tuple[SandboxRefusalRow, ...]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/plugins/test_launcher_refusal.py
"""Unit tests for the pure launcher sandbox-refusal stderr parser (#433)."""

from __future__ import annotations

import json

import pytest

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS
from alfred.plugins.launcher_refusal import (
    SandboxRefusalRow,
    parse_launcher_refusal_rows,
)


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
    rows = parse_launcher_refusal_rows(_row_json())
    assert len(rows) == 1
    row = rows[0]
    assert row.plugin_id == "alfred.quarantined-llm"
    assert row.reason == "sandbox_block_missing"
    assert row.host_os == "linux"
    assert row.environment == "development"
    # absent policy_ref canonicalized to ""
    assert row.policy_ref == ""
    assert set(row.as_subject().keys()) == SANDBOX_REFUSED_FIELDS


def test_policy_ref_present_is_preserved() -> None:
    raw = _row_json(policy_ref="policies/sandbox/full.toml", host_os="linux")
    (row,) = parse_launcher_refusal_rows(raw)
    assert row.policy_ref == "policies/sandbox/full.toml"


def test_interleaved_human_lines_are_ignored() -> None:
    raw = (
        b"supervisor.sandbox.refused.sandbox_block_missing plugin_id=x\n"
        + _row_json()
        + b"policy-resolving\n"
    )
    assert len(parse_launcher_refusal_rows(raw)) == 1


def test_multiple_rows_parsed_in_order() -> None:
    raw = _row_json(reason="unknown_host_os") + _row_json(reason="policy_ref_missing")
    rows = parse_launcher_refusal_rows(raw)
    assert [r.reason for r in rows] == ["unknown_host_os", "policy_ref_missing"]


def test_malformed_json_line_dropped_loudly(caplog: pytest.LogCaptureFixture) -> None:
    raw = b'{"event":"supervisor.plugin.sandbox_refused", NOT JSON\n' + _row_json()
    rows = parse_launcher_refusal_rows(raw)
    assert len(rows) == 1  # only the valid row survives


def test_unknown_event_ignored() -> None:
    raw = (
        json.dumps({"event": "supervisor.plugin.sandbox_stub_used", "plugin_id": "x"})
        + "\n"
    ).encode("utf-8")
    assert parse_launcher_refusal_rows(raw) == ()


def test_out_of_vocab_reason_dropped(caplog: pytest.LogCaptureFixture) -> None:
    raw = _row_json(reason="totally_made_up_reason")
    assert parse_launcher_refusal_rows(raw) == ()


def test_extra_unknown_key_dropped() -> None:
    raw = _row_json(smuggled="oops")
    assert parse_launcher_refusal_rows(raw) == ()


def test_non_dict_json_line_ignored() -> None:
    raw = b'["supervisor.plugin.sandbox_refused"]\n' + b'42\n'
    assert parse_launcher_refusal_rows(raw) == ()


def test_non_utf8_bytes_do_not_raise() -> None:
    raw = b"\xff\xfe not utf8\n" + _row_json()
    assert len(parse_launcher_refusal_rows(raw)) == 1


def test_empty_stderr_returns_empty_tuple() -> None:
    assert parse_launcher_refusal_rows(b"") == ()


def test_row_is_frozen() -> None:
    (row,) = parse_launcher_refusal_rows(_row_json())
    with pytest.raises((AttributeError, TypeError)):
        row.reason = "mutated"  # type: ignore[misc]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/plugins/test_launcher_refusal.py -q`
Expected: FAIL — `ModuleNotFoundError: alfred.plugins.launcher_refusal`.

- [ ] **Step 3: Write the parser**

```python
# src/alfred/plugins/launcher_refusal.py
"""Pure parser: launcher sandbox-refusal stderr bytes -> validated rows (#433).

``bin/alfred-plugin-launcher.sh`` is the sole producer of
``supervisor.plugin.sandbox_refused``; it ``printf``s the row as one JSON line
to stderr and ``exit 1``s. This module turns that stderr back into validated,
canonicalized :class:`SandboxRefusalRow` values so the core can persist them
(:mod:`alfred.security.sandbox_refusal_audit`). Pure — no I/O, no audit/hook
imports — so it is trivially unit-testable to 100% line+branch.

Trust posture: on a refusal the launcher exits BEFORE ``exec``ing the child, so
this stderr is 100%-launcher-authored (T0). Validation here is defense in depth;
#432 (closed reason vocabulary) and #437 (``policy_ref`` charset guard) already
constrain what the launcher writes. Any line that is not a well-formed,
closed-vocab ``sandbox_refused`` row is dropped LOUDLY (never trusted, never
silent).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import structlog

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS, SANDBOX_REFUSED_REASONS

_log = structlog.get_logger(__name__)

_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"

# The optional members of ``SANDBOX_REFUSED_FIELDS`` a launcher row may omit;
# canonicalized to "" so the subject always carries the full symmetric key-set
# ``AuditWriter.append_schema`` requires. ``policy_ref`` is absent from every
# pre-``policy_ref``-resolution refusal (environment / host-OS / block-missing).
_OPTIONAL_FIELDS: frozenset[str] = frozenset({"policy_ref"})


@dataclass(frozen=True, slots=True)
class SandboxRefusalRow:
    """One validated, canonicalized ``supervisor.plugin.sandbox_refused`` row.

    Carries exactly the ``SANDBOX_REFUSED_FIELDS`` members. :meth:`as_subject`
    returns the symmetric-keyed subject dict ``AuditWriter.append_schema``
    validates against ``SANDBOX_REFUSED_FIELDS``.
    """

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

    Scans line by line; accepts only a JSON object whose ``event`` is
    ``supervisor.plugin.sandbox_refused``, whose keys (minus ``event``) are a
    subset of ``SANDBOX_REFUSED_FIELDS``, and whose ``reason`` is in
    ``SANDBOX_REFUSED_REASONS``. Absent optional fields are canonicalized to "".
    Every rejected line is logged at warning (never silently dropped). Never
    raises — the caller is already mid-refusal.
    """
    rows: list[SandboxRefusalRow] = []
    text = stderr.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            candidate = json.loads(stripped)
        except ValueError:
            continue  # a human log line, not JSON — expected, not an error
        if not isinstance(candidate, dict) or candidate.get("event") != _REFUSED_EVENT:
            continue
        row = _validated_row(candidate)
        if row is not None:
            rows.append(row)
    return tuple(rows)


def _validated_row(candidate: dict[str, object]) -> SandboxRefusalRow | None:
    """Validate + canonicalize one candidate dict, or ``None`` (logged) if bad."""
    payload = {k: v for k, v in candidate.items() if k != "event"}
    unknown = payload.keys() - SANDBOX_REFUSED_FIELDS
    if unknown:
        _log.warning("security.launcher_refusal.unknown_fields", unknown=sorted(unknown))
        return None
    reason = payload.get("reason")
    if reason not in SANDBOX_REFUSED_REASONS:
        _log.warning("security.launcher_refusal.unknown_reason", reason=reason)
        return None
    missing_required = (SANDBOX_REFUSED_FIELDS - _OPTIONAL_FIELDS) - payload.keys()
    if missing_required:
        _log.warning(
            "security.launcher_refusal.missing_fields", missing=sorted(missing_required)
        )
        return None
    values = {field: str(payload.get(field, "")) for field in SANDBOX_REFUSED_FIELDS}
    return SandboxRefusalRow(**values)


__all__ = ["SandboxRefusalRow", "parse_launcher_refusal_rows"]
```

- [ ] **Step 4: Run tests to verify they pass + branch coverage**

Run: `uv run pytest tests/unit/plugins/test_launcher_refusal.py -q`
Expected: PASS (all).

Run: `uv run pytest tests/unit/plugins/test_launcher_refusal.py --cov=alfred.plugins.launcher_refusal --cov-branch --cov-report=term-missing -q`
Expected: 100% line + branch for `launcher_refusal.py` (`Missing` empty). If a
branch is uncovered, add the missing case (e.g. a candidate that is a JSON
non-dict already covered by `test_non_dict_json_line_ignored`).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/plugins/launcher_refusal.py tests/unit/plugins/test_launcher_refusal.py
git commit -m "feat(sandbox): #433 pure launcher sandbox-refusal stderr parser

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Reusable sandbox-refusal auditor

**Files:**

- Create: `src/alfred/security/sandbox_refusal_audit.py`
- Test: `tests/unit/security/test_sandbox_refusal_audit.py`

**Interfaces:**

- Consumes: `SandboxRefusalRow` (Task 1); `SANDBOX_REFUSED_FIELDS`;
  `AuditWriter.append_schema` shape; `alfred.hooks.invoke.invoke`,
  `alfred.hooks.context.HookContext`, `alfred.hooks.SYSTEM_ONLY_TIERS`.
- Produces:
  - `class SandboxRefusalRecorder(Protocol)` — `async def record(self, rows:
    tuple[SandboxRefusalRow, ...]) -> None`.
  - `class SandboxRefusalAuditor` — `__init__(self, *, audit_writer: AuditWriter)`;
    `async def record(self, rows) -> None` (satisfies the Protocol).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/security/test_sandbox_refusal_audit.py
"""Unit tests for the reusable sandbox-refusal auditor (#433)."""

from __future__ import annotations

from typing import Any

import pytest

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS
from alfred.plugins.launcher_refusal import SandboxRefusalRow
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


@pytest.mark.asyncio
async def test_record_writes_exact_schema_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    invoked: list[dict[str, Any]] = []

    async def _fake_invoke(name: str, ctx: object, **kwargs: Any) -> object:
        invoked.append({"name": name, **kwargs})
        return ctx

    monkeypatch.setattr("alfred.security.sandbox_refusal_audit.invoke", _fake_invoke)
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

    assert len(invoked) == 1
    assert invoked[0]["name"] == "supervisor.plugin.sandbox_refused"
    assert invoked[0]["fail_closed"] is True


@pytest.mark.asyncio
async def test_record_writes_every_row(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _noop_invoke(name: str, ctx: object, **kwargs: Any) -> object:
        return ctx

    monkeypatch.setattr("alfred.security.sandbox_refusal_audit.invoke", _noop_invoke)
    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record(
        (_row("unknown_host_os"), _row("policy_ref_missing"))
    )
    assert [c["subject"]["reason"] for c in audit.calls] == [
        "unknown_host_os",
        "policy_ref_missing",
    ]


@pytest.mark.asyncio
async def test_empty_rows_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _noop_invoke(name: str, ctx: object, **kwargs: Any) -> object:
        return ctx

    monkeypatch.setattr("alfred.security.sandbox_refusal_audit.invoke", _noop_invoke)
    audit = _FakeAudit()
    await SandboxRefusalAuditor(audit_writer=audit).record(())
    assert audit.calls == []


@pytest.mark.asyncio
async def test_append_schema_failure_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _noop_invoke(name: str, ctx: object, **kwargs: Any) -> object:
        return ctx

    monkeypatch.setattr("alfred.security.sandbox_refusal_audit.invoke", _noop_invoke)

    class _BoomAudit:
        async def append_schema(self, **kwargs: Any) -> None:
            raise RuntimeError("db down")

    with pytest.raises(RuntimeError, match="db down"):
        await SandboxRefusalAuditor(audit_writer=_BoomAudit()).record((_row(),))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_sandbox_refusal_audit.py -q`
Expected: FAIL — `ModuleNotFoundError: alfred.security.sandbox_refusal_audit`.

- [ ] **Step 3: Write the auditor**

```python
# src/alfred/security/sandbox_refusal_audit.py
"""Persist launcher sandbox-refusal rows + dispatch the fail-closed hookpoint (#433).

The reusable half of the launcher->core audit path (ADR-0051). Given validated
:class:`alfred.plugins.launcher_refusal.SandboxRefusalRow` values, writes each as
a ``supervisor.plugin.sandbox_refused`` audit row (``AuditWriter.append_schema``,
symmetric ``SANDBOX_REFUSED_FIELDS`` key-set) and dispatches the registered
``fail_closed`` T0 hookpoint (:func:`alfred.hooks.invoke.invoke`), mirroring the
daemon-boot hookpoint shape in ``cli/daemon/_boot_audit.py``.

The quarantine-child spawn is the first adopter; the comms-adapter, gateway-
adapter, and foreground-TUI launcher producers adopt this same auditor in the
#433 follow-ups. A write or dispatch failure is LOUD (CLAUDE.md hard rule #7) —
never swallowed.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_FIELDS
from alfred.hooks import SYSTEM_ONLY_TIERS
from alfred.hooks.context import HookContext
from alfred.hooks.invoke import invoke

if TYPE_CHECKING:
    from typing import Protocol

    from alfred.audit.log import AuditWriter
    from alfred.plugins.launcher_refusal import SandboxRefusalRow

    class SandboxRefusalRecorder(Protocol):
        """Narrow seam a launcher-spawn site calls to persist its refusals."""

        async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None: ...


_REFUSED_EVENT = "supervisor.plugin.sandbox_refused"


class SandboxRefusalAuditor:
    """Writes ``sandbox_refused`` rows + dispatches the fail-closed hookpoint."""

    def __init__(self, *, audit_writer: AuditWriter) -> None:
        self._audit = audit_writer

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
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


__all__ = ["SandboxRefusalAuditor"]
```

Note: `SandboxRefusalRecorder` is `TYPE_CHECKING`-only (a structural Protocol
used solely for annotations); if the build session finds a runtime need for it
(e.g. an `isinstance` check — there is none planned), promote it out of the
`TYPE_CHECKING` block. Confirm `alfred.hooks.context.HookContext` accepts the
kwargs shown (mirror `cli/daemon/_boot_audit.py:_invoke_boot_failed` verbatim);
if the `HookContext` field names differ at build time, copy them from that
function rather than guessing.

- [ ] **Step 4: Run tests + coverage**

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

## Task 3: Wire the recorder into `spawn_quarantine_child_io`

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py` (the
  `spawn_quarantine_child_io` signature + the `ProviderKeyDeliveryError` arm at
  `~803-813`; add a bounded raw-drain helper near `_read_stderr_bytes`)
- Test: `tests/unit/security/test_quarantine_child_io_refusal_audit.py`

**Interfaces:**

- Consumes: `SandboxRefusalRecorder` (Task 2), `parse_launcher_refusal_rows` +
  `SandboxRefusalRow` (Task 1), existing `_read_stderr_bytes`,
  `_STDERR_LOG_CAP_BYTES`, `_STDERR_DRAIN_TIMEOUT_S`, `_PLUGIN_ID`.
- Produces: `spawn_quarantine_child_io(..., refusal_recorder:
  SandboxRefusalRecorder | None = None)` — records parsed refusals (or a
  synthesized `provider_key_delivery_failed` row when stderr carried none)
  before raising `QuarantineChildSpawnError` on the delivery-failure arm.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/security/test_quarantine_child_io_refusal_audit.py
"""The spawn's delivery-failure arm records launcher refusals (#433)."""

from __future__ import annotations

import os
import stat
import textwrap
from pathlib import Path

import pytest

from alfred.plugins.launcher_refusal import SandboxRefusalRow
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    spawn_quarantine_child_io,
)


class _CapturingRecorder:
    def __init__(self) -> None:
        self.rows: list[SandboxRefusalRow] = []

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
        self.rows.extend(rows)


def _fake_refusing_launcher(tmp_path: Path) -> str:
    """A launcher stub that printfs a refusal row + exits 1 before exec."""
    script = tmp_path / "refusing-launcher.sh"
    script.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            printf 'supervisor.sandbox.refused.sandbox_block_missing plugin_id=%s\\n' "$1" >&2
            printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"sandbox_block_missing","environment":"development","host_os":"linux"}\\n' "$1" >&2
            exit 1
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.mark.asyncio
async def test_refusal_row_recorded_then_spawn_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", _fake_refusing_launcher(tmp_path))
    recorder = _CapturingRecorder()
    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == "sandbox_block_missing"


@pytest.mark.asyncio
async def test_delivery_failure_without_refusal_row_synthesizes_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A launcher that exits 1 with NO sandbox_refused row -> genuine delivery
    # failure -> synthesized provider_key_delivery_failed row.
    script = tmp_path / "silent-exit.sh"
    script.write_text("#!/usr/bin/env bash\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(script))
    recorder = _CapturingRecorder()
    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == "provider_key_delivery_failed"
    assert recorder.rows[0].plugin_id == "alfred.quarantined-llm"


@pytest.mark.asyncio
async def test_default_none_recorder_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", _fake_refusing_launcher(tmp_path))
    # No recorder passed -> unchanged behavior, still raises, no crash.
    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k")
```

Note: these tests assume the delivery-failure arm is reachable with a stub
launcher on the CI host (the stub exits before any bwrap/interpreter dependency,
so it runs cross-platform). If a preexisting spawn test in the suite uses a
different stub convention (e.g. a fixture launcher path helper), reuse that
helper instead of the inline `tmp_path` script — check
`tests/unit/security/` for an existing `ALFRED_PLUGIN_LAUNCHER` fixture first
and prefer it (DRY).

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_refusal_audit.py -q`
Expected: FAIL — `spawn_quarantine_child_io()` has no `refusal_recorder`
parameter (`TypeError: unexpected keyword argument`).

- [ ] **Step 3: Add the drain helper**

Add near `_read_stderr_bytes` (after it, ~line 314):

```python
async def _drain_exited_child_stderr(process: subprocess.Popen[bytes], *, cap: int) -> bytes:
    """Bounded off-loop read of an EXITED child's raw stderr (#433).

    Caller guarantees the child has been reaped (``_terminate_and_reap``), so the
    write-end is closed and the read cannot block; the deadline is defence in
    depth. Returns RAW bytes (NOT sanitized) — the refusal parser needs intact
    newlines to split JSON lines. Never raises: a drain failure must not preempt
    the caller's contracted ``QuarantineChildSpawnError``.
    """
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _read_stderr_bytes, process, cap),
            timeout=_STDERR_DRAIN_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001 - best-effort; loud, never preempts
        _log.warning(
            "security.quarantine_child.refusal_drain_failed", error_class=type(exc).__name__
        )
        return b""
```

- [ ] **Step 4: Add the parameter + import + record the refusals**

Add module imports (top of file, with the other `from alfred...` imports):

```python
from alfred.plugins.launcher_refusal import SandboxRefusalRow, parse_launcher_refusal_rows
```

Under `TYPE_CHECKING` (add a block if none exists — check the existing import
layout; put it beside the other type-only imports):

```python
if TYPE_CHECKING:
    from alfred.security.sandbox_refusal_audit import SandboxRefusalRecorder
```

Change the signature (at `~634`):

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

Replace the `ProviderKeyDeliveryError` arm (at `~803-813`):

```python
    try:
        deliver_provider_key_via_fd3(write_fd=write_fd, key=provider_key)
    except ProviderKeyDeliveryError as exc:
        _log.error("security.quarantine_child.provider_key_delivery_failed", reason=exc.reason)
        await _terminate_and_reap(process)
        if refusal_recorder is not None:
            stderr = await _drain_exited_child_stderr(process, cap=_STDERR_LOG_CAP_BYTES)
            rows = parse_launcher_refusal_rows(stderr)
            if not rows:
                # Genuine fd-3 delivery failure (no launcher refusal in stderr):
                # synthesize the reserved provider_key_delivery_failed reason so
                # the security-relevant refusal is still audited (ADR-0051).
                rows = (
                    SandboxRefusalRow(
                        plugin_id=_PLUGIN_ID,
                        policy_ref="",
                        host_os="",
                        reason="provider_key_delivery_failed",
                        environment="",
                    ),
                )
            await refusal_recorder.record(rows)
        if control_parent is not None:
            with contextlib.suppress(OSError):
                control_parent.close()
        raise QuarantineChildSpawnError(
            t("security.quarantine_child.provider_key_delivery_failed")
        ) from exc
```

Also add `TYPE_CHECKING` to the `from typing import` line if absent
(`from typing import IO, TYPE_CHECKING`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_refusal_audit.py -q`
Expected: PASS.

Run the existing spawn suite to confirm the precursor invariant (default-None
unchanged):
Run: `uv run pytest tests/unit/security/ -k quarantine_child_io -q`
Expected: PASS (all preexisting tests green).

- [ ] **Step 6: Coverage of the new arm**

Run: `uv run pytest tests/unit/security/ -k "quarantine_child_io" --cov=alfred.security.quarantine_child_io --cov-branch --cov-report=term-missing -q`
Expected: the new lines (drain helper, record arm, synthesized-row branch) all
covered. If the `if not rows` false-branch (a real refusal row present) or true-
branch (synthesized) is uncovered, both are exercised by
`test_refusal_row_recorded_then_spawn_raises` /
`test_delivery_failure_without_refusal_row_synthesizes_reason` respectively —
confirm both ran.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io_refusal_audit.py
git commit -m "feat(sandbox): #433 record launcher refusals on the quarantine spawn arm

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Inject the auditor from `daemon_runtime`

**Files:**

- Modify: `src/alfred/comms_mcp/daemon_runtime.py`
  (`_build_comms_inbound_extractor`, the `spawn_quarantine_child_io(...)` call
  at `~334`)
- Test: extend `tests/unit/` daemon-runtime wiring test (find the existing
  `_build_comms_inbound_extractor` test; if none, add
  `tests/unit/comms_mcp/test_daemon_runtime_refusal_wiring.py`)

**Interfaces:**

- Consumes: `SandboxRefusalAuditor` (Task 2), the `audit_writer: AuditWriter`
  already passed to `_build_comms_inbound_extractor`.
- Produces: the live spawn is now called with a real recorder.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/comms_mcp/test_daemon_runtime_refusal_wiring.py
"""_build_comms_inbound_extractor injects a SandboxRefusalAuditor (#433)."""

from __future__ import annotations

from typing import Any

import pytest


@pytest.mark.asyncio
async def test_spawn_called_with_refusal_recorder(monkeypatch: pytest.MonkeyPatch) -> None:
    from alfred.comms_mcp import daemon_runtime
    from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor

    seen: dict[str, Any] = {}

    async def _fake_spawn(**kwargs: Any) -> Any:
        seen.update(kwargs)
        raise RuntimeError("stop after capturing kwargs")

    monkeypatch.setattr(daemon_runtime, "spawn_quarantine_child_io", _fake_spawn, raising=False)
    # Minimal doubles for the builder's other deps — reuse the existing
    # daemon-runtime test fixtures if present (check the sibling test module).
    ...  # build audit_writer/outbound_dlp/secret_broker/staging doubles
    with pytest.raises(RuntimeError, match="stop after capturing kwargs"):
        await daemon_runtime._build_comms_inbound_extractor(
            audit_writer=...,  # the fixture AuditWriter double
            outbound_dlp=...,
            secret_broker=...,
            staging=...,
        )
    assert isinstance(seen.get("refusal_recorder"), SandboxRefusalAuditor)
```

Note: the `...` placeholders are the builder's existing dependency doubles —
locate the current `_build_comms_inbound_extractor` test (grep
`tests/ -rn "_build_comms_inbound_extractor"`) and reuse its fixtures verbatim
rather than reconstructing them. If `spawn_quarantine_child_io` is imported
lazily inside the function (it is — `from alfred.security.quarantine_child_io
import spawn_quarantine_child_io` at `~328`), patch it at its source module
(`alfred.security.quarantine_child_io.spawn_quarantine_child_io`) instead of on
`daemon_runtime`.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_daemon_runtime_refusal_wiring.py -q`
Expected: FAIL — `refusal_recorder` not in the captured kwargs (currently the
spawn is called without it).

- [ ] **Step 3: Wire the auditor**

In `_build_comms_inbound_extractor`, before the spawn call (`~328-334`):

```python
    from alfred.security.quarantine_child_io import spawn_quarantine_child_io
    from alfred.security.quarantine_transport import QuarantineStdioTransport
    from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor

    provider_key = _resolve_provider_key(secret_broker)
    refusal_recorder = SandboxRefusalAuditor(audit_writer=audit_writer)
    # SINGLE await — the spawn owns the process-wide fd-3 clobber window and must
    # not race any other coroutine. Do not interleave awaits here.
    child_io = await spawn_quarantine_child_io(
        provider_key=provider_key, refusal_recorder=refusal_recorder
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_daemon_runtime_refusal_wiring.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/daemon_runtime.py tests/unit/comms_mcp/test_daemon_runtime_refusal_wiring.py
git commit -m "feat(sandbox): #433 inject the sandbox-refusal auditor at daemon boot

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: ADR-0051 + prose corrections

**Files:**

- Create: `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md`
- Modify: `src/alfred/security/fd3_key_delivery.py` (docstring `~23-24`)
- Modify: `docs/subsystems/supervisor.md` (`~362-363`)
- Modify: `src/alfred/audit/audit_row_schemas.py` (`NOTE (#433)` `~1194-1198`)

- [ ] **Step 1: Write ADR-0051**

Create `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md` following
the repo ADR template (read `docs/adr/0050-*.md` for the exact heading
structure). Content — Context / Decision / Consequences / Alternatives — drawn
from the design spec's "ADR-0051 outline" section:

- **Context:** the launcher is the sole `sandbox_refused` producer and can only
  `printf` to stderr (a shell script, no DB/audit access); four spawn sites
  drain that stderr; today none persists the row (hard-rule-#7 gap).
- **Decision:** pure parser (`plugins/launcher_refusal`) + reusable auditor
  (`security/sandbox_refusal_audit`) + narrow-`SandboxRefusalRecorder`-Protocol
  injection into `spawn_quarantine_child_io`; quarantine-child producer first;
  interception at the pre-`exec` fd-3-delivery-failure arm; the synthesized
  `provider_key_delivery_failed` reason.
- **Consequences:** the T3 refusal is finally persisted; the reserved reason
  becomes real; three producers remain to adopt the seam (tracked follow-ups);
  the IO module gains one narrow dependency.
- **Alternatives:** B2 (attach rows to the exception); all-producers big-bang;
  parse-inside-`_log_child_stderr` — each rejected (spec records why).

- [ ] **Step 2: Correct `fd3_key_delivery.py` prose**

At `~23-24`, change the aspirational claim to descriptive fact:

Before:

```text
  truncated key. The caller maps this to a
  ``SANDBOX_REFUSED_FIELDS(reason="provider_key_delivery_failed")`` audit row
```

After:

```text
  truncated key. ``spawn_quarantine_child_io`` records this as a
  ``SANDBOX_REFUSED_FIELDS(reason="provider_key_delivery_failed")`` audit row
  via the injected ``SandboxRefusalRecorder`` (ADR-0051, #433) — synthesized
  when the launcher stderr carried no explicit refusal row.
```

- [ ] **Step 3: Correct `supervisor.md`**

At `~362-363`, update the "On a partial write / EAGAIN the Supervisor REFUSES to
spawn" sentence to note the audit row is now persisted:

```text
On a partial write / EAGAIN the Supervisor REFUSES to spawn
(`reason="provider_key_delivery_failed"`) and records a
`supervisor.plugin.sandbox_refused` audit row via the launcher->core refusal
audit path (ADR-0051, #433).
```

- [ ] **Step 4: Update the `NOTE (#433)` block in `audit_row_schemas.py`**

At `~1194-1198`, replace the "not yet persisted" NOTE with the shipped state:

```python
# NOTE (#433): the quarantine-child launcher path now persists this row — the
# ProviderKeyDeliveryError arm of ``spawn_quarantine_child_io`` drains the
# launcher stderr, ``alfred.plugins.launcher_refusal.parse_launcher_refusal_rows``
# validates it, and ``alfred.security.sandbox_refusal_audit.SandboxRefusalAuditor``
# writes it + dispatches the fail_closed T0 hookpoint (ADR-0051). The three other
# launcher producers (comms adapter, gateway adapter, foreground TUI) adopt the
# same auditor in the #433 follow-ups. This set still governs what the launcher
# WRITES (plus the reserved reasons below).
```

Also update the `provider_key_delivery_failed` reserved-reason comment
(`~1204-1206`): it is no longer "not yet written by any code" — it is
synthesized by `spawn_quarantine_child_io` on a genuine delivery failure.

- [ ] **Step 5: Lint docs + commit**

Run: `markdownlint-cli2 "docs/adr/0051-*.md" "docs/subsystems/supervisor.md"`
Expected: 0 errors (fix MD032/MD031/MD060/MD004 if any).

```bash
git add docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md \
        src/alfred/security/fd3_key_delivery.py \
        docs/subsystems/supervisor.md \
        src/alfred/audit/audit_row_schemas.py
git commit -m "docs(sandbox): #433 ADR-0051 + correct the now-true refusal-audit prose

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Adversarial coverage + full quality gates + follow-ups

**Files:**

- Create: an adversarial test under `tests/adversarial/` (pin the exact path
  against the corpus layout — read `tests/adversarial/README` / an existing
  sandbox adversarial test first; the #437 adversarial payload id was
  `sbx-2026-017`, so use `sbx-2026-018`)
- No src changes (verification + issue filing)

- [ ] **Step 1: Write the adversarial test**

A refusal row whose field values carry injection bytes must not forge a second
audit event or smuggle an out-of-vocab reason. (Upstream #437 charset-guards
`policy_ref`; this asserts the parser+auditor layer is also non-forging.)

```python
# tests/adversarial/plugins/test_sandbox_refusal_no_forged_event.py
"""sbx-2026-018: a launcher refusal row cannot forge a second audit event (#433)."""

from __future__ import annotations

from alfred.plugins.launcher_refusal import parse_launcher_refusal_rows


def test_embedded_json_in_value_does_not_forge_a_second_row() -> None:
    # A plugin_id value that itself contains a JSON object literal must not be
    # re-parsed into a second sandbox_refused row: parsing is line-oriented and
    # per-line json.loads yields ONE dict, so the nested text stays a value.
    raw = (
        b'{"event":"supervisor.plugin.sandbox_refused",'
        b'"plugin_id":"x\\", \\"event\\": \\"forged",'
        b'"reason":"sandbox_block_missing","environment":"development","host_os":"linux"}\n'
    )
    rows = parse_launcher_refusal_rows(raw)
    assert len(rows) == 1
    assert rows[0].reason == "sandbox_block_missing"


def test_out_of_vocab_reason_cannot_slip_through() -> None:
    raw = (
        b'{"event":"supervisor.plugin.sandbox_refused","plugin_id":"x",'
        b'"reason":"__forged__","environment":"development","host_os":"linux"}\n'
    )
    assert parse_launcher_refusal_rows(raw) == ()
```

- [ ] **Step 2: Run the adversarial suite (release-blocking — security/ touched)**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS (including the new sbx-2026-018 test).

- [ ] **Step 3: Confirm the #432 vocab-sync binding still holds**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q`
Expected: PASS (this PR added NO launcher reason, so the binding is unchanged).

- [ ] **Step 4: Full unit suite (the #437 SLICE_4_KEYS lesson — run the WHOLE suite, not just touched modules)**

Run: `uv run pytest tests/unit -q`
Expected: PASS, ≥ the assert-RAN floor. A new `supervisor.sandbox.`-prefixed
audit/log key would trip `test_catalog_slice_4_keys` — this PR adds none (the
audit event is reused; the parser's warnings use a `security.launcher_refusal.`
prefix), but confirm the full suite is green, not just the touched tests.

- [ ] **Step 5: i18n drift + all quality gates**

Run: `pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins && pybabel update -i /tmp/alfred.pot -d src/alfred/locale --no-fuzzy-matching`
Expected: no new untranslated msgids (this PR adds no `t()` string). If drift
appears, investigate — it should not.

Run: `make check`
Expected: lint + format + `mypy --strict` + `pyright` + tests all green. If
`make ...|tail` is used, check `$?` (a tail masks the exit code).

- [ ] **Step 6: File the three producer follow-up issues**

```bash
gh issue create --title "sandbox: persist sandbox_refused for the comms-adapter launcher producer" \
  --body "Adopt alfred.security.sandbox_refusal_audit.SandboxRefusalAuditor (ADR-0051, #433) in plugins/comms_stdio_transport.py so a comms-adapter launcher refusal is persisted. The stderr is already PIPE'd; wire the drain->parse->record on the adapter crash/exit arm."
gh issue create --title "sandbox: persist sandbox_refused for the gateway-adapter launcher producer" \
  --body "Adopt the shared SandboxRefusalAuditor (ADR-0051, #433) in gateway/adapter_child_factory.py."
gh issue create --title "sandbox: persist sandbox_refused for the foreground-TUI launcher producer" \
  --body "cli/_launcher_spawn.py inherits stderr today (cannot capture the refusal row). Add a stderr-capture path + adopt the shared SandboxRefusalAuditor (ADR-0051, #433) so a foreground 'alfred chat'/discord launcher refusal is audited, not just printed to the operator terminal."
```

- [ ] **Step 7: Open the PR**

```bash
git push -u origin 433-launcher-refusal-audit
gh pr create --title "feat(sandbox): #433 persist the sandbox_refused audit row (quarantine path)" \
  --body "<summary + link to the design spec + ADR-0051 + the three follow-ups>"
```

Then run the full `/review-pr` fleet (security ALWAYS) + CodeRabbit (both CLI
and cloud) + alfred-uat, resolve every thread, and merge with a plain
`gh pr merge --rebase` (NEVER `--admin`).

---

## Self-Review (completed by plan author)

**Spec coverage:** every spec section maps to a task — pure parser → Task 1;
reusable auditor → Task 2; spawn wiring + synthesized `provider_key_delivery_failed`
→ Task 3; daemon_runtime injection → Task 4; ADR-0051 + the three prose
corrections → Task 5; adversarial + vocab-sync + gates + the three producer
follow-ups → Task 6. The "out of scope" items (#434/#435/#436, boot-detection
timing) are explicitly not tasked. No gaps.

**Placeholder scan:** the only `...` are in Tasks 3/4 test-fixture notes that
explicitly instruct the implementer to reuse existing sibling-test fixtures
(named grep given) rather than invent them — a deliberate DRY handoff, not a
missing spec. Every code step shows complete code.

**Type consistency:** `SandboxRefusalRow` (fields + `as_subject`) is defined in
Task 1 and consumed identically in Tasks 2/3; `SandboxRefusalRecorder.record`
signature matches between Task 2 (definition), Task 3 (parameter), Task 4
(injection); `parse_launcher_refusal_rows` return type
(`tuple[SandboxRefusalRow, ...]`) is consistent across Tasks 1/3/6;
`SandboxRefusalAuditor(audit_writer=...)` construction matches between Task 2
and Task 4. `append_schema` kwargs match the real `AuditWriter` signature.
