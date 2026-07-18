# #444 — Persist the reserved `provider_key_delivery_failed` audit row Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On a genuine fd-3 provider-key delivery failure where the quarantine child is still running, persist the reserved `provider_key_delivery_failed` `SANDBOX_REFUSED_FIELDS` audit row (durable + signed) and dispatch its T0 `fail_closed` hookpoint, via the shared `SandboxRefusalAuditor` — closing the reserved-but-unwritten gap ADR-0051 tracked.

**Architecture:** The row is **host-authored** (the parent's own `os.writev` failed; there is no launcher stderr to parse), so unlike #433's stderr-parsed rows it is constructed directly as a `SandboxRefusalRow` by the auditor. `SandboxRefusalAuditor` gains the parent host context (`host_os`, `environment`) at construction (resolved once at daemon boot where `Settings` lives) and a new `record_provider_key_delivery_failure(plugin_id)` method that builds the row and reuses the existing `record()` write+dispatch path. `quarantine_child_io._record_fast_launcher_refusal`'s existing `poll() is None` branch — already labelled "#444's domain" — calls a new guarded `_SubprocessChildIO` method before teardown. The write is guarded so an auditor failure logs loud but never masks the fail-closed `QuarantineChildSpawnError`.

**Tech Stack:** Python 3.14+, asyncio, Pydantic v2 (schemas), structlog (redacted), pytest (async), `structlog.testing.capture_logs` for event assertions, the adversarial sbx corpus harness.

## Global Constraints

- **Python floor `>=3.14.6`**; modern idioms only (PEP 604 unions, PEP 585 generics). No `Optional[X]` / `typing.List`.
- **`mypy --strict` + `pyright` on `src/` only** (tests are NOT in the type-check scope — a widened Protocol does not force every test fake to implement the new method at type-check time; only fakes driven through the #444 path at RUNTIME need it).
- **Security boundary (`src/alfred/security/`, `src/alfred/audit/`):** 100% line + branch coverage on touched paths; the **release-blocking adversarial suite** MUST run (`uv run pytest tests/adversarial`).
- **HARD rule #7 — no silent failure on a security path:** the audit write is guarded to fail LOUD (explicit `error_class` structlog event) and MUST NOT mask the primary `QuarantineChildSpawnError`.
- **i18n:** audit-row fields + structlog event keys are **not** `t()` scope. No new operator-facing strings are introduced (the refusal message already routes through `t()`).
- **No `--no-verify`, no `git add -A`** (add named paths only). Commit subjects carry `#444` after the colon (Conventional-commit gate).
- **The row is host-authored, carrying only trusted host constants (plugin_id / reason / host_os / environment) — NO T3-derived field** — so the canary-forward gate that guards `_record_launcher_refusals` does not apply to this write.

---

## File Structure

- `src/alfred/security/sandbox_refusal_audit.py` — **modify.** `SandboxRefusalRecorder` Protocol gains `record_provider_key_delivery_failure`; `SandboxRefusalAuditor.__init__` gains `host_os` + `environment`; new method builds the host-authored row and delegates to the existing `record()`.
- `src/alfred/comms_mcp/daemon_runtime.py` — **modify.** New pure helper `_resolve_host_os()`; `_build_comms_inbound_extractor` gains an `environment: str` param; constructs the auditor with `host_os` + `environment`.
- `src/alfred/cli/daemon/_comms_boot.py:718` — **modify.** Pass `environment=settings.environment` into `_build_comms_inbound_extractor` (the caller already holds `settings`).
- `src/alfred/security/quarantine_child_io.py` — **modify.** New guarded `_SubprocessChildIO._record_provider_key_delivery_failure`; call it in `_record_fast_launcher_refusal`'s `poll() is None` branch before teardown; refresh that branch's docstring/comment.
- `src/alfred/supervisor/fd3_key_delivery.py` — **modify (comments only).** The "not emitted by any code today / reserved for a future writer" prose (`:23-28`, `:53-56`) becomes false; point it at the live writer.
- `src/alfred/audit/audit_row_schemas.py` — **modify (comments only).** The reserved-`provider_key_delivery_failed` comment (`:1201-1208`) becomes false; mark it written.
- `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md` — **modify.** Amend the "Follow-ups to file" section: the `provider_key_delivery_failed` writer is now implemented (#444).
- `tests/unit/security/test_sandbox_refusal_audit.py` — **modify.** Cover the new auditor method (row shape + T0 hookpoint dispatch) + the updated ctor.
- `tests/unit/security/test_quarantine_child_io_refusal_audit.py` — **modify.** Flip `test_fast_refusal_arm_running_child_torn_down_not_drained` to expect the row; add a guard test; add the method to `_CapturingRecorder`.
- `tests/unit/comms_mcp/test_daemon_runtime.py` — **modify.** Cover `_resolve_host_os()` mapping + auditor constructed with resolved host context.
- `tests/adversarial/sandbox_escape/sbx_2026_026_provider_key_delivery_failure_records_row.yaml` — **create.** The release-blocking payload.
- `tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py` — **modify.** Update the auditor construction at `:275` to the new ctor (Task 1); add the paired `test_sbx_2026_026_*` executable counterpart (mirrors the **021** real-registry oracle, Task 3).
- `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` — **modify.** Correct the now-false `_RESERVED_UNEMITTED` comment + docstring (`provider_key_delivery_failed` is now host-emitted; the launcher-emitter assertions still hold).

**Task decomposition rationale:** the `SandboxRefusalAuditor.__init__` signature change cannot be split from its sole production construction site (`daemon_runtime.py:339`) without a red intermediate tree, so Task 1 bundles the auditor capability with its live wiring. Task 2 is the `quarantine_child_io` consumer (depends on Task 1's Protocol method). Task 3 is the stale-comment fixes + release-blocking adversarial corpus + ADR (depends on 1-2 being live).

---

### Task 1: Auditor host-authored writer + live wiring

**Files:**

- Modify: `src/alfred/security/sandbox_refusal_audit.py`
- Modify: `src/alfred/comms_mcp/daemon_runtime.py`
- Modify: `src/alfred/cli/daemon/_comms_boot.py:718`
- Test: `tests/unit/security/test_sandbox_refusal_audit.py`
- Test: `tests/unit/comms_mcp/test_daemon_runtime.py`

**Interfaces:**

- Produces:
  - `SandboxRefusalRecorder.record_provider_key_delivery_failure(self, *, plugin_id: str) -> None` (Protocol method — the seam Task 2 calls).
  - `SandboxRefusalAuditor.__init__(self, *, audit_writer: AuditWriter, host_os: str, environment: str)`.
  - `SandboxRefusalAuditor.record_provider_key_delivery_failure(self, *, plugin_id: str) -> None` — builds `SandboxRefusalRow(plugin_id=plugin_id, policy_ref="", host_os=<ctor>, reason="provider_key_delivery_failed", environment=<ctor>)` and delegates to `record((row,))`.
  - `alfred.comms_mcp.daemon_runtime._resolve_host_os() -> str` — maps `platform.system()` → `{"linux","macos","windows","unknown"}`.
  - `_build_comms_inbound_extractor(*, audit_writer, outbound_dlp, secret_broker, staging, environment: str)` — new `environment` param.
- Consumes: existing `SandboxRefusalRow` (`alfred.audit.launcher_refusal`), `SANDBOX_REFUSED_FIELDS`, the existing `SandboxRefusalAuditor.record`.

- [ ] **Step 1: Write the failing auditor test**

Add to `tests/unit/security/test_sandbox_refusal_audit.py`. Reuse the file's REAL doubles (verified against the file): `_FakeAudit` (captures `append_schema` kwargs in `.calls`) and the `_fake_invoke` fixture (captures each `invoke` as `{"name", **kwargs}` in a list). This module marks async tests with `@pytest.mark.asyncio`:

```python
@pytest.mark.asyncio
async def test_record_provider_key_delivery_failure_writes_host_authored_row(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    audit = _FakeAudit()
    auditor = SandboxRefusalAuditor(
        audit_writer=audit, host_os="linux", environment="production"
    )
    await auditor.record_provider_key_delivery_failure(plugin_id="alfred.quarantined-llm")

    assert len(audit.calls) == 1
    call = audit.calls[0]
    assert call["event"] == "supervisor.plugin.sandbox_refused"
    assert call["trust_tier_of_trigger"] == "T0"
    assert call["result"] == "refused"
    assert call["subject"] == {
        "plugin_id": "alfred.quarantined-llm",
        "policy_ref": "",
        "host_os": "linux",
        "reason": "provider_key_delivery_failed",
        "environment": "production",
    }
    # The T0 fail_closed hookpoint fired exactly once for this row.
    assert len(_fake_invoke) == 1
    assert _fake_invoke[0]["name"] == "supervisor.plugin.sandbox_refused"
    assert _fake_invoke[0]["fail_closed"] is True
```

The `_fake_invoke` fixture param is **mandatory** — `record()` lazily imports and calls `invoke(..., fail_closed=True)` against the shared registry, so an unpatched test would fire a real dispatch (or fail on an undeclared hookpoint). Every existing `record()`-driving test in this file already takes `_fake_invoke`.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/security/test_sandbox_refusal_audit.py::test_record_provider_key_delivery_failure_writes_host_authored_row -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'host_os'` (and/or `AttributeError: 'SandboxRefusalAuditor' object has no attribute 'record_provider_key_delivery_failure'`).

- [ ] **Step 3: Implement the auditor change**

In `src/alfred/security/sandbox_refusal_audit.py`, widen the Protocol and auditor:

```python
class SandboxRefusalRecorder(Protocol):
    """Narrow seam a launcher-spawn site calls to persist its refusals."""

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None: ...

    async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
        """Persist the host-authored ``provider_key_delivery_failed`` row (#444)."""
        ...
```

```python
class SandboxRefusalAuditor:
    """Writes ``sandbox_refused`` rows + dispatches the fail-closed hookpoint."""

    def __init__(self, *, audit_writer: AuditWriter, host_os: str, environment: str) -> None:
        self._audit = audit_writer
        self._host_os = host_os
        self._environment = environment

    async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
        """Persist the reserved ``provider_key_delivery_failed`` row (#444).

        HOST-authored, not launcher-parsed: the parent's own ``os.writev`` over fd 3
        failed while the child was still up (partial write / EAGAIN), so there is no
        launcher stderr to parse. Every field is a trusted host constant (no T3), and
        the write reuses ``record`` for the durable ``append_schema`` + the T0
        ``fail_closed`` hookpoint dispatch (declared at ``hooks/boot.py`` ahead of the
        spawn — ADR-0051's #443 PR2 amendment).
        """
        from alfred.audit.launcher_refusal import SandboxRefusalRow

        # ``reason`` is the reserved constant ``ProviderKeyDeliveryError`` raises with
        # (``fd3_key_delivery.py``) — hard-coded here (not read from the exception) so a
        # caller cannot inject a reason outside ``SANDBOX_REFUSED_REASONS``. Keep the two
        # bound: if the exception's default reason ever changes, change this literal too.
        row = SandboxRefusalRow(
            plugin_id=plugin_id,
            policy_ref="",
            host_os=self._host_os,
            reason="provider_key_delivery_failed",
            environment=self._environment,
        )
        await self.record((row,))
```

(Keep the existing `record` body unchanged.)

- [ ] **Step 4: Update every construction broken by the new required ctor kwargs, then verify unit + adversarial**

The new required `host_os` + `environment` break every existing `SandboxRefusalAuditor(audit_writer=...)` construction. Update each to pass explicit values (`host_os="linux", environment="development"`, matching the file's `_row()` fixture):

- `tests/unit/security/test_sandbox_refusal_audit.py` — the 6 constructions at `:65, :83, :95, :106, :133, :219`.
- `tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py:275` — `SandboxRefusalAuditor(audit_writer=_CapturingWriter())`. This is in the **release-blocking** suite; leaving it turns `tests/adversarial` red the instant the ctor changes (finding B1) — fix it HERE, in the same task, not three tasks later.

Verify none remain on the old signature, then run both the auditor unit module and the adversarial boot-handshake file:

Run: `grep -rn "SandboxRefusalAuditor(" src/ tests/ | grep -v host_os` (expect: only the class-definition line)
Run: `uv run pytest tests/unit/security/test_sandbox_refusal_audit.py tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py -v`
Expected: PASS — the 6 updated auditor tests + the new one, and the adversarial boot-handshake suite (incl. sbx-2026-025), all green. Running the adversarial file HERE catches the ctor break where it is introduced.

- [ ] **Step 5: Write the failing daemon-wiring test**

Add to `tests/unit/comms_mcp/test_daemon_runtime.py`:

```python
import alfred.comms_mcp.daemon_runtime as daemon_runtime_mod


@pytest.mark.parametrize(
    ("system", "expected"),
    [("Linux", "linux"), ("Darwin", "macos"), ("Windows", "windows"), ("Plan9", "unknown")],
)
def test_resolve_host_os_maps_to_launcher_vocab(
    monkeypatch: pytest.MonkeyPatch, system: str, expected: str
) -> None:
    monkeypatch.setattr(daemon_runtime_mod.platform, "system", lambda: system)
    assert daemon_runtime_mod._resolve_host_os() == expected
```

- [ ] **Step 6: Run it to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_daemon_runtime.py::test_resolve_host_os_maps_to_launcher_vocab -v`
Expected: FAIL — `AttributeError: module 'alfred.comms_mcp.daemon_runtime' has no attribute '_resolve_host_os'` (and/or `platform` not imported).

- [ ] **Step 7: Implement the daemon wiring**

In `src/alfred/comms_mcp/daemon_runtime.py`:

Add `import platform` to the top-level imports. Add the helper near `_resolve_provider_key`:

```python
def _resolve_host_os() -> str:
    """Normalise the parent host OS to the launcher's {linux, macos, windows, unknown}.

    Mirrors ``bin/alfred-plugin-launcher.sh``'s ``_host_os()`` so a host-authored
    ``provider_key_delivery_failed`` row (#444) renders uniformly beside the
    launcher-authored ``sandbox_refused`` rows in ``alfred audit graph``.
    """
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "unknown"
```

Thread `environment` into `_build_comms_inbound_extractor` and use it + `_resolve_host_os()` at the auditor construction (currently `daemon_runtime.py:339`):

```python
async def _build_comms_inbound_extractor(
    *,
    audit_writer: AuditWriter,
    outbound_dlp: OutboundDlp,
    secret_broker: SecretBroker,
    staging: QuarantineStagingMap,
    environment: str,
) -> tuple[QuarantinedExtractor, QuarantineStdioTransport]:
    ...
    provider_key = _resolve_provider_key(secret_broker)
    refusal_recorder = SandboxRefusalAuditor(
        audit_writer=audit_writer,
        host_os=_resolve_host_os(),
        environment=environment,
    )
    ...
```

- [ ] **Step 8: Update the caller + the four test call sites to pass `environment`**

Production caller: in `src/alfred/cli/daemon/_comms_boot.py` at the `_build_comms_inbound_extractor(...)` call (~`:718`), add `environment=settings.environment` (the enclosing function already receives `settings: Settings`).

Test callers (the new required `environment` kwarg breaks all four — these are CERTAIN, not conditional): `tests/unit/comms_mcp/test_daemon_runtime.py:428, 501, 553, 600` each `await _build_comms_inbound_extractor(...)` with no `environment` — add `environment="production"` (or the value the test asserts on) to each. Additionally, the go-live test at `:600`/`:607` that asserts `isinstance(seen["refusal_recorder"], SandboxRefusalAuditor)` should ALSO assert the recorder carries the resolved host context (`host_os="linux"`, the passed `environment`) — that is the live proof Task 1's wiring goal actually landed.

Confirm the production call-site count + that no test call omits `environment`:

Run: `grep -rn "_build_comms_inbound_extractor(" src/` (expect: exactly one call site beyond the def)
Run: `grep -n "_build_comms_inbound_extractor(" tests/unit/comms_mcp/test_daemon_runtime.py` (expect: all four pass `environment=`)

- [ ] **Step 9: Run the wiring tests + type-check**

Run: `uv run pytest tests/unit/comms_mcp/test_daemon_runtime.py -v && uv run mypy src/alfred/comms_mcp/daemon_runtime.py src/alfred/security/sandbox_refusal_audit.py src/alfred/cli/daemon/_comms_boot.py`
Expected: PASS + no type errors. (If `test_daemon_runtime.py` constructs `SandboxRefusalAuditor` or calls `_build_comms_inbound_extractor` directly, update those constructions to the new signatures in the same edit.)

- [ ] **Step 10: Commit**

```bash
git add src/alfred/security/sandbox_refusal_audit.py src/alfred/comms_mcp/daemon_runtime.py src/alfred/cli/daemon/_comms_boot.py tests/unit/security/test_sandbox_refusal_audit.py tests/unit/comms_mcp/test_daemon_runtime.py
git commit -m "feat(security): #444 host-authored provider_key_delivery_failed writer + host-context wiring"
```

---

### Task 2: `quarantine_child_io` writes the row on the still-running delivery-failure branch

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py`
- Test: `tests/unit/security/test_quarantine_child_io_refusal_audit.py`

**Interfaces:**

- Consumes: `SandboxRefusalRecorder.record_provider_key_delivery_failure(plugin_id=...)` (Task 1), `_PLUGIN_ID = "alfred.quarantined-llm"`, the existing `_record_fast_launcher_refusal` `poll()` gate.
- Produces: `_SubprocessChildIO._record_provider_key_delivery_failure(self) -> None` (guarded, never raises).

- [ ] **Step 1: Add the method to the test's `_CapturingRecorder` + flip the existing branch test**

In `tests/unit/security/test_quarantine_child_io_refusal_audit.py`, extend `_CapturingRecorder` and change the running-child test's expectation. First, the recorder gains capture of the new call:

```python
class _CapturingRecorder:
    """A ``SandboxRefusalRecorder`` double that just remembers what it was given."""

    def __init__(self) -> None:
        self.rows: list[SandboxRefusalRow] = []
        self.delivery_failures: list[str] = []  # captured plugin_ids (#444)

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
        self.rows.extend(rows)

    async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
        self.delivery_failures.append(plugin_id)
```

Then rewrite `test_fast_refusal_arm_running_child_torn_down_not_drained` (currently asserts `recorder.rows == []`) to expect the #444 row AND the unchanged teardown:

```python
async def test_fast_refusal_arm_running_child_records_delivery_failure_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#444: a STILL-RUNNING child on the delivery-failure arm is a genuine delivery
    failure -> persist the reserved provider_key_delivery_failed row, THEN tear down.

    ``poll() is None`` means the child is up (partial writev / EAGAIN), NOT a fast
    (EPIPE, exited) launcher refusal. The row is host-authored (no read_frame drive,
    no ~25s stall), the child is still terminated + reaped, and boot still refuses
    fail-closed.
    """
    recorder = _CapturingRecorder()
    fake = _running_fake(_REFUSAL_ROW)  # returncode None -> poll() is None (still running)
    await _drive_epipe_spawn(fake, recorder, monkeypatch)  # raises QuarantineChildSpawnError
    assert recorder.rows == []  # NOT the launcher-authored stderr-parse path
    assert recorder.delivery_failures == ["alfred.quarantined-llm"]  # #444 host-authored row
    assert fake.terminate_calls >= 1  # the live child was torn down (terminate)...
    assert fake.wait_calls >= 1  # ...and reaped (wait)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest "tests/unit/security/test_quarantine_child_io_refusal_audit.py::test_fast_refusal_arm_running_child_records_delivery_failure_row" -v`
Expected: FAIL — `assert [] == ['alfred.quarantined-llm']` (nothing writes the row yet).

- [ ] **Step 3: Implement the guarded writer method**

In `src/alfred/security/quarantine_child_io.py`, add a method to `_SubprocessChildIO` (place it next to `_record_launcher_refusals`, mirroring its self-guard shape):

```python
    async def _record_provider_key_delivery_failure(self) -> None:
        """Persist the reserved ``provider_key_delivery_failed`` row (#444). Never raises.

        Called from ``_record_fast_launcher_refusal``'s ``poll() is None`` branch — a
        genuine fd-3 delivery failure with the child STILL UP (partial writev / EAGAIN),
        NOT a fast launcher refusal (which has EXITED -> the sec-001 stderr-parse path).
        The row is HOST-authored: every field is a trusted host constant carrying NO
        T3-derived value, so the canary-forward gate guarding ``_record_launcher_refusals``
        does not apply here.

        Fully self-guarding (CLAUDE.md hard rule #7): an ``append_schema`` / ``invoke``
        failure is logged LOUD with an explicit ``error_class`` and swallowed, so it
        never preempts the delivery-failure ``QuarantineChildSpawnError`` the caller
        re-raises.
        """
        if self._refusal_recorder is None:
            return
        try:
            await self._refusal_recorder.record_provider_key_delivery_failure(
                plugin_id=_PLUGIN_ID
            )
        except Exception as exc:
            _log.error(
                "security.quarantine_child.provider_key_delivery_audit_failed",
                error_class=type(exc).__name__,
            )
```

Then update `_record_fast_launcher_refusal`'s `poll() is None` branch (currently `quarantine_child_io.py:828-834`) to write the row before teardown:

```python
    if child_io._process.poll() is None:
        # A LIVE child is a genuine delivery failure (#444's domain), NOT a fast
        # refusal (which has EXITED). Persist the reserved provider_key_delivery_failed
        # row BEFORE teardown, then terminate+reap at once rather than driving read_frame
        # and blocking ~25s on an EOF a live child never sends. ``aclose`` runs in a
        # ``finally`` so the bwrap child is ALWAYS reaped + the control socket ALWAYS
        # closed, even if the (self-guarded) row-write escapes with a BaseException
        # (e.g. a CancelledError, which the writer's ``except Exception`` does not catch)
        # — leak-free fail-closed, mirroring the else arm's own ``finally`` below.
        try:
            await child_io._record_provider_key_delivery_failure()
        finally:
            await child_io.aclose()
        return
```

Refresh the `_record_fast_launcher_refusal` docstring line that says the `poll() is None` branch is "torn down IMMEDIATELY (``aclose``) with NO ``read_frame``" to note it now first persists the `provider_key_delivery_failed` row (still no `read_frame`).

- [ ] **Step 4: Run the new test + the whole refusal-audit module**

Run: `uv run pytest tests/unit/security/test_quarantine_child_io_refusal_audit.py -v`
Expected: PASS (the flipped test passes; every other test in the file — the sec-001 forgery-suppression + fast-refusal-EPIPE tests — stays green because they exercise the `poll()`-exited arm, unchanged).

- [ ] **Step 5: Write the guard-does-not-mask test**

Add to the same file (mirror `test_record_failure_does_not_mask_refusal`):

```python
async def test_delivery_failure_audit_error_does_not_mask_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recorder that raises on the #444 write must NOT mask the delivery refusal.

    The primary ``QuarantineChildSpawnError`` still propagates AND the guard logs
    ``provider_key_delivery_audit_failed`` loudly (CLAUDE.md hard rule #7).
    """
    import structlog.testing

    class _BoomDeliveryRecorder:
        async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:  # pragma: no cover
            raise AssertionError("record() is not the #444 path")

        async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
            raise RuntimeError("audit down")

    recorder = _BoomDeliveryRecorder()
    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(QuarantineChildSpawnError),  # the PRIMARY error still wins
    ):
        await _drive_epipe_spawn(_running_fake(_REFUSAL_ROW), recorder, monkeypatch)
    failed = [
        e
        for e in logs
        if e["event"] == "security.quarantine_child.provider_key_delivery_audit_failed"
    ]
    assert len(failed) == 1  # loud, not silent
    assert failed[0]["error_class"] == "RuntimeError"
```

- [ ] **Step 6: Run it to verify it passes**

Run: `uv run pytest "tests/unit/security/test_quarantine_child_io_refusal_audit.py::test_delivery_failure_audit_error_does_not_mask_refusal" -v`
Expected: PASS.

- [ ] **Step 7: Add the guaranteed `_refusal_recorder is None` coverage test, then verify 100% line+branch**

`_drive_epipe_spawn` always passes a recorder, so `_record_provider_key_delivery_failure`'s `if self._refusal_recorder is None: return` guard is GUARANTEED uncovered without an explicit test (not "if uncovered"). Add one:

```python
async def test_running_child_delivery_failure_without_recorder_still_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No recorder threaded -> the #444 write is a no-op, but boot still refuses fail-closed
    and the live child is still torn down (covers the ``_refusal_recorder is None`` branch)."""
    fake = _running_fake(_REFUSAL_ROW)
    await _drive_epipe_spawn(fake, None, monkeypatch)  # raises QuarantineChildSpawnError
    assert fake.terminate_calls >= 1
    assert fake.wait_calls >= 1
```

(`_drive_epipe_spawn` forwards to `spawn_quarantine_child_io(refusal_recorder=...)`, whose param is `SandboxRefusalRecorder | None`; if the helper's own annotation is narrower, widen it to `| None`.)

Then verify coverage:

Run: `uv run pytest tests/unit/security/ --cov=alfred.security.quarantine_child_io --cov=alfred.security.sandbox_refusal_audit --cov-branch --cov-report=term-missing -q`
Expected: PASS; 100% line+branch on the new method + the modified `poll() is None` branch (recorder-present, recorder-None, and recorder-raises paths all covered).

- [ ] **Step 8: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py tests/unit/security/test_quarantine_child_io_refusal_audit.py
git commit -m "feat(security): #444 write provider_key_delivery_failed row on live-child delivery failure"
```

---

### Task 3: Stale-comment fixes, adversarial corpus, ADR amendment

**Files:**

- Modify: `src/alfred/supervisor/fd3_key_delivery.py` (comments)
- Modify: `src/alfred/audit/audit_row_schemas.py` (comments)
- Modify: `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md`
- Create: `tests/adversarial/sandbox_escape/sbx_2026_026_provider_key_delivery_failure_records_row.yaml`
- Modify: `tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py`

**Interfaces:**

- Consumes: the live writer from Tasks 1-2; the sbx harness `_load("sbx-2026-026")` + `AdversarialPayload` schema; the `test_sbx_2026_025_*` structure as the template.

- [ ] **Step 1: Fix the now-false reserved-comment prose**

In `src/alfred/supervisor/fd3_key_delivery.py`, the module docstring (`:23-28`) and the `ProviderKeyDeliveryError` docstring (`:53-56`) both say the reason "is not emitted by any code today" / "no code writes that row today." That is now FALSE. Update both to: the `provider_key_delivery_failed` reason is written on the genuine-delivery-failure (child-still-up) path by `_SubprocessChildIO._record_provider_key_delivery_failure` via `SandboxRefusalAuditor.record_provider_key_delivery_failure` (#444).

In `src/alfred/audit/audit_row_schemas.py` (`:1201-1210`), update the reserved-`provider_key_delivery_failed` comment likewise (it is now written, not merely reserved).

In `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`, the `_RESERVED_UNEMITTED` set carries `"provider_key_delivery_failed"` with the comment `# ProviderKeyDeliveryError default; not a refused row` (~`:47`) + a module docstring asserting no Python writes one — both now FALSE. The assertions still PASS (that set measures LAUNCHER (bash `printf`) emitters via `_launcher_emittable_reasons()`; #444 adds a HOST emitter, so `provider_key_delivery_failed` correctly stays outside the launcher-emittable set and inside `_RESERVED_UNEMITTED`). But this is exactly the drift-guard #444 trips: correct the `:47` comment to name the truth (e.g. "host-authored refused row (#444); no LAUNCHER emitter — stays reserved w.r.t. the launcher printf vocab") + fix the docstring, and confirm the assertions still hold. The Step-2 grep is `src/alfred/`-scoped and structurally cannot catch this.

- [ ] **Step 2: Verify no stale "reserved/not emitted" prose remains**

Re-verify the exact current line numbers first (a prior edit may have shifted them):

Run: `grep -n provider_key_delivery_failed src/alfred/supervisor/fd3_key_delivery.py src/alfred/audit/audit_row_schemas.py`
Run: `grep -rn -iE "not emitted by any code|reserved.*future writer|no code writes that row|not yet written" src/alfred/`
Expected: no matches referencing `provider_key_delivery_failed` (the reservation is now fulfilled; the broadened `not yet written` alternative catches the `audit_row_schemas.py` phrasing the narrower pattern missed).

- [ ] **Step 3: Write the failing adversarial executable test (021 REAL-registry pattern — NOT 025's fake recorder)**

In `tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py`, add — modelled on `test_sbx_2026_021_*` (the REAL-registry oracle), **not** `test_sbx_2026_025_*` (which uses only a fake `_CapturingRecorder` and would make the dispatch assertion vacuous — it passes even on a build where `invoke` never runs). Reuse the file's existing self-contained helpers (all already imported/defined there): `_patch_spawn_seam_epipe` (the delivery-failure seam — `deliver_provider_key_via_fd3` RAISES `ProviderKeyDeliveryError`), the module-local `_FakePopen`, `_load`, `make_allow_system_gate`, `HookRegistry`/`get_registry`/`set_registry`, `declare_supervisor`. The distinguishing move vs 025: leave `fake.returncode` **None** so `poll() is None` (child still up → #444's arm, not the exited fast-refusal arm), and construct the auditor with the new `host_os`/`environment` kwargs:

```python
async def test_sbx_2026_026_provider_key_delivery_failure_records_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sbx-2026-026: a genuine fd-3 delivery failure with the child STILL RUNNING persists the
    host-authored provider_key_delivery_failed row + dispatches the T0 fail_closed hookpoint,
    and boot still refuses fail-closed.

    Real-registry oracle (per test_sbx_2026_021): a monkeypatched invoke would make the
    dispatch assertion vacuous. Distinct from sbx-2026-025 (fast EPIPE refusal, child EXITED
    -> launcher-authored sandbox_refused row via the stderr parse); here poll() is None.
    """
    payload = _load("sbx-2026-026")
    assert payload.expected_outcome == "refused"

    registry = HookRegistry(
        gate=make_allow_system_gate(
            plugin_id=__name__, hookpoint="supervisor.plugin.sandbox_refused"
        ),
        strict_declarations=True,
    )
    prior = get_registry()
    set_registry(registry)
    try:
        declare_supervisor(registry)

        fired_reasons: list[str] = []

        async def _sandbox_refused_subscriber(ctx: Any) -> None:
            fired_reasons.append(ctx.input["reason"])

        registry.register(
            hook_fn=_sandbox_refused_subscriber,
            hookpoint="supervisor.plugin.sandbox_refused",
            kind="post",
            tier="system",
        )

        rows: list[dict[str, Any]] = []

        class _CapturingWriter:
            async def append_schema(self, **kwargs: Any) -> None:
                rows.append(kwargs)

        recorder = SandboxRefusalAuditor(
            audit_writer=_CapturingWriter(), host_os="linux", environment="production"
        )

        fake = _FakePopen(stdout_frames=[])  # returncode left None -> poll() is None (still up)
        _patch_spawn_seam_epipe(monkeypatch, fake)  # deliver_provider_key_via_fd3 raises

        with structlog.testing.capture_logs() as logs, pytest.raises(QuarantineChildSpawnError):
            await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)

        # (a) exactly one DURABLE host-authored row; reason = the reserved constant.
        assert len(rows) == 1, f"expected one row, got {rows!r}"
        assert rows[0]["subject"]["reason"] == "provider_key_delivery_failed"
        # (b) POSITIVE T0 dispatch: the REAL registered subscriber fired once (a fake
        #     recorder or a zero-subscriber hookpoint would pass a weaker oracle).
        assert fired_reasons == ["provider_key_delivery_failed"]
        # (c) the #444 self-guard did NOT fire (the write succeeded, not swallowed).
        audit_failed = [
            e
            for e in logs
            if e["event"] == "security.quarantine_child.provider_key_delivery_audit_failed"
        ]
        assert not audit_failed, f"the #444 write failed: {audit_failed!r}"
    finally:
        set_registry(prior)
```

Confirm the module-local `_FakePopen(stdout_frames=[])` leaves `returncode` None (still running); if it defaults otherwise, set the still-running variant explicitly. This is the ONLY end-to-end proof that #444's dispatch resolves at its pre-`Supervisor` boot phase (the row fires at the delivery arm, even earlier than the boot handshake).

- [ ] **Step 4: Run it to verify it fails (payload missing)**

Run: `uv run pytest "tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py::test_sbx_2026_026_provider_key_delivery_failure_records_row" -v`
Expected: FAIL — `_load("sbx-2026-026")` raises (no such payload file yet).

- [ ] **Step 5: Create the payload YAML**

Create `tests/adversarial/sandbox_escape/sbx_2026_026_provider_key_delivery_failure_records_row.yaml` (schema-valid `AdversarialPayload`, mirror sbx-2026-025's field set — `extra="forbid"`, real `id`/`category`/`threat`/`ingestion_path`/`payload`/`expected_outcome`/`provenance`/`references`):

```yaml
id: sbx-2026-026
category: sandbox_escape
threat: >-
  A genuine fd-3 provider-key delivery failure (partial writev / EAGAIN) occurs
  while the quarantined child is STILL RUNNING. An attacker hopes the failure is
  torn down silently — no durable audit row, no fail-closed hookpoint — so the
  security-visible record of a key-delivery anomaly is lost even though boot
  refuses.
ingestion_path: stdio_fd3_key_delivery
payload:
  attack: fd3_delivery_failure_child_still_running
  framing: length_prefix_then_key
expected_outcome: refused
provenance: >-
  #444 (#433 follow-up). On a ProviderKeyDeliveryError with the child still up
  (poll() is None), _record_fast_launcher_refusal now persists the reserved
  provider_key_delivery_failed SANDBOX_REFUSED_FIELDS row (host-authored, via
  SandboxRefusalAuditor.record_provider_key_delivery_failure) and dispatches the
  T0 fail_closed hookpoint BEFORE tearing the child down — distinct from the fast
  (EPIPE, exited) launcher-refusal arm which records the launcher-authored
  sandbox_refused row via the stderr parse (sbx-2026-025).
references:
  - "src/alfred/security/quarantine_child_io.py (_record_fast_launcher_refusal poll() gate)"
  - "src/alfred/security/sandbox_refusal_audit.py (record_provider_key_delivery_failure)"
  - "src/alfred/supervisor/fd3_key_delivery.py"
  - "docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md (Follow-ups: #444)"
```

- [ ] **Step 6: Run the adversarial test + the corpus schema/density gates**

Run: `uv run pytest tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py -v && uv run pytest tests/adversarial -q`
Expected: PASS — the new executable test + the corpus schema/density validators accept sbx-2026-026, and the full release-blocking suite is green.

- [ ] **Step 7: Amend ADR-0051**

In `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md`, in the "Follow-ups to file" section, mark the `provider_key_delivery_failed` writer as **implemented (#444)** with a one-line pointer to `SandboxRefusalAuditor.record_provider_key_delivery_failure` + the `poll() is None` call site. Do not rewrite the ADR body; append an amendment note dated 2026-07-18.

- [ ] **Step 8: Markdown lint the ADR**

Run: `npx markdownlint-cli2@0.22.1 "docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md"`
Expected: 0 errors (match the file's existing emphasis/marker conventions).

- [ ] **Step 9: Commit**

```bash
git add src/alfred/supervisor/fd3_key_delivery.py src/alfred/audit/audit_row_schemas.py docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md tests/unit/plugins/test_sandbox_reason_vocab_sync.py tests/adversarial/sandbox_escape/sbx_2026_026_provider_key_delivery_failure_records_row.yaml tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py
git commit -m "test(security): #444 adversarial sbx-2026-026 + ADR-0051 follow-up done + fix stale reserved comments"
```

---

### Final verification (before PR)

- [ ] **All quality gates:** `make check` (ruff check + format + mypy + pyright + unit). Expected: green. If `make ...|tail` masks the exit code, check `$?`.
- [ ] **Adversarial suite (release-blocking — security path touched):** `uv run pytest tests/adversarial -q`. Expected: green.
- [ ] **i18n drift gate:** no new `t()` keys were added (audit rows / structlog events are out of `t()` scope), so `pybabel extract`/`update`/`compile --check` should show no catalog drift. Run the repo's i18n check if one is wired into `make check`.
- [ ] **Coverage:** 100% line+branch on `alfred.security.quarantine_child_io` + `alfred.security.sandbox_refusal_audit` touched paths.

---

## Self-Review

**1. Spec/design coverage** (against the approved inline design):

- Host-authored row on the `poll() is None` branch → Task 2. ✅
- Reuse `SandboxRefusalAuditor` (durable write + T0 hookpoint) → Task 1 (`record` delegation). ✅
- `host_os`/`environment` from a host source consistent with launcher rows → Task 1 (`_resolve_host_os` mirrors the launcher vocab; `environment` = `settings.environment`). ✅
- Guard so an audit failure never masks the refusal (HARD #7) → Task 2 (`provider_key_delivery_audit_failed` + `test_delivery_failure_audit_error_does_not_mask_refusal`). ✅
- Distinct provenance from #433's stderr-parsed rows → documented in the auditor method + the `_record_provider_key_delivery_failure` docstring + sbx-2026-026 threat. ✅
- Adversarial (release-blocking) coverage → Task 3 (sbx-2026-026 + paired executable test). ✅
- ADR amendment (no new ADR) → Task 3. ✅
- Fix now-false reserved comments → Task 3. ✅

**2. Placeholder scan:** the only `...` is the Protocol method body (a Protocol stub — correct). The sbx-2026-026 executable test is now written out in full against the 021 real-registry harness (post-plan-review fold). No `TBD`/`TODO`/"add error handling".

**4. Plan-review folds applied (focused security + core, 2026-07-19):** B1 (sbx `:275` ctor break → fixed in Task 1 + adversarial run added to Task 1); sec-I1 (`try/finally` teardown on the `poll() is None` branch); sec-I2 (sbx-2026-026 rewritten to the 021 real-registry oracle, not 025's fake recorder); sec-I3 (`test_sandbox_reason_vocab_sync.py` drift-guard comment); core-I1/I2 (the 6 auditor + 4 extractor ctor sites enumerated as certain); core-I3 (`_fake_invoke` fixture on the new auditor test); nits (guaranteed `_refusal_recorder is None` coverage test; `_FakeAudit`/`.calls`; reason-literal binding comment; broadened Step-2 grep). Design unchanged — all folds are plan-quality.

**3. Type consistency:** `record_provider_key_delivery_failure(*, plugin_id: str)` is spelled identically in the Protocol (Task 1), the auditor (Task 1), the `_SubprocessChildIO` call (Task 2), and both test fakes. `_resolve_host_os() -> str` and the `environment: str` param match across Tasks 1 and 3. `SandboxRefusalAuditor.__init__(*, audit_writer, host_os, environment)` is the single construction signature used in daemon_runtime + both test files.

**Open item deliberately left to the reviewers (not a placeholder):** whether the auditor method should be specific (`record_provider_key_delivery_failure`, chosen here — the reason is fixed to the reserved constant, no caller can pass an arbitrary reason) vs a generic `record_synthesized(reason, plugin_id)`. The focused security+core plan-review decides; the specific form is the safer default (YAGNI + closed reason vocabulary).
