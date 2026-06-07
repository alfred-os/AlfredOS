# PR-S4-5: CLI Operator Session — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the CLI operator-session surface — `alfred login` / `alfred logout` / `alfred whoami` — plus the host-side `_resolve_operator(ctx) -> UserId` helper and the cross-cutting threading that lets every operator-attributed CLI command emit audit rows whose `operator_user_id` is the canonical `User.id` of the logged-in operator. Closes [#153](https://github.com/MrReasonable/AlfredOS/issues/153) by replacing the Slice-3 `_resolve_operator_user_id() -> str | None` env/getlogin/getpwuid fallback in `src/alfred/cli/supervisor.py` (lines 161 and 541; verified via grep on `slice-4-plans`) with the new session-backed resolver.

**Architecture:** A new `OperatorSession` Pydantic v2 model lives at `src/alfred/identity/operator_session.py` and is serialised to `~/.config/alfred/session` as JSON. File load follows the TOCTOU-safe **open-then-fstat** discipline (spec §6.2). The session-creating CLI lives at `src/alfred/cli/operator_session.py`, registered against the root `typer` app as the `login`, `logout`, and `whoami` commands (no sub-app — they are top-level verbs, mirroring `alfred status` / `alfred chat`). The host-side resolver is a `Protocol` (`OperatorResolver`) consumed via DI; a pytest-time AST guard at `tests/unit/cli/test_operator_resolver_consumed.py` refuses any CLI command that emits an operator-attributed audit row without consuming the resolver. Three hookpoints (`operator.session.created`, `operator.session.revoked`, `operator.session.refused`) carry `carrier_tier="T1"` per spec §10.

**Tech Stack:** Python 3.12+ · Typer (CLI) · Pydantic v2 (frozen models, `SecretStr` for the token) · asyncio + `asyncio.wait_for` (250ms hard timeout per spec §6.4) · SQLAlchemy 2.0 typed (single-row index lookup on `uq_operator_sessions_token_hash`) · `secrets.token_urlsafe(32)` for token bytes · `hmac` + `hashlib.sha256` for `machine_id_hash` and `token_hash` · `babel.dates.format_datetime` for whoami locale formatting (i18n-003) · `secret_broker.get("audit.hash_pepper")` for the HMAC pepper · `os.open(O_RDONLY | O_NOFOLLOW)` + `os.fstat` for TOCTOU-safe file loads · structlog · `t()` for all operator-facing strings · pytest + testcontainers (integration)

**Depends on:** PR-S4-0a (merged — `OPERATOR_SESSION_CREATED_FIELDS` / `OPERATOR_SESSION_REVOKED_FIELDS` / `OPERATOR_SESSION_REFUSED_FIELDS` / `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` constants + the `osf` payload-schema prefix), PR-S4-0b (provider of Alembic 0012 `operator_sessions` table with the `uq_operator_sessions_token_hash` unique index, the bootstrapped `audit.hash_pepper` broker secret, the i18n catalog keys enumerated in spec §12.2), **PR-S4-3** (merged — `HookpointMeta.carrier_tier` + `HookpointMeta.allow_error_substitution` fields are required for the three new `operator.session.*` `register_hookpoint(...)` calls; rev-009 closure). Per `docs/superpowers/plans/2026-06-07-slice-4-index.md` §2.

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **sec-1 BLOCKER (SecretStr persistence breaks file load)**: `OperatorSession.token` field is `str` (NOT `SecretStr`) ONLY inside the file-persistence model `_OperatorSessionFileBytes`. The in-memory `OperatorSession` keeps `SecretStr` to redact in logs. The persistence path uses an explicit `_serialize_to_file_bytes(session: OperatorSession) -> bytes` helper that calls `session.token.get_secret_value()` and JSON-encodes the result. Symmetrically, `_deserialize_from_file_bytes(raw: bytes) -> OperatorSession` reads the raw token string and re-wraps in `SecretStr`. A new unit test `tests/unit/identity/test_operator_session_roundtrip.py` asserts `write→read→equality` on the secret. Without this fix EVERY login produces a file that fails the next load with `OperatorSessionNotFound` because `SecretStr.model_dump_json()` writes `"**********"` and the HMAC-SHA256(token_hash) lookup misses the DB row.

2. **sec-2 HIGH (parent-dir TOCTOU)**: `_load_session_file` uses `os.openat()` against an fstat-validated parent dirfd: `parent_fd = os.open(parent_dir, os.O_RDONLY | os.O_DIRECTORY); try: parent_stat = os.fstat(parent_fd); if parent_stat.st_mode & 0o077: raise ParentDirInsecure; if parent_stat.st_uid != os.geteuid(): raise ParentDirNotOwned; session_fd = os.openat(parent_fd, "session", os.O_RDONLY | os.O_NOFOLLOW); ...`. Symmetrically `_write_session_file` creates `~/.config/alfred/` with `0o700` if missing and refuses if existing mode is broader; `~/.config/alfred/session` is written with `0o600`. Refuses rename-into-dir attacks that `O_NOFOLLOW` alone misses.

3. **sec-3 HIGH (HMAC pepper domain separation via HKDF)**: `audit.hash_pepper` is the master pepper (32 bytes; validated at boot via `len(secret_broker.get("audit.hash_pepper").encode()) >= 32` in PR-S4-1's daemon-boot probe — if shorter, `daemon.boot.failed(failure_reason="audit_hash_pepper_too_short")` refuses boot). Two derived subkeys via HKDF-SHA256: `_TOKEN_HASH_SUBKEY = hkdf_expand(pepper, info=b"operator_session.token_hash.v1", length=32)` and `_MACHINE_ID_HASH_SUBKEY = hkdf_expand(pepper, info=b"operator_session.machine_id_hash.v1", length=32)`. The HMACs use these subkeys, NOT the master pepper directly. Domain separation prevents cross-purpose attacks (e.g., a leaked token-hash cannot be replayed as a machine-id-hash). A new unit test `tests/unit/security/test_operator_session_hkdf_subkeys.py` asserts the subkeys differ.

4. **sec-4 MEDIUM (attempted_user_id log-injection)**: `attempted_user_id` field on `OPERATOR_SESSION_REFUSED_FIELDS` is `Annotated[str, StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")]` — refusing a planted file with arbitrary bytes BEFORE emitting the audit row. The validation happens in `_load_session_file` via the Pydantic model's field validator; rejection emits `_emit_refused(reason="planted_file_invalid_user_id")` with `attempted_user_id=None` (no attacker-controlled bytes in the audit log). Corpus entry `osf-2026-007-planted_user_id_log_injection` covers this.

5. **arch-1 HIGH (cross-PR Supervisor wiring)**: PR-S4-5 EXPANDS its task list to include explicit modification of `src/alfred/supervisor/core.py:177-185` to accept `operator_session_resolver: OperatorResolver` as a required kwarg. The Supervisor stores it as `self._operator_resolver` and threads it into every audit-emitting code path that previously called `_resolve_operator_user_id()`. PR-S4-1's `_construct_supervisor` helper supplies a concrete `DefaultOperatorResolver` instance from `cli/_bootstrap.py`. The brief's "cross-PR contract with PR-S4-1" is realized — PR-S4-1 ships the constructor kwarg; PR-S4-5 ships the wiring through every consumer.

6. **arch-2 HIGH (protocol name)**: rename `OperatorResolver` → `OperatorSessionResolver` everywhere in the plan. Distinct from `IdentityResolver` (which resolves comms-platform identities → canonical user IDs). `OperatorSessionResolver` is exclusively for the CLI session-token → User.id resolution. Index §3 + spec §10 use `OperatorSessionResolver`; plan now matches.

7. **arch-3 MEDIUM (DefaultOperatorSessionResolver deps explicit)**: `DefaultOperatorSessionResolver.__init__(self, *, db_session: AsyncSession, audit_writer: AuditWriter, hook_dispatcher: HookDispatcher, machine_id_provider: MachineIdProvider, clock: Clock = SystemClock())`. The `HookDispatcher` is explicitly injected; `_emit_refused` consumes `self._hook_dispatcher`. No global state; passes CLAUDE.md "no global state, pass deps explicitly" gate.

8. **devex-1 HIGH (whoami readability)**: `alfred whoami` output template:

   ```text
   {t("whoami.signed_in_as")}: {display_name} ({user_id_short})
   {t("whoami.session_since")}: {issued_at_relative} ({issued_at_absolute_locale})
   {t("whoami.session_expires")}: {expires_at_relative} ({expires_at_absolute_locale})
   {t("whoami.machine")}: {hostname} ({machine_id_hash_short})
   ```

   Each line has a label via `t(...)`; relative-time helpers (`"3 days ago"`, `"in 12 hours"`) via `babel.dates.format_timedelta`. `user_id_short` = first 8 chars of canonical UUID with `…`. `machine_id_hash_short` = `:8 + '…'` BUT prefixed with `{hostname}` so operators see a human-recognizable identifier.

9. **devex-2 HIGH (refusal taxonomy includes recovery commands)**: every refusal-reason `t()` key has a `t("...recovery")` companion that includes a runnable command. Examples:
   - `t("operator_session.refused.expired") = "Your session expired {expires_at_relative}."` + `t("operator_session.refused.expired.recovery") = "Run \`alfred login\` to start a new session."`
   - `t("operator_session.refused.host_mismatch") = "This session was created on a different host."` + `t("operator_session.refused.host_mismatch.recovery") = "If you docked your laptop, run \`alfred login\` again on this host (the hostname changed)."`
   - `t("operator_session.refused.machine_mismatch") = "This machine's identity doesn't match the session."` + `t("operator_session.refused.machine_mismatch.recovery") = "If you reimaged this machine, the previous session is no longer valid. Run \`alfred login\` to start fresh."`
   The CLI always emits BOTH the reason AND the recovery line. §8.3 dock-attach narrative is now operator-actionable.

10. **devex-3 MEDIUM (alfred login bare-mode branches)**: `alfred login` flow:
    - **Zero users**: refuse with `t("login.no_users_exist") = "No users are registered. Add a user first: \`alfred user add\`."` exit 1.
    - **Single user**: auto-select that user (no picker), confirm with `t("login.auto_selected_single_user", display_name=...)`.
    - **Multi-user TTY**: render numbered picker via Typer.
    - **Multi-user non-TTY** (`not sys.stdin.isatty()`): refuse with `t("login.non_tty_requires_explicit_user") = "Multiple users registered. Pass \`--user <id>\` in non-interactive contexts."` exit 2.
    - `alfred login --user <id>` bypasses the picker entirely.

11. **test-1 HIGH (impersonation-by-mismatch corpus + test)**: NEW corpus entry `osf-2026-006-token_user_mismatch`: a planted session file containing a VALID token (matches a DB row's `token_hash`) but a DIFFERENT `user_id` in the file body. The contract: **token is authoritative** — `_resolve_operator_session` looks up the DB row by `token_hash` and refuses if `db_row.user_id != file.user_id` with reason `token_user_mismatch`. NEW exception `OperatorSessionTokenUserMismatch`. NEW unit test in `tests/unit/identity/test_operator_session_resolver.py` covering this branch.

12. **test-2 + test-3 MEDIUM (replay + coverage CI gate)**: NEW unit test `tests/unit/identity/test_replay_on_different_machine.py` constructs two `MachineIdProvider` stubs returning different hashes, creates a session under stub-A, attempts resolve under stub-B, asserts `OperatorSessionMachineIdMismatch`. Graduation Task 31 ADDS `coverage --fail-under=100 --branch --include=src/alfred/identity/operator_session.py,src/alfred/identity/_resolver.py` as a merge-blocking command (NOT just checklist).

13. **lifetime-pin clarification**: `_DEFAULT_EXPIRES_IN = timedelta(hours=12)` with `[1h, 7d]` clamp, NOT 30-day default. The earlier "30-day" mention in spec is an artifact of an earlier draft and is corrected in spec §6.4 final.

**Blocks:** PR-S4-8 (`process_inbound_message` exists at the host but does not itself depend on the operator session — the dependency is transitive via `Supervisor.request_plugin_restart` audit attribution; the slice-index lists PR-S4-5 as a blocker because the host-side resolver becomes the canonical attribution path).

**Closes:** [#153](https://github.com/MrReasonable/AlfredOS/issues/153).

---

## §1 Goal

This PR delivers the **CLI operator session** scope from [spec §6](../specs/2026-06-06-slice-4-design.md#6-cli-operator-session-153-closure) — every sub-section 6.1 through 6.8 lands here. By the time PR-S4-5 merges:

1. An operator on a fresh AlfredOS daemon host can run `alfred login --as <user>` (or bare `alfred login` to pick from a numbered list of users — devex-002), get a session token persisted at `~/.config/alfred/session` with mode `0600`, and from then on every operator-attributed CLI command emits an audit row whose `operator_user_id` is the canonical `User.id` rather than the Slice-3 OS-account fallback. `alfred logout` revokes the session; `alfred whoami` prints the bound user, host, machine-id-hash, and locale-formatted expiry.
2. The session-file load is TOCTOU-safe via the open-then-fstat pattern (sec-006 closure): `os.open(path, O_RDONLY | O_NOFOLLOW)` refuses symlinks at open time, then `os.fstat(fd)` validates `st_mode == 0o600` + `st_uid == os.getuid()` + `st_gid == os.getgid()` before the file is read.
3. `_resolve_operator(ctx) -> UserId` is the single helper every operator-attributed CLI command uses (DI'd via the `OperatorResolver` Protocol). It hits the `operator_sessions` table on the `uq_operator_sessions_token_hash` unique index (lookup-by-token-hash), validates expiry / host / machine-id / user-revoked state, with a **5ms p99 budget** and a **250ms hard timeout** via `asyncio.wait_for(...)` that raises `OperatorSessionTimeout` rather than hanging silently (err-008 closure).
4. The machine-id source is per-OS and **system-owned** (sec-006 closure): `/etc/machine-id` then `/var/lib/dbus/machine-id` on Linux; `IOPlatformUUID` (cached at `/var/db/alfred/machine-id`) on macOS; `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid` on Windows. The session file stores only the HMAC of the raw machine-id (HMAC-SHA256 keyed by the broker-resident `audit.hash_pepper`), never the raw value.
5. The four `_resolve_operator_user_id() -> str | None` callsites at `src/alfred/cli/supervisor.py` (lines 161 and 541 — note: the spec's "four sites" phrasing predates the Slice-3 hardening that consolidated them; verification-gate below documents exactly what exists) are migrated to `await _resolve_operator(ctx)`. The reset command refuses with `t("supervisor.breaker.reset.refused.not_logged_in")` and emits `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` carrying `reason="operator_session_missing"` if the operator is not logged in. The English inline literal that the Slice-4 draft used moves into the i18n catalog (i18n-001 closure).
6. `alfred config quarantined-provider` and `alfred plugin grant`/`revoke` gain the same attribution threading (spec §6.8). `alfred memory forget` and `alfred rollback` are out of scope (not shipped in Slice 3).
7. Three new hookpoints (`operator.session.created`, `operator.session.revoked`, `operator.session.refused`) are registered with `subscribable_tiers=SYSTEM_ONLY_TIERS`, `fail_closed=True`, `carrier_tier="T1"` per spec §10. **Requires PR-S4-3** because `HookpointMeta.carrier_tier` is a new required field.

Spec anchors: §6 entire (6.1 model, 6.2 file format + TOCTOU, 6.3 UX + bare-login, 6.4 resolver, 6.5 token / machine-id, 6.6 audit rows, 6.7 #153 closure, 6.8 other CLI commands), §9 audit-row schemas table row block for `OPERATOR_SESSION_*` + `SUPERVISOR_BREAKER_RESET_REFUSED`, §10 hookpoint table rows for `operator.session.*`, §11.5 merge-blocking integration tests row for `test_operator_session_lifecycle`, §12.2 i18n catalog enumeration, §13.1 glossary additions for `OperatorSession` / `OperatorResolver` / `OperatorSessionTimeout`, §14 graduation criterion 11 (trust-boundary coverage) row for `src/alfred/identity/operator_session.py` + `src/alfred/cli/operator_session.py`.

---

## §2 Architecture overview

```
                 +--------------------------------------+
   $ alfred login --as alice                            |
                 |                                      |
                 v                                      |
   +-----------------------------+                      |
   | src/alfred/cli/             |                      |
   |   operator_session.py       |   (Typer commands)   |
   |   - login(...)              |                      |
   |   - logout(...)             |                      |
   |   - whoami(...)             |                      |
   +-----------------------------+                      |
                 |                                      |
                 |  reads/writes ~/.config/alfred/session
                 |  (mode 0600, open-then-fstat)        |
                 v                                      |
   +-----------------------------+                      |
   | src/alfred/identity/        |                      |
   |   operator_session.py       |                      |
   |   - OperatorSession (model) |                      |
   |   - OperatorResolver (Proto)|                      |
   |   - _resolve_operator(ctx)  |                      |
   |   - load_session_file(path) |                      |
   |   - machine_id_provider()   |                      |
   +-----------------------------+                      |
                 |                                      |
                 |  audited via                         |
                 |  hookpoints + audit rows             |
                 v                                      |
   +-----------------------------+   +------------------+
   | operator_sessions (PG)      |   | secret broker    |
   |   PK (token_hash) UNIQUE    |   |   audit.hash_pepper
   +-----------------------------+   +------------------+

   $ alfred supervisor reset / config / plugin grant
       |
       v
   await _resolve_operator(ctx)   # 5ms p99, 250ms hard timeout
       |
       +-> UserId  -> audit row carries operator_user_id
       +-> raises OperatorSessionMissing -> refuse with
           t("supervisor.breaker.reset.refused.not_logged_in")
       +-> raises OperatorSessionTimeout -> refuse with
           t("operator_session.refused.resolver_timeout")
```

Key design constraints:

- **No global state** — the session-file path, the `SecretBroker`, the `AsyncSession` factory, the audit writer, and the machine-id provider are all passed as arguments to `_resolve_operator`. The Typer-layer wrapper constructs them from `cli/_bootstrap.py` (Slice-3-shipped seam — verified at `src/alfred/cli/_bootstrap.py`) and propagates them through the command callback. No module-level `os.environ["HOME"]` reads in `identity/operator_session.py`; the loader takes `home: Path` explicitly so tests can substitute.
- **Async-first** — `_resolve_operator` is `async def` and the resolver Protocol is `async`. Typer commands wrap with `asyncio.run(...)` at the outermost layer; everything underneath is async, matching the Slice-3 CLI convention (`src/alfred/cli/supervisor.py` already uses `asyncio.run` per the verified file).
- **Frozen Pydantic v2** — `OperatorSession` is frozen; the resolver returns a frozen `ResolvedOperator(user_id, session)` value-object.
- **Errors loud at boundaries** — every refusal path emits a typed audit row + raises a typed exception that bubbles to the Typer callback; the callback maps the exception to a localised stderr message and exits non-zero. No silent failures (CLAUDE.md hard rule 7).

---

## §3 File structure

| File | Action | Responsibility |
|---|---|---|
| `src/alfred/identity/operator_session.py` | **Create** | `OperatorSession` Pydantic v2 model; `OperatorResolver` Protocol; `_resolve_operator(ctx) -> UserId` async helper; `load_session_file(path) -> OperatorSession` TOCTOU-safe loader; `compute_machine_id_hash(...)`; per-OS `MachineIdProvider` (`LinuxMachineIdProvider`, `MacosMachineIdProvider`, `WindowsMachineIdProvider`); exception hierarchy rooted at `OperatorSessionError` (`OperatorSessionMissing`, `OperatorSessionExpired`, `OperatorSessionRevoked`, `OperatorSessionHostMismatch`, `OperatorSessionMachineMismatch`, `OperatorSessionBadFileMode`, `OperatorSessionBadFileOwner`, `OperatorSessionTokenUnknown`, `OperatorSessionUserRevoked`, `OperatorSessionTimeout`). |
| `src/alfred/cli/operator_session.py` | **Create** | `alfred login [--as <user>] [--expires-in <duration>] [--refresh]`, `alfred logout`, `alfred whoami` Typer commands. Imports `_resolve_operator`. Wires the bare-`alfred login` discoverability flow (devex-002). Locale-formats `whoami` timestamps via `babel.dates.format_datetime(dt, locale=user.language)`. |
| `src/alfred/cli/main.py` | **Modify** | Register `login` / `logout` / `whoami` as top-level commands on the root `app` (mirrors `alfred status`, `alfred chat`). Lazy-import `operator_session` to keep `alfred --help` under the Slice-3 perf budget (PR-S3-6 §8.5 lesson). |
| `src/alfred/cli/supervisor.py` | **Modify** | Replace `_resolve_operator_user_id()` callsites (line 161 in `_reset_breaker`, line 541 in `_apply_breaker_reset_proposal`) with `await _resolve_operator(ctx)`. Add the precondition refusal with `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` + the localised stderr message. Delete the Slice-3 fallback function once no callsites remain. |
| `src/alfred/cli/config.py` | **Modify** | The `alfred config quarantined-provider` callback gains `_resolve_operator(ctx)` so the queued state.git proposal payload carries the operator's canonical `user_id`. (Slice-3 left this attribution unset — devex review of #153.) |
| `src/alfred/cli/plugin.py` | **Modify** | `alfred plugin grant` and `alfred plugin revoke` callbacks gain `_resolve_operator(ctx)`. The proposal payload's `operator_user_id` field becomes the canonical `User.id`. |
| `src/alfred/identity/cli.py` | **Modify** | Add a small helper `def list_users_for_picker() -> Sequence[UserRow]` to support the bare-`alfred login` numbered-picker flow. Re-uses the existing `list_` SQLAlchemy query; does NOT touch the existing `user list` UX. |
| `tests/unit/cli/test_operator_resolver_consumed.py` | **Create** | **AST guard**: walks every module under `src/alfred/cli/`, finds every callsite of `await self._audit.append_schema(constant, ...)` where `constant` is in the closed set of operator-attributed audit-row constants enumerated from `audit_row_schemas.py`, and asserts the enclosing function consumes `OperatorResolver` (via parameter type-annotation or `_resolve_operator` import). Closed set: every constant whose field-set includes `operator_user_id`. |
| `tests/unit/identity/test_operator_session_model.py` | **Create** | `OperatorSession` frozen-model invariants; `SecretStr` token serialisation; `schema_version=1` Literal; `expires_at >= issued_at` validator. |
| `tests/unit/identity/test_operator_session_file_load.py` | **Create** | TOCTOU-safe load: refuses symlink (`O_NOFOLLOW`); refuses wrong mode (e.g., 0644); refuses wrong uid/gid; happy path returns the parsed `OperatorSession`. |
| `tests/unit/identity/test_operator_session_machine_id.py` | **Create** | Per-OS machine-id provider: Linux `/etc/machine-id` happy + fallback to `/var/lib/dbus/machine-id` + both-unreadable refusal; macOS provider reads `IOPlatformUUID` via mock + caches at `/var/db/alfred/machine-id`; Windows provider reads registry via mock. |
| `tests/unit/identity/test_resolve_operator.py` | **Create** | `_resolve_operator` happy path (file → DB lookup → returns `UserId`); each refusal path (`expired`, `host_mismatch`, `machine_mismatch`, `token_unknown`, `user_revoked`, `bad_file_mode`, `bad_file_owner`); the 250ms timeout raising `OperatorSessionTimeout`; the 5ms p99 budget assertion (advisory perf check). |
| `tests/unit/cli/test_login_command.py` | **Create** | `alfred login --as <user>` happy path; user-not-found refusal; existing-session overwrite prompt (mocked); `--expires-in` clamp `[1h, 7d]`; `--refresh` rotation; bare `alfred login` numbered-picker flow. |
| `tests/unit/cli/test_logout_command.py` | **Create** | `alfred logout` happy path (revokes DB row + deletes file); `alfred logout` with no session refuses with `t("logout.no_session")`. |
| `tests/unit/cli/test_whoami_command.py` | **Create** | `alfred whoami` happy path (locale-formatted timestamps via `babel.dates.format_datetime`); no-session non-zero exit; expired-session non-zero exit with `t("whoami.expired")`. |
| `tests/unit/cli/test_supervisor_reset_session_attribution.py` | **Create** | `alfred supervisor reset` carries the canonical `operator_user_id`; refusal when not logged in emits `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS(reason="operator_session_missing")` + the localised refusal stderr. |
| `tests/integration/test_operator_session_lifecycle.py` | **Create** | **Merge-blocking** (spec §11.5): login → use a session-attributed CLI command → logout cycle against a real Postgres testcontainer; asserts the `operator_sessions` row lifecycle (create / revoke); asserts the `audit_log` row chain (`OPERATOR_SESSION_CREATED` → consuming-command audit row with `operator_user_id` set → `OPERATOR_SESSION_REVOKED`). |
| `locale/en/LC_MESSAGES/alfred.po` | **Modify** | Add the i18n catalog entries enumerated in spec §12.2 "Login / session lifecycle" + "Operator-session refusal reasons" + "Supervisor reset refusals" + "TUI" subset relevant to this PR. **Note**: PR-S4-0b already lands the catalog keys; this PR's job is the production `t()` callsites, not the catalog source. The PR's `pybabel extract` run must produce zero new `#: TODO` markers beyond what PR-S4-0b shipped. |

The new file count is **2 source files + 1 modified CLI module + 4 modified existing modules + 1 i18n catalog + 8 new test files + 1 merge-blocking integration test**. The bulk of the work is the resolver and the per-OS machine-id discipline; the CLI surface is thin.

---

## §4 Cross-PR contracts

These surfaces are owned by other PRs in this slice; this PR consumes them. Drift between PRs is a release blocker.

### From PR-S4-0a (`audit_row_schemas.py` constants)

- `OPERATOR_SESSION_CREATED_FIELDS` — used by the `login` happy path + `--refresh` rotation.
- `OPERATOR_SESSION_REVOKED_FIELDS` — used by the `logout` happy path + the expiry-cleanup tick (deferred sub-task — see §6 Task 24).
- `OPERATOR_SESSION_REFUSED_FIELDS` — emitted by every `_resolve_operator` refusal path with the matching `reason` Literal.
- `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` — emitted when `alfred supervisor reset` refuses due to missing/expired session.

PR-S4-5 imports these constants from `src/alfred/audit/audit_row_schemas.py`; no inline field-list literal at any callsite. PR-S4-0a's test `tests/unit/audit/test_audit_constants_slice_4.py` already pins that each field name maps to an `AuditEntry` column.

### From PR-S4-0b (Alembic 0011 + i18n + broker pepper)

- **`operator_sessions` table** with columns `(user_id, token_hash, issued_at, expires_at, host, machine_id_hash, revoked_at)` and **unique index `uq_operator_sessions_token_hash`** on `token_hash`. The resolver's primary lookup is `WHERE token_hash = :h AND revoked_at IS NULL`.
- **`audit.hash_pepper` secret** bootstrapped in the broker config. The `AuditWriter` already fetches this at boot per spec §8.10; PR-S4-5 re-uses the same broker handle for the `machine_id_hash` HMAC and the `token_hash` HMAC. **The pepper is bytes, not a `Settings` field.**
- **i18n catalog keys** — every key enumerated in spec §12.2 lands in PR-S4-0b; PR-S4-5 wires the production `t()` callsites.

### From PR-S4-3 (HookpointMeta extension)

- **`HookpointMeta.carrier_tier: TrustTier`** is a new required field. The three `operator.session.*` `register_hookpoint(...)` calls in this PR must populate `carrier_tier="T1"`.
- **`HookpointMeta.allow_error_substitution: bool`** defaults `True`. The operator-session hookpoints are not observation-only; the default applies and no callsite passes the field explicitly.

The AST guard `tests/unit/hooks/test_carrier_tier_required.py` (PR-S4-3) refuses any `register_hookpoint(...)` that omits `carrier_tier=`. PR-S4-5 must clear this guard.

### Surfaces this PR DEFINES (consumed by other PRs)

- **`OperatorResolver` Protocol** (new in Slice 4). PR-S4-8's `process_inbound_message` does not consume this; the host-side identity boundary uses a different resolver (`IdentityResolver` for platform → canonical mapping). The `OperatorResolver` is exclusively for CLI command attribution. PR-S4-11 cross-links `OperatorResolver` from `docs/glossary.md` per spec §13.1.
- **`_resolve_operator(ctx) -> UserId`** async helper. Consumed by PR-S4-5's own `config.py` / `plugin.py` / `supervisor.py` callsites; not yet consumed elsewhere in the slice.
- **The AST guard** `tests/unit/cli/test_operator_resolver_consumed.py`. Other PRs adding CLI commands that emit operator-attributed audit rows must clear this guard.

### Fabricated-surfaces verification gate

Before any task begins, grep-verify every cited symbol exists or is explicitly marked as new. Captures the round-4 `/review-pr` lesson — invented `secret_broker.fetch_audit_pepper`, `AuditWriter.dedupe_surface`, `Python launcher`, `AlfredPluginSession._read_loop` all snuck through prior plans. Each row below has been re-verified on the `slice-4-plans` branch at planning time.

| Cited surface | Status on `slice-4-plans` | Verification |
|---|---|---|
| `SecretBroker.get(name) -> str` at `src/alfred/security/secrets.py:396` | **Exists** | `grep -n "def get\b" src/alfred/security/secrets.py` → `396: def get(self, name: str) -> str:` |
| `audit.hash_pepper` secret name | **Not yet present — lands in PR-S4-0b** | Bootstrapped by the PR-S4-0b migration per spec §8.10 + slice-index §3 audit-pepper bootstrap row. This PR assumes presence and emits `OperatorSessionError` at fetch time if missing (defensive — the daemon-boot probe in PR-S4-1 catches the absence first). |
| `OperatorResolver` Protocol | **NEW in Slice 4 — defined by this PR** | No grep hits on `slice-4-plans`. This PR is the introducing site. |
| `_resolve_operator` helper | **NEW in Slice 4 — defined by this PR** | No grep hits. The existing Slice-3 helper at `src/alfred/cli/supervisor.py:39` is the dissimilarly-named `_resolve_operator_user_id() -> str \| None` (env/getlogin/getpwuid fallback). This PR replaces it. |
| `alfred user show` / `alfred user list` / `alfred user add` | **Exist** | `grep -n "^@user_app.command" src/alfred/identity/cli.py` → `add` (line 241), `list` (line 374), `show` (line 449), `remove` (495), `bind` (559), `unbind` (618), `set` (677). Registered at `src/alfred/cli/main.py:86` (`app.add_typer(user_app, name="user", ...)`). |
| `alfred supervisor reset` | **Exists** at `src/alfred/cli/supervisor.py` | The four `operator_user_id=None` placeholder sites the round-4 spec describes have already been hardened in Slice 3 to `operator_user_id=_resolve_operator_user_id()` (env/getlogin/getpwuid fallback). The migration in this PR replaces the **Slice-3 fallback** with the new **session-backed resolver**. Exact callsite lines on `slice-4-plans`: 161 (`_reset_breaker`) and 541 (`_apply_breaker_reset_proposal`). The two additional sites the spec's "four sites" phrasing implied are read-only audit-projection lines (615, 662) where `operator_user_id` is a queried column, not a write. The PR description must call this out so reviewers can map spec wording to code reality. |
| `babel.dates.format_datetime` | **Available** — `babel>=2.16,<3` declared in `pyproject.toml:20` | `grep -n "babel" pyproject.toml` confirms the runtime dependency. |
| `BreakerResetProposal` | **Exists** at `src/alfred/state/proposal_payloads.py` | Consumed by `src/alfred/cli/supervisor.py:33` (import) and `src/alfred/cli/_state_git.py:54,283,292,1020,1026,1027`. The Slice-4 work is to populate the proposal payload's `operator_user_id` with the resolver's return value, not to change the payload schema. |
| `operator_sessions` table + `uq_operator_sessions_token_hash` unique index | **Not yet present — lands in PR-S4-0b migration 0011** | Per slice-index §3 + spec §12.1. This PR's resolver query uses this index; the integration test depends on the migration being applied. |
| `Supervisor.reset_breaker(...)` | **Exists** | `grep -n "reset_breaker" src/alfred/supervisor/core.py` (Slice-3-shipped per PR-S3-3b). No signature change in this PR. |
| `User` SQLAlchemy model + `UserId` type alias | **Exists** at `src/alfred/identity/models.py:57` (`class User(Base)`) | `UserId` is the canonical `str`-aliased identifier. |

Any task that depends on a row marked "Not yet present" must `assert` the predecessor PR has merged before opening this PR. The §6 task list's first task is to re-run this verification grep — drift between this plan and `main` is a planning-bug, not a code-bug, and is caught only by re-running grep at task-start.

---

## §5 OperatorSession model + file format

### §5.1 `OperatorSession` Pydantic v2 model (spec §6.1)

```python
# src/alfred/identity/operator_session.py
from __future__ import annotations

import hashlib
import hmac
import socket
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from alfred.identity.models import UserId


_TOKEN_BYTES: Final = 32  # 32 random bytes; base64url-encoded → ~43 chars
_HASH_LEN: Final = 64     # full HMAC-SHA256 hex output (256 bits) — no truncation; matches the algorithm's natural output width and the 256-bit pepper/token entropy

_DEFAULT_EXPIRES_IN: Final = timedelta(hours=12)
_MIN_EXPIRES_IN: Final = timedelta(hours=1)
_MAX_EXPIRES_IN: Final = timedelta(days=7)


class OperatorSession(BaseModel):
    """Persisted operator-session record.

    The token field is the verbatim base64url token generated at login.
    The session-file's mode (0600) is the host-side defence for the token;
    the daemon-side defence is the matching `token_hash` row in
    `operator_sessions` (PG) on the `uq_operator_sessions_token_hash` unique
    index.

    `machine_id_hash` is HMAC-SHA256(audit.hash_pepper, raw_machine_id),
    full HMAC-SHA256 hex output (64 chars / 256 bits). The raw machine-id is NEVER serialised.
    """

    schema_version: Literal[1]
    user_id: UserId
    token: SecretStr
    issued_at: datetime
    expires_at: datetime
    host: str
    machine_id_hash: str = Field(min_length=_HASH_LEN, max_length=_HASH_LEN)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def _expiry_after_issue(self) -> "OperatorSession":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be strictly after issued_at")
        return self
```

Tests pin:

- `schema_version` is `Literal[1]` — any other int refuses at validation.
- `token` is `SecretStr` — `str(session.token)` returns `"**********"`, not the raw value.
- `frozen=True` — any attribute set after construction raises `ValidationError`.
- `extra="forbid"` — an extra field in the JSON refuses (defence against malicious session-file injection).
- `expires_at > issued_at` — the model validator refuses.

### §5.2 Session-file format + TOCTOU-safe load (spec §6.2)

The file lives at `~/.config/alfred/session`. Format is `OperatorSession.model_dump_json()` (Pydantic v2 serialisation). Mode is `0o600`; ownership matches `os.getuid()` + `os.getgid()`. The load discipline (sec-006 closure):

```python
def load_session_file(path: Path) -> OperatorSession:
    """TOCTOU-safe session-file load.

    1. open(path, O_RDONLY | O_NOFOLLOW) — refuse symlinks at open time.
    2. fstat(fd) — validate mode 0600 + uid + gid on the OPEN FD,
       not via os.stat(path). This closes the stat-then-open window
       where an attacker swaps the file between the two syscalls.
    3. Only after fstat validation passes do we read the file contents.

    Raises:
        OperatorSessionMissing — file does not exist.
        OperatorSessionBadFileMode — st_mode lower 9 bits != 0o600.
        OperatorSessionBadFileOwner — st_uid or st_gid mismatch.
    """
    import os
    import json

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError as exc:
        raise OperatorSessionMissing(path=path) from exc
    except OSError as exc:
        # O_NOFOLLOW on a symlink raises ELOOP (errno 62 on Linux, 92 on macOS).
        # Either is "refuse the symlinked path" — surface as bad-file-mode so the
        # audit reason maps cleanly.
        raise OperatorSessionBadFileMode(
            path=path, reason=f"open_refused: {exc.errno}",
        ) from exc

    try:
        stat = os.fstat(fd)
        if (stat.st_mode & 0o777) != 0o600:
            raise OperatorSessionBadFileMode(
                path=path, mode=stat.st_mode & 0o777,
            )
        if stat.st_uid != os.getuid() or stat.st_gid != os.getgid():
            raise OperatorSessionBadFileOwner(
                path=path, st_uid=stat.st_uid, st_gid=stat.st_gid,
            )
        # Only now do we read.
        with os.fdopen(fd, "r", encoding="utf-8") as fp:
            raw = fp.read()
            fd = -1  # ownership transferred to fdopen
    finally:
        if fd != -1:
            os.close(fd)

    try:
        return OperatorSession.model_validate_json(raw)
    except Exception as exc:
        raise OperatorSessionMalformed(path=path) from exc
```

Tests pin (sec-006 closure):

- Symlink to attacker-owned content refuses at open time.
- File mode `0o644` refuses with `OperatorSessionBadFileMode`.
- File uid != caller's uid refuses with `OperatorSessionBadFileOwner`.
- Happy path returns the parsed `OperatorSession`.

**Notes on the stat-then-open anti-pattern.** The Slice-4 round-2 draft used `os.stat(path)` then `path.open()`. Between the two syscalls an attacker with control of the parent directory can swap the file. The open-then-fstat pattern eliminates the window because `fstat(fd)` reads kernel-side state of the already-open FD; swapping the file after `open` is irrelevant because the FD points to the original inode.

### §5.3 Per-OS machine-id sources (spec §6.5)

The machine-id is **system-owned** on every OS; the session file stores only the HMAC. Per-OS providers:

```python
@runtime_checkable
class MachineIdProvider(Protocol):
    async def read_raw(self) -> bytes:
        """Read the raw, system-owned machine-id bytes.

        Raises OperatorSessionNoMachineId on any read failure.
        """
        ...


class LinuxMachineIdProvider:
    """/etc/machine-id then /var/lib/dbus/machine-id fallback."""

    _PRIMARY: ClassVar[Path] = Path("/etc/machine-id")
    _FALLBACK: ClassVar[Path] = Path("/var/lib/dbus/machine-id")

    async def read_raw(self) -> bytes:
        for path in (self._PRIMARY, self._FALLBACK):
            try:
                return path.read_bytes().strip()
            except OSError:
                continue
        raise OperatorSessionNoMachineId(host_os="linux")


class MacosMachineIdProvider:
    """ioreg IOPlatformUUID, cached at /var/db/alfred/machine-id."""

    _CACHE: ClassVar[Path] = Path("/var/db/alfred/machine-id")

    async def read_raw(self) -> bytes:
        try:
            return self._CACHE.read_bytes().strip()
        except OSError:
            pass
        # First-read: query ioreg via subprocess (host-trusted; the spawn is
        # gated by Settings.environment == "development" so production must
        # have the cache prepopulated by the install step).
        from asyncio import create_subprocess_exec, subprocess as sp
        proc = await create_subprocess_exec(
            "ioreg", "-rd1", "-c", "IOPlatformExpertDevice",
            stdout=sp.PIPE, stderr=sp.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            raise OperatorSessionNoMachineId(host_os="macos")
        for line in stdout.splitlines():
            if b"IOPlatformUUID" in line:
                # line is like: '"IOPlatformUUID" = "ABCDEF-..."'
                _, _, val = line.partition(b"=")
                uuid = val.strip().strip(b'"').strip()
                self._CACHE.parent.mkdir(parents=True, exist_ok=True)
                self._CACHE.write_bytes(uuid)
                return uuid
        raise OperatorSessionNoMachineId(host_os="macos")


class WindowsMachineIdProvider:
    """HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid."""

    async def read_raw(self) -> bytes:
        # Lazy-import winreg so the module loads on Linux/macOS CI runners.
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError as exc:
            raise OperatorSessionNoMachineId(host_os="windows") from exc

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                return guid.encode("utf-8")
        except OSError as exc:
            raise OperatorSessionNoMachineId(host_os="windows") from exc


def machine_id_provider() -> MachineIdProvider:
    """Select the host-OS provider."""
    if sys.platform == "linux":
        return LinuxMachineIdProvider()
    if sys.platform == "darwin":
        return MacosMachineIdProvider()
    if sys.platform == "win32":
        return WindowsMachineIdProvider()
    raise OperatorSessionNoMachineId(host_os=sys.platform)


async def compute_machine_id_hash(
    *,
    provider: MachineIdProvider,
    audit_hash_pepper: bytes,
) -> str:
    """HMAC-SHA256(pepper, raw_machine_id), 64-char hex output (256 bits, no truncation).

    The pepper comes from secret_broker.get("audit.hash_pepper").encode("utf-8").
    Rotating the pepper invalidates cross-row correlation (documented trade-off
    per spec §8.10).
    """
    raw = await provider.read_raw()
    return hmac.new(
        key=audit_hash_pepper,
        msg=raw,
        digestmod=hashlib.sha256,
    ).hexdigest()
```

Tests (sec-006 closure):

- Linux: primary readable → returns its bytes. Primary missing, fallback readable → returns fallback. Both missing → `OperatorSessionNoMachineId(host_os="linux")`.
- macOS: cache hit → returns cached bytes. Cache miss → spawns `ioreg`; parses; writes cache; returns. `ioreg` exits non-zero → raises.
- Windows: registry read succeeds → returns. Registry missing → raises.
- HMAC: known pepper + known raw input → known output digest (deterministic).

### §5.4 Token hash storage

The token is **not** stored in the DB verbatim. The `operator_sessions.token_hash` column holds `hmac.new(pepper, token.encode(), sha256).hexdigest()`. The resolver computes the hash from the session-file's token and looks up `WHERE token_hash = :h AND revoked_at IS NULL`. Tests:

- Token + pepper → hash → DB lookup hits one row.
- Rotated pepper invalidates lookups (deliberately — operators re-login after a pepper rotation, documented per spec §8.10).
- Two distinct tokens produce two distinct hashes (no collisions in the 256-bit hash space within any plausible operator deployment).

---

## §6 Tasks

The tasks are sequenced so that the AST guard (Task 4) lands BEFORE any production callsite is migrated — the guard catches consumer-missing-resolver bugs the moment they appear, and the tasks that migrate `supervisor.py` / `config.py` / `plugin.py` (Tasks 19-21) run with the guard already green.

### Component A: Verification + foundations

---

- [ ] **Task 1 — Re-run the fabricated-surfaces verification gate.**

  **Files:** None (verification only).

  Run, from the repo root, exactly the commands listed in §4's verification table:

  ```bash
  grep -n "def get\b" src/alfred/security/secrets.py
  grep -n "operator_user_id" src/alfred/cli/supervisor.py
  grep -n "babel" pyproject.toml
  grep -rn "BreakerResetProposal" src/alfred/
  grep -n "^@user_app.command" src/alfred/identity/cli.py
  ls src/alfred/cli/supervisor.py src/alfred/cli/main.py
  ```

  Expected:
  - `SecretBroker.get` at line 396.
  - `_resolve_operator_user_id` callsites at lines 161 and 541 (the Slice-3 fallback we are replacing).
  - `babel>=2.16,<3` at line 20 of pyproject.toml.
  - `BreakerResetProposal` referenced in `src/alfred/cli/supervisor.py:33` and `src/alfred/cli/_state_git.py`.
  - User CLI commands `add`, `list`, `show`, `remove`, `bind`, `unbind`, `set` registered on `user_app`.

  If any of these grep results have shifted, halt and reconcile the plan with `main` before touching code. This step exists because the Slice-3 round-4 review surfaced multiple fabricated surfaces (e.g. `_read_loop`) that snuck through prior plans — re-grep before every implementation session.

  No commit.

---

- [ ] **Task 2 — Write failing tests for `OperatorSession` model.**

  **Files:** Test: `tests/unit/identity/test_operator_session_model.py` (new)

  Cover:
  - `schema_version=1` happy path; `schema_version=2` refused.
  - `token: SecretStr` — `str(session.token)` returns the redacted form; `session.token.get_secret_value()` returns the raw.
  - `frozen=True` — setting any field after construction raises.
  - `extra="forbid"` — unknown field refuses.
  - `expires_at <= issued_at` refuses with the model-validator message.
  - `machine_id_hash` length validator rejects 31-char and 33-char inputs.

  Run: `uv run pytest tests/unit/identity/test_operator_session_model.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.identity.operator_session'`.

---

- [ ] **Task 3 — Implement `OperatorSession` + exception hierarchy.**

  **Files:** Create `src/alfred/identity/operator_session.py` (model section only; rest of module follows in later tasks).

  Implement:
  - `OperatorSession` per §5.1.
  - `OperatorSessionError(AlfredError)` root — every refusal raises a subclass.
  - Subclasses one-per-reason: `OperatorSessionMissing`, `OperatorSessionExpired`, `OperatorSessionRevoked`, `OperatorSessionHostMismatch`, `OperatorSessionMachineMismatch`, `OperatorSessionBadFileMode`, `OperatorSessionBadFileOwner`, `OperatorSessionTokenUnknown`, `OperatorSessionUserRevoked`, `OperatorSessionTimeout`, `OperatorSessionMalformed`, `OperatorSessionNoMachineId`.
  - Constants `_TOKEN_BYTES = 32`, `_HASH_LEN = 64`, `_DEFAULT_EXPIRES_IN = timedelta(hours=12)`, `_MIN_EXPIRES_IN = timedelta(hours=1)`, `_MAX_EXPIRES_IN = timedelta(days=7)`.

  Run: `uv run pytest tests/unit/identity/test_operator_session_model.py -q`
  Expected: `6 passed` (one per bullet above).

  Run: `make check`
  Expected: passes (mypy strict + ruff).

  Commit: `feat(identity): OperatorSession Pydantic model + exception hierarchy (#153)`

---

- [ ] **Task 4 — Write failing tests for the AST guard.**

  **Files:** Test: `tests/unit/cli/test_operator_resolver_consumed.py` (new)

  The guard walks every module under `src/alfred/cli/`, finds every `await self._audit.append_schema(constant, …)` callsite whose constant is in the closed set of operator-attributed constants, and asserts the enclosing function consumes `OperatorResolver` (via a parameter type-annotation matching `OperatorResolver` OR via an explicit import of `_resolve_operator`).

  Closed set (programmatically computed, not hardcoded — captures any future operator-attributed constant added in later PRs):

  ```python
  import ast
  import inspect
  from pathlib import Path

  from alfred.audit import audit_row_schemas

  def _operator_attributed_constants() -> set[str]:
      """Every Final[frozenset] constant whose field-set includes 'operator_user_id'."""
      out: set[str] = set()
      for name in dir(audit_row_schemas):
          val = getattr(audit_row_schemas, name)
          if isinstance(val, frozenset) and "operator_user_id" in val:
              out.add(name)
      return out
  ```

  The guard fails on any callsite where the consuming function does not pass the AST sniff. Negative test: a stub CLI module that emits an operator-attributed audit row without consuming `OperatorResolver` is detected (fixture lives under `tests/fixtures/cli_negative_guard/`).

  Run: `uv run pytest tests/unit/cli/test_operator_resolver_consumed.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.cli.operator_session'` (because the guard imports the live module to enumerate).

---

- [ ] **Task 5 — Implement the AST guard.**

  **Files:** `tests/unit/cli/test_operator_resolver_consumed.py` (the guard itself + the fixture module).

  The guard parses each `cli/*.py` with `ast.parse`, walks every `FunctionDef`/`AsyncFunctionDef`, and for every `await self._audit.append_schema(constant_name, ...)` call asserts the enclosing function's argument list or local imports reference `OperatorResolver` or `_resolve_operator`.

  Implementation pattern (high-level):

  ```python
  def _consumes_resolver(func: ast.AST) -> bool:
      """True iff the function's arg-annotations or local imports name the resolver."""
      ...

  def test_every_operator_attributed_callsite_consumes_resolver() -> None:
      bad: list[tuple[str, str, str]] = []
      for module_path in Path("src/alfred/cli").rglob("*.py"):
          tree = ast.parse(module_path.read_text())
          for func in ast.walk(tree):
              if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                  continue
              for call in ast.walk(func):
                  if not _is_audit_emit(call):
                      continue
                  const_name = _constant_name(call)
                  if const_name not in _operator_attributed_constants():
                      continue
                  if not _consumes_resolver(func):
                      bad.append((module_path.name, func.name, const_name))
      assert not bad, f"Resolver not consumed at: {bad}"
  ```

  The negative-fixture test plants an example bad CLI module under `tests/fixtures/cli_negative_guard/` and asserts the guard's helper functions catch it.

  Run: `uv run pytest tests/unit/cli/test_operator_resolver_consumed.py -q`
  Expected: `2 passed` (positive guard + negative-fixture).

  At this point the guard is green because no operator-attributed callsite in the live `cli/` package emits without the resolver — but several Slice-3 supervisor/config/plugin callsites DO. The guard catches them in Tasks 19-21; document this expected progression in the test docstring.

  **Important:** the guard MUST be added BEFORE the supervisor/config/plugin migrations so the migration tasks have a green-bar feedback loop. Sequencing matters.

  Commit: `test(cli): AST guard for OperatorResolver consumption (#153)`

---

### Component B: TOCTOU-safe file load + machine-id

---

- [ ] **Task 6 — Write failing tests for `load_session_file`.**

  **Files:** Test: `tests/unit/identity/test_operator_session_file_load.py` (new)

  Cover (sec-006 closure):
  - Happy path: file with mode `0o600`, owned by caller, valid JSON → returns `OperatorSession`.
  - Symlink at the path refuses with `OperatorSessionBadFileMode` (open-time, not stat-time).
  - File mode `0o644` refuses with `OperatorSessionBadFileMode`.
  - File owned by `uid != os.getuid()` refuses with `OperatorSessionBadFileOwner`.
  - File missing refuses with `OperatorSessionMissing`.
  - Malformed JSON refuses with `OperatorSessionMalformed`.
  - JSON with extra field refuses with `OperatorSessionMalformed` (via `extra="forbid"`).

  The tests use `os.chown` only where possible (Linux + macOS); the wrong-owner test is skipped on Windows since `os.getuid()` does not exist there. Mark the wrong-owner test `@pytest.mark.skipif(sys.platform == "win32", ...)`.

  Run: `uv run pytest tests/unit/identity/test_operator_session_file_load.py -q`
  Expected: `AttributeError: module 'alfred.identity.operator_session' has no attribute 'load_session_file'`.

---

- [ ] **Task 7 — Implement `load_session_file`.**

  **Files:** Append to `src/alfred/identity/operator_session.py`.

  Implement per §5.2 — `os.open(path, O_RDONLY | O_NOFOLLOW)` → `os.fstat(fd)` validating mode/uid/gid → `os.fdopen(fd, "r", encoding="utf-8")` → `OperatorSession.model_validate_json(raw)`. Wrap the read in `try/finally` to ensure the FD is closed on any path.

  Edge cases:
  - The `O_NOFOLLOW` constant is platform-specific; on Windows it is not defined. Implement a constants-shim:

    ```python
    _O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
    ```

    On Windows the open-time symlink refusal is not enforced; Windows operators are directed at the WSL2 path per PR-S4-10 (devex). Tests document this gap.
  - The fstat-mode check uses `(stat.st_mode & 0o777) != 0o600` so the file type bits do not matter (regular file vs FIFO etc. — though FIFOs would have failed `O_RDONLY` open already).

  Run: `uv run pytest tests/unit/identity/test_operator_session_file_load.py -q`
  Expected: `6-7 passed` (one skipped on Windows).

  Run: `make check`
  Expected: passes.

  Commit: `feat(identity): TOCTOU-safe session-file load via open-then-fstat (#153, sec-006)`

---

- [ ] **Task 8 — Write failing tests for the per-OS machine-id providers.**

  **Files:** Test: `tests/unit/identity/test_operator_session_machine_id.py` (new)

  Cover:
  - `LinuxMachineIdProvider`: primary readable → returns its bytes; primary missing, fallback readable → returns fallback; both missing → `OperatorSessionNoMachineId(host_os="linux")`. Use a temp dir + `monkeypatch` on the class's `_PRIMARY` / `_FALLBACK` paths to avoid touching the real `/etc/machine-id`.
  - `MacosMachineIdProvider`: cache hit → returns cached bytes. Cache miss + mocked `ioreg` returning the canonical `IOPlatformUUID` line → parses + writes cache + returns. `ioreg` exits non-zero → raises. Patch `asyncio.create_subprocess_exec`.
  - `WindowsMachineIdProvider`: registry read mocked via a fake `winreg` module → returns the GUID. Registry missing → raises.
  - `compute_machine_id_hash`: HMAC-SHA256 with a known pepper + known raw → known 64-char hex digest (full 256-bit output).
  - `machine_id_provider()` returns the right concrete class per `sys.platform` (monkeypatched).

  Run: `uv run pytest tests/unit/identity/test_operator_session_machine_id.py -q`
  Expected: `0 passed; 6 errors` (or similar — module attributes missing).

---

- [ ] **Task 9 — Implement the per-OS machine-id providers.**

  **Files:** Append to `src/alfred/identity/operator_session.py`.

  Implement per §5.3 — the three concrete provider classes + the `machine_id_provider()` selector + `compute_machine_id_hash`.

  Notes:
  - The Linux provider's `read_raw()` reads from disk synchronously inside an `async def`. Reading a 32-byte file from `/etc/machine-id` is bounded-cost (no blocking risk); a `to_thread` wrapper is overkill. Document this trade-off in the docstring.
  - The macOS provider's `ioreg` spawn is async via `asyncio.create_subprocess_exec`. The spawn is gated by the cache check first; in production the cache is populated by the install step (PR-S4-7 macOS runbook entry).
  - The Windows provider lazy-imports `winreg` so the module loads on non-Windows CI runners.

  Run: `uv run pytest tests/unit/identity/test_operator_session_machine_id.py -q`
  Expected: `6 passed`.

  Run: `make check`
  Expected: passes.

  Commit: `feat(identity): per-OS machine-id providers + HMAC hash (#153, sec-006)`

---

### Component C: `_resolve_operator` host helper

---

- [ ] **Task 10 — Write failing tests for `OperatorResolver` Protocol.**

  **Files:** Test: `tests/unit/identity/test_resolve_operator.py` (new — covers both the Protocol + the concrete resolver in subsequent tasks)

  Cover:
  - `OperatorResolver` is a `Protocol` and runtime-checkable; a duck-typed stub that exposes `async def resolve(self, ctx: ResolverContext) -> UserId` passes `isinstance(obj, OperatorResolver)`.
  - The concrete resolver type is named (e.g., `DefaultOperatorResolver`) and instantiable with the deps enumerated in `__init__` (`session_factory`, `secret_broker`, `machine_id_provider`, `session_file_path`, `clock`).

  Run: `uv run pytest tests/unit/identity/test_resolve_operator.py -q`
  Expected: `ImportError`.

---

- [ ] **Task 11 — Implement `OperatorResolver` Protocol + `DefaultOperatorResolver` shell.**

  **Files:** Append to `src/alfred/identity/operator_session.py`.

  ```python
  from collections.abc import Awaitable
  from typing import Protocol, runtime_checkable


  @dataclass(frozen=True)
  class ResolverContext:
      """Context passed to OperatorResolver.resolve.

      The CLI command callback constructs this from typer's Context object
      plus the host bootstrap. Frozen so the resolver cannot mutate.
      """
      command_name: str
      now: datetime          # for testability
      host: str              # socket.gethostname()
      session_file_path: Path


  @runtime_checkable
  class OperatorResolver(Protocol):
      """Host-side resolver for the currently-logged-in operator's UserId."""

      async def resolve(self, ctx: ResolverContext) -> UserId: ...


  class DefaultOperatorResolver:
      """Concrete resolver wired by alfred/cli/_bootstrap.py.

      Reads the session file (TOCTOU-safe), hashes the token via the
      broker pepper, looks up operator_sessions.token_hash on the
      uq_operator_sessions_token_hash unique index, validates expiry +
      host + machine-id + user-revoked state.

      perf-001 budget breakdown (spec §6.4):
        - File open + fstat + read + JSON parse: ≤ 1ms (local SSD).
        - Postgres single-row index lookup: ≤ 2ms.
        - Audit-row write on success path: 0ms (success emits nothing;
          audit fires only on session-changed events).
        - Field validation + return: ≤ 1ms.
        Total p99: ≤ 5ms.

      Hard timeout: 250ms via asyncio.wait_for. Beyond that,
      OperatorSessionTimeout raises rather than hanging silently.
      """

      _HARD_TIMEOUT_S: ClassVar[float] = 0.250

      def __init__(
          self,
          *,
          session_factory: AsyncSessionFactory,
          secret_broker: SecretBroker,
          machine_id_provider: MachineIdProvider,
          audit_writer: AuditWriter,
      ) -> None:
          self._session_factory = session_factory
          self._secret_broker = secret_broker
          self._machine_id_provider = machine_id_provider
          self._audit = audit_writer

      async def resolve(self, ctx: ResolverContext) -> UserId:
          try:
              return await asyncio.wait_for(
                  self._resolve_inner(ctx),
                  timeout=self._HARD_TIMEOUT_S,
              )
          except asyncio.TimeoutError as exc:
              raise OperatorSessionTimeout(timeout_s=self._HARD_TIMEOUT_S) from exc

      async def _resolve_inner(self, ctx: ResolverContext) -> UserId:
          ...  # Task 13
  ```

  This task ships the Protocol, the dataclass, the resolver shell with `__init__`, and the `resolve` wrapper. `_resolve_inner` is a no-op `raise NotImplementedError` for now — Task 13 fills it.

  Run: `uv run pytest tests/unit/identity/test_resolve_operator.py -q`
  Expected: `2 passed` (Protocol + class instantiation).

  Run: `make check`
  Expected: passes.

  Commit: `feat(identity): OperatorResolver Protocol + DefaultOperatorResolver shell (#153)`

---

- [ ] **Task 12 — Write failing tests for `_resolve_inner` happy + refusal paths.**

  **Files:** Append to `tests/unit/identity/test_resolve_operator.py`.

  Cover (one test per row of the refusal table):

  | Refusal reason | Setup | Expected exception |
  |---|---|---|
  | happy path | valid file + DB row + matching host + matching machine-id-hash + expires_at > now | returns `UserId` |
  | `expired` | file present, expires_at < now | `OperatorSessionExpired` |
  | `host_mismatch` | file's host != ctx.host | `OperatorSessionHostMismatch` |
  | `machine_mismatch` | file's machine_id_hash != computed | `OperatorSessionMachineMismatch` |
  | `token_unknown` | file present, no matching DB row | `OperatorSessionTokenUnknown` |
  | `user_revoked` | DB row exists, but `User.is_active = False` | `OperatorSessionUserRevoked` |
  | `bad_file_mode` | file mode 0644 | `OperatorSessionBadFileMode` |
  | `bad_file_owner` | file uid != caller | `OperatorSessionBadFileOwner` |
  | timeout | DB query sleeps > 250ms | `OperatorSessionTimeout` |

  Use `sqlalchemy` in-memory testing or a Postgres testcontainer fixture for the DB row tests; for the timeout test, patch the resolver's `_query_session_row` to `await asyncio.sleep(0.5)`.

  Use a fake `SecretBroker` that returns a fixed `"test-pepper"` for `get("audit.hash_pepper")` so the HMAC is deterministic.

  Run: `uv run pytest tests/unit/identity/test_resolve_operator.py -q`
  Expected: 9 new tests failing with `NotImplementedError`.

---

- [ ] **Task 13 — Implement `_resolve_inner`.**

  **Files:** Append to `src/alfred/identity/operator_session.py`.

  ```python
      async def _resolve_inner(self, ctx: ResolverContext) -> UserId:
          # 1. Load session file (TOCTOU-safe). May raise
          # OperatorSessionMissing / BadFileMode / BadFileOwner / Malformed.
          session = load_session_file(ctx.session_file_path)

          # 2. Compare expires_at; on miss emit refused row + raise.
          if session.expires_at < ctx.now:
              await self._emit_refused(session, reason="expired", ctx=ctx)
              raise OperatorSessionExpired(user_id=session.user_id)

          # 3. Compare host.
          if session.host != ctx.host:
              await self._emit_refused(session, reason="host_mismatch", ctx=ctx)
              raise OperatorSessionHostMismatch(
                  expected=session.host, actual=ctx.host,
              )

          # 4. Compare machine_id_hash.
          pepper = self._secret_broker.get("audit.hash_pepper").encode("utf-8")
          live_hash = await compute_machine_id_hash(
              provider=self._machine_id_provider,
              audit_hash_pepper=pepper,
          )
          if session.machine_id_hash != live_hash:
              await self._emit_refused(session, reason="machine_mismatch", ctx=ctx)
              raise OperatorSessionMachineMismatch()

          # 5. DB lookup by token_hash on the unique index.
          raw_token = session.token.get_secret_value()
          token_hash = hmac.new(
              key=pepper, msg=raw_token.encode("utf-8"), digestmod=hashlib.sha256,
          ).hexdigest()
          async with self._session_factory() as db:
              row = await db.execute(
                  select(OperatorSessionRow).where(
                      OperatorSessionRow.token_hash == token_hash,
                      OperatorSessionRow.revoked_at.is_(None),
                  ),
              )
              row = row.scalar_one_or_none()
              if row is None:
                  await self._emit_refused(session, reason="token_unknown", ctx=ctx)
                  raise OperatorSessionTokenUnknown()
              if not await self._user_is_active(db, row.user_id):
                  await self._emit_refused(session, reason="user_revoked", ctx=ctx)
                  raise OperatorSessionUserRevoked(user_id=row.user_id)

          return UserId(row.user_id)
  ```

  Notes:
  - The DB query MUST use the unique index. The Slice-3 SQLAlchemy convention is to express the `select(...).where(...)` and trust the unique index in the schema; `EXPLAIN ANALYZE` in PR-S4-0b verifies the index is hit.
  - `_emit_refused` is a thin helper that appends `OPERATOR_SESSION_REFUSED_FIELDS` carrying the matching `reason` Literal + the `attempted_user_id` (from the file's `user_id`, even when the file's data is suspect — the audit value is operator-visibility, not source-of-truth).
  - The refused-emit path uses `await self._audit.append_schema(OPERATOR_SESSION_REFUSED_FIELDS, ...)` — never an inline field literal.
  - The dispatcher does NOT cache. Every CLI command call hits Postgres; the budget (≤5ms p99) absorbs this. The Slice-3 PR description for #153 documented this trade-off.

  Run: `uv run pytest tests/unit/identity/test_resolve_operator.py -q`
  Expected: `9 passed`.

  Run: `make check`
  Expected: passes.

  Commit: `feat(identity): _resolve_operator host helper with 5ms p99 + 250ms timeout (#153, perf-001, err-008)`

---

### Component D: CLI surface — `login` / `logout` / `whoami`

---

- [ ] **Task 14 — Write failing tests for `alfred login`.**

  **Files:** Test: `tests/unit/cli/test_login_command.py` (new)

  Cover:
  - `alfred login --as alice` happy path: writes the session file with mode `0o600`; the DB `operator_sessions` row appears; the audit log carries `OPERATOR_SESSION_CREATED_FIELDS` with `via="login"`.
  - `alfred login --as no-such-user` refuses with `t("login.user_not_found")` on stderr + suggests `t("login.user_not_found_action_alfred_user_list")`.
  - Existing session present + `--as bob` (different user): prompts with `t("login.session_overwrite_confirm")`; answer no → exits non-zero, original session preserved; answer yes → overwrites.
  - `alfred login --expires-in 30m` refuses with `t("login.expires_in_out_of_range")` (below 1h floor).
  - `alfred login --expires-in 8d` refuses with `t("login.expires_in_out_of_range")` (above 7d ceiling).
  - `alfred login --refresh` happy path: rotates the token (new urandom), resets `expires_at`, emits `OPERATOR_SESSION_CREATED_FIELDS` with `via="refresh"`. Requires a non-expired session present.
  - Bare `alfred login` with no `--as`: runs `alfred user list` inline + prompts the operator to pick by number; then re-runs as `alfred login --as <chosen>` (devex-002).
  - The session file's mode after write is exactly `0o600` (asserted via `os.stat(...).st_mode & 0o777 == 0o600`).
  - The machine-id-hash unreadable case (Linux: both `/etc/machine-id` and `/var/lib/dbus/machine-id` missing) refuses with `t("login.no_machine_id")`.

  Run: `uv run pytest tests/unit/cli/test_login_command.py -q`
  Expected: 9 tests failing with `ModuleNotFoundError`.

---

- [ ] **Task 15 — Implement `alfred login`.**

  **Files:** Create `src/alfred/cli/operator_session.py`. Modify `src/alfred/cli/main.py` to register the commands.

  ```python
  # src/alfred/cli/operator_session.py
  """alfred login / logout / whoami — operator-session CLI surface.

  Closes #153. Spec §6.3 carries the UX contract; this module is the
  production implementation. All operator-facing strings route through
  t() per CLAUDE.md i18n rule #1.
  """
  from __future__ import annotations

  import asyncio
  import json
  import os
  import secrets
  import socket
  import sys
  from datetime import UTC, datetime, timedelta
  from pathlib import Path
  from typing import Annotated, Optional

  import typer
  from babel.dates import format_datetime
  from pydantic import SecretStr

  from alfred.audit.audit_row_schemas import (
      OPERATOR_SESSION_CREATED_FIELDS,
      OPERATOR_SESSION_REVOKED_FIELDS,
  )
  from alfred.cli._bootstrap import (
      build_audit_writer,
      build_secret_broker,
      build_session_factory,
  )
  from alfred.i18n import t
  from alfred.identity.operator_session import (
      OperatorSession,
      OperatorSessionError,
      OperatorSessionMissing,
      compute_machine_id_hash,
      load_session_file,
      machine_id_provider,
  )

  _SESSION_FILE: Final = Path.home() / ".config" / "alfred" / "session"


  def login(
      as_user: Annotated[Optional[str], typer.Option("--as", help=...)] = None,
      expires_in: Annotated[Optional[str], typer.Option("--expires-in", help=...)] = None,
      refresh: Annotated[bool, typer.Option("--refresh", help=...)] = False,
  ) -> None:
      """Create or refresh the operator session."""
      asyncio.run(_login_impl(as_user=as_user, expires_in=expires_in, refresh=refresh))


  async def _login_impl(*, as_user, expires_in, refresh) -> None:
      ...
  ```

  The `_login_impl` body implements:

  1. **Bare-login discoverability** (devex-002): if `as_user is None and not refresh`, list users via the helper `list_users_for_picker` (Task 18 result), print a numbered list, prompt for a number, set `as_user` to the chosen slug, fall through to the normal flow.
  2. **`--refresh`**: load the existing session via `load_session_file`; if `OperatorSessionMissing`, refuse with `t("login.refresh_no_session")`; otherwise rotate the token + reset `expires_at` (within the clamp), write new file + DB row, emit `OPERATOR_SESSION_CREATED_FIELDS` with `via="refresh"`.
  3. **User-existence check**: call `alfred user show <as_user>` programmatically (use the existing `alfred.identity.cli.show` or a lightweight DB read); if not found, refuse with `t("login.user_not_found")` + the action suggestion.
  4. **Overwrite confirmation**: if a session file exists for a different user, prompt with `t("login.session_overwrite_confirm")` (`typer.confirm`); on refuse, exit non-zero.
  5. **`--expires-in` clamp**: parse the duration (`1h`, `24h`, `7d`); if outside `[1h, 7d]`, refuse with `t("login.expires_in_out_of_range")`.
  6. **Machine-id read**: call `compute_machine_id_hash(provider=machine_id_provider(), pepper=secret_broker.get("audit.hash_pepper").encode())`; on `OperatorSessionNoMachineId`, refuse with `t("login.no_machine_id")`.
  7. **Token generation**: `token_raw = secrets.token_urlsafe(_TOKEN_BYTES)`. `token_hash = HMAC(pepper, token_raw)` (full 64-char hex, no truncation).
  8. **DB row insert** into `operator_sessions`.
  9. **Session-file write** via a `0o600`-mode temp file + atomic rename. Use `os.umask(0o077)` around the write to make the temp file mode 0600 from the start (do not rely on `os.chmod` after-the-fact which is TOCTOU).
  10. **Audit emit**: `OPERATOR_SESSION_CREATED_FIELDS` with `via="login"` (or `"refresh"` for the refresh path).
  11. **Success message**: `t("login.confirmed", user_id=..., expires_at=...)`.

  Register in `cli/main.py`:

  ```python
  from alfred.cli.operator_session import login, logout, whoami
  app.command()(login)
  app.command()(logout)
  app.command()(whoami)
  ```

  These are top-level verbs; no sub-app. Lazy-import via `cli/main.py:_lazy_login()` pattern so `alfred --help` does not pay the import cost — follow the PR-S3-6 §8.5 pattern.

  Run: `uv run pytest tests/unit/cli/test_login_command.py -q`
  Expected: `9 passed`.

  Run: `make check`
  Expected: passes.

  Commit: `feat(cli): alfred login (with bare discoverability + refresh) (#153, devex-002)`

---

- [ ] **Task 16 — Write failing tests for `alfred logout`.**

  **Files:** Test: `tests/unit/cli/test_logout_command.py` (new)

  Cover:
  - `alfred logout` happy path: file exists, DB row exists → file removed, DB row's `revoked_at` set, audit emits `OPERATOR_SESSION_REVOKED_FIELDS` with `via="logout"`.
  - `alfred logout` with no session file: refuses with `t("logout.no_session")` + non-zero exit.
  - `alfred logout` with bad file mode: refuses with the matching `OperatorSessionError`, still removes the bad file (defensive cleanup).
  - Post-logout, the file is absent (`not _SESSION_FILE.exists()`).
  - The DB row is **revoked, not deleted** (history preserved). `revoked_at` is set; `expires_at` unchanged.

  Run: `uv run pytest tests/unit/cli/test_logout_command.py -q`
  Expected: 5 failing tests.

---

- [ ] **Task 17 — Implement `alfred logout`.**

  **Files:** Append to `src/alfred/cli/operator_session.py`.

  ```python
  def logout() -> None:
      """Revoke and delete the current operator session."""
      asyncio.run(_logout_impl())


  async def _logout_impl() -> None:
      try:
          session = load_session_file(_SESSION_FILE)
      except OperatorSessionMissing:
          typer.echo(t("logout.no_session"), err=True)
          raise typer.Exit(code=1)
      except OperatorSessionError as exc:
          # Bad mode / bad owner / malformed: defensively remove the file
          # so the next login is unblocked. Audit the cleanup.
          await audit.append_schema(
              OPERATOR_SESSION_REVOKED_FIELDS,
              user_id="unknown",
              revoked_at=datetime.now(UTC),
              via="bad_file_cleanup",
          )
          _SESSION_FILE.unlink(missing_ok=True)
          typer.echo(t("logout.no_session"), err=True)
          raise typer.Exit(code=1) from exc

      # DB: set revoked_at on the matching token_hash row.
      ...
      _SESSION_FILE.unlink(missing_ok=True)
      await audit.append_schema(
          OPERATOR_SESSION_REVOKED_FIELDS,
          user_id=session.user_id,
          revoked_at=datetime.now(UTC),
          via="logout",
      )
      typer.echo(t("logout.confirmed", user_id=session.user_id))
  ```

  Run: `uv run pytest tests/unit/cli/test_logout_command.py -q`
  Expected: `5 passed`.

  Commit: `feat(cli): alfred logout (#153)`

---

- [ ] **Task 18 — Write failing tests for `alfred whoami`.**

  **Files:** Test: `tests/unit/cli/test_whoami_command.py` (new)

  Cover:
  - Happy path: session present + non-expired → prints `user_id`, locale-formatted `expires_at`, `host`, `machine_id_hash` (truncated for display).
  - No session: exits non-zero with `t("whoami.no_session")`.
  - Expired session: exits non-zero with `t("whoami.expired")`.
  - Locale formatting (i18n-003): for a user with `language="en"` the timestamp matches Babel's English short-form; for `language="ja"` the timestamp matches Babel's Japanese form. Use Babel's `format_datetime(dt, locale=...)` directly in the assertion for parity.
  - The output does NOT print the raw token (must remain in `SecretStr`-redacted form).

  Run: `uv run pytest tests/unit/cli/test_whoami_command.py -q`
  Expected: 5 failing tests.

---

- [ ] **Task 19 — Implement `alfred whoami` + `list_users_for_picker`.**

  **Files:**
  - Append `whoami` to `src/alfred/cli/operator_session.py`.
  - Append `list_users_for_picker` to `src/alfred/identity/cli.py`.

  ```python
  def whoami() -> None:
      """Print the currently-bound operator."""
      asyncio.run(_whoami_impl())


  async def _whoami_impl() -> None:
      try:
          session = load_session_file(_SESSION_FILE)
      except OperatorSessionMissing:
          typer.echo(t("whoami.no_session"), err=True)
          raise typer.Exit(code=1)
      now = datetime.now(UTC)
      if session.expires_at < now:
          typer.echo(t("whoami.expired"), err=True)
          raise typer.Exit(code=1)
      # Look up the User to get language.
      user_lang = await _lookup_user_language(session.user_id)
      formatted_expires = format_datetime(
          session.expires_at, locale=user_lang,
      )
      formatted_issued = format_datetime(
          session.issued_at, locale=user_lang,
      )
      typer.echo(t(
          "whoami.template",
          user_id=session.user_id,
          issued_at=formatted_issued,
          expires_at=formatted_expires,
          host=session.host,
          machine_id_hash=session.machine_id_hash[:8] + "...",
      ))
  ```

  `list_users_for_picker` is a thin SQLAlchemy `select(User.slug).order_by(User.created_at)` wrapper — used by the bare-login flow (Task 15) and reusable for future picker UX. Cover it with a small unit test in `tests/unit/identity/test_list_users_for_picker.py`.

  Run: `uv run pytest tests/unit/cli/test_whoami_command.py -q`
  Expected: `5 passed`.

  Run: `make check`
  Expected: passes.

  Commit: `feat(cli): alfred whoami + list_users_for_picker (#153, i18n-003)`

---

### Component E: Hookpoint registrations + audit-row emit

---

- [ ] **Task 20 — Write failing tests for hookpoint registration.**

  **Files:** Test: `tests/unit/hooks/test_operator_session_hookpoints.py` (new)

  Cover:
  - `operator.session.created` is registered with `subscribable_tiers=SYSTEM_ONLY_TIERS`, `fail_closed=True`, `carrier_tier="T1"`.
  - `operator.session.revoked` ditto.
  - `operator.session.refused` ditto.
  - Each registration passes the AST guard from PR-S4-3 (`tests/unit/hooks/test_carrier_tier_required.py`) — the test asserts no `register_hookpoint(...)` callsite in `src/alfred/identity/operator_session.py` omits `carrier_tier=`.

  Run: `uv run pytest tests/unit/hooks/test_operator_session_hookpoints.py -q`
  Expected: 4 failing tests.

---

- [ ] **Task 21 — Register the three hookpoints + wire the emit sites.**

  **Files:**
  - Append `register_hookpoint(...)` calls to `src/alfred/identity/operator_session.py` at module-import time (`SYSTEM_ONLY_TIERS` + `fail_closed=True` + `carrier_tier="T1"` per spec §10).
  - Audit-emit sites:
    - `login` happy path → `await self._invoke_hooks("operator.session.created", ...)` after the `audit.append_schema(OPERATOR_SESSION_CREATED_FIELDS, ...)` write.
    - `logout` happy path → `await self._invoke_hooks("operator.session.revoked", ...)`.
    - `_emit_refused` (called from `_resolve_inner`) → `await self._invoke_hooks("operator.session.refused", ...)` after the audit write.

  The hookpoint invocation uses the Slice-2.5-shipped `alfred.hooks.invoke` API (verified at `src/alfred/hooks/invoke.py`). Subscribers are unlikely to exist at this layer in Slice 4; the hookpoints exist for future Slice-5+ consumers (step-up auth, session-cluster federation).

  Run: `uv run pytest tests/unit/hooks/test_operator_session_hookpoints.py -q`
  Expected: `4 passed`.

  Commit: `feat(hooks): register operator.session.{created,revoked,refused} (#153)`

---

### Component F: Migrate operator-attributed CLI commands

---

- [ ] **Task 22 — Write failing tests for `alfred supervisor reset` session attribution.**

  **Files:** Test: `tests/unit/cli/test_supervisor_reset_session_attribution.py` (new)

  Cover (i18n-001 + sec closure):
  - `alfred supervisor reset <component> --confirm` with no session: refuses with `t("supervisor.breaker.reset.refused.not_logged_in")` on stderr; emits `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS(reason="operator_session_missing")`; exits non-zero.
  - With a valid session: the `BreakerResetProposal` payload carries `operator_user_id = session.user_id` (not None, not `"unknown"`, not the OS account).
  - The structlog `supervisor.breaker.reset.attempted` event carries `operator_user_id` set to the same value.
  - The Slice-3 fallback `_resolve_operator_user_id()` is **deleted** — `grep -rn "_resolve_operator_user_id" src/alfred/cli/supervisor.py` returns no hits.
  - With an expired session: refuses with `t("operator_session.refused.expired")`; emits `OPERATOR_SESSION_REFUSED_FIELDS` AND `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS(reason="operator_session_expired")`.

  Run: `uv run pytest tests/unit/cli/test_supervisor_reset_session_attribution.py -q`
  Expected: 5 failing tests.

---

- [ ] **Task 23 — Migrate `alfred supervisor reset` to the session resolver.**

  **Files:** Modify `src/alfred/cli/supervisor.py`.

  Step-by-step:
  1. Delete `_resolve_operator_user_id` (lines 39-…). Any test importing it (e.g., `tests/unit/cli/test_supervisor_reset_confirm.py:139`) gets updated to use the new resolver via DI fixtures, NOT to import the deleted function. Mark that test file with a Task-23 follow-up — fix it inline.
  2. At each `operator_user_id=_resolve_operator_user_id()` callsite (lines 161 and 541), replace with `operator_user_id = await _resolve_operator(_make_resolver_ctx(...))`. Wrap each in a `try/except OperatorSessionError as exc: _refuse(reason=...)` block that emits `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` + the localised message.
  3. The `_refuse` helper maps `OperatorSessionMissing → "operator_session_missing"`, `OperatorSessionExpired → "operator_session_expired"`, `OperatorSessionTimeout → "operator_session_resolver_timeout"`, etc.
  4. Update `tests/unit/cli/test_supervisor_reset_confirm.py` (Slice-3-shipped) — its `_resolve_operator_user_id` tests are obsolete; replace with fixture-driven session-attributed tests. **Delete** the four `test_resolve_operator_user_id_*` functions; they become Slice-3 dead code.

  Verify post-migration:

  ```bash
  grep -rn "_resolve_operator_user_id" src/alfred/ tests/
  ```

  Expected: zero hits.

  Run: `uv run pytest tests/unit/cli/test_supervisor_reset_session_attribution.py tests/unit/cli/test_supervisor_reset_confirm.py -q`
  Expected: every test passes.

  Run: `make check`
  Expected: passes (the AST guard from Task 5 now passes for `supervisor.py`).

  Commit: `refactor(cli): supervisor reset uses session-backed operator attribution (#153, i18n-001)`

---

- [ ] **Task 24 — Migrate `alfred config quarantined-provider` to the session resolver.**

  **Files:** Modify `src/alfred/cli/config.py` (Slice-3-shipped; verified via `ls src/alfred/cli/config.py` per Task 1 — if absent, this task becomes a no-op with a comment in the PR description).

  - The `alfred config quarantined-provider` callback queues a state.git proposal payload. Today (Slice 3) the payload's `operator_user_id` field is unset. After this task, it carries the resolver's return value.
  - Refusal path on missing session: refuses with `t("config.quarantined_provider.refused.not_logged_in")` (i18n catalog key landed in PR-S4-0b). Emits `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS`-style refused row — verify the constant name in PR-S4-0a's audit-row table; if a dedicated `CONFIG_QUARANTINED_PROVIDER_REFUSED_FIELDS` is not in the §9 list, **the refusal piggy-backs on `OPERATOR_SESSION_REFUSED_FIELDS`** and the command exits non-zero. Document this choice in the PR description so reviewers can either confirm or escalate to PR-S4-0a for a new constant.

  Write the matching test under `tests/unit/cli/test_config_quarantined_provider_session_attribution.py`.

  Run: `uv run pytest tests/unit/cli/test_config_quarantined_provider_session_attribution.py -q`
  Expected: 2 passed.

  Commit: `refactor(cli): config quarantined-provider gains session attribution (#153)`

---

- [ ] **Task 25 — Migrate `alfred plugin grant` / `revoke` to the session resolver.**

  **Files:** Modify `src/alfred/cli/plugin.py`.

  Same shape as Task 24:
  - Both callbacks gain `await _resolve_operator(ctx)`; the proposal payload's `operator_user_id` field is set.
  - Refusal path uses `OPERATOR_SESSION_REFUSED_FIELDS` + the matching localised refusal.
  - Tests at `tests/unit/cli/test_plugin_grant_session_attribution.py` and `tests/unit/cli/test_plugin_revoke_session_attribution.py`.

  Run: `uv run pytest tests/unit/cli/test_plugin_grant_session_attribution.py tests/unit/cli/test_plugin_revoke_session_attribution.py -q`
  Expected: passes.

  Commit: `refactor(cli): plugin grant/revoke gain session attribution (#153)`

---

- [ ] **Task 26 — Verify the AST guard sweeps clean across `cli/`.**

  **Files:** None (verification).

  Re-run the AST guard:

  ```bash
  uv run pytest tests/unit/cli/test_operator_resolver_consumed.py -q
  ```

  Expected: green. If any callsite emits an operator-attributed audit row without consuming `OperatorResolver`, the guard names it; add the resolver consumption.

  Audit-row constants whose field-set includes `operator_user_id` at this point in the Slice-4 timeline:

  | Constant | Defined in | Consumed by |
  |---|---|---|
  | `SUPERVISOR_BREAKER_RESET_FIELDS` | Slice-3 (PR-S3-0a) | `supervisor.py` ✓ (Task 23) |
  | `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` | PR-S4-0a | `supervisor.py` ✓ (Task 23) |
  | `PLUGIN_GRANT_FIELDS` (or whatever Slice-3 named it) | Slice-3 | `plugin.py` ✓ (Task 25) |
  | `WEB_ALLOWLIST_*` | Slice-3 | `web.py` (Slice-3 already consumes via `_resolve_operator_user_id`; this PR does NOT touch `web.py` because the slice-4 scope explicitly enumerates `supervisor reset`, `config quarantined-provider`, `plugin grant/revoke`. `web allowlist` is out of scope per spec §6.8's enumeration — document this in the PR description.) |

  If `web.py` shows up in the AST-guard failure list, escalate to the architect: spec §6.8 explicitly omits it, but the AST guard would flag the gap. Either the guard needs a one-off exemption (with a `# noqa` comment + a TODO referencing the next slice) OR scope creeps to include `web.py`. **Default**: exempt `web.py` via the guard's allowlist with a tracking issue.

  Commit: `chore(cli): AST guard green across operator-attributed callsites (#153)`

---

### Component G: Merge-blocking integration test

---

- [ ] **Task 27 — Write the merge-blocking lifecycle integration test.**

  **Files:** Create `tests/integration/test_operator_session_lifecycle.py`.

  Per spec §11.5, this test is merge-blocking for PR-S4-5 and promoted to required-status-check via `gh api` (ops-007 closure — promote in the PR that ships, not in PR-S4-11).

  Use `pytest-postgresql` or `testcontainers` for the Postgres testcontainer (Slice-3 convention).

  Cover:
  1. **Setup**: spin up Postgres + apply Alembic migrations through 0011 (`operator_sessions` table). Seed a `User` row (`alice`).
  2. **Login**: invoke `alfred login --as alice` (via the typer runner with the test's temp `HOME` and `XDG_CONFIG_HOME`). Assert:
     - `~/.config/alfred/session` exists with mode `0o600`.
     - The `operator_sessions` table has one row with `user_id=alice.id`, `revoked_at IS NULL`, the matching `token_hash`.
     - The `audit_log` has an `OPERATOR_SESSION_CREATED` row with `via="login"`.
     - The `operator.session.created` hookpoint fired (if a subscriber was registered for the test).
  3. **Use the session**: invoke `alfred supervisor reset some-component --confirm`. Assert the `BreakerResetProposal` payload's `operator_user_id` == `alice.id`. Assert the supervisor-side audit row carries the same.
  4. **whoami**: invoke `alfred whoami`. Assert stdout contains `alice.id` and the locale-formatted expiry timestamp.
  5. **Logout**: invoke `alfred logout`. Assert:
     - `~/.config/alfred/session` is gone.
     - The `operator_sessions` row has `revoked_at IS NOT NULL`.
     - The `audit_log` has an `OPERATOR_SESSION_REVOKED` row with `via="logout"`.
  6. **Post-logout supervisor reset**: invoke `alfred supervisor reset other-component --confirm`. Assert it refuses with `OPERATOR_SESSION_REFUSED_FIELDS(reason="operator_session_missing")`. Stderr matches `t("supervisor.breaker.reset.refused.not_logged_in")`.
  7. **Resolver-timeout simulation**: monkey-patch the resolver's DB query to sleep > 250ms. Assert `OperatorSessionTimeout` raises within the budget (use `time.monotonic()` to assert the elapsed wall-time stays under 300ms — 250ms timeout + ~50ms slack for asyncio scheduling).

  Run: `uv run pytest tests/integration/test_operator_session_lifecycle.py -q`
  Expected: passes locally and in CI.

  Commit: `test(integration): operator-session lifecycle merge-blocking test (#153, §11.5)`

---

- [ ] **Task 28 — Promote the integration test to a required-status check.**

  **Files:** None (workflow + `gh api` step).

  Follow the `author-gating-workflow` skill: open the PR with the workflow already gating on `test_operator_session_lifecycle`, merge, then promote via:

  ```bash
  gh api -X PATCH "repos/MrReasonable/AlfredOS/branches/main/protection/required_status_checks" \
    -f "contexts[]=test_operator_session_lifecycle"
  ```

  Update `required-checks.json` (or whatever tracked manifest exists per the slice-2.5 author-gating-workflow skill).

  Per ops-007 round-3 closure (slice-index §4), the gate is promoted in the **PR that ships it**, not bulked into PR-S4-11.

  Commit: `ci(required-checks): promote test_operator_session_lifecycle (#153)`

---

### Component H: i18n catalog wiring + docs

---

- [ ] **Task 29 — Verify every operator-facing string in this PR routes through `t()`.**

  **Files:** None (verification).

  Run `pybabel extract` and review the diff. Every new `_("...")` or inline English literal in `src/alfred/cli/operator_session.py`, `src/alfred/cli/supervisor.py` (Task 23 changes), and `src/alfred/identity/operator_session.py`-emitted error messages must produce a catalog entry that matches a key enumerated in PR-S4-0b. If `pybabel extract` finds any new strings without a matching catalog key, **the PR cannot ship until PR-S4-0b absorbs them** — coordinate with the PR-S4-0b author or open a fixup PR.

  Run: `uv run pybabel extract -F locale/babel.cfg -o locale/messages.pot src/`
  Then: `uv run pybabel update -i locale/messages.pot -d locale -l en -N`
  Expected: zero new strings beyond what PR-S4-0b already lists in spec §12.2.

---

- [ ] **Task 30 — Update `docs/glossary.md` with the new terms.**

  **Files:** Modify `docs/glossary.md`.

  Per spec §13.1 (PR-S4-0a ships the initial set; PR-S4-5 audits for any drift), this PR adds (if not already present):
  - `OperatorSession` — Pydantic v2 model + persistence layer.
  - `OperatorResolver` — DI Protocol for the host-side resolver.
  - `OperatorSessionTimeout` — exception raised by `_resolve_operator` when the 250ms hard timeout fires.

  If PR-S4-0a already shipped these (per its plan), this task is a verification that the entries cross-link to `src/alfred/identity/operator_session.py`. If absent, add them with a `(see PR-S4-5)` provenance note.

  Commit: `docs(glossary): operator session terms cross-link to source (#153)`

---

- [ ] **Task 31 — Re-run the full quality bar.**

  **Files:** None.

  Run, in order:

  ```bash
  uv run pytest tests/unit/ -q
  uv run pytest tests/integration/test_operator_session_lifecycle.py -q
  uv run pytest tests/adversarial/ -q          # operator_session_forgery corpus runs here
  make check                                    # ruff + format + mypy + pyright
  uv run pybabel compile --check -d locale -l en
  ```

  All must be green. The adversarial corpus's `operator_session_forgery` category (spec §11.4) lands as part of this PR via PR-S4-0a-shipped Literal `osf` prefix; corpus YAMLs go under `tests/adversarial/operator_session_forgery/`:

  - `osf-2026-001 forged_session_file` — attacker writes a syntactically-valid session file with a chosen user_id; resolver refuses with `token_unknown` (no matching DB row).
  - `osf-2026-002 replayed_session_from_other_host` — attacker copies a victim's session file to a different host; resolver refuses with `host_mismatch`.
  - `osf-2026-003 replayed_session_from_other_machine` — attacker swaps the host hostname but the machine-id-hash refuses with `machine_mismatch`.
  - `osf-2026-004 stat_then_open_toctou_race` — attacker swaps the file between stat and open; the open-then-fstat pattern is unaffected (no race window). The test asserts the load succeeds with the original content (the attacker swap is invisible at the FD level).
  - `osf-2026-005 symlink_to_attacker_owned_file` — operator's session path is replaced by a symlink to an attacker-controlled file; `O_NOFOLLOW` refuses at open.

  Each corpus entry's YAML follows the Slice-3 format: `id`, `title`, `category: operator_session_forgery`, `ingestion_path: operator_session_file`, `expected_outcome: session_refused` (or `boundary_refused` for the symlink case), `setup` (programmatic — sets up the bad file), `assertion` (the audit row + exception).

  Commit (if anything was tidied): `chore(quality): close out PR-S4-5 quality bar (#153)`

---

## §7 Verification + observability

### §7.1 Performance budget verification

Spec §6.4 mandates 5ms p99 + 250ms hard timeout. This PR adds two perf-relevant assertions:

1. **Unit-test budget assertion** (advisory). `tests/unit/identity/test_resolve_operator.py::test_resolve_under_p99_budget` runs the resolver 100 times against a real Postgres testcontainer with the unique index in place, sorts the wall-clock times, asserts `p99 < 0.005`. This is advisory in CI (it can flake on contended runners) but should hold consistently on a developer's laptop. The CI runner topology (per ops-002 in slice-index §4 — `ubuntu-latest` shared runner) introduces 1-2ms jitter; the test allows a 2x slack for CI (`p99 < 0.010`).
2. **Hard timeout assertion** (merge-blocking). `tests/integration/test_operator_session_lifecycle.py::test_resolver_timeout` (Task 27 step 7) patches the DB query to sleep 0.5s + asserts the resolver raises `OperatorSessionTimeout` within ~300ms wall-clock.

### §7.2 Audit-row observability

Every `OperatorSession*` exception path emits exactly one audit row. The integration test asserts the audit-log row-count delta per command — login adds 1 row; logout adds 1 row; refused-resolve adds 1 row per refusal reason.

### §7.3 Hookpoint observability

The three hookpoints are observable via the existing Slice-2.5 `alfred.hooks.invoke` framework. Future Slice-5+ consumers (step-up auth, federated-session sync) hang off these without further core changes.

### §7.4 Structlog event taxonomy

Add the following structlog events to `docs/superpowers/structlog-events.md` (Slice-3 convention — if the file does not exist, defer this to PR-S4-11's docs sweep):

- `operator.session.login.attempted` — bare login + `--as` cases; carries `user_id`, `via`, `expires_in_seconds`.
- `operator.session.login.completed` — happy path; carries `user_id`, `session_id` (hash), `expires_at`.
- `operator.session.login.refused` — reason Literal.
- `operator.session.logout.attempted` — start of logout.
- `operator.session.logout.completed` — happy path.
- `operator.session.resolve.attempted` — every `_resolve_operator` call; carries `command_name`.
- `operator.session.resolve.completed` — happy path; carries `user_id` + `elapsed_ms`.
- `operator.session.resolve.refused` — reason Literal + `elapsed_ms`.
- `operator.session.resolve.timeout` — hard-timeout path; carries `command_name` + `elapsed_ms`.

---

## §8 Risk + rollback

### §8.1 Risk: a regression in the resolver breaks every operator-attributed CLI command

**Mitigation:** the AST guard catches missing-resolver bugs at lint time. The integration test catches DB-shape regressions. The Slice-3 `_resolve_operator_user_id` fallback is deleted but its behaviour can be partially restored as a defensive last-resort by **NOT** doing so — the Slice-4 design explicitly refuses to log in as "unknown" because that's worse than refusing the command. CLAUDE.md hard rule 7 applies.

### §8.2 Risk: TOCTOU window between `os.stat` and `path.open`

**Mitigation:** open-then-fstat closes the window. The negative test in `test_operator_session_file_load.py` plants a swap between the stat and open syscalls (via a `threading.Thread` racing the load) and asserts the loaded contents match the original — i.e., the FD-level read sees the original inode regardless of post-open file-replacement.

### §8.3 Risk: machine-id binding too tight (laptop + dock changes hostname/MAC)

**Mitigation:** machine-id sources (Linux `/etc/machine-id`, macOS `IOPlatformUUID`, Windows `MachineGuid`) are explicitly **stable across boots + network reconfiguration**. The hostname (`socket.gethostname()`) can change on dock attach; this is checked alongside the machine-id, and a mismatch refuses. Operators who change hostnames re-login. Documented in the slice-graduation runbook (PR-S4-11) under troubleshooting.

### §8.4 Risk: per-OS provider unreadable in a sandboxed CI runner

**Mitigation:** the per-OS providers raise `OperatorSessionNoMachineId` cleanly; tests use mocked providers (see Task 8). The CI runner does not run the production `login` flow — it tests components via fixtures.

### §8.5 Rollback path

This PR's revert path is:

- Revert `src/alfred/identity/operator_session.py` (new — no upstream consumer).
- Revert `src/alfred/cli/operator_session.py` (new — no upstream consumer).
- Revert the `supervisor.py` / `config.py` / `plugin.py` changes (the Slice-3 `_resolve_operator_user_id` fallback comes back).
- The Alembic migration 0011 from PR-S4-0b is NOT reverted by this PR's revert (it stays applied; the table just goes unused).
- The audit-row constants from PR-S4-0a stay (unused).
- The hookpoints (`operator.session.*`) are deleted; future subscriber registrations would fail (none expected).

The revert leaves the system in a Slice-3 state with respect to operator attribution: `supervisor reset` falls back to env/getlogin/getpwuid. Acceptable interim until a forward-fix lands.

---

## §9 Out of scope — explicit defers

1. **Step-up auth** (PRD §7.1). Out-of-band Discord/Telegram DM confirmation for high-blast actions. The minimal CLI session-file login lands here; step-up auth is its own design and depends on the comms-MCP rewrite being in production (PR-S4-8 / PR-S4-9 / PR-S4-10). Slice 5+.
2. **`Settings.operator_session_default_expires_in_hours`** — site-wide configurable default for `--expires-in` (currently hardcoded 12h with `[1h, 7d]` clamp). Deferred per slice-index §8 (devex-006 round-3). Slice 5+.
3. **Expired-session cleanup tick** — a background task that revokes rows in `operator_sessions` whose `expires_at < now`. Slice 4 lets expired rows linger (the resolver refuses them on read; storage cost is bounded). A Slice-5 backlog item adds the cleanup tick.
4. **`alfred memory forget` / `alfred rollback`** — spec §6.8 lists these as "out of scope for Slice 4 if not shipped." They are not shipped in Slice 3; not in scope here.
5. **`alfred web allowlist` operator attribution** — spec §6.8 enumerates `supervisor reset`, `config quarantined-provider`, `plugin grant/revoke`. `web allowlist` is not enumerated. The AST guard exempts it via an allowlist comment with a follow-up issue (Task 26 closure).
6. **`SecretBroker.get_bytes(name) -> bytearray`** — the broker returns `str`; the pepper sits as an immutable Python `str` between fetch and HMAC use. Brief residency window; mitigation per spec §8.10 (Slice 5 backlog).
7. **Federated session across multiple AlfredOS hosts** — the session file is host-bound by design (host + machine-id). Cross-host sessions are out of scope; operators on multiple hosts log in to each.

---

## §10 Acceptance criteria

PR-S4-5 lands only when:

1. `make check` is green.
2. `uv run pytest tests/unit/ -q` is green.
3. `uv run pytest tests/adversarial/operator_session_forgery/ -q` is green (5 corpus entries — Task 31).
4. `tests/integration/test_operator_session_lifecycle.py` is green (Task 27).
5. The AST guard `tests/unit/cli/test_operator_resolver_consumed.py` is green across `src/alfred/cli/` (Task 26).
6. The `test_operator_session_lifecycle` required-status check is promoted (Task 28).
7. The `_resolve_operator_user_id` fallback function and every callsite are deleted (Task 23 grep verification).
8. The integration test runs the full login → operator-attributed command → logout cycle and asserts the audit-log row chain.
9. Coverage on `src/alfred/identity/operator_session.py` and `src/alfred/cli/operator_session.py` is 100% line + 100% branch (spec §14 criterion 11; merge-blocking trust-boundary files).
10. The PR description includes:
    - The closure callout for #153 with an explicit note that the Slice-3 `_resolve_operator_user_id()` env/getlogin/getpwuid fallback is being replaced (not the literal `operator_user_id=None` placeholders the round-1/2 spec wording implied — those were already hardened in Slice 3).
    - The cross-PR contract verification table from §4.
    - The integration test's required-status-check promotion command (`gh api -X PATCH ...`).
    - The `make check` + `uv run pytest tests/adversarial` output trail.

---

## §11 References

### Spec anchors

- [`docs/superpowers/specs/2026-06-06-slice-4-design.md#6-cli-operator-session-153-closure`](../specs/2026-06-06-slice-4-design.md#6-cli-operator-session-153-closure) — §6 in full.
- [`docs/superpowers/specs/2026-06-06-slice-4-design.md#9-audit-row-schemas-slice-4-additions`](../specs/2026-06-06-slice-4-design.md#9-audit-row-schemas-slice-4-additions) — `OPERATOR_SESSION_*` + `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` rows.
- [`docs/superpowers/specs/2026-06-06-slice-4-design.md#10-hookpoint-surface-slice-4-additions`](../specs/2026-06-06-slice-4-design.md#10-hookpoint-surface-slice-4-additions) — hookpoint table rows for `operator.session.*`.
- [`docs/superpowers/specs/2026-06-06-slice-4-design.md#11-adversarial-corpus-additions`](../specs/2026-06-06-slice-4-design.md#11-adversarial-corpus-additions) — `osf` prefix, `operator_session_forgery` category.
- [`docs/superpowers/specs/2026-06-06-slice-4-design.md#12-migrations--i18n-catalog`](../specs/2026-06-06-slice-4-design.md#12-migrations--i18n-catalog) — i18n key enumeration.
- [`docs/superpowers/specs/2026-06-06-slice-4-design.md#13-pr-breakdown--12-prs-summary`](../specs/2026-06-06-slice-4-design.md#13-pr-breakdown--12-prs-summary) — PR-S4-5 row.

### Slice index

- [`docs/superpowers/plans/2026-06-07-slice-4-index.md#3-cross-pr-contracts`](./2026-06-07-slice-4-index.md#3-cross-pr-contracts) — `OperatorSession` model + file-load contract row.
- [`docs/superpowers/plans/2026-06-07-slice-4-index.md#4-cross-fork-integration-test-gate`](./2026-06-07-slice-4-index.md#4-cross-fork-integration-test-gate) — `test_operator_session_lifecycle` ownership.

### Slice predecessor

- [`docs/superpowers/plans/2026-05-31-slice-3-pr-s3-6-cli-comms-mcp-stub.md`](./2026-05-31-slice-3-pr-s3-6-cli-comms-mcp-stub.md) — Slice-3 CLI surface precedent (StateGitProposalClient, async-UX pattern, i18n key wiring).

### Verified surfaces (re-runnable greps)

- `src/alfred/security/secrets.py:396` — `SecretBroker.get(name: str) -> str`.
- `src/alfred/cli/supervisor.py:39` — Slice-3 `_resolve_operator_user_id() -> str | None`.
- `src/alfred/cli/supervisor.py:161,541` — production callsites of the Slice-3 fallback.
- `src/alfred/cli/main.py:55,86` — `user_app` registration.
- `src/alfred/identity/cli.py:241,374,449,495,559,618,677` — `alfred user {add,list,show,remove,bind,unbind,set}`.
- `src/alfred/identity/models.py:57` — `class User(Base)`.
- `src/alfred/state/proposal_payloads.py` — `BreakerResetProposal`.
- `pyproject.toml:20` — `babel>=2.16,<3`.

### Closes

- [#153](https://github.com/MrReasonable/AlfredOS/issues/153) — `operator_user_id` flows through `alfred supervisor reset`. The closure replaces the Slice-3 env/getlogin/getpwuid fallback with the session-backed resolver and extends attribution to `config quarantined-provider` + `plugin grant/revoke`.

---
