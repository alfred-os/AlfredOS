# PR-S4-6: Sandbox Launcher — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is trust-boundary work — TDD is HARD here, not advisory. Every audit-row emit and every sandbox-refusal branch needs a failing test first.

**Goal:** Ship the policy-resolving extension of `bin/alfred-plugin-launcher.sh` (bash — sec-004 round-3 honest), the pre-launcher Python helper at `src/alfred/plugins/manifest_reader.py`, the mandatory `Settings.environment` field with dual-sourced precedence (env var > `/etc/alfred/environment`), the dev-escape-hatch refuse-in-production semantics with operator-visible stderr (devex-001), the `bwrap --keep-fd 3` provider-key fd-3 inheritance pattern (sec-004 round-4), the Supervisor-side `setrlimit(RLIMIT_CORE)` + best-effort `mlockall` posture, the quarantined-LLM plugin's `kind: none` → `kind: full` manifest migration with per-OS `policy_refs`, and the `supervisor.plugin.sandbox_refused` hookpoint. The launcher policy-resolving probe (consumed by PR-S4-1) flips from no-op stub to real behaviour in this PR.

**Architecture:** Spec §7 in full. The launcher stays bash. A pre-launcher Python one-shot (`python3 -m alfred.plugins.manifest_reader <plugin_id>`) reads the manifest's `sandbox` block and prints a stable JSON line the bash script consumes. The bash launcher then branches: `kind: full` → resolve the per-OS `policy_ref`, `exec bwrap --keep-fd 3 [policy flags] -- ${PLUGIN_BINARY}`; `kind: none` → existing UID-separated baseline (Slice-3); `kind: stub` → refuse in production, dev-only exec unsandboxed with `SANDBOX_STUB_USED_FIELDS`. The Supervisor (Python, host) fetches the quarantined provider key via `SecretBroker.get("quarantined.provider_key")`, opens a pipe whose read end is fd 3 of the launcher subprocess, writes the 4-byte big-endian length prefix + key bytes, closes the write end, then `gc.collect()`s. The bash launcher never reads fd 3 — `--keep-fd 3` makes the kernel inherit fd 3 into the bwrap-spawned plugin, and the plugin's existing Slice-3 `read_fd3_secret()` consumes the framed bytes. Honest limitation acknowledged: Supervisor holds the key in Python `str` (interned, non-zeroizable) for microseconds between broker fetch and fd-3 write; `gc.collect()` is mitigation, not elimination. Slice-5 `SecretBroker.get_bytes` will close this; deferred.

**Tech Stack:** Python 3.12+ · Bash (POSIX-portable with `set -eu`, no `pipefail`) · `tomllib` (stdlib TOML reader) · Pydantic v2 (`Settings` extension) · `alfred.security.secrets.SecretBroker.get` (Slice-3 shipped at `src/alfred/security/secrets.py:396`) · `alfred.plugins.manifest.parse_manifest` (Slice-3 shipped — gains an extension for the `sandbox` block) · `alfred.audit.audit_row_schemas` (Slice-4 `SANDBOX_REFUSED_FIELDS` / `SANDBOX_STUB_USED_FIELDS` ship in PR-S4-0a; this PR consumes them) · `alfred.i18n.t()` for every operator-facing stderr/error string · `resource.setrlimit` + `ctypes.CDLL("libc.so.6").mlockall` (Linux best-effort) · `bin/alfred-plugin-launcher.sh` (Slice-3 shipped; PR-S4-6 extends) · `structlog` · pytest + testcontainers + bash-fixture harness · `coverage --fail-under=100` on every trust-boundary file this PR touches.

**Depends on:**

- **PR-S4-0a (merged)** — `SANDBOX_REFUSED_FIELDS` and `SANDBOX_STUB_USED_FIELDS` audit constants; `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS`; `sandbox_escape` adversarial category + `sbx-` prefix in `_PREFIX_TO_CATEGORY`; ADR-0015 still Proposed (flip deferred to PR-S4-11); glossary entries for *sandbox kind*, *policy_ref*, *fd-3 inheritance*.
- **PR-S4-0b (merged)** — Dockerfile for `alfred-core` with `bubblewrap` apt-installed (the launcher needs `bwrap` on the runtime PATH); `bin/alfred-setup.sh` updates; alembic migrations relevant to operator session (unrelated but ordering required).
- **PR-S4-3 (merged)** — `HookpointMeta.carrier_tier` + `HookpointMeta.allow_error_substitution` required fields. Every `register_hookpoint(...)` in this PR passes `carrier_tier="T0"`. Without PR-S4-3, registration fails the AST guard (rev-009 round-3 closure on the index).

**Blocks:**

- **PR-S4-7** — depends on the launcher's policy-file resolution path being live so the actual policy bytes have a consumer (the index pins this as the only consumer of the resolver's per-OS lookup).
- **PR-S4-9** (Discord adapter) — uses the manifest `sandbox.kind: none` shape this PR defines.
- **PR-S4-10** (TUI adapter) — same.
- **PR-S4-1** boot path's "launcher policy-resolving probe" flips from PR-S4-1's no-op stub to the real probe shipped here (arch-001 closure on the spec).

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **sec-1 BLOCKER (launcher truthy-parsing regression)**: `bin/alfred-plugin-launcher.sh` MUST use a shared truthy helper that matches the Python helper in PR-S4-1:

   ```bash
   _truthy() {
     case "${1:-}" in
       1|true|TRUE|yes|YES|on|ON) return 0 ;;
       *) return 1 ;;
     esac
   }
   if [ "$UNSANDBOXED_MODE" = "kind:stub" ] && _truthy "${ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED:-}"; then
     ...
   fi
   ```

   Trimming whitespace (POSIX `${var# }`) happens BEFORE the case-match. NEVER `[ "${VAR}" = "1" ]`. The Python helper at `src/alfred/cli/daemon/_env_truthy.py` ships in PR-S4-1 (round-2 closure 2); this PR's bash version is its mirror. Synchronized via a shared test fixture `tests/unit/cli/test_env_truthy_parity.py`.

2. **sec-2 BLOCKER (policy_refs path-confinement)**: `manifest_reader.py` MUST refuse any `policy_ref` that:
   - Is not a relative path under `~/.config/alfred/sandbox/` or `${ALFRED_HOME}/sandbox/`
   - Contains `..` path components
   - Resolves (via `Path.resolve(strict=True)`) outside the sandbox-policy directory canonical root
   - Symlinks point outside the policy root

   The refusal is `SandboxPolicyRefInvalid` with `reason="policy_ref_escapes_root"`. Adversarial corpus entry `sbx-2026-007-policy_ref_traversal` plants a manifest with `policy_ref = "../../../etc/passwd-bind.toml"` and asserts refusal. PR-S4-7's policy translator is downstream of this check; even a clean-translated `--ro-bind /etc /etc` is impossible because the path-confinement gate stops the policy file ever being read.

3. **sec-3 HIGH (fd-3 single-writev syscall)**: provider-key delivery MUST use `os.writev(fd3_write_end, [length_prefix_bytes, key_bytes])` — single syscall, atomic on POSIX. On EAGAIN/partial-write the Supervisor refuses to spawn the plugin AND emits `SANDBOX_REFUSED_FIELDS(reason="provider_key_delivery_failed")`. Key bytes are stored in a `bytearray` (mutable), zeroed via `key_bytes[:] = b"\x00" * len(key_bytes)` immediately after the writev call, BEFORE `gc.collect()`. The honest limitation re: Python `str` interning at the broker-fetch boundary is unchanged; this closure tightens the post-fetch path.

4. **sec-4 HIGH (`--read-environment` TOCTOU)**: `--read-environment` (the env-conflict probe) MUST be called EXACTLY ONCE in the boot path; the result is stashed in a module-level frozen Pydantic model `EnvironmentLoadResult` and consulted from there. The Python helper that drives the probe is `src/alfred/cli/daemon/_environment_probe.py:probe_environment() -> EnvironmentLoadResult` — one process, one read, one result. Audit-row emit consumes the cached result. NO repeat invocations.

5. **devops-1 HIGH (bwrap version pin)**: PR-S4-0b's Dockerfile MUST pin `bubblewrap=0.8.0-1` (Debian Bookworm version that ships `--keep-fd`; the round-2 closure-1 in PR-S4-0b said 0.6.0 — corrected here to 0.8.0 to ensure `--keep-fd` support; `--keep-fd` requires bwrap 0.5.0+). PR-S4-1's daemon-boot probe adds `bwrap_version_check`: parse `bwrap --version` output, refuse boot if `< 0.5.0`. New i18n key `daemon.boot.bwrap_version_too_old`. New corpus entry `sbx-2026-008-bwrap_version_drift` simulates an old bwrap and asserts boot refusal.

6. **devops-2 HIGH (cross-OS CI matrix)**: PR-S4-6 CI workflow expands to run the launcher's macOS branch on `macos-latest` runners and the Windows-stub branch on `windows-latest`. Tests use `FAKE_UNAME=Darwin` / `FAKE_UNAME=Windows_NT` overrides in the bash launcher (a new `_uname()` shim helper). The matrix asserts: (a) Linux+bwrap → success; (b) macOS+sandbox-exec stub → success; (c) Windows → refuse with `kind:none_only_on_windows` audit row. Without the matrix, the per-OS branches drift silently.

7. **devops-3 MEDIUM (SUID-vs-userns mode detection)**: PR-S4-1's daemon-boot probe (closure 5 above) ADDS a sub-probe `bwrap_mode_probe`: runs `bwrap --unshare-user --uid 1000 -- /bin/true`; if exit code != 0, falls back to SUID-mode detection via `getcap /usr/bin/bwrap | grep cap_sys_admin`. Result stashed in `EnvironmentLoadResult.bwrap_mode: Literal["userns", "suid"]`. Logged at boot via `daemon.boot.bwrap_mode_detected` audit row. `docker-compose.yaml` documents the `--privileged` opt-out + the `apparmor=unconfined` annotation needed for hardened-kernel hosts.

8. **arch-1 HIGH (PR-S4-7 fixture contract)**: PR-S4-6 EXPORTS `tests/conftest.py:launcher_chain_fixture` (a pytest fixture that returns a callable spawning the bash launcher against a per-test temporary policy-file directory). PR-S4-7's plan imports this fixture for its policy-translation tests. Fixture signature: `def launcher_chain_fixture(tmp_path: Path) -> Callable[[str], LauncherResult]`. Without the export, PR-S4-7's tests don't compile.

9. **arch-2 MEDIUM (fd-3 invariant enforcement)**: `SandboxPolicy` (Pydantic frozen model) adds a `model_validator` that REFUSES any `kind: full` policy whose `keep_fds` does NOT include 3. Refusal at policy-parse time, not at runtime. Test `tests/unit/sandbox/test_policy_keep_fds_3_required.py` plants `kind: full` + `keep_fds = []` and asserts `SandboxPolicyInvalid("kind_full_requires_fd_3_keep")`.

10. **arch-3 MEDIUM (session-layer sandbox-info handshake)**: `AlfredPluginSession._on_post_handshake_method` (real Slice-3 method at `src/alfred/plugins/session.py:347`) extends to accept a `sandbox_info` post-handshake method from the plugin. Plugin reports back its `effective_sandbox_kind`, `pid_namespace`, `mount_namespace`, etc. Supervisor compares against the manifest's declared `sandbox.kind`; mismatch raises `SandboxInfoHandshakeMismatch` and tears down the session. Corpus entry `sbx-2026-009-sandbox_info_lies` plants a `kind: none` plugin pretending to be `kind: full` and asserts teardown.

11. **test-1 HIGH (active escape-attempt tests in this PR)**: J.1 integration test MUST exercise escape attempts against the bash launcher's fixture policy:
    - `test_plugin_cannot_read_host_etc_passwd` — `kind: full` plugin attempts `open("/etc/passwd")`, expects EACCES.
    - `test_plugin_cannot_exec_host_bin_sh` — plugin attempts `subprocess.run(["/bin/sh", "-c", "echo escape"])`, expects ENOENT (sandbox doesn't bind `/bin/sh`).
    - `test_plugin_cannot_read_host_proc_self_environ` — plugin attempts `open("/proc/<host_pid>/environ")`, expects EPERM (mount-ns isolation).
    Without these the PR's "bwrap is correctly invoked" claim is unsupported by behavioural evidence.

12. **test-2 HIGH (fd-leak deeper coverage)**: `tests/unit/cli/test_fd_leak.py` asserts: (a) `os.listdir("/proc/self/fd")` BEFORE launcher spawn equals expected baseline; (b) AFTER spawn, only fds 0,1,2,3 are inherited; (c) any extra fd (e.g. plant fd 4 via `os.dup`) is closed by the `pass_fds=[3]` discipline. Test plants fd 4 and asserts it's NOT visible inside the launched plugin via a `read_fd_set_from_plugin()` helper.

13. **test-3 MEDIUM (cross-OS asymmetry resolved by devops-2 closure 6 above)**: covered by the CI matrix expansion.

14. **DR-001 (rev-009 corollary on the renumbered migration)**: PR-S4-0b's migrations renumbered 0011→0012-0015; PR-S4-6 carries no migration. The "Depends on PR-S4-0b — Alembic 0011" line was a typo. Corrected: no migration dependency from PR-S4-6.

---

## §1 Goal

This PR closes spec §7.1 through §7.5, §7.8, §7.9, §7.11. After this PR merges:

1. Every plugin manifest gains a `[sandbox]` block (TOML — see §4.1 on the manifest-format reconciliation; the spec wrote YAML, the existing parser is TOML). Missing block → load refused with `reason="sandbox_block_missing"`.
2. `Settings.environment: Literal["development", "production", "test"]` exists and is mandatory at daemon boot. It is dual-sourced: `ALFRED_ENVIRONMENT` env var (primary) > `/etc/alfred/environment` file (fallback). Neither source set → CLI refuses with `t("daemon.boot.environment_not_set")` and exits non-zero.
3. `bin/alfred-plugin-launcher.sh` runs the pre-launcher Python helper to read the `sandbox` block and branches:
   - `kind: full` → resolve OS-specific `policy_refs.{linux,macos,windows}`; refuse if missing/unreadable/OS-mismatch; `exec bwrap --keep-fd 3 ... -- ${PLUGIN_BINARY}` on Linux. macOS+Windows bytes ship in PR-S4-7; PR-S4-6 ensures the *resolver path* compiles for all three OSes.
   - `kind: none` → existing Slice-3 UID-separated subprocess (unchanged behaviour).
   - `kind: stub` → refuse in production; in development emit `SANDBOX_STUB_USED_FIELDS` and exec unsandboxed.
4. `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` + `Settings.environment == "production"` → refuse with operator-visible **stderr** message (`t("supervisor.sandbox.unsandboxed_refused_in_production")`) and emit `SANDBOX_REFUSED_FIELDS(reason="unsandboxed_env_set_in_production")` (devex-001 closure).
5. Supervisor (Python) ships fd-3 provider key delivery: `SecretBroker.get("quarantined.provider_key")` → 4-byte big-endian length prefix + key bytes → fd 3 → close write end → `gc.collect()`. The launcher's `--keep-fd 3` invariant means bash never touches the bytes.
6. Supervisor-side process posture: `resource.setrlimit(RLIMIT_CORE, (0, 0))` at boot (no core dumps), `mlockall(MCL_CURRENT | MCL_FUTURE)` best-effort on Linux. Failure of `mlockall` is loud (`supervisor.boot.mlock_unavailable` audit row) but non-fatal — operators without `CAP_IPC_LOCK` boot.
7. `plugins/alfred_quarantined_llm/manifest.toml` migrates `[plugin].sandbox_profile = "user-plugin"` semantic onto the new `[sandbox] kind = "full"` block with `[sandbox.policy_refs] linux/macos/windows` map.
8. New host-side hookpoint `supervisor.plugin.sandbox_refused` registered with `carrier_tier="T0"`, `fail_closed=True`.
9. The merge-blocking integration test `tests/integration/test_launcher_policy_resolver.py` ships under this PR (index §4 — PR-S4-6 owns it).

Spec anchors: [§7.1 manifest sandbox](../specs/2026-06-06-slice-4-design.md#71-plugin-manifest-sandbox-declaration), [§7.2 launcher policy resolution](../specs/2026-06-06-slice-4-design.md#72-binalfred-plugin-launcher-policy-resolution), [§7.3 production-refuse + dual-sourced env](../specs/2026-06-06-slice-4-design.md#73-production-refuse-without-policy-semantics), [§7.4 dev escape hatch + stderr](../specs/2026-06-06-slice-4-design.md#74-dev-escape-hatch-alfred_plugin_launcher_unsandboxed1), [§7.5 fd-3 inheritance + residency](../specs/2026-06-06-slice-4-design.md#75-linux-bwrap-policy-configsandboxquarantined-llmlinuxbwrappolicy), [§7.8 quarantined-LLM manifest update](../specs/2026-06-06-slice-4-design.md#78-quarantined-llm-manifest-update), [§7.9 first-party comms carve-out](../specs/2026-06-06-slice-4-design.md#79-first-party-comms-adapters-declare-kind-none), [§7.11 audit rows](../specs/2026-06-06-slice-4-design.md#711-audit-row-family).

---

## §2 Architecture overview

```
                 ┌──────────────────────────────────────────────────┐
                 │ alfred daemon start (PR-S4-1 boot path)         │
                 │   probes: launcher_policy_resolving (THIS PR)   │
                 │           snapshot_ref_init                     │
                 │           capability_gate_handshake             │
                 └──────────────────────┬───────────────────────────┘
                                        │ probes pass
                                        ▼
            ┌──────────────────────────────────────────────────────────┐
            │ Supervisor (Python, host) — spawns plugin subprocess     │
            │                                                          │
            │ 1. resource.setrlimit(RLIMIT_CORE, (0, 0))   # at boot    │
            │ 2. mlockall(MCL_CURRENT | MCL_FUTURE)        # at boot    │
            │     on Linux best-effort                                  │
            │ 3. SecretBroker.get("quarantined.provider_key")           │
            │      returns Python `str` (interned, non-zeroizable —     │
            │      acknowledged residency window — §4.6 honest          │
            │      limitation)                                          │
            │ 4. pipe_read_fd, pipe_write_fd = os.pipe()                │
            │ 5. os.dup2(pipe_read_fd, 3)                               │
            │      in the child (subprocess_exec preexec_fn or via      │
            │      pass_fds=(3,) so launcher inherits fd 3)             │
            │ 6. asyncio.subprocess_exec(                               │
            │      "bin/alfred-plugin-launcher.sh",                     │
            │      plugin_id, plugin_binary, *args,                     │
            │      pass_fds=(3,),                                       │
            │      env=scrubbed_env_dict)                               │
            │ 7. os.write(pipe_write_fd, length_prefix + key_bytes)     │
            │ 8. os.close(pipe_write_fd)                                │
            │ 9. del key_bytes; del key_str; gc.collect()               │
            └──────────────────────┬───────────────────────────────────┘
                                   │ exec
                                   ▼
        ┌────────────────────────────────────────────────────────────┐
        │ bin/alfred-plugin-launcher.sh (bash)                       │
        │                                                            │
        │ 1. set -eu; validate PLUGIN_ID charset; help flag          │
        │ 2. Read Settings.environment via:                          │
        │       ENV=$(python3 -m alfred.plugins.manifest_reader      │
        │             --read-environment 2>/dev/null || echo "")     │
        │    If ENV unset → emit                                     │
        │       SANDBOX_REFUSED_FIELDS(reason="environment_not_set") │
        │    bare i18n key on stderr + exit 1                        │
        │ 3. Dev escape hatch check:                                 │
        │    if [[ "$ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED" == "1"      │
        │           && "$ENV" == "production" ]]; then               │
        │      printf '%s\n' "$(t supervisor.sandbox.                │
        │        unsandboxed_refused_in_production)" >&2             │
        │      emit SANDBOX_REFUSED_FIELDS(                          │
        │        reason="unsandboxed_env_set_in_production")         │
        │      exit 1                                                │
        │    fi                                                      │
        │ 4. Read manifest sandbox block via:                        │
        │       SANDBOX_JSON=$(python3 -m                            │
        │         alfred.plugins.manifest_reader                     │
        │         --read-sandbox "$PLUGIN_ID")                       │
        │    On failure (missing block, malformed TOML, OS-mismatch) │
        │    → emit SANDBOX_REFUSED_FIELDS(reason=…) + stderr key    │
        │    + exit 1                                                │
        │ 5. SANDBOX_KIND=$(echo "$SANDBOX_JSON" | jq -r .kind)      │
        │ 6. Branch:                                                 │
        │    kind=full → POLICY_REF=$(echo "$SANDBOX_JSON" |         │
        │                  jq -r .policy_ref)                        │
        │                test -r "$POLICY_REF" || refuse with        │
        │                reason="policy_ref_unreadable"              │
        │                On Linux: exec bwrap --keep-fd 3            │
        │                  $(cat "$POLICY_REF" |                     │
        │                   python3 -m                               │
        │                   alfred.plugins.manifest_reader           │
        │                   --policy-to-bwrap-flags)                 │
        │                  -- "$PLUGIN_BINARY" "$@"                  │
        │                On macOS: defer to PR-S4-7                  │
        │                On Windows: stub → refuse in prod, dev      │
        │                   emits SANDBOX_STUB_USED_FIELDS           │
        │    kind=none → existing Slice-3 runuser UID-separated      │
        │                path (unchanged); fd 3 still inherited      │
        │    kind=stub → if ENV=production → refuse with             │
        │                  reason="windows_stub_in_production"       │
        │                else → emit SANDBOX_STUB_USED_FIELDS        │
        │                  exec "$PLUGIN_BINARY" "$@"                │
        └────────────────────────────────────────────────────────────┘
                                   │ exec'd plugin
                                   ▼
        ┌────────────────────────────────────────────────────────────┐
        │ Plugin (Python, runs under bwrap on Linux / sandbox-exec   │
        │ on macOS / unsandboxed-with-loud-audit on Windows-dev)     │
        │                                                            │
        │ - resource.setrlimit(RLIMIT_CORE, (0, 0))   # plugin-side  │
        │ - mlockall(MCL_CURRENT | MCL_FUTURE)        # plugin-side  │
        │ - read_fd3_secret() → bytearray (Slice-3 shipped helper —  │
        │   already zeroizes after use; this PR does NOT modify it)  │
        └────────────────────────────────────────────────────────────┘
```

**The bash-shape is load-bearing.** A Python launcher would have to start its own Python interpreter to read the manifest before launching the plugin's Python interpreter — chicken-and-egg + double the cold-start tax. The pre-launcher helper is a one-shot subprocess invoked from bash, not an embedded module load. Each invocation of `manifest_reader` is independent; failures don't taint subsequent calls.

**Fd-3 inheritance, not bwrap-bind.** The round-3 spec draft used `--rw-bind /dev/fd/3 /dev/fd/3` — mechanically wrong, because `/dev/fd/3` only exists on Linux as a special procfs symlink that resolves to the inherited fd. Round-4 corrected this to `bwrap --keep-fd 3` — bwrap's documented flag for "leave fd N intact in the spawned process." The kernel handles the inheritance; no mount manipulation needed. PR-S4-6's launcher invocation is the round-4-correct shape.

**Sandbox kind versus subscriber tier.** The Slice-3 manifest already carries `[plugin] subscriber_tier` (closed vocabulary `{system, operator, user-plugin}`) and `[plugin] sandbox_profile` (free-form string, currently set to `"user-plugin"` for the quarantined-LLM). The new `[sandbox] kind` is **orthogonal** — `kind` is the OS-level isolation primitive, `subscriber_tier` is the capability-gate posture, `sandbox_profile` is a legacy free-form label that PR-S4-6 leaves untouched (PR-S4-7 may deprecate it; out-of-scope here). Conflating these is a tier-laundering bug shape; the manifest parser refuses combinations that don't make sense (e.g., `[plugin] subscriber_tier = "system"` with `[sandbox] kind = "stub"` outside dev is refused).

---

## §3 Fabricated-surfaces verification gate

Per Slice-4 index §8 watchlist (round-2 invented `secret_broker.fetch_audit_pepper`, `AuditWriter.dedupe_surface`, `Python launcher`, `AlfredPluginSession._read_loop` — the pattern is reflexive enough to need explicit grep verification). Every claim below was checked at plan-authoring time; each row carries the verifying command, the actual location, and either "verified" or "NEW".

| Claim | Location | Status |
|---|---|---|
| `bin/alfred-plugin-launcher.sh` exists and is bash | Read full file at `bin/alfred-plugin-launcher.sh` — `#!/usr/bin/env bash`, ~190 lines, `set -eu`, no `pipefail` | **verified** |
| Existing launcher invariants: charset-validate PLUGIN_ID, help flag, dev escape hatch, fail-closed without policy, runuser UID-drop on Linux | All present in current file | **verified** — PR-S4-6 extends, does not rewrite |
| `SecretBroker.get(name) -> str` at `src/alfred/security/secrets.py:396` | `sed -n '396p' src/alfred/security/secrets.py` shows `def get(self, name: str) -> str:` | **verified** |
| Quarantined-LLM manifest path | `plugins/alfred_quarantined_llm/manifest.toml` (NOT `manifest.yaml` as spec §7.8 wrote — the spec example used YAML shorthand; the actual file is TOML) | **verified — file is TOML, spec snippet is illustrative** |
| Quarantined-LLM manifest currently declares `[plugin] subscriber_tier = "system"`, `sandbox_profile = "user-plugin"` | Cat of file confirms | **verified** |
| `class Settings(BaseSettings)` at `src/alfred/config/settings.py:28` | `grep -n "class Settings" src/alfred/config/settings.py` returns line 28 | **verified** |
| `Settings.environment: Literal[…]` field exists | `grep -n "environment" src/alfred/config/settings.py` returns ONLY the module-level docstring's "environment variables" — no field | **NEW — PR-S4-6 adds the field** |
| `ALFRED_ENV` reading convention | `bootstrap/gate_factory.py:64 _ENV_KEY: str = "ALFRED_ENV"` and `_gate.py` consult it; sec-007 forbids direct `import os` outside the bootstrap layer | **verified** — Slice-4 introduces `ALFRED_ENVIRONMENT` (note the difference) per spec §7.3; ALFRED_ENV remains for the capability-gate selector |
| `SANDBOX_REFUSED_FIELDS` / `SANDBOX_STUB_USED_FIELDS` constants | `grep -rn "SANDBOX_REFUSED_FIELDS\|SANDBOX_STUB_USED_FIELDS" src/alfred/audit/` returns nothing on current main | **NEW — lands in PR-S4-0a per index §3; PR-S4-6 consumes** |
| bwrap `--keep-fd` flag | Per bwrap upstream docs (verified via context7 / bwrap manpage where available); flag exists in bwrap ≥ 0.4 | **verified — DO NOT use `/dev/fd/3` mount as the round-3 spec draft wrote** |
| `alfred.plugins.manifest.parse_manifest` | Exists at `src/alfred/plugins/manifest.py` (Slice-3 shipped) — currently does NOT read a `[sandbox]` table | **verified — PR-S4-6 extends** |
| `alfred.plugins.manifest_reader` (pre-launcher helper) | Does not exist | **NEW — PR-S4-6 creates** |
| `bwrap` available on alfred-core image | PR-S4-0b adds `bubblewrap` apt-install to Dockerfile (per index §1) | **verified — PR-S4-6 depends on PR-S4-0b** |
| `_PREFIX_TO_CATEGORY` includes `"sbx"` | PR-S4-0a per index §3 adds it | **verified — PR-S4-6 references for adversarial corpus IDs** |

**Verification protocol** for the implementer: before writing any task's code, re-run the grep that verifies the surface the task calls. If the surface has drifted between plan-authoring and implementation, capture the drift in the PR description and bring it to `alfred-architect` rather than papering over.

---

## §4 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/config/settings.py` | Modify | Add `environment: Literal["development", "production", "test"]` field; dual-source resolver (env var > `/etc/alfred/environment`); emit `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` on disagreement |
| `src/alfred/plugins/manifest.py` | Modify | Extend `PluginManifest` model with optional `sandbox: SandboxBlock` field; extend `parse_manifest` to read `[sandbox]` TOML table; define `SandboxKind = Literal["full", "none", "stub"]` and `SandboxBlock` Pydantic model with `kind` + `policy_refs: Mapping[Literal["linux","macos","windows"], str]` |
| `src/alfred/plugins/manifest_reader.py` | **Create** | CLI-style Python entry point: `python3 -m alfred.plugins.manifest_reader --read-sandbox <plugin_id>` prints JSON sandbox block; `--read-environment` prints `Settings.environment`; `--policy-to-bwrap-flags` reads a policy file from stdin and prints bwrap CLI flags. All commands fail fast with non-zero exit + bare i18n key on stderr |
| `src/alfred/plugins/sandbox_policy.py` | **Create** | `SandboxPolicy` Pydantic model (TOML schema for `config/sandbox/*.policy` files); `policy_to_bwrap_flags(policy)` translator; reserves the Linux bwrap schema in PR-S4-6 (PR-S4-7 ships the bytes for the quarantined-LLM specifically). PR-S4-6 ships the schema + translator + a fixture-only policy file used by the resolver integration test |
| `src/alfred/supervisor/process_posture.py` | **Create** | `disable_core_dumps()` — `resource.setrlimit(RLIMIT_CORE, (0, 0))`; `try_mlockall()` — Linux `ctypes` best-effort wrapper, emits `supervisor.boot.mlock_unavailable` audit row on failure |
| `src/alfred/supervisor/fd3_key_delivery.py` | **Create** | `deliver_provider_key_via_fd3(launcher_process, key: str) -> None` — opens pipe, writes 4-byte big-endian length prefix + key bytes, closes write end, `del key`, `gc.collect()`. Audit-row attribution: `provider_key_delivered` (informational, T0 carrier) |
| `bin/alfred-plugin-launcher.sh` | Modify | Add: `Settings.environment` read; dev-escape-hatch refuse-in-production with stderr message; manifest sandbox block read via `manifest_reader.py`; `kind` branching (`full` / `none` / `stub`); `bwrap --keep-fd 3` invocation on Linux for `kind: full`. PRESERVES Slice-3 invariants: charset-validate PLUGIN_ID, help flag, runuser UID-drop on Linux for `kind: none`, fail-closed semantics, structured audit JSON on stderr |
| `plugins/alfred_quarantined_llm/manifest.toml` | Modify | Add `[sandbox]` table: `kind = "full"`, `[sandbox.policy_refs]` with `linux` / `macos` / `windows` entries. Leaves the Slice-3 `[plugin]` block unchanged |
| `src/alfred/hooks/registry.py` | Modify | Register `supervisor.plugin.sandbox_refused` hookpoint with `carrier_tier="T0"`, `fail_closed=True`, `allow_error_substitution=True` (default). Also register `supervisor.boot.mlock_unavailable` with `carrier_tier="T0"`, `fail_closed=False` (informational — boot proceeds even if `mlockall` fails) |
| `src/alfred/audit/__init__.py` or relevant emit-site | Verify | Confirm `SANDBOX_REFUSED_FIELDS` and `SANDBOX_STUB_USED_FIELDS` are imported and re-exported per the Slice-4 audit convention (PR-S4-0a ships the constants; PR-S4-6 references) |
| `src/alfred/i18n/locales/en/LC_MESSAGES/alfred.po` | Modify | Add keys: `daemon.boot.environment_not_set`, `daemon.boot.environment_source_conflict`, `supervisor.sandbox.unsandboxed_refused_in_production`, `supervisor.sandbox.policy_ref_missing`, `supervisor.sandbox.policy_ref_os_mismatch`, `supervisor.sandbox.policy_ref_unreadable`, `supervisor.sandbox.sandbox_block_missing`, `supervisor.sandbox.windows_stub_in_production`, `supervisor.sandbox.stub_used`, `supervisor.boot.mlock_unavailable`, `supervisor.boot.core_dumps_disabled`. Each key has English text only; pybabel compile runs in `make check` |
| `config/sandbox/_fixtures/policy_resolver_test.linux.bwrap.policy` | **Create** | A fixture-only policy file consumed by the resolver integration test. NOT the quarantined-LLM policy — that ships in PR-S4-7. Schema: TOML with `[bwrap] ro_binds = […]`, `tmpfs = […]`, `unshare = […]`, `die_with_parent = true`. Documents the schema this PR's resolver supports |
| `tests/unit/config/test_settings_environment.py` | **Create** | Settings.environment field tests: env var > file precedence; conflict emits audit row; neither source set raises; only the three Literal values accepted; absence at boot is a hard error |
| `tests/unit/plugins/test_manifest_sandbox_block.py` | **Create** | TOML parsing: missing `[sandbox]` → `ManifestSandboxMissingError`; `kind` outside Literal → `ManifestError`; `kind: full` without `policy_refs` → `ManifestError`; `kind: none` with `policy_refs` → tolerated (forward-compat); OS keys outside `{linux,macos,windows}` → `ManifestError` |
| `tests/unit/plugins/test_manifest_reader_cli.py` | **Create** | The three CLI subcommands: stdout shape, exit codes, stderr bare-key shape, malformed inputs all refuse loudly |
| `tests/unit/plugins/test_sandbox_policy_translator.py` | **Create** | `policy_to_bwrap_flags` shape: every TOML key maps to documented flag set; unknown keys refuse; the fixture policy translates correctly |
| `tests/unit/supervisor/test_process_posture.py` | **Create** | `disable_core_dumps` sets RLIMIT_CORE to (0, 0); `try_mlockall` emits `supervisor.boot.mlock_unavailable` on simulated failure but does not raise; both are idempotent |
| `tests/unit/supervisor/test_fd3_key_delivery.py` | **Create** | 4-byte big-endian length prefix + bytes; write-end closed after; `gc.collect()` invoked; assertion that the function does NOT retain the key in any local-frame attribute past return. Uses a captured-pipe-reader fixture (no real subprocess) |
| `tests/unit/launcher/test_environment_read.py` | **Create** | bash-fixture-harness test: `Settings.environment` not set → launcher refuses with bare key + exit 1; env-var-only set → uses env-var value; file-only set → uses file value; both agree → no conflict row; both disagree → conflict audit row JSON on stderr, env-var value wins |
| `tests/unit/launcher/test_dev_escape_hatch_prod_refusal.py` | **Create** | bash-fixture-harness test: `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` + `ALFRED_ENVIRONMENT=production` → refuse with the operator-facing stderr message + audit row + exit 1. Same with file source. Honoured in development with audit row |
| `tests/unit/launcher/test_sandbox_kind_branching.py` | **Create** | bash-fixture-harness test: `kind: full` invokes bwrap with `--keep-fd 3`; `kind: none` falls through to Slice-3 runuser path; `kind: stub` refuses in prod, emits stub-used row in dev |
| `tests/unit/launcher/test_policy_ref_resolution.py` | **Create** | bash-fixture-harness test: missing file → `policy_ref_missing`; unreadable file → `policy_ref_unreadable`; OS mismatch (Linux launcher, only macOS key in manifest) → `policy_ref_os_mismatch` |
| `tests/integration/test_launcher_policy_resolver.py` | **Create** | Index §4 merge-blocking integration test. End-to-end: real bash launcher process; real manifest_reader subprocess; real fixture policy file; assert bwrap is invoked with `--keep-fd 3` and the fixture's policy flags. Skipped if `bwrap` not on PATH (CI image has it after PR-S4-0b) |
| `tests/adversarial/sandbox_escape/test_manifest_sandbox_bypass.py` | **Create** | Adversarial corpus: `manifest_omits_sandbox_block` (sbx-2026-001); attacker plants a kind: stub on a production-deployed plugin (sbx-2026-002); attacker plants a policy_ref pointing outside the install tree (sbx-2026-003). Each refused with `SANDBOX_REFUSED_FIELDS` |
| `tests/adversarial/sandbox_escape/test_launcher_key_inheritance.py` | **Create** | Adversarial corpus sbx-2026-004 / sbx-2026-005: under strace (Linux) or dtruss (macOS — advisory only), assert the bash launcher process never reads from fd 3; only the spawned plugin does. Skipped if strace not on PATH |
| `scripts/check_no_direct_env_reads.py` | Modify | Allowlist `src/alfred/supervisor/fd3_key_delivery.py` for `os.pipe`, `os.write`, `os.close`; allowlist `src/alfred/plugins/manifest_reader.py` for the `--read-environment` subcommand's `os.environ.get("ALFRED_ENVIRONMENT")` read (manifest_reader is the explicit boundary — sec-007 carve-out) |

---

## §5 Cross-PR contracts

These contract surfaces are owned by PR-S4-6 and consumed by downstream PRs. Drift between PRs is a release-blocker.

### Manifest sandbox-block schema (TOML; spec §7.1 reconciled)

```toml
# Every plugin manifest gains this block. Required (no default).
[sandbox]
kind = "full"   # Literal["full", "none", "stub"]

[sandbox.policy_refs]
# Required when kind = "full". Path is relative to the AlfredOS install root.
linux   = "config/sandbox/<name>.linux.bwrap.policy"
macos   = "config/sandbox/<name>.macos.sb"
windows = "config/sandbox/<name>.windows.stub.policy"
```

- `kind: none` → block is still required; `policy_refs` table may be absent. The resolver MUST refuse if `policy_refs` is present AND any of its entries is malformed (defence in depth — silent tolerance is a foothold for tomorrow's misconfiguration).
- `kind: stub` → same as `kind: none` for the table presence rule. Only the `windows` `policy_refs` key is meaningful for a stub (currently); the resolver tolerates absence.
- Spec §7.1 wrote `policy_ref` (singular). Spec §7.8 wrote `policy_refs` (plural, OS-keyed map). The plural form is the load-bearing one (per-OS resolution is the whole point); the singular form was an early-draft holdover. PR-S4-6 SHIPS THE PLURAL.

This schema is consumed by PR-S4-7 (quarantined-LLM policy bytes — only adds bytes, does not modify schema), PR-S4-9 (Discord adapter manifest declares `kind: none`), PR-S4-10 (TUI adapter manifest declares `kind: none`). Any later PR adding a fourth OS key (e.g., `freebsd`) must extend the `Literal` in `SandboxBlock.policy_refs` AND extend `manifest_reader.py`'s `--read-sandbox` validation AND update the launcher's `case "${HOST_OS}" in …` branch — three atomic changes in one PR.

### Launcher CLI contract

The launcher's command-line invocation contract:

```
bin/alfred-plugin-launcher.sh <plugin_id> <plugin_binary> [args...]
```

Inherited from Slice-3 unchanged. PR-S4-6 does NOT add new positional or flag arguments. All new behaviour is governed by:

- Environment variables: `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED`, `ALFRED_ENVIRONMENT`, `ALFRED_SANDBOX_POLICY_DIR`, `ALFRED_PLUGIN_UID`.
- The manifest's `[sandbox]` block (read via `manifest_reader.py`).
- The `/etc/alfred/environment` file fallback for `Settings.environment`.

Fd 3 is the documented out-of-band channel for the quarantined-LLM provider key. PR-S4-6 establishes that fd 3 is **always passed through** by the launcher whether or not the plugin uses it (the cost of `--keep-fd 3` when nothing is written to fd 3 is zero — the inherited fd is just unused). PR-S4-9 (Discord) and PR-S4-10 (TUI) plugins do NOT consume fd 3 but the launcher still inherits it for forward-compat.

### Audit-row constants this PR consumes (defined in PR-S4-0a)

- `SANDBOX_REFUSED_FIELDS` — fields: `plugin_id`, `policy_ref` (Optional[str]; None when no policy was attempted), `host_os` (Literal["linux", "macos", "windows"]), `reason` (Literal — see below), `environment` (Literal["development", "production", "test"] or "unset"). `reason` Literal:
  - `"policy_ref_missing"` — the `policy_refs.<host_os>` key is absent.
  - `"policy_ref_os_mismatch"` — the manifest declares OS keys but not the launcher's host OS (e.g., quarantined-LLM on FreeBSD before FreeBSD is supported).
  - `"policy_ref_unreadable"` — the file at `policy_refs.<host_os>` is missing or not readable.
  - `"sandbox_block_missing"` — manifest lacks `[sandbox]`.
  - `"windows_stub_in_production"` — `kind: stub` on a `production` Windows daemon.
  - `"unsandboxed_env_set_in_production"` — `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` in production.
  - `"environment_not_set"` — neither env var nor file source resolves to a Literal value.
- `SANDBOX_STUB_USED_FIELDS` — fields: `plugin_id`, `policy_ref` (Optional[str]), `host_os`, `environment` (must be `"development"`).

Both constants are imported from `alfred.audit.audit_row_schemas`; PR-S4-6 does NOT inline field-list literals at emit sites (per Slice-4 index §3 contract).

### Hookpoint registration this PR ships

| Hookpoint | Carrier tier | fail_closed | Notes |
|---|---|---|---|
| `supervisor.plugin.sandbox_refused` | T0 | True | Fires on every `SANDBOX_REFUSED_FIELDS` emit. Carries `plugin_id` + `reason` in the hook context. |
| `supervisor.boot.mlock_unavailable` | T0 | False | Informational — boot proceeds. Carries `errno_string` (translated) and `effective_uid` (no PII; this is the host process's UID). |
| `supervisor.boot.core_dumps_disabled` | T0 | False | Informational — boot proceeds. Carries `rlim_cur_before` + `rlim_cur_after` for forensic visibility. |

Each registration uses `register_hookpoint(name="…", carrier_tier="T0", fail_closed=…)`. PR-S4-3's `HookpointMeta.carrier_tier` requirement is honoured. PR-S4-3's AST guard (`tests/unit/hooks/test_carrier_tier_required.py`) will refuse the PR if any registration omits `carrier_tier`.

### Settings.environment dual-source resolver contract

```python
# In src/alfred/config/settings.py
class Settings(BaseSettings):
    ...
    environment: Literal["development", "production", "test"]
    # No default — explicit operator declaration mandatory. Pydantic raises
    # ValidationError at construction time if neither env nor file resolves.
```

The dual-source resolver runs BEFORE pydantic constructs the `Settings` instance — `pydantic-settings` reads `ALFRED_ENVIRONMENT` natively; if the env var is unset, a `BaseSettings` `settings_customise_sources` hook reads `/etc/alfred/environment` and injects the value. If both sources are present and disagree, the env var wins (per spec §7.3 precedence rule) AND a one-shot `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` audit row fires at the first `Settings()` construction in the daemon process. The audit emit is deferred until an `AuditWriter` is available (Settings is constructed too early in boot to call audit); the resolver returns a `(value, conflict_detected: bool)` tuple, and the daemon's CLI entry consults the tuple's second field to emit the audit row after wiring AuditWriter.

If neither source is set, `Settings.__init__` raises `SettingsError` carrying the `t("daemon.boot.environment_not_set")` operator-facing message. The CLI catches `SettingsError` per the existing `_load_settings_or_die` path.

### Quarantined-LLM manifest migration

```toml
# plugins/alfred_quarantined_llm/manifest.toml — after PR-S4-6

[alfred]
manifest_version = 1

[plugin]
id = "alfred.quarantined-llm"
subscriber_tier = "system"
sandbox_profile = "user-plugin"   # left unchanged for Slice-4 — PR-S4-7+ may deprecate

[sandbox]
kind = "full"

[sandbox.policy_refs]
linux   = "config/sandbox/quarantined-llm.linux.bwrap.policy"
macos   = "config/sandbox/quarantined-llm.macos.sb"
windows = "config/sandbox/quarantined-llm.windows.stub.policy"
```

The policy files at those three paths land in **PR-S4-7**. PR-S4-6 reserves the schema and the resolution path. A PR-S4-6 integration test uses a *fixture* policy file at `config/sandbox/_fixtures/policy_resolver_test.linux.bwrap.policy` to exercise the resolver end-to-end without depending on PR-S4-7's bytes.

If a Slice-4 deployment of just PR-S4-6 (without PR-S4-7) attempts to launch the quarantined-LLM, the launcher emits `SANDBOX_REFUSED_FIELDS(reason="policy_ref_unreadable")` and refuses. Operators MUST land PR-S4-7 before booting in production. PR-S4-11's graduation runbook documents this ordering.

---

## §6 Tasks

Tasks follow TDD: write failing test → confirm FAIL → implement → confirm PASS → commit. Every commit uses the convention `(#TBD-slice4)` and references PR-S4-6.

Numbering by component to keep cross-references stable during review.

---

### Component A — Settings.environment field

- [ ] **Task A.1 — Failing test: `Settings.environment` exists and is a `Literal`.**

  File: `tests/unit/config/test_settings_environment.py`.

  ```python
  import pytest
  from alfred.config.settings import Settings, SettingsError

  def test_environment_required_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
      s = Settings()
      assert s.environment == "development"

  def test_environment_invalid_value_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")  # not a Literal value
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
      with pytest.raises(SettingsError):
          Settings()

  def test_environment_unset_refuses_with_t_key(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
      monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
      # No /etc/alfred/environment file either — point the loader at an empty dir
      monkeypatch.setattr("alfred.config.settings._ETC_ENV_FILE", tmp_path / "nonexistent")
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
      with pytest.raises(SettingsError) as exc_info:
          Settings()
      assert "daemon.boot.environment_not_set" in str(exc_info.value)
  ```

  Run: `uv run pytest tests/unit/config/test_settings_environment.py -q` → expect failure (field doesn't exist yet).

- [ ] **Task A.2 — Implement `Settings.environment` field.**

  File: `src/alfred/config/settings.py`. Add:

  ```python
  from pathlib import Path
  from typing import Literal

  _ETC_ENV_FILE: Path = Path("/etc/alfred/environment")

  AlfredEnvironment = Literal["development", "production", "test"]

  class Settings(BaseSettings):
      ...
      environment: AlfredEnvironment   # no default — see settings_customise_sources

      @classmethod
      def settings_customise_sources(cls, settings_cls, ...):
          # Add a custom source between env_settings and dotenv_settings that
          # reads /etc/alfred/environment if ALFRED_ENVIRONMENT is unset.
          ...
  ```

  The custom source returns `{"environment": <file_contents.strip()>}` when the file is readable and the env var is unset. When both are present, a `(value, conflict_detected: bool)` tuple is stashed on a module-level `_ENVIRONMENT_CONFLICT` Box (a frozen Pydantic model holding the tuple) for the daemon's CLI to consume post-AuditWriter-wiring (this is the contract from §5).

  Make Task A.1's tests pass. Run `make check`.

- [ ] **Task A.3 — Failing test: env-var > file precedence + conflict detection.**

  ```python
  def test_environment_file_only(monkeypatch, tmp_path) -> None:
      env_file = tmp_path / "environment"
      env_file.write_text("production\n")
      monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
      monkeypatch.setattr("alfred.config.settings._ETC_ENV_FILE", env_file)
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
      s = Settings()
      assert s.environment == "production"

  def test_environment_env_var_wins_on_conflict(monkeypatch, tmp_path) -> None:
      env_file = tmp_path / "environment"
      env_file.write_text("production\n")
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
      monkeypatch.setattr("alfred.config.settings._ETC_ENV_FILE", env_file)
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
      s = Settings()
      assert s.environment == "development"
      from alfred.config.settings import get_environment_conflict
      conflict = get_environment_conflict()
      assert conflict is not None
      assert conflict.env_value == "development"
      assert conflict.file_value == "production"
  ```

- [ ] **Task A.4 — Implement conflict-detection accessor + file-only path.**

  Add to `src/alfred/config/settings.py`:

  ```python
  class _EnvironmentConflict(BaseModel):
      env_value: AlfredEnvironment
      file_value: AlfredEnvironment
      model_config = ConfigDict(frozen=True)

  _LAST_CONFLICT: _EnvironmentConflict | None = None

  def get_environment_conflict() -> _EnvironmentConflict | None:
      return _LAST_CONFLICT
  ```

  The CLI's `alfred daemon start` consults `get_environment_conflict()` after wiring AuditWriter and emits `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS`. PR-S4-1 owns the emit-site wiring; PR-S4-6 only ships the accessor.

  Make Task A.3's tests pass. `make check`.

---

### Component B — Manifest sandbox block

- [ ] **Task B.1 — Failing test: `parse_manifest` reads `[sandbox]` block.**

  File: `tests/unit/plugins/test_manifest_sandbox_block.py`.

  ```python
  import pytest
  from alfred.plugins.manifest import parse_manifest
  from alfred.plugins.errors import ManifestError, ManifestSandboxMissingError

  _BASE = """
  [alfred]
  manifest_version = 1

  [plugin]
  id = "alfred.example"
  subscriber_tier = "user-plugin"
  sandbox_profile = "user-plugin"
  """

  def test_sandbox_block_missing_refuses() -> None:
      with pytest.raises(ManifestSandboxMissingError):
          parse_manifest(_BASE)

  def test_sandbox_kind_full_with_policy_refs_parses() -> None:
      raw = _BASE + """
      [sandbox]
      kind = "full"

      [sandbox.policy_refs]
      linux = "config/sandbox/foo.linux.bwrap.policy"
      macos = "config/sandbox/foo.macos.sb"
      windows = "config/sandbox/foo.windows.stub.policy"
      """
      m = parse_manifest(raw)
      assert m.sandbox.kind == "full"
      assert m.sandbox.policy_refs["linux"].endswith(".bwrap.policy")

  def test_sandbox_kind_full_without_policy_refs_refuses() -> None:
      raw = _BASE + """
      [sandbox]
      kind = "full"
      """
      with pytest.raises(ManifestError, match="policy_refs required"):
          parse_manifest(raw)

  def test_sandbox_kind_none_no_policy_refs_ok() -> None:
      raw = _BASE + """
      [sandbox]
      kind = "none"
      """
      m = parse_manifest(raw)
      assert m.sandbox.kind == "none"
      assert m.sandbox.policy_refs == {}

  def test_sandbox_kind_invalid_refuses() -> None:
      raw = _BASE + """
      [sandbox]
      kind = "containerd"
      """
      with pytest.raises(ManifestError):
          parse_manifest(raw)

  def test_sandbox_policy_refs_unknown_os_key_refuses() -> None:
      raw = _BASE + """
      [sandbox]
      kind = "full"

      [sandbox.policy_refs]
      linux = "x"
      plan9 = "y"
      """
      with pytest.raises(ManifestError, match="unknown OS"):
          parse_manifest(raw)
  ```

  Run → expect failure.

- [ ] **Task B.2 — Implement `SandboxBlock` Pydantic model + `ManifestSandboxMissingError`.**

  File: `src/alfred/plugins/errors.py`. Add:

  ```python
  class ManifestSandboxMissingError(PluginError):
      """The manifest lacks a required [sandbox] block (spec §7.1).

      Distinct from ManifestError so the supervisor's
      sandbox_refused emit can attribute reason="sandbox_block_missing"
      without parsing the exception message.
      """
      def __init__(self, plugin_id: str) -> None:
          super().__init__(t("plugin.manifest_sandbox_block_missing", plugin_id=plugin_id))
          self.plugin_id = plugin_id
  ```

  File: `src/alfred/plugins/manifest.py`. Add:

  ```python
  _SANDBOX_KIND: Final[frozenset[str]] = frozenset({"full", "none", "stub"})
  _VALID_OS_KEYS: Final[frozenset[str]] = frozenset({"linux", "macos", "windows"})

  class SandboxBlock(BaseModel):
      kind: Literal["full", "none", "stub"]
      policy_refs: Mapping[Literal["linux", "macos", "windows"], str] = Field(default_factory=dict)

      model_config = ConfigDict(frozen=True, extra="forbid")

      @model_validator(mode="after")
      def _validate_policy_refs_when_full(self) -> SandboxBlock:
          if self.kind == "full" and not self.policy_refs:
              raise ValueError(
                  t("plugin.manifest_sandbox_policy_refs_required", kind=self.kind)
              )
          return self
  ```

  Extend `PluginManifest`:

  ```python
  class PluginManifest(BaseModel):
      ...
      sandbox: SandboxBlock
  ```

  Extend `parse_manifest`:

  ```python
  sandbox_section = data.get("sandbox")
  if not isinstance(sandbox_section, dict):
      raise ManifestSandboxMissingError(plugin_id=plugin_id)

  raw_kind = sandbox_section.get("kind")
  if raw_kind not in _SANDBOX_KIND:
      raise ManifestError(
          t("plugin.manifest_sandbox_kind_invalid", got=repr(raw_kind),
            valid=", ".join(sorted(_SANDBOX_KIND)))
      )

  policy_refs_raw = sandbox_section.get("policy_refs", {})
  if not isinstance(policy_refs_raw, dict):
      raise ManifestError(t("plugin.manifest_sandbox_policy_refs_type"))
  for os_key in policy_refs_raw:
      if os_key not in _VALID_OS_KEYS:
          raise ManifestError(
              t("plugin.manifest_sandbox_policy_refs_unknown_os",
                got=repr(os_key), valid=", ".join(sorted(_VALID_OS_KEYS)))
          )

  sandbox_block = SandboxBlock(kind=raw_kind, policy_refs=policy_refs_raw)
  ```

  Make B.1's tests pass. `make check`.

- [ ] **Task B.3 — Migrate quarantined-LLM manifest.**

  File: `plugins/alfred_quarantined_llm/manifest.toml`. Append:

  ```toml
  [sandbox]
  kind = "full"

  [sandbox.policy_refs]
  linux   = "config/sandbox/quarantined-llm.linux.bwrap.policy"
  macos   = "config/sandbox/quarantined-llm.macos.sb"
  windows = "config/sandbox/quarantined-llm.windows.stub.policy"
  ```

  Add a manifest-roundtrip test under `tests/unit/plugins/test_quarantined_llm_manifest.py` that parses the on-disk file and asserts `m.sandbox.kind == "full"` and `m.sandbox.policy_refs["linux"]` ends with `.bwrap.policy`. This is the proof that the migration sticks.

  Note: PR-S4-7 ships the actual policy bytes at the three referenced paths. Until PR-S4-7 lands, attempting to boot the daemon with `kind: full` will refuse with `policy_ref_unreadable` — correct fail-closed posture during the slice's mid-flight state.

---

### Component C — `manifest_reader` CLI helper

- [ ] **Task C.1 — Failing test: `--read-sandbox` prints JSON.**

  File: `tests/unit/plugins/test_manifest_reader_cli.py`.

  ```python
  import json, subprocess, sys

  def test_read_sandbox_emits_json(tmp_path) -> None:
      manifest = tmp_path / "manifest.toml"
      manifest.write_text("""[alfred]
  manifest_version = 1
  [plugin]
  id = "alfred.example"
  subscriber_tier = "user-plugin"
  sandbox_profile = "user-plugin"
  [sandbox]
  kind = "full"
  [sandbox.policy_refs]
  linux = "config/sandbox/foo.linux.bwrap.policy"
  macos = "config/sandbox/foo.macos.sb"
  windows = "config/sandbox/foo.windows.stub.policy"
  """)
      result = subprocess.run(
          [sys.executable, "-m", "alfred.plugins.manifest_reader",
           "--read-sandbox", "--manifest-path", str(manifest)],
          capture_output=True, text=True, check=True,
      )
      payload = json.loads(result.stdout)
      assert payload["kind"] == "full"
      assert payload["policy_refs"]["linux"].endswith(".bwrap.policy")

  def test_read_sandbox_missing_block_refuses(tmp_path) -> None:
      manifest = tmp_path / "manifest.toml"
      manifest.write_text("""[alfred]
  manifest_version = 1
  [plugin]
  id = "alfred.example"
  subscriber_tier = "user-plugin"
  sandbox_profile = "user-plugin"
  """)
      result = subprocess.run(
          [sys.executable, "-m", "alfred.plugins.manifest_reader",
           "--read-sandbox", "--manifest-path", str(manifest)],
          capture_output=True, text=True,
      )
      assert result.returncode != 0
      assert "plugin.manifest_sandbox_block_missing" in result.stderr

  def test_read_environment_emits_value(monkeypatch) -> None:
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
      result = subprocess.run(
          [sys.executable, "-m", "alfred.plugins.manifest_reader",
           "--read-environment"],
          capture_output=True, text=True, check=True,
      )
      assert result.stdout.strip() == "development"

  def test_read_environment_unset_refuses(monkeypatch, tmp_path) -> None:
      monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
      result = subprocess.run(
          [sys.executable, "-m", "alfred.plugins.manifest_reader",
           "--read-environment"],
          capture_output=True, text=True,
          env={"PATH": "/usr/bin:/bin", "ALFRED_ETC_ENV_FILE": str(tmp_path / "no")},
      )
      assert result.returncode != 0
      assert "daemon.boot.environment_not_set" in result.stderr
  ```

  Run → expect ImportError because module doesn't exist.

- [ ] **Task C.2 — Implement `src/alfred/plugins/manifest_reader.py`.**

  ```python
  """Pre-launcher Python helper invoked by bin/alfred-plugin-launcher.sh
  (spec §7.2 — bash launcher reads manifest via this one-shot).

  CLI subcommands:
    --read-sandbox --manifest-path <path>
        Print JSON {kind, policy_refs} from the manifest's [sandbox] block.
        Refuses on missing block / malformed TOML / invalid kind.

    --read-environment
        Print Settings.environment value (development|production|test).
        Refuses (exit 1) if neither ALFRED_ENVIRONMENT env var nor
        /etc/alfred/environment file resolves to a Literal value.

    --policy-to-bwrap-flags
        Read TOML policy from stdin; print the bwrap CLI flags one per line.
        Used by the bash launcher's `kind: full` branch on Linux.

  All output is JSON or simple text on stdout; refusal emits a bare i18n
  key on stderr and exits non-zero. The bash launcher captures stderr and
  the supervisor renders the localised message.

  The module deliberately does the smallest thing per subcommand so each
  invocation is independent — failure of one --read-sandbox call cannot
  corrupt subsequent calls.
  """
  ```

  Implementation outline:

  - argparse with three mutually exclusive subcommands
  - `--read-sandbox`: load manifest via `parse_manifest`; serialise the `sandbox` field via `model_dump_json()`; print to stdout
  - `--read-environment`: import `Settings`; print `Settings().environment`; on `SettingsError` print the bare i18n key to stderr + exit 1
  - `--policy-to-bwrap-flags`: parse stdin as TOML via `tomllib`; pass through `policy_to_bwrap_flags` (from `src/alfred/plugins/sandbox_policy.py` — Component D); print each flag on its own line

  Make C.1's tests pass. `make check`.

  **Note on the env-read carve-out:** the `--read-environment` subcommand reads `os.environ` directly. The Slice-3 `scripts/check_no_direct_env_reads.py` AST guard must allowlist this module (per §4 file table). The carve-out is justified because `manifest_reader.py` is the explicit boundary the bash launcher uses; the alternative would be the bash launcher itself reading env vars, which moves the trust-tier-tagging surface into bash where it cannot be Python-tested.

---

### Component D — Sandbox policy schema + bwrap translator

- [ ] **Task D.1 — Failing test: `policy_to_bwrap_flags` shape.**

  File: `tests/unit/plugins/test_sandbox_policy_translator.py`.

  ```python
  import pytest
  from alfred.plugins.sandbox_policy import SandboxPolicy, policy_to_bwrap_flags

  def test_simple_policy_translates() -> None:
      policy = SandboxPolicy(
          ro_binds=[("/usr/lib/x", "/usr/lib/x")],
          tmpfs=["/tmp"],
          unshare=["pid", "uts", "cgroup", "ipc"],
          die_with_parent=True,
          keep_fds=[3],
      )
      flags = policy_to_bwrap_flags(policy)
      # Order matters — the resolver must emit flags in a stable order so
      # tests don't get flaky across Python dict-ordering changes.
      assert flags == [
          "--ro-bind", "/usr/lib/x", "/usr/lib/x",
          "--tmpfs", "/tmp",
          "--unshare-pid", "--unshare-uts",
          "--unshare-cgroup", "--unshare-ipc",
          "--die-with-parent",
          "--keep-fd", "3",
      ]

  def test_unknown_unshare_kind_refuses() -> None:
      with pytest.raises(ValueError, match="unknown unshare kind"):
          SandboxPolicy(unshare=["zinc"])
  ```

- [ ] **Task D.2 — Implement `SandboxPolicy` + translator.**

  File: `src/alfred/plugins/sandbox_policy.py`.

  ```python
  from typing import Literal, Sequence
  from pydantic import BaseModel, ConfigDict, field_validator

  _VALID_UNSHARE: frozenset[str] = frozenset({
      "pid", "uts", "cgroup", "ipc", "user", "net",
  })

  class SandboxPolicy(BaseModel):
      ro_binds: Sequence[tuple[str, str]] = ()
      rw_binds: Sequence[tuple[str, str]] = ()
      tmpfs: Sequence[str] = ()
      unshare: Sequence[Literal["pid", "uts", "cgroup", "ipc", "user", "net"]] = ()
      die_with_parent: bool = True
      keep_fds: Sequence[int] = (3,)   # fd 3 always kept by default — Supervisor's provider-key channel

      model_config = ConfigDict(frozen=True, extra="forbid")

      @field_validator("unshare")
      @classmethod
      def _validate_unshare(cls, value: Sequence[str]) -> Sequence[str]:
          for v in value:
              if v not in _VALID_UNSHARE:
                  raise ValueError(f"unknown unshare kind: {v!r}")
          return value

  def policy_to_bwrap_flags(policy: SandboxPolicy) -> list[str]:
      flags: list[str] = []
      for src, dst in policy.ro_binds:
          flags += ["--ro-bind", src, dst]
      for src, dst in policy.rw_binds:
          flags += ["--rw-bind", src, dst]
      for path in policy.tmpfs:
          flags += ["--tmpfs", path]
      for kind in policy.unshare:
          flags += [f"--unshare-{kind}"]
      if policy.die_with_parent:
          flags += ["--die-with-parent"]
      for fd in policy.keep_fds:
          flags += ["--keep-fd", str(fd)]
      return flags
  ```

  Make D.1's test pass.

- [ ] **Task D.3 — Ship the fixture policy file.**

  File: `config/sandbox/_fixtures/policy_resolver_test.linux.bwrap.policy`.

  ```toml
  # Fixture policy consumed by tests/integration/test_launcher_policy_resolver.py.
  # NOT the quarantined-LLM policy — that ships in PR-S4-7.
  # This file documents the policy schema PR-S4-6 ships.

  ro_binds = [
      ["/usr/lib", "/usr/lib"],
      ["/etc/ssl/certs", "/etc/ssl/certs"],
  ]
  tmpfs = ["/tmp"]
  unshare = ["pid", "uts", "cgroup", "ipc"]
  die_with_parent = true
  keep_fds = [3]
  ```

  A unit test under `tests/unit/plugins/test_sandbox_policy_translator.py` parses this fixture and asserts the bwrap flag list matches the documented shape — proof the schema sticks across the slice.

---

### Component E — Process posture (core dumps, mlockall)

- [ ] **Task E.1 — Failing test: `disable_core_dumps` sets RLIMIT_CORE = (0, 0).**

  File: `tests/unit/supervisor/test_process_posture.py`.

  ```python
  import resource
  from alfred.supervisor.process_posture import disable_core_dumps, try_mlockall

  def test_disable_core_dumps_sets_zero() -> None:
      # Capture before
      before = resource.getrlimit(resource.RLIMIT_CORE)
      disable_core_dumps()
      after = resource.getrlimit(resource.RLIMIT_CORE)
      assert after == (0, 0)
      # Idempotent
      disable_core_dumps()
      assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)

  def test_try_mlockall_does_not_raise() -> None:
      # On most CI runners we lack CAP_IPC_LOCK; this MUST not raise.
      result = try_mlockall()
      # result is a typed enum: Success | Unavailable(errno_str)
      assert result is not None
  ```

- [ ] **Task E.2 — Implement `process_posture.py`.**

  ```python
  """Supervisor-side process posture (spec §7.5 honest limitations).

  disable_core_dumps() — RLIMIT_CORE = (0, 0). A core dump of the
  Supervisor process would contain the in-memory provider key (the brief
  residency window between SecretBroker.get and fd-3 write). Disabling
  core dumps closes that channel.

  try_mlockall() — Linux best-effort wrapper around the libc mlockall(2)
  syscall. Prevents the Supervisor's pages from swapping to disk. Failure
  (typically missing CAP_IPC_LOCK in containers) is loud (audit row)
  but non-fatal.
  """
  import ctypes
  import os
  import resource
  import sys
  from dataclasses import dataclass
  from typing import Literal

  _MCL_CURRENT = 1
  _MCL_FUTURE = 2

  @dataclass(frozen=True)
  class MlockResult:
      kind: Literal["success", "unavailable"]
      errno_string: str = ""

  def disable_core_dumps() -> None:
      resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

  def try_mlockall() -> MlockResult:
      if sys.platform != "linux":
          return MlockResult(kind="unavailable", errno_string="non-linux platform")
      try:
          libc = ctypes.CDLL("libc.so.6", use_errno=True)
          rc = libc.mlockall(_MCL_CURRENT | _MCL_FUTURE)
          if rc != 0:
              errno = ctypes.get_errno()
              return MlockResult(kind="unavailable", errno_string=os.strerror(errno))
          return MlockResult(kind="success")
      except OSError as exc:
          return MlockResult(kind="unavailable", errno_string=str(exc))
  ```

  Make E.1's tests pass. The audit-row emit on `unavailable` happens at the caller in the daemon boot path (PR-S4-1 owns the emit-site wiring); PR-S4-6 ships the primitive and the contract.

  Note: this task touches `RLIMIT_CORE` for the test process. The test must save and restore the limit in fixture teardown so it doesn't leak across pytest workers.

---

### Component F — Fd-3 provider key delivery

- [ ] **Task F.1 — Failing test: 4-byte length prefix + write-end-closed + gc.collect invoked.**

  File: `tests/unit/supervisor/test_fd3_key_delivery.py`.

  ```python
  import gc, os, struct
  from unittest.mock import patch
  from alfred.supervisor.fd3_key_delivery import deliver_provider_key_via_fd3

  def test_delivery_writes_length_prefix_then_bytes() -> None:
      read_fd, write_fd = os.pipe()
      key = "sk-test-12345"
      key_bytes = key.encode("utf-8")
      # Fake "launcher process": we just consume the read end.
      class FakeProc:
          def __init__(self, write_fd: int) -> None:
              self._write_fd = write_fd
          @property
          def write_fd(self) -> int:
              return self._write_fd

      with patch("alfred.supervisor.fd3_key_delivery.gc.collect") as mock_collect:
          deliver_provider_key_via_fd3(write_fd=write_fd, key=key)
          mock_collect.assert_called_once()

      # write_fd should now be closed
      try:
          os.write(write_fd, b"x")
          raise AssertionError("write_fd should be closed")
      except OSError:
          pass

      # Read framing
      length_prefix = os.read(read_fd, 4)
      assert struct.unpack(">I", length_prefix)[0] == len(key_bytes)
      received = os.read(read_fd, len(key_bytes))
      assert received == key_bytes
      os.close(read_fd)

  def test_delivery_does_not_retain_key_in_locals() -> None:
      # Defensive: after delivery, the function must not hold the key in
      # any module-level attribute. (We cannot prove zero residency in
      # CPython — see spec §7.5 honest limitations — but we can prove
      # the function doesn't leak the key into module state.)
      import alfred.supervisor.fd3_key_delivery as mod
      _, write_fd = os.pipe()
      key = "sk-residency-canary"
      deliver_provider_key_via_fd3(write_fd=write_fd, key=key)
      module_attrs = {name: getattr(mod, name) for name in dir(mod)
                      if not name.startswith("_")}
      for name, value in module_attrs.items():
          if isinstance(value, str):
              assert key not in value, f"key found in module attr {name!r}"
  ```

- [ ] **Task F.2 — Implement `fd3_key_delivery.py`.**

  ```python
  """Provider-key fd-3 delivery (spec §7.5 sec-004 round-4).

  The Supervisor opens a pipe whose write end is held by this module and
  whose read end is fd 3 of the launcher subprocess. We write a 4-byte
  big-endian length prefix + the key bytes, close the write end, then
  invoke gc.collect() so the Python str holding the key is reclaimed at
  earliest opportunity.

  Honest limitation: Python str is interned and non-zeroizable. The brief
  residency window between SecretBroker.get and this function's return is
  measured in microseconds; gc.collect() is mitigation, not elimination.
  Slice-5 SecretBroker.get_bytes(name) -> bytearray will close this.
  """
  import gc
  import os
  import struct

  def deliver_provider_key_via_fd3(write_fd: int, key: str) -> None:
      """Write length-prefix + key bytes to write_fd, close it, then gc.collect.

      Args:
          write_fd: The write end of a pipe whose read end is fd 3 of the
                    launcher subprocess. Caller owns the read-end lifecycle.
          key: The provider key string fetched via SecretBroker.get.
      """
      key_bytes = key.encode("utf-8")
      length_prefix = struct.pack(">I", len(key_bytes))
      try:
          os.write(write_fd, length_prefix)
          os.write(write_fd, key_bytes)
      finally:
          os.close(write_fd)
          # del + collect — best-effort residency reduction. Real
          # zeroization needs SecretBroker.get_bytes (Slice-5+).
          del key_bytes
          gc.collect()
  ```

  Make F.1's tests pass.

  Note: `key: str` arrives at the function boundary. We cannot zeroize the caller's str either (CPython interning). The audit-row emit `provider_key_delivered` (informational, T0 carrier) happens at the caller — PR-S4-7 wires the emit into the actual quarantined-LLM spawn path because the Supervisor's plugin-spawn code is the bigger picture; PR-S4-6 ships the primitive.

---

### Component G — Launcher bash extension

This is the largest component. Each task touches `bin/alfred-plugin-launcher.sh` only — the Slice-3 invariants stay intact.

- [ ] **Task G.1 — Failing test: launcher refuses on environment_not_set.**

  File: `tests/unit/launcher/test_environment_read.py`.

  Strategy: invoke the bash launcher in a subprocess, set `PATH` and `PYTHONPATH` so the embedded `manifest_reader` works, capture stderr.

  ```python
  import os, subprocess, sys
  from pathlib import Path
  REPO_ROOT = Path(__file__).resolve().parents[3]
  LAUNCHER = REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"

  def _launcher_env(env_value: str | None, etc_env_file: Path | None, **extras) -> dict[str, str]:
      base = {
          "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
          "PYTHONPATH": str(REPO_ROOT / "src"),
      }
      if env_value is not None:
          base["ALFRED_ENVIRONMENT"] = env_value
      if etc_env_file is not None:
          base["ALFRED_ETC_ENV_FILE"] = str(etc_env_file)
      base.update(extras)
      return base

  def test_launcher_refuses_when_environment_unset(tmp_path) -> None:
      result = subprocess.run(
          [str(LAUNCHER), "alfred.example", "/bin/true"],
          env=_launcher_env(None, tmp_path / "no-file"),
          capture_output=True, text=True,
      )
      assert result.returncode != 0
      assert "daemon.boot.environment_not_set" in result.stderr
  ```

  Plus tests for env-only, file-only, env-wins-on-conflict (mirrors the C.1 cases at the launcher boundary).

- [ ] **Task G.2 — Add environment-read step to launcher.**

  Edit `bin/alfred-plugin-launcher.sh`. Insert AFTER the charset-validation block, BEFORE the existing `ALFRED_ENV` / `UNSANDBOXED` env reads:

  ```bash
  # Read Settings.environment via the pre-launcher Python helper. This is the
  # PR-S4-6 dual-source resolver: ALFRED_ENVIRONMENT env var (primary) >
  # /etc/alfred/environment file (fallback). Neither set → refuse.
  if ! ALFRED_RESOLVED_ENVIRONMENT="$(python3 -m alfred.plugins.manifest_reader --read-environment 2>&1 >/dev/null)"; then
      # manifest_reader prints bare i18n key to stderr; we redirected stdout
      # to /dev/null and captured stderr in $ALFRED_RESOLVED_ENVIRONMENT
      printf '%s\n' "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
      exit 1
  fi
  # Re-run capturing stdout this time (the first call only validated)
  ALFRED_RESOLVED_ENVIRONMENT="$(python3 -m alfred.plugins.manifest_reader --read-environment)"
  ```

  (Two invocations is mildly wasteful; the simpler alternative is to capture stdout and stderr separately via process substitution, which is non-POSIX. The current Slice-3 launcher convention is plain POSIX sh-compat-ish bash; we keep it. Performance cost is ~10ms once per plugin spawn — negligible.)

  Make G.1's tests pass.

- [ ] **Task G.3 — Failing test: dev escape hatch refuses in production.**

  File: `tests/unit/launcher/test_dev_escape_hatch_prod_refusal.py`.

  ```python
  def test_unsandboxed_in_production_refuses(tmp_path) -> None:
      result = subprocess.run(
          [str(LAUNCHER), "alfred.example", "/bin/true"],
          env=_launcher_env(
              env_value="production",
              etc_env_file=None,
              ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED="1",
          ),
          capture_output=True, text=True,
      )
      assert result.returncode != 0
      assert "supervisor.sandbox.unsandboxed_refused_in_production" in result.stderr
      # The structured JSON audit row also fires on stderr (separate line)
      assert "unsandboxed_env_set_in_production" in result.stderr

  def test_unsandboxed_in_development_proceeds(tmp_path) -> None:
      # Stub plugin binary
      stub = tmp_path / "stub"
      stub.write_text("#!/bin/sh\nexit 42\n")
      stub.chmod(0o755)
      result = subprocess.run(
          [str(LAUNCHER), "alfred.example", str(stub)],
          env=_launcher_env(
              env_value="development",
              etc_env_file=None,
              ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED="1",
              ALFRED_SANDBOX_POLICY_DIR=str(tmp_path),  # so policy lookup fails-through to dev path
          ),
          capture_output=True, text=True,
      )
      assert result.returncode == 42, f"got {result.returncode} stderr={result.stderr!r}"
  ```

- [ ] **Task G.4 — Add prod-refusal branch.**

  Edit `bin/alfred-plugin-launcher.sh`. The Slice-3 launcher already has a production-refusal for the UNSANDBOXED flag — verify with `grep -n "unsandboxed_rejected" bin/alfred-plugin-launcher.sh`. The existing branch refuses when `ALFRED_ENV != development && UNSANDBOXED == 1`. The Slice-4 change:

  - Replace the `ALFRED_ENV` read with the new `ALFRED_RESOLVED_ENVIRONMENT` from G.2.
  - Change the bare-key from `plugin.launcher_unsandboxed_rejected` to `supervisor.sandbox.unsandboxed_refused_in_production` (the spec's i18n key; the existing key was Slice-3's pre-spec name and the i18n catalog acquires both keys for backward compat — the old key stays valid for any Slice-3 caller, the new key is what the operator sees from Slice-4 onwards).
  - Also emit the structured JSON audit row using `SANDBOX_REFUSED_FIELDS` shape (PR-S4-0a constant):

  ```bash
  if [ "${ALFRED_RESOLVED_ENVIRONMENT}" = "production" ] && [ "${UNSANDBOXED}" = "1" ]; then
      printf 'supervisor.sandbox.unsandboxed_refused_in_production plugin_id=%s\n' "${PLUGIN_ID}" >&2
      printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"unsandboxed_env_set_in_production","environment":"production","host_os":"%s"}\n' "${PLUGIN_ID}" "$(uname -s | tr A-Z a-z)" >&2
      exit 1
  fi
  ```

  Make G.3's tests pass.

- [ ] **Task G.5 — Failing test: sandbox-kind branching.**

  File: `tests/unit/launcher/test_sandbox_kind_branching.py`. Three sub-tests:

  - `kind: full` → bwrap invocation observed (use a `BWRAP=/path/to/echo-bwrap-args` env var override the launcher honours; ship `tests/fixtures/echo-bwrap.sh` that prints its args + exits 0; assert `--keep-fd 3` appears in the printed args).
  - `kind: none` → falls through to existing Slice-3 `_do_exec` (runuser path on Linux; direct exec on macOS-dev).
  - `kind: stub` in prod → refuses with `windows_stub_in_production`.
  - `kind: stub` in dev → emits SANDBOX_STUB_USED_FIELDS JSON + execs the binary.

- [ ] **Task G.6 — Add sandbox-kind branching.**

  Edit `bin/alfred-plugin-launcher.sh`. After the prod-refusal branch, BEFORE the existing policy-file check:

  ```bash
  # Read the manifest's [sandbox] block via the pre-launcher Python helper.
  # The helper prints a JSON line like
  # {"kind":"full","policy_refs":{"linux":"...","macos":"...","windows":"..."}}
  # On failure (missing block / malformed TOML / unknown kind) it exits non-zero
  # with a bare i18n key on stderr.
  if ! SANDBOX_JSON="$(python3 -m alfred.plugins.manifest_reader --read-sandbox --plugin-id "${PLUGIN_ID}" 2>&1)"; then
      printf '%s\n' "${SANDBOX_JSON}" >&2
      printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"sandbox_block_missing","environment":"%s","host_os":"%s"}\n' \
          "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "$(uname -s | tr A-Z a-z)" >&2
      exit 1
  fi

  # jq is required on alfred-core (PR-S4-0b apt-installs it). Refuse loudly if
  # missing — the resolver is unimplementable without a JSON parser in bash.
  if ! command -v jq >/dev/null 2>&1; then
      printf 'supervisor.sandbox.jq_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
      exit 1
  fi

  SANDBOX_KIND="$(printf '%s\n' "${SANDBOX_JSON}" | jq -r '.kind')"
  HOST_OS="$(uname -s | tr A-Z a-z)"
  # uname returns "Linux" / "Darwin" / "MINGW64_NT-*"; normalise:
  case "${HOST_OS}" in
      linux) HOST_OS="linux" ;;
      darwin) HOST_OS="macos" ;;
      mingw* | msys* | cygwin*) HOST_OS="windows" ;;
      *)
          printf 'supervisor.sandbox.unknown_host_os plugin_id=%s host_os=%s\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
          exit 1
          ;;
  esac

  case "${SANDBOX_KIND}" in
      full)
          POLICY_REF="$(printf '%s\n' "${SANDBOX_JSON}" | jq -r ".policy_refs.\"${HOST_OS}\"")"
          if [ "${POLICY_REF}" = "null" ] || [ -z "${POLICY_REF}" ]; then
              printf 'supervisor.sandbox.policy_ref_missing plugin_id=%s host_os=%s\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
              printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"policy_ref_missing","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
              exit 1
          fi
          if [ ! -r "${POLICY_REF}" ]; then
              printf 'supervisor.sandbox.policy_ref_unreadable plugin_id=%s policy_ref=%s\n' "${PLUGIN_ID}" "${POLICY_REF}" >&2
              printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","policy_ref":"%s","reason":"policy_ref_unreadable","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
              exit 1
          fi
          case "${HOST_OS}" in
              linux)
                  # Translate TOML policy into bwrap flags via the pre-launcher
                  # helper; one flag per line.
                  BWRAP_FLAGS_FILE="$(mktemp)"
                  if ! python3 -m alfred.plugins.manifest_reader --policy-to-bwrap-flags < "${POLICY_REF}" > "${BWRAP_FLAGS_FILE}"; then
                      printf 'supervisor.sandbox.policy_translate_failed plugin_id=%s\n' "${PLUGIN_ID}" >&2
                      rm -f "${BWRAP_FLAGS_FILE}"
                      exit 1
                  fi
                  # Read flags into a bash array
                  BWRAP_FLAGS=()
                  while IFS= read -r flag; do
                      BWRAP_FLAGS+=("${flag}")
                  done < "${BWRAP_FLAGS_FILE}"
                  rm -f "${BWRAP_FLAGS_FILE}"
                  : "${BWRAP:=bwrap}"   # tests override via BWRAP env
                  exec "${BWRAP}" "${BWRAP_FLAGS[@]}" -- "${EXECUTABLE}" "$@"
                  ;;
              macos)
                  # PR-S4-7 ships sandbox-exec invocation; PR-S4-6 ships a
                  # refusal so the resolver path is well-defined.
                  printf 'supervisor.sandbox.macos_full_not_yet_shipped plugin_id=%s\n' "${PLUGIN_ID}" >&2
                  exit 1
                  ;;
              windows)
                  # kind:full on Windows means "stub policy file present" —
                  # the stub's body says PRD non-compliant. Fall through to
                  # the stub-handling branch.
                  printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"windows_stub_in_production","environment":"%s","host_os":"windows"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
                  if [ "${ALFRED_RESOLVED_ENVIRONMENT}" = "production" ]; then
                      exit 1
                  fi
                  printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","policy_ref":"%s","host_os":"windows","environment":"development"}\n' "${PLUGIN_ID}" "${POLICY_REF}" >&2
                  exec "${EXECUTABLE}" "$@"
                  ;;
          esac
          ;;
      none)
          # Slice-3 baseline: UID-separated runuser path on Linux; direct
          # exec on macOS-dev. _do_exec function is already defined.
          _do_exec "$@"
          ;;
      stub)
          if [ "${ALFRED_RESOLVED_ENVIRONMENT}" = "production" ]; then
              printf 'supervisor.sandbox.windows_stub_in_production plugin_id=%s\n' "${PLUGIN_ID}" >&2
              printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"windows_stub_in_production","environment":"production","host_os":"%s"}\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
              exit 1
          fi
          printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","host_os":"%s","environment":"development"}\n' "${PLUGIN_ID}" "${HOST_OS}" >&2
          exec "${EXECUTABLE}" "$@"
          ;;
  esac
  ```

  Make G.5's tests pass.

  **Note on bash arrays + POSIX.** The launcher's `set -eu` and absence of `pipefail` matches the existing Slice-3 convention. The new branching introduces a bash array (`BWRAP_FLAGS=()`) which is bashism, not POSIX sh. The shebang is `#!/usr/bin/env bash` — this is fine. If a downstream platform forces POSIX-sh-only, the array can be replaced with a temp-file-and-`eval` pattern; we don't pre-optimise.

- [ ] **Task G.7 — Failing test: policy-ref OS-mismatch path.**

  File: `tests/unit/launcher/test_policy_ref_resolution.py`.

  ```python
  def test_policy_ref_missing_for_host_os(tmp_path) -> None:
      manifest_dir = tmp_path / "plugins" / "alfred.example"
      manifest_dir.mkdir(parents=True)
      manifest = manifest_dir / "manifest.toml"
      manifest.write_text("""[alfred]
  manifest_version = 1
  [plugin]
  id = "alfred.example"
  subscriber_tier = "user-plugin"
  sandbox_profile = "user-plugin"
  [sandbox]
  kind = "full"
  [sandbox.policy_refs]
  macos = "config/sandbox/foo.macos.sb"
  """)
      # Run on Linux — manifest lacks linux key → policy_ref_missing
      stub_binary = tmp_path / "bin"
      stub_binary.write_text("#!/bin/sh\nexit 0\n")
      stub_binary.chmod(0o755)
      result = subprocess.run(
          [str(LAUNCHER), "alfred.example", str(stub_binary)],
          env=_launcher_env(
              env_value="development",
              etc_env_file=None,
              ALFRED_PLUGIN_MANIFEST_PATH=str(manifest),  # override for the test
          ),
          capture_output=True, text=True,
      )
      assert result.returncode != 0
      assert "policy_ref_missing" in result.stderr
  ```

- [ ] **Task G.8 — Wire the `ALFRED_PLUGIN_MANIFEST_PATH` test-override into `manifest_reader.py`.**

  The launcher invokes `manifest_reader --read-sandbox --plugin-id <id>`. The reader, in the production path, looks up the manifest at `plugins/<plugin_id>/manifest.toml`. Tests need to override this. Solution: `--manifest-path` flag takes precedence over `--plugin-id`. The launcher passes `--plugin-id`; tests pass `--manifest-path` directly OR set `ALFRED_PLUGIN_MANIFEST_PATH` which the launcher forwards as `--manifest-path`.

  Edit `manifest_reader.py` to accept either flag. Edit the launcher's `--read-sandbox` invocation to forward `${ALFRED_PLUGIN_MANIFEST_PATH:+--manifest-path ${ALFRED_PLUGIN_MANIFEST_PATH}}` when set.

  Make G.7's tests pass.

---

### Component H — Hookpoint registration

- [ ] **Task H.1 — Failing test: hookpoints registered.**

  File: `tests/unit/hooks/test_sandbox_hookpoints_registered.py`.

  ```python
  from alfred.hooks.registry import get_hookpoint_meta

  def test_sandbox_refused_hookpoint_registered() -> None:
      meta = get_hookpoint_meta("supervisor.plugin.sandbox_refused")
      assert meta.carrier_tier == "T0"
      assert meta.fail_closed is True

  def test_mlock_unavailable_hookpoint_registered() -> None:
      meta = get_hookpoint_meta("supervisor.boot.mlock_unavailable")
      assert meta.carrier_tier == "T0"
      assert meta.fail_closed is False

  def test_core_dumps_disabled_hookpoint_registered() -> None:
      meta = get_hookpoint_meta("supervisor.boot.core_dumps_disabled")
      assert meta.carrier_tier == "T0"
      assert meta.fail_closed is False
  ```

- [ ] **Task H.2 — Register hookpoints.**

  Edit the relevant `register_hookpoint(...)` call site (Slice-3 has a module-level registration helper at `src/alfred/hooks/registry.py`; PR-S4-3 may have refactored this slightly — verify before editing). Add three new registrations with the metadata above. Confirm the PR-S4-3 AST guard passes (every registration has `carrier_tier=`).

  Make H.1's tests pass. `make check`.

---

### Component I — Adversarial corpus entries

- [ ] **Task I.1 — Failing test: adversarial entries land under correct prefix.**

  File: `tests/adversarial/sandbox_escape/test_manifest_sandbox_bypass.py`.

  Per PR-S4-0a's `_PREFIX_TO_CATEGORY` map, IDs prefixed `sbx-` route to category `sandbox_escape`. Entries to ship:

  - `sbx-2026-001 manifest_omits_sandbox_block` — manifest without `[sandbox]`; load refused with `reason="sandbox_block_missing"`.
  - `sbx-2026-002 attacker_plants_kind_stub_on_production_plugin` — production daemon sees `kind: stub`; refused with `reason="windows_stub_in_production"`.
  - `sbx-2026-003 attacker_plants_policy_ref_outside_install_tree` — manifest declares `linux = "/etc/passwd"` (or `../../etc/passwd`); the launcher reads the file but the contents are NOT a valid TOML policy; `policy_translate_failed` fires. (Defence in depth: the *secondary* defence is the policy translator refusing malformed TOML. The *primary* defence is bwrap's filesystem isolation refusing to actually mount /etc/passwd as a policy file in the sandbox — that's PR-S4-7's territory. PR-S4-6 covers the secondary defence.)

  ```python
  from pathlib import Path
  import subprocess

  def test_sbx_2026_001_sandbox_block_missing(launcher_fixture, ...) -> None:
      # Manifest without [sandbox]; launcher refuses with sandbox_block_missing
      ...

  def test_sbx_2026_002_kind_stub_in_production(launcher_fixture, ...) -> None:
      # production env + kind:stub → refused
      ...

  def test_sbx_2026_003_policy_ref_outside_tree(launcher_fixture, ...) -> None:
      # policy_ref points at /etc/passwd → policy_translate_failed
      ...
  ```

  Plus YAML-spec entries under `tests/adversarial/corpus/sandbox_escape/`:

  ```yaml
  # tests/adversarial/corpus/sandbox_escape/sbx-2026-001.yaml
  id: sbx-2026-001
  category: sandbox_escape
  summary: Manifest omits [sandbox] block; load refused.
  payload:
    manifest_toml: |
      [alfred]
      manifest_version = 1
      [plugin]
      id = "attacker.example"
      subscriber_tier = "user-plugin"
      sandbox_profile = "user-plugin"
  expected:
    audit_row: SANDBOX_REFUSED_FIELDS
    reason: sandbox_block_missing
  ```

  (Three YAMLs + the test module that loads each YAML and runs the launcher against it.)

  Run → expect failure (tests don't exist).

- [ ] **Task I.2 — Implement the corpus entries.**

  Write the YAML fixtures and the test runner that loops over the corpus loading each YAML, building a fixture manifest, invoking the launcher, and asserting the expected `reason`.

  Make I.1's tests pass. The `tests/unit/adversarial/test_slice_4_categories.py` AST guard from PR-S4-0a should already be green — the `sbx-` prefix is already mapped.

- [ ] **Task I.3 — Failing test: key inheritance under strace.**

  File: `tests/adversarial/sandbox_escape/test_launcher_key_inheritance.py`.

  ```python
  import os, pytest, shutil, subprocess

  @pytest.mark.skipif(not shutil.which("strace"), reason="strace required")
  def test_sbx_2026_004_launcher_does_not_read_fd3(tmp_path, ...) -> None:
      # Strace the launcher process; assert it never read(2)'s from fd 3.
      # The spawned plugin (real Python binary that does read fd 3) is fine.
      strace_log = tmp_path / "strace.log"
      subprocess.run(
          ["strace", "-f", "-e", "read", "-o", str(strace_log),
           str(LAUNCHER), "alfred.example", "/usr/bin/python3", "-c",
           "import os; os.read(3, 4)"],
          env=...,
      )
      # Parse strace output: launcher PID never reads fd 3
      launcher_pid_lines = [...]
      for line in launcher_pid_lines:
          assert "read(3" not in line
  ```

  This is sbx-2026-004 / sbx-2026-005 per spec §7.5. Skipped if strace not on PATH (macOS / dev). CI runs on Linux with strace available.

- [ ] **Task I.4 — Make I.3 pass.**

  Verify the launcher's bash code never references fd 3 in any `read` call. The `--keep-fd 3` flag to bwrap is the only fd-3 touch; bash itself never reads. The test should pass on first try — the launcher was designed for this.

---

### Component J — Integration test (merge-blocking)

- [ ] **Task J.1 — Ship `tests/integration/test_launcher_policy_resolver.py`.**

  Per Slice-4 index §4, this is the merge-blocking integration test PR-S4-6 owns. It exercises the resolver end-to-end with real subprocesses (no mocks):

  ```python
  import json, os, shutil, subprocess, sys
  import pytest
  from pathlib import Path
  REPO_ROOT = Path(__file__).resolve().parents[2]
  LAUNCHER = REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"
  FIXTURE_POLICY = REPO_ROOT / "config" / "sandbox" / "_fixtures" / "policy_resolver_test.linux.bwrap.policy"

  @pytest.mark.skipif(not shutil.which("bwrap"), reason="bwrap required for full integration")
  def test_resolver_invokes_bwrap_with_keep_fd_3(tmp_path) -> None:
      # Build a fixture plugin: a Python script that prints OK if fd 3 is set
      stub = tmp_path / "stub.py"
      stub.write_text("""
  import os, struct, sys
  prefix = os.read(3, 4)
  length, = struct.unpack(">I", prefix)
  key = os.read(3, length).decode()
  print(f"GOT key=len{len(key)}", flush=True)
  sys.exit(0)
  """)
      # Fixture manifest pointing at the fixture policy
      manifest = tmp_path / "plugins" / "alfred.fixture" / "manifest.toml"
      manifest.parent.mkdir(parents=True)
      manifest.write_text(f"""[alfred]
  manifest_version = 1
  [plugin]
  id = "alfred.fixture"
  subscriber_tier = "user-plugin"
  sandbox_profile = "user-plugin"
  [sandbox]
  kind = "full"
  [sandbox.policy_refs]
  linux = "{FIXTURE_POLICY}"
  macos = "{FIXTURE_POLICY}"
  windows = "{FIXTURE_POLICY}"
  """)
      # Open a pipe; fd 3 of the child is the read end
      read_fd, write_fd = os.pipe()
      env = {
          "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
          "PYTHONPATH": str(REPO_ROOT / "src"),
          "ALFRED_ENVIRONMENT": "test",
          "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
      }
      proc = subprocess.Popen(
          [str(LAUNCHER), "alfred.fixture", sys.executable, str(stub)],
          env=env,
          pass_fds=(read_fd,),  # the launcher's fd 3 becomes our read_fd
          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
      )
      os.close(read_fd)
      # Write the framed key
      key = b"sk-fixture-12345"
      os.write(write_fd, len(key).to_bytes(4, "big"))
      os.write(write_fd, key)
      os.close(write_fd)
      stdout, stderr = proc.communicate(timeout=10)
      assert proc.returncode == 0, f"stderr={stderr}"
      assert "GOT key=len16" in stdout
  ```

  Also assert:
  - The audit-row JSON `{"event":"supervisor.plugin.sandbox_refused", ...}` does NOT appear on stderr (refusal path didn't fire).
  - When the manifest is mutated to omit `[sandbox]`, the audit JSON DOES appear.

  Make this test pass via the cumulative behaviour from Components A-H.

- [ ] **Task J.2 — Add to required-status-check.**

  Per index ops-007: each merge-blocking integration test is promoted to required status check **in the PR that ships it** (not bulked into S4-11). Update `.github/workflows/integration-tests.yml` (or the equivalent gating workflow) to include `tests/integration/test_launcher_policy_resolver.py` in the merge-blocking matrix. Update the tracked required-checks manifest (`docs/ci/required-checks.md` per the slice-2.5 precedent).

  Follow the `author-gating-workflow` skill if uncertain about the promotion steps.

---

### Component K — Documentation back-patch

- [ ] **Task K.1 — Update `docs/subsystems/supervisor.md`.**

  Add a section "Sandbox launcher policy resolution (PR-S4-6)" describing:
  - The pre-launcher Python helper's role
  - The manifest `[sandbox]` block shape
  - The `Settings.environment` dual-source resolver
  - The dev escape hatch's production-refusal semantics
  - The fd-3 inheritance pattern
  - The honest residency-window limitation and the Slice-5 path

- [ ] **Task K.2 — Update `docs/glossary.md`.**

  PR-S4-0a added initial entries for *sandbox kind*, *policy_ref*, *fd-3 inheritance*. PR-S4-6 fleshes them out with implementation-grounded descriptions:

  - **policy_refs (plural)** — the per-OS map in the manifest's `[sandbox]` block. See PR-S4-6.
  - **launcher policy-resolving probe** — the daemon-boot check that the launcher's resolver branch is live. PR-S4-1 calls this probe at boot; PR-S4-6 makes the probe meaningful.
  - **fd-3 inheritance** — the kernel-managed pattern by which the Supervisor delivers a secret to a sandboxed plugin without bash buffering the bytes. `bwrap --keep-fd 3` is the documented invocation.
  - **honest residency window** — the brief microsecond interval when a Python `str` holds the provider key in the Supervisor process. Acknowledged limitation; closed by Slice-5 `SecretBroker.get_bytes`.

- [ ] **Task K.3 — Update `docs/runbooks/`.**

  Append a section to `docs/runbooks/slice-3-plugins.md` (the existing launcher runbook) noting:
  - PR-S4-6 ADDS the `[sandbox]` manifest requirement (existing third-party plugins must declare it).
  - Before deploying PR-S4-6 to production, ensure `bwrap ≥ 0.6` is on PATH (apt-installed via PR-S4-0b's Dockerfile).
  - Ensure `ALFRED_ENVIRONMENT` is set (env var OR `/etc/alfred/environment` file).
  - The PR-S4-11 graduation runbook will consolidate this guidance.

---

### Component L — Coverage + final gates

- [ ] **Task L.1 — 100% line + branch coverage.**

  Per CLAUDE.md hard rule: 100% on every trust-boundary file. The new files in this PR ALL qualify:

  - `src/alfred/plugins/manifest_reader.py`
  - `src/alfred/plugins/sandbox_policy.py`
  - `src/alfred/supervisor/process_posture.py`
  - `src/alfred/supervisor/fd3_key_delivery.py`
  - The modified `src/alfred/plugins/manifest.py` (the sandbox-parsing additions; full file already had coverage from Slice 3)
  - The modified `src/alfred/config/settings.py` (the environment-field additions)
  - The modified `bin/alfred-plugin-launcher.sh` — bash branch coverage via `bashcov` (per `Makefile`'s `make check` step from slice-3 if installed; otherwise document the test surface coverage manually in PR description)

  Run `uv run pytest --cov=src/alfred/plugins/manifest_reader --cov=src/alfred/plugins/sandbox_policy --cov=src/alfred/supervisor/process_posture --cov=src/alfred/supervisor/fd3_key_delivery --cov-branch --cov-fail-under=100`. Fix gaps until green.

- [ ] **Task L.2 — Adversarial suite.**

  Per CLAUDE.md hard rule: this PR touches `src/alfred/security/` indirectly (the secret-broker fetch + the fd-3 delivery). Run `uv run pytest tests/adversarial` and confirm green. New sandbox_escape entries from Component I should all pass.

- [ ] **Task L.3 — `make check`.**

  Lint, format, type-check, unit tests. All green.

- [ ] **Task L.4 — i18n catalog compile.**

  `uv run pybabel compile --check` — confirm no drift. The new keys from Component G must be in the catalog.

- [ ] **Task L.5 — Manifest snapshot test.**

  Add `tests/unit/plugins/test_quarantined_llm_manifest_snapshot.py` that parses `plugins/alfred_quarantined_llm/manifest.toml`, dumps the `sandbox` block, and snapshot-asserts the shape. This catches drift in B.3's migration over time.

- [ ] **Task L.6 — PR description.**

  Per CLAUDE.md and the Slice-4 index §5 quality gate, the PR description must:

  - State this is **PR-S4-6**, references Slice 4 index, references PR-S4-3 + PR-S4-0a + PR-S4-0b as dependencies.
  - Conventional-commit format `feat(supervisor)` or `feat(plugins)` plus `(#NNN)` (the spec §5 gate).
  - Note that PR-S4-7 must land before production booting of the quarantined-LLM. Production deployments of *just* PR-S4-6 will see `policy_ref_unreadable` refusals — correct fail-closed behaviour during slice mid-flight.
  - Include the adversarial-suite result block.
  - Reference the merge-blocking integration test promoted under this PR.

---

## §7 Risk register

| Risk | Mitigation | Severity |
|---|---|---|
| `bwrap` missing on alfred-core image after PR-S4-0b → all `kind: full` plugin spawns refuse | PR-S4-0b's Dockerfile change is a hard dependency; the integration test `test_launcher_policy_resolver.py` is skip-if-bwrap-missing locally but **required** in CI; CI image MUST have bwrap. PR description verifies. | HIGH |
| Bash-launcher complexity grows past 400 lines, making review hard | Component G splits across seven sub-tasks; each task adds a tightly-scoped block; bash's `set -eu` catches missing-arg errors loudly | MEDIUM |
| `manifest_reader.py` Python startup cost (~50ms per invocation) becomes a plugin-spawn perf regression | Slice-3 baseline already spawns Python for each plugin; one additional manifest-reader subprocess adds ~50ms per spawn. Plugin spawns are not hot-path (the daemon spawns each plugin once at boot). Spec §7.5 perf envelope is silent — Slice-4 graduation runbook documents the cost | LOW |
| Spec §7.1 wrote `policy_ref` (singular) while §7.8 wrote `policy_refs` (plural). Resolver shape ambiguous | §5 of this plan resolves: the plural form is load-bearing; the singular form is a draft holdover. Integration tests assert the plural shape. Document in PR description | MEDIUM |
| `kind: full` on macOS without PR-S4-7 → refusal | This is the correct fail-closed behaviour. macOS dev work uses `kind: none` via the dev-escape-hatch path. Document in K.3 | LOW |
| Spec §7.5 acknowledged residency window in Python `str` is a real CVE-class risk if the host process leaks memory | Slice-5 SecretBroker.get_bytes closes this. PR-S4-6 documents in §6 task F.2's docstring. PR description calls out as known limitation | MEDIUM |
| `--keep-fd 3` not present in bwrap < 0.4 | PR-S4-0b's apt install gives bwrap ≥ 0.6 on alfred-core. CI image gates on bwrap version. PR description states the floor | LOW |
| Test process `RLIMIT_CORE` mutation leaks across pytest workers | E.1 test fixture saves and restores via try/finally; uses pytest's `monkeypatch` discipline | LOW |
| `ALFRED_ENVIRONMENT` env-var name conflicts with `ALFRED_ENV` (already in use by capability-gate selector at `bootstrap/gate_factory.py:64`) | Spec §7.3 uses `ALFRED_ENVIRONMENT`; capability-gate uses `ALFRED_ENV`. These are intentionally separate names with distinct semantics. PR description documents the distinction. The Slice-4 graduation runbook clarifies for operators | MEDIUM |
| `manifest_reader --read-environment` reading `os.environ` directly violates the sec-007 no-direct-env-reads guard | The §4 file table adds `manifest_reader.py` to the AST-scan allowlist. The carve-out is justified because `manifest_reader.py` is the explicit boundary the bash launcher uses; the alternative (bash reads env vars directly) is worse | LOW |

---

## §8 Out-of-scope (deferred)

Per the spec and the brief:

- **Per-OS policy bytes** — Linux bwrap policy + macOS sandbox-exec policy + Windows stub policy for the quarantined-LLM specifically. PR-S4-7.
- **Comms adapter manifests** declaring `sandbox.kind: none`. PR-S4-9 (Discord), PR-S4-10 (TUI). Both use this PR's manifest schema unchanged.
- **`SecretBroker.get_bytes(name) -> bytearray`** zeroizable accessor. Slice 5+. The residency-window limitation in §6 Task F.2 stays acknowledged until then.
- **`alfred sandbox lint <plugin>`** CLI for validating third-party plugins' policy refs without spawning. Slice 5+ per index §1.2.
- **`alfred daemon start` boot-path emit-site wiring** for `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` and `SUPERVISOR_BOOT_MLOCK_UNAVAILABLE_FIELDS` and `SUPERVISOR_BOOT_CORE_DUMPS_DISABLED_FIELDS`. PR-S4-6 ships the primitives + accessors; PR-S4-1 wires the emits into the daemon CLI.
- **The launcher policy-resolving probe** consumed by PR-S4-1's pre-`TaskGroup` boot sequence. PR-S4-6 ships the resolver itself (which the probe will exercise); PR-S4-1 ships the probe-shape (currently a no-op stub per arch-001 closure). PR-S4-1's plan owns the probe wiring once both PRs are in flight.
- **macOS `kind: full` actual sandbox-exec invocation.** PR-S4-7. PR-S4-6 ships the refusal path so the resolver is well-defined on macOS.
- **Adversarial-test runtime escape attempts** (bwrap filesystem escape, network escape, subprocess escape). PR-S4-7 — those need the real policy bytes to be meaningful.

---

## §9 References

- Spec §7 entire: [docs/superpowers/specs/2026-06-06-slice-4-design.md §7](../specs/2026-06-06-slice-4-design.md#7-sandbox-containerisation-adr-0015)
- Slice-4 index §3 sandbox-manifest contract: [docs/superpowers/plans/2026-06-07-slice-4-index.md §3](./2026-06-07-slice-4-index.md#sandbox-plugin-manifest-declaration--launcher-contract-defined-in-pr-s4-6-consumed-by-pr-s4-78910)
- ADR-0015 (Proposed; flips Accepted at PR-S4-11): containerised quarantined-LLM
- ADR-0017 (Accepted): Slice-3 trust-tier completion — manifest_version pinned, UID-separated baseline
- PRD §5 line 117: hybrid-isolation invariant — closed by Slice 4 graduation
- CLAUDE.md security rules 1, 2, 6, 7: secret handling + capability gate + audit-write discipline + no silent failures
- Bash launcher convention precedent: `bin/alfred-plugin-launcher.sh` (Slice-3) — `set -eu`, no `pipefail`, bare i18n keys on stderr
- Slice-4 backlog seed for Slice-5 SecretBroker enhancements: index §8

---

## §10 Definition of done

- [ ] All Component A-L tasks complete; every test in §6 green.
- [ ] `make check` green.
- [ ] `uv run pytest tests/adversarial` green.
- [ ] `uv run pytest tests/integration/test_launcher_policy_resolver.py` green on CI.
- [ ] Coverage 100% line + branch on the five new/modified trust-boundary files.
- [ ] Required-status-check promotion landed for the integration test (per ops-007).
- [ ] `docs/glossary.md`, `docs/subsystems/supervisor.md`, `docs/runbooks/slice-3-plugins.md` updates landed.
- [ ] PR description references PR-S4-3 + PR-S4-0a + PR-S4-0b dependencies; flags the Slice-5 residency-window limitation; states the bwrap version floor.
- [ ] `/review-pr` round green from `alfred-architect`, `alfred-reviewer`, `alfred-test-engineer`, `alfred-security-engineer`. Cross-provider review preferred — when handing off, request a different model than the one used here.
- [ ] No fabricated surfaces in the implementation — every cited Slice-3 or PR-S4-0a/0b/3 symbol verified by grep before invocation. Drift discovered during implementation flagged in the PR description, not papered over.
