# PR-S4-7: Sandbox Policies — Implementation Plan

> **fd-3 delivery — SUPERSEDING NOTE (#152 / #229, supersedes #218 + #210).**
> This plan was authored when the launcher was believed to emit a bwrap fd
> flag (`--keep-fd 3`, later `--sync-fd 3`) to deliver the provider key over
> fd 3. **Both are wrong.** Empirically proven in a docker `bwrap` repro
> against the production image (Debian Bookworm, bubblewrap 0.8.0) and 0.9.0:
> bwrap inherits open, non-CLOEXEC fds (fd 3) into the sandboxed child **BY
> DEFAULT — NO CLI flag**. `--sync-fd` is bwrap's *internal* sync fd and
> CONSUMES fd 3 if pointed at it (the child's `os.read(3)` raises EBADF). The
> translator therefore emits NO fd flag; `keep_fds` is a validated declaration
> only (arch-2). Wherever this plan says `--sync-fd 3` / `--keep-fd 3` for
> fd-3 delivery, read: **no fd flag — bwrap inherits fd 3 by default.** The
> Linux policy file must NOT carry any fd-keep directive. ADR-0015's flag
> section owns the final truth.

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is trust-boundary work — TDD is HARD here, not advisory. Every policy byte you ship is a kernel-enforced control, and the adversarial corpus this PR also ships is the only thing standing between a misconfigured-policy regression and a silent escape.

**Goal:** Ship the three per-OS sandbox policy files the launcher (PR-S4-6) resolves, the merge-blocking integration test that proves the Linux policy is kernel-enforced, the macOS advisory variant, and the adversarial sandbox-escape corpus (`sbx-2026-*`) covering insider-author / runtime-compromised / misconfigured-policy attacker models. Migrate the quarantined-LLM `manifest.toml` to `sandbox.kind = "full"` if PR-S4-6 has not already done so (verification gate, not duplicate work) — and register the `supervisor.plugin.sandbox_stub_used` hookpoint that PR-S4-6 reserved.

**Architecture:** The launcher resolves the OS-specific policy from the manifest's `sandbox.policy_refs` map. On Linux the policy is a declarative file the launcher translates into `bwrap` flags before `exec`. On macOS it is a sandbox-exec scheme file passed verbatim to `/usr/bin/sandbox-exec -f`. On Windows the stub file is read, the launcher refuses in production, and emits `supervisor.plugin.sandbox_stub_used` in development. This PR ships only the policy bytes + tests; the launcher's policy-resolution logic is PR-S4-6's territory (one-time ownership rule, index §3).

**Tech Stack:** bwrap 0.8+ (Linux, apt-installed by PR-S4-0b's `alfred-core` Dockerfile) · `sandbox-exec` (macOS, system-bundled, deprecated-but-functional) · TOML (Windows stub) · pytest + `pytest-asyncio` · adversarial harness from `tests/adversarial/payload_schema.py` (PR-S4-0a `sandbox_escape` category + `sbx` prefix shipped) · `strace` (Linux runner) / `dtruss` (macOS runner) for fd-3 inheritance test · GitHub Actions matrix (`ubuntu-latest` merge-blocking, `macos-latest` advisory).

**Depends on:**

- **PR-S4-0a** (merged) — `sandbox_escape` Literal + `sbx` prefix in `_PREFIX_TO_CATEGORY` + `_ID_PATTERN` extension; `SANDBOX_REFUSED_FIELDS` + `SANDBOX_STUB_USED_FIELDS` audit constants.
- **PR-S4-0b** (merged) — `alfred-core` Dockerfile with `bubblewrap` apt-installed; `sandbox_policy_registry` Alembic table for observability.
- **PR-S4-3** (merged) — `HookpointMeta.carrier_tier` field; the `register_hookpoint(...)` call this PR adds for `supervisor.plugin.sandbox_stub_used` must populate `carrier_tier="T0"`.
- **PR-S4-6** (merged) — `bin/alfred-plugin-launcher.sh` policy-resolution extension; quarantined-LLM manifest `kind: none` → `kind: full` migration; `supervisor.plugin.sandbox_refused` hookpoint registered. **This PR ships the policy bytes the launcher consumes.**

**Blocks:**

- PR-S4-11 (graduation runbook references the kernel-enforced posture this PR ships).

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **sec-1 + test-1 HIGH (path-traversal / symlink / oversized in TOML)**: `SandboxPolicy` Pydantic model's `binds: list[BindSpec]` field validator REFUSES any `BindSpec` where:
   - `src` or `dst` contains `..` path component
   - `src` or `dst` resolves outside an allow-list of sandbox-acceptable roots (`/usr`, `/lib`, `/lib64`, `/etc/ssl/certs`, `/etc/resolv.conf`, `/tmp/alfred-sandbox/*`)
   - `src` is a symlink (refuses follow; `Path.is_symlink()` BEFORE `Path.resolve()`)
   - Policy file total size > 8KB (DoS guard)
   Adversarial corpus entries `sbx-2026-010-policy_bind_traversal`, `sbx-2026-011-policy_bind_symlink_follow`, `sbx-2026-012-policy_oversize` plant each vector and assert refusal at policy-parse time. The PR-S4-6 sec-002 BLOCKER closure (path-confinement) layers on top.

2. **sec-2 HIGH (integrity protection on policy files post-deployment)**: every vendor policy file ships with a sibling `<policy>.sha256` file containing the canonical hex digest. `SandboxPolicyLoader.load(path)` MUST verify `sha256(policy_bytes) == sha256_file_contents` BEFORE parsing. The hash file is created by `bin/alfred-setup.sh` at install time (computed against the vendor file just copied). Operator edits to the policy MUST be accompanied by a regenerated `.sha256` (the operator-tooling `alfred sandbox-policy edit <name>` regenerates the digest as part of save; manual `vim` edit breaks the digest check and refuses to load). New corpus entry `sbx-2026-013-policy_silent_byte_substitution` plants a byte-flipped policy without updating the sha256 file and asserts refusal at load.

3. **arch-1 HIGH (sandbox_policy_registry populated)**: PR-S4-6's launcher (NOT this PR) populates `sandbox_policy_registry` via a one-shot INSERT at launch-time. PR-S4-6's task list expands to include the INSERT call (`alfred.sandbox.registry.insert(plugin_id=..., os=..., policy_ref=..., policy_sha256=..., resolved_at=now)`). PR-S4-7 Task 19 ADDS an integration test `tests/integration/test_sandbox_policy_registry_populated.py` that asserts a row exists after `kind: full` plugin spawn. Without this, migration 0015 is dead schema. The registry purpose is operator observability of which policies are actively bound to which plugins.

4. **devops-1 HIGH (setup-script vendor policy copy + overwrite-protection)**: `bin/alfred-setup.sh` gains:

   ```bash
   _install_sandbox_policies() {
     local src="${ALFRED_REPO}/config/sandbox"
     local dst="${HOME}/.config/alfred/sandbox"
     mkdir -p "${dst}" && chmod 0700 "${dst}"
     for policy in "${src}"/*.toml; do
       name=$(basename "${policy}")
       if [ -e "${dst}/${name}" ]; then
         echo "Skipping ${name} (already present; operator-customized)"
         continue
       fi
       install -m 0644 "${policy}" "${dst}/${name}"
       sha256sum "${dst}/${name}" | cut -d' ' -f1 > "${dst}/${name}.sha256"
       chmod 0644 "${dst}/${name}.sha256"
     done
   }
   ```

   Mode 0644 (world-read OK for policy bytes; not secret). Operator-customized files preserved.

5. **devops-2 HIGH (Docker deployment + overlay precedence)**: vendor policies are baked into the Docker image at `/usr/share/alfred/sandbox/` (image-build copies `config/sandbox/` here). At launcher resolution time, the lookup order is: (a) `~/.config/alfred/sandbox/<policy>.toml` (operator overlay); (b) `/usr/share/alfred/sandbox/<policy>.toml` (image-baked fallback). The lookup helper at `src/alfred/sandbox/policy_loader.py:resolve_policy_path()` implements this precedence. `Dockerfile` adds the COPY step. New test `tests/integration/test_docker_image_has_baked_policies.py` (runs against built image) asserts the baked path exists and contains a known policy.

6. **devops-3 MEDIUM (CI matrix bwrap version + userns probe)**: covered by PR-S4-6 closure 5 (bwrap version pin) + closure 7 (SUID-vs-userns probe). PR-S4-7's CI workflow reuses the daemon-boot probe results; if the matrix runner has incompatible bwrap, the integration test SKIPs with a logged warning rather than passing silently.

7. **sec-3 MEDIUM (Linux outbound_allowlist HTTP downgrade)**: when translating `outbound_allowlist` from `routing.yaml[quarantine].provider_url`, the translator REFUSES any URL not matching `https://*` (HTTP refused with `SandboxPolicyOutboundInsecure`). New corpus entry `sbx-2026-014-policy_outbound_http_downgrade` plants `provider_url = "http://attacker.example/..."` and asserts refusal.

8. **sec-4 MEDIUM (macOS symlink-follow into /etc)**: macOS sandbox-exec policy gains `(deny file-read* (subpath "/etc"))` + `(deny file-read* (subpath "/var"))` + `(deny process-fork)` + `(deny process-exec*)` as baseline denies BEFORE any allows. The symlink chase is contained because the deny rules apply to the resolved path. New corpus entry `sbx-2026-015-policy_macos_symlink_to_etc` asserts refusal.

9. **arch-2 MEDIUM (vendor vs operator-overrideable split)**: covered by closures 4 + 5 above (vendor under `/usr/share`, operator overlay under `~/.config`, sha256 sidecar enforces integrity).

10. **arch-3 MEDIUM (launcher_chain_fixture contract)**: PR-S4-6 ships the sync fixture per its closure 8. PR-S4-7 Task 19 RENAMES the imported fixture to `launcher_chain_fixture_sync` and ADAPTS the test to: `launcher = launcher_chain_fixture_sync(tmp_path); result = launcher("test-plugin-id")`. Drops the async-context-manager mental model. A new helper `await_async_handle(launcher, plugin_id)` wraps the sync call in an `asyncio.to_thread` if the test needs async composition.

11. **test-2 HIGH (policy-translation unit tests)**: NEW test suite `tests/unit/sandbox/test_policy_translation.py` covers the TOML→bwrap argv translator end-to-end:
    - `test_simple_ro_bind_translates_to_bwrap_arg` — `binds = [{src="/usr/lib", dst="/usr/lib", mode="ro"}]` → `--ro-bind /usr/lib /usr/lib` exactly.
    - `test_rw_bind_translates_to_bind` — mode="rw" → `--bind`.
    - `test_share_net_default_false_emits_unshare_net` — absence of `share_net` → `--unshare-net`.
    - `test_share_net_true_omits_unshare_net` — explicit `share_net = true` → no `--unshare-net`.
    - `test_keep_fds_3_translates_to_keep_fd_3` — keeps the fd-3 invariant from PR-S4-6 closure 9.
    Each test parametrizes the assertion against both Linux (bwrap) and macOS (sandbox-exec) translators. Coverage gate `--fail-under=100` on the translator file.

12. **test-3 MEDIUM (3 other bundled kind:full plugins)**: integration test `tests/integration/test_bundled_kind_full_plugins.py` parametrizes across the 4 bundled `kind: full` plugins (quarantined-LLM + 3 others to be enumerated in this PR's §3). Each plugin gets: (a) policy lookup; (b) spawn under bwrap; (c) sandbox-info handshake assertion; (d) graceful teardown.

---

## §1 Goal

This PR delivers the three load-bearing artifacts that close the kernel-enforcement leg of PRD §5 line 117 on supported hosts:

1. `config/sandbox/quarantined-llm.linux.bwrap.policy` — declarative TOML the launcher translates into `bwrap` flags. Fail-closed shape: `--unshare-net` (no `--share-net`), `--die-with-parent`, four namespace unshares, and `keep_fds = [3]` as a validated DECLARATION (arch-2). NO fd flag is emitted: bwrap inherits fd 3 by default for the provider-key channel PR-S4-6 wires (see superseding note).
2. `config/sandbox/quarantined-llm.macos.sb` — sandbox-exec scheme syntax: `(deny default)` + four explicit allows + the explicit `(deny network-outbound (remote tcp "*"))` catch-all after the proxy allow.
3. `config/sandbox/quarantined-llm.windows.stub.policy` — TOML stub declaring `prd_compliant = false`. Production refuses; development emits `supervisor.plugin.sandbox_stub_used`.

…and the assertions that prove the policies actually work:

4. `tests/integration/test_sandbox_escape_kernel_enforced.py` — merge-blocking on `ubuntu-latest`. Spawns the launcher-policy chain against the quarantined-LLM plugin and asserts the kernel itself refuses three classes of escape (filesystem, network, subprocess). Advisory `macos-latest` variant.
5. `tests/adversarial/sandbox_escape/*.yaml` — corpus entries `sbx-2026-001` through `sbx-2026-009` (or thereabouts) covering insider-author + runtime-compromised + the five misconfigured-policy flag-variants + schema-version-downgrade + manifest-omits-sandbox-block + launcher key-inheritance (fd-3, `sbx-2026-005`).
6. `register_hookpoint("supervisor.plugin.sandbox_stub_used", carrier_tier="T0", …)` declaration site.

Spec anchors: [§7.5 Linux bwrap policy](../specs/2026-06-06-slice-4-design.md#75-linux-bwrap-policy-configsandboxquarantined-llmlinuxbwrappolicy), [§7.6 macOS sandbox-exec policy](../specs/2026-06-06-slice-4-design.md#76-macos-sandbox-exec-policy-configsandboxquarantined-llmmacossb), [§7.7 Windows stub policy](../specs/2026-06-06-slice-4-design.md#77-windows-stub-policy-configsandboxquarantined-llmwindowsstubpolicy), [§7.8 manifest update](../specs/2026-06-06-slice-4-design.md#78-quarantined-llm-manifest-update), [§7.11 audit row family](../specs/2026-06-06-slice-4-design.md#711-audit-row-family), [§7.12 adversarial corpus entry](../specs/2026-06-06-slice-4-design.md#712-adversarial-corpus-entry), [§11.4 attacker models](../specs/2026-06-06-slice-4-design.md#114-test-placement--attacker-models), [§11.5 cross-fork integration test gate](../specs/2026-06-06-slice-4-design.md#115-cross-fork-integration-test-gate--adds-beyond-the-14-2-list).

Index anchors: [Slice-4 index §3 sandbox launcher contract](./2026-06-07-slice-4-index.md#3-cross-pr-contracts), [Slice-4 index §4 cross-fork integration test gate](./2026-06-07-slice-4-index.md#4-cross-fork-integration-test-gate).

---

## §2 Verification gate — fabricated-surfaces check

Before any task in this plan runs, the implementing worker re-verifies the cited Slice-3 and PR-S4-6 surfaces. The pattern documented in #204 round-4 fixup (and Slice-4 index §8 backlog item "Fabricated-surfaces watchlist") makes this a mandatory pre-flight. Each surface below is followed by the `grep`/`ls` command that confirms it.

| Surface | Verification command | Status at plan-write time |
|---|---|---|
| `bin/alfred-plugin-launcher.sh` exists and PR-S4-6 has added policy-resolution behaviour | `ls bin/alfred-plugin-launcher.sh && grep -n "policy_refs" bin/alfred-plugin-launcher.sh` | **Slice-3 launcher exists** (`bin/alfred-plugin-launcher.sh` confirmed). PR-S4-6 must be merged before PR-S4-7 implementation begins; the worker re-runs this grep and expects a match against `policy_refs`. NB: the launcher emits NO fd flag (`--sync-fd`/`--keep-fd`) — bwrap inherits fd 3 by default (superseding note); do NOT grep for an fd flag. |
| `config/routing.yaml [quarantine]` block (Slice-3 shipped) | `grep -n "^quarantine:" config/routing.yaml` | **Confirmed** — `config/routing.yaml` declares a top-level `quarantine:` block at line 19. The macOS policy's `network*` host/port resolves from `routing.yaml[quarantine].provider_url` at policy-load time (spec §7.6). |
| `plugins/alfred_quarantined_llm/manifest.toml` (Slice-3 shipped — TOML, NOT YAML) | `ls plugins/alfred_quarantined_llm/manifest.toml` | **Confirmed** — the manifest is TOML at `plugins/alfred_quarantined_llm/manifest.toml`. Spec §7.8 and index §3 use a YAML code-block to illustrate the `sandbox` block shape; the actual file format is TOML. The migration PR-S4-6 lands edits the TOML; this PR does NOT re-edit. |
| `tests/adversarial/payload_schema.py` has `sandbox_escape` category and `sbx` prefix | `grep -nE "sandbox_escape\|\"sbx\":" tests/adversarial/payload_schema.py` | **Lands in PR-S4-0a** — at plan-write time the Slice-3 `_PREFIX_TO_CATEGORY` is at line 21 and `_ID_PATTERN` at line 34, neither carrying `sbx`. The worker re-runs this grep and expects matches after PR-S4-0a merges. If the grep is empty, the worker stops and escalates (PR-S4-7 cannot ship without the category constant). |
| `register_hookpoint` shape (Slice-3 `HookpointMeta` + PR-S4-3 `carrier_tier`) | `grep -n "def register_hookpoint\|carrier_tier" src/alfred/hooks/registry.py` | **Confirmed at plan-write time** — `def register_hookpoint(...)` at `src/alfred/hooks/registry.py:539`. PR-S4-3 adds `carrier_tier`; the worker confirms the kwarg appears in the signature before adding the `supervisor.plugin.sandbox_stub_used` registration. |
| `SANDBOX_REFUSED_FIELDS` + `SANDBOX_STUB_USED_FIELDS` constants | `grep -n "SANDBOX_REFUSED_FIELDS\|SANDBOX_STUB_USED_FIELDS" src/alfred/audit/audit_row_schemas.py` | **Lands in PR-S4-0a.** Plan-write time check is "expect not yet shipped". The worker re-runs after PR-S4-0a merges and expects two `Final[Mapping[...]]` definitions. |
| `bwrap` and `sandbox-exec` reference | `man bwrap` (Linux runner) / `man sandbox-exec` (macOS runner) | Both man pages are the canonical reference. fd-3 inheritance needs NO bwrap flag — bwrap inherits open, non-CLOEXEC fds (fd 3) by default (superseding note; supersedes the earlier `--keep-fd`/`--sync-fd` claims and the mechanically-wrong `--rw-bind /dev/fd/3 /dev/fd/3` snippet). The worker must NOT improvise alternatives nor emit any fd-keep flag. |
| `supervisor.plugin.sandbox_refused` hookpoint declaration site | `grep -rn "supervisor.plugin.sandbox_refused" src/alfred/` | **PR-S4-6 territory.** This PR adds the sibling `supervisor.plugin.sandbox_stub_used` declaration only; PR-S4-6 owns `sandbox_refused` per index §3. |
| GitHub Actions matrix (`ubuntu-latest` + `macos-latest` runners) | `ls .github/workflows/` and inspect existing matrix shapes | The merge-blocking `ubuntu-latest` runner is the standard. The `macos-latest` runner is added by this PR as advisory (`continue-on-error: true`). The worker confirms the existing test workflow uses a strategy matrix before adding a new entry. |

**Fabricated-surface guard rail:** if any of the checks above returns empty when it should not, the implementing worker stops, opens a comment on this PR, and escalates rather than inventing a surface. The Slice-3 round-4 retrospective named this pattern as the highest-payoff cheap intervention (#204 round-4 fixup; index §8).

---

## §3 Architecture overview

```
                    ┌──────────────────────────────────────────────────┐
                    │  Operator host (Linux / macOS / Windows-stub)    │
                    └────────────────┬─────────────────────────────────┘
                                     │
                                     │ alfred daemon start
                                     ▼
                          Supervisor (Python)
                                     │
                                     │ spawn quarantined-LLM plugin
                                     ▼
                  bin/alfred-plugin-launcher.sh <plugin_id> ...
                                     │
                                     │ read manifest.toml → sandbox.policy_refs[<os>]
                                     │ (PR-S4-6 logic; this PR ships the policy bytes)
                                     ▼
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
       Linux: bwrap            macOS: sandbox-exec    Windows: stub
       --die-with-parent       -f <policy>.sb --     refuse-in-prod,
       --unshare-pid           /path/to/quarantined- emit sandbox_stub_used
       --unshare-uts           llm --                 in dev
       (fd 3 inherited,
        NO fd flag)
       --unshare-cgroup
       --unshare-ipc
       --ro-bind /usr/lib/...
       --ro-bind /etc/ssl/...
       --tmpfs /tmp
       (NO --share-net)
              │                      │                      │
              ▼                      ▼                      ▼
       exec plugins/alfred_quarantined_llm/quarantine_plugin.py
              │                      │                      │
              │ fd 3 inherited       │ fd 3 inherited       │ stub path skipped
              │ from supervisor      │ from supervisor      │ in production
              ▼                      ▼                      ▼
       Plugin reads provider key from fd 3 (Slice-3 helper),
       zeroizes, opens stdio MCP loop to host.
```

The diagram is the same on each OS up to the policy-translation step. Spec §7.5–§7.7 spell out the per-OS shape; this PR ships the bytes those shapes parse from.

The integration test boots the chain end-to-end on `ubuntu-latest`. Three escape attempts are made *from inside the spawned plugin*; each must fail at the syscall layer, not at the application layer. The adversarial corpus declares the same three classes + their misconfigured-policy preconditions + the fd-3 inheritance property.

---

## §4 File structure

| File | Status | Responsibility |
|---|---|---|
| `config/sandbox/quarantined-llm.linux.bwrap.policy` | Create | Declarative TOML policy file. Launcher (PR-S4-6) parses, translates into `bwrap` flags. Spec §7.5. |
| `config/sandbox/quarantined-llm.macos.sb` | Create | macOS sandbox-exec scheme syntax. Launcher passes verbatim to `sandbox-exec -f`. Spec §7.6. |
| `config/sandbox/quarantined-llm.windows.stub.policy` | Create | TOML stub: `schema_version`, `isolation`, `prd_compliant=false`, `notes`. Spec §7.7. |
| `config/sandbox/README.md` | Create | Operator-facing description: how the launcher resolves the per-OS policy, where to find each policy's source-of-truth schema (the spec sections above), and the explicit warning that the Windows stub is not PRD-compliant. |
| `src/alfred/supervisor/hookpoints.py` (or wherever PR-S4-6 declared `sandbox_refused`) | Modify | Add `register_hookpoint("supervisor.plugin.sandbox_stub_used", carrier_tier="T0", fail_closed=True, …)`. Spec §7.11 + index §3 hookpoint table. |
| `tests/integration/test_sandbox_escape_kernel_enforced.py` | Create | **Merge-blocking on `ubuntu-latest`** (index §4). Three escape classes: filesystem (`open(/etc/passwd)` → ENOENT/EACCES), network (`connect(1.1.1.1)` → ENETUNREACH), subprocess (`execve(/bin/sh)` → EPERM). macOS variant in same file gated by `sys.platform`, marked advisory via `pytestmark`. |
| `tests/integration/conftest.py` | Modify (if needed) | Add `launch_quarantined_plugin` fixture that boots the launcher chain with the test policy file. If PR-S4-6 has not added a launcher-driven fixture, this PR adds it. |
| `tests/adversarial/sandbox_escape/__init__.py` | Create | Package marker. |
| `tests/adversarial/sandbox_escape/sbx-2026-001-bwrap_filesystem_escape.yaml` | Create | Runtime-compromised: `open(/etc/passwd)` returns ENOENT/EACCES. No audit row (kernel-handled). Spec §7.12. |
| `tests/adversarial/sandbox_escape/sbx-2026-002-bwrap_network_escape.yaml` | Create | Runtime-compromised: `connect(1.1.1.1:443)` returns ENETUNREACH. No audit row. |
| `tests/adversarial/sandbox_escape/sbx-2026-003-bwrap_subprocess_escape.yaml` | Create | Runtime-compromised: `execve(/bin/sh, [], [])` returns EPERM. No audit row. |
| `tests/adversarial/sandbox_escape/sbx-2026-004-bwrap_fork_escape.yaml` | Create | Runtime-compromised: `fork()` then `execve` in the child. Kernel refuses (PID namespace + EPERM). No audit row. |
| `tests/adversarial/sandbox_escape/sbx-2026-005-launcher_key_inheritance.yaml` | Create | Insider-author + runtime-compromised crossover: `strace`/`dtruss` asserts the bash launcher process never reads from fd 3. Only the spawned plugin does. Spec §7.5 fd-3 discipline. |
| `tests/adversarial/sandbox_escape/sbx-2026-006-policy_missing_unshare_net.yaml` | Create | **Misconfigured-policy** (test-009 closure): policy with `--unshare-net` removed (or `--share-net` re-added). Launcher's policy validator refuses at load time with `supervisor.plugin.sandbox_refused(reason="policy_invalid_share_net")`. |
| `tests/adversarial/sandbox_escape/sbx-2026-007-policy_missing_die_with_parent.yaml` | Create | Misconfigured-policy: `--die-with-parent` removed. Refused with `reason="policy_invalid_die_with_parent"`. |
| `tests/adversarial/sandbox_escape/sbx-2026-008-policy_rebinds_root_writable.yaml` | Create | Misconfigured-policy: an extra `--bind / /` (writable root) added. Refused with `reason="policy_invalid_root_writable"`. |
| `tests/adversarial/sandbox_escape/sbx-2026-009-policy_missing_unshare_pid.yaml` | Create | Misconfigured-policy: `--unshare-pid` removed. Refused with `reason="policy_invalid_unshare_pid"`. |
| `tests/adversarial/sandbox_escape/sbx-2026-010-policy_schema_downgrade.yaml` | Create | Misconfigured-policy: policy `schema_version=0` (or absent). Refused with `reason="policy_invalid_schema_version"`. |
| `tests/adversarial/sandbox_escape/sbx-2026-011-manifest_omits_sandbox_block.yaml` | Create | Plugin manifest with no `[sandbox]` block. Launcher refuses with `plugin.load_refused(reason="sandbox_block_missing")`. Spec §7.1 + §7.12. |
| `tests/adversarial/sandbox_escape/sbx-2026-012-macos_sandbox_escape_subset.yaml` | Create | macOS variant of `sbx-2026-001/002/003` collapsed into one entry; advisory-only on `macos-latest` runner. |
| `tests/adversarial/sandbox_escape/conftest.py` | Create | Pytest fixtures: `policy_with_flag_removed(flag)` returning a temporary policy-file path with the named flag stripped; `policy_with_schema(version)` for the downgrade variant; `launcher_refuses(plugin_id, expected_reason)` assertion helper that runs the launcher with `Settings.environment="production"` and asserts the audit row + non-zero exit. |
| `.github/workflows/ci.yml` | Modify | Add a `sandbox-escape` job matrix: `runs-on: ubuntu-latest` merge-blocking; `runs-on: macos-latest` `continue-on-error: true` advisory. Promote the merge-blocking ubuntu job to required-status-check via `gh api` per the workflow-author skill convention (index §4, ops-007). |
| `docs/runbooks/slice-4-graduation.md` | Modify (back-patch) | If PR-S4-6's runbook section "Sandbox policy bytes" exists, append the per-OS file paths this PR ships. Otherwise PR-S4-11 owns the section. |

The `register_hookpoint` declaration site for `supervisor.plugin.sandbox_stub_used` lives wherever PR-S4-6 declared `supervisor.plugin.sandbox_refused`. The worker greps for that declaration first (see §2) and adds the sibling alongside.

---

## §5 Cross-PR contracts

These surfaces this PR depends on (defined elsewhere) and the surfaces this PR defines (consumed elsewhere). Drift between PRs is a release blocker — the same discipline §3 of the slice-4 index applies.

### 5.1 Consumed from PR-S4-0a

- `tests/adversarial/payload_schema.py` Slice-4 additions: `sandbox_escape` Literal in `SLICE_4_CATEGORIES`; `"sbx": "sandbox_escape"` in `_PREFIX_TO_CATEGORY`; `sbx` in `_ID_PATTERN`. Every `sbx-2026-NNN` YAML this PR ships parses cleanly against the schema validator (spec §11.1, index §3).
- `src/alfred/audit/audit_row_schemas.py` constants `SANDBOX_REFUSED_FIELDS` (`plugin_id, policy_ref, host_os, reason, environment`) and `SANDBOX_STUB_USED_FIELDS` (`plugin_id, policy_ref, host_os, environment`). This PR's tests assert the launcher emits each constant with the expected `reason` value at the expected refusal points.

### 5.2 Consumed from PR-S4-6

- `bin/alfred-plugin-launcher.sh` policy-resolving extension: reads `manifest.toml [sandbox] policy_refs.<os>` via the pre-launcher Python helper `src/alfred/plugins/manifest_reader.py`; translates the resolved Linux policy file into `bwrap` flags (binds, tmpfs, `--dev`, unshares, `--die-with-parent`) — NO fd flag; bwrap inherits fd 3 by default (superseding note); passes the macOS file verbatim to `sandbox-exec -f`; refuses on the Windows stub in production. This PR's integration tests invoke the launcher; if the launcher's behaviour differs from the contract above, the integration test fails loudly rather than silently masking.
- `Settings.environment: Literal["development", "production", "test"]` (spec §7.3 sec-003 closure). The misconfigured-policy adversarial entries set `Settings.environment="production"` when asserting the launcher's refusal.
- Quarantined-LLM manifest at `plugins/alfred_quarantined_llm/manifest.toml`: post-PR-S4-6 the file declares `[sandbox] kind = "full"` with `policy_refs.linux/macos/windows` pointing at the three policy files this PR ships. The integration test loads this manifest unchanged.
- `supervisor.plugin.sandbox_refused` hookpoint already registered. This PR adds the sibling `supervisor.plugin.sandbox_stub_used`.

### 5.3 Defined by this PR (consumed elsewhere)

- Three policy files at `config/sandbox/quarantined-llm.{linux.bwrap,macos.sb,windows.stub}`. Consumed by PR-S4-6 launcher at runtime; consumed by PR-S4-11 graduation runbook for operator deployment guidance.
- `register_hookpoint("supervisor.plugin.sandbox_stub_used", carrier_tier="T0", fail_closed=True, …)`. Consumed by PR-S4-6's launcher emit-site in the dev-only stub-spawn path. This PR registers; PR-S4-6's launcher already calls. (If the order swaps — i.e. PR-S4-6 lands first with a missing-hookpoint test failure — the worker waits for PR-S4-7 hookpoint registration before unblocking the launcher.)
- `tests/integration/test_sandbox_escape_kernel_enforced.py` — merge-blocking on `ubuntu-latest`. Required-status-check promotion via `gh api` in this PR's `gating-workflow` push.
- Adversarial corpus entries `sbx-2026-001` through `sbx-2026-012`. Consumed by `tests/adversarial/` harness on every CI run.

### 5.4 NOT defined by this PR (explicit non-ownership)

- Launcher policy-resolution logic — **PR-S4-6 only** (one-time ownership rule, index §3). This PR does NOT modify `bin/alfred-plugin-launcher.sh`.
- macOS sandbox-exec deprecation handling — Apple's deprecation is acknowledged in `docs/subsystems/security.md` per ADR-0015's "best-effort" stance; no replacement migration is in Slice 4 scope.
- Windows-native sandbox implementation — post-MVP, deferred per spec §7.7.
- The manifest migration `kind: none` → `kind: full` — **PR-S4-6 only** per index §3. This PR verifies the migration has happened (a unit assertion under §6 Task 1) but does NOT re-edit the manifest.

---

## §6 Tasks

Tasks follow TDD. All commits use `(#TBD-slice4-pr-s4-7)`. Each task: failing test first, implementation second, commit third. The `make check` gate runs before every commit; `uv run pytest tests/adversarial/sandbox_escape/ -q` runs before the final integration-test promotion.

---

### Component A — Pre-flight: verify upstream surfaces and manifest state

This component does not ship code. It is a checkbox-driven verification gate that the implementing worker executes before writing the first policy byte. The pattern matches Slice-3 PR-S3-4's "Component A — `Provider.capabilities()` + `ProviderCapability` enum" preamble: explicit prep, no shortcuts.

- [ ] **Task 1 — Re-run the §2 verification gate.**

  Re-run every command in the §2 table. Each expected match must return a non-empty result; each "lands in PR-S4-0a" or "PR-S4-6 territory" surface must now resolve.

  ```bash
  cd <repo-root>
  ls bin/alfred-plugin-launcher.sh
  grep -nE "policy_refs" bin/alfred-plugin-launcher.sh  # NO fd flag emitted; bwrap inherits fd 3 by default (superseding note)
  ls plugins/alfred_quarantined_llm/manifest.toml
  grep -E '\[sandbox\]|kind\s*=\s*"full"|policy_refs' plugins/alfred_quarantined_llm/manifest.toml
  grep -nE 'sandbox_escape|"sbx":' tests/adversarial/payload_schema.py
  grep -n "SANDBOX_REFUSED_FIELDS\|SANDBOX_STUB_USED_FIELDS" src/alfred/audit/audit_row_schemas.py
  grep -n "supervisor.plugin.sandbox_refused" src/alfred/
  grep -n "carrier_tier" src/alfred/hooks/registry.py
  ```

  Expected: every grep returns matches; the manifest declares `kind = "full"` with the three `policy_refs.<os>` entries; `carrier_tier` is a kwarg of `register_hookpoint`.

  If any check fails, STOP. Comment on the PR draft "PR-S4-7 verification gate failed: <surface>"; escalate. The worker does NOT improvise. (#204 round-4 fixup discipline.)

  No commit for this task — verification only.

- [ ] **Task 2 — Confirm the launcher's policy-validator surface contract.**

  The misconfigured-policy adversarial entries (`sbx-2026-006` through `sbx-2026-010`) assume the launcher's policy validator rejects each named flag's absence with a deterministic `reason` string. The validator is PR-S4-6's territory; this task locates the validation site and the documented reason-string set, and confirms the strings match the YAML `id`s this PR ships.

  ```bash
  grep -rn "policy_invalid_" bin/alfred-plugin-launcher.sh src/alfred/plugins/manifest_reader.py
  ```

  Expected: each of `policy_invalid_share_net`, `policy_invalid_die_with_parent`, `policy_invalid_root_writable`, `policy_invalid_unshare_pid`, `policy_invalid_schema_version` is emitted by the validator. If any string differs from PR-S4-6's actual implementation, the worker updates THIS PR's YAML `expected_outcome.reason` to match — the launcher is the source of truth — and notes the resolution in the PR description.

  No commit; verification only.

---

### Component B — Linux bwrap policy file

This component ships `config/sandbox/quarantined-llm.linux.bwrap.policy` and the unit tests asserting its structural correctness.

- [ ] **Task 3 — Failing test: TOML schema of the Linux policy file.**

  Files: Create `tests/unit/sandbox/__init__.py`, `tests/unit/sandbox/test_linux_policy_schema.py`.

  The test loads the policy as TOML and asserts:

  - Top-level keys: `schema_version` (integer, equals `1`), `os` (string, equals `"linux"`), `runtime` (string, equals `"bwrap"`), `flags` (table), `binds` (array), `unshare` (array), `keep_fds` (array).
  - `flags.die_with_parent == true`.
  - `flags.share_net == false` (the load-bearing fail-closed property; spec §7.5 "deliberately omitted").
  - `unshare == ["pid", "uts", "cgroup", "ipc"]` (or contains all four as a frozenset comparison).
  - `binds` contains two entries: `{"src": "/usr/lib/alfred-quarantine", "dst": "/usr/lib/alfred-quarantine", "ro": true}` and `{"src": "/etc/ssl/certs", "dst": "/etc/ssl/certs", "ro": true}`.
  - `tmpfs == ["/tmp"]`.
  - `keep_fds == [3]` (a validated DECLARATION of intent, arch-2 — NO fd flag is emitted; bwrap inherits fd 3 by default, see superseding note).
  - `network.outbound_allowlist` is a single entry resolved from `routing.yaml[quarantine].provider_url` (the test asserts the field name exists; it does NOT assert the value because the routing config is operator-set).

  ```python
  # tests/unit/sandbox/test_linux_policy_schema.py
  from pathlib import Path
  import tomllib

  POLICY_PATH = Path(__file__).resolve().parents[3] / "config" / "sandbox" / "quarantined-llm.linux.bwrap.policy"

  def _load() -> dict[str, object]:
      with POLICY_PATH.open("rb") as fh:
          return tomllib.load(fh)

  def test_schema_version_is_one() -> None:
      policy = _load()
      assert policy["schema_version"] == 1

  def test_runtime_is_bwrap() -> None:
      policy = _load()
      assert policy["os"] == "linux"
      assert policy["runtime"] == "bwrap"

  def test_die_with_parent_is_true() -> None:
      policy = _load()
      assert policy["flags"]["die_with_parent"] is True

  def test_share_net_is_false() -> None:
      policy = _load()
      # The load-bearing fail-closed property. Spec §7.5: --share-net is
      # "deliberately omitted". The launcher translates share_net=false
      # into the absence of --share-net (i.e. the default --unshare-net).
      assert policy["flags"]["share_net"] is False

  def test_unshares_cover_pid_uts_cgroup_ipc() -> None:
      policy = _load()
      assert frozenset(policy["unshare"]) >= frozenset({"pid", "uts", "cgroup", "ipc"})

  def test_binds_match_spec_7_5() -> None:
      policy = _load()
      binds = {(b["src"], b["dst"], b["ro"]) for b in policy["binds"]}
      assert ("/usr/lib/alfred-quarantine", "/usr/lib/alfred-quarantine", True) in binds
      assert ("/etc/ssl/certs", "/etc/ssl/certs", True) in binds

  def test_tmpfs_is_slash_tmp() -> None:
      policy = _load()
      assert policy["tmpfs"] == ["/tmp"]

  def test_keep_fds_is_three() -> None:
      policy = _load()
      # keep_fds is a validated DECLARATION (arch-2). NO fd flag is emitted —
      # bwrap inherits fd 3 by default for the provider-key channel (see
      # superseding note; supersedes the earlier --sync-fd/--keep-fd and the
      # mechanically-wrong --rw-bind /dev/fd/3).
      assert policy["keep_fds"] == [3]

  def test_outbound_allowlist_field_present() -> None:
      policy = _load()
      assert "network" in policy
      assert "outbound_allowlist" in policy["network"]
      assert isinstance(policy["network"]["outbound_allowlist"], list)
  ```

  Run: `uv run pytest tests/unit/sandbox/test_linux_policy_schema.py -v` — expected: all fail (file does not exist).

  No commit; failing-test step only.

- [ ] **Task 4 — Implement: write `config/sandbox/quarantined-llm.linux.bwrap.policy`.**

  Files: Create `config/sandbox/quarantined-llm.linux.bwrap.policy`.

  Format: TOML. Content (the test from Task 3 enforces structural correctness; this is the literal file the launcher reads):

  ```toml
  # AlfredOS quarantined-LLM sandbox policy — Linux (bwrap).
  #
  # Spec §7.5 of docs/superpowers/specs/2026-06-06-slice-4-design.md.
  # The launcher (bin/alfred-plugin-launcher.sh) reads this file and
  # translates it into bwrap CLI flags before exec'ing the plugin.
  #
  # Fail-closed shape:
  #   * flags.share_net = false   → launcher omits --share-net (kernel default --unshare-net).
  #   * flags.die_with_parent = true → launcher passes --die-with-parent (supervisor death kills plugin).
  #   * unshare list              → launcher passes --unshare-pid --unshare-uts --unshare-cgroup --unshare-ipc.
  #   * binds with ro=true        → launcher passes --ro-bind <src> <dst> per entry.
  #   * tmpfs                     → launcher passes --tmpfs <path>.
  #   * keep_fds = [3]            → DECLARATION only (arch-2). NO fd flag is emitted; bwrap inherits fd 3 by default for provider-key delivery (superseding note).
  #
  # The outbound network access is brokered: no --share-net, so the kernel
  # blocks all socket egress. The plugin contacts the quarantined-LLM
  # provider via the host-supplied proxy URL declared at
  # network.outbound_allowlist[0]; the supervisor sets the proxy's host:port
  # before spawn.

  schema_version = 1
  os = "linux"
  runtime = "bwrap"

  [flags]
  die_with_parent = true
  share_net = false

  unshare = ["pid", "uts", "cgroup", "ipc"]

  tmpfs = ["/tmp"]

  keep_fds = [3]

  [[binds]]
  src = "/usr/lib/alfred-quarantine"
  dst = "/usr/lib/alfred-quarantine"
  ro = true

  [[binds]]
  src = "/etc/ssl/certs"
  dst = "/etc/ssl/certs"
  ro = true

  [network]
  # The launcher reads routing.yaml[quarantine].provider_url at spawn time
  # and exposes it as an outbound proxy. This list is the allowlist of
  # endpoints the plugin may attempt to connect to. The launcher refuses
  # to spawn if any entry references a non-quarantine provider.
  outbound_allowlist = ["__routing.yaml[quarantine].provider_url__"]
  ```

  The sentinel string `__routing.yaml[quarantine].provider_url__` is documented in `config/sandbox/README.md` (Task 13) as the placeholder the launcher resolves at spawn time. PR-S4-6's launcher logic handles the substitution; this PR ships the placeholder literal.

  Run the Task 3 tests: `uv run pytest tests/unit/sandbox/test_linux_policy_schema.py -v` — expected: PASS.

  Commit:

  ```
  feat(sandbox): ship Linux bwrap policy for quarantined-LLM plugin (#TBD-slice4-pr-s4-7)
  ```

---

### Component C — macOS sandbox-exec policy file

- [ ] **Task 5 — Failing test: structural validation of the macOS policy file.**

  Files: Create `tests/unit/sandbox/test_macos_policy_schema.py`.

  The macOS policy is sandbox-exec scheme syntax, not TOML. The test validates the file is non-empty, parses against a minimal scheme tokenizer (we use `pathlib.Path.read_text` + regex assertions, not a full scheme parser — sandbox-exec itself is the only valid parser), and asserts the load-bearing forms are present.

  ```python
  # tests/unit/sandbox/test_macos_policy_schema.py
  import re
  from pathlib import Path

  POLICY_PATH = Path(__file__).resolve().parents[3] / "config" / "sandbox" / "quarantined-llm.macos.sb"

  def _read() -> str:
      return POLICY_PATH.read_text(encoding="utf-8")

  def test_first_directive_is_version() -> None:
      # sandbox-exec requires (version 1) as the first non-comment form.
      lines = [ln.strip() for ln in _read().splitlines() if ln.strip() and not ln.strip().startswith(";")]
      assert lines[0].startswith("(version "), lines[0]

  def test_deny_default_present() -> None:
      assert re.search(r"\(deny\s+default\)", _read()) is not None

  def test_binary_read_subpath_allowed() -> None:
      assert re.search(
          r'\(allow\s+file-read\*\s+\(subpath\s+"/usr/lib/alfred-quarantine"\)\)',
          _read(),
      ) is not None

  def test_tls_ca_read_literal_allowed() -> None:
      assert re.search(
          r'\(allow\s+file-read\*\s+\(literal\s+"/etc/ssl/cert\.pem"\)\)',
          _read(),
      ) is not None

  def test_scratch_write_subpath_allowed() -> None:
      assert re.search(
          r'\(allow\s+file-write\*\s+\(subpath\s+"/tmp/alfred-quarantine"\)\)',
          _read(),
      ) is not None

  def test_network_allow_for_proxy_only() -> None:
      # spec §7.6: (allow network* (remote tcp "host.docker.internal:443")).
      # The host:port is a placeholder the launcher rewrites at spawn time;
      # the literal we ship is what the operator-deployed default looks like.
      assert re.search(
          r'\(allow\s+network\*\s+\(remote\s+tcp\s+"[^"]+"\)\)',
          _read(),
      ) is not None

  def test_explicit_catchall_deny_after_proxy() -> None:
      # spec §7.6: explicit catch-all deny after the proxy allow.
      assert re.search(
          r'\(deny\s+network-outbound\s+\(remote\s+tcp\s+"\*"\)\)',
          _read(),
      ) is not None
  ```

  Run: `uv run pytest tests/unit/sandbox/test_macos_policy_schema.py -v` — expected: fail (file does not exist).

  No commit.

- [ ] **Task 6 — Implement: write `config/sandbox/quarantined-llm.macos.sb`.**

  Files: Create `config/sandbox/quarantined-llm.macos.sb`.

  Content:

  ```scheme
  ; AlfredOS quarantined-LLM sandbox policy — macOS (sandbox-exec).
  ;
  ; Spec §7.6 of docs/superpowers/specs/2026-06-06-slice-4-design.md.
  ; ADR-0015 acknowledges macOS sandbox-exec as best-effort (Apple has
  ; deprecated it but it still works on supported macOS versions).
  ;
  ; The launcher (bin/alfred-plugin-launcher.sh) invokes:
  ;   sandbox-exec -f config/sandbox/quarantined-llm.macos.sb -- <plugin> <args>
  ; The "host.docker.internal:443" literal in the network allow rule is a
  ; sentinel; PR-S4-6's launcher rewrites it from routing.yaml[quarantine]
  ; .provider_url at spawn time. The catch-all (deny network-outbound) is
  ; mandatory because (deny default) does NOT cover outbound TCP cleanly
  ; in older sandbox-exec versions.

  (version 1)
  (deny default)

  (allow file-read* (subpath "/usr/lib/alfred-quarantine"))
  (allow file-read* (literal "/etc/ssl/cert.pem"))
  (allow file-write* (subpath "/tmp/alfred-quarantine"))

  ; Outbound network — proxy only.
  (allow network* (remote tcp "host.docker.internal:443"))
  (deny network-outbound (remote tcp "*"))
  ```

  Run the Task 5 tests: `uv run pytest tests/unit/sandbox/test_macos_policy_schema.py -v` — expected: PASS.

  Commit:

  ```
  feat(sandbox): ship macOS sandbox-exec policy for quarantined-LLM plugin (#TBD-slice4-pr-s4-7)
  ```

---

### Component D — Windows stub policy file

- [ ] **Task 7 — Failing test: Windows stub policy TOML.**

  Files: Create `tests/unit/sandbox/test_windows_policy_schema.py`.

  ```python
  # tests/unit/sandbox/test_windows_policy_schema.py
  import tomllib
  from pathlib import Path

  POLICY_PATH = Path(__file__).resolve().parents[3] / "config" / "sandbox" / "quarantined-llm.windows.stub.policy"

  def _load() -> dict[str, object]:
      with POLICY_PATH.open("rb") as fh:
          return tomllib.load(fh)

  def test_schema_version_is_one() -> None:
      assert _load()["schema_version"] == 1

  def test_isolation_is_stub() -> None:
      assert _load()["isolation"] == "stub"

  def test_prd_compliant_is_false() -> None:
      # The load-bearing field — the Windows stub does NOT claim PRD §5
      # line 117 compliance. Operators must read the notes string.
      assert _load()["prd_compliant"] is False

  def test_notes_field_explains_non_compliance() -> None:
      notes = _load()["notes"]
      assert isinstance(notes, str)
      # Hardcoded substring check: the notes string must reference the
      # PRD invariant explicitly. Hardcoded English in this file is
      # acceptable because the policy file itself is operator-config,
      # not a user-facing string (i18n hard rule scope).
      assert "PRD §5 line 117" in notes
  ```

  Run: `uv run pytest tests/unit/sandbox/test_windows_policy_schema.py -v` — expected: fail.

- [ ] **Task 8 — Implement: write `config/sandbox/quarantined-llm.windows.stub.policy`.**

  Files: Create `config/sandbox/quarantined-llm.windows.stub.policy`.

  Content:

  ```toml
  # AlfredOS quarantined-LLM sandbox policy — Windows (stub).
  #
  # Spec §7.7 of docs/superpowers/specs/2026-06-06-slice-4-design.md.
  # This stub exists so the launcher's policy resolver finds A file when
  # sys.platform == "win32", but the file declares prd_compliant = false.
  # The launcher refuses to spawn in production (Settings.environment ==
  # "production") and emits supervisor.plugin.sandbox_refused with
  # reason="windows_stub_in_production". In development the launcher
  # spawns the plugin unsandboxed under the calling user with a loud
  # supervisor.plugin.sandbox_stub_used audit row.
  #
  # Operators running AlfredOS on Windows are directed to WSL2 + the
  # Linux bwrap policy. See docs/runbooks/slice-4-graduation.md.

  schema_version = 1
  isolation = "stub"
  prd_compliant = false
  notes = "Windows native sandbox not implemented; quarantined-LLM runs unsandboxed under the calling user in development. PRD §5 line 117 invariant NOT satisfied on Windows. Use WSL2 + the Linux bwrap policy for PRD compliance."
  ```

  Run the Task 7 tests: `uv run pytest tests/unit/sandbox/test_windows_policy_schema.py -v` — expected: PASS.

  Commit:

  ```
  feat(sandbox): ship Windows stub policy declaring prd_compliant=false (#TBD-slice4-pr-s4-7)
  ```

---

### Component E — `supervisor.plugin.sandbox_stub_used` hookpoint registration

- [ ] **Task 9 — Failing test: hookpoint declaration site exists with `carrier_tier="T0"`.**

  Files: Create `tests/unit/hooks/test_sandbox_stub_used_hookpoint.py`.

  ```python
  # tests/unit/hooks/test_sandbox_stub_used_hookpoint.py
  from alfred.hooks.registry import HookRegistry

  def test_sandbox_stub_used_hookpoint_declared() -> None:
      meta = HookRegistry.singleton().hookpoint_meta("supervisor.plugin.sandbox_stub_used")
      assert meta is not None, "hookpoint not declared at module-init time"

  def test_sandbox_stub_used_carrier_tier_is_t0() -> None:
      meta = HookRegistry.singleton().hookpoint_meta("supervisor.plugin.sandbox_stub_used")
      assert meta is not None
      assert meta.carrier_tier == "T0"

  def test_sandbox_stub_used_fail_closed() -> None:
      meta = HookRegistry.singleton().hookpoint_meta("supervisor.plugin.sandbox_stub_used")
      assert meta is not None
      # All Slice-4 hookpoints carry fail_closed=True uniformly (#167
      # per-kind override deferred). Index §3 hookpoint surface table.
      assert meta.fail_closed is True
  ```

  Run: `uv run pytest tests/unit/hooks/test_sandbox_stub_used_hookpoint.py -v` — expected: fail (hookpoint not declared).

- [ ] **Task 10 — Implement: add `register_hookpoint("supervisor.plugin.sandbox_stub_used", …)` alongside PR-S4-6's `sandbox_refused` declaration.**

  Files: Modify the module that PR-S4-6 added the `sandbox_refused` declaration to (locate via `grep -rn "supervisor.plugin.sandbox_refused" src/alfred/`).

  Add the sibling registration:

  ```python
  register_hookpoint(
      name="supervisor.plugin.sandbox_stub_used",
      carrier_tier="T0",
      fail_closed=True,
      subscribable_tiers=frozenset(),  # observation-only by orchestrator; no subscribers
      ...  # other kwargs to match PR-S4-6's sandbox_refused shape (allow_error_substitution, etc.)
  )
  ```

  The kwargs that match PR-S4-6's `sandbox_refused` declaration verbatim — the worker mirrors that registration's full kwarg set with two changes only: `name` swap to `sandbox_stub_used`; no other behavioural difference.

  Run the Task 9 tests: `uv run pytest tests/unit/hooks/test_sandbox_stub_used_hookpoint.py -v` — expected: PASS.

  Commit:

  ```
  feat(supervisor): register supervisor.plugin.sandbox_stub_used hookpoint with carrier_tier=T0 (#TBD-slice4-pr-s4-7)
  ```

---

### Component F — Adversarial corpus: insider-author + runtime-compromised + misconfigured-policy

This component ships `tests/adversarial/sandbox_escape/` with 12 entries. Each YAML conforms to `tests/adversarial/payload_schema.py` (PR-S4-0a `sandbox_escape` category + `sbx` prefix). The harness loads each YAML and runs its `attack_vector` against the configured `ingestion_path`; the assertion is the `expected_outcome` field.

- [ ] **Task 11 — Failing test: corpus YAML schema validates against `payload_schema.py`.**

  Files: Create `tests/adversarial/sandbox_escape/__init__.py`. Create `tests/adversarial/sandbox_escape/test_corpus_loads.py`.

  ```python
  # tests/adversarial/sandbox_escape/test_corpus_loads.py
  from pathlib import Path

  import pytest
  import yaml
  from tests.adversarial.payload_schema import AdversarialPayload

  CORPUS_DIR = Path(__file__).parent

  @pytest.mark.parametrize(
      "yaml_path",
      sorted(CORPUS_DIR.glob("sbx-2026-*.yaml")),
      ids=lambda p: p.stem,
  )
  def test_each_corpus_entry_parses(yaml_path: Path) -> None:
      raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
      payload = AdversarialPayload.model_validate(raw)
      assert payload.id == yaml_path.stem
      assert payload.category == "sandbox_escape"
  ```

  Run: `uv run pytest tests/adversarial/sandbox_escape/test_corpus_loads.py -v` — expected: NOOP / 0 collected (no YAMLs yet).

- [ ] **Task 12 — Implement: ship `sbx-2026-001-bwrap_filesystem_escape.yaml` through `sbx-2026-004-bwrap_fork_escape.yaml` (the runtime-compromised quartet).**

  Files: Create the four YAML files.

  Shape (`sbx-2026-001` shown; the other three follow the same pattern with the syscall + expected errno swapped):

  ```yaml
  id: sbx-2026-001
  category: sandbox_escape
  title: bwrap filesystem escape — open(/etc/passwd) refused at syscall layer
  attacker_model: runtime_compromised
  ingestion_path: stdio_fd3_key_delivery  # the launcher chain
  description: |
    A payload running inside the bwrap-isolated quarantined-LLM plugin
    attempts to open(2) /etc/passwd. The Linux bwrap policy mounts
    /usr/lib/alfred-quarantine and /etc/ssl/certs read-only; /etc/passwd
    is not in the bind list. The kernel must refuse with ENOENT (file
    invisible in the sandbox's mount namespace) or EACCES.
  attack_vector:
    syscall: open
    args:
      path: /etc/passwd
      flags: O_RDONLY
  expected_outcome:
    classification: sandbox_refused
    audit_row: null  # kernel-handled; no AlfredOS audit row
    errno_one_of: [ENOENT, EACCES]
  references:
    - spec://2026-06-06-slice-4-design.md#7.5
    - spec://2026-06-06-slice-4-design.md#7.12
  ```

  `sbx-2026-002`: `syscall: connect`, `args.address: 1.1.1.1:443`, `expected_outcome.errno_one_of: [ENETUNREACH]` (the kernel refuses because the sandbox has no network namespace access).

  `sbx-2026-003`: `syscall: execve`, `args.path: /bin/sh`, `expected_outcome.errno_one_of: [EPERM, ENOENT]` (EPERM if `/bin/sh` is invisible; ENOENT if not bound).

  `sbx-2026-004`: `syscall: fork`. The PID namespace unshare means the forked child is in a fresh PID namespace; subsequent escapes from the child are equally refused. `expected_outcome.errno_one_of` left empty; `expected_outcome.classification: sandbox_refused` with `notes: "fork succeeds but child cannot exec into shell or connect"`.

  Run the Task 11 schema test: `uv run pytest tests/adversarial/sandbox_escape/test_corpus_loads.py -v` — expected: 4 entries parse cleanly.

  Commit:

  ```
  test(adversarial): add sbx-2026-001 through 004 — runtime-compromised escape quartet (#TBD-slice4-pr-s4-7)
  ```

- [ ] **Task 13 — Implement: `sbx-2026-005-launcher_key_inheritance.yaml` (the fd-3 strace property).**

  Files: Create `tests/adversarial/sandbox_escape/sbx-2026-005-launcher_key_inheritance.yaml`.

  ```yaml
  id: sbx-2026-005
  category: sandbox_escape
  title: launcher fd-3 key inheritance — bash never reads, plugin reads exactly once
  attacker_model: insider_author
  ingestion_path: stdio_fd3_key_delivery
  description: |
    Spec §7.5 fd-3 discipline: the supervisor writes the provider key
    to fd 3; the bash launcher passes fd 3 through via bwrap's DEFAULT fd
    inheritance (NO fd flag; --sync-fd would consume fd 3 — superseding note)
    WITHOUT reading the bytes itself; the spawned plugin reads exactly
    the framed bytes and zeroizes. An insider-author who modifies the
    launcher to capture fd 3 (e.g. `cat <&3 > /tmp/leak`) would compromise
    the provider key.
    This corpus entry runs the launcher under strace (or dtruss on macOS)
    and asserts:
      1. The bash process never issues a read(3, ...) syscall.
      2. The spawned plugin process issues exactly one read(3, ...) of
         the framed length (4 bytes prefix + N bytes key).
      3. The plugin closes fd 3 immediately after the read.
    fd 3 is inherited by bwrap's default fd inheritance — NO fd flag (this
    supersedes the earlier --sync-fd/--keep-fd and the mechanically-wrong
    --rw-bind /dev/fd/3 /dev/fd/3; superseding note).
  attack_vector:
    method: strace_assertion
    target_process: bash_launcher
  expected_outcome:
    classification: property_holds
    audit_row: null
    invariants:
      - bash_reads_fd3: false
      - plugin_reads_fd3_count: 1
      - plugin_closes_fd3_after_read: true
  references:
    - spec://2026-06-06-slice-4-design.md#7.5
  ```

  Run Task 11: 5 entries parse. Commit:

  ```
  test(adversarial): add sbx-2026-005 — fd-3 key inheritance property (#TBD-slice4-pr-s4-7)
  ```

- [ ] **Task 14 — Implement: the misconfigured-policy variants `sbx-2026-006` through `sbx-2026-010` (test-009 closure).**

  Files: Create five YAML files, one per missing/extra flag.

  `sbx-2026-006-policy_missing_unshare_net.yaml` (the prototype; the other four follow the same shape with the flag name swapped):

  ```yaml
  id: sbx-2026-006
  category: sandbox_escape
  title: misconfigured policy — share_net=true re-enables network egress
  attacker_model: misconfigured_policy
  ingestion_path: sandbox_policy_load
  description: |
    Spec §11.4 test-009 closure: the operator ships a policy file with
    flags.share_net = true (or --share-net added to the launcher's
    translation). The launcher's policy validator MUST refuse at load
    time rather than spawn with the relaxed policy. The audit row carries
    reason="policy_invalid_share_net".

    This entry is part of the five-flag misconfigured-policy battery the
    spec mandates: --unshare-net (covered here), --die-with-parent
    (sbx-2026-007), --ro-bind / rebinds root writable (sbx-2026-008),
    --unshare-pid (sbx-2026-009), schema-version-downgrade (sbx-2026-010).
  attack_vector:
    method: ship_invalid_policy
    policy_mutation:
      file: config/sandbox/quarantined-llm.linux.bwrap.policy
      patch:
        path: flags.share_net
        from: false
        to: true
  expected_outcome:
    classification: sandbox_refused
    audit_row:
      hookpoint: supervisor.plugin.sandbox_refused
      reason: policy_invalid_share_net
    launcher_exit_code: nonzero
  references:
    - spec://2026-06-06-slice-4-design.md#7.5
    - spec://2026-06-06-slice-4-design.md#11.4
  ```

  `sbx-2026-007-policy_missing_die_with_parent.yaml`: `patch.path: flags.die_with_parent`, `from: true`, `to: false`. `reason: policy_invalid_die_with_parent`.

  `sbx-2026-008-policy_rebinds_root_writable.yaml`: patch adds a new bind `{src: "/", dst: "/", ro: false}`. `reason: policy_invalid_root_writable`.

  `sbx-2026-009-policy_missing_unshare_pid.yaml`: patch removes `"pid"` from `unshare`. `reason: policy_invalid_unshare_pid`.

  `sbx-2026-010-policy_schema_downgrade.yaml`: patch sets `schema_version: 0` (or deletes the key). `reason: policy_invalid_schema_version`. attacker_model: `misconfigured_policy`.

  Run Task 11: 10 entries parse. Commit:

  ```
  test(adversarial): add sbx-2026-006 through 010 — misconfigured-policy 5-flag battery + schema downgrade (#TBD-slice4-pr-s4-7)
  ```

- [ ] **Task 15 — Implement: `sbx-2026-011-manifest_omits_sandbox_block.yaml` and `sbx-2026-012-macos_sandbox_escape_subset.yaml`.**

  Files: Create both YAMLs.

  `sbx-2026-011`:

  ```yaml
  id: sbx-2026-011
  category: sandbox_escape
  title: manifest omits [sandbox] block — plugin load refused
  attacker_model: insider_author
  ingestion_path: sandbox_policy_load
  description: |
    Spec §7.1: the [sandbox] block is required (no default). A plugin
    manifest without it must trigger plugin.load_refused with
    reason="sandbox_block_missing" rather than fall through to a
    permissive default.
  attack_vector:
    method: ship_invalid_manifest
    manifest_mutation:
      file: plugins/<test_plugin>/manifest.toml
      remove_section: sandbox
  expected_outcome:
    classification: plugin_load_refused
    audit_row:
      hookpoint: plugin.load_refused
      reason: sandbox_block_missing
  references:
    - spec://2026-06-06-slice-4-design.md#7.1
    - spec://2026-06-06-slice-4-design.md#7.12
  ```

  `sbx-2026-012` (macOS advisory):

  ```yaml
  id: sbx-2026-012
  category: sandbox_escape
  title: macOS sandbox-exec escape subset — file/network/subprocess refused
  attacker_model: runtime_compromised
  ingestion_path: stdio_fd3_key_delivery
  description: |
    The macOS sandbox-exec policy is best-effort (ADR-0015). This entry
    bundles the file/network/subprocess escape attempts the Linux trio
    (sbx-2026-001/002/003) covers, collapsed into one entry that runs
    only on macos-latest CI runners. Advisory (continue-on-error: true).
  attack_vector:
    method: bundled
    inner_vectors: [open_etc_passwd, connect_1_1_1_1, execve_bin_sh]
  expected_outcome:
    classification: sandbox_refused
    audit_row: null
    notes: "sandbox-exec refuses each; exact errnos vary by macOS version."
  references:
    - spec://2026-06-06-slice-4-design.md#7.6
    - spec://2026-06-06-slice-4-design.md#7.12
  ```

  Run Task 11: 12 entries parse. Commit:

  ```
  test(adversarial): add sbx-2026-011 (manifest-omits-sandbox-block) + sbx-2026-012 (macOS bundle) (#TBD-slice4-pr-s4-7)
  ```

---

### Component G — Adversarial fixture helpers

The corpus YAMLs above are declarative. The harness needs Python helpers to mutate policy files / manifests / launch the launcher under `strace` / assert the launcher exit code. This component ships those helpers.

- [ ] **Task 16 — Failing test: each adversarial fixture helper has a unit test.**

  Files: Create `tests/adversarial/sandbox_escape/test_fixture_helpers.py`.

  Helpers to test:

  - `policy_with_flag_removed(source_path, flag_dotted_path)` → returns a temp `Path` to a policy file with the named flag removed/inverted.
  - `policy_with_schema_version(source_path, version)` → returns a temp `Path` with `schema_version` set to the given value.
  - `launcher_refuses(plugin_id, manifest_path, policy_path, expected_reason, environment="production")` → spawns the launcher and asserts non-zero exit + the expected audit row was emitted.
  - `strace_launcher_for_fd3_reads(plugin_id, manifest_path, policy_path)` → returns a dict `{"bash_reads_fd3": bool, "plugin_reads_fd3_count": int, "plugin_closes_fd3_after_read": bool}`.

  Each helper has a happy-path unit test. The Linux-specific ones skip on non-Linux via `pytestmark = pytest.mark.skipif(sys.platform != "linux", ...)`.

  Run: expected fail.

- [ ] **Task 17 — Implement: write the four helpers in `tests/adversarial/sandbox_escape/conftest.py`.**

  Files: Create `tests/adversarial/sandbox_escape/conftest.py`.

  ```python
  # tests/adversarial/sandbox_escape/conftest.py
  import shutil
  import subprocess
  import sys
  import tomllib
  import tomli_w
  from pathlib import Path
  from typing import Any

  import pytest

  @pytest.fixture
  def policy_with_flag_removed(tmp_path: Path):
      def _make(source_path: Path, flag_dotted_path: str) -> Path:
          policy = tomllib.loads(source_path.read_text(encoding="utf-8"))
          # Walk dotted path; invert / pop the leaf.
          parts = flag_dotted_path.split(".")
          node: Any = policy
          for part in parts[:-1]:
              node = node[part]
          leaf = parts[-1]
          if isinstance(node.get(leaf), bool):
              node[leaf] = not node[leaf]
          else:
              node.pop(leaf, None)
          out = tmp_path / "mutated.policy"
          out.write_text(tomli_w.dumps(policy), encoding="utf-8")
          return out
      return _make

  @pytest.fixture
  def policy_with_schema_version(tmp_path: Path):
      def _make(source_path: Path, version: int) -> Path:
          policy = tomllib.loads(source_path.read_text(encoding="utf-8"))
          policy["schema_version"] = version
          out = tmp_path / "downgraded.policy"
          out.write_text(tomli_w.dumps(policy), encoding="utf-8")
          return out
      return _make

  @pytest.fixture
  def launcher_refuses(audit_log_capture):
      # audit_log_capture is the Slice-3 fixture that snapshots audit rows
      # written during the test. PR-S4-6 may have renamed it; the worker
      # mirrors the name used by tests/integration/test_launcher_policy_resolver.py.
      def _assert(
          plugin_id: str,
          manifest_path: Path,
          policy_path: Path,
          expected_reason: str,
          environment: str = "production",
      ) -> None:
          env = {
              "ALFRED_ENVIRONMENT": environment,
              "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest_path),
              "ALFRED_SANDBOX_POLICY_PATH": str(policy_path),
          }
          proc = subprocess.run(
              ["bin/alfred-plugin-launcher.sh", plugin_id, "/bin/true"],
              capture_output=True,
              env=env,
              check=False,
          )
          assert proc.returncode != 0, f"launcher exited 0 unexpectedly: {proc.stderr!r}"
          rows = audit_log_capture.rows_for_hookpoint("supervisor.plugin.sandbox_refused")
          assert any(r.fields.get("reason") == expected_reason for r in rows), (
              f"no sandbox_refused audit row with reason={expected_reason!r}; rows: {rows}"
          )
      return _assert

  @pytest.fixture
  def strace_launcher_for_fd3_reads(tmp_path: Path):
      if sys.platform != "linux":
          pytest.skip("strace fixture is Linux-only")
      if shutil.which("strace") is None:
          pytest.skip("strace not installed on runner")
      def _run(plugin_id: str, manifest_path: Path, policy_path: Path) -> dict[str, Any]:
          trace_path = tmp_path / "trace.txt"
          # -f follows forks (plugin is forked from bash); -e read,close
          # narrows the output; -y prints fd context.
          subprocess.run(
              ["strace", "-f", "-e", "read,close", "-o", str(trace_path),
               "bin/alfred-plugin-launcher.sh", plugin_id, "/bin/true"],
              capture_output=True,
              check=False,
          )
          text = trace_path.read_text(encoding="utf-8")
          bash_pid_line = next(ln for ln in text.splitlines() if "launcher.sh" in ln or "bash" in ln)
          bash_pid = int(bash_pid_line.split()[0])
          bash_lines = [ln for ln in text.splitlines() if ln.startswith(f"{bash_pid} ")]
          plugin_lines = [ln for ln in text.splitlines() if not ln.startswith(f"{bash_pid} ")]
          return {
              "bash_reads_fd3": any("read(3," in ln for ln in bash_lines),
              "plugin_reads_fd3_count": sum(1 for ln in plugin_lines if "read(3," in ln),
              "plugin_closes_fd3_after_read": any("close(3)" in ln for ln in plugin_lines),
          }
      return _run
  ```

  Run the Task 16 helper unit tests. Expected: PASS where Linux runner; skip elsewhere.

  Commit:

  ```
  test(adversarial): ship sandbox-escape fixture helpers — policy mutation, launcher-refuses, strace fd-3 (#TBD-slice4-pr-s4-7)
  ```

---

### Component H — Merge-blocking integration test on Linux + macOS advisory

- [ ] **Task 18 — Failing test: `test_sandbox_escape_kernel_enforced.py` — three escape classes, expected to fail with sandbox unconfigured.**

  Files: Create `tests/integration/test_sandbox_escape_kernel_enforced.py`.

  Spec §11.5 promotion target. This is the single merge-blocking integration test for sandbox escape on `ubuntu-latest`.

  ```python
  # tests/integration/test_sandbox_escape_kernel_enforced.py
  """Merge-blocking integration test for PRD §5 line 117 (Linux).

  Boots the launcher chain against the quarantined-LLM plugin and asserts
  the kernel refuses three escape classes. Spec §7.5 + §11.5 (ops-007).

  A macOS variant in the same module is gated by sys.platform and marked
  advisory via `pytestmark = pytest.mark.advisory` (the CI matrix entry
  sets continue-on-error: true).
  """

  from __future__ import annotations

  import errno
  import socket
  import subprocess
  import sys
  from pathlib import Path

  import pytest

  pytestmark = pytest.mark.integration

  REPO_ROOT = Path(__file__).resolve().parents[2]
  PLUGIN_MANIFEST = REPO_ROOT / "plugins" / "alfred_quarantined_llm" / "manifest.toml"
  LINUX_POLICY = REPO_ROOT / "config" / "sandbox" / "quarantined-llm.linux.bwrap.policy"

  @pytest.fixture
  def spawn_quarantined_plugin(launcher_chain_fixture):
      # launcher_chain_fixture comes from PR-S4-6's launcher integration-test
      # conftest. It returns an async context manager that boots
      # bin/alfred-plugin-launcher.sh under bwrap, exec's a test-mode
      # plugin that exposes a `run_in_sandbox(syscall_spec)` MCP method.
      return launcher_chain_fixture

  @pytest.mark.skipif(sys.platform != "linux", reason="bwrap is Linux-only")
  async def test_filesystem_escape_returns_eacces_or_enoent(spawn_quarantined_plugin) -> None:
      async with spawn_quarantined_plugin(PLUGIN_MANIFEST, LINUX_POLICY) as plugin:
          result = await plugin.run_in_sandbox({"syscall": "open", "path": "/etc/passwd", "flags": "O_RDONLY"})
          assert result["errno"] in {errno.ENOENT, errno.EACCES}, result

  @pytest.mark.skipif(sys.platform != "linux", reason="bwrap is Linux-only")
  async def test_network_escape_returns_enetunreach(spawn_quarantined_plugin) -> None:
      async with spawn_quarantined_plugin(PLUGIN_MANIFEST, LINUX_POLICY) as plugin:
          result = await plugin.run_in_sandbox({"syscall": "connect", "address": "1.1.1.1", "port": 443})
          assert result["errno"] == errno.ENETUNREACH, result

  @pytest.mark.skipif(sys.platform != "linux", reason="bwrap is Linux-only")
  async def test_subprocess_escape_returns_eperm(spawn_quarantined_plugin) -> None:
      async with spawn_quarantined_plugin(PLUGIN_MANIFEST, LINUX_POLICY) as plugin:
          result = await plugin.run_in_sandbox({"syscall": "execve", "path": "/bin/sh"})
          assert result["errno"] in {errno.EPERM, errno.ENOENT}, result

  # macOS advisory variant (runs on macos-latest with continue-on-error: true).

  @pytest.mark.advisory
  @pytest.mark.skipif(sys.platform != "darwin", reason="sandbox-exec is macOS-only")
  async def test_macos_sandbox_exec_subset(spawn_quarantined_plugin) -> None:
      macos_policy = REPO_ROOT / "config" / "sandbox" / "quarantined-llm.macos.sb"
      async with spawn_quarantined_plugin(PLUGIN_MANIFEST, macos_policy) as plugin:
          for spec in (
              {"syscall": "open", "path": "/etc/passwd", "flags": "O_RDONLY"},
              {"syscall": "connect", "address": "1.1.1.1", "port": 443},
              {"syscall": "execve", "path": "/bin/sh"},
          ):
              result = await plugin.run_in_sandbox(spec)
              assert result["errno"] != 0, (spec, result)
  ```

  Run: `uv run pytest tests/integration/test_sandbox_escape_kernel_enforced.py -v` — expected: fail (launcher_chain_fixture not yet wired, or policy not yet shipped → the kernel does not block).

- [ ] **Task 19 — Implement: ensure the integration test passes against the policies shipped in Components B/C.**

  Files: Modify `tests/integration/conftest.py` if needed to expose `launcher_chain_fixture`. The fixture's contract:

  - Async context manager.
  - Boots `bin/alfred-plugin-launcher.sh <plugin_id> <test_plugin_path>` with `ALFRED_ENVIRONMENT=test`, the manifest path, and the policy path.
  - The test plugin is a small Python MCP server in `tests/integration/_fixtures/sandbox_test_plugin.py` that exposes one method `run_in_sandbox(spec)` which performs the syscall via `os.open` / `socket.socket.connect` / `os.execve`, captures `OSError.errno`, and returns it to the host.
  - Yields a handle that exposes `await handle.run_in_sandbox(spec)`.
  - On exit, sends `lifecycle.stop` and reaps the launcher subprocess.

  Implementation steps:

  1. Create `tests/integration/_fixtures/__init__.py` if not present.
  2. Create `tests/integration/_fixtures/sandbox_test_plugin.py` — minimal MCP plugin that:

     ```python
     # tests/integration/_fixtures/sandbox_test_plugin.py
     """Test-only quarantined-plugin shape used by the sandbox-escape integration
     test. NOT a production plugin. Lives under tests/ so the production
     plugins/ tree stays clean."""
     import os
     import socket
     import sys
     # ... MCP stdio loop reading method calls; the `run_in_sandbox` method
     # performs the requested syscall and returns {"errno": <int>} where
     # 0 means success (which the test treats as a failure mode for an
     # escape attempt).
     ```

  3. Add the `launcher_chain_fixture` to `tests/integration/conftest.py` (or import it from PR-S4-6's launcher conftest if that fixture already exists).

  4. Verify the `plugins/alfred_quarantined_llm/manifest.toml` `[sandbox] policy_refs.linux` value points at `config/sandbox/quarantined-llm.linux.bwrap.policy` (Task 1 verification confirms).

  Run: `uv run pytest tests/integration/test_sandbox_escape_kernel_enforced.py -v` — expected: PASS on Linux runner; SKIP elsewhere.

  Commit:

  ```
  test(integration): merge-blocking sandbox-escape kernel-enforcement gate on ubuntu-latest (#TBD-slice4-pr-s4-7)
  ```

---

### Component I — CI runner topology + required-status-check promotion

- [ ] **Task 20 — Modify `.github/workflows/ci.yml`: add the `sandbox-escape` job matrix.**

  Files: Modify `.github/workflows/ci.yml`.

  Add a new job (or extend an existing integration-test job) with a strategy matrix:

  ```yaml
  sandbox-escape:
    name: sandbox-escape (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            advisory: false
          - os: macos-latest
            advisory: true
    continue-on-error: ${{ matrix.advisory }}
    permissions:
      contents: read
    env:
      ALFRED_ENVIRONMENT: test
    steps:
      - uses: actions/checkout@v4
      - name: Install bwrap (Linux only)
        if: matrix.os == 'ubuntu-latest'
        run: sudo apt-get update && sudo apt-get install -y bubblewrap strace
      - name: Install uv
        uses: astral-sh/setup-uv@v3
      - name: Run sandbox-escape integration tests
        run: uv run pytest tests/integration/test_sandbox_escape_kernel_enforced.py tests/adversarial/sandbox_escape/ -v
  ```

  The `permissions:` block follows the workflow-author skill's least-privilege convention. The `continue-on-error: ${{ matrix.advisory }}` flips the macOS leg to advisory.

  Use the `author-gating-workflow` skill to confirm the YAML shape matches AlfredOS conventions before pushing.

  Commit:

  ```
  ci: add sandbox-escape job matrix — ubuntu-latest merge-blocking, macos-latest advisory (#TBD-slice4-pr-s4-7)
  ```

- [ ] **Task 21 — Promote `sandbox-escape (ubuntu-latest)` to required status check.**

  After the PR merges, follow the `author-gating-workflow` skill's post-merge promotion step: use `gh api` to add `sandbox-escape (ubuntu-latest)` to the `main` branch's required-status-check list. Update `.github/required-checks.json` (the tracked required-checks manifest — index §4 ops-007 mentions per-PR promotion, not bulked into PR-S4-11).

  ```bash
  gh api -X PATCH /repos/<owner>/<repo>/branches/main/protection/required_status_checks \
      -F contexts[]="sandbox-escape (ubuntu-latest)" \
      -F strict=true
  ```

  (The exact `gh api` invocation matches the `author-gating-workflow` skill's recipe; the worker uses the skill rather than inventing flags.)

  No commit; this is a post-merge GitHub-side action. The PR description records the promotion was performed.

---

### Component J — Operator-facing README

- [ ] **Task 22 — Create `config/sandbox/README.md`.**

  Files: Create `config/sandbox/README.md`.

  Sections:

  1. **What lives here.** One sentence per policy file pointing at the spec section that owns the schema.
  2. **How the launcher uses each file.** Three short paragraphs (Linux/macOS/Windows) covering the launcher's translation step. Cross-reference `bin/alfred-plugin-launcher.sh` and PR-S4-6.
  3. **Editing safety.** Bold warning: editing these files at runtime in production is the operator's responsibility; the launcher's policy validator catches the five misconfigured-policy flag-removal modes adversarial corpus `sbx-2026-006` through `sbx-2026-010` cover, but it does NOT catch arbitrary semantic regressions. Operators run `uv run pytest tests/adversarial/sandbox_escape/ -q` after edits.
  4. **Placeholder substitution.** The Linux policy carries `__routing.yaml[quarantine].provider_url__` as a sentinel for the outbound proxy endpoint; the launcher resolves it at spawn time from `config/routing.yaml`. The macOS policy carries `host.docker.internal:443` as the sentinel; same resolution.
  5. **Windows stub.** The file declares `prd_compliant = false`; AlfredOS does not claim PRD §5 line 117 compliance on Windows-native. WSL2 + the Linux policy is the supported path.

  Length: 60–90 lines. The README is operator-facing English; it is acceptable hardcoded English under the i18n rule (operator-config files, not user-facing strings).

  Commit:

  ```
  docs(sandbox): operator-facing README for the per-OS policy files (#TBD-slice4-pr-s4-7)
  ```

---

### Component K — Final quality gates

- [ ] **Task 23 — Run the full quality bar.**

  ```bash
  cd <repo-root>
  uv run ruff check .
  uv run ruff format --check .
  uv run mypy src/
  uv run pyright src/
  uv run pytest tests/unit/sandbox/ -v
  uv run pytest tests/unit/hooks/test_sandbox_stub_used_hookpoint.py -v
  uv run pytest tests/adversarial/sandbox_escape/ -q
  uv run pytest tests/integration/test_sandbox_escape_kernel_enforced.py -v
  ```

  All must pass on Linux. The macOS leg is advisory; failures there do NOT block.

  If `uv run pytest tests/adversarial/` (full adversarial suite) raises new findings unrelated to this PR — STOP, escalate. The adversarial suite is release-blocking and this PR's changes must not regress unrelated entries.

- [ ] **Task 24 — Run `make check` + the local pre-push routine.**

  ```bash
  make check
  ```

  Per project memory `feedback_make_check_before_push.md`, this catches mechanical breakage in 5 seconds and avoids a 3–5 minute CI cycle burn.

- [ ] **Task 25 — Run `/review-pr` and CodeRabbit CLI locally before pushing.**

  Per project memory `feedback_local_review_before_push.md`, the local cycle of `/review-pr` + CodeRabbit CLI closes the feedback loop in seconds vs the cloud round-trip.

  ```bash
  /review-pr
  # Address any HIGH findings before push.
  ```

  Commit (if any review-fixup needed):

  ```
  fix(sandbox): address /review-pr findings on sandbox-policies PR (#TBD-slice4-pr-s4-7)
  ```

  Or, for in-branch review-fixups per `procedural_in_branch_fixes.md`:

  ```bash
  git commit --fixup=<sha>
  git rebase -i --autosquash main
  ```

- [ ] **Task 26 — Open the PR.**

  Use `commit-commands:commit-push-pr` if appropriate, or the `gh pr create` recipe from the operating manual. PR body covers:

  - **Summary:** ships per-OS sandbox policy bytes the launcher (PR-S4-6) resolves, the merge-blocking kernel-enforcement integration test on `ubuntu-latest`, the advisory macOS variant, and the `sbx-2026-001` through `sbx-2026-012` adversarial corpus covering insider-author + runtime-compromised + 5-flag misconfigured-policy + schema-version-downgrade + manifest-omits-sandbox-block attacker models.
  - **Test plan:**
    - [x] `uv run pytest tests/unit/sandbox/ -v` passes
    - [x] `uv run pytest tests/unit/hooks/test_sandbox_stub_used_hookpoint.py -v` passes
    - [x] `uv run pytest tests/adversarial/sandbox_escape/ -q` passes
    - [x] `uv run pytest tests/integration/test_sandbox_escape_kernel_enforced.py -v` passes on Linux
    - [x] `make check` clean
    - [x] `/review-pr` HIGH findings addressed
    - [x] `sandbox-escape (ubuntu-latest)` promoted to required status check post-merge

  Reference `#TBD-slice4-pr-s4-7` and link the spec/index anchors above.

---

## §7 Spec Coverage Map

| Spec section | Implementing task(s) |
|---|---|
| §7.5 Linux bwrap policy file shape (`--ro-bind`, `--tmpfs`, `--unshare-*`, `--die-with-parent`, no `--share-net`; fd 3 inherited by default — NO fd flag, superseding note) | Tasks 3, 4 |
| §7.5 fd-3 inheritance discipline (sec-004 round-4) — bash never reads, plugin reads exactly once | Tasks 13 (corpus), 17 (strace helper) |
| §7.5 Process-level posture inheritance — covered by PR-S4-6 supervisor/launcher; no new code here | Verification only (§2) |
| §7.6 macOS sandbox-exec policy file shape (`deny default`, four allows, proxy + catch-all deny) | Tasks 5, 6 |
| §7.7 Windows stub policy TOML — `schema_version`, `isolation`, `prd_compliant=false`, `notes` | Tasks 7, 8 |
| §7.7 Production refuse / development stub-used behaviour | PR-S4-6 territory; this PR registers the hookpoint (Tasks 9, 10) |
| §7.8 Quarantined-LLM manifest update `kind: none` → `kind: full` + `policy_refs` map | **PR-S4-6 territory**; verified by Task 1 (one-time ownership rule) |
| §7.11 `SANDBOX_REFUSED_FIELDS` / `SANDBOX_STUB_USED_FIELDS` audit constants | Consumed via Tasks 9, 10, 14, 17 — constants defined in PR-S4-0a |
| §7.12 Adversarial corpus: `bwrap_filesystem_escape`, `bwrap_network_escape`, `bwrap_subprocess_escape` | Task 12 (`sbx-2026-001/002/003`) |
| §7.12 `macos_sandbox_escape_subset` | Task 15 (`sbx-2026-012`) |
| §7.12 `manifest_omits_sandbox_block` → `plugin.load_refused` with `reason="sandbox_block_missing"` | Task 15 (`sbx-2026-011`) |
| §11.4 Insider-author attacker model | Tasks 13 (`sbx-2026-005`), 15 (`sbx-2026-011`) |
| §11.4 Runtime-compromised attacker model | Task 12 (`sbx-2026-001` through `004`), Task 15 (`sbx-2026-012`) |
| §11.4 Misconfigured-policy attacker model — 5 flag variants + schema downgrade | Task 14 (`sbx-2026-006` through `010`) |
| §11.5 `tests/integration/test_sandbox_escape_kernel_enforced.py` merge-blocking from S4-7 | Tasks 18, 19 |
| §11.5 CI runner topology — ubuntu-latest merge-blocking + macos-latest advisory (ops-002 / ops-007) | Tasks 20, 21 |
| Index §3 hookpoint surface — `supervisor.plugin.sandbox_stub_used` carrier_tier=T0 | Tasks 9, 10 |
| Index §3 sandbox launcher contract — policy bytes consumed by launcher | Tasks 4, 6, 8 |
| Index §4 cross-fork integration test gate — promote per-PR | Tasks 20, 21 |

**Deferred / not in PR-S4-7:**

- Launcher policy-resolution logic (`bin/alfred-plugin-launcher.sh` extensions) — PR-S4-6.
- Quarantined-LLM manifest migration `kind: none` → `kind: full` — PR-S4-6.
- macOS sandbox-exec deprecation handling — post-MVP.
- Windows-native sandbox — post-MVP.
- `alfred sandbox lint <plugin>` CLI — Slice-5 backlog (spec §1.2, index §8).
- `SecretBroker.get_bytes(name) -> bytearray` zeroizable-buffer broker API — Slice-5 backlog (spec §7.5 honest limitation).

---

## §8 Cross-reference notes for the implementing worker

1. **TOML over YAML on the Linux policy** — chosen for parity with `manifest.toml` and the Windows stub. Spec §7.5 leaves the format choice deferred to PR-S4-7; we land on TOML for one fewer parser dependency on the launcher's pre-launcher Python helper.
2. **The Linux policy's `network.outbound_allowlist` sentinel** — `__routing.yaml[quarantine].provider_url__` is documented in `config/sandbox/README.md` Task 22. The launcher (PR-S4-6) is responsible for substituting it at spawn time from `config/routing.yaml`. This PR does NOT modify the launcher; if PR-S4-6's launcher logic does not handle the sentinel, this PR's integration test (Tasks 18, 19) fails loudly during the launcher-chain boot, surfacing the gap rather than masking it.
3. **The macOS `host.docker.internal:443` literal** — also a sentinel. Same launcher-side resolution. The unit test (Task 5) asserts the literal exists; the integration test exercises the real substitution.
4. **The fd-3 strace fixture is Linux-only** — the macOS `dtruss` equivalent is not portable enough for the advisory variant. The spec acknowledges this; `sbx-2026-005` declares `attacker_model: insider_author` and runs only on Linux.
5. **Hookpoint registration order** — PR-S4-6 declares `supervisor.plugin.sandbox_refused`; this PR declares `supervisor.plugin.sandbox_stub_used`. Index §3 fixes ownership. If PR-S4-6 has not landed when this PR's worker starts, the Component E tasks (Tasks 9, 10) block until PR-S4-6 merges. The Component F tasks (adversarial corpus) and Component B/C/D tasks (policy files) can proceed in parallel with PR-S4-6 review because they do not depend on the launcher's runtime behaviour.
6. **Required-status-check promotion is per-PR** — index §4 ops-007 closure. This PR's post-merge step (Task 21) promotes `sandbox-escape (ubuntu-latest)` to a required check on `main`. PR-S4-11 graduation does NOT bulk-promote.
7. **The `pytestmark = pytest.mark.advisory` marker** — exists in the AlfredOS test harness conventions; if the marker is missing the worker confirms with `grep -rn "pytest.mark.advisory" tests/` whether to fall back to `continue-on-error: true` at the workflow level only (no `@pytest.mark.advisory` decorator needed in code).
8. **Audit-row capture in `launcher_refuses` fixture** — Task 17 references `audit_log_capture` as a fixture from PR-S4-6's launcher integration tests. If the fixture's name differs the worker mirrors the actual name; if no such fixture exists the worker writes a minimal one that subscribes to the in-memory `AuditWriter` test substitute and snapshots rows during the test.
9. **The strace test is best-effort** — `sbx-2026-005` runs only when `strace` is installed on the runner. CI installs it via the `apt-get install -y bubblewrap strace` step (Task 20). Local developer machines without strace skip the test cleanly.
10. **The misconfigured-policy `reason` strings are launcher-defined** — Task 2 reconciles this PR's YAML `expected_outcome.reason` against the actual strings the launcher emits. If PR-S4-6 uses different strings, the worker updates THIS PR's YAML to match the launcher (the launcher is the source of truth; the corpus follows). The PR description records the reconciliation.

---

## §9 Risks + mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `bwrap` not installed on the developer's local machine, integration test silently skips | Medium | Medium | The Linux integration test asserts `shutil.which("bwrap") is not None` at module level; if missing, the test FAILS rather than skips. CI installs it explicitly in Task 20. |
| The fd-3 strace test is flaky on heavily-loaded CI runners | Low | Low | The `strace -f -e read,close -o <file>` output is parsed for the bash-PID's read-syscalls only; race conditions in interleaved syscalls do not affect the read-fd-3 invariant because the bash launcher does not race with itself. |
| The macOS sandbox-exec policy works on the current `macos-latest` runner but stops working on a future runner image due to Apple deprecating sandbox-exec further | Medium | Low | The macOS leg is advisory (`continue-on-error: true`). ADR-0015 acknowledges macOS as best-effort. If the runner image bumps and the test fails, Slice 5 takes the deprecation-handling work; no Slice-4 release is blocked. |
| PR-S4-6's launcher emits different `reason` strings than the corpus YAMLs encode | High at plan-write time | High | Task 2 reconciles before any YAML lands. The worker treats the launcher's emit-site as the source of truth; the corpus follows. |
| The Windows stub policy's `notes` field accidentally drifts away from PRD §5 line 117 reference | Low | Low | Task 7's `test_notes_field_explains_non_compliance` asserts the literal substring "PRD §5 line 117" is present. |
| New `sbx-2026-NNN` adversarial entries collide with another worker's parallel PR | Low | Low | The `NNN` sequence is monotonic within a single category-year; merge conflict resolution renumbers if needed. The merge order index §2 has S4-7 trailing only S4-3 and S4-6, neither of which add `sbx-` entries. |
| `register_hookpoint("supervisor.plugin.sandbox_stub_used", ...)` lands before PR-S4-6's emit-site, leaving an unused hookpoint declaration | Low | None | Acceptable. The hookpoint registry stores declarations; an unused declaration is inert until a publisher invokes it. PR-S4-6's emit-site lands separately. |
| Corpus YAML `id` does not match its filename stem | Low | Medium | Task 11's parametrized test asserts `payload.id == yaml_path.stem` per entry. The harness rejects mismatches at collection time. |

---

## §10 Definition of Done

- [ ] All §6 tasks committed.
- [ ] `make check` clean.
- [ ] `uv run pytest tests/unit/sandbox/ -v` — all PASS.
- [ ] `uv run pytest tests/unit/hooks/test_sandbox_stub_used_hookpoint.py -v` — all PASS.
- [ ] `uv run pytest tests/adversarial/sandbox_escape/ -q` — all PASS (12 entries parse + Component G helpers pass).
- [ ] `uv run pytest tests/integration/test_sandbox_escape_kernel_enforced.py -v` — PASS on `ubuntu-latest`; advisory result on `macos-latest`.
- [ ] CI `sandbox-escape (ubuntu-latest)` job runs and is green on the PR.
- [ ] CI `sandbox-escape (macos-latest)` job runs (advisory; result recorded but not blocking).
- [ ] `/review-pr` HIGH findings addressed; CodeRabbit cloud-review reviewed; review-thread resolution discipline followed per `feedback_cr_thread_resolution.md`.
- [ ] PR merged.
- [ ] `sandbox-escape (ubuntu-latest)` promoted to required status check on `main` via `gh api` per the `author-gating-workflow` skill (Task 21).
- [ ] `.github/required-checks.json` (or the tracked equivalent) updated with the new required check.
- [ ] PR-S4-11 graduation runbook back-patched with the per-OS policy file paths (or PR-S4-11 owns the section if PR-S4-7 lands first).

Once these are checked, the kernel-enforcement leg of PRD §5 line 117 is satisfied for Linux + advisory-best-effort on macOS, and PR-S4-7 is closed.

---

## §11 Followups seeded for Slice 5

These are NOT in PR-S4-7 scope but are worth tracking when Slice 5 kicks off (cross-referenced from index §8):

- `alfred sandbox lint <plugin>` CLI — validates a third-party plugin's declared `sandbox.policy_refs` against the launcher's resolver without spawning. Useful once third-party plugins arrive.
- `SecretBroker.get_bytes(name) -> bytearray` — zeroizable provider-key delivery, closing the Supervisor-side residency-window limitation spec §7.5 acknowledges. PR-S4-7's `sbx-2026-005` strace assertion holds the bash-launcher property; the Supervisor-side property awaits Slice 5.
- `watchdog`-based migration for sandbox policy mtime polling — if PR-S4-4's `PolicyWatcher` migrates to `watchdog`, the sandbox-policy files inherit the same migration. Not currently planned for sandbox policies (the launcher reads the policy once at plugin spawn; no polling needed).
- `macos-latest` advisory leg graduation to merge-blocking — when Apple ships a sandbox-exec replacement or the deprecation removal date approaches, the advisory leg should be upgraded or replaced. Slice 5+ scope.
- Per-`adapter_kind` sandbox policy templates — if Slice-5 ships third-party comms adapters (Telegram, Slack), each one needs its own `config/sandbox/<adapter>.<os>.<ext>` policy file. The shape is the same as the quarantined-LLM trio this PR ships; the launcher's resolver is generic.

---

End of plan.
