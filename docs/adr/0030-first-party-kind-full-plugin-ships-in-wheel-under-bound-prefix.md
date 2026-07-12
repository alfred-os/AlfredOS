# ADR-0030: First-party `kind=full` plugin code ships in the wheel under a bound prefix; sandboxed children exec a bound real interpreter

- **Status:** Proposed
- **Date:** 2026-06-11
- **PR:** PR-S4-11c-2b0 (epic #237 — Slice-4 graduation closer)
- **Amends / extends:** [ADR-0015](0015-slice4-containerised-quarantined-llm.md) (Slice-4
  containerised quarantined-LLM subprocess). ADR-0015's spawn target was the repo-root
  `plugins/alfred_quarantined_llm` plugin; this ADR moves first-party `kind=full` child code into
  the installed package so it is reachable inside the `bwrap` sandbox. ADR-0015's factual amendment
  (2026-06-11) records the spawn-target move; ADR-0015 status stays `Proposed` (human-gated).
- **Related:** [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)
  (process-boundary isolation, hybrid-isolation relaxation), ADR-0029 (inline-over-wire quarantine
  content path), PRD §5 (hybrid isolation line 119, dual-LLM split line 122, **DEC-007** line 606),
  spec §5.1 / §5.2 / §5.3 / §7.1.
- **Amended by:** [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — Spec B G6-1: the gateway is now a SECOND launcher / bwrap host (in addition to alfred-core), with `cap_add: SETUID` + the `alfred-bwrap` AppArmor/seccomp profiles.

## Context

ADR-0015 specifies the quarantined-LLM subprocess runs under `bwrap` with `sandbox.kind="full"`.
The shipped Linux policy (`config/sandbox/quarantined-llm.linux.bwrap.policy`) binds **`/usr`,
`/lib`, `/lib64` read-only only** — a deliberately tight mount namespace (no `/etc`, no `/home`, no
repo bind) so a compromised child has no host filesystem, host shell, or host env (proven by
`sbx-2026-003/004/006`).

> **AMENDED 2026-07-12 ([#269](https://github.com/alfred-os/AlfredOS/issues/269)) — `/lib64` is now
> a SOFT bind; the reachable set is unchanged.** The bind-set above is still the invariant, but
> `/lib64` is declared in a new `ro_binds_try` policy field and emitted as `--ro-bind-try` (bind iff
> the source exists, else skip) rather than a hard `--ro-bind`. Reason: `/lib64` holds the dynamic
> linker on x86-64 but **does not exist on arm64**, where the loader is `/lib/ld-linux-aarch64.so.1`
> under the already-bound `/lib`. A hard bind therefore killed the sandbox launch on aarch64
> (`bwrap: Can't find source path /lib64`), so the child never spawned — the same class of
> "the child cannot start at all" blocker this ADR exists to record (cf. [ADR-0037](0037-production-quarantine-sandbox-boundary.md)).
>
> **This does not widen the sandbox**: the mount stays read-only where it exists, and a path that
> does not exist was never reachable from inside. **Authoring rule:** `ro_binds_try` is a CLOSED
> vocabulary (`_SOFT_BINDABLE_PATHS` in `alfred.plugins.sandbox_policy`, today `{"/lib64"}`) — a
> soft bind SILENTLY skips a missing source, so only genuinely **arch-variable** paths may go there.
> Anything that must always exist (`/usr`, `/lib`, Discord's `/etc/ssl/certs`) stays a HARD
> `ro_binds` entry, where a missing source fails loud instead of degrading the sandbox in silence
> (CLAUDE.md hard rule #7). A policy soft-binding anything outside the allow-list is refused at
> parse time with `SandboxPolicyInvalid(reason="soft_bind_forbidden_path")`.

When PR-S4-11c-2b drove the FIRST real `kind=full` spawn end-to-end (the docker real-spawn proof on
`debian:bookworm`, bubblewrap 0.8.0), two structural blockers surfaced that no mac/unit leg could
catch — only a real bwrap spawn under root exercises them:

1. **The child CODE was unreachable.** The quarantined-LLM child lived at repo-root
   `plugins/alfred_quarantined_llm/` and is EXCLUDED from the wheel
   (`[tool.hatch.build.targets.wheel] packages = ["src/alfred"]`); in dev it is imported via a `.`
   `pythonpath` entry. Under `bwrap` the repo root is NOT bound, so
   `import plugins.alfred_quarantined_llm.quarantine_plugin` fails — the code physically does not
   exist inside the sandbox's mount namespace. Binding `/repo` (Option B) was rejected: it would
   bind `.env` / `.git` / operator secrets into the most adversary-facing surface in the system — a
   security regression.

2. **The INTERPRETER was unreachable.** A `uv`-venv `sys.executable` is a SYMLINK to
   `~/.local/share/uv/python/...`, outside any bound path → `bwrap: execvp <python>: No such file
   or directory`. The exec target must be a REAL binary under a bound prefix.

The quarantined LLM is the load-bearing T3 trust boundary (PRD DEC-007: the dual-LLM split is
non-negotiable). A `kind=full` child that cannot be spawned at all is not merely a bug — it blocks
the Slice-4 graduation criterion that the dual-LLM boundary is proven against a real sandboxed
child.

## Decision

**First-party `kind=full` plugin code ships IN the installed `alfred` wheel under a bound prefix,
and the sandboxed child execs a bound REAL interpreter.**

Concretely, for the quarantined-LLM child (the first instance):

1. **Wheel co-location.** Move the child out of repo-root `plugins/alfred_quarantined_llm/` INTO the
   installed package `alfred.security.quarantine_child` (`__main__.py` + `provider_dispatch.py` +
   `__init__.py` + `manifest.toml`). It ships in the wheel (`packages = ["src/alfred"]`) → lands at
   `/usr/.../site-packages/alfred/security/quarantine_child/` → **already covered by the policy's
   `/usr` read-only bind**. The bwrap policy is UNTOUCHED — no widening. The child is spawned via
   `python -m alfred.security.quarantine_child`.

2. **Bound-interpreter contract.** The `bwrap` exec target must be a real binary under a bound
   prefix.
   - **Production:** run the daemon under the pip-installed `/usr` CPython; `sys.executable`
     resolves it, and the policy's `/usr` bind covers interpreter + site-packages.
   - **Dev / CI:** a new env override `ALFRED_QUARANTINE_CHILD_PYTHON` (consumed by
     `spawn_quarantine_child_io` in `src/alfred/security/quarantine_child_io.py`, default
     `sys.executable`) points the child at a real interpreter binary with `alfred` installed into it.

   **Amendment (2026-06-12, PR #250):** the bound-interpreter contract no longer requires the
   interpreter to live under `/usr`. `bin/alfred-plugin-launcher.sh` now binds the configured
   interpreter's install prefix (`dirname`-of-`dirname` of the realpath'd executable) read-only into
   the sandbox and execs the realpath, so the child can run a self-contained
   python-build-standalone — a `proto`/`uv`-managed hermetic 3.14 under `~/.proto` whose interpreter,
   stdlib, and site-packages share one prefix. The interpreter is the operator-configured
   `<executable>` spawn arg (never attacker-controlled); the extra bind is read-only and
   redundant-but-harmless when it already resolves under the policy's `/usr` bind. This removes the
   system-python dependency the #248 real-spawn CI gate hit, and supersedes the earlier
   `/usr/bin/python3` framing of this bullet. The #248 CI gate provisions 3.14 via `proto` +
   `uv pip install --python`, NOT a system/deadsnakes python.

   This extra bind is **opt-in** (CR #250): `EXECUTABLE` is the launcher's generic exec target for
   EVERY `kind:full` plugin, so binding `dirname(dirname(realpath))` unconditionally would widen the
   namespace for any plugin (a shallow / repo-root exec → an unintended host subtree, worst-case
   `/`). The bind is scoped to callers that set `ALFRED_SANDBOX_BIND_INTERP_PREFIX=1` — only the
   quarantine-child spawn (`_child_env`) does, because only it execs a bound interpreter that may
   live outside the static binds. Generic `kind:full` plugins run under a `/usr` interpreter the
   policy already binds, don't opt in, and are never widened. The launcher fails **closed**
   (`supervisor.sandbox.refused.interpreter_prefix_too_broad`, hard rule #7) when the opted-in
   prefix resolves to `/` or empty, rather than binding host root.

3. **Bounded reachable surface.** The child imports only the extraction schemas + `ProviderCapability`
   — NO privileged `alfred.audit` (the signed audit writer), `alfred.core` (orchestrator / loop /
   supervisor), `alfred.memory`, secret broker, capability gate, or DLP. This bound is codified by a
   release-blocking import-closure guard (`tests/unit/security/test_quarantine_child_import_closure.py`):
   importing the child entry pulls in no forbidden-root module. Moving privileged code into the
   child's reachable graph would break the dual-LLM reachable-surface bound (PRD DEC-007 / hard rule
   #5) and fail the guard.

The `provider_dispatch` module (the only `httpx` importer) stays a LAZY in-function import on the
dead `handle_extract` path, so the live deterministic-echo loop's module-scope closure carries no
egress-capable import — separately enforced by the #230 go-live egress gate.

## Consequences

### Positive

- The `kind=full` quarantined-LLM child is import-reachable inside the sandbox with **zero policy
  widening** — the tight `/usr`-only mount namespace (no `/etc`, no repo bind) is preserved, and the
  `sbx-2026-003/004/006` containment proofs still hold.
- The dual-LLM boundary is now provable against a REAL bwrapped child (the docker-only
  `tests/integration/test_quarantine_child_real_spawn.py`, direct-spawn shape — no daemon flip).
- The bound-interpreter contract makes the dev/CI vs production interpreter difference explicit and
  testable, instead of a silent `execvp` failure deep inside bwrap.

### Negative / costs

- First-party `kind=full` plugin code must live under `src/alfred` (wheel-included), not repo-root
  `plugins/`. This is a placement constraint on future `kind=full` first-party plugins.
- The bounded reachable surface is a STANDING constraint: a future change that imports a privileged
  module from the child trips the import-closure guard (intended — it is a trust-boundary tripwire,
  not a nuisance).
- The `ALFRED_QUARANTINE_CHILD_PYTHON` override is a dev/CI affordance that must be set correctly in
  the docker/UAT harness (documented in the real-spawn test docstring).

### Neutral / follow-ups

- **Discord (`plugins/alfred_discord`) is the SECOND `kind=full` instance** and hits the SAME
  repo-root, wheel-excluded gap on its real spawn. Its migration is deferred behind
  [#230](https://github.com/MrReasonable/AlfredOS/issues/230) (its egress release-blocker). This ADR
  records the principle so the next `kind=full` plugin does not re-discover the gap.
- This is a PRECURSOR PR: it ships the wheel-co-located child + the spawn substrate
  (`quarantine_child_io.py`), but the production daemon STAYS on the ADR-0027 fixture extractor (no
  flip). The atomic production flip is the final PR-S4-11c-2b (mirrors 11c-1's `build_orchestrator`
  — machinery merged ahead of its production caller).
- Egress is still NOT kernel-enforced (#230); the 2b deterministic-echo child makes no provider call,
  so the open-egress gap contains nothing live (the #230 go-live gate enforces the child stays
  egress-free until #230 lands).

## Alternatives considered

- **(B) Bind the repo (or the plugin dir) into the sandbox policy.** Rejected: widens the mount
  namespace to include `.env` / `.git` / operator secrets, regressing the containment the policy
  exists to provide. A security regression on the most adversary-facing surface.
- **(D) Provision a real-binary interpreter under `/usr` + install the plugin under a bound prefix
  WITHOUT moving it into the package.** Rejected as more moving parts (a separate deployment layout /
  Dockerfile that does not exist at repo root) for no benefit over wheel co-location, which the
  existing wheel build already produces.
- **Keep the child at repo-root and accept `kind=full` cannot spawn it.** Rejected: blocks the
  Slice-4 dual-LLM graduation criterion (PRD DEC-007).
