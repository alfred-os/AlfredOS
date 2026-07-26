# ADR-0055 — Single repo-root resolution convention

- **Status**: Accepted
- **Date**: 2026-07-26
- **Slice**: #469 Step 3 / #500 (alfred-core boots in the shipped image)
  (`docs/superpowers/specs/2026-07-25-500-core-boots-shipped-image-design.md`,
  Part A)
- **Relates to**: issue [#494](https://github.com/alfred-os/AlfredOS/issues/494)
  (the e2e boot lane this unification flips green), issue
  [#499](https://github.com/alfred-os/AlfredOS/issues/499) (gateway Settings
  decoupling — its comms review first flagged the `settings.py` /
  `_launcher_spawn.repo_root()` pair as an "unexercised dependency that must
  agree in the shipped image"), [ADR-0036](0036-gateway-adapter-hosting-inversion.md)
  (gateway adapter-hosting inversion — `gateway/adapter_child_factory.py` is a
  second bwrap-launcher host and a call site this ADR routes),
  [ADR-0053](0053-three-layer-environment-precedence.md) (three-layer
  `environment` precedence — cited here as a **contrast**: that ADR's
  `/etc`-vs-env trust machinery does not apply to the seam this ADR defines;
  see Trust model below), the established `/app`-fallback precedent in
  `src/alfred/i18n/translator.py`
- **Supersedes**: the copy-pasted per-module `Path(__file__).resolve().parents[N]`
  pattern previously present in `config/settings.py`, `cli/_launcher_spawn.py`,
  `security/capability_gate/_comms_adapter_grants.py`, and
  `security/quarantine_child_io.py` (no ADR recorded that pattern; it is
  retired here, not formally deprecated from a prior number).

## Context

`docker/alfred-core.Dockerfile` installs `alfred` **non-editable** into a PBS
Python prefix, so in the built image the package lives under
`/opt/alfred-python/lib/python3.14/site-packages/alfred/…` — the source
tree's `src/` wrapper level is gone. Every `Path(__file__).resolve().parents[N]`
"repo root" computation that assumed the source-checkout layout **overshoots**
in this layout, and modules at different nesting depths overshoot by different
amounts. A full `alfred daemon start` boot-path trace for #500 found four
independent repo-root resolvers on the boot-to-healthy path, at three
different `parents[N]` depths (`config/settings.py` at `parents[3]`,
`security/capability_gate/_comms_adapter_grants.py` at `parents[4]`,
`cli/daemon/_daemon_probes.py` reading a hardcoded module constant derived at
`parents[4]` that additionally **ignored** the `ALFRED_PLUGIN_LAUNCHER`
override) — plus a fifth site (`gateway/adapter_child_factory.py`) added by
Spec B's gateway-hosted adapter launcher. Because the sites disagree on depth,
they cannot be fixed consistently by editing each in place — that is precisely
the drift #499's comms review flagged as an unexercised cross-module
dependency that "must agree in the shipped image." The correct fix is
structural: one resolver, one known depth, every call site routes through it.

The artifacts at stake — `plugins/`, `bin/`, `config/`, `alembic.ini` — are
runtime assets the running container reads by path, not Python code the
interpreter imports; they are orthogonal to wherever `pip`/`uv` placed the
`alfred` package itself.

## Decision

`src/alfred/_repo_root.py` is the single source of truth for the in-tree repo
root. It exposes one function:

```python
def repo_root() -> Path: ...
```

Resolution order, implemented by the pure helper `_resolve()`:

1. **`ALFRED_REPO_ROOT` environment variable** — the explicit deploy-time
   seam. `docker/alfred-core.Dockerfile` sets it to `/app` (its `WORKDIR`) in
   the runtime stage. A present, non-blank value wins unconditionally — the
   installed image never depends on `__file__` arithmetic.
2. **Marker-gated source-tree fallback** — `Path(__file__).resolve().parents[2]`
   (`src/alfred/_repo_root.py` → `alfred` → `src` → `<repo>`), used only if
   that directory contains a `plugins/` subdirectory. This matches `uv run
   pytest` from a source checkout or worktree without requiring the env var.
3. **`/app` terminal fallback** — mirrors the existing `/app` fallback
   candidate in `src/alfred/i18n/translator.py`; reached only when neither of
   the above resolves.

The module is dependency-free (`os` + `pathlib` only), so `config/settings.py`
can import it during very-early boot without pulling the `cli` package into
its closure — the prior per-module comment that said as much ("do NOT import
`_launcher_spawn`") is replaced by importing `alfred._repo_root` directly.

**Every repo-root call site routes through `repo_root()`.** Confirmed at HEAD:

- `config/settings.py` — `validate_comms_adapter_ids` calls `repo_root()`
  fresh per validator invocation, joining `plugins/<adapter_id>/manifest.toml`
  and re-anchoring the `is_relative_to(plugins_root)` containment check.
- `cli/_launcher_spawn.py` — its own `repo_root()` is a thin delegating
  wrapper (`return _resolve_repo_root()`), kept so existing importers and test
  patches of `_launcher_spawn.repo_root` keep working; `launcher_path()`
  builds the launcher default from it.
- `security/capability_gate/_comms_adapter_grants.py` — the first-party grant
  seed calls `repo_root()` fresh per call, computing its own sink-local
  `plugins_root` containment check the same way `Settings` does (defense in
  depth, #364), so the two can never independently drift.
- `cli/daemon/_daemon_probes.py` — routes indirectly: it imports and calls
  `launcher_path()` from `cli/_launcher_spawn.py` rather than resolving a path
  itself, closing the prior bug where its hardcoded module constant ignored
  `ALFRED_PLUGIN_LAUNCHER`.
- `security/quarantine_child_io.py` — a private `_repo_root()` wrapper
  delegates to `alfred._repo_root.repo_root()`, kept for existing test
  patches; used only to build the default launcher path (the quarantine child
  code itself ships in the wheel per ADR-0030 and needs no repo-relative
  import root).
- `plugins/comms_stdio_transport.py` — a private `_repo_root()` wrapper
  imports `alfred._repo_root` directly (not `cli._launcher_spawn`) to avoid
  closing an import cycle (`cli._launcher_spawn` already imports
  `plugins._comms_child_env`).
- `gateway/adapter_child_factory.py` — `_launcher_path()` calls `repo_root()`
  directly; the gateway is a second bwrap-launcher host (ADR-0036) that
  previously computed its own inline `parents[3]`.

`i18n/translator.py` is unchanged by this ADR. It resolves a *specific
catalog directory* through a richer three-candidate search (source tree /
`/app/locale` / wheel-embedded `alfred/_locale`) that already works correctly
in the shipped image; the generic resolver here does not replace it, though
its first candidate could optionally consume `repo_root()` in the future.

## Trust model (sec-002/sec-003)

`ALFRED_REPO_ROOT` is a **process-environment seam**, set by whoever controls
process launch — the Dockerfile's `ENV` directive, or an operator's shell for
a bare-host run. No T3-reachable or lower-trust input can set or influence it:
it is not read from a request body, a plugin manifest, or any content that
crosses the [trust tier](../glossary.md#trust-tier) boundary. This is why it
needs **none** of the three-layer `os.environ` > `/etc` > `.env` precedence
machinery [ADR-0053](0053-three-layer-environment-precedence.md) builds for
`Settings.environment` — that machinery exists because `environment` gates a
security-load-bearing decision (the sec-002 unsandboxed-in-production refusal)
and a lower-trust `.env` source could otherwise downgrade it silently.
`ALFRED_REPO_ROOT` gates no comparable security decision; it only relocates
*where* in-tree artifacts are read from, and the sole party who can set it
already controls the process's entire environment and filesystem.

The manifest path-traversal containment guard is unchanged by this ADR: every
call site that resolves a manifest path re-anchors `plugins_root` to
`repo_root() / "plugins"` and checks `is_relative_to(plugins_root)` before
reading, exactly as it did against the previous `parents[N]` root. Unifying
the resolver changes *what depth `root` resolves to*, not the containment
check built on top of it — `validate_comms_adapter_ids` (`config/settings.py`)
and the first-party grant seed (`security/capability_gate/_comms_adapter_grants.py`)
each still perform their own sink-local re-check (defense in depth, #364)
rather than trusting the other's validation.

## Scope boundaries (arch-003)

This ADR deliberately excludes two adjacent concerns:

- **`src/` is not COPYed into the runtime image, and this ADR does not change
  that.** The shipped `ALFRED_COMMS_ENABLED_ADAPTERS=["alfred_tui"]` default
  needs no `/app/src` — the TUI carrier is socket-backed and spawns no
  subprocess. Only the opt-in stdio carrier for Discord and reference
  adapters (`cli/daemon/_comms_boot.py`'s `_spawn_comms_adapter`) joins
  `repo_root() / "src"`, and it is unreached by the shipped default. Making
  that path resolve correctly in the image is tracked as its own follow-up,
  not this ADR's job — this ADR fixes path *resolution*, not what the image
  contains.
- **`audit.hash_pepper` derivation and `state.git` seeding stay with
  `bin/alfred-setup.sh`.** Neither gates boot-to-healthy for the shipped
  default (the pepper derives lazily on first inbound hash use; `state.git` is
  read via a sentinel-returning helper that does not refuse on an unseeded
  repo), so neither belongs in a boot-time resolver.

## Consequences

### Positive

- **One resolution algorithm, one known depth.** The `parents[N]`-depth drift
  that caused four boot-path gates to disagree cannot recur structurally — a
  future change to precedence or fallback behavior touches one function.
- **The installed image no longer depends on `__file__` arithmetic.** The
  explicit `ALFRED_REPO_ROOT=/app` deploy seam (set by
  `docker/alfred-core.Dockerfile`) is authoritative in the shipped container;
  no call site needs to reason about how many directories a non-editable
  install drops.
- **Closes the const-ignores-env bug in `cli/daemon/_daemon_probes.py`.** Its
  launcher self-test previously read a hardcoded module constant that could
  not honor `ALFRED_PLUGIN_LAUNCHER`; routing through `_launcher_spawn.launcher_path()`
  fixes that as a side effect of the unification, not a separate patch.
- **Test-friendly by construction.** Setting `ALFRED_REPO_ROOT` in a test
  fixture (or patching `repo_root` directly) overrides every call site
  uniformly; call sites that read the resolver fresh per call
  (`config/settings.py`, `security/capability_gate/_comms_adapter_grants.py`)
  honor a patch applied after import time, not just at module load.

### Negative

- **Seven call sites to keep in sync going forward.** The unification removes
  *depth* drift, but a future eighth repo-root consumer that reaches for
  `Path(__file__).resolve().parents[N]` instead of importing `repo_root()`
  would reintroduce exactly the bug this ADR closes. Nothing in the type
  system enforces the convention; it is a code-review discipline, not a
  compiler-checked invariant.
- **The marker-gated fallback (`plugins/` presence) is a heuristic, not a
  guarantee.** A source checkout that happens to lack a `plugins/` directory
  (a partial clone, an unusual packaging step) falls through to the `/app`
  terminal fallback even outside a container, which would resolve to a
  nonexistent path on a bare host. This mirrors a pre-existing class of risk
  already accepted by `i18n/translator.py`'s own fallback chain, not a new one
  introduced here.

### Neutral

- `i18n/translator.py` keeps its own independent, richer candidate search and
  is not required to consume `repo_root()` — the two resolvers solve
  adjacent but distinct problems (a specific catalog directory with a
  wheel-embedded layer, versus a generic in-tree artifact root).

## Alternatives considered

### Option A — Fix each `parents[N]` site in place

Correct each module's hardcoded `parents[N]` depth individually for the
non-editable image layout. Rejected: this reproduces the exact drift that
caused the bug — four sites at three depths were already individually
"correct" for the source-checkout layout and silently disagreed the moment
the install layout changed. A per-site fix has no mechanism to keep future
sites in agreement; it only patches the symptom this trace found, not the
structural cause.

### Option B — Candidate-list search, no explicit env seam

Give `_repo_root.py` a translator.py-style ordered candidate list (source
tree, `/app`, …) with no `ALFRED_REPO_ROOT` variable, relying entirely on
`plugins/`-marker detection to pick the right candidate. Rejected as the
primary mechanism, though kept as the fallback layer: an explicit deploy seam
is self-documenting, consistent with the Dockerfile's existing
`ALFRED_PYTHON_PREFIX` / `ALFRED_QUARANTINE_CHILD_PYTHON` env-contract
pattern, and lets the container assert its root directly rather than relying
on marker-file heuristics to infer it correctly in every future image layout.

## References

- Design spec:
  `docs/superpowers/specs/2026-07-25-500-core-boots-shipped-image-design.md`
  — Part A (the mechanism this ADR records), Part G (names this ADR and
  ADR-0056).
- `src/alfred/_repo_root.py` — `repo_root()`, `_resolve()`,
  `_REPO_ROOT_ENV`, `_ROOT_MARKER`, `_CONTAINER_ROOT`.
- `src/alfred/config/settings.py` — `validate_comms_adapter_ids`.
- `src/alfred/cli/_launcher_spawn.py` — `repo_root()`, `launcher_path()`.
- `src/alfred/security/capability_gate/_comms_adapter_grants.py` — the
  first-party grant seed's `plugins_root` containment re-check.
- `src/alfred/cli/daemon/_daemon_probes.py` — `_launcher_self_test_impl`
  (now calls `launcher_path()`, closing the const-ignores-env bug).
- `src/alfred/security/quarantine_child_io.py:239` — `_repo_root()` wrapper.
- `src/alfred/plugins/comms_stdio_transport.py:70` — `_repo_root()` wrapper.
- `src/alfred/gateway/adapter_child_factory.py:261` — `_launcher_path()`.
- `src/alfred/i18n/translator.py` — the pre-existing `/app`-fallback
  precedent this ADR's terminal fallback mirrors.
- `docker/alfred-core.Dockerfile` — `ENV ALFRED_REPO_ROOT=/app`.
- [ADR-0030](0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md)
  — the wheel-embedded quarantine-child layout `security/quarantine_child_io.py`
  cites as the reason it needs no repo-relative import root.
- [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — the gateway as a
  second bwrap-launcher host.
- [ADR-0053](0053-three-layer-environment-precedence.md) — contrasted above:
  the `/etc`-vs-env precedence model that does not apply to this seam.
- Issue [#494](https://github.com/alfred-os/AlfredOS/issues/494) — the e2e
  boot lane (`tests/e2e/test_first_run_boot.py`) this unification flips green.
- Issue [#499](https://github.com/alfred-os/AlfredOS/issues/499) — gateway
  Settings decoupling; its comms review first flagged the drift this ADR
  closes.
