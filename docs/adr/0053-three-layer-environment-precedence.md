# ADR-0053 — Three-layer `Settings.environment` precedence

- **Status**: Accepted
- **Date**: 2026-07-23
- **Slice**: #469 Blocker 1 (first-run experience — environment resolution)
- **Relates to**: issue [#469](https://github.com/alfred-os/AlfredOS/issues/469)
  (first-run experience epic this closes Blocker 1 of), issue #174 (the
  original PR-S4-1 daemon-boot dispatch design that introduced the
  env-var-vs-`/etc` two-source model this ADR supersedes), issue
  [#351](https://github.com/alfred-os/AlfredOS/issues/351) (config-as-interface
  DIP — `docs/python-conventions.md:176` — this ADR's multi-process
  composition-root reasoning is consistent with, not a departure from),
  [ADR-0044](0044-dependency-constraint-policy.md) (dependency
  version-constraint policy — the `pydantic-settings<2.15` cap here is the
  policy's documented-incompatibility exception, not a speculative cap),
  design spec
  `docs/superpowers/specs/2026-07-22-469-blocker1-environment-resolution-design.md`
- **Supersedes**: —

## Context

`alfred daemon start` could refuse to boot with "Set `ALFRED_ENVIRONMENT`
... in your `.env`" even when the operator had done exactly that. The root
cause: the pre-`Settings()` boot gate (`cli/daemon/_commands.py`) called a
standalone loader that read only `os.environ["ALFRED_ENVIRONMENT"]` and
`/etc/alfred/environment` — never `.env` — and refused *before* `Settings`
was constructed. `Settings` itself (pydantic-settings, `env_file=".env"`)
**does** read `.env`, so the pre-`Settings` gate was a less-capable,
`.env`-blind duplicate of the resolution `Settings` performed a moment
later. This was masked in `docker compose` (compose forwards `.env` into
`os.environ`, so the loader never needed to read the file itself) and
broken on the documented bare-host / bare-`.env`-only path.

`environment` is security-load-bearing: `environment == "production"` gates
the sec-002 unsandboxed-in-production refusal and the gateway
launch-target-override escape hatch (PRD §7.1 — Security & Prompt Injection
Defense; the loader module previously cited "§7.3", which is Self-Healing &
Auto-Recovery and has no bearing on this decision). The dangerous failure
mode is a **silent production → development downgrade**, so precedence
among the candidate sources has to be chosen deliberately, not left to
whatever pydantic-settings does natively (`os.environ > .env` — it never
reads `/etc` at all).

## Decision

### 1. Canonical precedence

`Settings.environment` resolves via exactly one three-layer precedence
chain, highest trust to lowest:

```text
os.environ["ALFRED_ENVIRONMENT"]  >  /etc/alfred/environment  >  .env
```

- `os.environ["ALFRED_ENVIRONMENT"]` — set by whoever controls process
  launch (compose, systemd, an operator's shell).
- `/etc/alfred/environment` — a root-owned system file; an app-user process
  cannot forge it.
- `.env` — a working-directory file the app user can write. Lowest
  precedence, gap-fill only: it can supply a value when nothing above it
  is set, but it can never override a higher source, participate in the
  env-var-vs-`/etc` conflict audit, or (see §3) unlock a permissive
  escape hatch.

pydantic-settings' NATIVE precedence considers only the two sources it has
built-in support for: `os.environ > .env`. It has no notion of
`/etc/alfred/environment` at all, so it never consults `/etc` under any
composition — this is not a documented gap in some `/etc` support pydantic
ships, it is simply outside what the library knows how to source a field
from. The comparison that matters is what happens if `/etc` were bolted on
the most straightforward way — as a naive additional lowest-priority
source layered under pydantic's own two: that HYPOTHETICAL composition
would yield `os.environ > .env > /etc`, and an app-writable `.env` could
then silently outrank a root-owned `/etc`. Only `os.environ > /etc > .env`
keeps the root-owned file above the app-writable one, so `Settings`
**delegates** the field to a single external resolver (see §4) that
implements that exact order directly, rather than composing pydantic's
native two sources with `/etc` bolted on beneath them.

The one and only implementation of this chain is
`resolve_environment()` in `src/alfred/config/_environment_loader.py`. It
returns an `EnvironmentLoadResult(value, source, conflict,
conflicting_file_value, unrecognised_value)` describing the resolved value,
which source produced it (`EnvironmentSource.ENV_VAR` / `ETC_FILE` /
`DOTENV`, or the no-value cases below), and — for the env-var-vs-`/etc`
pair specifically — whether the two disagreed.

### 2. Single-resolver invariant, scoped to `ALFRED_ENVIRONMENT`

Every process that needs `environment` before it can construct a full
`Settings` object — the daemon boot gate
(`cli/daemon/_commands.py:_load_settings_or_die`), the pre-launcher helper
(`plugins/manifest_reader.py:_cmd_read_environment`), and the gateway's
escape-hatch gate
(`gateway/adapter_child_factory.py:_resolve_launch_target`) — calls
`resolve_environment()` directly. `Settings` itself calls it internally (a
fourth caller, for in-process code that can afford to build a real
`Settings`). All four call the SAME resolver (M-4: not "byte-identical
precedence logic" — the launcher opts out of the `.env` layer entirely via
`consult_dotenv=False`, a genuinely two-layer chain per §3, so the logic
each caller EXERCISES differs by design); there is no second implementation
anywhere in the tree to drift out of sync.

**This invariant is scoped to the `ALFRED_ENVIRONMENT` variable only.** A
fifth, pre-existing, security-load-bearing site —
`src/alfred/plugins/content_store_base.py:149` (`InMemoryContentStore.__init__`,
sec-S3-003) — reads a **different** variable, `ALFRED_ENV`, via a bare
`os.environ.get("ALFRED_ENV", "").strip()`, to decide whether the unsafe
in-memory content-store stub may be constructed. `src/alfred/bootstrap/gate_factory.py`
(`is_production()`, sec-007) reads the same `ALFRED_ENV` variable for a
related but distinct decision — which capability gate implementation to
build. Both are intentionally left alone here:

- `ALFRED_ENV` and `ALFRED_ENVIRONMENT` are different variables with
  different semantics (a free-form dev/production selector vs. the closed
  `{development, production, test}` triple), different defaults (`ALFRED_ENV`
  treats unset/empty as development; `ALFRED_ENVIRONMENT` treats unset as
  "no value, refuse"), and different consumers.
- Neither reader participates in `Settings` construction, so folding them
  into `resolve_environment()` is a separate, larger change (reconciling
  two independently-evolved security gates), not a doc-drift or precedence
  fix.

A known, **latent** gap follows from the divergence: an operator who sets
`ALFRED_ENVIRONMENT=production` only in `/etc/alfred/environment` (with
`ALFRED_ENV` left unset) gets a correctly-`production` `Settings.environment`
but does **not** trip the sec-S3-003 in-memory-store refusal, because
`ALFRED_ENV` — read independently — still defaults to "development" when
unset. Reconciling the two variables is issue
[#489](https://github.com/alfred-os/AlfredOS/issues/489) (out of scope here
— see Scope below); this ADR's job is to document the divergence honestly
rather than claim a single-resolver guarantee it does not provide.

### 3. `.env` lowest, closed by construction, plus two independent trust floors

Making `.env` the lowest layer closes the sec-002 downgrade risk in
`Settings.environment` itself by construction — a CWD `.env` can supply a
value only when both higher sources are silent. But `environment` also
gates a **permissive** escape hatch (the gateway's dev/test-only
launch-target override), where the danger inverts: a fail-closed refusal
must not flip to fail-open because a CWD `.env` claims `development`. Two
call sites each close this the way their interface allows:

- **In-process trust floor** — `gateway/adapter_child_factory._resolve_launch_target`
  calls `resolve_environment()` normally (so it stays uniformly `.env`-aware,
  matching every other call site) but only honors the override when
  `result.source in {EnvironmentSource.ENV_VAR, EnvironmentSource.ETC_FILE}`.
  A `.env`-sourced `development`/`test` value never satisfies the gate,
  because it can express the source it read the value from.
- **Launcher trusted-sources-only** — `plugins/manifest_reader.py`'s
  `--read-environment` subcommand cannot use the same trick: its interface
  is a bare stdout string consumed by `bin/alfred-plugin-launcher.sh`
  (bash), which has no way to carry a `source` alongside the value. Instead
  it calls `resolve_environment(consult_dotenv=False)` — the `.env` layer
  is excluded from consultation entirely, so a CWD `.env` cannot influence
  the value the launcher receives at all, trusted-source-only by
  construction rather than by post-hoc filtering.

`resolve_environment()`'s `consult_dotenv` parameter exists specifically to
support this second pattern: a caller whose downstream interface cannot
express provenance opts out of the lowest-trust layer up front.

**err-01 — fail-closed on an unreadable `/etc`, scoped to "no higher-trust
source resolved" (final-review I-3).** The resolver evaluates the env var to
completion FIRST, entirely ahead of any `/etc` read: a present-and-valid env
var returns immediately (the conflict flag, if any, is still computed against
whatever `/etc` value the resolver can read — see below), and a
present-but-invalid env var short-circuits `UNRECOGNISED` before `/etc` is
even consulted. **Only when the env var did not itself resolve a value** does
the resolver read `/etc`, and only then can a present-but-unreadable
`/etc/alfred/environment` (`PermissionError` / `IsADirectoryError` / generic
`OSError`) return `EnvironmentSource.UNREADABLE` — never falling through to
`.env`. Gating a *resolved, valid* env-var value behind `/etc`'s readability
was rejected: whoever controls process launch already controls the env var,
so refusing boot on an unreadable `/etc` in that case buys no additional
security and had newly broken a previously-working root-owned-0600-`/etc` +
non-root-daemon + env-var-set deployment (the concrete regression the final
whole-branch review caught). The original intent of err-01 is preserved
exactly where it matters: a mode-misconfigured `/etc` must never silently
downgrade to the lower-trust `.env` layer when `/etc` is the highest source
actually consulted. Only a genuinely *absent* `/etc` file
(`FileNotFoundError`) is treated as unset, at any position in this chain.
`.env` read failures (`PermissionError`/`OSError`/`IsADirectoryError`/
`FileNotFoundError`/`UnicodeDecodeError`) are, by contrast, treated as
*absent* rather than fatal: `.env` is the lowest layer, so a
mode-misconfigured `.env` degrading to "no value from this source" cannot
itself cause a downgrade, and CLAUDE.md hard rule 7 (no silent crashes) is
served by never raising a raw, un-audited traceback out of a boot-time file
read.

### 4. Retiring the ContextVar / dual-validator

`Settings.environment` previously required a `before`+`after` validator
pair coordinated through a module-level `_ENVIRONMENT_LOAD_RESULT`
`ContextVar` to hand the resolved `EnvironmentLoadResult` from the `before`
step to the `after` step. Both are deleted. A single `model_validator(mode="wrap")`
now does the whole job: `settings_customise_sources` strips `environment`
out of every non-init pydantic source first (via a `_Without` source
wrapper keyed off the field's alias set, not a hardcoded string, so a
future `validation_alias` on `environment` cannot silently reopen the
bypass), which makes `"environment" in data`  mean "explicitly constructed"
unambiguously. The wrap validator then has exactly one decision to make —
call `resolve_environment()` and inject the value when `environment` is
absent — and one thing to do afterwards — store the `EnvironmentLoadResult`
on a `PrivateAttr`, verified against the field the handler actually
validated — both in one place, with no side channel and no `ContextVar`
needed to cross the validator boundary.

### 5. `EnvironmentSource.DOTENV` / `UNREADABLE`, and short-circuit-on-typo

`EnvironmentSource` grows two members beyond the pre-existing
`ENV_VAR`/`ETC_FILE`/`NONE`/`UNRECOGNISED`: `DOTENV` (the value came from
`.env`) and `UNREADABLE` (err-01 above). `.env` is normalized identically
to the other two sources (`.strip()`, blank/whitespace-only treated as
unset) so precedence never depends on which layer happened to contain
trailing whitespace.

**Short-circuit on a typo'd higher source.** Precedence resolves top-down:
the highest source that is *set* decides, full stop. If that source's
value is not one of `{development, production, test}`, the resolver
returns `UNRECOGNISED` (echoing the raw string so the operator sees their
own typo) and does **not** fall through to a valid lower source. Without
this, a root typo in `/etc/alfred/environment` (e.g. `prod`) could let a
`.env=development` silently win — a downgrade-via-typo. A source that is
merely *unset* (absent, or blank after normalization) is skipped, not a
short-circuit; only a *present-but-invalid* value short-circuits. `.env`
can never itself trigger the env-var-vs-`/etc` `conflict` flag — that flag
is computed solely between the top two layers — but it can be the value
that resolves to `UNRECOGNISED` when it is the highest set source.

### 6. `pydantic-settings<2.15` cap exception

`pyproject.toml` pins `pydantic-settings>=2.14.2,<2.15`. Per
[ADR-0044](0044-dependency-constraint-policy.md), AlfredOS's default policy
is *no speculative upper caps* — but ADR-0044 also carves out an explicit
exception for a **documented, concrete incompatibility**, and this is one:
the `_Without` source wrapper (§4) forwards pydantic-settings' per-source
state protocol to the wrapped inner source — an internal, undocumented
2.14.x mechanism, not covered by pydantic-settings' own semver guarantees.
Faithful forwarding is two parts, not one: the two `_set_current_state` /
`_set_settings_sources_data` passthrough methods, **and** an identity pydantic-
settings can key on. `pydantic_settings/main.py`'s `_settings_build_values`
keys its per-source `states` dict by `source.__name__ if hasattr(source,
"__name__") else type(source).__name__`; without a `__name__` of its own,
every `_Without` instance fell back to the literal class name `"_Without"`,
so all three instances `settings_customise_sources` constructs collided
under one shared key instead of the three distinct keys the wrapped
`EnvSettingsSource` / `DotEnvSettingsSource` / `SecretsSettingsSource` would
occupy unwrapped (final-review I-2). `_Without.__init__` now sets
`self.__name__ = getattr(inner, "__name__", type(inner).__name__)`, adopting
the wrapped source's own identity — the per-source state protocol is now
forwarded faithfully, verified by a regression test asserting the three
wrapped sources resolve to three distinct state-dict keys. The cap is a
tripwire, not a permanent ceiling: widening it is fine, but only after
re-verifying that internal against the target minor, since a silent
behavior change there would reopen the exact downgrade this ADR closes.

## What this ADR homes

This is the first ADR to record the environment-precedence decision. A
prior draft of the design spec that led to this ADR labeled it as "homing
arch-002" — that label was a mis-attribution and has been corrected: in the
plan-review round for this work, `arch-002` was the finding about the
daemon boot gate's return shape (keep the non-optional
`tuple[Settings, EnvironmentLoadResult]` rather than smuggling the result
back onto the `Settings` instance via a second `PrivateAttr` write path),
not the precedence chain itself. This ADR owns the precedence decision
(§1–§6 above); no earlier ADR does.

## Consequences

**Positive**

- One resolution algorithm, exercised identically by every process that
  needs `environment` before (or without) constructing a `Settings` object.
  A future change to precedence, source normalization, or fail-closed
  behavior touches one function.
- The documented remedy ("set `ALFRED_ENVIRONMENT` in your `.env`") now
  actually works on the bare-host path **for daemon boot**, closing the #469
  Blocker-1 boot loop. This does NOT extend to plugin spawns on that same
  bare-host path — see the Residual below.
- The escape-hatch danger (a permissive override unlocked by a low-trust
  source) is closed at each consumer by construction, not by a shared
  runtime check that could be bypassed by a new call site forgetting to
  apply it.

**Negative / residuals**

- **The `.env` remedy reaches daemon boot but NOT plugin spawns, on the
  bare-host path (final-review I-4).** `alfred.plugins._comms_child_env
  ._scrubbed_base()` forwards `os.environ["ALFRED_ENVIRONMENT"]` verbatim
  into every sandboxed plugin's child env — it does NOT forward the daemon's
  own *resolved* value. So on a bare-host, `.env`-only install (no
  `ALFRED_ENVIRONMENT` env var, no `/etc/alfred/environment`, but a valid
  `ALFRED_ENVIRONMENT=` line in `.env`), the daemon boots cleanly (`Settings`
  resolves `environment` from `.env` via `resolve_environment()`, per §1), but
  EVERY sandboxed plugin spawn (`bin/alfred-plugin-launcher.sh`, via
  `manifest_reader --read-environment`) still refuses with
  `daemon.boot.environment_not_set` — the `.env`-blind pre-launcher probe
  reads only the env var and `/etc` (deliberately — §3's launcher
  trusted-sources-only trust floor), and the child process the daemon spawns
  never had `ALFRED_ENVIRONMENT` in ITS `os.environ` to forward, because
  nothing promoted the `.env` value into the daemon process's own environment
  block. This is the #469 bug shape recurring one layer down, scoped to
  **bare-host installs only** — `docker compose` is unaffected, because
  compose's own `.env` handling promotes `.env` into `os.environ` for every
  container (including the daemon), so `ALFRED_ENVIRONMENT` is already a real
  env var by the time `_scrubbed_base()` reads it. Not fixed here: the
  mechanism fix (teaching `_scrubbed_base()` to forward the daemon's resolved
  value rather than re-reading `os.environ`) is out of scope for this ADR —
  filed as issue [#486](https://github.com/alfred-os/AlfredOS/issues/486).
- **The launcher and the daemon report DIFFERENT refusal reasons for the
  IDENTICAL condition — a present-but-unreadable `/etc` (final-review
  M-5).** The daemon boot gate distinguishes this precisely:
  `_load_settings_or_die` raises `_EnvironmentSourceUnreadableError` on
  `EnvironmentSource.UNREADABLE`, and `_start_async` audits a distinct
  `environment_source_unreadable` failure reason with
  `environment_source="unreadable"`. The launcher's pre-launch helper does
  not: `manifest_reader._cmd_read_environment` branches only on
  `result.value is not None` and `result.source is
  EnvironmentSource.UNRECOGNISED`, so an `UNREADABLE` result falls through to
  the SAME bare `daemon.boot.environment_not_set` key a fully-absent
  environment would produce — the launcher's stdout/stderr interface cannot
  distinguish "no source claims a value" from "the highest source exists but
  this process cannot read it." `EnvironmentSource.UNREADABLE` is new in this
  branch (§5); the asymmetry is a direct consequence of adding it only to the
  in-process `EnvironmentLoadResult` without teaching the launcher's bare-key
  vocabulary the same distinction. Filed as issue
  [#487](https://github.com/alfred-os/AlfredOS/issues/487).
- **Two `.env` parsers for one file.** The resolver reads `environment`
  out of `.env` via `python-dotenv`'s `dotenv_values(..., interpolate=False)`;
  pydantic-settings' own dotenv source (still active for every *other*
  field) parses the same file with its own settings (`interpolate=True`
  by default). Excluding `environment` from pydantic's sources means only
  the resolver ever touches that one field, so the two parsers never
  disagree about it; `interpolate=False` is chosen specifically to
  eliminate a `$VAR`-expansion injection vector in the environment value,
  not to mirror pydantic's behavior.
- **Malformed `.env` line dropped silently (err-03).** `dotenv_values`
  silently drops a line with an unbalanced quote or a missing `=`. If the
  `ALFRED_ENVIRONMENT` line itself is malformed, it reads as absent — the
  operator sees an `environment_not_set` refusal rather than a
  parse-error-specific one. Documented and pinned by test; a friendlier
  message is issue [#490](https://github.com/alfred-os/AlfredOS/issues/490),
  not a hand-rolled `.env` parser.
- **`_Without`'s internal-API dependency** on pydantic-settings 2.14.x's
  per-source state protocol (§6) is mitigated by forwarding it faithfully,
  capping the version, and a regression test — but it remains a dependency
  on undocumented internals until pydantic-settings exposes a public
  per-field source-exclusion API, if it ever does.
- **CWD-relative `.env`.** The resolver's default `.env` path matches
  pydantic-settings' own `env_file` resolution (relative to the process's
  current working directory). This is consistent with existing behavior,
  not a new risk, but it means the daemon's CWD at boot still determines
  which `.env` is consulted — a `.env` is lowest-precedence and excluded
  from the escape hatch regardless of which file it is.
- **The `ALFRED_ENV`/`ALFRED_ENVIRONMENT` divergence** (§2) remains
  unresolved by this ADR; the latent sec-S3-003 gap it describes is a
  known, pre-existing condition, not a defect introduced here — filed as
  issue [#489](https://github.com/alfred-os/AlfredOS/issues/489).
- **`settings.py` is not whole-file coverage-gated.** The CI per-module
  coverage gate added alongside this ADR (`_environment_loader.py` at 100%)
  deliberately does NOT extend to `settings.py` as a whole file — it carries
  one pre-existing uncovered line (the `comms_enabled_adapters` traversal-
  containment branch, dated 2026-06-11, unrelated to environment
  resolution) that would red the gate on day one. Filed as issue
  [#488](https://github.com/alfred-os/AlfredOS/issues/488) rather than
  closed here, since closing it means either adding a test for that
  unrelated branch or accepting a narrower gate deliberately — a decision
  for its own PR.

## Alternatives considered

- **Let `Settings` resolve `environment` independently via pydantic-settings'
  native source ordering.** Rejected: native ordering is `os.environ > .env`
  and never consults `/etc` at all, which would make an app-writable `.env`
  outrank a root-owned `/etc/alfred/environment` — the exact downgrade this
  ADR exists to prevent.
- **Keep the pre-`Settings` boot gate as its own permanent second
  implementation**, just teach it to read `.env` too. Rejected: two
  implementations of the same precedence chain is exactly the drift risk
  that produced the original bug (the boot gate silently fell behind
  `Settings`'s own resolution once); a single shared resolver removes the
  possibility structurally rather than by discipline.
- **Reconcile `ALFRED_ENV` and `ALFRED_ENVIRONMENT` into one variable now.**
  Rejected for this ADR: the two variables are semantically distinct
  (closed triple vs. free-form dev/production selector) and used by
  independently-evolved security gates; reconciling them is a larger,
  separate change with its own review — issue
  [#489](https://github.com/alfred-os/AlfredOS/issues/489) — rather than
  folded into a precedence fix.

## Scope

**In scope (this ADR):** the three-layer precedence and its single
resolver (`resolve_environment()`), the `Settings` delegation via
`settings_customise_sources` + a `mode="wrap"` validator, the two
independent escape-hatch trust floors, the `err-01`/`err-03` fail-closed
and silently-dropped-line behaviors, `EnvironmentSource.DOTENV`/`UNREADABLE`,
the short-circuit-on-typo semantics, and the `pydantic-settings<2.15` cap.

**Out of scope (follow-ups, each filed as its own issue):** reconciling
`ALFRED_ENV` and `ALFRED_ENVIRONMENT`, including the latent sec-S3-003 gap
in §2 — [#489](https://github.com/alfred-os/AlfredOS/issues/489); a
friendlier operator-facing message for a malformed `.env` line (err-03) —
[#490](https://github.com/alfred-os/AlfredOS/issues/490); a broader
settings-factory DIP consolidation — the pre-existing
[#351](https://github.com/alfred-os/AlfredOS/issues/351), not a new ADR-0054
issue; teaching `alfred.plugins._comms_child_env._scrubbed_base()` to
forward the daemon's own *resolved* `environment` value into a sandboxed
plugin's child env instead of re-reading `os.environ["ALFRED_ENVIRONMENT"]`
(the bare-host-only plugin-spawn gap in Consequences → Negative/residuals,
final-review I-4) — [#486](https://github.com/alfred-os/AlfredOS/issues/486);
teaching the launcher's bare-key vocabulary to distinguish an unreadable
`/etc` from a fully-absent one (final-review M-5) —
[#487](https://github.com/alfred-os/AlfredOS/issues/487); extending the
per-module coverage gate to `settings.py` as a whole file —
[#488](https://github.com/alfred-os/AlfredOS/issues/488).

## References

- Epic [#469](https://github.com/alfred-os/AlfredOS/issues/469); design spec
  `docs/superpowers/specs/2026-07-22-469-blocker1-environment-resolution-design.md`
  (10-lane `/review-plan` fleet + coordinator cross-check: 0 Critical, 13
  High, 27 Medium, 12 Low; 8/8 solo findings confirmed).
- `src/alfred/config/_environment_loader.py` — `resolve_environment()`,
  `EnvironmentLoadResult`, `EnvironmentSource`.
- `src/alfred/config/settings.py` — `_Without`, `settings_customise_sources`,
  `_resolve_environment` (the `mode="wrap"` validator).
- `src/alfred/cli/daemon/_commands.py` — `_load_settings_or_die` (the daemon
  boot gate; the sole caller that also emits the
  `daemon.boot.environment_source_conflict` audit row).
- `src/alfred/plugins/manifest_reader.py` — `_cmd_read_environment` (the
  launcher's trusted-sources-only caller, `consult_dotenv=False`).
- `src/alfred/gateway/adapter_child_factory.py` — `_resolve_launch_target`
  (the in-process trust-floor caller).
- `src/alfred/plugins/_comms_child_env.py:52,86` — `_scrubbed_base()`, the
  bare-host-only plugin-spawn residual named in Consequences →
  Negative/residuals (final-review I-4): forwards `os.environ`, not the
  daemon's resolved `environment`.
- `src/alfred/plugins/content_store_base.py:149` (sec-S3-003) and
  `src/alfred/bootstrap/gate_factory.py` (sec-007) — the two `ALFRED_ENV`
  readers named in §2 as a known, intentional divergence.
- [ADR-0044](0044-dependency-constraint-policy.md) — dependency
  version-constraint policy (the `<2.15` cap exception).
- Issue [#351](https://github.com/alfred-os/AlfredOS/issues/351) —
  config-as-interface DIP (`docs/python-conventions.md:176`); this ADR's
  multi-process composition-root reasoning is consistent with it, and it is
  the pre-existing issue the settings-factory/DIP consolidation follow-up
  (Scope → Out of scope) points at rather than a new ADR-0054 number.
- Follow-up issues filed against this ADR's residuals (final-review M-5):
  [#486](https://github.com/alfred-os/AlfredOS/issues/486) (bare-host
  plugin-spawn gap, I-4), [#487](https://github.com/alfred-os/AlfredOS/issues/487)
  (launcher/daemon refusal-reason asymmetry for an unreadable `/etc`),
  [#488](https://github.com/alfred-os/AlfredOS/issues/488) (`settings.py`
  not whole-file coverage-gated), [#489](https://github.com/alfred-os/AlfredOS/issues/489)
  (`ALFRED_ENV`/`ALFRED_ENVIRONMENT` reconciliation, §2), and
  [#490](https://github.com/alfred-os/AlfredOS/issues/490) (malformed
  `.env` line silently dropped, err-03).
- `tests/unit/cli/daemon/test_environment_loader.py`,
  `tests/unit/cli/daemon/test_probe_environment_not_set.py`,
  `tests/unit/config/test_settings_environment_mandatory.py`,
  `tests/adversarial/comms/test_launch_target_override_refusal.py`,
  `tests/unit/gateway/test_launch_target_override.py`.
