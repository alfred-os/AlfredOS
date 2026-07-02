# Config-consumer DIP — narrow read-only Protocols over the `Settings` god-object

- **Issue**: [#351](https://github.com/alfred-os/AlfredOS/issues/351)
- **Date**: 2026-07-02
- **Status**: Design — converged after two review rounds (architect/reviewer/test/security/docs + CodeRabbit)
- **Raised by**: @MrReasonable during the G7-3 review ([#350](https://github.com/alfred-os/AlfredOS/pull/350))

## Problem

The codebase designs **behaviour** dependencies to interfaces — `dlp._BrokerLike`,
`OutboundDlpProtocol`, `identity/_session_protocols.py` (`BrokerLike` / `MachineIdLike` /
`AuditLike`), the G7-3 `_SecretBrokerLike`. **Config**, by contrast, flows as the concrete
`Settings` god-object (`src/alfred/config/settings.py:66`, a Pydantic `BaseSettings`): a
function reading one field still depends on the whole type, and its unit tests must build a
real `Settings` (or `model_construct(...)`) rather than a trivial stub.

**Primary benefit = DIP decoupling + trivial test doubles**, *not* a type-ignore purge. A prior
draft over-stated the scope; the real picture, verified against the tree:

- **9 genuine leaf consumers across 7 files in 5 subsystems** carry a typed `settings:
  Settings` param or a `from_settings` classmethod (full inventory below). Not ~30 files.
- Of the **405** `# type: ignore[arg-type]` in tests, **~1** is a `Settings` config-double.
  The type-ignore cleanup is therefore a *minor side-effect* (a handful of ignores), not the
  motivation. The motivation is interface segregation: a consumer should depend on exactly the
  fields it reads.

## Genuine consumer inventory (verified)

The **composition-root layer** — `cli/_bootstrap.py`, `cli/daemon/_commands.py` (8 sites),
`cli/gateway/_commands.py:151` (constructs `Settings()` directly), `bootstrap/`, the `config`
loader, and the `Settings` definition — constructs/forwards the whole `Settings` and is
**exempt as a layer** (even a pure field-reader there, e.g. `_bootstrap.sync_db_url`, stays
put — narrowing one boot helper in isolation adds churn without the DIP benefit). The
narrowable leaf consumers are:

| Subsystem | Consumer(s) | Fields read | Note |
| --- | --- | --- | --- |
| memory | `db.py`: `make_engine` / `make_session_factory` / `build_session_scope` | `database_url` | Plain functions — the cleanest mechanism-proof exemplar. |
| egress | `client.py`: `EgressClient.from_settings` | `egress_proxy_url` | The #350 motivating case; `egress_proxy_url` has a `mode="before"` normalizer (blank→`None`) — a **validator-coupled** consumer. |
| providers | `deepseek.py` / `anthropic_native.py`: `from_settings` | provider base-url / key refs | |
| plugins | `web_fetch/assembly.py`: `build_web_fetch_egress_extractor` | `egress_relay_url` | **validator-coupled** — `egress_relay_url` has a `mode="before"` normalizer (`_normalize_egress_relay_url`, `settings.py:360`); fail-closed if unset. |
| security | `secrets.py`: `SecretBroker.from_settings`; `capability_gate/_comms_adapter_grants.py`: `comms_adapter_load_grants` | broker + adapter config | `comms_adapter_load_grants` is **validator-coupled** (trusts `_validate_comms_enabled_adapters` rejected path-traversal ids). |

There are **no** genuine `identity` or `gateway` consumers (`gateway/_commands.py:151`
constructs `Settings()` itself — composition root; `identity` references `Settings` only in
comments). The exact per-batch
site list is re-confirmed at implementation by grepping typed `settings: Settings` params +
`from_settings` defs and letting `warn_unused_ignores` flag the removable ignores.

## Decision summary

| Axis | Decision |
| --- | --- |
| **Sequencing** | **Batched by subsystem** — a small series of medium, independently reviewable PRs. |
| **Protocol shape** | **Narrow, read-only Protocols** per consumer / field-cluster, grouped in a per-subsystem `_config_protocols.py`. |
| **Read-only intent** | `@property` getters — a **new member shape** for this codebase (all existing Protocols model *behaviour via methods*; none uses `@property`/attributes). Chosen over a plain `field: T` annotation because a getter-only property is read-only + covariant, is satisfied by `Settings`' attribute *and* a plain stub (PEP 544), and states DIP intent. |
| **Boundary** | **Leaf consumers narrow — including a `from_settings` that reads ≤k fields.** Only code that *constructs or forwards the whole* `Settings` (`cli/_bootstrap.py`, `bootstrap/`, the loader, the `Settings` definition) stays on concrete `Settings`. |
| **Validator coupling** | A consumer whose correctness relies on a `Settings` validator/normalizer **retains ≥1 real-`Settings` validated test**, and its Protocol docstrings the producer-side invariant it assumes. |
| **type-ignore cleanup** | Per-PR, enforced by the existing `warn_unused_ignores = true` (mypy). Removes only the handful of config-double ignores that go unused. pyright is **not** a second enforcer (`reportUnnecessaryTypeIgnoreComment` is unset → off). |
| **Lint gate** | *Optional* capstone: enable ruff **`PGH003` specifically** (not the `PGH` family — PGH005's mock-method check is unaudited). Purely a **forward-guard** against future bare `# type: ignore` (the tree has ≈0 today), so low value — include only if desired. |

## The pattern

Each subsystem gets a `_config_protocols.py` of narrow read-only Protocols. Real `Settings`
satisfies them structurally → **`Settings` is unchanged**, **zero runtime behaviour change**.

```python
# src/alfred/egress/_config_protocols.py
from typing import Protocol

class EgressProxyConfig(Protocol):
    # Producer invariant assumed: egress_proxy_url is normalized (blank -> None) by
    # Settings._normalize_egress_proxy_url. A stub bypasses that normalizer, so the
    # from_settings normalizer seam keeps a real-Settings test (see Validator coupling).
    @property
    def egress_proxy_url(self) -> str | None: ...
```

```python
# src/alfred/egress/client.py  (REAL shape today)
# before:  def from_settings(cls, settings: Settings) -> EgressClient:
#              if settings.egress_proxy_url is None: ...
#              return cls(proxy_url=settings.egress_proxy_url)
# after:
    @classmethod
    def from_settings(cls, config: EgressProxyConfig) -> EgressClient:
        ...  # reads only config.egress_proxy_url
```

```python
# test — before:  EgressClient.from_settings(settings)          # real Settings / model_construct
# after (for logic that does NOT depend on the normalizer):
class _StubEgressCfg:
    egress_proxy_url = "http://gw:8080"
EgressClient.from_settings(_StubEgressCfg())     # trivial stub
# AND retain one real-Settings test that exercises the blank -> None normalizer seam.
```

**Conventions** (land in `docs/python-conventions.md` with the first batch):

- Naming + module-grouping mirror `identity/_session_protocols.py` (grouped) vs inline
  `dlp._BrokerLike`; the `@property`/attribute *member shape* is new — state that so later
  batches don't re-litigate.
- The read-only benefit is **compile-time only** — mypy blocks assignment through a getter-only
  property; `Settings` (`BaseSettings`) remains runtime-mutable. Do not imply runtime immutability.
- Reuse one Protocol across consumers reading the same field-cluster; don't mint near-duplicates.

## Batch plan

Each row is one medium, independently reviewable, zero-behaviour-change PR that adds
`<subsystem>/_config_protocols.py`, narrows that subsystem's leaf consumers, and removes any
config-double ignore `warn_unused_ignores` now flags. Full `/review-pr` + CodeRabbit + rebase-merge.

| PR | Subsystem | Notes |
| --- | --- | --- |
| **1** | **memory** (`db.py`) | Cleanest plain-function consumer (`database_url`, no validator subtlety). **Lands the convention doc + the mechanism-proof artifact.** |
| 2 | **egress** (`client.py`) | The #350 motivating case; demonstrates the **validator-retention rule** (normalizer seam). |
| 3 | **providers** (`deepseek.py`, `anthropic_native.py`) | Both `from_settings`. |
| 4 | **plugins** (`web_fetch/assembly.py`) | `build_web_fetch_egress_extractor` reads `egress_relay_url` (validator-coupled). Its Protocol may share the egress cluster (`egress/_config_protocols.py`) since `egress_relay_url` is an egress-plane field — placement decided at planning; could ride the egress batch instead. |
| 5 | **security** (`secrets.py`, `capability_gate/_comms_adapter_grants.py`) | High-care, late. Touches `src/alfred/security/` → **full adversarial suite** + **assert 100% line+branch coverage retained** (CLAUDE.md hard rule), not merely "suite green". `_comms_adapter_grants` is validator-coupled → retains a real-`Settings` traversal-rejection test. |
| **6** | **capstone** (optional) | Enable ruff `PGH003` as a forward-guard. Include only if the team wants it; ≈0 bare ignores exist today. |

`memory` first (proves the `@property` mechanism on the simplest consumer + lands the
convention); `security` last (after the pattern is settled). No `identity` batch — it has no
genuine consumers. Ordering is otherwise adjustable.

## Testing & verifiable success criteria

Per batch, all of:

1. `mypy --strict` + `pyright` green; **`warn_unused_ignores` clean** (removed ignores stay removed).
2. Subsystem unit tests pass with the simplified stubs — **plus** a preserved done-criterion:
   *no migrated field is `Settings`-validated/normalized/`@computed_field` unless a real-`Settings`
   test retains that seam.* A plain stub with a hardcoded literal must not silently drop
   validator coverage.
3. **PR1 mechanism-proof artifact** — a committed, CI-`mypy --strict`-checked identity return
   (needs no env construction), e.g. `def _proof(s: Settings) -> MemoryDbConfig: return s`,
   which type-checks iff `Settings` structurally satisfies the `@property` Protocol. Home it in a
   test module (or annotate it) so ruff's unused-arg / dead-code lints don't flag the proof.
4. **Shared-fixture ignores are sequenced last (if any exist).** *If* a `conftest`/fixture typed
   `-> Settings` is shared across subsystems, its ignore only goes unused when the *last* consumer
   migrates — so remove it in the final consumer's batch, not per-subsystem (a merge-conflict
   vector). With only ~1 config-double ignore in the tree today this may be a no-op; confirm during
   planning rather than hunting for a phantom fixture.
5. **PR5 (security)**: full adversarial suite + a coverage diff showing 100% line+branch retained on
   the touched trust-boundary code.

No new runtime tests are required (pure typing/DIP refactor); the win is that a Protocol-typed
param cannot touch un-declared attributes, so consumer-body narrowing is machine-verified.

## Non-goals

- Changing `Settings` itself (stays a `BaseSettings`).
- Touching the composition root / CLI / `bootstrap/` / `config` loader that construct or forward
  the whole `Settings`.
- A mass `# type: ignore[arg-type]` purge (only ~1 is a config-double) or a blanket ban.
- Adding, renaming, or restructuring config keys/values.
- `migrations/env.py` (Alembic boundary).

## Risks & mitigations

| Risk | Mitigation |
| --- | --- |
| A plain stub bypasses a `Settings` validator/normalizer, masking a bug | Validator-coupled consumers retain a real-`Settings` test; Protocol docstrings the invariant. Verified cases: egress `egress_proxy_url` normalizer, `web_fetch/assembly` `egress_relay_url` normalizer, `_comms_adapter_grants` traversal validator. |
| Protocol proliferation | Group in `_config_protocols.py`; reuse across same-field-cluster consumers. |
| `@property`-satisfaction uncertainty | Proven by the PR1 committed mechanism-proof artifact before other batches rely on it (standard PEP 544). |
| Shared-fixture ignore can't be removed mid-sequence | Sequence such ignores to the last consuming batch (criterion 4). |
| Small realized value (few consumers, ~1 ignore) | Accept: the benefit is DIP cleanliness + trivial future doubles, scoped to a small, bounded set; the capstone is optional. |

## References

- [#351](https://github.com/alfred-os/AlfredOS/issues/351) — this issue.
- [#350](https://github.com/alfred-os/AlfredOS/pull/350) — G7-3 PR where the egress-only version
  was deferred to avoid a lone inconsistency.
- `docs/python-conventions.md` — "prefer small Protocols", interface segregation, Protocols over
  ABCs; the convention lands here (PR1).
- Precedents (method Protocols; the `@property`/attribute shape is new):
  `src/alfred/identity/_session_protocols.py`, `src/alfred/security/dlp.py`.
- `pyproject.toml` — `warn_unused_ignores = true` (mypy); ruff `select` lacks `PGH`; pyright
  `reportUnnecessaryTypeIgnoreComment` unset (off).
