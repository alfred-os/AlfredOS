# ADR-0019 — `_DevGateLikeFixture` test-helper gate shim

- **Status**: Accepted (Slice 3, PR-S3-7).
- **Date**: 2026-06-02
- **Slice**: 3 — `docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md` §15.1 (flag-day `DevGate` removal).
- **Refines**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — decision §15.1 sets the boundary between production gates (`RealGate` only, no `DevGate` in `src/`) and the test fixture ergonomics this ADR pins.
- **Issue**: #134 (PR-S3-7, Stage 4 — ADR + DRY + code-quality polish).

## Context

PR-S3-7 deleted `DevGate` from `src/alfred/hooks/capability.py` (spec §15.1 flag-day). `RealGate` is now the single gate type the production tree builds — both the development and production bootstrap branches construct a `RealGate`, the development branch wraps it over an in-process stub backend with zero grants (every check denies fail-closed) and skips the heartbeat.

The flag-day uncovered three categories of test that needed a non-RealGate gate shape:

1. **Deny-path security tests** (`tests/adversarial/hooks/test_hk_2026_*`, `tests/adversarial/tier_laundering/`, `tests/unit/security/capability_gate/`). These tests assert that `RealGate` refuses an undeclared / mis-tiered subscriber. Replacing the gate with a test shim would hide a future RealGate-side regression behind the shim's logic. **These must use `RealGate` directly** (via `make_deny_all_gate` / `make_allow_system_gate`).
2. **Non-deny-path tests that need a permissive gate to register an operator-tier or user-plugin subscriber and then exercise other code paths** — the dispatcher's fault semantics (timeout, exception, re-entry), the registry's hookpoint-declaration metadata, plugin-load contract, performance benchmarks, and the hundreds of Slice-2.5 test bodies that register an `operator`-tier hook under an arbitrary module-named `plugin_id` before exercising the registry's other surfaces. Asserting these against `RealGate` would force every test to construct an `(plugin_id, hookpoint, "operator")` grant row up front — pure ceremony that obscures the test's actual property.
3. **Positive-control tests** where the gate must grant so a downstream assertion (e.g. the strict-hookpoint refusal path under #119) becomes the load-bearing arm of the test.

The Slice-2.5 `DevGate(allow_system=...)` carried exactly the "operator + user-plugin granted, system optionally granted, plugin_id and hookpoint ignored" semantics category 2 and 3 want. With `DevGate` deleted from `src/`, the tests needed a successor.

## Decision

Ship `_DevGateLikeFixture` (and its public constructor `make_permissive_fixture_gate`) **as a test helper only**, in `tests/helpers/gates.py`. The shim:

* Mimics the Slice-2.5 `DevGate` semantics: operator and user-plugin tiers granted unconditionally, system gated on the `allow_system` flag, `plugin_id` and `hookpoint` ignored.
* Is structurally a `alfred.hooks.capability.CapabilityGate` (the Protocol is `@runtime_checkable`) so dispatcher code that type-narrows via `isinstance` works with it. It is **not** a parallel production gate hierarchy — it is a test double.
* Is private (`_DevGateLikeFixture` — leading underscore) and lives in `tests/helpers/`. The AST guard `tests/unit/hooks/test_devgate_removed.py` plus the public-surface invariant test enforce that no `src/` code can import it.
* Carries a deliberately loud lockdown docstring (the class docstring + the `make_permissive_fixture_gate` constructor docstring + this ADR) so a reviewer who sees `make_permissive_fixture_gate` in a deny-path security test rejects the PR on sight.

**Deny-path security tests use `make_deny_all_gate` / `make_allow_system_gate`** — both constructed over `RealGate` so the assertion's load-bearing target is the production gate, not the shim. Stage 3 of #134 audited and migrated every adversarial / security deny-path test (`hk-2026-001` tier-escalation, `hk-2026-002` registration-tier-rejection, tier-laundering capability-gate-bypass) to the RealGate helpers; the migration is locked in by the `test_devgate_removed.py` AST guard.

The fixture-parity helpers (`fresh_registry`, `fresh_registry_allow_system`, `spy_registry_allow_system`, `strict_registry`) in `tests/unit/hooks/conftest.py` are composed of `make_permissive_fixture_gate(...)` so the Slice-2.5 test bodies that register an `operator`-tier subscriber under an arbitrary module-named `plugin_id` keep working without per-test rework.

## Consequences

### Positive

* **Zero risk that a RealGate deny-path regression is hidden by the shim** — the audit + AST guard pins the boundary. A future PR that points an adversarial test at `make_permissive_fixture_gate` flips a behavioural check, not just a lint nit.
* **Slice-2.5 test bodies keep working** — the fixture-parity gate preserves the operator + user-plugin posture the existing test corpus depends on.
* **Cheap to understand** — the shim is ~40 lines of pure-function `check` / `check_plugin_load` / `check_content_clearance` with closed-vocabulary tier-string handling. The class docstring lists every legitimate use site.

### Negative / accepted

* **DRY violation, by design.** `tests/helpers/gates.py`'s `_make_in_memory_backend` + `_make_no_op_audit_sink` shape mirrors `src/alfred/bootstrap/gate_factory.py`'s `_make_in_memory_backend` + `_make_no_op_audit_sink` shape. They are intentionally not extracted to a shared module: shipping a `test_fixtures` module under `src/` is a layering violation (production code MUST NOT depend on test scaffolding), and shipping the production stubs under `tests/` would invert the dependency. The two ~15-line stub builders coexist; each module's docstring names the other. Future drift surfaces as a test failure: the gate-factory selection test asserts both branches build a `RealGate`, and the helper exercises the same Protocol shape, so a backend Protocol change must update both sides or one site fails to type-check.
* **A second `_make_no_op_audit_sink` shape exists.** Same rationale; both honour err-003 (`RealGate` requires an audit sink), neither emits rows — the development bootstrap and the test fixture both rely on the no-grant policy denying every check on the hot path so the sink is never invoked in practice.
* **The fixture-parity gate is permissive** — operator and user-plugin always grant. A test author who picks `make_permissive_fixture_gate` for a deny-path assertion gets a green test that doesn't exercise the production gate. The naming pin (`permissive_fixture_gate`) + class docstring lockdown + ADR cross-link + AST guard are the four lines of defence; if all four fail, a reviewer would still see the symbol's name in the diff.

### Layering invariant pinned

* `src/alfred/` MUST NOT import from `tests/helpers/`. The static check is the AST guard in `tests/unit/security/test_capability_gate_ast_no_os_import.py` (extended to also reject `from tests.helpers` and `import tests.helpers`).
* `tests/helpers/` MUST NOT import from `tests/unit/` or `tests/integration/`. The helpers package is a leaf in the test dependency tree — tests depend on it, it depends only on `src/alfred/` and the standard library.
* The two ~15-line stubs (`_make_in_memory_backend` + `_make_no_op_audit_sink`) are duplicated **once** across the boundary and not factored out. Each docstring carries a pointer to the other.

## Alternatives considered

1. **Factor the stub backend + audit sink to a shared `src/alfred/security/capability_gate/test_fixtures.py` module.** Rejected: shipping a `test_fixtures` module under `src/` is bad architecture (production code depending on test scaffolding), and the module would either need to be filtered out of the public-surface invariant test (introducing a new exception) or appear in the runtime tree as a backdoor that test-only consumers exploit.
2. **Subclass `RealGate` to make a permissive `_PermissiveGate` test type.** Rejected: `RealGate`'s `check` / `check_plugin_load` / `check_content_clearance` consult `GatePolicy`, which is keyed on `(plugin_id, hookpoint, tier)`. A subclass that overrides every check method to ignore the policy is structurally a different gate, not a `RealGate` — the subclass relationship would be a lie.
3. **Construct a `RealGate` with a wildcard-grant for every `(plugin_id, hookpoint, operator)` combination the test corpus uses.** Rejected: the test corpus's `plugin_id` set is open (module-named at registration time). The grant table would either need to be regenerated per test or carry a wildcard that doesn't match `GatePolicy`'s grant-key shape.
4. **Use a `unittest.mock.MagicMock` per test.** Rejected: loses the structural Protocol guarantee — a `MagicMock` is structurally a `CapabilityGate` only by accident, and a test that calls `gate.check_content_clearance` after the Protocol grows a new method would silently return a `MagicMock` truthy instead of failing loudly.

## Cross-references

* [`tests/helpers/gates.py`](../../tests/helpers/gates.py) — the shim source. Module docstring + `_DevGateLikeFixture` class docstring + `make_permissive_fixture_gate` constructor docstring all carry the lockdown rules.
* [`src/alfred/bootstrap/gate_factory.py`](../../src/alfred/bootstrap/gate_factory.py) — the production-side `_make_in_memory_backend` + `_make_no_op_audit_sink` stub builders the helper deliberately duplicates.
* [`tests/unit/hooks/test_devgate_removed.py`](../../tests/unit/hooks/test_devgate_removed.py) — AST guard that pins `DevGate`'s removal from `src/`.
* [`tests/unit/hooks/conftest.py`](../../tests/unit/hooks/conftest.py) — the registry-fixture family that consumes the shim.
* Stage 3 of #134 — the migration commits (`a9265ea`, `6701efa`, `0af1781`) that audited every adversarial / security deny-path test and pointed it at `make_deny_all_gate`.
