# 0007 — Python toolchain: ruff format + pyright + hypothesis + lefthook (pre-push)

- **Status**: Accepted
- **Date**: 2026-05-25
- **Slice**: 1 (`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`) and forward
- **Supersedes**: —
- **Superseded by**: —

## Context

The PRD and CLAUDE.md set the original Python toolchain expectations:

- PRD §8.1 (line 514 at time of writing): "Pre-commit hooks for lint + type-check + the fast subset of unit tests."
- PRD tech-stack: "Pydantic v2 for data models; mypy in strict mode for the core; ruff + black."
- CLAUDE.md memory rule about prior incidents drove the "no mocked DB for integration paths" testing posture.

Slice 1 implementation surfaced several decisions the original wording doesn't cover:

1. **Formatter consolidation**: `ruff format` (Astral, Rust-based) is ~10× faster than `black`, byte-compatible with black's output, and shares config + invocation with `ruff check`. Maintaining both is duplicated tooling.
2. **Type-checker coverage**: `mypy --strict` catches one set of bugs; `pyright` (Microsoft, used by VS Code Pylance) catches a different set, particularly around data-flow narrowing and recent typing features. Industry practice in Python-strong-typing shops increasingly runs both.
3. **Property-based testing**: `hypothesis` is the de-facto standard for invariant-checking in Python. Adding it as a dev dep + first-class testing posture (vs ad-hoc) hardens redactors, parsers, and serialisers.
4. **Pre-commit vs pre-push**: A pre-commit hook fires on every `git commit`, which is painful with the fixup-and-autosquash discipline AlfredOS adopts for review feedback (one would generate many short-lived commits). Pre-push is the right place to interpose the local quality bar — fires once per `git push`, doesn't impede iteration.
5. **Conventions doc authority**: The Slice-1 plan started accumulating Python style decisions inside task specs. Without a single source of truth, the same decision would re-appear inconsistently in Task 5 vs Task 11. The `docs/python-conventions.md` doc and the `alfred-python-developer` subagent are the centralisation.

These are five separate decisions; they are bundled in this ADR because they ship as one PR and serve the same goal (codifying a consistent, opinionated Python developer experience).

## Decision

The AlfredOS Python toolchain is:

| Concern | Tool | Replaces |
|---|---|---|
| Package manager | `uv` | (unchanged from PRD) |
| Build backend | `hatchling` | (unchanged) |
| Formatter | **`ruff format`** | `black` (dropped) |
| Linter | `ruff check` | (unchanged; rule set tightened — see `docs/python-conventions.md`) |
| Type checker (primary) | `mypy --strict` | (unchanged) |
| Type checker (secondary) | **`pyright`** | (new; runs alongside mypy) |
| Test framework | `pytest` + `pytest-asyncio` | (unchanged) |
| Property tests | **`hypothesis`** | (new; opt-in per test) |
| Integration test infra | `testcontainers[postgres]` | (unchanged) |
| Pre-push hook runner | **`lefthook`** | replaces the PRD's "pre-commit" wording |

**Canonical conventions** live in [`docs/python-conventions.md`](../python-conventions.md). **The `alfred-python-developer` subagent** ([`.rulesync/subagents/alfred-python-developer.md`](../../.rulesync/subagents/alfred-python-developer.md)) enforces them.

**Conflict resolution**: when a task spec disagrees with `docs/python-conventions.md`, the implementing agent surfaces the conflict to `alfred-architect` who reconciles by updating one, the other, or by writing a follow-up ADR. The conventions doc does NOT unilaterally override task specs.

**Hook stage**: lefthook installs as a **pre-push** hook, not pre-commit. This deviates from PRD §8.1's wording. The PRD update is human-gated; the deviation is recorded here and the PRD will be updated in a follow-up edit.

**Type-checker disagreement policy**: if mypy and pyright disagree on a finding, the implementer chooses one to satisfy (with a `# type: ignore[<code>]` or `# pyright: ignore[<code>]` on the other) and notes the conflict in a code comment. Persistent class-wide disagreement is an architecture finding for `alfred-architect`.

## Consequences

**Positive**

- One formatter, one linter, one source of style truth.
- Two type-checkers catches more bugs without imposing two competing styles (the disagreement-resolution policy keeps it manageable).
- Property-based tests for the load-bearing transformations (redactors, parsers, audit serialisers) — exactly the code where examples-based tests miss invariants.
- Pre-push aligns with the fixup-heavy review workflow without paying per-commit cost.
- `alfred-python-developer` + conventions doc + dispatch policy means a contributor (human or AI) writing Python in this repo doesn't have to derive style from existing code samples.

**Negative**

- Two type-checkers add a small dependency-resolution surface (pyright pulls `node` for its Python wrapper). Mitigated: only a dev dep; CI runs both in parallel; first-push latency on a cold cache is ~10s for pyright.
- Dropping `black` is a one-time `pyproject.toml` change (Slice 1 Task 1 fixup) and a remove-the-step change in `.github/workflows/ci.yml` (this PR).
- `lefthook` is a new tool contributors install once per clone. We accept this; the `make setup` target makes it a one-command install with a clean fallback if `lefthook` isn't on PATH.
- The `alfred-python-developer` subagent overlaps with the existing `alfred-*-engineer` subsystem owners. Mitigated by an explicit routing table in the subagent definition — it's a style/conventions enforcer, not a primary implementer for subsystem-owned code.

**Neutral**

- The Python community is consolidating on `ruff` (format + lint) and increasingly on `pyright` as a complement to `mypy`. This decision rides that wave rather than fighting it.

## Implementation status (at time of writing)

- `ruff format` + `ruff check` strict rule set — codified in `docs/python-conventions.md`. `pyproject.toml` config lands in Slice 1 Task 1 fixup.
- `pyright` + `hypothesis` — listed as dev deps in `docs/python-conventions.md`. Added to `pyproject.toml` in Slice 1 Task 1 fixup.
- `lefthook` — config shipped in this PR (`lefthook.yml`); contributor install via `make setup`.
- CI gates — `pr-validate-python.yml` shipped in this PR; promoted to required status checks via `gh api POST .../contexts` after merge.
- Conventions doc + subagent — shipped in this PR.

## Follow-ups

- **PRD §8.1 update** (human-gated): re-word "pre-commit hooks" to "pre-push hooks" and adjust §7.7's pybabel-as-pre-commit reference. Tracked as a separate PR per CLAUDE.md self-improvement rule #4.
- **pyproject.toml toolchain change** (drop black, add pyright + hypothesis, tighten ruff rules): lands as a fixup on Slice 1 Task 1's `pyproject.toml` commit after this PR merges.
- **i18n catalog freshness gate** (CLAUDE.md hard rule #4): a `pr-validate-i18n.yml` workflow that runs `pybabel compile --check` and detects extracted-msgid drift. Tracked in `docs/ci/required-checks.md` Pending row; authored as a follow-up issue.

## Slice-2+ implications

- If a future slice needs ruff or pyright config that diverges per-package (e.g. `tests/` allows `S101`, `src/alfred/security/` forbids `# type: ignore`), the per-file-ignore mechanism in `pyproject.toml` is the lever — no new tools required.
- If we adopt a `Result`-monad library for typed-error returns, a new ADR documents it; the conventions doc currently keeps that future open without naming a library.
- If `ty` / `pyrefly` (other Rust type-checkers) reach parity, revisiting pyright is a follow-up ADR — not a quiet swap.
