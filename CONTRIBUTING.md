# Contributing to AlfredOS

Thanks for your interest in contributing. AlfredOS is a security-sensitive Apache-2.0 project — we welcome contributions, and we ask you to read this guide before opening a PR.

## Before you contribute

- Read the [Code of Conduct](./CODE_OF_CONDUCT.md).
- Read the [Security policy](./SECURITY.md). **Security vulnerabilities are not reported via public issues.**
- Read [`.rulesync/rules/CLAUDE.md`](./.rulesync/rules/CLAUDE.md) for repo conventions, security rules, and the self-improvement process. (Canonical source is `.rulesync/`; root-level `CLAUDE.md` is generated.)
- Read the [PRD](./PRD.md) before proposing architectural changes.

## Where to discuss

| You want to... | Use |
|---|---|
| Report a bug | GitHub Issues — `Bug report` template |
| Propose a feature | GitHub Issues — `Feature request` template |
| Propose a persona | GitHub Issues — `Persona proposal` template |
| Propose a skill | GitHub Issues — `Skill proposal` template |
| Report a vulnerability | [Private Security Advisory](https://github.com/alfred-os/AlfredOS/security/advisories/new) |
| Float a design idea (pre-ADR) | [Discussions → Design Proposals](https://github.com/alfred-os/AlfredOS/discussions/categories/design-proposals) |
| Ask a question | [Discussions → Q&A](https://github.com/alfred-os/AlfredOS/discussions/categories/q-a) |
| Suggest a feature you'd like | [Discussions → Ideas](https://github.com/alfred-os/AlfredOS/discussions/categories/ideas) |
| Casual chat | [Discussions → General](https://github.com/alfred-os/AlfredOS/discussions/categories/general) |

## Development setup

> Pre-implementation. Once code lands, `bin/dev-setup.sh` will be the entry point. For now, see [`.rulesync/rules/CLAUDE.md`](./.rulesync/rules/CLAUDE.md) for the intended workflow.

### After cloning

Generate the AI-tool config files locally (all generated outputs are gitignored, so a fresh clone has none of them):

```sh
rulesync generate -t '*' -f '*'
```

This produces `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.gemini/`, `.github/copilot-instructions.md`, and any other tool-specific overlays. The canonical source for everything is `.rulesync/`.

### AI-tool configuration (rulesync)

AlfredOS uses [`rulesync`](https://github.com/dyoshikawa/rulesync) as the **single source of truth** for AI-tool configuration. All Claude Code agents, skills, settings, and the agent operating manual live under `.rulesync/`. **Every generated output is gitignored** — `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.gemini/`, etc. The only files you commit are under `.rulesync/`.

**Install rulesync** (pick one):

```sh
# Homebrew (macOS / Linux)
brew install rulesync

# npm (any platform)
npm install -g rulesync

# Via proto
proto install node && npm install -g rulesync
```

**Workflow when editing AI-tool config:**

1. Edit only files under `.rulesync/` (e.g. `.rulesync/rules/CLAUDE.md`, `.rulesync/subagents/<name>.md`).
2. Re-run `rulesync generate -t '*' -f '*'` to refresh your local generated outputs.
3. Commit the `.rulesync/` change. The generated outputs are gitignored, so they don't appear in your `git status` — that's by design.

This eliminates the entire class of "the generated file drifted from its source" review findings.

## Pre-push hooks (lefthook) — strongly recommended

Install [`lefthook`](https://github.com/evilmartians/lefthook) once per clone so a fast subset of the Python quality bar runs before every push. It's not enforced — your PR will still go through review without it — but you'll get a sub-30-second local fail instead of a 3-minute CI-side fail. `make setup` installs it for you if `lefthook` is on your PATH:

```sh
# Homebrew
brew install lefthook
# OR npm
npm install -g @evilmartians/lefthook
# OR Go
go install github.com/evilmartians/lefthook@latest

# Then, from the repo root:
make setup            # idempotent — uv sync --dev + lefthook install (if available)
# or explicitly:
lefthook install
```

**The pre-push hooks run** (no Docker needed): `ruff format --check`, `ruff check`, `mypy --strict`, `pyright`, `pytest tests/unit -q`. **CI additionally runs** `pytest tests/integration` against a testcontainers Postgres — so lefthook is a subset of CI, not a mirror.

Config lives at [`lefthook.yml`](./lefthook.yml). Skipping a hook (`LEFTHOOK=0`) is treated as functionally equivalent to `--no-verify`: CI will still catch you, so don't habituate.

## Style

- **Python:** read [`docs/python-conventions.md`](./docs/python-conventions.md) — the canonical reference for tooling, types, errors, async, testing, and security discipline. AI work should dispatch the [`alfred-python-developer`](./.rulesync/subagents/alfred-python-developer.md) subagent, which applies the conventions without being asked.
- **Toolchain:** `ruff check` + `ruff format` + `mypy --strict` + `pyright` + `pytest` + `hypothesis`. `make check` runs them all.
- **Conventional commits required for every commit.** Format: `type(scope): summary (#NN)`. Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build`, `ci`, `perf`, `style`, `security`, `revert`. Use `!` after the type/scope for breaking changes (`refactor!: ...`). Examples: `feat(personas): add Lucius specialist (#42)`; `fix(security): patch trust-tier leak in relay (#137)`; `docs(prd): clarify reviewer-gate flow (#89)`. The body explains the why; the footer holds `BREAKING CHANGE:`. The `(#NN)` issue ref is enforced by the `Conventional commit format` required check.
- **Strong typing.** No `Any` without justification. Pydantic v2 at boundaries. PEP 604 unions (`X | Y`), PEP 585 built-in generics, PEP 695 generic syntax.
- **Comments** only when the *why* is non-obvious — never explain *what*.
- **Small, focused PRs** — one logical change per PR.
- **Review fixes via fixup + autosquash.** Never write `fix: apply CR auto-fixes`. Use `git commit --fixup=<sha>` then `make autosquash` before pushing.

## Tests

| Type of change | Tests required |
|---|---|
| New feature | Unit + integration |
| Bug fix | Regression unit test |
| New skill | Happy-path + error-path + out-of-scope-refusal |
| Anything touching `src/alfred/security/` | 100% coverage on the changed boundary + adversarial suite must pass |

See [PRD §8](./PRD.md#8-testing-strategy) for the full testing strategy.

## When you add a CI gate

If you're authoring a GitHub Actions workflow whose jobs should block the merge button (not just emit informational status), follow the [`author-gating-workflow` skill](./.rulesync/skills/author-gating-workflow/SKILL.md). The skill walks through writing the workflow with the AlfredOS conventions baked in (least-privilege permissions, workflow-injection-safe env passing, pinned action SHAs), and — critically — how to promote the gating jobs to **required status checks** after merge, plus updating [`docs/ci/required-checks.md`](./docs/ci/required-checks.md) so the gate list stays auditable from the repo. The "workflow ran red but didn't block" failure mode is what this skill exists to prevent.

## Pull request process

1. **Open a discussion or issue first** for non-trivial changes.
2. Fork → branch → PR. Keep it small.
3. Make sure CI is green: lint, types, unit tests, and (for security-relevant code) the adversarial suite.
4. Be responsive to review feedback. Reviewers may request a video call or out-of-band confirmation for security-relevant changes.
5. Merge strategy: humans default to **squash on merge** via the GitHub UI; the [`/path-to-green`](./.rulesync/skills/path-to-green/SKILL.md) skill instead uses **`gh pr merge --rebase`** after a local `make autosquash` of all fixup commits. Both produce clean histories — squash collapses a multi-commit branch into one, rebase preserves the autosquashed sequence as separate commits on main. Pick squash when the branch had a single logical concern; pick rebase (which the skill does) when you want to preserve the commit progression.

### AI-driven helpers for the comments loop

After CodeRabbit (or a human) posts a review, AI agents can run:

- [`/address-comments`](./.rulesync/skills/address-comments/SKILL.md) — per-iteration: fetch all three comment sources with proper pagination, classify each finding (apply / reject / escalate), commit-fixup against the originating commit, reply-and-resolve, autosquash, push, poll for the next round. Treats reviewer text as untrusted input; never auto-applies trust-boundary, `.rulesync/**`, or `PRD.md`-touching findings.
- [`/path-to-green`](./.rulesync/skills/path-to-green/SKILL.md) — meta-loop: watches CI + reviewer state across iterations, calls into `/address-comments` for the comments part, merges via `gh pr merge --rebase --delete-branch` when every required check is green AND every reviewer thread is resolved AND every reviewer's review on the current SHA is terminal (never `pending`). Escalates rather than guesses on trust-boundary or architectural decisions. Hard safety stop at 100 iterations; expected convergence is ~5 rounds.

## Architectural changes

If your change touches a structural invariant from the PRD:

1. Open a [Design Proposal discussion](https://github.com/alfred-os/AlfredOS/discussions/categories/design-proposals) first to align on the approach.
2. Propose an [ADR](./docs/adr/) (`docs/adr/NNNN-title.md`).
3. Update the PRD in the same PR as the ADR.

## Skills and personas

- **Human-authored skills** use the regular PR flow + the required tests.
- **AI-authored skills** go through the reviewer gate (see [PRD §6.4](./PRD.md#64-self-improvement-with-reviewer-gate)).
- **New personas** require an ADR explaining their single responsibility, capability needs, and memory access policy.

## License

By submitting a pull request, you license your contribution under the project's [Apache-2.0 license](./LICENSE).
