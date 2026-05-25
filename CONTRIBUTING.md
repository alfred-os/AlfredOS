# Contributing to AlfredOS

Thanks for your interest in contributing. AlfredOS is a security-sensitive Apache-2.0 project — we welcome contributions, and we ask you to read this guide before opening a PR.

## Before you contribute

- Read the [Code of Conduct](./CODE_OF_CONDUCT.md).
- Read the [Security policy](./SECURITY.md). **Security vulnerabilities are not reported via public issues.**
- Read [`CLAUDE.md`](./CLAUDE.md) for repo conventions, security rules, and the self-improvement process.
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

**What goes where in `.rulesync/`:**

| You want to add… | Edit here | Becomes (per AI tool) |
|---|---|---|
| Operating-manual / global rules an AI agent must follow when working on AlfredOS | `.rulesync/rules/<name>.md` | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules/*.mdc`, `.github/copilot-instructions.md`, `.windsurf/rules/*.md` |
| A specialized **subagent** that can be dispatched by name (e.g. `alfred-security-engineer`) | `.rulesync/subagents/<name>.md` | `.claude/agents/<name>.md`, `.codex/agents/<name>.md` |
| An **invokable skill** for the AI tool (e.g. `review-plan`, `author-gating-workflow`) | `.rulesync/skills/<name>/SKILL.md` | `.claude/skills/<name>/SKILL.md`, equivalent paths for other tools |
| A **slash command** | `.rulesync/commands/<name>.md` | `.claude/commands/<name>.md` |
| A **Claude Code hook** (PreToolUse, PostToolUse, SessionStart, etc.) | `.rulesync/hooks.json` | `.claude/settings.json` (hooks section) |
| **Permission allowlist / denylist** for Claude Code tools | `.rulesync/permissions.json` | `.claude/settings.json` (permissions section) |
| **MCP server** config (Gmail, custom MCP plugins, etc.) | `.rulesync/mcp.json` | `.mcp.json` |

> **Important distinction**: `.rulesync/skills/` and `skills/` are **different things**.
> - `.rulesync/skills/` = AI-tool helper skills for contributors building AlfredOS (the `review-plan`, `author-gating-workflow` kind — invoked by your editor's AI). Lives in `.rulesync/`, generated to `.claude/skills/`.
> - `skills/` (top-level, lands in Slice 1) = AlfredOS's **own runtime skills** — procedural plugins loaded by the AlfredOS orchestrator at runtime. Lives in the repo root, NOT under `.rulesync/`. See PRD §6.3 and `.rulesync/skills/alfred-runtime-skill-author/SKILL.md`.

**Workflow when editing `.rulesync/`:**

1. Edit only files under `.rulesync/`.
2. Re-run `rulesync generate -t '*' -f '*'` to refresh your local generated outputs.
3. Commit the `.rulesync/` change. The generated outputs are gitignored, so they don't appear in your `git status` — that's by design.
4. **If you added or renamed a subagent / skill / command**, mention "restart your AI tool to pick this up" in the PR description. Most AI tools (Claude Code included) cache their available-skills / subagents registry at session start; a new file on disk is invisible to a running session until restart.

This eliminates the entire class of "the generated file drifted from its source" review findings, and the "I created a new skill but the dispatch silently uses the old definition" silent-failure mode.

## Style

- **Python:** `ruff` + `black` + `mypy --strict` for the core.
- **Conventional commits required for every commit.** Format: `type(scope): summary`. Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build`, `ci`, `perf`, `style`, `security`, `revert`. Use `!` after the type/scope for breaking changes (`refactor!: ...`). Examples: `feat(personas): add Lucius specialist`; `fix(security): patch trust-tier leak in relay`; `docs(prd): clarify reviewer-gate flow`. The body explains the why; the footer holds `Closes #NN`, `BREAKING CHANGE:`, etc.
- **Strict typing.** No `Any` without justification. Pydantic v2 at boundaries.
- **Comments** only when the *why* is non-obvious — never explain *what*.
- **Small, focused PRs** — one logical change per PR.

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
5. Squash on merge.

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
