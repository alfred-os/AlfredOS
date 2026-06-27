# Slice 2 — Implementation Plan Index

> **Slice 2 = Discord adapter + multi-user identity + secret broker file backend.**
> Spec: [`docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`](../specs/2026-05-26-slice-2-discord-multiuser-design.md) (PR #93, 1042 lines).
> Plans below are sequenced: each PR's plan lists what the next PR may assume.

## What ships

When all 6 PRs below have merged:

- TUI keeps working unchanged from the operator's perspective.
- New `alfred user *` CLI for operator-pre-mapped identity binding (canonical slug `user_id`).
- New `alfred-discord` service in compose for the Discord DM round-trip.
- Per-user `BudgetGuard`, per-user `WorkingMemoryPool`, per-user `language`.
- File-backed `SecretBroker` at `~/.config/alfred/secrets.toml` (fail-closed, plaintext for Slice 2).
- `CommsAdapter` Protocol seam — TUI and Discord both behind one interface.
- `OutboundDlp` on every Discord outbound (`broker.redact` + generic-API-key regex + canary stub).
- Adversarial-corpus harness ready for Slice 3 to populate.

## PR sequence

Each PR's plan is **self-contained** and **TDD-bite-sized**. Default executor: `superpowers:subagent-driven-development`.

| # | Plan | Owner | Depends on |
| --- | --- | --- | --- |
| 1 | [PR A — Identity layer + ContextVar + 5 ADRs](./2026-05-26-slice-2-pr-A-identity.md) | `alfred-python-developer` + `alfred-docs-author` (ADR-0009 + 0010 bodies) | main as of slice-1 |
| 2 | [PR B — Per-user BudgetGuard + WorkingMemoryPool + orchestrator contract](./2026-05-26-slice-2-pr-B-budget-memory-orchestrator.md) | `alfred-memory-engineer` + `alfred-provider-engineer` + `alfred-core-engineer` + `alfred-persona-engineer` | PR A |
| 3 | [PR C — SecretBroker file backend + perf-006 caching](./2026-05-26-slice-2-pr-C-secret-broker.md) | `alfred-security-engineer` | PR A (PR B is independent) |
| 4 | [PR D1 — CommsAdapter Protocol + OutboundDlp + RateLimiter + splitter](./2026-05-26-slice-2-pr-D1-comms-protocol-dlp.md) | `alfred-comms-engineer` + `alfred-security-engineer` | PRs A, B, C |
| 5 | [PR D2 — DiscordAdapter + compose + setup + README](./2026-05-26-slice-2-pr-D2-discord-adapter.md) | `alfred-comms-engineer` + `alfred-security-engineer` + `alfred-devops-engineer` | PRs A, B, C, D1 |
| 6 | [PR E — Smoke + adversarial corpus scaffolding + subsystem docs + ADRs](./2026-05-26-slice-2-pr-E-smoke-corpus-docs.md) | `alfred-test-engineer` + `alfred-docs-author` + `alfred-security-engineer` | PRs A, B, C, D1, D2 |

### Parallelisation

PR C is independent of PR B. They CAN ship in parallel if two engineers are working the slice simultaneously. Everything else is strictly sequential.

```
A → B ─┐
       ├→ D1 → D2 → E
A → C ─┘
```

## Spec coverage matrix

Where each spec section lands:

| Spec section | Lands in |
| --- | --- |
| §0.1 ContextVar refactor | PR A (commit 1) |
| §0.2 ADR-0013 placeholder body | PR A (commit 2) |
| §2 `CommsAdapter` Protocol + TuiAdapter wrap | PR D1 |
| §2 Three identity modules (models, resolver, version_counter) | PR A |
| §2 `LISTEN/NOTIFY` cross-process + listener resilience (err-001) | PR A |
| §2 `BudgetGuard` contract change | PR B |
| §2 `SecretBroker` file backend (full subsection) | PR C |
| §2 `User.authorization` enum + `read_only` security invariant | PR A (column) + PR D1 (RateLimiter gate) |
| §2 Database migration `0004` | PR A |
| §2 Compose changes | PR D2 |
| §3 Discord adapter detail (entire §3 minus carved-out helpers) | PR D2 |
| §3 Orchestrator contract change | PR B |
| §3 `WorkingMemoryPool` ownership and lifecycle | PR B |
| §3 Outbound DLP + structlog bridge (sec-003) | PR D1 |
| §3 Per-user rate limiting | PR D1 |
| §3 i18n keys (`cli.user.*`) | PR A |
| §3 i18n keys (`discord.*`) | PR D2 |
| §3 i18n keys (`secrets.*`) | PR C |
| §3 Audit-DoS mitigation (unknown-DM flood) | PR D2 |
| §3 Markdown-aware splitter | PR D1 |
| §4 Slug pipeline + edge cases | PR A |
| §4 `User` + `PlatformIdentity` ORMs | PR A |
| §4 `alfred user *` CLI commands | PR A |
| §4 First-deploy operator-onboarding flow (setup script) | PR A (skeleton) + PR D2 (Discord-bind extension) |
| §4 Slice-1-to-Slice-2 migration semantic | PR A |
| §4 `IdentityResolver` cache | PR A |
| §4 Operator's TUI session resolves to themselves | PR A |
| §5 Unit tests | distributed per-PR |
| §5 Integration tests | distributed per-PR |
| §5 Smoke tests | PR E |
| §5 Adversarial corpus scaffolding | PR E |
| §5 ADR-0009 + ADR-0010 bodies | PR A |
| §5 ADR-0011 + ADR-0012 + ADR-0013 placeholders | PR A |
| §5 ADR-0011 + ADR-0012 + ADR-0013 bodies | PR E |
| §5 `docs/subsystems/identity.md` + `comms.md` + `glossary.md` | PR E |
| §6 PR sequence rationale | this index |
| §7 Open questions | (carry into Slice 3 plan) |
| §7 Punch list (perf-006 redactor caching) | PR C |

## Cross-PR contracts (the things one PR ships that the next assumes)

These are the load-bearing public APIs that the per-PR plans pin. A drift across plans here is a slice-blocking inconsistency.

### From PR A

- `src/alfred/identity/models.py`
  - `class User` — ORM with columns: `id`, `slug`, `display_name`, `authorization`, `daily_budget_usd`, `language`, `rate_limit_per_min` (nullable), `rate_limit_per_day` (nullable), `created_at`, `deleted_at`.
  - `class PlatformIdentity` — ORM with `id`, `user_id` (FK CASCADE), `platform`, `platform_id`, `created_at`, `deleted_at`.
  - `class Authorization(StrEnum)` — `read_only`, `standard`, `trusted`, `operator`.
- `src/alfred/identity/resolver.py`
  - `class IdentityResolver` with `resolve(platform: str, platform_id: str) -> User | None`, `add(name: str, …) -> User`, `bind(slug: str, platform: str, platform_id: str) -> PlatformIdentity`, `remove(slug: str) -> None`, `get_operator() -> User`.
  - Raises `OperatorAlreadyExistsError` on second-operator add without `--replace-operator`.
- `src/alfred/identity/version_counter.py`
  - `class IdentityVersionCounter` with `bump()` and `current() -> int`.
- `src/alfred/i18n/translator.py`
  - `_active_lang: ContextVar[str]` — `set_language()` becomes `_active_lang.set()`; `t()` reads via `.get()`.
- Migration `0004` adds `episodes.persona_id`, `episodes.language`, `audit_log.persona_id`, `audit_log.language` (all nullable).
- ADRs 0009 + 0010 with full bodies; ADRs 0011 + 0012 + 0013 with placeholder bodies.

### From PR B

- `src/alfred/budget/guard.py`
  - `BudgetGuard.check_and_charge(user_id: str, cost_usd: float)` (was no-user in slice-1).
  - `BudgetGuard.would_exceed(user_id, cost_usd) -> bool`, `estimate_for(user_id, …) -> float`.
  - `BudgetGuard.evict(user_id: str) -> None`.
  - `UnknownBudgetUserError(BudgetError)` typed.
  - `BudgetExceededError(BudgetError)` with `spent_usd` + `cap_usd` attributes.
- `src/alfred/memory/working.py`
  - `class WorkingMemoryPool` with `async acquire(key: tuple[str, str]) -> WorkingMemory`, `async release(key, wm)`, `evict(key)`.
- `src/alfred/orchestrator/core.py`
  - `Orchestrator.handle_user_message(*, user: User, content: TaggedContent[T2], working_memory: WorkingMemory) -> str`.
- `render_persona_prompt(persona=ALFRED_PERSONA, operator_name=…, requesting_user_name=…, language=…)` with the cacheable prefix + `<user_context>` tail per spec §3 line 439-454.
- `episodic.record(…, persona=…, language=…)` and `audit.append(…, persona_id=…, language=…)` per-row threading.

### From PR C

- `src/alfred/security/secrets.py`
  - `SecretBroker(secrets_file: Path | None = None, require_file: bool = False, …)`.
  - `SecretBroker.get(name: str) -> str | None` honouring env-vs-file precedence (env wins for slice-1 keys; file wins for `_PREFER_FILE` keys).
  - `SecretBroker.redact(text: str) -> str` with bounded regex cache (perf-006).
  - Error hierarchy: `SecretBrokerConfigError` (base) → `SecretBrokerPermissionsError`, `SecretBrokerFileMissingError`, `SecretBrokerNotAFileError`.
- `SUPPORTED_SECRETS` grows `discord_bot_token`; `_PREFER_FILE = {"discord_bot_token"}` (extensible).
- `tests/unit/_shared/import_violation.py` — shared remediation-message helper (reused by PR D1's `test_no_direct_adapter_imports.py`).

### From PR D1

- `src/alfred/comms/adapter.py`
  - `class CommsAdapter(Protocol)` with `name: str`, `async start/run/stop`, `def health() -> AdapterHealth`.
  - `@dataclass class AdapterHealth(gateway_connected, last_on_ready_at, recent_reconnect_count)`.
- `src/alfred/comms/discord_types.py`
  - `class _DiscordClientLike(Protocol)` — structural Protocol for the client factory (covers `event/start/close/is_ready`).
- `src/alfred/comms/tui_adapter.py`
  - `class TuiAdapter(CommsAdapter)` wrapping `AlfredTuiApp`.
- `src/alfred/comms/markdown_split.py`
  - `_split_for_discord(text, max_len=2000)` — markdown-state-aware; Slice-4 Telegram reuses with `max_len=4096`.
- `src/alfred/identity/rate_limit.py`
  - `class RateLimiter(Protocol)` async with `allow(user: User) -> bool`, `reset(user_id) -> None`, `health() -> RateLimiterHealth`.
  - `class InProcessTokenBucketRateLimiter(RateLimiter)` — `read_only` check FIRST in `allow()` (security invariant per spec §2 line 223).
- `src/alfred/security/dlp.py`
  - `class OutboundDlp` with `scan(text: str) -> str` — two-stage (broker.redact + generic-API-key regex) + canary stub.
- `src/alfred/cli/main.py`
  - structlog `_redact_value` routes through `OutboundDlp.scan` (sec-003).
- `tests/unit/comms/test_no_direct_adapter_imports.py` (reuses PR C's shared helper).

### From PR D2

- `src/alfred/comms/discord.py`
  - `class DiscordAdapter(CommsAdapter)` with `client_factory` mock seam, `_send` chokepoint, allowlist trust-tagging.
- `src/alfred/cli/discord_cmd.py`
  - `alfred discord` (run the adapter loop) + `alfred discord verify` (30s smoke with exit codes 0/1/2/3/4/130).
- `pyproject.toml` — `discord.py>=2.4,<3` + `cachetools` runtime deps.
- `docker-compose.yaml` — new `alfred-discord` service.
- `bin/alfred-setup.sh` — portable operator-onboarding bootstrap step.
- `README.md` — Developer Mode walkthrough.

### From PR E

- `tests/smoke/test_discord_gateway_smoke.py` — `ALFRED_SMOKE_DISCORD_TOKEN`-gated.
- `docs/runbooks/slice-2-discord-smoke.md` — operator-facing walkthrough.
- `tests/adversarial/` scaffolding — runnable harness; CI job stub with `continue-on-error: true` (flips in Slice 3).
- `docs/subsystems/identity.md` + `docs/subsystems/comms.md` + `docs/glossary.md` — required headings `Authorization role` (slug `authorization-role`) and `Canonical user_id` (slug `canonical-user-id`) per spec §6 PR-E row.
- ADRs 0011 + 0012 + 0013 full bodies (placeholders shipped in PR A).

## How to execute

For each PR plan in order:

1. **Open a feature branch** from main: `git switch -c feat/slice-2-pr-<X>-<name>`.
2. **Invoke `superpowers:subagent-driven-development`** with the PR's plan file as the argument. It dispatches a fresh implementer subagent per task, with two-stage review (spec compliance + code quality) between tasks.
3. **Drive CI to green** with `/path-to-green` (autonomous CI + reviewer-cloud + CR loop, with merge authority per slice-1 pattern).
4. **Address inline review comments** with `/address-comments` per iteration.
5. **Merge to main.** Next PR depends on this one — don't start it until main has the new contracts.

Alternative for a single sit-down: `superpowers:executing-plans` runs the plan inline in batch with checkpoints. Slower iteration but no inter-task subagent dispatch overhead.

## References

- [Slice 2 spec](../specs/2026-05-26-slice-2-discord-multiuser-design.md)
- [Slice 1 plan](./2026-05-24-slice-1-hello-alfred.md)
- [PRD](../../../PRD.md)
- [CLAUDE.md](../../../CLAUDE.md)
- [`alfred-docs-author` agent](../../../.rulesync/subagents/alfred-docs-author.md)
- [`alfred-adversarial-corpus` skill](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
