# ADR-0054 — Gateway-hosted comms adapters default to empty (opt-in Discord)

- **Status**: Accepted
- **Date**: 2026-07-24
- **Slice**: #469 Blocker 2 (first-run experience — opt-in Discord)
  (`docs/superpowers/specs/2026-07-23-469-blocker2-gateway-optin-discord-design.md`,
  `docs/superpowers/plans/2026-07-24-469-blocker2-opt-in-discord.md`)
- **Relates to**: issue [#469](https://github.com/alfred-os/AlfredOS/issues/469)
  (first-run experience epic this closes Blocker 2 of), issue
  [#309](https://github.com/alfred-os/AlfredOS/issues/309) (the Spec B G6-7-8
  flag-day migration that introduced the on-by-default value this ADR
  reverses — see
  [the flag-day runbook](../runbooks/2026-06-25-discord-flag-day-migration.md)),
  [ADR-0036](0036-gateway-adapter-hosting-inversion.md) (gateway
  adapter-hosting inversion — the hosting mechanism this ADR leaves
  untouched), [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md)
  (Discord-adapter egress — also mechanism, also untouched), issue
  [#331](https://github.com/alfred-os/AlfredOS/issues/331) (park-not-abort,
  the follow-up this ADR's first residual defers to), issue
  [#493](https://github.com/alfred-os/AlfredOS/issues/493) (invalid-token
  legibility, the follow-up this ADR's second residual defers to)
- **Supersedes**: — (no prior ADR recorded the on-by-default compose
  value; #309 shipped it via a plan/runbook, not an ADR. ADR-0036 and
  ADR-0043 govern the gateway-hosting *mechanism* — spawning, credential
  delivery, egress — which this ADR does not change.)

## Context

The documented quickstart is `git clone && bin/alfred-setup.sh && docker
compose up`, and PRD [§4 SC-1](../../PRD.md#4-success-criteria--mvp-v01)
makes that a binary MVP success criterion: it must "bring up a working
stack on macOS, Linux, or Windows-via-WSL." Before this change it did not.
`docker-compose.yaml` resolved the gateway's hosted-adapter set as
`${ALFRED_GATEWAY_HOSTED_ADAPTERS:-["alfred_discord"]}` — Discord hosted by
default, with no token required to reach that state. On a stock first run
with no `ALFRED_DISCORD_BOT_TOKEN` set, the gateway's first spawn attempt
for the Discord child hit a credential refusal
(`AdapterCredentialError(reason="missing_secret")`), which the supervisor
re-raises fail-closed on a first attempt. `start_gateway`'s `_main` runs
the adapter supervisor, the TUI relay, and both egress planes under one
`asyncio.TaskGroup`, so that single failure cancelled the whole group and
the gateway process exited with an uncaught traceback. `restart:
unless-stopped` turned that into an infinite crash-loop, and because
`alfred-core` declares `depends_on: alfred-gateway: condition:
service_healthy`, the core never started either — an operator saw
containers cycling between "up" and "restarting" with no actionable
message.

The on-by-default value was not a mistake in isolation — it was the
correct choice for the migration it shipped in.
[#309](https://github.com/alfred-os/AlfredOS/issues/309) (Spec B G6-7-8)
moved Discord from a standalone `alfred-discord` Compose service to a
gateway-hosted child. Every deployment running that migration already had
a working `discord_bot_token` (in `secrets.toml`, then moved to
`ALFRED_DISCORD_BOT_TOKEN`) — on-by-default was safe for an *upgrade*
where a token already existed. It was never revisited for a *first* run,
where no token exists yet, and the compose fallback silently drifted from
the code-level default: `Settings.comms_enabled_adapters` was already
`Field(default=())` — empty. Only the deployed `docker-compose.yaml`
fallback disagreed with the code's own default.

## Decision

`docker-compose.yaml`'s `ALFRED_COMMS_ENABLED_ADAPTERS` resolves
`${ALFRED_GATEWAY_HOSTED_ADAPTERS:-[]}` — the shipped default hosts **no**
comms adapter. Enabling Discord is an explicit operator action: set
`ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]` in `.env` alongside
`ALFRED_DISCORD_BOT_TOKEN`, or re-run `bin/alfred-setup.sh`, which seeds
the var automatically once it finds a token already present.

This flips a **deployment default**, not the Discord **capability**. The
adapter itself, the spawn mechanism, credential delivery over fd-3, and
the L7-proxy egress bridge ([ADR-0036](0036-gateway-adapter-hosting-inversion.md),
[ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md)) are
unchanged — the same code path runs whether the adapter is opted in via
`.env` or (previously) enabled by the compose fallback. PRD
[§6.1](../../PRD.md#61-multi-modal-comms) lists Discord as an MVP
*capability* AlfredOS must support, not a mandate that it run
out of the box; this ADR aligns the zero-config default with that reading
without touching the capability. The PRD [§5](../../PRD.md#5-architecture-overview)
architectural invariants this touches the *edge* of — gateway as the sole
external egress plane, the connectivity-free core, the dual-LLM split —
are all untouched: none of them are about which adapters are hosted by
default, only about how a hosted adapter's traffic and content are
handled once it exists.

## Consequences

### Positive

- Restores PRD §4 SC-1: a stock `docker compose up -d` boots a healthy
  gateway (`supervise_all([])` is a no-op) and the core's health-gated
  `depends_on` clears, with zero configuration and no token.
- The fail-closed posture for an *explicit* opt-in is unchanged — a
  missing credential still refuses the spawn loud, per hard rules #5/#7.
  This ADR only changes whether that refusal is reachable by default.
- Combined with the Blocker-2 companion changes ([#469] Tasks 2–4, this
  epic), an opt-in with a *missing* token now fails with a legible message
  and `exit 10` instead of a raw traceback, and an opt-in typo'd as the
  canonical `["discord"]` (instead of the package id `["alfred_discord"]`)
  renders the existing config-failed refusal instead of also crashing raw.

### Negative

- **Opt-in-misconfigured is whole-stack-down, accepted until
  [#331](https://github.com/alfred-os/AlfredOS/issues/331).** An operator
  who sets `ALFRED_GATEWAY_HOSTED_ADAPTERS` but leaves the token unset
  still takes the *entire* gateway process down — not just the Discord
  adapter — because the adapter supervisor, the TUI relay, and both
  egress planes share one `TaskGroup` in `start_gateway._main`. `alfred
  chat` and every other gateway-mediated surface go down with it. This
  ADR's compose-default flip does not change that blast radius; it only
  changes whether an operator reaches it by default (no longer) or by
  deliberate choice (still yes). The structural fix — parking the broken
  adapter without aborting the gateway — is #331's scope, not this ADR's.
- **A wrong (not merely absent) token stays loud until
  [#493](https://github.com/alfred-os/AlfredOS/issues/493).** The friendly
  exit-10 refusal this epic ships is narrowly scoped to the
  already-audited credential-refusal path (`missing_secret` /
  `grant_mismatch` / `delivery_failed`). An *invalid* token fails the
  Discord handshake (`LoginFailure`) on a separate path that is not yet
  distinguishable from a genuine handshake bug without threading a typed
  auth-failure reason through the shared `comms_runner` — a
  trust-boundary-weighted change with its own review, deliberately not
  folded in here. Until #493 lands, a wrong token still surfaces as a raw
  traceback.
- **A pre-existing deployment that never sets the opt-in var explicitly
  loses Discord silently on upgrade.** An operator who deployed under the
  old default (relying on `ALFRED_GATEWAY_HOSTED_ADAPTERS` being implicit
  rather than set in their `.env`) sees the gateway stop hosting Discord
  the next time they pull this change and run `docker compose up -d`,
  with no error — the new default is simply empty. Re-running
  `bin/alfred-setup.sh` restores it (the seed step detects the existing
  token and writes the opt-in var), but a bare `docker compose pull && up
  -d` with no setup re-run does not. This is a one-time migration cost of
  reversing an established default, not an ongoing risk.

## Alternatives considered

- **Park instead of abort (surviving the credential failure).** Keep
  Discord on-by-default, but change the supervisor to park the failed
  adapter and let the rest of the gateway (relay, egress planes, other
  adapters) continue. Rejected for this ADR: it is the right long-term
  shape but a materially larger, fail-closed-trust-boundary change
  needing its own security and adversarial sign-off — tracked as
  [#331](https://github.com/alfred-os/AlfredOS/issues/331) rather than
  bundled into a default-value fix.
- **Hard-gate at setup instead of flipping the deployed default.** Make
  `bin/alfred-setup.sh` refuse to proceed (or refuse to write a
  `.env`) until the operator makes an explicit Discord yes/no choice,
  leaving the compose default on-by-default. Rejected: it does not fix
  the failure mode for anyone who deploys via `docker compose up`
  directly without running the setup script first (a supported path per
  PRD §4 SC-1's own wording), and it adds an interactive gate to what is
  otherwise a non-interactive, idempotent script.

## References

- PRD [§4 Success Criteria — MVP (v0.1)](../../PRD.md#4-success-criteria--mvp-v01)
  — SC-1, the onboarding criterion this ADR restores.
- PRD [§5 Architecture Overview](../../PRD.md#5-architecture-overview) —
  the gateway-as-sole-egress-plane, connectivity-free-core, and dual-LLM
  invariants this ADR leaves untouched.
- PRD [§6.1 Multi-modal Comms](../../PRD.md#61-multi-modal-comms) —
  Discord as an MVP capability, not a default-on mandate.
- [docs/runbooks/2026-06-25-discord-flag-day-migration.md](../runbooks/2026-06-25-discord-flag-day-migration.md)
  — the #309 migration that introduced the on-by-default value this ADR
  reverses; carries a forward-pointer to this ADR.
- [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — gateway
  adapter-hosting inversion (the hosting mechanism, unchanged here).
- [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md) —
  Discord-adapter egress via the gateway L7 proxy (also unchanged).
- Design spec:
  `docs/superpowers/specs/2026-07-23-469-blocker2-gateway-optin-discord-design.md`
  (v4; a 10-lane `/review-plan` fleet pass folded into v2, plus a focused
  4-lane re-review on v3's invalid-token addition that split it out to
  #493).
- Plan: `docs/superpowers/plans/2026-07-24-469-blocker2-opt-in-discord.md`.
- `docker-compose.yaml` — the `ALFRED_COMMS_ENABLED_ADAPTERS` default.
- `src/alfred/config/settings.py` — `Settings.comms_enabled_adapters`
  (`Field(default=())`), the code-level default this ADR aligns the
  deployed default with.
- `src/alfred/gateway/adapter_supervisor.py` — `GatewayAdapterCredentialError`,
  the credential-refusal marker the exit-10 friendly handler catches.
- `src/alfred/cli/gateway/_commands.py` — `start_gateway`, `_EXIT_ADAPTER_SPAWN_FAILED`.
- `bin/alfred-setup.sh` — `seed_hosted_adapters`, the idempotent opt-in
  seed step.
- Follow-up issues: [#331](https://github.com/alfred-os/AlfredOS/issues/331)
  (park-not-abort), [#493](https://github.com/alfred-os/AlfredOS/issues/493)
  (invalid-token legibility).
