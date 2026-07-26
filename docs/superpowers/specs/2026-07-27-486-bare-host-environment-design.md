# #486 — bare-host `.env`-only install: every sandboxed plugin spawn refuses

**Status:** design, awaiting security sign-off on the chosen option.
**Issue:** [#486](https://github.com/alfred-os/AlfredOS/issues/486) · epic [#469](https://github.com/alfred-os/AlfredOS/issues/469) · residual of [#469 Blocker 1](https://github.com/alfred-os/AlfredOS/pull/491) / [ADR-0053](../../adr/0053-three-layer-environment-precedence.md)

## The defect

On a bare-host install configured **only** through a CWD `.env` (no `ALFRED_ENVIRONMENT`
exported, no `/etc/alfred/environment`):

1. The daemon boots fine — `Settings` resolves `environment` **with** `.env`
   (`consult_dotenv=True`).
2. Every sandboxed plugin spawn then refuses with `daemon.boot.environment_not_set`.

Because `_scrubbed_base()` (`src/alfred/plugins/_comms_child_env.py`) forwards
`os.environ["ALFRED_ENVIRONMENT"]` — which on this path is **unset** — the child launcher
re-resolves from its own trusted sources only (`resolve_environment(consult_dotenv=False)`,
env var + `/etc`), finds nothing, and refuses.

Compose is unaffected: it promotes `.env` into `os.environ`, so the key is present to forward.

The refusal message is also wrong on this path — it tells the operator to set it in `.env`,
which they already did.

## The finding that changes the fix

The issue proposes: *"have the daemon inject its resolved (source-floored) environment into
the child spawn env."*

**Implemented naively, that reintroduces the exact vulnerability #469 Blocker 1 closed as a
CRITICAL.** Measured, not inferred:

```
setup: /etc = production (root-owned, trusted)   .env = development (app-writable, CWD)

  launcher today, no env var      : 'production'  via etc_file
  daemon today  (consults .env)   : 'production'  via etc_file
  launcher with INJECTED env var  : 'development' via env_var      <-- overrides /etc
```

`resolve_environment` precedence is **`ENV_VAR > ETC_FILE > DOTENV`**
(`_environment_loader.py:262/282/292`). So injecting the daemon's resolved value as
`ALFRED_ENVIRONMENT` in the child env makes it an **env var in the child — the highest-trust
source — outranking root-owned `/etc`**.

Consequence: an app-writable CWD `.env` saying `development` would set the launcher's
`IS_PRODUCTION=false`, which gates the unsandboxed-in-prod refusal
(`bin/alfred-plugin-launcher.sh:324`), the non-Linux UID-drop refusal (`:308`), and the
`FAKE_UNAME` keystone (`:250`). That is precisely the downgrade the trusted-sources-only
decision exists to prevent.

**So the issue's suggested fix is unsafe as written.** Any accepted option must not let a
`.env`-sourced value carry env-var authority into the launcher.

### Second-order observation (worth security's attention independently)

`ALFRED_ENVIRONMENT` is already on `_SCRUBBED_ENV_ALLOWLIST`. So on the **compose** path a
compromised daemon can already put any value in the child env and outrank `/etc`. The
launcher's "independent check" is therefore already daemon-dependent wherever the daemon's own
env carries the key; its real teeth are on the bare-host path, where the daemon's env is empty
and the launcher falls back to `/etc`.

This is not introduced by #486 — but it bears on how much independence the current design
actually buys, and it should be judged explicitly rather than assumed.

## Options

### A. Trust-floored injection — inject only when source ∈ {ENV_VAR, ETC_FILE}

Safe, and a strict improvement in clarity, but **does not fix #486**: the failing path is
precisely the one where the only source is `.env`. Rejected as a complete fix; harmless as a
component.

### B. Inject value **and** source; the launcher applies its own floor

Add e.g. `ALFRED_ENVIRONMENT_SOURCE` to the child env; the launcher refuses to honour a
`dotenv`-sourced downgrade (treats it as production).

Restores the source-conditioned check that `manifest_reader`'s docstring calls
"unexpressable" over a bare-stdout interface — the daemon knows the source, so it can pass it.
A compromised daemon could lie, but it can already set `ALFRED_ENVIRONMENT` outright, so this
is no worse and strictly better on bare-host.

Cost: widens the launcher's control surface by one key, and every consumer must be taught the
new key or fail closed.

### C. Floor a `.env`-sourced value to `production`

If the daemon's resolution came from `DOTENV`, inject `production` regardless of the value.

Fail-closed and simple: bare-host spawns start working, fully sandboxed. A developer whose
`.env` says `development` silently gets production sandboxing — arguably correct, since the
dev escape hatch is deliberately gated behind a trusted source, but it is a **silent** override
and would need a loud log line.

### D. Provision the trusted source at setup — `bin/alfred-setup.sh` writes `/etc/alfred/environment`

Fixes the defect at its origin with **zero trust concession**: the value then arrives via a
genuinely trusted, root-owned file, exactly as ADR-0053 intends. The bare-host install simply
becomes a *complete* install.

Cost: needs root once at setup (`sudo`), and setup must handle the no-root case gracefully.

### E. Make the refusal actionable (pairs with any of the above)

The current message tells a bare-host operator to set the thing in `.env` that they already
set. It should name the trusted sources: export `ALFRED_ENVIRONMENT`, or write
`/etc/alfred/environment`. Cheap, no trust change, and it is a genuine first-run defect on its
own (#469's subject matter).

## Two holes in option D, found while drafting

**D1 — there is no bare-host installer to hook into.** `bin/alfred-setup.sh` is a *compose*
installer (31 `docker compose` invocations, no bare-host mode). The bare-host path #486 is about
is "run `alfred daemon start` directly" (`docs/runbooks/alfred-chat-through-the-gateway.md`).
So "setup provisions `/etc/alfred/environment`" has nowhere to live today without either adding
a bare-host setup path (larger scope than this issue) or having the daemon write its own trust
anchor — which is circular and should not be entertained.

Mitigating context: setup.sh *already* performs a one-time root-requiring host step (the
AppArmor profile load, `:282-311`) with exactly the shape D would need — `id -u` check, `sudo`
only when not already root, idempotent, graceful WARN where inapplicable, loud fail where it is
an integrity error. So the *mechanism* is precedented; the *hook point* is missing.

**D2 — D can create a worse trap than it fixes.** Once `/etc/alfred/environment` exists, an
operator editing `.env` to change environment sees NOTHING happen, because `/etc` outranks
`.env`. The current failure is at least loud; a silently-ignored edit is not.

## The documentation defect underneath all of this

`README.md:273` tells the operator: *"copy it to `.env` as-is, **or** export the env var, **or**
write `/etc/alfred/environment`, to satisfy this."* Those three are **not** equivalent. `.env`
satisfies daemon boot and does **not** satisfy sandboxed plugin spawns. Whatever option is
chosen, that sentence is wrong today and is arguably the root first-run defect — an operator
followed the README exactly and hit a dead end.

## Recommendation

**E unconditionally, plus D *if* a bare-host setup path is in scope** (see D1 — it may not
be). E alone already fixes the documented-quickstart defect, which is what epic #469 is about.
D resolves #486 without trading away the launcher's independent check at all,
which means it needs no security concession — the operator's intent reaches the launcher
through the channel the design already trusts. E makes the residual case (operator declined
`sudo`, or a non-root install) self-service instead of a dead end.

**C is the fallback** if requiring root at setup is judged unacceptable; it is fail-closed, but
it silently overrides operator intent and needs a loud audit line.

**B is the most flexible** and the most faithful to "the launcher keeps its own judgment", but
it adds a second trust-bearing key to a bash control surface that is already the subject of a
CRITICAL. That is a real cost on a security boundary.

## What needs deciding (human + security)

1. Is requiring `sudo` once during bare-host setup acceptable? (Decides D.)
2. If not, is a silent `.env` → `production` floor acceptable, with an audit line? (Decides C.)
3. Independently: is the second-order observation — that a compromised daemon can already
   outrank `/etc` on the compose path via the allowlisted `ALFRED_ENVIRONMENT` — an accepted
   residual, or its own issue?

## Non-goals

- Changing `resolve_environment`'s precedence. `ENV_VAR > ETC_FILE` is load-bearing elsewhere.
- Relaxing the launcher's `consult_dotenv=False`. That decision stands (ADR-0053 §3).
- Reconciling `ALFRED_ENV` vs `ALFRED_ENVIRONMENT` (#489).
