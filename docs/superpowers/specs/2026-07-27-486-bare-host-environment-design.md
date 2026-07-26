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

**Implemented naively that reintroduces the CRITICAL #469 Blocker 1 closed** — but not by the
mechanism this spec originally claimed. Corrected after the security review refuted the first
version. Measured, three scenarios:

```
                                     daemon resolves        launcher today   launcher w/ naive inject
A. /etc=production, .env=development  production via etc     production       production   <- NO downgrade
B. /etc ABSENT,     .env=development  development via dotenv REFUSE           development  <- THE HARM
C. /etc ABSENT,     .env=production   production via dotenv  REFUSE           production
```

**Scenario A — the exploit this spec first claimed — is not reachable.** The daemon's own
precedence (`ENV_VAR > ETC_FILE > DOTENV`) already floors `.env` under `/etc` *before* anything
is injected, so the daemon resolves `production` and injects `production`. The original table
reached `development` only by *forcing* it — measuring the mechanism's capability and presenting
it as the exploit's reachability. (Same error shape as the #514 CPython-patch theory: a
confident mechanism asserted without checking it was the one actually firing.)

**Scenario B is the real harm, and it is exactly #486's configuration.** Where `/etc` is absent,
naive injection converts a fail-closed `REFUSE` into a `.env`-decided value. A CWD `.env` saying
`development` then sets `IS_PRODUCTION=false`, unlocking the `FAKE_UNAME` keystone
(`bin/alfred-plugin-launcher.sh:250`), the non-Linux unsandboxed exec (`:310`), and the
dev escape hatch (`:324`). It fills a void rather than outranking a trusted source — same
consequence, different physics.

**So the issue's suggested fix is unsafe as written.** Any accepted option must not let a
`.env`-sourced value *loosen* the launcher's posture.

**Scenario C is why Option F below works:** `.env.example` ships `ALFRED_ENVIRONMENT=production`
uncommented, so on the documented default path the only value `.env` ever supplies is
`production` — the strictest setting.

### Second-order finding — CONFIRMED, and stronger than first framed

`docker-compose.yaml:146,277` set `ALFRED_ENVIRONMENT: ${ALFRED_ENVIRONMENT:-production}`.
Compose substitutes that from the host shell **or the project `.env`**. So on the compose path
a host-side `.env` saying `development` becomes a genuine env var in the daemon,
`_scrubbed_base()` forwards it verbatim, and the launcher resolves it as `ENV_VAR` — the top
tier — outranking the container's `/etc/alfred/environment`.

**No compromised daemon, no injection, no code change. This works today.** The original framing
(a *compromised* daemon) was too weak; the plain compose path already does it.

ADR-0053 cites the compose `.env`→`os.environ` promotion three times, each as the reason compose
"is unaffected", and never observes that the same promotion defeats §3's launcher trust floor on
that path. That is an unrecorded gap, not an accepted residual. There is a legitimate mitigating
argument — the compose `.env` is host-side, outside the container, so a container-escaped plugin
cannot write it, unlike a bare-host `.env` in the daemon's own CWD — but it appears nowhere.
**Filed separately; it determines how much independence the launcher's check actually buys.**

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

### F. Directional trust — a low-trust source may ratchet toward the STRICTER value only

Resolve with `consult_dotenv=True` inside `_cmd_read_environment`
(`src/alfred/plugins/manifest_reader.py:247`), but honour a `DOTENV`-sourced value **only when
it is `production`**. A `DOTENV`-sourced `development`/`test` refuses as today, under a new
`environment_untrusted_source` key (Option E's payload).

- Fixes the documented default path outright — `.env.example` ships `production`, so the
  operator who followed the README gets a working, **fully sandboxed** spawn.
- Zero trust concession: the only value `.env` can supply is `production`, and `production` is
  uniformly the stricter branch across the launcher (`:250`, `:271`, `:310`, `:324`, `:550`,
  `:570`). Forcing it can only DoS a dev box — and whoever can write `.env` can already do that.
- No rule-7 violation: the loosening case still refuses **loudly** and actionably. Nothing is
  silently overridden — which is precisely where C fails.
- Smallest blast radius: no new env key, no bash change, no daemon change, no root, no setup
  script, no version handshake. Covers all three spawn surfaces at once (`comms_child_env`, the
  foreground `_launcher_spawn`, and `gateway/adapter_child_factory`) because they all funnel
  through the launcher.

Costs, stated honestly: it reopens the `.env` read on the launcher path that ADR-0053 §3 closed
*by construction*. The invariant weakens from "the launcher never reads `.env`" to "a `.env` may
never loosen the launcher's posture" — a weaker structural claim needing an ADR amendment and
dedicated adversarial tests. It does **not** fix the macOS-dev case (`.env=development`); nothing
safe does, and E tells that operator so in one line.

### G. Make the trusted source verify its trust (companion, independent of A-F)

`_read_etc` never stats owner or mode — the `ETC_FILE` tier is trusted purely by convention. It
should treat a non-root-owned or group/other-writable file as `UNREADABLE`, reusing the existing
fail-closed err-01 path. Latent today because a fresh install has no `/etc/alfred` at all; any
option that leans harder on `/etc` (D most of all) makes that convention load-bearing.

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

## Recommendation (post security review)

**F + E + G.** D remains the correct long-term destination once a bare-host installer exists to
hang it on.

- **F** fixes the documented default path with no trust concession.
- **E** makes the remaining case (`.env=development` on a dev box) self-service in one line
  instead of a dead end.
- **G** makes the middle tier earn its rank before anything leans harder on it.

Rejected: the naive injection (scenario B). **B** — the source key is unauthenticated, so it
buys no adversarial guarantee the design lacks; worse, daemon/launcher version skew is
*fail-open*. **C** — a production floor on macOS/Windows converts a diagnosable
`environment_not_set` into an undiagnosable `uid_separation_unavailable`, so it does not fix #486
there at all, and the override is silent.

## What the human is actually being asked

Not "is `sudo` acceptable" — there is no bare-host installer to put it in (D1). The live
question is:

> **Is `.env` a supported configuration channel for the launcher's `environment`, in the
> strictly-tightening direction only?**
>
> - **Yes → Option F.** A `.env` may say `production` and be believed; it may never say
>   `development` and be believed. The shipped `.env.example` default works out of the box.
>   ADR-0053 §3 is amended from "the launcher never reads `.env`" to "a `.env` may never loosen
>   the launcher's posture."
> - **No → E alone.** `.env` is then not a complete config channel for bare-host. The honest
>   resolution is to say so in the refusal message with a one-line remedy
>   (`export ALFRED_ENVIRONMENT=…`), close #486 as working-as-designed-with-a-fixed-message, and
>   defer D until a bare-host installer exists.

## Non-goals

- Changing `resolve_environment`'s precedence. `ENV_VAR > ETC_FILE` is load-bearing elsewhere.
- Relaxing the launcher's `consult_dotenv=False`. That decision stands (ADR-0053 §3).
- Reconciling `ALFRED_ENV` vs `ALFRED_ENVIRONMENT` (#489).

---

## Review synthesis (security · architect · devex)

All three lanes reviewed this spec. They **agree** that the naive injection is unsafe and that
the original mechanism claim was wrong. They **disagree on option D**, and that disagreement is
the decision.

### Unanimous — the spec's own framing was wrong in three ways

1. **Mechanism** (security, architect, independently): scenario A is unreachable. Corrected above.
2. **D has no delivery vehicle** (all three): `bin/alfred-setup.sh` hard-requires `docker` +
   `docker compose` (`:127-133`) and no compose service mounts `/etc/alfred`, so the write is
   inert on compose and unreachable on bare-host. `bin/dev-setup.sh`, listed in CLAUDE.md's
   command table, **does not exist**.
3. **Option E as scoped is aimed at the wrong string** (architect H-4, devex C-1/C-2/C-3):
   - The launcher's catalog text was already fixed in Blocker 1 and is *three-layer*; the defect
     is that the launcher **reuses the daemon's key verbatim**
     (`manifest_reader.py:104` → `daemon.boot.environment_not_set`), so a two-layer caller emits a
     three-layer message naming `.env` — the one file that cannot work. E must **split the key**,
     not reword it.
   - Worse, on the documented path the operator never sees that string at all. Every
     `QuarantineChildSpawnError` maps to `t("daemon.boot.quarantine_child_spawn_failed")`
     (`_commands.py:981-985`), whose only actionable remedy is *install bwrap* or *disable comms*
     — both wrong when bwrap is present and the launcher is provisioned.
   - And `_sandbox_i18n.py:5-7` documents a supervisor-side catalog render **that does not
     exist**, so improving a `msgstr` improves nothing that reaches a terminal.

### The disagreement on D

| lane | verdict on D |
| --- | --- |
| security | right long-term destination, no vehicle today → not this week |
| **architect** | **reject outright** — see below |
| devex | yes, `sudo` is acceptable; relocate it above the Docker gate |

**The architect's objection is the sharpest thing in the three reviews, and it is decisive:**
the spec never says *what value* setup writes, and both branches are bad.

- **Writes the operator's `.env` value** → the installer copies an app-writable file's value into
  a root-owned *trusted* source. That durably unlocks the gateway launch-target escape hatch
  (`adapter_child_factory._resolve_launch_target` honours `ETC_FILE`) from a `.env`-sourced value.
  Strictly worse than the concession C makes: C's floor is per-spawn and revocable, D's is
  persistent on-disk state nothing removes.
- **Hardcodes `production`** → D *is* option C, written to disk, with C's silent-override cost
  plus permanence, minus C's reversibility.

Either way, "zero trust concession" — the whole basis of this spec's original recommendation —
**is not accurate**.

### Where the lanes land on the mechanism

- **security → F** (directional trust in `_cmd_read_environment`: a `DOTENV` value is honoured
  only when it is `production`).
- **architect → A+C as one composite rule** at the spawn boundary: inject *this process's*
  resolved value, floored to `production` when `source is DOTENV`. Notes this is literally the
  issue's own words — "inject its resolved (**source-floored**) environment" — and that the spec
  rejected a naive version the issue never proposed.

These two are **the same trust rule at different sites**: "a `.env` may select `production` and
be believed; it may never select `development` and be believed." F puts it in the launcher's
resolver (one site, covers all four spawn surfaces); A+C puts it at each spawn site (four sites —
`comms_stdio_transport.py:175`, `quarantine_child_io.py:303`, `adapter_child_factory.py:298`, and
`_launcher_spawn.py:162` which **inlines** the comprehension rather than calling `_scrubbed_base`,
so it silently misses a `_scrubbed_base`-only fix — the #422 drift shape).

**F is the smaller blast radius and is preferred** unless security objects to the launcher reading
`.env` at all.

### Uncontested, zero-trust-cost work all three lanes endorse

These need no security sign-off and are independently shippable:

- **Split the boot message** so an environment refusal is not reported as a missing-bwrap host,
  and stop recommending "disable comms" as the remedy.
- **Split the launcher's catalog key** from the daemon's, and ship a renderer so it reaches a
  terminal.
- **`--self-test` must resolve the environment.** It currently `exit 0`s at
  `bin/alfred-plugin-launcher.sh:48`, *before* the resolution at `:223` — so
  `probe_launcher_policy_resolving` passes green on a launcher that will refuse every spawn. A
  paper gate of exactly the #514 shape.
- **`README.md:273`** presents the three sources as interchangeable. Two of them satisfy the
  launcher; `.env` does not.

### Filed separately

- **The launcher's control surface is daemon-supplied.** Not just `ALFRED_ENVIRONMENT`:
  `FAKE_UNAME`, `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED`, `ALFRED_PLUGIN_UID`, and
  `ALFRED_SANDBOX_POLICY_DIR` are on the same allowlist, and the production refusals gating them
  key on the value the daemon supplies. Also reachable with no compromise at all:
  `docker-compose.yaml:146,277` substitute `ALFRED_ENVIRONMENT` from the **host** `.env`.
  Unrecorded in ADR-0053, which cites the same promotion three times as the reason compose "is
  unaffected".
- **Two spawn sites discard the launcher's stderr entirely** (`comms_stdio_transport.py:164-176`,
  `adapter_child_factory.py:544-551`) — a Discord adapter refusing produces no log, no audit row,
  no message. Hard rule #7.

### ADR disposition

New **ADR-0057** (highest on disk is 0056; claim it against `git ls-tree origin/main` plus open
branches — the duplicate-0047 precedent came from claiming off the working tree). Do **not**
supersede ADR-0053: its §1 precedence decision is untouched. Do edit 0053 in place at the three
places naming `_comms_child_env._scrubbed_base()` as the fix location (`:289-311`, `:409-413`,
`:437-440`), or a reader looks in the wrong module.

### The question for the human, restated

> **May a `.env` select `production` for the launcher — the strictly-stricter value — while never
> being able to select `development` or `test`?**
>
> - **Yes** → ship F (or A+C), behind ADR-0057. `.env.example` ships `production`, so the
>   documented default path works out of the box with no trust concession.
> - **No** → `.env` is not a complete config channel for bare-host. Ship the uncontested message
>   and `--self-test` work, say so plainly in the docs, and close #486 as
>   working-as-designed-with-a-fixed-message. Note this **retracts a documented capability**
>   (`README.md:273`, `.env.example:164`), which is a scope reduction needing explicit approval.

**#469 is not closable on this alone** — #493 is open and labelled #469 scope, and the epic's UAT
item 1 (the gateway service block carries `ALFRED_DEEPSEEK_BASE_URL` but not
`ALFRED_DEEPSEEK_API_KEY`) appears still open on `main`. Verify before closing.
