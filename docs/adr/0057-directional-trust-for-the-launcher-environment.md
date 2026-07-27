# ADR-0057: Directional trust — a `.env` may tighten the launcher's environment, never loosen it

- **Status:** Accepted
- **Date:** 2026-07-27
- **Supersedes:** nothing. **Amends** [ADR-0053](0053-three-layer-environment-precedence.md)
  §3 (the launcher's trust rule) and its §2 aside describing the launcher as a two-layer
  chain. ADR-0053 §1, §4, §5 and §6 stand unchanged — superseding it would orphan them.
- **Issue:** [#486](https://github.com/alfred-os/AlfredOS/issues/486) · epic
  [#469](https://github.com/alfred-os/AlfredOS/issues/469)

## Context

`bin/alfred-plugin-launcher.sh` resolves `ALFRED_ENVIRONMENT` for itself, via
`manifest_reader --read-environment`. Its answer becomes `ALFRED_RESOLVED_ENVIRONMENT` and the
`IS_PRODUCTION` flag derived from it, which gate the unsandboxed-in-production refusal (`:341`,
which tests `ALFRED_RESOLVED_ENVIRONMENT` directly), the non-Linux UID-drop refusal (`:327`), and
the `FAKE_UNAME` keystone (`:267`, `:288`). Line numbers are against this branch — the #521
commit shifts them 17 lines from `origin/main`.

ADR-0053 §3 resolved that path **trusted-sources-only** (`consult_dotenv=False`): env var and
`/etc/alfred/environment`, never a CWD `.env`. The reasoning was sound — a `.env` is writable by
anything with directory access, including a plugin that escaped its sandbox, so letting it select
`development` would let an escape make itself permanent.

That left a residual, recorded in ADR-0053 and filed as #486: a bare-host install configured
**only** through `.env` boots the daemon (which does read `.env`) and then refuses **every**
sandboxed plugin spawn. Meanwhile `README.md` and `.env.example` present `.env` as a sufficient
way to configure this — `.env.example` ships `ALFRED_ENVIRONMENT=production` uncommented. So an
operator who followed the documentation exactly hit a dead end.

### The obvious fix is unsafe

Issue #486 proposed having the daemon inject its resolved environment into the child spawn env.
Measured:

```
                                     daemon resolves         launcher today   launcher w/ naive inject
A. /etc=production, .env=development  production via etc      production       production
B. /etc ABSENT,     .env=development  development via dotenv  REFUSE           development  <- the harm
C. /etc ABSENT,     .env=production   production via dotenv   REFUSE           production
```

Scenario B is exactly #486's configuration: naive injection converts a fail-closed refusal into a
`.env`-decided value, and `development` from `.env` unlocks the gates above. (Scenario A is *not*
reachable — the daemon's own precedence floors `.env` under `/etc` before injection. An earlier
draft of this analysis claimed otherwise and was wrong.)

## Decision

Trust becomes **directional** rather than exclusionary.

`manifest_reader --read-environment` resolves **with** `.env` (`consult_dotenv=True`), and
honours a `DOTENV`-sourced value **only when it is `production`** — the strictest setting. A
`DOTENV`-sourced `development` or `test` refuses with its own key,
`daemon.boot.environment_untrusted_source`.

> **A writable `.env` may ratchet the sandbox tighter. It can never loosen it.**

Precedence is unchanged: a trusted source still outranks `.env` entirely, so this only ever
decides the case where `.env` is the **only** source.

`.env` here means `Path(".env")` relative to the **daemon process's CWD**, not the repo
directory — no spawn site passes `cwd=`. Under a systemd unit with `WorkingDirectory=/` there
is no `.env` to find and #486's dead end persists as `environment_not_set`; such a deployment
must use a trusted source.

## Consequences

### Positive

- The documented default path works on Linux. `.env.example` ships `production`, so the
  operator who copied it as the README instructs gets a working, **fully sandboxed** spawn.
  On a macOS/Windows bare host the spawn still refuses — `uid_separation_unavailable` at
  `:327`, unrelated to this ADR — so this fixes the environment dead end there without making
  those hosts spawn-capable.
- **No trust concession in the VALUE.** The only value `.env` can supply is the strictest one,
  and it can never relax the sandbox. This is *not* a claim of no concession in the SURFACE —
  see Negative below.
- Fail-closed and **loud**. The loosening case refuses with a distinct, actionable reason rather
  than being silently overridden — CLAUDE.md hard rule #7.
- One edit site. Every spawn surface (`comms_stdio_transport`, `quarantine_child_io`,
  `adapter_child_factory`, and the foreground `_launcher_spawn`) funnels through the launcher, so
  none can drift. A fix at the spawn sites would have needed four edits, and
  `_launcher_spawn.py:162` *inlines* `_scrubbed_base`'s comprehension rather than calling it — it
  would have been missed (the #422 drift shape).

### Negative

- **A new attack SURFACE, even though the value domain is closed.** The launcher now opens and
  parses an attacker-writable file it previously never touched: a python-dotenv parse over
  adversary bytes, and a blocking `open()` with no timeout (a `mkfifo .env` wedges the read;
  the boot probe is bounded, the spawn path is not).
- **A new runtime DoS primitive — not the pre-existing one.** Corrupting `.env` previously
  affected only the DAEMON AT BOOT, because the launcher never read it. It now denies every
  subsequent spawn of an already-running daemon, live, with no restart. Measured: garbage →
  `environment_unrecognised`; directory / mode-000 / invalid UTF-8 → `environment_not_set`.
- **The invariant is weaker to state, and therefore easier to break.** It was "the launcher never
  reads `.env`" — structurally verifiable by grepping for `consult_dotenv=False`. It is now "a
  `.env` may never *loosen* the launcher's posture", which a future change can violate while still
  looking correct. Mitigated by release-blocking adversarial tests asserting the loosening case
  refuses, but a reviewer must now understand the property rather than just the call.
- The dev escape hatch is unreachable from `.env` alone. A developer wanting `development` must
  export the variable or write `/etc/alfred/environment`. The refusal message says so.
- Audit rows carrying `environment=production` no longer distinguish a `.env`-sourced value from a
  trusted one.

### Rejected alternatives

- **Provision `/etc/alfred/environment` at setup.** No delivery vehicle — `bin/alfred-setup.sh` is
  a compose installer that hard-requires Docker, no compose service mounts `/etc/alfred`, and
  `bin/dev-setup.sh` (in CLAUDE.md's table) does not exist. Worse, it never specified *what value*
  to write: the operator's `.env` value would launder an app-writable value into a root-owned
  trusted source — durably unlocking the gateway launch-target escape hatch — and a hardcoded
  `production` is this ADR's rule, written to disk, permanent and less reversible.
- **Floor a `.env` value to `production` silently.** A production floor on macOS/Windows converts
  a diagnosable `environment_not_set` into an undiagnosable `uid_separation_unavailable`, so it
  does not fix #486 there at all, and the override is silent (hard rule #7).
- **Pass value + source, let the launcher floor it.** The source key would be unauthenticated —
  a daemon that would lie about the source would lie about the value — so it buys no adversarial
  guarantee. Worse, daemon/launcher version skew is *fail-open*.

## Related

- [ADR-0053](0053-three-layer-environment-precedence.md) — precedence (§1) is untouched; §3's
  trusted-sources-only rule for the launcher is amended by this ADR.
- [#519](https://github.com/alfred-os/AlfredOS/issues/519) — the launcher's control surface is
  daemon-supplied for five allowlisted keys, and compose substitutes `ALFRED_ENVIRONMENT` from the
  host `.env`. That bounds how much independence the launcher's check buys, and is unrecorded in
  ADR-0053. It does not change this decision — `.env` still cannot loosen — but it should be
  answered on its own terms.
- [#521](https://github.com/alfred-os/AlfredOS/issues/521) — the launcher self-test now exercises
  this resolution, so a launcher that cannot resolve fails the boot probe instead of passing green.
