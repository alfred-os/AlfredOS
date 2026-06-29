# G7-3 — The connectivity-free-core cutover (Spec C)

> Epic #333. Predecessor: G7-2.5 (PR1 #348 `cf0e16f1` + PR2 #349 `afa05783`) — both
> merged. Successors: G7-4 (Discord L7-proxy), G7-5 (PRD §5/§7.1 + ADR-0040 + ops +
> operator CLI). Branch `spec-c-g7-3-connectivity-free-core` off `origin/main` @
> `afa05783`.

## 1. Problem & scope

Spec C's core invariant is a **connectivity-free core**: `alfred-core` has no route to
the internet, kernel-enforced, and the gateway is the sole external egress plane. G7-0
through G7-2.5 built every piece *except the cutover itself*:

- The two-network compose topology exists, but `alfred_internal` is still
  internet-reachable and `alfred-core` is still on `alfred_external` — both networks
  behave like the default bridge (G7-0 laid membership only).
- The in-core `EgressClient` still carries a **direct-egress fallback**: when
  `ALFRED_EGRESS_PROXY_URL` is unset, `build_provider_http_client()` returns `None` and
  the provider SDKs open sockets directly (the loud `egress.client.direct` log).
- Two compose-invariant tests that would assert the end-state are `@pytest.mark.skip`-ped
  with G7-3 pointers.

G7-3 performs the **atomic cutover**: kernel-isolate the core *and* delete its
direct-egress fallback, in one PR, so no intermediate state leaves a half-isolated or
still-routable window. After G7-3 the core can reach the internet **only** through the
gateway.

This is structural — it changes a system invariant (the core loses its external route)
— so it ships with a new ADR (**ADR-0042**).

### In scope

1. Compose isolation flip: `alfred_internal: {internal: true}` + remove `alfred_external`
   from `alfred-core` (one atomic edit).
2. Delete the provider-proxy direct-egress fallback: a missing proxy URL becomes
   fail-closed (`IOPlaneUnavailableError`), not a silent direct hop.
3. Un-skip + tighten the three compose-invariant tests that pin the end-state.
4. A layered connectivity proof — static (always-on, required) + a docker-gated runtime
   egress/DNS proof in the required `integration` lane (paper-gate-proof).
5. ADR-0042 + factual amendments to any ADR that still describes the fallback as live;
   runbook/README note for the macOS host-port consequence.

### Out of scope (held firm)

- G7-4 (Discord L7-proxy hardening), G7-5 (PRD §5/§7.1 rewrite, ADR-0040, ops dashboards,
  operator CLI).
- Production-readiness epics #338/#339/#340 — explicitly sequenced **after** G7-3 (a live
  agent must not egress while a fallback could still exist).
- Relay boot-time enforcement. The tool-egress relay is **already** fail-closed on an
  unset URL (`assembly.py` and `RelayEgressClient` raise) and has no live caller until
  #339, so G7-3 adds no new relay enforcement — it only documents the symmetry.
- Editing `CLAUDE.md` / `PRD.md` (human-gated). ADR-0040 stays reserved for G7-5.

## 2. Locked decisions (do NOT relitigate)

1. **The gateway is the sole external egress plane.** Unchanged from Spec C.
2. **The flip is atomic.** Never isolate while a fallback exists; never delete the
   fallback while the core is still externally routable. Both move in **one PR**
   (confirmed: the change is small and the atomicity is load-bearing — a guarded
   sequence would re-introduce exactly the window the invariant forbids).
3. **Fail-closed if the gateway proxy/relay is unreachable or unconfigured.** A missing
   `ALFRED_EGRESS_PROXY_URL` is now a boot refusal on egress-needing paths, not a direct
   hop.
4. **`internal: true` is the kernel enforcement-of-record.** The userspace forward-proxy
   allowlist + the import-guard are independent defense-in-depth, not the primary control.

## 3. The cutover — four coupled edits

### 3.1 Compose isolation flip (`docker-compose.yaml`)

```yaml
# alfred-core.networks: remove the external leg
networks:
  - alfred_internal
  # - alfred_external          # DELETED at G7-3 (the connectivity-free flip)

# networks block:
alfred_internal:
  internal: true               # ADDED at G7-3 (kernel enforcement-of-record)
alfred_external: {}
```

- `alfred-gateway` keeps **both** networks — it is the egress chokepoint (receives from
  the core on `alfred_internal`, reaches the internet on `alfred_external`).
- Datastores (`alfred-postgres`, `alfred-redis`) are already `alfred_internal`-only —
  unaffected by the membership change, but now genuinely isolated by `internal: true`.
- **Boot ordering (Spec C §11):** add `alfred-core.depends_on: alfred-gateway` (the gateway
  boots healthy in its core-down/buffering state and has no `depends_on` on the core, so
  there is no cycle). This makes the gateway's egress-proxy/relay listeners ready before the
  isolated core's first CONNECT — Spec C §11 line 167 lists this `depends_on`/`--wait` as a
  canonical G7-3 deliverable. (Not load-bearing *today* — no production egress caller until
  #338/#339 wires the orchestrator into boot — but cheap, correct, and prevents a real
  future first-CONNECT race.)
- **Stale-doc sweep (HARD rule #9 — security-boundary doc drift).** Every surface that still
  describes the now-deleted "unset ⇒ direct egress" fallback is rewritten to the realized
  end-state: the network-block comments (`# G7-3 removes this line` / `# The ISOLATION FLIP
  is a single atomic step at G7-3`), the inline `ALFRED_EGRESS_PROXY_URL` comment
  (`docker-compose.yaml:165-167`), and `.env.example:54-56`.

**macOS / OrbStack consequence (verified empirically, 2026-06-29):** an `internal: true`
container's host-published port is **not** forwarded on OrbStack/Docker-Desktop
(`127.0.0.1:5432` → connection refused), though Linux NATs published ports independently
of the network's external gateway (so Linux CI + Linux deploys keep working). Decision:
**keep** `alfred-postgres`'s `5432:5432`. The compose-internal core reaches Postgres over
`alfred_internal`, and the dev test loop uses testcontainers (independent networks), so
neither is affected — only host-side tooling that genuinely dials `localhost:5432` on a
Mac (e.g. a host `psql`). This is documented in the runbook. **No test breaks:** the one
smoke test that names `127.0.0.1:5432` (`test_discord_gateway_smoke.py`) uses it as a
*placeholder DSN* to satisfy `Settings.model_validate` only — it never opens a Postgres
connection (the gateway holds no DB session, ADR-0036) — verified during planning (§5).

### 3.2 Delete the provider-proxy direct fallback (`src/alfred/egress/client.py`)

- `EgressClient.from_settings(settings)` **raises `IOPlaneUnavailableError`** when
  `settings.egress_proxy_url is None` — the connectivity-free core has no direct-egress
  fallback (HARD rule #9). The constructor tightens to `proxy_url: str` (non-optional).
- `build_provider_http_client()` loses its `None`-branch and the `egress.client.direct`
  log; it unconditionally returns the proxied `httpx.AsyncClient` (return type
  `httpx.AsyncClient`, no longer `| None`). The error `detail` string **names
  `ALFRED_EGRESS_PROXY_URL`** so the refusal points the operator at the missing variable.
- `Settings.egress_proxy_url` **stays** `str | None` (a dumb config holder; the blank→None
  validator is unchanged). The invariant — "None is fatal" — lives at the egress seam, not
  in Settings.
- **Stale-doc sweep within `client.py`:** the module docstring (lines 7-12, which still
  describes "unset ⇒ None and providers construct directly") and the `proxy_url` property
  (`-> str | None` → `-> str`, now that the ctor takes a non-optional `proxy_url`) are
  rewritten for a type-clean, doc-accurate deletion.
- **Resolve the deferred limits marker (`client.py:62-71`).** That comment promised
  "revisit the limits before G7-3 deletes the direct fallback and the proxied path becomes
  the only egress" — G7-3 *is* that trigger. Decision: **accept httpx's default connection
  limits / HTTP-version** (safe at single-operator scale; the operative request timeout
  stays on the SDK ctor, `rider 4`) and rewrite the marker so G7-3 does not ship a stale
  promise. Tuning the proxied-path limits is a tracked G7-5 ops concern, not a G7-3 blocker.
- The error message reuses the existing `egress.io_plane_unavailable` i18n key
  (detail-driven); no new catalog key. The deleted `egress.client.direct` is a structlog
  event, not a `t()` string.

**Runtime reality (honest framing — `component-complete ≠ runtime-wired`).** The fallback
deletion is a **fail-closed seam guarantee**: `EgressClient` can no longer hand a provider a
direct (un-proxied) client. It is *not* yet a live daemon boot-refusal — `build_router`'s
only production caller is `build_orchestrator` (`_bootstrap.py:448`), and the orchestrator
is **not** wired into daemon `start` today (the deterministic-echo daemon; post-Spec-A-G5
`alfred chat` no longer builds the router either), and `IOPlaneUnavailableError` is in **no**
daemon-start `except` tuple. So the **live** G7-3 enforcement is the kernel isolation
(`internal: true`), not a boot refusal. **Hand-off:** when #338/#339 wires
`build_orchestrator` into boot, that PR MUST catch `IOPlaneUnavailableError` at the boot
boundary and route it to the audited `_refuse_boot` path (HARD rule #7), not let it surface
as a bare unaudited traceback. G7-3 records this hand-off; it does not pre-wire it (no
consumer would be dead code — the G7-0/G7-1 "no dead seam" discipline).

The **tool-egress relay** path needs no code change: `build_web_fetch_egress_extractor`
already raises on an unset `egress_relay_url`, and `RelayEgressClient` raises
`RelayIOPlaneUnavailableError` when it cannot reach the gateway. Note the symmetry is
**nominal, not exact**: the proxy seam raises a typed/audited `IOPlaneUnavailableError`
while the relay assembly raises a bare `ValueError` (`assembly.py:160`). G7-3 records this in
ADR-0042 as an honest residual (a typed `RelayIOPlaneUnavailableError` at the assembly seam
is a #339-era cleanup) and adds no relay enforcement (no live caller until #339).

### 3.3 Flip the compose-invariant tests (`tests/unit/test_compose_invariants.py`)

- Un-skip and de-"deferred"-name `test_alfred_internal_is_internal_true_deferred_to_g7_3`
  (:368) → asserts `networks.alfred_internal.internal is True`.
- Un-skip and de-"deferred"-name `test_core_not_on_external_deferred_to_g7_3` (:435) →
  asserts `alfred_external` not in `alfred-core`'s networks.
- Tighten `test_only_gateway_and_core_on_external` (:418) → the on-external set is now
  exactly `{alfred-gateway}` (the core has left). Keep its generic "any new service on
  external fails" property.
- **Add `test_core_joins_internal_only`** — assert `alfred-core`'s network set is *exactly*
  `== {"alfred_internal"}` (mirroring the datastores' `test_datastores_join_internal_only`),
  **plus** a no-`network_mode` invariant (no service sets `network_mode: host`). The
  existing flips assert core-on-internal (a *subset* check) + core-not-on-external; neither
  catches a future *third* internet-reachable network (or `network_mode: host`) on the core
  silently re-opening egress. The core is the subject of the connectivity-free invariant, so
  it gets the same exact-set treatment the datastores already get (sec-001 / test-002).

### 3.4 Add the missing fail-closed coverage of the egress seam

The originally-planned "fix `test_orchestrator_bootstrap.py` to set `egress_proxy_url`" is a
**no-op**: that test monkeypatches `_bootstrap.build_router` (line 131) before
`build_orchestrator` runs, so the real `build_router → EgressClient.from_settings` is never
executed there (prov-001 / test-003 / sec-004). It needs no change.

Instead, the fail-closed path needs **its own** required-lane unit coverage: a focused
`build_router`-seam test (`tests/unit/...`) asserting both directions —
`egress_proxy_url` unset ⇒ `pytest.raises(IOPlaneUnavailableError)` (and the message names
`ALFRED_EGRESS_PROXY_URL`), and `egress_proxy_url` set ⇒ a proxied client is wired onto the
provider. This is the test that proves the §3.2 deletion actually fails closed; without it
no required check exercises the new raise branch (the `egress/client.py` 100% line+branch
gate covers `EgressClient` in isolation, but the `build_router` wiring needs its own test).

## 4. The connectivity proof (layered; paper-gate-proof)

The G7-0 review flagged the original connectivity-free enforcement as a #243/#245-style
**paper gate** (a kernel test that skips on PR runners protects nothing) and named a DNS
hole (`internal: true` can leave Docker's `127.0.0.11` resolver able to recurse, so a
`connect()`-only test passes while the core DNS-exfils). G7-3's proof has two layers:

### 4.1 Always-on, required (the source/config ratchet)

- The three un-skipped compose-invariant tests (§3.3) — run in the required `python` unit
  lane. They prove the compose file *declares* the isolation.
- The existing non-root AST import-guard (`tests/unit/egress/test_in_core_http_egress_guard.py`)
  — proves no in-core code constructs a direct provider SDK / alt-HTTP / httpx client.

### 4.2 Enforcement-of-record (the kernel actually blocks egress)

A new docker-gated integration test (in the **required `Integration` lane** — confirmed
in `docs/ci/required-checks.md`; `runs-on: ubuntu-latest`, which already runs
testcontainers so the docker daemon is available to the non-root runner — gated
`skipif(docker unavailable)` mirroring the `bwrap`-absent skip of
`test_quarantined_llm_policy_kernel_enforced.py`):

1. Create a throwaway `internal: true` docker network.
2. Run a container on it and assert **both**:
   - a TCP `connect()` to an external IP (e.g. `1.1.1.1:443`) fails (`Network is
     unreachable`), and
   - resolving an external hostname (`getaddrinfo` / `getent hosts`) fails (the DNS hole is
     closed).
3. Assert a sibling container on the same network **is** reachable (we isolate from the
   internet without over-blocking the internal plane).
4. Tear the network + containers down.

**Image + probe mechanics (avoid a flake vector in a required lane):** use an image already
present in the lane (`postgres:16`, which testcontainers pulls) and drive the probes with
shell primitives (`bash`'s `/dev/tcp`, `getent hosts`) rather than pulling an anonymous
`python:3.12-slim` (an extra Docker Hub pull = a rate-limit flake vector on a *required*
check). Pre-pull / reuse so the proof never depends on a fresh anonymous pull
(test-006 / devops-003).

**The skip must not silently pass the gate.** A "loud skip" is still a *green* required
check — exactly the paper-gate the project's own #245 not-skipped guard exists to prevent.
The proof carries a **not-skipped assertion** in the required lane (assert the docker daemon
is present and the proof ran, fail rather than skip when it is absent), mirroring
`integration-privileged`'s #245 guard — not merely a loud skip reason (test-001 / err-002 /
sec-003).

**Honest scope of the DNS-hole claim (sec-002).** `getaddrinfo`-must-fail validates that
*this lane's* docker daemon does not forward its embedded resolver out of an `internal: true`
network (empirically true on OrbStack and the GitHub `ubuntu-latest` daemon). It does **not**
prove every production daemon closes the hole — a differently-configured embedded resolver
could still recurse. ADR-0042 scopes the claim to "the core performs no client-side DNS (the
gateway resolves for both the proxy and the relay) **and** the tested daemons close the
forward path"; a resolver-strip / operator-verify backstop is named as a G7-5 ops residual.

**Why the primitive, not the full stack:** the chain is *(static) `alfred-core` is on
`alfred_internal`-only and `alfred_internal` is `internal: true`* **∧** *(runtime)
`internal: true` blocks egress + DNS while leaving siblings reachable* ⇒ the core cannot
egress. Each link is tested; the runtime test proves Docker's primitive enforces what the
compose file declares, without standing up the heavy bwrap-profile core container in CI.
A full-stack "the real `alfred-core` cannot curl out" assertion is a candidate hardening
for the G7-5 smoke/ops lane (noted, not built here — and not a substitute, since smoke is
opt-in and would be a paper gate on the merge path).

**Empirically verified on the target-class runtime (OrbStack, 2026-06-29):** egress
blocked (`Network is unreachable`), DNS hole closed (`Temporary failure in name
resolution`), siblings resolvable+reachable, host-published port on an internal-only
container refused. The runtime proof therefore reproduces locally on the dev Mac as well
as in Linux CI.

The `Integration` lane — a required status check (`docs/ci/required-checks.md`) — runs the
proof on every PR, and the not-skipped assertion above guarantees it cannot pass
green-because-skipped.

## 5. Tests & quality gates

- **Unit** (`src/alfred/egress/client.py`, in the egress 100% line+branch gate): add
  `from_settings(egress_proxy_url=None)` → raises `IOPlaneUnavailableError` (message names
  `ALFRED_EGRESS_PROXY_URL`); delete the `egress.client.direct` log-assertion and the
  `None`-returns-direct test. Keep coverage at 100% line **and** branch (the deleted
  `None`-branch removes a branch; the new raise adds one).
- **Unit (new) — the `build_router` seam** (§3.4): proxy unset ⇒
  `pytest.raises(IOPlaneUnavailableError)`; proxy set ⇒ a proxied client is wired onto the
  provider. The required-lane proof that the §3.2 deletion fails closed in the wiring, not
  just in `EgressClient` isolation.
- **Settings** (`tests/unit/config/test_settings_egress_proxy_url.py`): the field stays
  optional; the unset-is-fatal behavior is now asserted at the egress seam, not Settings.
  Audit and adjust the test's framing.
- **Compose-invariant**: the three flips + `test_core_joins_internal_only` (exact-set +
  no-`network_mode`) (§3.3).
- **Integration**: the docker-gated egress/DNS proof with the not-skipped assertion (§4.2).
  `test_orchestrator_bootstrap.py` needs **no change** — it monkeypatches `build_router`
  (§3.4).
- **Smoke**: no change. `tests/smoke/test_discord_gateway_smoke.py`'s `127.0.0.1:5432`
  is a placeholder DSN for `Settings.model_validate` (the test only reads adapter status;
  the gateway holds no DB session) — it never dials the compose Postgres, so the flip does
  not affect it. `test_gateway_core_link_smoke.py` already scrapes from *within* the
  compose network (`docker compose exec`). Verified during planning.
- **Adversarial (release-blocking)**: this touches the egress boundary, so the full
  adversarial suite must run green. The existing `sbx_2026_005` /
  `test_quarantined_llm_not_yet_spawned_while_egress_open` gates stay green and are **not**
  weakened.
- **`make check`** before every push; full `/review-pr` fleet (security ALWAYS) +
  CodeRabbit (both); resolve every thread; UAT; plain `gh pr merge --rebase` (never
  `--admin`).

## 6. ADR & docs

- **New ADR-0042 — "connectivity-free-core cutover."** Records: the atomic-flip decision
  (and why one PR over a guarded sequence); the macOS/OrbStack host-port consequence and
  the keep-the-port decision; the DNS-hole-closed finding **scoped to the tested daemons**
  (sec-002) plus the no-client-side-DNS invariant; the layered-proof strategy (static
  required, docker-gated runtime, not-skipped assertion — paper-gate avoidance); the
  now-nominal proxy/relay fail-closed symmetry and the bare-`ValueError` relay residual; the **runtime
  reality** that the fallback deletion is a fail-closed *seam* (the live enforcement is the
  kernel isolation) with the #338/#339 boot-boundary catch as a recorded hand-off; that the
  cutover **preserves the ADR-0036 cred-concentration invariant** (the gateway still holds
  no vault key; the Proxy-Authorization upgrade is a future add); and the **lag** that PRD
  §5/§7.1 + ADR-0040 are realized-in-code here but their prose update is human-gated to G7-5
  (forward-reference it so the gap is tracked, not reconstructed — arch-002 / sec-007). ADRs
  are agent-authorable (unlike CLAUDE.md/PRD.md); ADR-0040 stays reserved for the
  comprehensive G7-5 egress ADR; ADR-0041 is taken.
- **Factual amendments** to any ADR that still describes the core's direct-egress fallback
  as live (e.g. the G7-1 fallback note) — mark it deleted as of G7-3 (the dated factual
  amendment precedent from G7-1a/2b; status flips stay human-gated).
- **Operator-facing doc sweep** (the §3.1/§3.2 stale-doc surfaces, gathered here for the
  doc-author): `.env.example:54-56`, the `docker-compose.yaml:165-167` inline comment, and
  the `client.py` docstring — all must drop the "unset ⇒ direct egress" model.
- **Runbook / README**: document (a) the macOS host-tooling limitation — host `psql` →
  compose-Postgres now needs Linux or a one-off `docker compose exec alfred-postgres
  psql …`; the dev test loop (testcontainers) and the daemon (internal network) are
  unaffected; and (b) that a set `ALFRED_ANTHROPIC_BASE_URL` / `ALFRED_DEEPSEEK_BASE_URL`
  override must be on the gateway's allowlist or the now-mandatory proxy hard-fails the call
  (prov-004; the known arch-002 safe-fail/deny).

## 7. Risk & rollback

- **Risk:** a deployment that forgets `ALFRED_EGRESS_PROXY_URL`. Today this is fail-closed
  by the kernel isolation (any direct provider dial hits `Network is unreachable`); once the
  orchestrator is wired into boot (#338/#339) the egress seam refuses at the boot boundary
  (audited `_refuse_boot`). Either way it is *never* a silent direct hop. Compose ships the
  default, and the error `detail` names the missing variable.
- **Risk:** a Linux host that genuinely needs host-side Postgres access is unaffected
  (published ports still NAT); a Mac host loses `localhost:5432` (documented; use
  `docker compose exec`).
- **Rollback:** revert the single PR — the atomicity that makes the cutover safe also
  makes the rollback a clean single-commit revert (restores both the external route and
  the fallback together).

## 8. PR shape

**One PR** (`spec-c-g7-3-connectivity-free-core`). Suggested commit sequence (TDD,
isolation-test-first so no commit lands an unguarded window):

1. ADR-0042 + the spec.
2. `client.py` fail-closed (RED: the new `EgressClient.from_settings` raise test + the
   `build_router`-seam test, then GREEN) + unit-test updates + the `client.py` docstring /
   `proxy_url` property / limits-marker sweep.
3. Compose flip (`internal: true`, core off `alfred_external`, `depends_on: alfred-gateway`),
   the three un-skipped/tightened compose-invariant tests, and the new
   `test_core_joins_internal_only` (exact-set + no-`network_mode`).
4. The docker-gated runtime egress/DNS proof (with the #245-style not-skipped assertion,
   `postgres:16` + shell-primitive probes).
5. Operator-doc sweep (`.env.example`, compose inline comment) + runbook/README + ADR
   factual amendments.

`writing-plans` sequences and details each task.

## 9. References

- Spec C design: `docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md`
  (§3 topology, §7 connectivity-free enforcement, §11 decomposition).
- G7-2.5 design: `docs/superpowers/specs/2026-06-28-g7-2.5-web-fetch-rehome-design.md`.
- The fallback marker: `src/alfred/egress/client.py:49` (`# G7-3: DELETE this …`).
- The deferred invariant tests: `tests/unit/test_compose_invariants.py:368`, `:435`,
  `:418`.
- The kernel-test gating precedent:
  `tests/integration/test_quarantined_llm_policy_kernel_enforced.py`.
- HARD rule #9 (egress): `CLAUDE.md` "Security rules — HARD".
