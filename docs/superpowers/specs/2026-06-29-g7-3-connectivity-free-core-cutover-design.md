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
- The stale `# G7-3 removes this line` / `# The ISOLATION FLIP is a single atomic step at
  G7-3` comments are rewritten to describe the realized end-state.

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
  `httpx.AsyncClient`, no longer `| None`).
- `Settings.egress_proxy_url` **stays** `str | None` (a dumb config holder; the blank→None
  validator is unchanged). The invariant — "None is fatal" — lives at the egress seam, not
  in Settings.
- Net runtime effect: `build_router` (reached only by `daemon start`'s orchestrator and
  `alfred chat`) refuse-boots without the proxy URL. Non-egress CLI paths (`status`,
  `user`, `migrate`, `login`) never build a router, so they are unaffected. Compose always
  sets the proxy URL (default `http://alfred-gateway:8889`), so the deployed stack boots
  normally.
- The error message reuses the existing `egress.io_plane_unavailable` i18n key
  (detail-driven); no new catalog key. The deleted `egress.client.direct` is a structlog
  event, not a `t()` string.

The **tool-egress relay** path needs no code change: `build_web_fetch_egress_extractor`
already raises on an unset `egress_relay_url`, and `RelayEgressClient` raises
`RelayIOPlaneUnavailableError` when it cannot reach the gateway. G7-3 records this symmetry
in ADR-0042 but adds no enforcement (no live caller until #339).

### 3.3 Flip the compose-invariant tests (`tests/unit/test_compose_invariants.py`)

- Un-skip and de-"deferred"-name `test_alfred_internal_is_internal_true_deferred_to_g7_3`
  (:368) → asserts `networks.alfred_internal.internal is True`.
- Un-skip and de-"deferred"-name `test_core_not_on_external_deferred_to_g7_3` (:435) →
  asserts `alfred_external` not in `alfred-core`'s networks.
- Tighten `test_only_gateway_and_core_on_external` (:418) → the on-external set is now
  exactly `{alfred-gateway}` (the core has left). Keep its generic "any new service on
  external fails" property.

### 3.4 Update the one affected integration test

`tests/integration/test_orchestrator_bootstrap.py` builds a router; it must set
`egress_proxy_url` (env or Settings) so the now-mandatory proxy URL is present. Verified
during planning that this is the only `build_router` caller outside production wiring.

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
2. Run a minimal container on it and assert **both**:
   - `socket.connect()` to an external IP (e.g. `1.1.1.1:443`) fails (`Network is
     unreachable`), and
   - `socket.getaddrinfo()` of an external hostname fails (the DNS hole is closed).
3. Assert a sibling container on the same network **is** reachable (we isolate from the
   internet without over-blocking the internal plane).
4. Tear the network + containers down.

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

The skip must be **loud** (a clear skip reason naming "docker unavailable") so a runner
without docker cannot silently mask a containment regression, and the `Integration` lane —
a required status check (`docs/ci/required-checks.md`) — runs it on every PR.

## 5. Tests & quality gates

- **Unit** (`src/alfred/egress/client.py`, in the egress 100% line+branch gate): add
  `from_settings(egress_proxy_url=None)` → raises `IOPlaneUnavailableError`; delete the
  `egress.client.direct` log-assertion and the `None`-returns-direct test. Keep coverage
  at 100% line **and** branch (the deleted `None`-branch removes a branch; the new raise
  adds one).
- **Settings** (`tests/unit/config/test_settings_egress_proxy_url.py`): the field stays
  optional; the unset-is-fatal behavior is now asserted at the egress seam, not Settings.
  Audit and adjust the test's framing.
- **Compose-invariant**: the three flips (§3.3).
- **Integration**: the docker-gated egress/DNS proof (§4.2); the
  `test_orchestrator_bootstrap.py` fix (§3.4).
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
  the keep-the-port decision; the DNS-hole-closed finding; the layered-proof strategy
  (static required + docker-gated runtime, paper-gate avoidance); and the now-true
  relay/proxy fail-closed symmetry. ADRs are agent-authorable (unlike CLAUDE.md/PRD.md);
  ADR-0040 stays reserved for the comprehensive G7-5 egress ADR; ADR-0041 is taken.
- **Factual amendments** to any ADR that still describes the core's direct-egress fallback
  as live (e.g. the G7-1 fallback note) — mark it deleted as of G7-3 (the dated factual
  amendment precedent from G7-1a/2b; status flips stay human-gated).
- **Runbook / README**: document the macOS host-tooling limitation — host `psql` →
  compose-Postgres now needs Linux or a one-off `docker compose exec alfred-postgres
  psql …`; the dev test loop (testcontainers) and the daemon (internal network) are
  unaffected.

## 7. Risk & rollback

- **Risk:** a deployment that forgets `ALFRED_EGRESS_PROXY_URL` now refuse-boots the
  daemon (vs. silently egressing direct). This is the *intended* fail-closed posture;
  compose ships the default, and the boot error names the missing variable.
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
2. `client.py` fail-closed (RED: the new raise test, then GREEN) + unit-test updates.
3. Compose flip + the three un-skipped/tightened compose-invariant tests + the
   `test_orchestrator_bootstrap.py` fix.
4. The docker-gated runtime egress/DNS proof.
5. Smoke-test repoint (if needed) + runbook/README + ADR factual amendments.

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
