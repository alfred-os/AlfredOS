# G6-1 — Gateway Privilege Reframe (Spec B / G6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the Spec B privilege reframe in isolation — author ADR-0036, grant the always-up `alfred-gateway` Compose service `cap_add: SETUID` + the `#290` AppArmor/seccomp sandbox profiles (the capability to spawn bwrap-sandboxed adapter children), and reconcile the `devops-010` compose-invariant tests to a positive allowed-SETUID-set — with **no adapter-hosting code** (that arrives in G6-2).

**Architecture:** All three Compose services (`alfred-core`, `alfred-discord`, `alfred-gateway`) already build from the single `docker/alfred-core.Dockerfile`, which already carries bubblewrap + the launcher + `jq` + the PBS interpreter (shipped for the core's quarantine child in `#290`). So the *image* already has the launcher; G6-1 only flips the gateway **Compose service** from "stable, low-privilege relay" to "stable-code, privileged" by adding `cap_add: SETUID` and the same `security_opt` AppArmor/seccomp pair the core uses — plus ADR-0036 recording the maintainer-co-signed (2026-06-18) decision, and the `devops-010` test reframe. No `src/` changes; no `GatewayAdapterSupervisor`. The privilege is granted but dormant until G6-2 hosts an adapter.

**Tech Stack:** Docker Compose, pytest, PyYAML, Markdown (ADR).

---

## Scope & non-scope

- **In:** ADR-0036 (records Spec B decisions 2–5 + §5 credential-during-outage + §6 trust posture + adversarial corpus + the captured maintainer security co-sign); annotate ADR-0031/0032/0033/0015/0030; add `cap_add: SETUID` + `security_opt` (apparmor=alfred-bwrap, seccomp=docker/seccomp/alfred-bwrap.json) to the `alfred-gateway` Compose service; reframe `tests/unit/test_compose_invariants.py` to a positive allowed-SETUID-set `== {alfred-core, alfred-gateway}` + add `gateway-has-no-state_git`; flip `test_alfred_gateway_has_no_setuid` → has-SETUID.
- **Out:** `GatewayAdapterSupervisor` / `GatewayAdapterCredentialClient` / ingress gate / any `src/alfred/gateway/` hosting code (G6-2+); credential `spawn_request`/`spawn_grant` (G6-3); the Discord flag-day + `alfred-discord` service removal (G6-5). `alfred-discord` STAYS in this PR and MUST still carry no SETUID / no state_git.
- **Verify-only invariant (no code change):** the gateway's image already has bubblewrap/launcher (shared Dockerfile); G6-1 does not modify `docker/alfred-core.Dockerfile`.

---

## File structure

- Create: `docs/adr/0036-gateway-adapter-hosting-inversion.md` — the human-gated ADR recording the locked, co-signed Spec B decisions.
- Modify: `docs/adr/0031-*.md`, `0032-*.md`, `0033-*.md`, `0015-*.md`, `0030-*.md` — one-line annotation each (the gateway is now a second launcher host / privileged tier), do NOT rewrite.
- Modify: `docker-compose.yaml` — add `cap_add: [SETUID]` + `security_opt` (apparmor/seccomp) to the `alfred-gateway` service.
- Modify: `tests/unit/test_compose_invariants.py` — positive allowed-SETUID-set; flip the gateway-no-SETUID test; add gateway-no-state_git; keep the discord-no-SETUID / no-state_git asserts (discord still exists until G6-5).

---

## Task 1: Author ADR-0036 (the human-gated, co-signed record)

**Files:**

- Create: `docs/adr/0036-gateway-adapter-hosting-inversion.md`

- [ ] **Step 1: Read an existing ADR for the house format.** Read `docs/adr/0035-lifecycle-start-credentials-optional.md` and `docs/adr/0037-production-quarantine-sandbox-boundary.md` to match the exact heading structure (Status / Context / Decision / Consequences / Alternatives), front-matter, and the security-co-sign annotation style used in 0037.

- [ ] **Step 2: Write `docs/adr/0036-gateway-adapter-hosting-inversion.md`.** It must record (sourced verbatim-in-substance from the spec `docs/superpowers/specs/2026-06-18-spec-b-adapter-inversion-design.md` §2, §5, §6, §8 — do NOT invent new decisions):
  - **Status:** Accepted — security co-sign captured 2026-06-18 (maintainer, during the Spec B design session). State explicitly that this ADR *records* a captured co-sign; it does not request a new one.
  - **Context:** the daemon-spawned adapter model breaks platform-session resume across a core restart; the always-up tier must own adapter spawn (decision 2: full gateway-local lifecycle, core observes via audited status notifications, core never issues lifecycle *directives* but does provide the spawn credential).
  - **Decision (privilege reframe — decision 3):** the gateway gains `cap_add: SETUID` + bubblewrap + the launcher, reframed from "dumb/stable/low-privilege" to "stable-code, privileged"; a single privileged always-up host rather than a separate spawner sidecar. Include the `devops-010` reconciliation (positive allowed-SETUID-set `== {alfred-core, alfred-gateway}`; adapters never get SETUID/state_git; the gateway never mounts state_git).
  - **Credential contract (decision 4 / §5):** core-injects-at-spawn realized as **fd-3 transient delivery** (`spawn_request`/`spawn_grant`, epoch-bound, dedup-keyed); plaintext transits the gateway transiently, written to the child fd-3, zeroed-after-write; never env, never cached, never a vault key; the B-achievable testable invariant; the credential-during-core-outage default (await-core, loud+bounded+terminal-ceiling) + the rejected cache-in-MADV_DONTDUMP overturn; deferred-to-C SCM_RIGHTS fd-pass.
  - **Ingress (decision 5):** coarse two-tier per-adapter payload-blind gate; the explicit comms-F2 overturn; the core `_PreResolutionLimiter` is additive defense-in-depth, not weakened.
  - **Honest scope (§6):** the gateway transits plaintext credentials at spawn (payload-blind = message bodies, not cred control frames); a **compromised gateway can serially harvest** every platform credential via legitimate grants — bounded by per-adapter bwrap+netns+scrubbed-env+fd-3-transient+no-vault-key, NOT by process count; closed by Spec C (connectivity-free core + core→child fd-pass). Record the adversarial corpus (a–g; b/c/e/f release-blocking).
  - **Alternatives considered & rejected:** separate spawner sidecar (same trust tier, added IPC, marginal isolation); rootless bwrap via unprivileged userns / no SETUID (rejected — global sandbox-model change, out of scope; AlfredOS deliberately chose the privileged-launcher model for hardened hosts where unprivileged userns is disabled).
  - **Consequences:** concentration acknowledged; per-PR adversarial gating; the G6-2…G6-6 epic that realizes it. **Dormant-privilege window** `[security plan-review]`: G6-1 grants the SETUID capability + sandbox profiles to the network-facing gateway BEFORE the hosting code (G6-2) uses it, so for the G6-1→G6-2 window the gateway is privileged but spawns nothing — acknowledge this is an accepted, bounded ordering (the capability is inert without the supervisor; the alternative, granting it atomically with hosting, couples the security co-sign to a larger PR and was rejected for reviewability). **Operator deployment hazard** `[devops plan-review]`: the gateway now requires the `alfred-bwrap` AppArmor profile loaded on the host (same named profile alfred-core already needs) — on an AppArmor host that has not run `bin/alfred-setup.sh`, Docker will refuse to create the gateway container. The same profile-preload note already exists in the README for alfred-core (#290); G6-5's migration runbook owns the operator-facing restatement. No new CI gate breaks (the live-compose gateway smokes are `@pytest.mark.skip`; merge-gating gateway tests run in-process).

- [ ] **Step 3: Verify ADR cross-references resolve.** Run `uv run python -c "import re,sys,pathlib; ..."` is overkill; instead grep that the referenced ADRs exist:
  Run: `for n in 0015 0030 0031 0032 0033 0037; do ls docs/adr/${n}-*.md >/dev/null && echo "OK $n" || echo "MISSING $n"; done`
  Expected: all `OK`.

- [ ] **Step 4: markdownlint the ADR.** Run: `npx --yes markdownlint-cli2@0.14.0 "docs/adr/0036-gateway-adapter-hosting-inversion.md"`
  Expected: `Summary: 0 error(s)` (emphasis = underscore; lists surrounded by blank lines; fences surrounded by blank lines — the repo `.markdownlint-cli2.jsonc` rules).

- [ ] **Step 5: Commit:**

```bash
git add docs/adr/0036-gateway-adapter-hosting-inversion.md
git commit -m "docs(adr): ADR-0036 gateway adapter-hosting inversion + privilege reframe (Spec B G6-1)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

(The commit subject MUST contain a `#`-issue ref to pass the conventional-commit gate `^[a-z]+(\([^)]+\))?(!)?: .*#[0-9]+.*$` — replace with the real epic issue number at commit time, e.g. `(#288)` if Spec B's epic issue is #288, or the G6 tracking issue. Confirm the issue number with `gh issue list --search "Spec B" --state open` before committing.)

---

## Task 2: Annotate the affected prior ADRs (do not rewrite)

**Files:**

- Modify: `docs/adr/0031-*.md`, `0032-*.md`, `0033-*.md`, `0015-*.md`, `0030-*.md`

- [ ] **Step 1: Add a one-line forward-annotation to each.** For each ADR add a single line under its Status/Context (match the file's existing annotation style — grep each for an existing "See ADR-" or "Superseded/Amended by" line first). The annotations:
  - `0031` (socket transport): "Spec B G6-1 (ADR-0036): the gateway becomes a privileged adapter-hosting tier in addition to the socket relay."
  - `0032` / `0033` (Spec A wire / lifecycle): "Spec B (ADR-0036) reuses this wire/lifecycle for the gateway-hosted adapter legs + the spawn-credential control frames."
  - `0015` / `0030` (launcher / sandbox): "Spec B G6-1 (ADR-0036): the gateway is now a SECOND launcher/bwrap host (in addition to alfred-core), with `cap_add: SETUID` + the alfred-bwrap AppArmor/seccomp profiles."

- [ ] **Step 2: markdownlint the five touched ADRs.** Run: `npx --yes markdownlint-cli2@0.14.0 "docs/adr/0015-*.md" "docs/adr/0030-*.md" "docs/adr/0031-*.md" "docs/adr/0032-*.md" "docs/adr/0033-*.md"`
  Expected: `Summary: 0 error(s)`.

- [ ] **Step 3: Verify the docs link/anchor checker is unaffected.** Run: `uv run python scripts/check_docs_links.py 2>/dev/null || echo "no such script — skip"` (the CI gate is "Docs link + anchor check"; locate its actual entrypoint in `.github/workflows/` if the path differs and run that).

- [ ] **Step 4: Commit:**

```bash
git add docs/adr/0015-*.md docs/adr/0030-*.md docs/adr/0031-*.md docs/adr/0032-*.md docs/adr/0033-*.md
git commit -m "docs(adr): annotate launcher/socket/wire ADRs for the gateway privilege reframe (Spec B G6-1, #288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: devops-010 reframe — positive allowed-SETUID-set (TDD)

**Files:**

- Test: `tests/unit/test_compose_invariants.py`
- Modify: `docker-compose.yaml`

- [ ] **Step 1: Write the failing/updated invariant tests.** In `tests/unit/test_compose_invariants.py`:

  Add a positive allowed-set invariant (the devops-010 reframe):

```python
def test_setuid_allowed_set_is_core_and_gateway(compose: dict[str, Any]) -> None:
    """G6-1 (ADR-0036): cap_add SETUID is granted to EXACTLY {alfred-core, alfred-gateway}.

    The positive allowed-set is the devops-010 reframe: rather than asserting each service
    individually, pin the whole set so a NEW service silently gaining SETUID fails loud, and
    so the privilege concentration is auditable in one place. Adapters never get SETUID.
    """
    services = compose.get("services", {})
    with_setuid = {
        name
        for name, svc in services.items()
        if "SETUID" in (svc.get("cap_add", []) or [])
    }
    assert with_setuid == {"alfred-core", "alfred-gateway"}, (
        f"SETUID must be granted to exactly {{alfred-core, alfred-gateway}}; got {with_setuid}."
    )
```

  FLIP the existing `test_alfred_gateway_has_no_setuid` to assert the gateway now HAS SETUID + the sandbox profiles:

```python
def test_alfred_gateway_has_setuid_and_sandbox_profiles(compose: dict[str, Any]) -> None:
    """G6-1 (ADR-0036): the gateway gains SETUID + the alfred-bwrap AppArmor/seccomp profiles
    so it can spawn bwrap-sandboxed adapter children (capability granted; hosting lands G6-2)."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    assert "SETUID" in (gw.get("cap_add", []) or []), (
        "alfred-gateway must have cap_add: SETUID in G6-1 (ADR-0036) to host bwrap adapters."
    )
    security_opt = gw.get("security_opt", []) or []
    assert "apparmor=alfred-bwrap" in security_opt
    assert "seccomp=docker/seccomp/alfred-bwrap.json" in security_opt
```

  REFRAME `test_bwrap_security_opt_scoped_to_core` (currently at `tests/unit/test_compose_invariants.py:135-151`) — THIS IS THE UNANIMOUS PLAN-REVIEW CRITICAL (architect/security/devops/test-engineer all caught it). It currently loops over `("alfred-discord", "alfred-gateway")` asserting NEITHER carries the `alfred-bwrap` profiles; Task 3's compose edit adds exactly those profiles to the gateway, so it WILL fail. Convert it to a positive bwrap-profile allowed-set (mirrors the SETUID positive-set), keep the discord negative, and rewrite the now-false docstring:

```python
def test_bwrap_security_opt_set_is_core_and_gateway(compose: dict[str, Any]) -> None:
    """G6-1 (ADR-0036): the alfred-bwrap AppArmor/seccomp profiles are carried by EXACTLY
    {alfred-core, alfred-gateway} — the two bwrap-spawning hosts. alfred-core spawns the
    quarantine child (#290); the gateway spawns bwrap adapter children (capability granted in
    G6-1, used in G6-2). Adapters (alfred-discord) must NEVER carry them — an adapter that could
    build the userns sandbox could impersonate the quarantine UID (see test_alfred_discord_has_no_setuid).
    """
    services = compose.get("services", {})
    with_bwrap_profiles = {
        name
        for name, svc in services.items()
        if any("alfred-bwrap" in entry for entry in (svc.get("security_opt", []) or []))
    }
    assert with_bwrap_profiles == {"alfred-core", "alfred-gateway"}, (
        f"the alfred-bwrap profiles must be scoped to exactly {{alfred-core, alfred-gateway}}; "
        f"got {with_bwrap_profiles}. Adapters must never carry them (#290 / ADR-0036)."
    )
```

  (Delete the old `test_bwrap_security_opt_scoped_to_core`; this positive-set replaces it AND closes the symmetric-guard gap test-engineer flagged.)

  `test_alfred_gateway_has_no_state_git_volume` ALREADY EXISTS (at `tests/unit/test_compose_invariants.py:221`) `[architect plan-review]` — do NOT add a duplicate. Confirm it still PASSES after the compose edit (the gateway gains no state_git mount in G6-1); leave it unchanged.

  KEEP `test_alfred_discord_has_no_setuid`, `test_alfred_discord_has_no_state_git_volume`, `test_alfred_core_has_setuid`, `test_alfred_core_has_state_git_volume`, `test_alfred_core_is_not_privileged`, `test_alfred_core_has_no_unconfined_security_opt` unchanged (discord still exists until G6-5; the positive-set tests subsume but do not replace the discord negative until the service is removed). DELETE the old `test_alfred_gateway_has_no_setuid` (superseded by the flip above) — and confirm no other test still asserts gateway-has-no-SETUID or gateway-lacks-bwrap-profiles.

- [ ] **Step 2: Run → new/flipped tests FAIL** (gateway has no SETUID/profiles yet). Run: `uv run pytest tests/unit/test_compose_invariants.py -q`
  Expected: `test_setuid_allowed_set_is_core_and_gateway`, `test_alfred_gateway_has_setuid_and_sandbox_profiles`, and the reframed `test_bwrap_security_opt_set_is_core_and_gateway` FAIL; the discord/core negatives + `test_alfred_gateway_has_no_state_git_volume` pass.

- [ ] **Step 3: Edit `docker-compose.yaml`** — in the `alfred-gateway` service add `cap_add` + `security_opt` mirroring `alfred-core`'s (same named AppArmor profile + the repo-relative seccomp path). Add a comment block keyed to G6-1/ADR-0036 explaining the gateway is now a second privileged launcher host (capability granted; hosting in G6-2). Example shape (preserve the existing gateway keys — build/command/healthcheck/depends_on/alfred_run volume):

```yaml
  alfred-gateway:
    build:
      context: .
      dockerfile: docker/alfred-core.Dockerfile
    command: ["gateway", "start"]
    # Spec B G6-1 (ADR-0036): the gateway is reframed to a privileged adapter-hosting tier.
    # It gains SETUID + the alfred-bwrap AppArmor/seccomp profiles so it CAN spawn bwrap-
    # sandboxed adapter children — the capability is granted here; the GatewayAdapterSupervisor
    # that uses it lands in G6-2. The gateway still mounts NO alfred_state_git (grant store
    # stays core-only). Profiles must be loaded on the host first (bin/alfred-setup.sh /
    # nightly already load the same named alfred-bwrap profile for alfred-core; it is host-
    # global once loaded — no new load step).
    cap_add:
      - SETUID
    security_opt:
      - "apparmor=alfred-bwrap"
      - "seccomp=docker/seccomp/alfred-bwrap.json"
      # ... (KEEP the existing depends_on / healthcheck / environment / alfred_run volume) ...
```

- [ ] **Step 4: Run invariants + compose validity.** Run: `uv run pytest tests/unit/test_compose_invariants.py -q` (all pass) and `docker compose config --quiet && echo OK`.

- [ ] **Step 5: Commit:**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "feat(compose): grant alfred-gateway SETUID + bwrap profiles; positive allowed-SETUID-set (Spec B G6-1, #288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Full local gate

- [ ] **Step 1:** `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pytest tests/unit -q` — all green; fix any G6-1-introduced finding (report unrelated pre-existing failures, don't fix).
- [ ] **Step 2:** `docker compose config --quiet && echo OK`.
- [ ] **Step 3:** markdownlint parity for the committed tree (the markdown-lint gate lints the whole committed checkout): export the committed tree + run `npx --yes markdownlint-cli2@0.14.0 "**/*.md" "!LICENSE" "!node_modules/**"` and confirm `Summary: 0 error(s)` (gitignored/untracked local files are absent in CI; only the committed ADRs matter).
- [ ] **Step 4:** Confirm the catalog drift gate is unaffected — G6-1 adds NO operator-facing `t()` strings (ADR + compose + tests only). If any slipped in, run the pybabel extract/update/compile + `--check`.
- [ ] **Step 5:** No commit (verification only); the per-task commits stand.

---

## Self-review

**Spec coverage (spec §9 G6-1 row):** ADR-0036 → Task 1. devops-010 reframe (positive SETUID allowed-set; positive bwrap-profile allowed-set [the unanimous plan-review Critical]; flip gateway-no-SETUID; verify the pre-existing gateway-no-state_git) → Task 3. Gateway image gains bubblewrap/launcher/SETUID → the image ALREADY has bubblewrap/launcher (shared `docker/alfred-core.Dockerfile`); G6-1 grants the SETUID *capability* + sandbox profiles to the gateway COMPOSE service (Task 3); "no hosting yet" → confirmed (no `src/alfred/gateway/` change, no supervisor). Annotate prior ADRs → Task 2. Security co-sign → captured 2026-06-18, *recorded* (not re-requested) in ADR-0036 Status. Dormant-privilege window + operator profile-preload hazard → recorded in ADR-0036 Consequences.

**Plan-review incorporated (2026-06-19, architect/security/devops/test-engineer):** the unanimous Critical/High — Task 3 must REFRAME the existing `test_bwrap_security_opt_scoped_to_core` (else the compose edit lands a red suite) — is now Task 3 Step 1. The architect's duplicate-function catch (`test_alfred_gateway_has_no_state_git_volume` already exists) is resolved (verify, don't add). The security/devops dormant-privilege + profile-preload notes are in ADR-0036 Consequences.

**Placeholder scan:** the only deferred decision is the real epic-issue number in the commit subjects (Task 1 Step 5 / Task 2 / Task 3) — bounded (`gh issue list` resolves it), not a content placeholder. All test code + the compose diff are concrete.

**Type/name consistency:** `cap_add: [SETUID]` / `security_opt: [apparmor=alfred-bwrap, seccomp=docker/seccomp/alfred-bwrap.json]` identical to the shipped `alfred-core` service. The positive-set `{"alfred-core", "alfred-gateway"}` matches the service names exactly. `_volume_strings` + `.split(":",1)[0]` exact-source-match mirrors the G6-0b `alfred_run` invariant convention.

**Trust-boundary note for the reviewer + plan-review:** this PR EXPANDS the gateway's privilege (network-facing process gains SETUID). It is a maintainer-co-signed (2026-06-18), spec-locked decision recorded in ADR-0036 — NOT a new self-granted approval. The review-pr fleet (security always) + the adversarial suite still apply. The privilege is dormant (no hosting code) until G6-2.
