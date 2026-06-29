# G7-3 Connectivity-Free-Core Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `alfred-core` connectivity-free — kernel-isolated (`internal: true`, off `alfred_external`) AND with its provider-proxy direct-egress fallback deleted — as one atomic PR, proven by a layered static+runtime gate.

**Architecture:** Two coupled edits ship together so no commit leaves a half-isolated/half-fallback window: (1) the compose isolation flip, (2) the `EgressClient` fail-closed deletion. Within one PR either commit order is safe — each enforcement layer is independently fail-closed-or-inert (an isolated core's direct fallback is dead-by-kernel; a fail-closed seam on a still-routable core has no bypass). Proof is layered: the always-on required static ratchet (compose-invariant tests + the existing import-guard) plus a docker-gated runtime egress/DNS proof in the required `Integration` lane with a #245-style not-skipped guard.

**Tech Stack:** Python 3.12+, pytest, Pydantic v2 Settings, httpx, Docker Compose, GitHub Actions, structlog. The runtime proof drives the `docker` CLI via `subprocess`.

## Global Constraints

- **Atomic cutover:** the compose isolation flip and the fallback deletion ship in **one PR**. Never isolate while a fallback exists; never delete the fallback while still routable.
- **Fail-closed:** a missing/empty `ALFRED_EGRESS_PROXY_URL` raises `IOPlaneUnavailableError`; never a silent direct hop.
- **HARD rule #9:** the gateway is the sole external egress plane; the core is connectivity-free.
- **Trust-boundary coverage:** `src/alfred/egress/client.py` stays at **100% line + branch** in the egress coverage gate (`ci.yml` `python` job + `coverage-gates` job).
- **No paper gates:** the runtime kernel proof must RUN (not skip) in a required lane — assert not-skipped, do not merely skip-loud.
- **Docs are English-only; `t()` for operator strings;** reuse the existing `egress.io_plane_unavailable` key (no new catalog key in this PR).
- **`make check` before every push.** Local: `export DOCKER_HOST=unix:///Users/iandominey/.orbstack/run/docker.sock` for testcontainers/docker-driven tests. Conventional Commits. Never `--no-verify`. Never `--admin` merge.
- **Out of scope:** G7-4 (Discord L7-proxy), G7-5 (PRD §5/§7.1, ADR-0040, ops, operator CLI), #338/#339/#340. ADR-0040 stays reserved. Editing `CLAUDE.md`/`PRD.md` is human-gated.

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `docs/adr/0042-connectivity-free-core-cutover.md` | The decision record | 1 |
| `src/alfred/egress/client.py` | Fail-closed seam (raise on unset; always-proxied client; type-tighten; doc/limits sweep) | 2 |
| `tests/unit/egress/test_egress_client.py` | Unit coverage of the seam (raise + proxied) | 2 |
| `tests/unit/cli/test_bootstrap_build_router_egress.py` | Required-lane coverage that the wiring fails closed | 3 |
| `docker-compose.yaml` | `internal: true`, core off `alfred_external`, `depends_on: alfred-gateway`, inline-comment sweep | 4 |
| `tests/unit/test_compose_invariants.py` | Static ratchet: un-skip + tighten + exact-set + no-host-net + depends_on | 4 |
| `tests/integration/egress/test_core_network_isolation_kernel.py` | Runtime egress/DNS kernel proof | 5 |
| `.github/workflows/ci.yml` | #245 not-skipped guard for the runtime proof | 6 |
| `.env.example` | Operator-doc sweep (drop the "unset ⇒ direct" model) | 7 |
| `docs/runbooks/*.md` / `README.md` | macOS host-port limitation + mandatory-proxy notes | 7 |

---

## Task 1: ADR-0042 — connectivity-free-core cutover

**Files:**

- Create: `docs/adr/0042-connectivity-free-core-cutover.md`

**Interfaces:**

- Consumes: nothing.
- Produces: the decision record the rest of the PR (and ADR factual-amendment grep in Task 7) references.

- [ ] **Step 1: Write the ADR**

Create `docs/adr/0042-connectivity-free-core-cutover.md`:

```markdown
# ADR-0042 — Connectivity-free-core cutover

- **Status**: Proposed (accepted on G7-3 merge)
- **Date**: 2026-06-29
- **Slice**: Spec C — G7-3 connectivity-free-core cutover (`docs/superpowers/specs/2026-06-29-g7-3-connectivity-free-core-cutover-design.md`)
- **Relates to**: ADR-0040 (reserved — comprehensive Spec-C egress ADR, G7-5),
  [ADR-0036](0036-gateway-adapter-hosting-inversion.md) (gateway holds no vault key),
  ADR-0041 (web.fetch fused fetch+extract),
  epic [#333](https://github.com/alfred-os/AlfredOS/issues/333),
  issues [#338](https://github.com/alfred-os/AlfredOS/issues/338) / [#339](https://github.com/alfred-os/AlfredOS/issues/339) (orchestrator boot-wiring — the live boot-boundary refusal hand-off)
- **Supersedes**: —

## Context

G7-0..G7-2.5 built the connectivity-free-core machinery (two-network compose topology, the
in-core `EgressClient` proxy seam, the gateway L7 proxy + tool-egress relay) but left the
core internet-reachable: `alfred_internal` was not `internal: true`, `alfred-core` was still
on `alfred_external`, and `EgressClient` retained a direct-egress fallback (unset
`ALFRED_EGRESS_PROXY_URL` ⇒ providers build their own un-proxied httpx client). This ADR
records the atomic cutover.

## Decision

1. **Atomic flip, one PR.** Add `internal: true` to `alfred_internal` AND remove
   `alfred_external` from `alfred-core` AND delete the provider-proxy direct-egress fallback,
   together. The invariant — never isolate while a fallback exists; never delete the fallback
   while still routable — is load-bearing; a guarded sequence would re-introduce the window.
   This is the deliberate exception to the "small PRs" rule.
2. **Fail-closed.** A missing/empty `ALFRED_EGRESS_PROXY_URL` raises `IOPlaneUnavailableError`
   at the `EgressClient` seam, never a silent direct hop.
3. **Kernel isolation is the enforcement-of-record.** `internal: true` is the primary control;
   the userspace forward-proxy allowlist and the AST import-guard are independent
   defense-in-depth. The import-guard covers only the httpx/SDK vector — `subprocess`,
   `urllib.request`, `http.client`, and raw `socket` are exempt by design, so the kernel
   block is the *sole* control for those residual vectors.
4. **Layered, paper-gate-proof proof.** Static (un-skipped compose-invariant tests +
   import-guard, always required) plus a docker-gated runtime egress/DNS proof in the required
   `Integration` lane, carrying a #245-style not-skipped assertion (a loud skip is still a
   green required check).

## Consequences

- **macOS/OrbStack host-port loss.** An `internal: true` container's host-published port is
  not forwarded on OrbStack/Docker-Desktop (verified 2026-06-29); `alfred-postgres`'s
  `5432:5432` keeps working on Linux but is unreachable from a Mac host. We keep the port and
  document the limitation; the compose-internal core (over `alfred_internal`) and the dev test
  loop (testcontainers) are unaffected.
- **DNS-hole closure is daemon-scoped.** The runtime proof's `getaddrinfo`-must-fail assertion
  validates that the *tested* daemons (OrbStack, the GitHub `ubuntu-latest` daemon) do not
  forward their embedded resolver out of an `internal: true` network. The durable invariant is
  "the core performs no client-side DNS — the gateway resolves for both the proxy and the
  relay"; a resolver-strip / operator-verify backstop is a G7-5 ops residual.
- **Runtime reality — seam vs boot.** The fallback deletion is a fail-closed *seam* guarantee
  now (`EgressClient` can no longer hand a provider an un-proxied client). It is not yet a live
  daemon boot-refusal: `build_router`'s only production caller (`build_orchestrator`) is not
  wired into daemon `start` today, and `IOPlaneUnavailableError` is in no daemon-start `except`
  tuple. The live G7-3 enforcement is the kernel isolation. **Hand-off:** when #338/#339 wires
  `build_orchestrator` into boot, that PR MUST catch `IOPlaneUnavailableError` at the boot
  boundary → audited `_refuse_boot` (HARD rule #7), not a bare traceback.
- **Cred-concentration preserved (ADR-0036).** The gateway remains the sole egress plane while
  holding no vault key — the provider path is an L7 CONNECT tunnel (the gateway sees the
  destination, never the prompt or the API key). The Proxy-Authorization upgrade stays a future add.
- **Symmetry is nominal.** The proxy seam raises a typed/audited `IOPlaneUnavailableError`; the
  relay assembly raises a bare `ValueError`. A typed `RelayIOPlaneUnavailableError` at the
  assembly seam is a #339-era cleanup. The `io_plane_unavailable` audit token is reused for both
  "unreachable" and "unconfigured" (the `detail` string disambiguates); a distinct token is a
  future refinement.
- **PRD lag.** This realizes the PRD §5 / §7.1 (line 447, default-deny outbound) invariant in
  code; the PRD prose + the comprehensive ADR-0040 are human-gated to G7-5.

## Alternatives considered

- **Guarded sequence (2+ PRs behind a flag).** Rejected — re-introduces the forbidden window and
  needs guard machinery deleted again at the end.
- **Full-stack runtime proof (boot the real `alfred-core` and assert it cannot curl out).**
  Deferred to the G7-5 smoke/ops lane — heavy (bwrap profiles) and opt-in (a paper gate on the
  merge path). The required proof tests the `internal: true` primitive; the static ratchet ties
  the real core to that primitive.
```

- [ ] **Step 2: Lint the ADR**

Run: `npx --no-install markdownlint-cli2 "docs/adr/0042-connectivity-free-core-cutover.md"`
Expected: `Summary: 0 error(s)` (if it reports MD-errors, fix tables/headings; never `--fix` a single file — it rewrites the whole tree).

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0042-connectivity-free-core-cutover.md
git commit -m "docs(adr): ADR-0042 connectivity-free-core cutover (#333)"
```

---

## Task 2: `EgressClient` fail-closed seam

**Files:**

- Modify: `src/alfred/egress/client.py`
- Test: `tests/unit/egress/test_egress_client.py`

**Interfaces:**

- Consumes: `IOPlaneUnavailableError` from `alfred.egress.errors` (existing).
- Produces: `EgressClient(*, proxy_url: str)`; `EgressClient.from_settings(settings) -> EgressClient` (raises `IOPlaneUnavailableError` when `settings.egress_proxy_url is None`); `EgressClient.proxy_url -> str`; `EgressClient.build_provider_http_client() -> httpx.AsyncClient` (never `None`).

- [ ] **Step 1: Rewrite the unit tests (RED)**

Replace the whole body of `tests/unit/egress/test_egress_client.py` with:

```python
from __future__ import annotations

import httpx
import pytest

from alfred.egress.client import EgressClient
from alfred.egress.errors import IOPlaneUnavailableError


class _Settings:
    deepseek_base_url = "https://api.deepseek.com/v1"

    def __init__(self, proxy: str | None) -> None:
        self.egress_proxy_url = proxy


def test_unset_proxy_raises_io_plane_unavailable() -> None:
    # G7-3: the connectivity-free core has no direct-egress fallback — an unset
    # ALFRED_EGRESS_PROXY_URL is fail-closed, and the message names the variable.
    with pytest.raises(IOPlaneUnavailableError) as exc_info:
        EgressClient.from_settings(_Settings(None))  # type: ignore[arg-type]
    assert "ALFRED_EGRESS_PROXY_URL" in exc_info.value.detail


@pytest.mark.asyncio
async def test_proxy_builds_a_non_redirecting_httpx_client() -> None:
    client = EgressClient.from_settings(_Settings("http://alfred-gateway:8889"))  # type: ignore[arg-type]
    assert client.proxy_url == "http://alfred-gateway:8889"
    http_client = client.build_provider_http_client()
    assert isinstance(http_client, httpx.AsyncClient)
    assert http_client.follow_redirects is False  # rider 2: redirect-escape closed
    assert http_client.trust_env is False  # ambient HTTP_PROXY/NO_PROXY must not bypass the pin
    await http_client.aclose()  # the SDK/process owns lifecycle; closeable here for the test
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/egress/test_egress_client.py -v`
Expected: `test_unset_proxy_raises_io_plane_unavailable` FAILS (current code returns a client with `proxy_url is None`, does not raise).

- [ ] **Step 3: Rewrite `client.py` (GREEN)**

Replace `src/alfred/egress/client.py` with:

```python
"""The in-core egress seam (Spec C §3/§4.1, epic #333).

The ONE sanctioned in-core constructor of an httpx.AsyncClient — every other
in-core httpx-client construction is forbidden by the import-guard, which
allowlists THIS file.

A STATELESS factory: the gateway L7 CONNECT proxy is the SOLE provider-egress
path (G7-3 connectivity-free cutover, ADR-0042). ``ALFRED_EGRESS_PROXY_URL`` is
MANDATORY — ``from_settings`` raises ``IOPlaneUnavailableError`` when it is unset
(there is no direct-egress fallback; the core has no route to the internet). The
injected client's lifecycle is SDK/provider-owned and process-lifetime — the SDK
acloses an injected client on provider.close(), httpx.aclose is idempotent, and
nothing calls provider.close() today, so no leak/double-close hazard.

follow_redirects=False (rider 2): a redirect to a non-allowlisted host must not
silently escape the allowlist. The client carries NO timeout source-of-truth
(rider 4) — the provider keeps timeout=_HTTP_TIMEOUT on the SDK ctor. The
Proxy-Authorization seam (Option 2) is a one-line future add: pass
proxy=httpx.Proxy(url=..., headers={...}).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx
import structlog

from alfred.egress.errors import IOPlaneUnavailableError

if TYPE_CHECKING:
    from alfred.config.settings import Settings

_log = structlog.get_logger(__name__)


class EgressClient:
    def __init__(self, *, proxy_url: str) -> None:
        self._proxy_url = proxy_url

    @classmethod
    def from_settings(cls, settings: Settings) -> EgressClient:
        if settings.egress_proxy_url is None:
            # G7-3 (ADR-0042): the connectivity-free core has no direct-egress
            # fallback — a missing proxy URL is fail-closed, not a silent direct hop.
            raise IOPlaneUnavailableError(
                detail=(
                    "ALFRED_EGRESS_PROXY_URL is unset — the connectivity-free core has "
                    "no direct-egress fallback (HARD rule #9); set it to the gateway L7 "
                    "CONNECT proxy (compose default http://alfred-gateway:8889)."
                )
            )
        return cls(proxy_url=settings.egress_proxy_url)

    @property
    def proxy_url(self) -> str:
        return self._proxy_url

    def build_provider_http_client(self) -> httpx.AsyncClient:
        # Log scheme/host/port only — NEVER the raw URL: a future Proxy-Authorization
        # upgrade (Option 2) may carry userinfo, and CLAUDE.md hard rule #1 forbids
        # logging secrets on any path.
        proxy_parts = urlsplit(self._proxy_url)
        _log.info(
            "egress.client.proxied",
            proxy_scheme=proxy_parts.scheme,
            proxy_host=proxy_parts.hostname,
            proxy_port=proxy_parts.port,
        )
        # trust_env=False: the egress pin must be absolute — an ambient HTTP_PROXY /
        # HTTPS_PROXY / NO_PROXY in the core container env must NOT redirect or BYPASS
        # the gateway proxy (NO_PROXY would otherwise let httpx connect a matching host
        # directly, escaping the connectivity-free-core invariant). The proxied path is
        # now the ONLY provider egress; it uses httpx's default connection limits /
        # HTTP-version / transport timeouts (the operative request timeout stays on the
        # provider SDK ctor, rider 4). Tuning those limits is a tracked G7-5 ops concern.
        return httpx.AsyncClient(proxy=self._proxy_url, follow_redirects=False, trust_env=False)


__all__ = ["EgressClient"]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/egress/test_egress_client.py -v`
Expected: both tests PASS.

- [ ] **Step 5: Verify 100% line+branch coverage of the seam**

Run: `uv run pytest tests/unit/egress/test_egress_client.py --cov=src/alfred/egress/client.py --cov-branch --cov-report=term-missing`
Expected: `src/alfred/egress/client.py` reports `100%` with no `Missing` lines/branches.

- [ ] **Step 6: Type-check**

Run: `uv run mypy src/alfred/egress/client.py && uv run pyright src/alfred/egress/client.py`
Expected: no errors (the return type is now `httpx.AsyncClient`, the property `str`).

- [ ] **Step 7: Commit**

```bash
git add src/alfred/egress/client.py tests/unit/egress/test_egress_client.py
git commit -m "feat(egress): fail-closed EgressClient — delete the direct-egress fallback (#333)"
```

---

## Task 3: `build_router` fail-closed wiring test

**Files:**

- Create: `tests/unit/cli/test_bootstrap_build_router_egress.py`

**Interfaces:**

- Consumes: `build_router(broker, settings) -> ProviderRouter` (`alfred.cli._bootstrap`); `IOPlaneUnavailableError`; `ProviderRouter` (`alfred.providers.router`).
- Produces: required-lane proof that the §3.2 deletion fails closed *in the wiring*, not only in `EgressClient` isolation.

> Why a separate test: `tests/integration/test_orchestrator_bootstrap.py` monkeypatches `build_router` out (line 131), so it never exercises the real seam; and `build_orchestrator`/`build_router` has no production daemon-boot caller yet — so without this test no required check covers the wiring's fail-closed path.

- [ ] **Step 1: Write the failing tests (RED)**

Create `tests/unit/cli/test_bootstrap_build_router_egress.py`:

```python
from __future__ import annotations

import pytest

from alfred.cli._bootstrap import build_router
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.providers.router import ProviderRouter


class _StubBroker:
    """Minimal SecretBroker surface build_router touches."""

    def get(self, name: str) -> str:
        return "sk-test-dummy"

    def has(self, name: str) -> bool:
        return False  # no anthropic fallback — keep the wiring single-provider


class _StubSettings:
    deepseek_base_url = "https://api.deepseek.com/v1"
    deepseek_model = "deepseek-chat"
    anthropic_model = "claude-sonnet-4-6"

    def __init__(self, proxy: str | None) -> None:
        self.egress_proxy_url = proxy


def test_build_router_refuses_without_proxy() -> None:
    # build_router calls EgressClient.from_settings FIRST, so an unset proxy URL
    # fails closed before any provider/broker access.
    with pytest.raises(IOPlaneUnavailableError):
        build_router(_StubBroker(), _StubSettings(None))  # type: ignore[arg-type]


def test_build_router_wires_a_router_when_proxy_set() -> None:
    router = build_router(_StubBroker(), _StubSettings("http://alfred-gateway:8889"))  # type: ignore[arg-type]
    assert isinstance(router, ProviderRouter)
```

- [ ] **Step 2: Run to verify the first test fails for the right reason**

Run: `uv run pytest tests/unit/cli/test_bootstrap_build_router_egress.py -v`
Expected: `test_build_router_refuses_without_proxy` FAILS pre-Task-2 (no raise) — but since Task 2 already shipped, confirm it now PASSES and `test_build_router_wires_a_router_when_proxy_set` PASSES too. (If `ProviderRouter`'s import path differs, fix the import to the real module — verify with `python -c "from alfred.providers.router import ProviderRouter"`.)

- [ ] **Step 3: Confirm both pass**

Run: `uv run pytest tests/unit/cli/test_bootstrap_build_router_egress.py -v`
Expected: 2 passed.

- [ ] **Step 4: Type-check the test module**

Run: `uv run mypy tests/unit/cli/test_bootstrap_build_router_egress.py`
Expected: no errors (the `# type: ignore[arg-type]` covers the stubs).

- [ ] **Step 5: Commit**

```bash
git add tests/unit/cli/test_bootstrap_build_router_egress.py
git commit -m "test(egress): build_router fails closed without the egress proxy (#333)"
```

---

## Task 4: Compose isolation flip + the static ratchet

**Files:**

- Modify: `docker-compose.yaml` (alfred-core `networks` ~line 184-186; `depends_on` ~87-91; `ALFRED_EGRESS_PROXY_URL` comment ~162-168; `networks:` block ~265-277)
- Modify: `tests/unit/test_compose_invariants.py` (:368, :418, :435 + new tests)

**Interfaces:**

- Consumes: the `compose` fixture + `_service_networks` helper (existing in the test module).
- Produces: `alfred_internal` is `internal: true`; `alfred-core` is on `{alfred_internal}` only and `depends_on` `alfred-gateway`.

- [ ] **Step 1: Update the compose-invariant tests (RED)**

In `tests/unit/test_compose_invariants.py`:

(a) Remove the `@pytest.mark.skip(...)` decorator above `test_alfred_internal_is_internal_true_deferred_to_g7_3` and rename it to `test_alfred_internal_is_internal_true`. Leave the body (it already asserts `internal.get("internal") is True`). Update the docstring to drop "deferred"/"un-skip … in the G7-3 PR".

(b) Remove the `@pytest.mark.skip(...)` decorator above `test_core_not_on_external_deferred_to_g7_3` and rename it to `test_core_not_on_external`. Leave the body. Update the docstring similarly.

(c) In `test_only_gateway_and_core_on_external`, rename to `test_only_gateway_on_external`, change the assertion and message:

```python
def test_only_gateway_on_external(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §3): alfred_external carries ONLY the gateway — the core has left.

    A GENERIC guard: any future service silently joining alfred_external fails here.
    """
    services = compose.get("services", {})
    on_external = {n for n in services if "alfred_external" in _service_networks(compose, n)}
    assert on_external == {"alfred-gateway"}, (
        "Only alfred-gateway may join alfred_external (the connectivity-free core has "
        f"left it); got {sorted(on_external)}. A new service on alfred_external breaks the "
        "connectivity-free invariant."
    )
```

(d) Add three new tests after it:

```python
def test_core_joins_internal_only(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §3, sec-001/test-002): the core is on EXACTLY alfred_internal.

    The subset check (test_core_joins_internal) + external-absent (test_core_not_on_external)
    do not catch a future THIRD internet-reachable network on the core; the exact-set does
    (mirroring test_datastores_join_internal_only). The core is the subject of the invariant.
    """
    nets = _service_networks(compose, "alfred-core")
    assert nets == {"alfred_internal"}, (
        f"alfred-core must join alfred_internal ONLY (connectivity-free core); got {sorted(nets)}."
    )


def test_no_service_uses_host_network_mode(compose: dict[str, Any]) -> None:
    """G7-3 (sec-001): network_mode: host bypasses the custom networks entirely — forbid it."""
    for name, svc in (compose.get("services", {}) or {}).items():
        assert "network_mode" not in (svc or {}), (
            f"{name} sets network_mode (bypasses alfred_internal/alfred_external isolation)."
        )


def test_core_depends_on_gateway(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §11, arch-001): the isolated core waits for the gateway egress plane."""
    depends = (compose.get("services", {}).get("alfred-core", {}) or {}).get("depends_on", {}) or {}
    assert "alfred-gateway" in depends, (
        "alfred-core must depend_on alfred-gateway so the egress proxy/relay listeners are up "
        f"before the connectivity-free core's first CONNECT; got depends_on={sorted(depends)}."
    )
```

- [ ] **Step 2: Run the invariant tests to verify they fail**

Run: `uv run pytest tests/unit/test_compose_invariants.py -v`
Expected: the un-skipped + new tests FAIL (compose not yet flipped): `test_alfred_internal_is_internal_true`, `test_core_not_on_external`, `test_only_gateway_on_external`, `test_core_joins_internal_only`, `test_core_depends_on_gateway`. (`test_no_service_uses_host_network_mode` already passes — no service uses host mode.)

- [ ] **Step 3: Flip the compose file (GREEN)**

In `docker-compose.yaml`:

(a) alfred-core `networks` (remove the external leg):

```yaml
    networks:
      - alfred_internal
```

(b) alfred-core `depends_on` (add the gateway; keep postgres+redis):

```yaml
    depends_on:
      alfred-postgres:
        condition: service_healthy
      alfred-redis:
        condition: service_healthy
      alfred-gateway:
        condition: service_healthy
```

(c) Rewrite the `ALFRED_EGRESS_PROXY_URL` inline comment (currently "UNSET => direct egress (dev / pre-G7-3 fallback …) … G7-3 makes this mandatory + deletes the direct fallback"):

```yaml
      # Spec C G7-3 (#333, ADR-0042): route ALL provider egress through the gateway L7
      # CONNECT proxy — the gateway is the sole external egress plane. The connectivity-free
      # core has NO direct-egress fallback: an unset value fails closed at the EgressClient
      # seam (IOPlaneUnavailableError). Compose-internal — the proxy port is NEVER
      # host-published (test_egress_proxy_port_never_host_published).
      ALFRED_EGRESS_PROXY_URL: ${ALFRED_EGRESS_PROXY_URL:-http://alfred-gateway:8889}
```

(d) Rewrite the `networks:` block (the trailing comment described the deferred flip):

```yaml
networks:
  # Spec C / G7 (epic #333, ADR-0042): the connectivity-free-core split. alfred_internal is
  # kernel-isolated (internal: true — no route to the internet); the core + datastores live
  # here. The gateway is the sole bridge: it joins BOTH networks and is the only external
  # egress plane. alfred_internal's internal:true is the kernel enforcement-of-record.
  # NOTE: an internal:true container's host-published port is not forwarded on
  # Docker-Desktop/OrbStack (macOS) — alfred-postgres's 5432:5432 works on Linux but is
  # unreachable from a Mac host (use `docker compose exec alfred-postgres psql …`).
  alfred_internal:
    internal: true
  alfred_external: {}
```

- [ ] **Step 4: Run the invariant tests to verify they pass**

Run: `uv run pytest tests/unit/test_compose_invariants.py -v`
Expected: all PASS (including the datastore/gateway membership tests, which are unaffected).

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "feat(egress): flip alfred-core connectivity-free — internal:true + off external (#333)"
```

---

## Task 5: Runtime egress/DNS kernel proof

**Files:**

- Create: `tests/integration/egress/test_core_network_isolation_kernel.py` (the `tests/integration/egress/` package already exists — `__init__.py` + `conftest.py` are present from G7-2c; the new test is standalone and does not use that conftest's Postgres fixtures)

**Interfaces:**

- Consumes: the `docker` CLI (present in the `Integration` lane; locally via `DOCKER_HOST`).
- Produces: `test_internal_network_blocks_egress_and_dns` — the enforcement-of-record that `internal: true` blocks `connect()` + `getaddrinfo()` to external targets while leaving siblings reachable.

- [ ] **Step 1: Write the failing test (RED)**

Create `tests/integration/egress/test_core_network_isolation_kernel.py`:

```python
"""G7-3 (Spec C §4.2, ADR-0042): the kernel enforcement-of-record for the
connectivity-free core.

The static compose-invariant tests prove the compose file DECLARES the isolation
(alfred-core on alfred_internal-only; alfred_internal internal:true). This proves the
Docker `internal: true` PRIMITIVE actually blocks egress + DNS while leaving the internal
plane reachable — the two together close the chain "the core cannot egress."

Deterministic by construction (required-lane flake discipline, rev-003): reuses the
already-present `postgres:16` image (no anonymous Docker Hub pull), drives probes with
bash primitives, bounds every probe with `timeout`, and tears down in a finally.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="docker CLI required for the connectivity-free-core kernel proof (Integration lane / local OrbStack)",
)

_IMAGE = "postgres:16"  # already pulled by testcontainers in the Integration lane


def _run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def test_internal_network_blocks_egress_and_dns() -> None:
    suffix = uuid.uuid4().hex[:10]
    net = f"alfred_g73_isolation_{suffix}"
    sibling = f"alfred_g73_sibling_{suffix}"

    created_net = _run("network", "create", "--internal", net)
    assert created_net.returncode == 0, f"network create failed: {created_net.stderr}"
    try:
        sib = _run(
            "run", "-d", "--name", sibling, "--network", net,
            "--entrypoint", "sleep", _IMAGE, "300",
        )
        assert sib.returncode == 0, f"sibling start failed: {sib.stderr}"

        # One probe container, three checks. Each line prints a stable marker.
        script = (
            'if timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443" 2>/dev/null; '
            "then echo EXTERNAL_CONNECT_OK; else echo EXTERNAL_CONNECT_BLOCKED; fi; "
            "if getent hosts api.deepseek.com >/dev/null 2>&1; "
            "then echo EXTERNAL_DNS_OK; else echo EXTERNAL_DNS_BLOCKED; fi; "
            f"if getent hosts {sibling} >/dev/null 2>&1; "
            "then echo SIBLING_DNS_OK; else echo SIBLING_DNS_BLOCKED; fi"
        )
        probe = _run(
            "run", "--rm", "--network", net,
            "--entrypoint", "bash", _IMAGE, "-c", script,
        )
        out = probe.stdout
        assert "EXTERNAL_CONNECT_BLOCKED" in out, f"core could reach the internet: {out!r}"
        assert "EXTERNAL_DNS_BLOCKED" in out, f"core could resolve an external name (DNS hole): {out!r}"
        assert "SIBLING_DNS_OK" in out, f"internal plane over-blocked (sibling unreachable): {out!r}"
    finally:
        _run("rm", "-f", sibling, timeout=30)
        _run("network", "rm", net, timeout=30)
```

(`tests/integration/egress/__init__.py` already exists — no package-marker step needed.)

- [ ] **Step 2: Run the test locally (it should PASS on OrbStack)**

Run: `export DOCKER_HOST=unix:///Users/iandominey/.orbstack/run/docker.sock; uv run pytest tests/integration/egress/test_core_network_isolation_kernel.py -v`
Expected: PASS (egress + DNS blocked, sibling resolvable). If `postgres:16` is not present locally, pre-pull once: `docker pull postgres:16`.

> This is RED→GREEN inverted: the assertion encodes the desired kernel behavior and the primitive already enforces it, so it passes immediately. To prove the test has teeth, temporarily change `--internal` to a normal network and confirm `EXTERNAL_CONNECT_BLOCKED`/`EXTERNAL_DNS_BLOCKED` flip (the assertions then FAIL). Revert the change before committing.

- [ ] **Step 3: Confirm the skip is loud when docker is absent**

Run: `PATH=/usr/bin uv run pytest tests/integration/egress/test_core_network_isolation_kernel.py -rs` (a PATH without `docker`)
Expected: `SKIPPED` with the reason naming "docker CLI required …". (The Task 6 CI guard turns this skip into a job failure in the required lane.)

- [ ] **Step 4: Commit**

```bash
git add tests/integration/egress/test_core_network_isolation_kernel.py
git commit -m "test(egress): runtime kernel proof — internal:true blocks egress + DNS (#333)"
```

---

## Task 6: #245 not-skipped CI guard

**Files:**

- Modify: `.github/workflows/ci.yml` (the `integration` job — add a step after "Run integration tests with coverage append")

**Interfaces:**

- Consumes: the `steps.check.outputs.has_integration` guard + the test file from Task 5.
- Produces: a required-lane assertion that the kernel proof RAN (did not skip) and passed.

- [ ] **Step 1: Add the not-skipped guard step**

In `.github/workflows/ci.yml`, in the `integration` job, immediately after the `Run integration tests with coverage append` step, add:

```yaml
      - name: Assert the connectivity-free-core kernel proof RUNS (not skipped) — #245 paper-gate guard
        # The runtime egress/DNS proof is the enforcement-of-record for the connectivity-free
        # core (ADR-0042 / Spec C §4.2). A `skipif(docker unavailable)` LOUD skip is still a
        # GREEN required check — the exact #245 failure mode. The Integration runner has Docker
        # (testcontainers), so the proof MUST run here. `tee` keeps the summary on disk to
        # skip-parse it; `set -o pipefail` propagates a pytest non-zero exit through the pipe.
        if: steps.check.outputs.has_integration == 'true' && hashFiles('tests/integration/egress/test_core_network_isolation_kernel.py') != ''
        run: |
          set -euo pipefail
          uv run pytest tests/integration/egress/test_core_network_isolation_kernel.py \
            -rs -p no:cacheprovider --cov-fail-under=0 | tee /tmp/core_net_isolation.out
          if grep -qE "(^|[^0-9])[1-9][0-9]* skipped" /tmp/core_net_isolation.out; then
            echo "::error::connectivity-free-core kernel proof SKIPPED on the required Integration lane — paper-gate hazard (#245); docker provisioning regressed."
            exit 1
          fi
          grep -q "1 passed" /tmp/core_net_isolation.out || { echo "::error::connectivity-free-core kernel proof did not report '1 passed'."; exit 1; }
```

- [ ] **Step 2: Validate the workflow YAML**

Run: `uv run python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml-ok')"`
Expected: `yaml-ok`. (If `actionlint` is installed, also run `actionlint .github/workflows/ci.yml` and expect no errors.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(egress): assert the connectivity-free-core kernel proof runs, not skipped (#333)"
```

---

## Task 7: Operator-doc sweep + runbook/README + ADR-amendment check

**Files:**

- Modify: `.env.example` (lines ~53-56)
- Modify: a runbook under `docs/runbooks/` and/or `README.md`
- Verify: `docs/adr/*` (no provider-fallback amendment expected)

**Interfaces:**

- Consumes: nothing.
- Produces: operator-facing docs consistent with the deleted fallback + the macOS limitation.

- [ ] **Step 1: Rewrite the `.env.example` egress-proxy note**

Replace the sentences in `.env.example` that describe the "unset => direct-egress fallback (a loud egress.client.direct log)" (currently ~lines 53-56) with the realized end-state:

```text
# with the gateway default (`${ALFRED_EGRESS_PROXY_URL:-http://alfred-gateway:8889}`), and
# the `:-` form treats an EMPTY `.env` value as unset too — so under compose the stack
# ALWAYS routes through the proxy. G7-3 (ADR-0042) made the proxy MANDATORY: the
# connectivity-free core has NO direct-egress fallback — an unset/empty value fails closed
# at the EgressClient seam (IOPlaneUnavailableError), never a silent direct hop.
```

- [ ] **Step 2: Verify no other `.env.example` text still claims the fallback**

Run: `grep -n "direct egress\|egress.client.direct\|restore direct\|direct-egress fallback" .env.example`
Expected: no matches (or only the new fail-closed wording). Fix any stragglers.

- [ ] **Step 3: Add the operator runbook note**

Pick the egress/deployment runbook (`ls docs/runbooks/`; if none fits, add a short note to `README.md`'s deployment section). Add:

```markdown
### macOS host access to Postgres (G7-3 connectivity-free core)

`alfred_internal` is `internal: true`, so on Docker-Desktop/OrbStack (macOS) the
`alfred-postgres` host-published port `5432` is not forwarded — `psql -h localhost` from a
Mac host will not connect. The compose-internal core reaches Postgres over `alfred_internal`,
and the dev test loop uses testcontainers, so neither is affected. For a one-off host query,
exec into the network: `docker compose exec alfred-postgres psql -U alfred -d alfred`. On
Linux, published ports NAT independently of the internal network, so host access still works.

### Mandatory egress proxy

`ALFRED_EGRESS_PROXY_URL` is mandatory — the core has no direct-egress fallback. A non-default
`ALFRED_ANTHROPIC_BASE_URL` / `ALFRED_DEEPSEEK_BASE_URL` override must be on the gateway's
destination allowlist (set the matching base-url var on `alfred-gateway` too), or the proxied
call is denied.
```

- [ ] **Step 4: Verify no ADR describes the provider fallback as live**

Run: `grep -rln "egress.client.direct\|direct-egress fallback\|unset.*direct egress" docs/adr/`
Expected: no matches → no ADR factual amendment needed (the deletion is recorded in ADR-0042). If a match appears, add a dated `> **2026-06-29 (G7-3) factual amendment:**` line marking the fallback deleted (do not flip ADR status — human-gated).

- [ ] **Step 5: Lint the docs**

Run: `npx --no-install markdownlint-cli2 "docs/**/*.md" "README.md"`
Expected: `Summary: 0 error(s)` for the files you touched (fix any MD errors by hand).

- [ ] **Step 6: Commit**

```bash
git add .env.example README.md docs/
git commit -m "docs(egress): sweep stale direct-egress fallback refs + macOS host-port note (#333)"
```

---

## Final verification (before opening the PR)

- [ ] **Step 1: Full quality gate**

Run: `export DOCKER_HOST=unix:///Users/iandominey/.orbstack/run/docker.sock; make check`
Expected: ruff + format + mypy + pyright + tag-t3 + unit/integration all green. (Mac integration-load flakes in UNTOUCHED capability_gate timing tests are environmental — verify any suspect in isolation; trust Linux CI.)

- [ ] **Step 2: Run the egress + compose + isolation suites together**

Run: `export DOCKER_HOST=unix:///Users/iandominey/.orbstack/run/docker.sock; uv run pytest tests/unit/egress/test_egress_client.py tests/unit/cli/test_bootstrap_build_router_egress.py tests/unit/test_compose_invariants.py tests/integration/egress/test_core_network_isolation_kernel.py -v`
Expected: all PASS, none skipped (docker present locally).

- [ ] **Step 3: Adversarial suite (release-blocking — egress boundary touched)**

Run: `export DOCKER_HOST=unix:///Users/iandominey/.orbstack/run/docker.sock; uv run pytest tests/adversarial -q`
Expected: all PASS — including `sbx_2026_005` / `test_quarantined_llm_not_yet_spawned_while_egress_open` (unchanged, not weakened).

- [ ] **Step 4: Confirm 100% egress coverage holds**

Run: `uv run pytest tests/unit/egress -q --cov=src/alfred/egress/client.py --cov-branch --cov-report=term-missing`
Expected: `client.py` at 100%.

- [ ] **Step 5: Push + open the PR; run `/review-pr` (full fleet, security ALWAYS) + CodeRabbit; resolve every thread; UAT; `gh pr merge --rebase`.**

---

## Self-Review

**Spec coverage (each §):**

- §3.1 compose flip + depends_on + macOS port → Task 4 + Task 7. ✅
- §3.2 fallback deletion + type/doc/limits sweep + runtime-reality framing → Task 2 + ADR-0042 (Task 1). ✅
- §3.3 the three invariant flips + exact-set → Task 4. ✅
- §3.4 build_router seam test (bootstrap test is a no-op) → Task 3. ✅
- §4.1 static ratchet (compose-invariants + import-guard — existing, unchanged) → Task 4 references it. ✅
- §4.2 runtime egress/DNS proof + image/probe + not-skipped + DNS scope → Task 5 + Task 6 + ADR-0042. ✅
- §5 tests (unit/settings/compose/integration/adversarial) → Tasks 2-6 + Final verification. ✅
- §6 ADR-0042 + operator-doc sweep + runbook → Task 1 + Task 7. ✅
- §7 risk/rollback → captured in ADR-0042 Consequences + the atomic single-PR shape. ✅
- §8 commit sequence → Tasks 1-7 mirror it (ADR → client.py → router test → compose → proof → CI guard → docs). ✅

**Type consistency:** `EgressClient.__init__(*, proxy_url: str)`, `from_settings(...) -> EgressClient`, `proxy_url -> str`, `build_provider_http_client() -> httpx.AsyncClient`, `IOPlaneUnavailableError(*, detail=...)` with `.detail` — used identically in Tasks 2 and 3.

**Placeholder scan:** every code/step block is concrete; the one conditional (`__init__.py` creation in Task 5, ADR amendment in Task 7) carries an exact verification command and the action for each branch.
