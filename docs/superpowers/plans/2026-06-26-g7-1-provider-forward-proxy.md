# G7-1 — Provider Forward-Proxy + the In-Core Egress Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the mode-(a) provider egress path of Spec C — an in-core `EgressClient`/typed-error seam plus a gateway L7 CONNECT forward-proxy — and route both providers through it via an injected `http_client`, while giving the quarantine child `--unshare-net`.

**Architecture:** Spec C ([2026-06-25-spec-c-egress-control-plane-design](../specs/2026-06-25-spec-c-egress-control-plane-design.md), epic #333) makes the core connectivity-free and the gateway the sole external I/O plane. G7-0 (merged) laid the two-network topology + the structural gates. G7-1 builds the **mode-(a)** path: the core's `EgressClient` builds a proxied `httpx.AsyncClient(proxy="http://alfred-gateway:PORT")`, the provider `from_settings` constructors accept it as an injected `http_client`, and a new gateway **L7 CONNECT forward-proxy** (TLS-passthrough — payload-blind to the prompt; native SDK streaming preserved) enforces a live-config-derived **destination allowlist**, refuses literal-IP CONNECT, resolves DNS gateway-side, rejects a resolved IP that is not globally-routable, and audits every CONNECT. The transport is **TCP on `alfred_internal`, peer-auth by network membership** (maintainer co-signed 2026-06-26; see *Locked transport decision*). The quarantine child gets `--unshare-net` now (deterministic-echo needs no network), closing its half of #230.

> **This plan was reviewed by a 6-agent `/review-plan` fleet (architect, security, test-engineer, reviewer, provider, devops) on 2026-06-26; all Critical/High/Medium findings are folded in. `[rev]` marks a change that landed from that review.**

**Tech Stack:** Python 3.12+, asyncio, httpx 0.28.1, anthropic 0.104.1, openai 2.38.0, Pydantic v2 settings, pytest, Docker Compose. No new third-party dependency.

## Locked transport decision (maintainer co-sign, 2026-06-26)

A 5-lens fleet panel (security / architect / provider / devops / comms) unanimously recommended, and the maintainer co-signed, **Option 1 — TCP CONNECT proxy on `alfred_internal`, peer-auth by network membership**, with the hardening riders below. The spec §3 "0600 unix socket + SO_PEERCRED" wording describes the **comms control wire** (Spec A/B), **not** the egress proxy; an httpx CONNECT proxy needs a TCP endpoint. Reconciling that wording in the PRD/ADR is human-gated and lands at **G7-5** (ADR-0040); G7-1 carries only a plan-level note placed **at spec §3**.

**Riders baked into this plan (each re-verified by the security reviewer):**

1. The proxy is **never host-published** — a compose-invariant test asserts no service publishes the egress container port (the existing `test_alfred_gateway_publishes_no_host_port` is the primary gateway guard). Bind defaults to the compose-internal interface; the destination allowlist is the security control during the pre-`internal:true` window (closed structurally at G7-3).
2. The **destination allowlist is the control**: default-deny, derived from each provider's *effective* base URL, refuse-literal-IP CONNECT, gateway-side DNS resolution, **reject a resolved IP that is not globally-routable** `[rev: sec-003]`, `follow_redirects=False` on the in-core client, the CONNECT **request-line authority is the sole allowlist source** (the `Host:` header is never trusted) `[rev: sec-004]`, bounded request-line/header reads, and a gateway-local audit row on every CONNECT incl. refusals.
3. Proxy bind-failure / link-down is **fail-closed** → `IOPlaneUnavailableError`. This means a proxy bind failure refuses the gateway start and the gateway **crash-loops under `restart: unless-stopped`** — the intended I/O-plane posture (the proxy is the gateway's reason to exist), NOT the metrics server's loud-and-continue `[rev: devops-004]`.
4. **`timeout=_HTTP_TIMEOUT` + `max_retries` stay on the SDK ctor** — the `EgressClient` is not the timeout source of truth. Because the providers pass `timeout=` explicitly, the SDK's omit-timeout/http_client-adoption branch is never entered, so the injected client's timeout is irrelevant `[rev: prov-003]`; `max_retries` is never inherited from the http_client (anthropic's `max_retries=2` survives).
5. The `http_client` seam is shaped so an Option-2 **shared-secret `Proxy-Authorization` token** is a one-line additive upgrade later (a `httpx.Proxy(headers=...)` arg) — not built now. mTLS / per-principal client certs are recorded in ADR-0040 (G7-5) as the named future path.

## Resolved open decisions (were flagged for /review-plan; reviewers converged)

1. **Bind interface** → **accept `ALFRED_EGRESS_PROXY_BIND` default `0.0.0.0` + never-host-published + the destination allowlist** for G7-1 (security + devops + architect concur). Binding the per-network IP is fiddly (a two-network container has two IPs; no clean per-network hostname) and buys nothing while `alfred_external` still reaches the internet; `internal:true` at G7-3 closes the interface question structurally. The pre-G7-3 "any `alfred_external` co-tenant could reach the proxy on the port, bounded by the allowlist" window is recorded as an **accepted, time-boxed residual** that G7-3 must close `[rev: arch-008, sec-006, devops-005]`.
2. **Config-gated vs mandatory** → **config-gated now** (`ALFRED_EGRESS_PROXY_URL`): compose sets it so the real stack routes through the proxy; unset → direct (dev + pre-G7-3 safety), with a **loud `egress.client.direct` structlog line** so the direct path is never silent `[rev: sec-007]`. G7-3 makes it mandatory + deletes the direct fallback atomically with `internal:true`; a `# G7-3: DELETE this fallback ...` anchored marker sits at the fallback site so G7-3 cannot miss it.
3. **`http_client` lifecycle / `aclose` ownership** → **`EgressClient` is a stateless factory** (no `_built` list, no `aclose`). The injected client's lifecycle is SDK/provider-owned and process-lifetime: prov-005 verified the SDK acloses the injected client on `provider.close()`, `httpx.AsyncClient.aclose()` is idempotent, and nothing calls `provider.close()` today — so a tracked-but-unreachable reaper would be dead-code smell `[rev: arch-003, sec-009, rev-003, prov-005]`. Documented in the `EgressClient` docstring.

## Out of scope (later G7 slices — do NOT build here)

- **Mode (b)** inspecting tool-egress relay, the gateway DLP second pass, the real outbound canary scanner, the §4.3 egress-response quarantine-extract, **egress idempotency** → **G7-2**. (G7-1 introduces **no outbound BODY path** — CONNECT tunnels are opaque byte-splices, so DLP is N/A by design and there is no un-DLP'd body escape.)
- The **`internal:true` flip + core-off-`alfred_external` + the kernel/DNS enforcement tests + the `depends_on` boot-ordering + deleting the direct-egress fallback + datastore enumeration on `alfred_internal` (incl. adding Qdrant)** → **G7-3** `[rev: devops-006]`. G7-1 keeps the core on both networks and the direct path available; it does NOT add `depends_on` (the proxied client dials the gateway only on a provider call, not at boot, so there is no boot deadlock).
- The **`gateway_egress_inflight` gauge + saturation alert + the full head-of-line isolation hardening + the `connect_denied`-rate alert rule + Grafana panels** → **G7-3/G7-5**. G7-1 ships a per-call task + per-CONNECT audit + a single per-outcome Counter only (provisional name; G7-5 owns the canonical egress metric/alert set) `[rev: arch-005, devops-007]`.
- **Discord-adapter** L7-proxy hardening → **G7-4**. NOTE for that PR: the comms-lens panel found the spec's literal "`--unshare-net` + `Client(proxy=...)`" is in tension — an empty-netns child cannot reach a TCP proxy on `alfred_internal`; G7-4 must resolve netns placement (containment by the per-caller allowlist, not netns emptiness). Recorded so G7-4 does not inherit a contradiction.
- PRD §5/§7.1 + ADR-0040 + ops dashboards/alerts + operator CLI → **G7-5**.

## Global Constraints

- **Python 3.12+**; `mypy --strict` + `pyright` clean; `ruff check` + `ruff format` clean.
- **No `--no-verify`, no pre-commit-hook skipping.**
- **Conventional Commits** with `(#333)` in every commit subject. Trailers: `MrReasonable <...>` + `Claude-Session: ...`.
- **`make check`** before every push; **`make docs-check`** additionally for any docs change. `make check`'s integration step is slow (~10min) — run unit/lint/type locally; integration runs in CI.
- **No new third-party dependency.**
- **i18n is HARD:** every operator-facing string through `t()`; drift gate (`.github/workflows/pr-validate-python.yml`) runs `pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins` → `pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching` → `pybabel compile`. **NEVER `--omit-header`.** Audit-reason *tokens* stay stable identifiers; their operator-rendered *presentations*, the two typed-error reasons, and the egress CLI text go through `t()`. Metric names / Help strings / `ops/alerts` stay English.
- **Security boundaries → 100% line + branch coverage, via the repo's TWO-GATES pattern** `[rev: devops-001]`. Each new egress security-boundary file (`errors.py`, `allowlist.py`, `client.py`, `egress_proxy.py`) gets a named per-file gate in **BOTH** CI jobs: the `python` job (guard `steps.check.outputs.has_py == 'true'`) AND the `coverage-gates` job (guard `steps.check.outputs.has_coverage_corpus == 'true'`). The `security/*` glob gate does NOT catch these files. `allowlist.py` IS a boundary (it derives the deny set + the literal-IP detector) and gets its own gate too.
- **Adversarial suite is release-blocking.** Task A5 re-pivots release-blocking adversarial gates; run `uv run pytest tests/adversarial` after it and include a security-engineer adjudication note in the PR (mirroring the 2b0 gate re-pivot precedent in that file).
- **Behaviour-neutral default.** With `ALFRED_EGRESS_PROXY_URL` unset, provider construction is byte-for-byte today's direct path (verified: both SDK ctors default `http_client=None` and build their own client) — Part A is safe to merge before the proxy exists.

## File structure

In-core seam — new package `src/alfred/egress/` (each file gets the two-gates per-file coverage gate):

- `src/alfred/egress/__init__.py`
- `src/alfred/egress/errors.py` — `IOPlaneUnavailableError`, `EgressDeniedError` (rooted at `AlfredError`).
- `src/alfred/egress/allowlist.py` — pure helpers: derive the provider destination allowlist; literal-IP + globally-routable-IP + host/port parsing. Imported by BOTH the in-core client (reference) and the gateway proxy.
- `src/alfred/egress/client.py` — `EgressClient` stateless factory. **The one file added to the import-guard `_CONSTRUCT_ALLOWLIST`.**

Gateway-side:

- `src/alfred/gateway/egress_proxy.py` — `EgressForwardProxy`: the TCP L7 CONNECT listener.
- `src/alfred/gateway/egress_audit.py` — gateway-local egress audit (structlog + counter + closed-vocab reason enum), modelled on `ingress_audit.record_ingress_refusal` `[rev: sec-002]`.

Touched existing: `providers/anthropic_native.py`, `providers/deepseek.py`, `cli/_bootstrap.py`, `config/settings.py`, `cli/gateway/_commands.py`, `config/sandbox/quarantined-llm.linux.bwrap.policy`, `config/sandbox/README.md`, `docker-compose.yaml`, `.env.example`, `.github/workflows/ci.yml`, `tests/unit/egress/test_in_core_http_egress_guard.py`, `tests/unit/test_compose_invariants.py`, the adversarial sandbox-escape file + `sbx_2026_005_*.yaml` + `test_sbx_corpus_executable.py`, `locale/en/LC_MESSAGES/alfred.{po,mo}`, `docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md` (a §3 plan-reconciliation note).

## PR decomposition (recommended; architect endorsed the seam)

- **G7-1a — in-core egress seam (Part A, behaviour-neutral).** Tasks A1–A5. Default-off → byte-for-byte today's path; mergeable with low risk. Within A*, tasks are order-free.
- **G7-1b — gateway L7 proxy + the flip (Part B).** Tasks B1–B5. **Hard ordering: B1 → B2 → B4 (audit) → B3 (compose flip is LAST) → B5** `[rev: arch-002, test-007]`. The compose `ALFRED_EGRESS_PROXY_URL` flip MUST NOT land before the proxy exists + is mounted, or the core dials a dead proxy.

---

## Part A — In-core egress seam (G7-1a, behaviour-neutral)

### Task A1: Typed egress errors + i18n

**Files:**

- Create: `src/alfred/egress/__init__.py`, `src/alfred/egress/errors.py`
- Create: `tests/unit/egress/test_egress_errors.py`, `tests/unit/test_catalog_g7_egress_keys.py`
- Modify: `locale/en/LC_MESSAGES/alfred.{po,mo}`, `.github/workflows/ci.yml` (two-gates for `errors.py`)

**Interfaces:**

- Produces: `IOPlaneUnavailableError(*, detail: str)` with `.reason = "io_plane_unavailable"`; `EgressDeniedError(*, destination: str, deny_reason: str)` with class attr `.reason = "egress_denied"` and instance `.deny_reason` `[rev: sec-008/rev-002 — the ctor param is`deny_reason`, NOT`reason`, so it never shadows the class-level audit token]`.

- [ ] **Step 1: Write the failing test** — `tests/unit/egress/test_egress_errors.py`:

```python
from __future__ import annotations

import pytest

from alfred.egress.errors import EgressDeniedError, IOPlaneUnavailableError
from alfred.errors import AlfredError


def test_io_plane_unavailable_is_alfred_error_with_reason() -> None:
    err = IOPlaneUnavailableError(detail="connect timeout to alfred-gateway:8889")
    assert isinstance(err, AlfredError)
    assert err.reason == "io_plane_unavailable"
    assert "connect timeout" in str(err)


def test_egress_denied_carries_destination_and_deny_reason() -> None:
    err = EgressDeniedError(destination="evil.example:443", deny_reason="destination_not_allowlisted")
    assert isinstance(err, AlfredError)
    assert err.reason == "egress_denied"  # class-level audit token, never shadowed
    assert err.destination == "evil.example:443"
    assert err.deny_reason == "destination_not_allowlisted"
    assert "evil.example:443" in str(err)


@pytest.mark.parametrize("make", [
    lambda: IOPlaneUnavailableError(detail="x"),
    lambda: EgressDeniedError(destination="h:1", deny_reason="r"),
])
def test_errors_render_a_nonempty_message(make) -> None:
    assert str(make())
```

- [ ] **Step 2: Run it** — `uv run pytest tests/unit/egress/test_egress_errors.py -v` → FAIL (`No module named 'alfred.egress'`).

- [ ] **Step 3: Create the package + errors** — `src/alfred/egress/__init__.py` empty; `src/alfred/egress/errors.py`:

```python
"""Fail-loud typed errors for the egress plane (Spec C §6/§7, epic #333).

* IOPlaneUnavailableError — the gateway egress proxy is unreachable, so ALL
  external I/O is down. Loud, audited, bounded.
* EgressDeniedError — a destination-allowlist / DLP denial. Surfaced distinctly.

Both root at AlfredError. ``reason`` is a closed-vocabulary audit token (stable,
NOT localised); the rendered message goes through t(). The EgressDeniedError ctor
param is ``deny_reason`` (the specific denial), deliberately NOT named ``reason``
so it never shadows the class-level ``reason`` audit token.
"""

from __future__ import annotations

from alfred.errors import AlfredError
from alfred.i18n import t


class IOPlaneUnavailableError(AlfredError):
    """The gateway egress proxy is unreachable — total external-I/O outage."""

    reason = "io_plane_unavailable"

    def __init__(self, *, detail: str) -> None:
        self.detail = detail
        super().__init__(t("egress.io_plane_unavailable", detail=detail))


class EgressDeniedError(AlfredError):
    """An egress call was refused by the destination allowlist or the DLP pass."""

    reason = "egress_denied"

    def __init__(self, *, destination: str, deny_reason: str) -> None:
        self.destination = destination
        self.deny_reason = deny_reason
        super().__init__(t("egress.denied", destination=destination, reason=deny_reason))


__all__ = ["EgressDeniedError", "IOPlaneUnavailableError"]
```

- [ ] **Step 4: i18n keys + enumeration test** — add to `alfred.po` (placed by the Step-5 pybabel flow):

```
msgid "egress.io_plane_unavailable"
msgstr "External I/O is unavailable: the core could not reach the gateway egress proxy ({detail})."

msgid "egress.denied"
msgstr "Egress to {destination} was denied ({reason})."
```

Create `tests/unit/test_catalog_g7_egress_keys.py` (the ONE home for all G7-egress keys; B2/B4 extend `G7_EGRESS_KEYS`) `[rev: test-009]`:

```python
"""Closed key-set for the G7 egress plane (Spec C, epic #333). Mirrors
tests/unit/test_catalog_slice_4_keys.py — every key must resolve with a non-empty
msgstr so a dropped/renamed egress key fails loud."""

from __future__ import annotations

from alfred.i18n import t

G7_EGRESS_KEYS: tuple[str, ...] = (
    "egress.io_plane_unavailable",
    "egress.denied",
    # B2 adds gateway.start.egress_proxy_bind_failed; B4 adds the audit-reason presentations.
)


def test_g7_egress_keys_resolve() -> None:
    for key in G7_EGRESS_KEYS:
        value = t(key)
        assert value != key, f"G7 egress key {key!r} not found in catalog"
        assert value.strip(), f"G7 egress key {key!r} has empty msgstr"
    assert len(G7_EGRESS_KEYS) == len(set(G7_EGRESS_KEYS)), "duplicate G7 egress keys"
```

- [ ] **Step 5: pybabel flow** (NEVER `--omit-header`):

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching
# fill the msgstrs if blank, then:
uv run pybabel compile -d locale -D alfred --statistics
```

- [ ] **Step 6: Two-gates CI for `errors.py`** `[rev: devops-001]`. Add the SAME named step to BOTH jobs, with the correct per-job guard. In the **`python`** job:

```yaml
      - name: Egress control-plane 100% line+branch coverage (unit)
        if: steps.check.outputs.has_py == 'true' && hashFiles('src/alfred/egress/errors.py') != ''
        run: |
          uv run coverage report --include='src/alfred/egress/errors.py' --fail-under=100
```

In the **`coverage-gates`** job (combined corpus):

```yaml
      - name: Egress control-plane 100% line+branch coverage (combined)
        if: steps.check.outputs.has_coverage_corpus == 'true' && hashFiles('src/alfred/egress/errors.py') != ''
        run: |
          uv run coverage report --include='src/alfred/egress/errors.py' --fail-under=100
```

(Tasks A2/A3/B1 extend the `--include` list in BOTH jobs as their files land. Verify each gate locally: `uv run coverage run -m pytest tests/unit/egress/ && uv run coverage report --include='...' --fail-under=100`.)

- [ ] **Step 7: Run** — `uv run pytest tests/unit/egress/test_egress_errors.py tests/unit/test_catalog_g7_egress_keys.py -v` → PASS.

- [ ] **Step 8: Commit** — `feat(egress): fail-loud IOPlaneUnavailable/EgressDenied typed errors (#333)`.

---

### Task A2: Destination allowlist + globally-routable-IP guard

**Files:** Create `src/alfred/egress/allowlist.py`, `tests/unit/egress/test_egress_allowlist.py`; Modify `.github/workflows/ci.yml` (add `allowlist.py` to BOTH egress gates) `[rev: test-003]`.

**Interfaces:**

- `EgressDestination = tuple[str, int]`; `ANTHROPIC_DEFAULT_HOST = "api.anthropic.com"`; `host_port_from_url(url, *, default_port=443) -> EgressDestination`; `is_literal_ip(host) -> bool`; `is_globally_routable(host_or_ip) -> bool` `[rev: sec-003]`; `provider_egress_allowlist(settings) -> frozenset[EgressDestination]`.

- [ ] **Step 1: Write the failing test** — `tests/unit/egress/test_egress_allowlist.py`:

```python
from __future__ import annotations

import pytest

from alfred.egress.allowlist import (
    ANTHROPIC_DEFAULT_HOST,
    host_port_from_url,
    is_globally_routable,
    is_literal_ip,
    provider_egress_allowlist,
)


@pytest.mark.parametrize(("url", "expected"), [
    ("https://api.deepseek.com/v1", ("api.deepseek.com", 443)),
    ("https://api.deepseek.com:8443/v1", ("api.deepseek.com", 8443)),
    ("http://localhost:11434/v1", ("localhost", 11434)),
])
def test_host_port_from_url(url: str, expected: tuple[str, int]) -> None:
    assert host_port_from_url(url) == expected


@pytest.mark.parametrize(("host", "literal"), [
    ("1.2.3.4", True), ("::1", True), ("[2606:4700::1111]", True),
    ("2606:4700:4700::1111", True), ("api.anthropic.com", False), ("localhost", False),
])
def test_is_literal_ip(host: str, literal: bool) -> None:
    assert is_literal_ip(host) is literal


@pytest.mark.parametrize(("ip", "ok"), [
    ("1.1.1.1", True), ("127.0.0.1", False), ("169.254.169.254", False),
    ("10.0.0.5", False), ("::1", False), ("not-an-ip", False),
])
def test_is_globally_routable(ip: str, ok: bool) -> None:
    assert is_globally_routable(ip) is ok


def test_provider_allowlist_from_settings() -> None:
    class _S:
        deepseek_base_url = "https://api.deepseek.com/v1"

    allow = provider_egress_allowlist(_S())  # type: ignore[arg-type]
    assert (ANTHROPIC_DEFAULT_HOST, 443) in allow
    assert ("api.deepseek.com", 443) in allow
```

- [ ] **Step 2: Run it** → FAIL (`No module named 'alfred.egress.allowlist'`).

- [ ] **Step 3: Implement** — `src/alfred/egress/allowlist.py`:

```python
"""Provider egress destination allowlist + IP guards (Spec C §4.1, epic #333).

Pure helpers — NO httpx, NO provider-SDK imports (the import-guard ignores this
file). The gateway L7 CONNECT proxy enforces this set; the in-core EgressClient
references it. The set is derived from LIVE provider config so it cannot drift
from a second hard-coded list.

NOTE on Anthropic: the SDK has no base_url override Setting today, so
ANTHROPIC_DEFAULT_HOST mirrors the SDK default. The anthropic SDK DOES read the
ANTHROPIC_BASE_URL env var; if an operator sets it the gateway would deny the
(non-allowlisted) host — the SAFE failure direction (deny, not leak). If an
anthropic_base_url Setting is ever added, derive this host from it (mirror
DeepSeek) to keep the no-drift property. `[rev: arch-009, prov-006, devops-008]`
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from alfred.config.settings import Settings

EgressDestination = tuple[str, int]
ANTHROPIC_DEFAULT_HOST = "api.anthropic.com"
_DEFAULT_HTTPS_PORT = 443


def host_port_from_url(url: str, *, default_port: int = _DEFAULT_HTTPS_PORT) -> EgressDestination:
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        raise ValueError(f"egress allowlist: URL {url!r} has no host")
    return (host, parts.port or default_port)


def is_literal_ip(host: str) -> bool:
    """True if ``host`` is a literal IPv4/IPv6 address (accepts a bracketed IPv6)."""
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_globally_routable(host_or_ip: str) -> bool:
    """True iff ``host_or_ip`` parses as an IP that is globally routable.

    Rejects loopback / link-local / private / reserved / multicast. A non-IP
    string returns False (the proxy only calls this on the RESOLVED address).
    """
    try:
        return ipaddress.ip_address(host_or_ip.strip("[]")).is_global
    except ValueError:
        return False


def provider_egress_allowlist(settings: Settings) -> frozenset[EgressDestination]:
    """Allowed provider egress destinations from live config (DeepSeek base_url
    host + the Anthropic SDK default). G7-4 adds the Discord hosts."""
    return frozenset(
        {host_port_from_url(settings.deepseek_base_url), (ANTHROPIC_DEFAULT_HOST, _DEFAULT_HTTPS_PORT)}
    )


__all__ = [
    "ANTHROPIC_DEFAULT_HOST",
    "EgressDestination",
    "host_port_from_url",
    "is_globally_routable",
    "is_literal_ip",
    "provider_egress_allowlist",
]
```

- [ ] **Step 4: Run** → PASS. Add `src/alfred/egress/allowlist.py` to the `--include` list of BOTH egress gates (Task A1 Step 6). Verify 100% locally.

- [ ] **Step 5: Commit** — `feat(egress): live-config destination allowlist + globally-routable-IP guard (#333)`.

---

### Task A3: The in-core `EgressClient` (stateless factory) + import-guard allowlist

**Files:** Create `src/alfred/egress/client.py`, `tests/unit/egress/test_egress_client.py`; Modify `src/alfred/config/settings.py`, `tests/unit/egress/test_in_core_http_egress_guard.py`, `.github/workflows/ci.yml` (both egress gates).

**Interfaces:**

- `Settings.egress_proxy_url: str | None`.
- `EgressClient.from_settings(cls, settings) -> EgressClient`; `EgressClient.proxy_url: str | None`; `EgressClient.build_provider_http_client() -> httpx.AsyncClient | None`. **No `aclose`, no `_built`** — stateless factory (open-decision 3).

- [ ] **Step 1: Add the Settings field** in `src/alfred/config/settings.py` near the provider fields:

```python
    # Spec C / G7-1 (#333): when set, the core builds provider SDK clients with an
    # httpx proxy pointed at the gateway L7 CONNECT proxy (e.g. "http://alfred-gateway:8889").
    # UNSET => direct egress (today's behaviour); the direct fallback is deleted
    # atomically at G7-3.
    egress_proxy_url: str | None = None
```

- [ ] **Step 2: Write the failing test** — `tests/unit/egress/test_egress_client.py`:

```python
from __future__ import annotations

import httpx
import pytest

from alfred.egress.client import EgressClient


class _Settings:
    deepseek_base_url = "https://api.deepseek.com/v1"

    def __init__(self, proxy: str | None) -> None:
        self.egress_proxy_url = proxy


def test_no_proxy_returns_none_client() -> None:
    client = EgressClient.from_settings(_Settings(None))  # type: ignore[arg-type]
    assert client.proxy_url is None
    assert client.build_provider_http_client() is None


@pytest.mark.asyncio
async def test_proxy_builds_a_non_redirecting_httpx_client() -> None:
    client = EgressClient.from_settings(_Settings("http://alfred-gateway:8889"))  # type: ignore[arg-type]
    assert client.proxy_url == "http://alfred-gateway:8889"
    http_client = client.build_provider_http_client()
    assert isinstance(http_client, httpx.AsyncClient)
    assert http_client.follow_redirects is False  # rider 2: redirect-escape closed
    await http_client.aclose()  # the SDK/process owns lifecycle; closeable here for the test
```

- [ ] **Step 3: Run it** → FAIL (`No module named 'alfred.egress.client'`).

- [ ] **Step 4: Implement** — `src/alfred/egress/client.py`:

```python
"""The in-core egress seam (Spec C §3/§4.1, epic #333).

The ONE sanctioned in-core constructor of an httpx.AsyncClient — every other
in-core httpx-client construction is forbidden by the import-guard, which
allowlists THIS file.

A STATELESS factory (open-decision 3): when ALFRED_EGRESS_PROXY_URL is set,
build_provider_http_client returns a proxied client; unset => None and providers
construct directly (today's behaviour). The injected client's lifecycle is
SDK/provider-owned and process-lifetime — the SDK acloses an injected client on
provider.close(), httpx.aclose is idempotent, and nothing calls provider.close()
today, so no leak/double-close hazard and no reaper is needed here.

follow_redirects=False (rider 2): a redirect to a non-allowlisted host must not
silently escape the allowlist. The client carries NO timeout source-of-truth
(rider 4) — the provider keeps timeout=_HTTP_TIMEOUT on the SDK ctor. The
Proxy-Authorization seam (Option 2) is a one-line future add: pass
proxy=httpx.Proxy(url=..., headers={...}).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from alfred.config.settings import Settings

_log = structlog.get_logger(__name__)


class EgressClient:
    def __init__(self, *, proxy_url: str | None) -> None:
        self._proxy_url = proxy_url

    @classmethod
    def from_settings(cls, settings: Settings) -> EgressClient:
        return cls(proxy_url=settings.egress_proxy_url)

    @property
    def proxy_url(self) -> str | None:
        return self._proxy_url

    def build_provider_http_client(self) -> httpx.AsyncClient | None:
        if self._proxy_url is None:
            # G7-3: DELETE this direct-egress fallback atomically with internal:true (#333).
            _log.info("egress.client.direct")  # never silent
            return None
        _log.info("egress.client.proxied", proxy_url=self._proxy_url)
        return httpx.AsyncClient(proxy=self._proxy_url, follow_redirects=False)


__all__ = ["EgressClient"]
```

- [ ] **Step 5: Add `egress/client.py` to the import-guard `_CONSTRUCT_ALLOWLIST`** in `tests/unit/egress/test_in_core_http_egress_guard.py`:

```python
_CONSTRUCT_ALLOWLIST: dict[str, str] = {
    "egress/client.py": "the sanctioned in-core egress seam — builds the proxied httpx.AsyncClient (Spec C G7-1)",
}
```

- [ ] **Step 6: Extend BOTH egress CI gates** to add `src/alfred/egress/client.py` to the `--include` list (in the `python` AND `coverage-gates` jobs).

- [ ] **Step 7: Run** — `uv run pytest tests/unit/egress/ -v` → PASS (the import-guard stays green now that `client.py` is allowlisted).

- [ ] **Step 8: Commit** — `feat(egress): in-core EgressClient factory (proxied httpx client) (#333)`.

---

### Task A4: Re-point both providers through the injected `http_client`

**Files:** Modify `providers/anthropic_native.py`, `providers/deepseek.py`, `cli/_bootstrap.py`, `tests/unit/providers/test_anthropic.py` `[rev: prov-008 — the real path is test_anthropic.py, NOT test_anthropic_native.py]`, `tests/unit/providers/test_deepseek.py`.

**Interfaces:**

- `AnthropicProvider.from_settings(cls, api_key, model, *, http_client: httpx.AsyncClient | None = None)`
- `DeepSeekProvider.from_settings(cls, api_key, base_url, model, *, http_client: httpx.AsyncClient | None = None)`

- [ ] **Step 1: Write the failing provider tests.** In `tests/unit/providers/test_anthropic.py`:

```python
def test_from_settings_passes_http_client_and_preserves_retries(monkeypatch) -> None:
    import alfred.providers.anthropic_native as mod

    captured: dict[str, object] = {}
    monkeypatch.setattr(mod, "AsyncAnthropic", lambda **kw: captured.update(kw) or object())
    sentinel = object()
    mod.AnthropicProvider.from_settings(api_key="k", model="claude-sonnet-4-6", http_client=sentinel)
    assert captured["http_client"] is sentinel
    assert captured["max_retries"] == 2  # rider 4: SDK-level retry preserved


def test_from_settings_default_passes_none_http_client(monkeypatch) -> None:
    """Behaviour-neutral default: http_client=None => SDK builds its own (today's path)."""
    import alfred.providers.anthropic_native as mod

    captured: dict[str, object] = {}
    monkeypatch.setattr(mod, "AsyncAnthropic", lambda **kw: captured.update(kw) or object())
    mod.AnthropicProvider.from_settings(api_key="k", model="claude-sonnet-4-6")
    assert captured["http_client"] is None
```

Add the analogous `test_from_settings_passes_http_client` + `test_from_settings_default_passes_none_http_client` to `tests/unit/providers/test_deepseek.py` (patch `AsyncOpenAI`, assert `captured["http_client"]` + `captured["base_url"] == "https://api.deepseek.com/v1"`) `[rev: test-008]`.

- [ ] **Step 2: Run** → FAIL (`unexpected keyword argument 'http_client'`).

- [ ] **Step 3: Thread `http_client` through both providers.** Anthropic `from_settings`:

```python
    @classmethod
    def from_settings(
        cls, api_key: str, model: str, *, http_client: httpx.AsyncClient | None = None
    ) -> AnthropicProvider:
        # http_client is the G7-1 egress seam: a proxied client when the gateway proxy
        # is configured, None => direct (today's behaviour). timeout + max_retries STAY
        # on the SDK ctor (rider 4): the SDK applies timeout per-request and never
        # inherits max_retries from the http_client.
        return cls(
            client=AsyncAnthropic(
                api_key=api_key, timeout=_HTTP_TIMEOUT, max_retries=2, http_client=http_client
            ),
            model=model,
        )
```

DeepSeek `from_settings`:

```python
    @classmethod
    def from_settings(
        cls, api_key: str, base_url: str, model: str, *, http_client: httpx.AsyncClient | None = None
    ) -> DeepSeekProvider:
        # See AnthropicProvider.from_settings. max_retries left at the SDK default (2),
        # same effective posture as Anthropic's explicit value (rider 4).
        return cls(
            client=AsyncOpenAI(
                api_key=api_key, base_url=base_url, timeout=_HTTP_TIMEOUT, http_client=http_client
            ),
            model=model,
        )
```

- [ ] **Step 4: Wire the EgressClient into `build_router`** in `cli/_bootstrap.py` (add `from alfred.egress.client import EgressClient` near the provider imports):

```python
def build_router(broker: SecretBroker, settings: Settings) -> ProviderRouter:
    """Build the slice-1 ProviderRouter from the broker's secrets.

    Spec C G7-1 (#333): when ALFRED_EGRESS_PROXY_URL is set the providers get a
    proxied http_client pointed at the gateway L7 CONNECT proxy; unset => direct.
    One proxied client per provider is intentional (no cross-provider pool sharing
    in G7-1); the EgressClient is a stateless factory and the SDK/process owns each
    client's lifetime (open-decision 3).
    """
    egress = EgressClient.from_settings(settings)
    primary: Provider = DeepSeekProvider.from_settings(
        api_key=broker.get("deepseek_api_key"),
        base_url=settings.deepseek_base_url,
        model=settings.deepseek_model,
        http_client=egress.build_provider_http_client(),
    )
    fallback: Provider | None = None
    if broker.has("anthropic_api_key"):
        fallback = AnthropicProvider.from_settings(
            api_key=broker.get("anthropic_api_key"),
            model=settings.anthropic_model,
            http_client=egress.build_provider_http_client(),
        )
    return ProviderRouter(primary=primary, fallback=fallback)
```

- [ ] **Step 5: Run** — `uv run pytest tests/unit/providers/ -k "http_client or default" -v` + the full provider + bootstrap suites → PASS.

- [ ] **Step 6: Commit** — `feat(providers): inject proxied http_client via EgressClient seam (#333)`.

---

### Task A5: Quarantine child `--unshare-net` (re-pivots release-blocking adversarial gates)

> **`[rev: arch-001, sec-001, test-001 — CRITICAL]`** This task re-pivots the whole premise of `tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py` (egress OPEN → CLOSED for the echo child). Read the WHOLE file first and enumerate the gates. The exact gates that change/stay:
>
> - **INVERT + RENAME** `test_gate_is_anchored_to_the_open_egress_state` (line ~445, asserts `re.search(r'unshare...\"net\"', body) is None`) → `test_gate_is_anchored_to_the_closed_egress_state`, assertion `is not None`.
> - **KEEP GREEN** `test_open_egress_is_documented_against_230` (line ~469, parametrized over the policy file + `config/sandbox/README.md`, asserts `"#230" in text`) — the new policy note + README keep a `#230` reference (the remaining 2c real-LLM egress is still #230), so update the README prose to "egress CLOSED for the echo child; #230 tracks the 2c real-LLM provider-only path" and the test stays green.
> - **KEEP INTACT** `test_quarantined_child_has_no_module_scope_egress_import` (line ~379) — the echo child still imports no egress module; this is the import-graph teeth, do NOT touch.
> - **KEEP + RECONCILE NAME** `test_only_sanctioned_quarantined_llm_spawn_while_egress_open` (line ~399) and `test_sanctioned_spawn_site_actually_exists` (line ~427) — the spawn-site detector is egress-state-independent; update the docstring/name to drop the now-false "while egress open" premise.
> - **FLIP THE CORPUS** `sbx_2026_005_outbound_network_unrestricted.yaml` + `test_sbx_corpus_executable.py` per spec §9: from `out_of_scope` → enforced containment, and invert its "net not in policy.unshare" tripwire (it now asserts net IS unshared). `[rev — the original plan mis-deferred this to G7-4; spec §9 ties it to "when the child gets --unshare-net" = now.]`

**Files:** Modify `config/sandbox/quarantined-llm.linux.bwrap.policy`, `config/sandbox/README.md`, the adversarial sandbox-escape test file, `sbx_2026_005_outbound_network_unrestricted.yaml`, `test_sbx_corpus_executable.py`.

- [ ] **Step 1: Read the whole adversarial file + the corpus yaml + README** to enumerate the exact gates and the `#230` references (the line numbers above are from the 2026-06-26 tree; confirm).

- [ ] **Step 2: Write the failing inverted gate (TDD).** Invert + rename `test_gate_is_anchored_to_the_open_egress_state`:

```python
def test_gate_is_anchored_to_the_closed_egress_state() -> None:
    """Spec C G7-1 (#333): the deterministic-echo quarantine child unshares net.

    The echo child needs ZERO network, so --unshare-net closes the #230 egress hole
    NOW. The 2c real-LLM child (separate follow-on, still #230) re-opens a
    PROVIDER-ONLY path via the gateway L7 proxy — NOT a relaxation of this gate.
    """
    body = _REAL_POLICY.read_text(encoding="utf-8")
    assert re.search(r'unshare\s*=\s*\[[^\]]*"net"', body) is not None, (
        "the quarantine policy must now unshare net (egress closed, Spec C G7-1)"
    )
```

- [ ] **Step 3: Run it** → FAIL (policy has no `"net"` yet).

- [ ] **Step 4: Add `"net"` + rewrite the egress note** in `config/sandbox/quarantined-llm.linux.bwrap.policy` (line ~68): `unshare = ["pid", "uts", "cgroup", "ipc", "net"]`. Replace the `!! EGRESS IS CURRENTLY UNRESTRICTED !!` block with a CLOSED note that KEEPS a `#230` reference for the 2c work (so `test_open_egress_is_documented_against_230` stays green), and update `config/sandbox/README.md` correspondingly (egress closed for the echo child; #230 = the 2c provider-only path).

- [ ] **Step 5: Flip the corpus.** Update `sbx_2026_005_outbound_network_unrestricted.yaml` (out_of_scope → enforced; invert the net-unshare tripwire) + reconcile `test_sbx_corpus_executable.py`. Update the two spawn-site gate names/docstrings.

- [ ] **Step 6: Run the targeted gates + the FULL adversarial suite (release-blocking):**

```bash
uv run pytest tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py -v
uv run pytest tests/unit/plugins/test_sandbox_policy_translator.py -k unshare_net -v
uv run pytest tests/adversarial -q
```

Expected: PASS. If any other gate depended on the child having open egress, surface it — do NOT weaken it.

- [ ] **Step 7: Commit** — `feat(sandbox): quarantine child --unshare-net closes #230 egress half (#333)`. Include a security-engineer adjudication note in the PR (mirror the 2b0 re-pivot precedent).

---

## Part B — Gateway L7 CONNECT forward-proxy + the flip (G7-1b)

> **Hard task order: B1 → B2 → B4 → B3 → B5** (the compose proxy-URL flip is LAST, after the proxy exists + is mounted + audits).

### Task B1: The L7 CONNECT forward-proxy listener

**Files:** Create `src/alfred/gateway/egress_proxy.py`, `tests/unit/gateway/test_egress_proxy.py`; Modify `.github/workflows/ci.yml` (two-gates for `egress_proxy.py`).

**Interfaces:**

- `EgressForwardProxy(*, allowlist: frozenset[EgressDestination], bind_host: str, port: int, audit: Callable[[str, dict[str, object]], None], resolve: Callable[[str], str] = ..., open_upstream: Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]] = ...)`
- `async EgressForwardProxy.serve(self, shutdown_event: asyncio.Event) -> None`
- `resolve_egress_proxy_port() -> int` (env `ALFRED_EGRESS_PROXY_PORT`, default `8889`); `resolve_egress_proxy_bind() -> str` (env `ALFRED_EGRESS_PROXY_BIND`, default `0.0.0.0`).

**Contract the implementer must satisfy (100% line+branch from UNIT tests so the combined gate never depends on integration coverage)** `[rev: test-005, devops-002]`:

- `serve` binds `asyncio.start_server`; the bind is **fail-closed** — an `OSError` propagates (mapped to `IOPlaneUnavailableError` in B2). Serves until `shutdown_event`, then closes + reaps in-flight.
- Read ONE request line, **bounded** (`readuntil(b"\r\n\r\n", max=…)` with a small cap + a per-handshake read timeout). Parse `CONNECT <authority> HTTP/1.1`. The **request-line authority is the SOLE allowlist source — never the `Host:` header** `[rev: sec-004]`. Oversized/timeout/malformed → `400`, audit `gateway.egress.connect_denied` reason `malformed_connect`, close.
- `is_literal_ip(host)` → `403`, reason `literal_ip_target`.
- `(host, port) not in allowlist` → `403`, reason `destination_not_allowlisted`.
- Resolve gateway-side (`resolve(host)`). If `not is_globally_routable(resolved_ip)` → `403`, reason `resolved_ip_not_global` `[rev: sec-003]`.
- Else open upstream to the **resolved IP**, reply `200 Connection Established`, audit `gateway.egress.connect_allowed`, splice bidirectionally with `await asyncio.sleep(0)` yields between chunks (incremental — must NOT buffer-until-EOF, so streaming survives `[rev: prov-007]`). Reap both directions on either EOF.
- Each connection is its own task. A module Prometheus `Counter` `GATEWAY_EGRESS_CONNECT{outcome}` (allowed/denied) on the default registry (auto-served by the existing `/metrics`); the metric NAME is provisional (G7-5 owns the canonical set).

- [ ] **Step 1: Write the failing tests** — `tests/unit/gateway/test_egress_proxy.py`. Provide a **concrete** one-shot upstream fixture (not a stub) and thread its address as a param `[rev: test-004, rev-004]`:

```python
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest


@pytest.fixture
async def fake_upstream() -> AsyncIterator[tuple[str, int]]:
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"UPSTREAM-OK")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    async with server:
        yield host, port


async def _connect(proxy_port: int, target: str, upstream: tuple[str, int]):
    from alfred.gateway.egress_proxy import EgressForwardProxy

    audit: list[tuple[str, dict]] = []

    async def _open(_ip: str, _port: int):
        return await asyncio.open_connection(*upstream)

    proxy = EgressForwardProxy(
        allowlist=frozenset({("api.anthropic.com", 443)}),
        bind_host="127.0.0.1",
        port=proxy_port,
        audit=lambda event, fields: audit.append((event, fields)),
        resolve=lambda _h: "1.1.1.1",  # globally routable
        open_upstream=_open,
    )
    shutdown = asyncio.Event()
    serve_task = asyncio.ensure_future(proxy.serve(shutdown))
    await asyncio.sleep(0.05)
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    await writer.drain()
    resp = await reader.read(2048)
    writer.close()
    shutdown.set()
    await serve_task
    return resp, audit


@pytest.mark.asyncio
async def test_connect_allowlisted_succeeds(fake_upstream) -> None:
    resp, audit = await _connect(8951, "api.anthropic.com:443", fake_upstream)
    assert b"200" in resp
    assert any(e == "gateway.egress.connect_allowed" for e, _ in audit)


@pytest.mark.asyncio
async def test_connect_non_allowlisted_denied(fake_upstream) -> None:
    resp, audit = await _connect(8952, "evil.example:443", fake_upstream)
    assert b"403" in resp
    assert any(f.get("reason") == "destination_not_allowlisted" for _, f in audit)


@pytest.mark.asyncio
async def test_connect_literal_ip_denied(fake_upstream) -> None:
    resp, audit = await _connect(8953, "1.2.3.4:443", fake_upstream)
    assert b"403" in resp
    assert any(f.get("reason") == "literal_ip_target" for _, f in audit)


# Implementer: ADD cases to reach 100% line+branch [rev: test-005]:
#   - malformed CONNECT line -> 400 / malformed_connect
#   - resolve() returns a private IP (e.g. 127.0.0.1) -> 403 / resolved_ip_not_global
#   - mid-flight shutdown (set shutdown_event while a connection is open) -> clean reap
#   - upstream-initiated EOF closes the client side
#   - bind failure: serve() on an already-bound port raises OSError (fail-closed)
```

- [ ] **Step 2: Run** → FAIL (`No module named 'alfred.gateway.egress_proxy'`).

- [ ] **Step 3: Implement `EgressForwardProxy`** per the contract above + `resolve_egress_proxy_port`/`resolve_egress_proxy_bind` (mirror `metrics_server.resolve_metrics_port`; loud `ValueError` on a bad port).

- [ ] **Step 4: Run + 100% locally** — `uv run pytest tests/unit/gateway/test_egress_proxy.py -v` then `uv run coverage run -m pytest tests/unit/gateway/test_egress_proxy.py && uv run coverage report --include='src/alfred/gateway/egress_proxy.py' --fail-under=100` → 100%.

- [ ] **Step 5: Two-gates CI** for `src/alfred/gateway/egress_proxy.py` (both jobs, correct guards).

- [ ] **Step 6: Commit** — `feat(gateway): L7 CONNECT forward-proxy with destination allowlist + resolved-IP guard (#333)`.

---

### Task B2: Mount the proxy in the gateway process (fail-closed)

**Files:** Modify `src/alfred/cli/gateway/_commands.py`; Create `tests/unit/cli/gateway/test_egress_proxy_mount.py`; Modify `locale/en/LC_MESSAGES/alfred.{po,mo}` + extend `G7_EGRESS_KEYS`.

- [ ] **Step 1: Write the failing test** — assert `_main()` builds an `EgressForwardProxy` with the settings-derived allowlist and runs it concurrently with `GatewayProcess.run()`, and that a bind `OSError` surfaces as `IOPlaneUnavailableError` → the mapped friendly exit. Use a temporary inline audit sink so B2 is runnable BEFORE B4 `[rev: test-007]`.

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Mount it** inside `_main()` under a `TaskGroup` so a proxy bind failure aborts the start fail-closed:

```python
        from alfred.config.settings import Settings
        from alfred.egress.allowlist import provider_egress_allowlist
        from alfred.gateway.egress_audit import record_egress_connect  # B4
        from alfred.gateway.egress_proxy import (
            EgressForwardProxy, resolve_egress_proxy_bind, resolve_egress_proxy_port,
        )

        settings = Settings()  # type: ignore[call-arg]
        proxy = EgressForwardProxy(
            allowlist=provider_egress_allowlist(settings),
            bind_host=resolve_egress_proxy_bind(),
            port=resolve_egress_proxy_port(),
            audit=record_egress_connect,  # B4 provides this; until B4 lands, a structlog stub
        )
        async with asyncio.TaskGroup() as tg:
            tg.create_task(proxy.serve(shutdown_event))
            tg.create_task(GatewayProcess(
                shutdown_event=shutdown_event, dial_adapter_id=dial_adapter_id,
                adapter_ids=hosted_adapter_ids,
            ).run())
```

Map a proxy-bind `OSError` to a friendly `IOPlaneUnavailableError` refusal in `start_gateway`'s `try/except` (new exit code + `t("gateway.start.egress_proxy_bind_failed")`). Document that this refuses the start → the gateway **crash-loops under `restart: unless-stopped`** (intended fail-closed I/O-plane posture; contrast metrics' loud-and-continue) `[rev: devops-004]`.

- [ ] **Step 4: i18n** — add `gateway.start.egress_proxy_bind_failed` to the catalog + `G7_EGRESS_KEYS`; run the pybabel flow.

- [ ] **Step 5: Run + lint/type** → PASS / clean.

- [ ] **Step 6: Commit** — `feat(gateway): mount the egress forward-proxy fail-closed in the process (#333)`.

---

### Task B4: Gateway-local egress audit (structlog + counter) `[rev: sec-002]`

> The gateway holds **no DB session and no signing key** (confirmed in `ingress_audit.py`: "Gateway audit is structlog-only … the gateway holds no signing key"). So G7-1 ships the **gateway-local structlog tier** + the counter, modelled on `record_ingress_refusal` + the closed-vocab `IngressRefusalReason` enum. The **durable signed reconcile into the core log is DEFERRED** as an honest residual (recorded in ADR-0040 at G7-5, mirroring the G6-2b durable-audit disposition) — G7-1 does NOT claim hard-rule-7 durable audit on this path.

**Files:** Create `src/alfred/gateway/egress_audit.py` (with a closed-vocab `EgressConnectOutcome`/reason enum + `record_egress_connect(event, fields)` + `reason_i18n_key`), `tests/unit/gateway/test_egress_audit.py`; Modify `_commands.py` (use it), `alfred.po/.mo` + `G7_EGRESS_KEYS` (the rendered reason presentations through `t()`; tokens stay English).

- [ ] **Step 1–4:** TDD a closed-vocab reason enum (`destination_not_allowlisted`, `literal_ip_target`, `resolved_ip_not_global`, `malformed_connect`) so tokens can't drift; a `record_egress_connect` structlog emitter field-allowlisted to `{destination, reason}` only (never a body / Host header / IP beyond the destination); rendered presentations via `t()`. Replace B2's inline stub with `record_egress_connect`. Two-gates CI for `egress_audit.py`. Run.

- [ ] **Step 5: Commit** — `feat(gateway): gateway-local egress CONNECT/deny audit (structlog tier) (#333)`.

---

### Task B3: Compose wiring + the "never host-published" invariant (LAST in B)

**Files:** Modify `docker-compose.yaml`, `.env.example`, `tests/unit/test_compose_invariants.py`.

- [ ] **Step 1: Write the failing compose-invariant tests** — strengthen beyond a substring check; the existing `test_alfred_gateway_publishes_no_host_port` (line ~297) is the primary gateway guard, so this is defense-in-depth across ALL services parsing the host side of each mapping `[rev: devops-003, rev-006, sec-006]`:

```python
def test_egress_proxy_port_never_host_published(compose: dict[str, Any]) -> None:
    """G7-1 rider 1: no service host-publishes the egress container port."""
    proxy_port = 8889
    for name, svc in (compose.get("services", {}) or {}).items():
        for mapping in svc.get("ports", []) or []:
            parts = str(mapping).split(":")
            container_port = parts[-1].split("/")[0]
            assert container_port != str(proxy_port), (
                f"{name} host-publishes the egress proxy container port {proxy_port}; "
                "the egress proxy must stay compose-internal (Spec C G7-1 rider 1)."
            )


def test_core_routes_egress_through_gateway_proxy(compose: dict[str, Any]) -> None:
    env = (compose["services"]["alfred-core"].get("environment", {})) or {}
    assert "alfred-gateway" in str(env.get("ALFRED_EGRESS_PROXY_URL", "")), (
        "alfred-core must route provider egress through the gateway proxy in G7-1"
    )
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Wire compose.** `alfred-core.environment`:

```yaml
      # Spec C G7-1 (#333): route provider egress through the gateway L7 CONNECT proxy.
      # UNSET => direct egress (dev / pre-G7-3 fallback). Compose-internal (never
      # host-published). G7-3 makes this mandatory + deletes the direct fallback.
      ALFRED_EGRESS_PROXY_URL: ${ALFRED_EGRESS_PROXY_URL:-http://alfred-gateway:8889}
```

`alfred-gateway.environment`:

```yaml
      ALFRED_EGRESS_PROXY_PORT: ${ALFRED_EGRESS_PROXY_PORT:-8889}
      # The gateway derives the egress allowlist from the SAME provider config as the
      # core, so an operator base_url override must reach BOTH (else a silent mismatch).
      ALFRED_DEEPSEEK_BASE_URL: ${ALFRED_DEEPSEEK_BASE_URL:-https://api.deepseek.com/v1}
```

Add `.env.example` entries for `ALFRED_EGRESS_PROXY_URL`, `ALFRED_EGRESS_PROXY_PORT`, `ALFRED_EGRESS_PROXY_BIND`, `ALFRED_DEEPSEEK_BASE_URL` `[rev: devops-008]`. Do NOT add a `ports:` mapping for 8889; do NOT add `depends_on`.

- [ ] **Step 4: Run + validate** — `uv run pytest tests/unit/test_compose_invariants.py -v && docker compose config --quiet && echo "compose OK"` (skip the live probe + say so if docker is unavailable).

- [ ] **Step 5: Commit** — `feat(compose): route core egress through the gateway proxy (internal-only) (#333)`.

---

### Task B5: Integration proof (core → proxy → fake upstream) + docs

**Files:** Create the end-to-end proxy proof test; Modify `.rulesync/rules/CLAUDE.md` (egress note — **human-gated**, `rulesync generate`, flag for maintainer approval); Modify the spec doc (a §3 plan-reconciliation note placed **at §3** `[rev: arch-007]`).

> Place the proof where it does NOT pull in the testcontainers Postgres fixture unnecessarily — it needs only loopback sockets `[rev: test-006]`. `egress_proxy.py`'s 100% coverage is already reached by the B1 UNIT tests, so this test is an end-to-end PROOF, not a coverage dependency. Put it under `tests/unit/egress/` (or a socket-only tier) unless the integration conftest fixtures are confirmed opt-in.

- [ ] **Step 1: Write the proof** — stand up the real `EgressForwardProxy` on loopback + a fake upstream; build `EgressClient(proxy_url="http://127.0.0.1:<port>")`, issue a request through the proxied client; assert (a) an allowlisted CONNECT is spliced and the proxy forwards opaque bytes it never parses (payload-blindness), (b) a non-allowlisted CONNECT is refused (403 / `EgressDeniedError`), (c) a **chunked** upstream response is observed by the client incrementally BEFORE upstream EOF (streaming survives the splice `[rev: prov-007]`), (d) audit rows land.

- [ ] **Step 2: Run** → PASS.

- [ ] **Step 3: Docs** — the spec §3 plan-reconciliation note (at §3): "G7-1 implements the egress channel as a TCP CONNECT proxy on `alfred_internal` (peer-auth by network membership); the §3 unix-socket text describes the Spec A/B comms wire; ADR-0040 (G7-5) is the authoritative reconciliation." Prepare the `.rulesync/rules/CLAUDE.md` egress note + `rulesync generate -t <active-tool> -f '*'`; flag the CLAUDE.md change for maintainer approval (human-gated, NOT self-merged).

- [ ] **Step 4: `make check` + `make docs-check`** → green.

- [ ] **Step 5: Commit** — the proof: `test(egress): end-to-end provider forward-proxy mode-a proof (#333)`. The spec-doc §3 note in its OWN commit `docs(spec): reconcile §3 egress-channel transport to the TCP proxy (#333)` `[rev: arch-006]`. The `.rulesync` CLAUDE.md change committed separately AFTER maintainer approval.

---

## Definition of Done

- `src/alfred/egress/` has `errors.py`, `allowlist.py`, `client.py`; `src/alfred/gateway/` gains `egress_proxy.py` + `egress_audit.py`. Each of the five new security-boundary files has a named 100% line+branch gate in BOTH the `python` and `coverage-gates` CI jobs. `egress/client.py` is in the import-guard `_CONSTRUCT_ALLOWLIST`.
- Both providers accept an injected `http_client`; `build_router` wires the stateless `EgressClient`; with `ALFRED_EGRESS_PROXY_URL` unset, provider construction is byte-for-byte today's direct path (default-None test pins it).
- The quarantine policy runs `--unshare-net`; the inverted gate + the kept gates + the flipped `sbx-2026-005` corpus all pass; the FULL adversarial suite passes; a security adjudication note is in the PR.
- The gateway serves an L7 CONNECT forward-proxy: allowlist-enforced, refuse-literal-IP, gateway-resolves-DNS, reject-non-global-resolved-IP, request-line-authority-only, bounded reads, fail-closed bind → crash-loop, incremental (streaming-preserving) splice, payload-blind, gateway-locally audited; mounted in the gateway process; never host-published (compose-invariant); the core routes through it in compose.
- The gateway audit is the structlog tier with a closed-vocab reason enum; the durable signed reconcile is deferred as an ADR-0040 residual (NOT claimed delivered).
- The two typed errors + the egress audit-reason presentations + the egress CLI text go through `t()`; `G7_EGRESS_KEYS` enumerates them all; the i18n drift gate passes.
- `make check` + `make docs-check` green; the end-to-end proof passes. Commits Conventional + `#333` + trailers, single-responsibility. The `.rulesync` CLAUDE.md egress note staged for human approval (NOT self-merged). The pre-G7-3 `0.0.0.0`-bind window and the direct-fallback deletion are recorded as G7-3 must-closes.

## Self-Review

- **Spec coverage (§11 G7-1):** EgressClient seam ✅(A3); typed errors ✅(A1); gateway L7 CONNECT proxy mode-a ✅(B1–B2); per-client `http_client=AsyncClient(proxy=...)` on both providers ✅(A4); import-guard construct-allowlist entry ✅(A3); live-config allowlist ✅(A2); T2 carve-out — provider responses re-enter as assistant output (T2), the proxy is destination-only/payload-blind, no T3 tagging introduced (asserted in B5); quarantine `--unshare-net` ✅(A5). The §3 "egress channel socket lifecycle" is reconciled to the TCP proxy (Locked transport decision); no separate persistent control channel is built (mode-b framing is G7-2).
- **Placeholder scan:** the only deferrals are scoped + named (A5 Step 1 reads the file to confirm line numbers; the B1 contract lists the exact extra coverage cases). The previously-stubbed `_fake_upstream_addr` is now a concrete fixture; the previously-vague B4 is now a concrete structlog-tier task with a closed enum.
- **Type consistency:** `EgressClient.build_provider_http_client` (A3) == the name `build_router` calls (A4); `provider_egress_allowlist`/`is_literal_ip`/`is_globally_routable`/`EgressDestination` (A2) == the names B1 imports; the `http_client` kwarg; the `ALFRED_EGRESS_PROXY_{URL,PORT,BIND}` env names; `record_egress_connect` (B4) == the sink B2 wires; `EgressDeniedError(deny_reason=...)` consistent A1↔B-deny-paths.
- **All `[rev]` findings folded:** the 2 Criticals (A5 real-gate targeting; two-gates CI), the Highs (audit honest-tier; resolved-IP-global; B1 coverage cases + concrete fixture; CONNECT request-line authority + bounded reads; `allowlist.py` gate), and the Mediums/Lows (stateless-factory aclose; `deny_reason` rename; streaming proof; provider test path/default-None; anthropic drift note; compose test strengthening; env naming; docs commit split; §3 note placement; B-part ordering). Open decisions 1–3 resolved with reviewer-concurred rationale.

## Execution Handoff

Plan revised and re-reviewed. Per the program cadence the next step is **subagent-driven TDD** (G7-1a first: A1→A5; then G7-1b: B1→B5 in order), then a full `/review-pr` fleet + CodeRabbit, resolve every thread, plain `gh pr merge --rebase`.
