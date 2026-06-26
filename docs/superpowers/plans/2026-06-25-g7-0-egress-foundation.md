# G7-0 — Egress-Plane Foundation (topology + structural gates) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the connectivity-free-core *structural foundation* — the two-network Docker topology and the two always-on merge gates (a compose-invariant lint and an in-core HTTP-egress import-guard) — with **zero external-behaviour change**, so every later G7 PR is structurally guarded from the first commit.

**Architecture:** Spec C ([2026-06-25-spec-c-egress-control-plane-design](../specs/2026-06-25-spec-c-egress-control-plane-design.md), epic #333) makes the core connectivity-free and the gateway the sole egress plane. This first PR is pure scaffolding: it defines two custom networks (`alfred_internal`, `alfred_external`) and attaches services to them **behaviour-neutrally** — both networks stay internet-reachable and the core stays on both, so nothing breaks. The **isolation flip is one atomic change at G7-3**: adding `internal: true` to `alfred_internal` AND removing `alfred_external` from the core. Splitting it is unsafe — `internal: true` here breaks the `alfred-postgres` host-published port on Docker Desktop/macOS (an internal-only container is not port-forwarded there; **verified live during execution**) before the gateway proxy that justifies the isolation even exists. G7-0 adds a compose-invariant test pinning the network *membership* (the two isolation assertions are present but skipped, pointing at G7-3) and an AST import-guard test forbidding *new* in-core external-HTTP-egress clients (baseline-allowlisting today's two provider files). Both tests live in the already-required `tests/unit` lane, so they gate `main` immediately. The `EgressClient` seam, the typed egress errors, and the provider forward-proxy are deferred to **G7-1** (they need a real implementation + consumer; defining them here would be dead code).

**Tech Stack:** Python 3.12+, pytest, PyYAML (`yaml.safe_load`), the stdlib `ast` module, Docker Compose. No new dependencies.

## Global Constraints

- **Python 3.12+**; `mypy --strict` + `pyright` clean; `ruff check` + `ruff format` clean. (Verbatim from CLAUDE.md tech stack.)
- **No `--no-verify`, no pre-commit-hook skipping.** (CLAUDE.md security rule 8.)
- **Conventional Commits** with a `#NNN` issue ref in every commit subject — use `(#333)` (the epic). Pattern: `^[a-z]+(\([^)]+\))?(!)?: .*#[0-9]+.*$`.
- **`make check` before every push** (lint + format + type + unit). **`make docs-check`** additionally for any docs change.
- **No behaviour change in G7-0** — the core must retain external reachability after this PR (the net-flip is G7-3). Any task that would cut the core off is out of scope here.
- **No new third-party dependency** (PyYAML and `ast` are already available).
- This PR touches **no** `src/alfred/security/*` file, so the 100%-coverage security gate is not triggered; do not add files there.

---

### Task 1: Two-network Docker topology + compose-invariant lint

Define the two custom networks and attach every service, keeping every service internet-reachable (no isolation yet). Pin the network *membership* with compose-invariant tests in the already-required unit lane. The two assertions that encode the actual isolation — `alfred_internal.internal == true` and *core is NOT on `alfred_external`* — are deferred to G7-3 (where they flip atomically) with documented skipped tests, so the intent is recorded without breaking G7-0.

**Files:**

- Modify: `docker-compose.yaml` (add top-level `networks:` block; add `networks:` to each of `alfred-postgres`, `alfred-redis`, `alfred-core`, `alfred-gateway`)
- Modify: `tests/unit/test_compose_invariants.py` (append new test functions)

**Interfaces:**

- Consumes: nothing (first task).
- Produces: the compose topology contract that G7-3 tightens — networks `alfred_internal` and `alfred_external`; `alfred-core` ∈ {both} (G7-3 removes `alfred_external` + adds `internal: true`); `alfred-gateway` ∈ {both}; datastores ∈ {`alfred_internal`}. Test names: `test_two_custom_networks_defined`, `test_gateway_joins_both_networks`, `test_datastores_join_internal_only`, `test_core_joins_internal` (active); `test_alfred_internal_is_internal_true_deferred_to_g7_3` + `test_core_not_on_external_deferred_to_g7_3` (skipped, un-skip at G7-3).

- [ ] **Step 1: Write the failing compose-invariant tests**

Append to `tests/unit/test_compose_invariants.py`:

```python
def test_two_custom_networks_defined(compose: dict[str, Any]) -> None:
    """G7-0 (Spec C §3): the two egress-plane networks exist."""
    networks = compose.get("networks", {})
    assert set(networks) >= {"alfred_internal", "alfred_external"}, (
        "Spec C requires custom networks alfred_internal + alfred_external; "
        f"got {sorted(networks)}."
    )


@pytest.mark.skip(
    reason="G7-3 adds internal:true to alfred_internal as ONE atomic isolation flip with "
    "removing alfred_external from alfred-core. G7-0 keeps both networks internet-reachable "
    "(behaviour-neutral) — internal:true here breaks the alfred-postgres host-published port "
    "on Docker Desktop/macOS before the proxy that justifies it exists."
)
def test_alfred_internal_is_internal_true_deferred_to_g7_3(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §3, §6): alfred_internal must be internal:true (no route to the internet).

    The kernel enforcement-of-record for the connectivity-free core; un-skip and make it pass
    in the G7-3 PR (together with test_core_not_on_external_deferred_to_g7_3).
    """
    internal = compose.get("networks", {}).get("alfred_internal", {}) or {}
    assert internal.get("internal") is True, (
        "alfred_internal must set 'internal: true' so attached services have no "
        f"route to the internet; got {internal!r}."
    )


def _service_networks(compose: dict[str, Any], service: str) -> set[str]:
    svc = compose.get("services", {}).get(service, {}) or {}
    nets = svc.get("networks", []) or []
    # Compose allows networks as a list OR a mapping; set() over either yields the
    # network-name set (set(dict) is its keys).
    return set(nets)


def test_gateway_joins_both_networks(compose: dict[str, Any]) -> None:
    """G7-0 (Spec C §3): the gateway is the bridge — it joins both networks."""
    nets = _service_networks(compose, "alfred-gateway")
    assert nets >= {"alfred_internal", "alfred_external"}, (
        f"alfred-gateway must join both networks (it is the egress chokepoint); got {sorted(nets)}."
    )


def test_datastores_join_internal_only(compose: dict[str, Any]) -> None:
    """G7-0 (Spec C §3): datastores never touch alfred_external."""
    for service in ("alfred-postgres", "alfred-redis"):
        nets = _service_networks(compose, service)
        assert nets == {"alfred_internal"}, (
            f"{service} must join alfred_internal ONLY (never alfred_external); got {sorted(nets)}."
        )


def test_core_joins_internal(compose: dict[str, Any]) -> None:
    """G7-0 (Spec C §3): the core is on alfred_internal (reaches datastores + the gateway)."""
    nets = _service_networks(compose, "alfred-core")
    assert "alfred_internal" in nets, (
        f"alfred-core must join alfred_internal; got {sorted(nets)}."
    )


@pytest.mark.skip(
    reason="G7-3 removes alfred_external from alfred-core once the gateway proxy exists; "
    "G7-0 keeps the core externally reachable (no behaviour change)."
)
def test_core_not_on_external_deferred_to_g7_3(compose: dict[str, Any]) -> None:
    """G7-3 (Spec C §11): the connectivity-free flip — core must NOT be on alfred_external.

    Recorded now so the intent is tracked; un-skip and make it pass in the G7-3 PR.
    """
    nets = _service_networks(compose, "alfred-core")
    assert "alfred_external" not in nets, (
        f"alfred-core must NOT join alfred_external (connectivity-free core); got {sorted(nets)}."
    )
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/unit/test_compose_invariants.py -k "two_custom_networks or gateway_joins_both or datastores_join_internal or core_joins_internal" -v`
Expected: FAIL — `alfred_internal`/`alfred_external` not defined; `networks` key absent on services (the empty-set assertions trip). The two `*_deferred_to_g7_3` tests report SKIPPED.

- [ ] **Step 3: Add the networks block + service attachments to `docker-compose.yaml`**

Add a top-level `networks:` block (place it beside the existing top-level `volumes:` block):

```yaml
networks:
  # Spec C / G7 (epic #333, ADR-0040): the connectivity-free-core split. G7-0
  # lays down the network MEMBERSHIP only — core + datastores on alfred_internal,
  # the gateway on both — behaviour-neutrally (both networks reach the internet
  # for now, exactly like today's default bridge). The ISOLATION FLIP is a single
  # atomic step at G7-3: add `internal: true` to alfred_internal AND remove
  # alfred_external from alfred-core. It is deliberately NOT split across PRs —
  # `internal: true` here would break the alfred-postgres host-published port on
  # Docker Desktop (verified: an internal-only container is not port-forwarded on
  # macOS), regressing dev/setup before the proxy that justifies it even exists.
  # `internal: true` is the kernel enforcement-of-record; it lands with the flip.
  alfred_internal: {}
  alfred_external: {}
```

Add `networks:` to each service block (preserving every other key):

```yaml
  alfred-postgres:
    # ...existing keys unchanged...
    networks:
      - alfred_internal

  alfred-redis:
    # ...existing keys unchanged...
    networks:
      - alfred_internal

  alfred-core:
    # ...existing keys unchanged...
    networks:
      - alfred_internal
      - alfred_external   # G7-3 removes this line (connectivity-free flip)

  alfred-gateway:
    # ...existing keys unchanged...
    networks:
      - alfred_internal
      - alfred_external
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/test_compose_invariants.py -v`
Expected: PASS for the five new active tests + every pre-existing test (the SETUID/devops-010 assertions still hold); `test_core_not_on_external_DEFERRED_to_g7_3` reports SKIPPED.

- [ ] **Step 5: Verify the compose file is valid AND the published Postgres port stays reachable (behaviour-neutral)**

`docker compose config --quiet` only validates syntax; it does not prove the `5432:5432` host-publish still works once Postgres moves off the default bridge onto the custom `alfred_internal` network. Probe it for real — this is the step that PROVED `internal: true` cannot ship in G7-0 (with `internal: true` the probe returned UNREACHABLE on Docker Desktop/macOS; without it, REACHABLE — hence the atomic G7-3 flip):

```bash
docker compose config --quiet && echo "compose syntax OK"
docker compose up -d alfred-postgres
# Docker's host port-forward binds as soon as the container starts (independent of
# postgres readiness), so a TCP connect proves the publish works under the custom network:
for i in $(seq 1 20); do
  if python3 -c "import socket; socket.create_connection(('localhost', 5432), 2).close()" 2>/dev/null; then break; fi
  sleep 2
done
python3 -c "import socket; socket.create_connection(('localhost', 5432), 2).close()" \
  && echo "REACHABLE" || { echo "UNREACHABLE — STOP; a custom-network change broke the publish"; exit 1; }
docker compose down
```

Expected: `compose syntax OK`, then `REACHABLE`. (If `docker` is genuinely unavailable in the worker environment, skip the live probe, rely on the unit tests, and state in the PR description that the published-port reachability probe was NOT run locally so a reviewer runs it.) G7-3 must re-run this probe on its target Linux host after adding `internal: true`, where published ports are NAT'd independently of the network's external gateway.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "feat(compose): define alfred_internal/alfred_external networks + invariant lint (#333)"
```

---

### Task 2: In-core HTTP-egress import-guard (required merge gate)

Add an AST-based test that fails if any module under `src/alfred/` gains a *new* external-HTTP-egress client — a module-scope import of `anthropic`/`openai`/`requests`/`aiohttp`, or a construction of `httpx.AsyncClient`/`httpx.Client` — outside an explicit baseline allowlist. This is the always-on PR ratchet against new direct egress (the kernel block at G7-3 is the runtime enforcement-of-record; this is its code-level complement). `socket` and a bare `import httpx` are **not** forbidden: `socket` is used for unix-domain sockets across the in-core tree, and `httpx` is imported for `httpx.Timeout`; only the connection-opening client constructions and the alternative HTTP libraries are caught. The test lives in `tests/unit`, which is already a required check, so it gates `main` from merge.

**Files:**

- Create: `tests/unit/egress/__init__.py`
- Create: `tests/unit/egress/test_in_core_http_egress_guard.py`

**Interfaces:**

- Consumes: nothing.
- Produces: the guard contract that later G7 PRs maintain — `IMPORT_ALLOWLIST` (files permitted to import a provider SDK) and `CONSTRUCT_ALLOWLIST` (files permitted to construct an `httpx` client). G7-1 adds the new `EgressClient` module to `CONSTRUCT_ALLOWLIST` when it builds the proxied `httpx.AsyncClient`; the provider files stay in `IMPORT_ALLOWLIST` (they keep wrapping the SDK with an injected client).

- [ ] **Step 1: Write the failing guard test**

> **Note (post-`/review-pr` hardening):** the committed `tests/unit/egress/test_in_core_http_egress_guard.py` is the authoritative version and strengthens the sketch below per the fleet review: both the SDK-import and httpx checks walk the **full tree** (a function-local `import anthropic` is caught too — rev-001); the allowlists are `dict[path, reason]` so each entry carries its justification (devex-001); a `test_src_root_resolves_and_is_nonempty` floor prevents a vacuous pass on a broken `_SRC_ROOT` (err-001); and synthetic `@pytest.mark.parametrize` table tests make the guard self-proving without depending on the live tree (test-001). The docstring records the accepted static-scope limitation (dynamic `importlib` + `urllib`/`http.client` are out of scope — the G7-3 kernel block is the enforcement-of-record; sec-001).

Create `tests/unit/egress/__init__.py` (empty file):

```python
```

Create `tests/unit/egress/test_in_core_http_egress_guard.py`:

```python
"""Connectivity-free-core code ratchet (Spec C §7, epic #333).

Fails if any in-core module gains a NEW external-HTTP-egress client outside the
baseline allowlist. The kernel block (G7-3: core on alfred_internal-only) is the
runtime enforcement-of-record; this AST guard is its always-on, non-root,
PR-level complement (mirrors the spawn/import guard in
tests/adversarial/sandbox_escape/test_quarantined_llm_not_yet_spawned_while_egress_open.py).

NOT forbidden: `import socket` (unix-domain sockets are used across the in-core
tree) and a bare `import httpx` (used for httpx.Timeout). Caught: connection-opening
httpx client constructions in EVERY binding form (`httpx.AsyncClient(...)`, an
aliased `import httpx as h; h.AsyncClient(...)`, and `from httpx import AsyncClient`),
plus module-scope imports of the alternative HTTP libraries (anthropic/openai/
requests/aiohttp).
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "alfred"

# Module-scope import of any of these external-HTTP libraries is forbidden in-core
# outside IMPORT_ALLOWLIST. (httpx is intentionally absent — bare import is fine.)
_FORBIDDEN_IMPORT_MODULES: frozenset[str] = frozenset(
    {"anthropic", "openai", "requests", "aiohttp"}
)

# Files permitted to import a provider SDK today (they wrap it; G7-1 injects a
# proxied http_client into the same wrappers). Paths are relative to _SRC_ROOT.
_IMPORT_ALLOWLIST: frozenset[str] = frozenset(
    {"providers/anthropic_native.py", "providers/deepseek.py"}
)

# Files permitted to CONSTRUCT an httpx client (httpx.AsyncClient/Client). Empty
# today — no in-core code opens an httpx connection directly. G7-1 adds the
# sanctioned EgressClient module here.
_CONSTRUCT_ALLOWLIST: frozenset[str] = frozenset()


def _rel(path: Path) -> str:
    return path.relative_to(_SRC_ROOT).as_posix()


def _module_scope_import_modules(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:  # module scope only
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module.split(".")[0])
    return names


def _imports_or_constructs_httpx_client(tree: ast.Module) -> bool:
    """True if the module pulls an httpx client into its namespace OR constructs one.

    Catches every binding form so the ratchet can't be bypassed:
      * ``from httpx import AsyncClient`` / ``Client`` (the import alone is the offence —
        the client class has no in-core use outside the sanctioned egress seam),
      * ``httpx.AsyncClient(...)`` and an aliased ``import httpx as h; h.AsyncClient(...)``.
    A bare ``import httpx`` (for ``httpx.Timeout``) is NOT an offence on its own.
    """
    httpx_module_aliases: set[str] = {"httpx"}
    httpx_client_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "httpx" and alias.asname:
                    httpx_module_aliases.add(alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.module == "httpx":
            for alias in node.names:
                if alias.name in {"AsyncClient", "Client"}:
                    httpx_client_names.add(alias.asname or alias.name)
    if httpx_client_names:
        return True  # importing the client class in-core is itself the offence
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"AsyncClient", "Client"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in httpx_module_aliases
        ):
            return True
    return False


def _iter_src_files() -> list[Path]:
    return sorted(p for p in _SRC_ROOT.rglob("*.py"))


def test_no_new_in_core_provider_sdk_import() -> None:
    """No in-core module imports a provider SDK / alt-HTTP lib outside the allowlist."""
    offenders: dict[str, set[str]] = {}
    for path in _iter_src_files():
        rel = _rel(path)
        if rel in _IMPORT_ALLOWLIST:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        bad = _module_scope_import_modules(tree) & _FORBIDDEN_IMPORT_MODULES
        if bad:
            offenders[rel] = bad
    assert not offenders, (
        "New in-core external-HTTP-egress import(s) detected outside the egress seam: "
        f"{offenders}. Route egress through the gateway proxy (Spec C); if this is the "
        "sanctioned seam, add the file to _IMPORT_ALLOWLIST with a comment."
    )


def test_no_in_core_httpx_client_import_or_construction() -> None:
    """No in-core module imports OR constructs httpx.AsyncClient/Client outside the allowlist."""
    offenders: list[str] = []
    for path in _iter_src_files():
        rel = _rel(path)
        if rel in _CONSTRUCT_ALLOWLIST:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _imports_or_constructs_httpx_client(tree):
            offenders.append(rel)
    assert not offenders, (
        "In-core httpx client import/construction outside the egress seam: "
        f"{sorted(offenders)}. The proxied client must be built only in the "
        "sanctioned EgressClient (G7-1); add that module to _CONSTRUCT_ALLOWLIST."
    )


def test_allowlist_entries_still_exist() -> None:
    """An allowlist entry that no longer exists is stale — fail so it gets pruned."""
    for rel in _IMPORT_ALLOWLIST | _CONSTRUCT_ALLOWLIST:
        assert (_SRC_ROOT / rel).is_file(), f"stale allowlist entry: {rel}"
```

- [ ] **Step 2: Run the guard to verify it passes against the current tree**

Run: `uv run pytest tests/unit/egress/test_in_core_http_egress_guard.py -v`
Expected: PASS — the only provider-SDK imports today are in the two allowlisted files, no in-core code constructs an httpx client, and both allowlist entries exist. (This guard is written to be GREEN on the current tree; its value is catching future violations.)

- [ ] **Step 3: Prove the guard actually bites (temporary negative check)**

Add a throwaway import to a non-allowlisted in-core file, confirm the guard fails, then revert. Do this twice — once for the SDK-import guard, once for the `from httpx import AsyncClient` bypass the strengthened construct-guard closes.

Run:

```bash
printf '\nimport requests  # TEMP guard check\n' >> src/alfred/errors.py
uv run pytest tests/unit/egress/test_in_core_http_egress_guard.py::test_no_new_in_core_provider_sdk_import -q
git checkout -- src/alfred/errors.py

printf '\nfrom httpx import AsyncClient  # TEMP guard check\n' >> src/alfred/errors.py
uv run pytest tests/unit/egress/test_in_core_http_egress_guard.py::test_no_in_core_httpx_client_import_or_construction -q
git checkout -- src/alfred/errors.py
```

Expected: BOTH pytest runs FAIL — the first with `{'errors.py': {'requests'}}`, the second listing `errors.py` as an httpx-client offender — and each `git checkout` restores the file. (Proves both guards bite, including the `from httpx import` bypass; nothing is committed.)

- [ ] **Step 4: Re-run the guard to confirm the tree is clean again**

Run: `uv run pytest tests/unit/egress/test_in_core_http_egress_guard.py -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Run the full quality bar**

Run: `make check`
Expected: ruff + format + mypy + pyright + unit tests all pass (the new test files are type-clean: `from __future__ import annotations`, fully annotated).

- [ ] **Step 6: Commit**

```bash
git add tests/unit/egress/__init__.py tests/unit/egress/test_in_core_http_egress_guard.py
git commit -m "test(egress): in-core HTTP-egress import-guard ratchet (#333)"
```

---

## Definition of Done

- `docker-compose.yaml` defines `alfred_internal` + `alfred_external` (both internet-reachable in G7-0); gateway on both, datastores on `alfred_internal`-only, core on both (no behaviour change; published Postgres port probed REACHABLE).
- `tests/unit/test_compose_invariants.py` pins the membership; the two isolation assertions (`internal: true`, `core_not_on_external`) are present but skipped with G7-3 pointers (they flip atomically there).
- `tests/unit/egress/test_in_core_http_egress_guard.py` is green on the current tree, proven to bite, and runs in the required `tests/unit` lane (so it gates `main`).
- `make check` green. No `src/alfred/` runtime code changed; no new dependency; core egress unchanged.
- Two commits, both Conventional-Commits with `(#333)`.

## Self-Review

- **Spec coverage:** This plan covers exactly the two G7-0 deliverables that are dead-code-free and behaviour-neutral — the network topology (Spec C §3) and the two structural gates (compose-invariant + import-guard, Spec C §7/§11). The `EgressClient` seam + typed errors that §11's sketch listed under G7-0 are explicitly deferred to G7-1 (documented in the Architecture note) to avoid unused code; the *gates* still land here as §11 intended.
- **Placeholder scan:** No TBD/TODO/"handle edge cases". Every test and YAML block is complete and copy-paste-ready.
- **Type consistency:** Helper names are stable across the file (`_service_networks`, `_module_scope_import_modules`, `_imports_or_constructs_httpx_client`, `_IMPORT_ALLOWLIST`, `_CONSTRUCT_ALLOWLIST`); the `compose` fixture is the existing module-scoped one in `test_compose_invariants.py`.
- **Behaviour-neutrality check:** the core keeps `alfred_external` in G7-0, so it retains internet egress; the only "new" runtime effect is custom-network attachment, validated by `docker compose config`.
