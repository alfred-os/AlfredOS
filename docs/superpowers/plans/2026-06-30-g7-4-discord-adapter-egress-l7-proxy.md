# G7-4 — Discord-adapter egress via the gateway L7 CONNECT proxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the gateway-hosted Discord adapter behind `--unshare-net` (empty netns) and route its egress through a second `EgressForwardProxy` instance bound on a **gateway-only** AF_UNIX socket, reached by a dumb in-child TCP→unix shim that `discord.py`'s `Client(proxy=...)` dials — kernel-enforced sole-egress, Discord-only allowlist.

**Architecture:** One `EgressForwardProxy` class, two instances (TCP+provider allowlist unchanged; new AF_UNIX+Discord allowlist). The AF_UNIX socket lives on a new **gateway-only** docker volume (`alfred_discord_egress`, never mounted into the connectivity-free core). A ~40-line in-child shim splices `127.0.0.1:PORT` → the bind-mounted unix socket. All new boundary code lives under `src/alfred/` for coverage + bwrap-importability.

**Tech Stack:** Python 3.12+ asyncio, `discord.py` 2.7.1 / `aiohttp` 3.13.5, bubblewrap, Docker Compose, pytest, mypy --strict + pyright, ruff.

**Design spec:** [`docs/superpowers/specs/2026-06-29-g7-4-discord-adapter-egress-l7-proxy-design.md`](../specs/2026-06-29-g7-4-discord-adapter-egress-l7-proxy-design.md) (commit `d524d693`, Round-2 converged). Read it before starting.

## Global Constraints

- **Python floor 3.12+**; modern idioms only (PEP 604 `X | Y`, PEP 585 builtins, no `Optional[X]`/`typing.List`).
- **Strong typing:** `mypy --strict` + `pyright` clean; no `Any` without justification; Pydantic/frozen at boundaries; no new `# type: ignore`.
- **Security boundary:** new egress/sandbox code needs **100% line + branch coverage**, enforced by a hand-maintained `coverage report --include=<path> --fail-under=100` step in **both** ci.yml jobs (Task 11). Touching `src/alfred/security/` or the egress boundary makes the **full adversarial suite release-blocking** — run `uv run pytest tests/adversarial` before the PR.
- **i18n:** every operator-facing string goes through `t()` (new keys in Task 13); run the pybabel extract→update→compile flow; never `--omit-header`.
- **No `--no-verify`.** **Conventional Commits** on every commit.
- **`.rulesync/` is canonical** — never edit generated `.claude/` / root `CLAUDE.md`. **CLAUDE.md / PRD.md / ADR-0040 edits are human-gated** (out of this plan; G7-5).
- **The gateway reads PUBLIC env, never `Settings`** (ADR-0036) — it holds no provider/secret key.
- **Quality gate before every push:** `make check` (lint + format + type + unit/integration). Docker-driven tests: `export DOCKER_HOST=unix://$HOME/.docker/run/docker.sock`.

## Plan-review fixes (2026-06-30) — READ BEFORE ANY TASK; these OVERRIDE the task bodies below

A focused security/devops/comms plan-review found execution-fidelity blockers (design unchanged). Apply these — they supersede the conflicting task text.

**FIX-1 (Critical — new prerequisite, do FIRST). Pre-create the gateway-only egress dir in the image.** A Docker-created volume mountpoint is `root:root`; the gateway runs as `alfred`, so binding the socket would `EACCES` and crash-loop every boot. In `docker/alfred-core.Dockerfile`, in the **runtime stage**, mirror the existing `/home/alfred/.run` creation: add `RUN mkdir -p /home/alfred/.egress/discord && chown -R alfred:alfred /home/alfred/.egress` (match the exact `useradd`/`chown` idiom already used for `~/.run`). The compose `alfred_discord_egress` volume mounts over `/home/alfred/.egress` and inherits the pre-created+chowned `discord/` subdir.

**FIX-2 (High — supersedes Task 3 Step 3, Task 5, Task 7). Bind CONFIG on the constructor; bind INSIDE `serve()`; `serve(shutdown_event)` signature UNCHANGED.** Do NOT move the bind to `serve()`'s params (that breaks the shared `_EgressProxyLike` Protocol at `_commands.py:151` and both call-sites) and do NOT eager-bind at construction (that mislabels a bind failure as exit-4 and breaks `test_egress_proxy_mount.py`/`test_egress_relay_mount.py`). Instead:

- `EgressForwardProxy.__init__(*, allowlist, match, audit, resolve=..., open_upstream=..., bind_host=None, port=None, unix_path=None)` — exactly one bind mode (`bind_host`+`port` **or** `unix_path`); a both/neither is a loud `ValueError`. `serve(self, shutdown_event)` keeps its EXACT current signature.
- `serve()` does the bind itself: if `unix_path` → `sock = bind_owner_only_unix_socket(unix_path); server = await asyncio.start_unix_server(self._handle_client, sock=sock, limit=_REQUEST_LINE_CAP)`; else the existing `asyncio.start_server(self._handle_client, bind_host, port, limit=_REQUEST_LINE_CAP)`. Because the bind is INSIDE `serve()`, an `OSError` propagates to the per-instance fail-closed wrapper and maps to the right exit code.
- Provider call-site (`_commands.py:303`): `EgressForwardProxy(..., match=exact_match, bind_host=resolve_egress_proxy_bind(), port=resolve_egress_proxy_port())`; `_serve_egress_proxy_failclosed` keeps calling `proxy.serve(shutdown_event)` UNCHANGED. The Protocol + relay are untouched.
- Task 5 `build_adapter_egress_proxy(*, extra_allowlist="") -> EgressForwardProxy` returns ONLY the proxy (no socket; NO eager bind) built with `unix_path=DISCORD_EGRESS_SOCKET_PATH`. `serve_adapter_egress_failclosed(proxy, shutdown_event)` just calls `await proxy.serve(shutdown_event)` and maps `OSError → EgressAdapterProxyUnavailableError`. Task 7 mounts `tg.create_task(serve_adapter_egress_failclosed(adapter_proxy, shutdown_event))` (no `adapter_sock`). (This supersedes the Round-2 "pre-bind + `serve(sock=)`": the bwrap policy binds the DIR, not the socket file, and FIX-1 pre-creates the dir, so no pre-bind-before-TaskGroup is needed; binding inside `serve()` matches the provider/relay and fixes the exit-code mapping.)
- Add an **in-process AF_UNIX serve test** (Task 3) that actually serves a CONNECT over a real unix socket + asserts allow/deny — the `serve(unix_path=...)` branch must be unit-covered (not docker-gated only), or `egress_proxy.py` drops below its 100% gate.

**FIX-3 (High — supersedes Task 8 shim supervision). Own the shim in `server.serve()` via the LOCAL `CrashEmitter`.** `DiscordServer` has no crash forwarder; `bind_shim`/`_on_shim_done`/`DiscordServer` indirection is wrong — delete it. In `server.serve()` (which already builds a `CrashEmitter` at ~`server.py:289`): `shim_server = await start_shim()`, then `shim_task = asyncio.create_task(shim_server.serve_forever())`, then `shim_task.add_done_callback(lambda t: _route_shim_failure(t, crash_emitter))` where `_route_shim_failure` retrieves `t.exception()` (skip `CancelledError`) and calls `crash_emitter.handle_crash(exc)` — a terminal, audited adapter exit, not a silent reconnect spin. `start_shim()` returns the `asyncio.Server` (Task 6 unchanged). Test the **`_route_shim_failure` handler directly** (a coverable function), not the `# pragma: no cover` `serve()` entrypoint.

**FIX-4 (Medium — Task 7). Use the REAL failure-emit pattern, not the invented `_emit_friendly_failure`.** Copy the relay's `except EgressRelayUnavailableError` body verbatim (`_commands.py:354-361`) for the new `except EgressAdapterProxyUnavailableError` clause (log + `raise typer.Exit(code=_EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED)`), placed BEFORE `except IOPlaneUnavailableError`. **Fix the except-order test** to be non-vacuous: assert the `except EgressAdapterProxyUnavailableError` *clause* index (search `src.index("except EgressAdapterProxyUnavailableError")`), not the bare class name (which matches the import).

**FIX-5 (Medium — Task 9). Use `--bind` (rw), not `--ro-bind`.** A `connect()` over a `--ro-bind` unix socket fails; cross-UID is NOT a concern (kind=full runs as `alfred`, no `runuser`). Add to `rw_binds` (not `ro_binds`): `["/home/alfred/.egress/discord", "/home/alfred/.egress/discord"]`. Also FLIP the existing `test_egress_deferral_to_230_documented_in_policy` (it stays green-but-false after enforcement) to assert the enforced posture.

**FIX-6 (High — Task 10). Update the EXACT-SET gateway-mount + relevant compose tests, don't just add.** Adding the mount breaks the required exact-set gateway-volume pin (`tests/unit/test_compose_invariants.py` — the gateway-mounts assertion near `:232`, plus `test_alfred_run_mounted_only_by_core_and_gateway:246` which must still hold for `alfred_run`). Update the gateway-mount exact-set to include `alfred_discord_egress:/home/alfred/.egress`; add an assertion that `alfred_discord_egress` is mounted by the gateway ONLY (mirror `:246`'s only-by pattern).

**FIX-7 (Medium — Task 11/12). Add the kernel-proof not-skipped CI guard step.** Task 12's privileged-lane proof needs a ci.yml step asserting it was collected-and-not-skipped (the `#245` pattern, but in the `integration-privileged` job) — Task 11 must add it, or the kernel gate is paper-only.

**FIX-8 (drop the trap). Remove the "caller label on the shared egress audit" punch-list item** — `record_egress_connect` validates an EXACT field set and RAISES on an extra field, so a naive caller label breaks ALL Discord egress. If attribution is wanted, it's a separate change extending the sink's field-allowlist (out of scope here). Likewise drop the `match.__name__ = "suffix_match"` hack in Task 5 — assert the matcher behaviour in the test, not its `__name__`.

## File Structure

**Create:**

- `docker/alfred-core.Dockerfile` (modify — FIX-1: pre-create+chown `/home/alfred/.egress/discord`).

- `src/alfred/egress/adapter_egress_addr.py` — the single source of truth for the gateway-only socket **path** + the shim **port** + the proxy-URL builder (shared by listener, shim, bot).
- `src/alfred/egress/byte_splice.py` — the shared bidirectional byte-splice (extracted from `EgressForwardProxy._pipe`).
- `src/alfred/egress/adapter_proxy_shim.py` — the dumb in-child TCP→unix shim.
- `src/alfred/gateway/adapter_egress_listener.py` — the gateway-side AF_UNIX listener lifecycle (eager-bind + the Discord proxy instance + fail-closed serve).
- `tests/unit/egress/test_adapter_egress_addr.py`, `tests/unit/egress/test_byte_splice.py`, `tests/unit/egress/test_adapter_proxy_shim.py`, `tests/unit/gateway/test_adapter_egress_listener.py`, plus the test files named per task.
- `tests/adversarial/sandbox_escape/sbx_2026_014_discord_outbound_network_contained.yaml`
- `tests/integration/egress/test_discord_policy_kernel_enforced.py`
- `docs/adr/0043-discord-adapter-egress-l7-proxy-netns-bridge.md`

**Modify:**

- `src/alfred/egress/allowlist.py` — add the Discord allowlist + the per-entry match predicate; fix the `provider_egress_allowlist` docstring.
- `src/alfred/egress/errors.py` — add `EgressAdapterProxyUnavailableError`.
- `src/alfred/gateway/egress_proxy.py` — `serve(sock=...)` selector + injected `match` predicate; `_pipe` calls `byte_splice`.
- `src/alfred/cli/gateway/_commands.py` — exit code 9 + `_serve_adapter_egress_failclosed` + TaskGroup task + `except` ordering.
- `plugins/alfred_discord/discord_gateway.py` — `AlfredDiscordBot(*, proxy=...)`.
- `plugins/alfred_discord/server.py` — start the shim in `serve()`; thread the proxy URL into `_build_server`.
- `config/sandbox/discord-adapter.linux.bwrap.policy` — `unshare += net` + the ro-bind + the egress-comment rewrite.
- `docker-compose.yaml` — the `alfred_discord_egress` gateway-only volume + `ALFRED_DISCORD_EGRESS_ALLOWLIST`.
- `.github/workflows/ci.yml` — the 3 new modules in both coverage `--include` lists.
- `tests/unit/plugins/test_discord_adapter_sandbox_policy.py`, `tests/unit/test_compose_invariants.py`, `tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py` — migrate/extend.
- `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md`, `docs/adr/0015-*.md`, `docs/subsystems/comms.md`, `docs/subsystems/security.md`, `config/sandbox/README.md`, the Spec C design doc (erratum note), `locale/en/LC_MESSAGES/alfred.po`.

---

### Task 1: Discord allowlist + per-entry match predicate

**Files:**

- Modify: `src/alfred/egress/allowlist.py`
- Test: `tests/unit/egress/test_discord_allowlist.py` (create)

**Interfaces:**

- Consumes: `EgressDestination = tuple[str, int]` (UNCHANGED — no 3-tuple ripple), `host_port_from_url`.
- Produces:
  - `DiscordEgressAllowlist` (frozen): `exact: frozenset[EgressDestination]`, `suffix_bases: frozenset[EgressDestination]`.
  - `discord_egress_allowlist(extra: str = "") -> DiscordEgressAllowlist`.
  - `ExactMatch` and a `SuffixMatch(discord)` callable: `Match = Callable[[str, int, frozenset[EgressDestination]], bool]` — the predicate `EgressForwardProxy._authorize` injects. `exact_match(host, port, allowlist)` ≡ the prior `(host, port) in allowlist`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/egress/test_discord_allowlist.py
import pytest
from alfred.egress.allowlist import (
    DiscordEgressAllowlist,
    discord_egress_allowlist,
    exact_match,
    suffix_match,
    provider_egress_allowlist,
)

def test_discord_default_set():
    al = discord_egress_allowlist()
    assert ("discord.com", 443) in al.exact
    assert ("discord.gg", 443) in al.suffix_bases  # apex + subdomains via suffix

def test_exact_match_equiv_prior_membership():
    allow = frozenset({("api.anthropic.com", 443)})
    assert exact_match("api.anthropic.com", 443, allow) is True
    assert exact_match("api.anthropic.com", 80, allow) is False
    assert exact_match("evil.api.anthropic.com", 443, allow) is False

@pytest.mark.parametrize("host,ok", [
    ("discord.gg", True),               # apex
    ("gateway.discord.gg", True),       # subdomain
    ("gateway-us-east1-b.discord.gg", True),  # dynamic resume host
    ("evildiscord.gg", False),          # near-miss: no dot boundary
    ("discord.gg.evil.com", False),     # near-miss: suffix not at end
    ("gateway.discord.gg.attacker.com", False),
    ("discord.gg.", False),             # trailing dot
])
def test_suffix_match_anchored(host, ok):
    bases = frozenset({("discord.gg", 443)})
    assert suffix_match(host, 443, bases) is ok

def test_suffix_match_port_checked():
    bases = frozenset({("discord.gg", 443)})
    assert suffix_match("gateway.discord.gg", 8080, bases) is False

def test_provider_and_discord_disjoint():
    prov = provider_egress_allowlist("https://api.deepseek.com/v1")
    disc = discord_egress_allowlist()
    disc_hosts = {h for h, _ in disc.exact} | {h for h, _ in disc.suffix_bases}
    prov_hosts = {h for h, _ in prov}
    assert disc_hosts.isdisjoint(prov_hosts)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/egress/test_discord_allowlist.py -q`
Expected: FAIL — `ImportError: cannot import name 'DiscordEgressAllowlist'`.

- [ ] **Step 3: Implement in `allowlist.py`**

Add after `provider_egress_allowlist` (and fix that docstring line: replace `G7-4 adds the Discord hosts.` with `The Discord adapter has its OWN disjoint allowlist (``discord_egress_allowlist``) — provider egress is never merged with it.`):

```python
import os
from collections.abc import Callable
from dataclasses import dataclass

Match = Callable[[str, int, frozenset[EgressDestination]], bool]


def exact_match(host: str, port: int, allow: frozenset[EgressDestination]) -> bool:
    """The provider matcher — identical to the prior ``(host, port) in allowlist``."""
    return (host, port) in allow


def suffix_match(host: str, port: int, suffix_bases: frozenset[EgressDestination]) -> bool:
    """Anchored suffix match: ``host == base`` (apex) or ``host`` ends with ``"." + base``.

    Never a bare ``endswith`` — that would match ``evildiscord.gg`` against ``discord.gg``.
    The port must match the base entry's port.
    """
    for base_host, base_port in suffix_bases:
        if port == base_port and (host == base_host or host.endswith("." + base_host)):
            return True
    return False


@dataclass(frozen=True, slots=True)
class DiscordEgressAllowlist:
    exact: frozenset[EgressDestination]
    suffix_bases: frozenset[EgressDestination]


_DISCORD_EXACT: frozenset[EgressDestination] = frozenset({("discord.com", _DEFAULT_HTTPS_PORT)})
_DISCORD_SUFFIX: frozenset[EgressDestination] = frozenset({("discord.gg", _DEFAULT_HTTPS_PORT)})


def discord_egress_allowlist(extra: str = "") -> DiscordEgressAllowlist:
    """The Discord-only egress set: ``discord.com`` exact + ``*.discord.gg`` (incl. the
    dynamic ``resume_gateway_url``) suffix. ``extra`` (the public
    ``ALFRED_DISCORD_EGRESS_ALLOWLIST`` env, comma ``host[:port]``) adds exact entries
    (e.g. ``cdn.discordapp.com`` when attachment fetch is enabled). Gateway reads the env,
    never ``Settings`` (ADR-0036)."""
    exact = set(_DISCORD_EXACT)
    for token in (t.strip() for t in extra.split(",") if t.strip()):
        host, sep, port_str = token.rpartition(":")
        if sep and port_str.isascii() and port_str.isdigit():
            exact.add((host.lower(), int(port_str)))
        else:
            exact.add((token.lower(), _DEFAULT_HTTPS_PORT))
    return DiscordEgressAllowlist(exact=frozenset(exact), suffix_bases=_DISCORD_SUFFIX)
```

Add `DiscordEgressAllowlist`, `discord_egress_allowlist`, `exact_match`, `suffix_match`, `Match` to `__all__`.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/egress/test_discord_allowlist.py -q` → Expected: PASS. Then `uv run pytest tests/unit/egress/ -q` to confirm the existing provider-allowlist tests still pass.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/egress/allowlist.py tests/unit/egress/test_discord_allowlist.py
git commit -m "feat(egress): Discord-only allowlist + anchored per-entry match predicate (#333)"
```

---

### Task 2: Shared byte-splice helper (extract `_pipe`)

**Files:**

- Create: `src/alfred/egress/byte_splice.py`
- Modify: `src/alfred/gateway/egress_proxy.py` (`_pipe` → calls the shared helper)
- Test: `tests/unit/egress/test_byte_splice.py` (create)

**Interfaces:**

- Produces: `async def splice(src: asyncio.StreamReader, dst: asyncio.StreamWriter, *, chunk: int = 65536) -> None` — incremental copy until EOF, then `write_eof()` (suppress `OSError`); a mid-splice `OSError` propagates.

- [ ] **Step 1: Write the failing test** (pin the exact `_pipe` behaviour so the extraction is provably neutral)

```python
# tests/unit/egress/test_byte_splice.py
import asyncio
import contextlib
import pytest
from alfred.egress.byte_splice import splice

class _CaptureWriter:
    def __init__(self): self.buf = bytearray(); self.eof = False; self.closed = False
    def write(self, data): self.buf.extend(data)
    async def drain(self): pass
    def write_eof(self): self.eof = True
    def close(self): self.closed = True

@pytest.mark.asyncio
async def test_splice_copies_then_half_closes():
    r = asyncio.StreamReader(); r.feed_data(b"hello"); r.feed_eof()
    w = _CaptureWriter()
    await splice(r, w)
    assert bytes(w.buf) == b"hello"
    assert w.eof is True

@pytest.mark.asyncio
async def test_splice_write_eof_oserror_suppressed():
    r = asyncio.StreamReader(); r.feed_eof()
    w = _CaptureWriter()
    def boom(): raise OSError("cannot half-close")
    w.write_eof = boom
    await splice(r, w)  # must not raise
```

- [ ] **Step 2: Run to verify fail**

Run: `uv run pytest tests/unit/egress/test_byte_splice.py -q` → Expected: FAIL (`ModuleNotFoundError: alfred.egress.byte_splice`).

- [ ] **Step 3: Create `src/alfred/egress/byte_splice.py`** (copy the body of `egress_proxy.py:_pipe` verbatim, parameterising the chunk)

```python
"""Shared bidirectional byte-splice for the egress proxy + the in-child shim (Spec C G7-4).

Extracted from ``EgressForwardProxy._pipe`` so the AF_UNIX bridge's shim reuses the SAME
audited copy loop instead of importing a gateway-private symbol across the package boundary.
Payload-blind: never buffers-until-EOF, so native TLS streaming survives.
"""
from __future__ import annotations

import asyncio
import contextlib

_SPLICE_CHUNK = 65536


async def splice(
    src: asyncio.StreamReader, dst: asyncio.StreamWriter, *, chunk: int = _SPLICE_CHUNK
) -> None:
    """Copy ``src``→``dst`` incrementally until EOF, then half-close ``dst``.

    A mid-splice ``OSError`` (peer reset) is NOT swallowed — it propagates to the caller's
    bounded handler. On normal EOF we ``write_eof`` so the peer observes the close;
    ``suppress(OSError)`` covers a transport that cannot half-close.
    """
    try:
        while True:
            data = await src.read(chunk)
            if not data:
                break
            dst.write(data)
            await dst.drain()
            await asyncio.sleep(0)
    finally:
        with contextlib.suppress(OSError):
            dst.write_eof()
```

- [ ] **Step 4: Refactor `egress_proxy.py:_pipe` to delegate** (behaviour-neutral)

Replace the body of `EgressForwardProxy._pipe` (around `egress_proxy.py:314-333`) with a delegation, keeping the staticmethod signature:

```python
    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        from alfred.egress.byte_splice import splice
        await splice(src, dst, chunk=_SPLICE_CHUNK)
```

- [ ] **Step 5: Run the new + existing proxy tunnel tests**

Run: `uv run pytest tests/unit/egress/test_byte_splice.py tests/unit/gateway/ -q -k "proxy or splice or tunnel or pipe"`
Expected: PASS (the existing payload-blindness / streaming / half-close proxy tests are unchanged).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/egress/byte_splice.py src/alfred/gateway/egress_proxy.py tests/unit/egress/test_byte_splice.py
git commit -m "refactor(egress): extract the proxy byte-splice into a shared byte_splice helper (#333)"
```

---

### Task 3: `EgressForwardProxy` bind selector + injected matcher

**Files:**

- Modify: `src/alfred/gateway/egress_proxy.py`
- Test: `tests/unit/gateway/test_egress_proxy_unix_and_match.py` (create)

**Interfaces:**

- Consumes: `Match`, `exact_match`, `suffix_match` (Task 1); `splice` (Task 2).
- Produces: `EgressForwardProxy(*, allowlist, match, audit, resolve=..., open_upstream=...)`; `async serve(shutdown_event, *, sock=None, bind_host=None, port=None)` — exactly one of `sock=` / `(bind_host, port)`; `_authorize` calls `self._match(host, port, self._allowlist)` instead of the hard-coded `in`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/gateway/test_egress_proxy_unix_and_match.py
import asyncio, socket
import pytest
from alfred.gateway.egress_proxy import EgressForwardProxy
from alfred.egress.allowlist import exact_match, suffix_match

def _proxy(match, allow):
    return EgressForwardProxy(allowlist=allow, match=match, audit=lambda e, f: None)

@pytest.mark.asyncio
async def test_serve_requires_exactly_one_bind_mode():
    p = _proxy(exact_match, frozenset())
    with pytest.raises(ValueError):
        await p.serve(asyncio.Event(), bind_host="0.0.0.0", port=1, sock=socket.socket())

@pytest.mark.asyncio
async def test_authorize_uses_injected_exact_match():
    p = _proxy(exact_match, frozenset({("discord.com", 443)}))
    # _authorize is exercised via _serve_connection in the existing tunnel tests; here
    # assert the predicate wiring directly:
    assert p._match("discord.com", 443, p._allowlist) is True
    assert p._match("evil.com", 443, p._allowlist) is False

@pytest.mark.asyncio
async def test_authorize_uses_injected_suffix_match():
    bases = frozenset({("discord.gg", 443)})
    p = _proxy(suffix_match, bases)
    assert p._match("gateway-us-east1-b.discord.gg", 443, p._allowlist) is True
    assert p._match("evildiscord.gg", 443, p._allowlist) is False
```

- [ ] **Step 2: Run to verify fail**

Run: `uv run pytest tests/unit/gateway/test_egress_proxy_unix_and_match.py -q` → Expected: FAIL (`match` kwarg unknown / `serve()` rejects the new kwargs).

- [ ] **Step 3: Implement** in `egress_proxy.py`:

1. `__init__`: add `match: Match` param; store `self._match = match`. Remove `bind_host`/`port` from `__init__` if present (they move to `serve()`); store nothing for them.
2. `_authorize` (around `:276-285`): replace `if (host, port) not in self._allowlist:` with `if not self._match(host, port, self._allowlist):`.
3. `serve` (around `:155`): accept `*, sock: socket.socket | None = None, bind_host: str | None = None, port: int | None = None`; validate exactly one mode; for `sock` use `asyncio.start_unix_server(self._handle_client, sock=sock, limit=_REQUEST_LINE_CAP)`, for TCP use the existing `asyncio.start_server(..., bind_host, port, limit=_REQUEST_LINE_CAP)`. Keep `limit=_REQUEST_LINE_CAP` on BOTH.

```python
    async def serve(
        self,
        shutdown_event: asyncio.Event,
        *,
        sock: socket.socket | None = None,
        bind_host: str | None = None,
        port: int | None = None,
    ) -> None:
        if (sock is None) == (bind_host is None and port is None):
            raise ValueError("serve() needs exactly one of sock= or (bind_host, port)")
        if sock is not None:
            server = await asyncio.start_unix_server(
                self._handle_client, sock=sock, limit=_REQUEST_LINE_CAP
            )
        else:
            assert bind_host is not None and port is not None
            server = await asyncio.start_server(
                self._handle_client, bind_host, port, limit=_REQUEST_LINE_CAP
            )
        _log.info("gateway.egress.serving", unix=sock is not None, bind=bind_host, port=port)
        try:
            async with server:
                await shutdown_event.wait()
        finally:
            await self._drain_connections()
```

- [ ] **Step 4: Update the EXISTING provider mount call site** in `cli/gateway/_commands.py` (around `:303`) so the provider proxy passes `match=exact_match` and moves its bind to `serve()`. (Task 7 also touches `_commands.py`; this sub-edit keeps the provider instance compiling.)

In the `EgressForwardProxy(...)` construction (`:303`): add `match=exact_match` (import `from alfred.egress.allowlist import exact_match`), drop `bind_host=/port=` from the ctor; in `_serve_egress_proxy_failclosed` change the call to `proxy.serve(shutdown_event, bind_host=resolve_egress_proxy_bind(), port=resolve_egress_proxy_port())`.

- [ ] **Step 5: Run** the new tests + the full existing proxy suite

Run: `uv run pytest tests/unit/gateway/ tests/unit/egress/ -q`
Expected: PASS — confirm the existing CONNECT/SSRF/payload-blind tests (provider path) still pass byte-for-byte (exact-match ≡ prior membership).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/gateway/egress_proxy.py src/alfred/cli/gateway/_commands.py tests/unit/gateway/test_egress_proxy_unix_and_match.py
git commit -m "feat(egress): EgressForwardProxy bind selector + injected match predicate (#333)"
```

---

### Task 4: Shared address constants (gateway-only path + shim port)

**Files:**

- Create: `src/alfred/egress/adapter_egress_addr.py`
- Test: `tests/unit/egress/test_adapter_egress_addr.py` (create)

**Interfaces:**

- Produces: `DISCORD_EGRESS_SOCKET_PATH: Final[Path]` (a **gateway-only** mount path, NEVER `runtime_dir()`/`~/.run/alfred`); `DISCORD_EGRESS_SHIM_PORT: Final[int]`; `discord_proxy_url() -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/egress/test_adapter_egress_addr.py
from pathlib import Path
from alfred.egress.adapter_egress_addr import (
    DISCORD_EGRESS_SOCKET_PATH, DISCORD_EGRESS_SHIM_PORT, discord_proxy_url,
)

def test_socket_path_is_gateway_only_not_runtime_dir():
    # devops-001: the egress socket must NOT live under ~/.run/alfred (the alfred_run
    # volume, which is mounted into BOTH core and gateway).
    assert ".run/alfred" not in str(DISCORD_EGRESS_SOCKET_PATH)
    assert str(DISCORD_EGRESS_SOCKET_PATH).endswith("/discord/egress.sock")

def test_proxy_url_uses_shim_port_and_http_scheme():
    assert discord_proxy_url() == f"http://127.0.0.1:{DISCORD_EGRESS_SHIM_PORT}"
```

- [ ] **Step 2: Run to verify fail** → `ModuleNotFoundError`.

- [ ] **Step 3: Create the module**

```python
"""Single source of truth for the Discord egress bridge address (Spec C G7-4, #333).

The socket lives on a GATEWAY-ONLY volume (``alfred_discord_egress``), NEVER on
``alfred_run`` / ``runtime_dir()`` (``~/.run/alfred``) — that volume is mounted into BOTH
the connectivity-free core AND the gateway, and an AF_UNIX *pathname* socket is
filesystem-namespace-scoped (NOT gated by ``internal:true``), so a socket there would let
the core reach the Discord egress proxy and reopen G7-3 / HARD-#9 (devops-001).

ONE constant each for the path (gateway bind / bwrap target / shim connect) and the shim
port (shim listen / bot ``proxy=`` URL) so the three sites can never skew.
"""
from __future__ import annotations

from pathlib import Path
from typing import Final

# Gateway-only mount (see docker-compose.yaml: alfred_discord_egress -> /home/alfred/.egress,
# mounted into alfred-gateway ONLY). The bwrap policy ro-binds the parent dir into the child.
DISCORD_EGRESS_SOCKET_PATH: Final[Path] = Path("/home/alfred/.egress/discord/egress.sock")
DISCORD_EGRESS_SHIM_PORT: Final[int] = 8891


def discord_proxy_url() -> str:
    """The in-child shim URL discord.py dials (scheme pinned to ``http://``)."""
    return f"http://127.0.0.1:{DISCORD_EGRESS_SHIM_PORT}"


__all__ = ["DISCORD_EGRESS_SHIM_PORT", "DISCORD_EGRESS_SOCKET_PATH", "discord_proxy_url"]
```

- [ ] **Step 4: Run** → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/egress/adapter_egress_addr.py tests/unit/egress/test_adapter_egress_addr.py
git commit -m "feat(egress): gateway-only Discord egress socket path + shim-port constants (#333)"
```

---

### Task 5: New typed error + AF_UNIX listener lifecycle

**Files:**

- Modify: `src/alfred/egress/errors.py`
- Create: `src/alfred/gateway/adapter_egress_listener.py`
- Test: `tests/unit/gateway/test_adapter_egress_listener.py` (create)

**Interfaces:**

- Consumes: `bind_owner_only_unix_socket` (`src/alfred/plugins/_local_socket.py` — does mkdir-0700 + chmod + **unlink-stale** + bind + chmod-0600 + listen), `DISCORD_EGRESS_SOCKET_PATH`, `EgressForwardProxy`, `discord_egress_allowlist`, `suffix_match`, the `egress_audit` sink.
- Produces:
  - `EgressAdapterProxyUnavailableError(IOPlaneUnavailableError)` (errors.py).
  - `build_adapter_egress_proxy(*, extra_allowlist: str = "") -> tuple[EgressForwardProxy, socket.socket]` — binds the gateway-only socket + builds the Discord instance.
  - `async serve_adapter_egress_failclosed(proxy, sock, shutdown_event) -> None` — maps a bind/serve `OSError` to `EgressAdapterProxyUnavailableError`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/gateway/test_adapter_egress_listener.py
import asyncio, socket
import pytest
from alfred.egress.errors import EgressAdapterProxyUnavailableError, IOPlaneUnavailableError
from alfred.gateway.adapter_egress_listener import (
    build_adapter_egress_proxy, serve_adapter_egress_failclosed,
)

def test_adapter_error_is_io_plane_subtype():
    assert issubclass(EgressAdapterProxyUnavailableError, IOPlaneUnavailableError)

def test_build_binds_gateway_only_path(tmp_path, monkeypatch):
    import alfred.gateway.adapter_egress_listener as m
    sock_path = tmp_path / "discord" / "egress.sock"
    monkeypatch.setattr(m, "DISCORD_EGRESS_SOCKET_PATH", sock_path)
    proxy, sock = build_adapter_egress_proxy()
    try:
        assert sock_path.exists()
        assert proxy._match.__name__ == "suffix_match"
    finally:
        sock.close()

@pytest.mark.asyncio
async def test_serve_maps_bind_oserror_to_adapter_error():
    class _Boom:
        async def serve(self, *a, **k): raise OSError("EADDRINUSE")
    with pytest.raises(EgressAdapterProxyUnavailableError):
        await serve_adapter_egress_failclosed(_Boom(), socket.socket(), asyncio.Event())
```

- [ ] **Step 2: Run to verify fail** → ImportError.

- [ ] **Step 3a: Add the error** to `src/alfred/egress/errors.py` (after `EgressRelayUnavailableError`):

```python
class EgressAdapterProxyUnavailableError(IOPlaneUnavailableError):
    """The gateway's Discord-adapter AF_UNIX egress listener could not bind/serve.

    A subtype of IOPlaneUnavailableError so the fail-closed handler still catches it — but
    it carries its OWN exit code (9; proxy=7, relay=8) and t() key so the operator sees
    "Discord egress listener failed", not the provider-proxy outage (its except-clause MUST
    precede ``except IOPlaneUnavailableError`` — see cli/gateway/_commands.py).
    """
```

Add it to `errors.py`'s `__all__`.

- [ ] **Step 3b: Create `src/alfred/gateway/adapter_egress_listener.py`**

```python
"""Gateway-side Discord-adapter AF_UNIX egress listener lifecycle (Spec C G7-4, #333).

A second ``EgressForwardProxy`` instance bound on a GATEWAY-ONLY AF_UNIX socket (never
``alfred_run``) carrying the Discord-only allowlist + the anchored suffix matcher. The
socket is eagerly bound BEFORE the gateway TaskGroup (the supervisor's adapter spawn races
it otherwise); ``bind_owner_only_unix_socket`` already does unlink-before-bind so a stale
socket from a prior crash cannot EADDRINUSE the restart.
"""
from __future__ import annotations

import asyncio
import socket

import structlog

from alfred.egress.adapter_egress_addr import DISCORD_EGRESS_SOCKET_PATH
from alfred.egress.allowlist import discord_egress_allowlist, suffix_match
from alfred.egress.errors import EgressAdapterProxyUnavailableError
from alfred.gateway.egress_audit import record_egress_connect  # the existing structlog sink
from alfred.gateway.egress_proxy import EgressForwardProxy
from alfred.plugins._local_socket import bind_owner_only_unix_socket

_log = structlog.get_logger(__name__)


def build_adapter_egress_proxy(
    *, extra_allowlist: str = "",
) -> tuple[EgressForwardProxy, socket.socket]:
    """Bind the gateway-only AF_UNIX socket and build the Discord proxy instance.

    Returns ``(proxy, bound_socket)``. ``extra_allowlist`` is the public
    ``ALFRED_DISCORD_EGRESS_ALLOWLIST`` env (gateway reads env, never Settings — ADR-0036).
    The suffix-base set is the matcher's allowlist arg; the exact set rides the SAME proxy
    via a combined frozenset the matcher splits — see the matcher closure below.
    """
    al = discord_egress_allowlist(extra_allowlist)
    # The matcher must consult BOTH exact and suffix. Bind a closure that splits the work.
    exact = al.exact
    suffix_bases = al.suffix_bases

    def match(host: str, port: int, _allow: frozenset[tuple[str, int]]) -> bool:
        return (host, port) in exact or suffix_match(host, port, suffix_bases)

    match.__name__ = "suffix_match"  # for the listener test + audit attribution
    sock = bind_owner_only_unix_socket(DISCORD_EGRESS_SOCKET_PATH)
    proxy = EgressForwardProxy(
        allowlist=exact, match=match, audit=record_egress_connect,
    )
    return proxy, sock


async def serve_adapter_egress_failclosed(
    proxy: EgressForwardProxy, sock: socket.socket, shutdown_event: asyncio.Event,
) -> None:
    """Serve the Discord egress proxy on the pre-bound AF_UNIX socket; fail-closed.

    A serve ``OSError`` maps to ``EgressAdapterProxyUnavailableError`` (exit 9) — distinct
    from the provider-proxy (7) and relay (8) outages.
    """
    try:
        await proxy.serve(shutdown_event, sock=sock)
    except OSError as exc:
        raise EgressAdapterProxyUnavailableError(detail=repr(exc)) from exc
```

> Note: confirm `EgressForwardProxy.__init__`'s `audit` signature matches `record_egress_connect`'s `(event, fields)` shape; if `record_egress_connect` needs a caller label, pass a partial that stamps `caller="discord"` (sec-001 Low — optional this task).

- [ ] **Step 4: Run** → PASS. Then `make check` (mypy/pyright on the new module).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/egress/errors.py src/alfred/gateway/adapter_egress_listener.py tests/unit/gateway/test_adapter_egress_listener.py
git commit -m "feat(egress): gateway Discord AF_UNIX egress listener + EgressAdapterProxyUnavailableError (#333)"
```

---

### Task 6: In-child TCP→unix shim

**Files:**

- Create: `src/alfred/egress/adapter_proxy_shim.py`
- Test: `tests/unit/egress/test_adapter_proxy_shim.py` (create)

**Interfaces:**

- Consumes: `splice` (Task 2), `DISCORD_EGRESS_SOCKET_PATH`, `DISCORD_EGRESS_SHIM_PORT`.
- Produces: `async def start_shim() -> asyncio.AbstractServer` — binds `127.0.0.1:DISCORD_EGRESS_SHIM_PORT`, splices each accepted conn to `open_unix_connection(DISCORD_EGRESS_SOCKET_PATH)`. **No CONNECT parsing, no allowlist.**

- [ ] **Step 1: Write the failing test** (a fake unix upstream proves the bytes are spliced verbatim)

```python
# tests/unit/egress/test_adapter_proxy_shim.py
import asyncio
from pathlib import Path
import pytest
import alfred.egress.adapter_proxy_shim as shim

@pytest.mark.asyncio
async def test_shim_splices_bytes_verbatim_to_unix(tmp_path, monkeypatch):
    sock_path = tmp_path / "egress.sock"
    received = bytearray()
    async def upstream(reader, writer):
        received.extend(await reader.read(64)); writer.write(b"PONG"); await writer.drain(); writer.close()
    unix_server = await asyncio.start_unix_server(upstream, path=str(sock_path))
    monkeypatch.setattr(shim, "DISCORD_EGRESS_SOCKET_PATH", sock_path)
    monkeypatch.setattr(shim, "DISCORD_EGRESS_SHIM_PORT", 0)  # ephemeral
    server = await shim.start_shim()
    port = server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"CONNECT discord.com:443 HTTP/1.1\r\n\r\n"); await w.drain()
    assert await r.read(4) == b"PONG"
    assert bytes(received).startswith(b"CONNECT discord.com:443")
    server.close(); unix_server.close()
```

- [ ] **Step 2: Run to verify fail** → ImportError / AttributeError.

- [ ] **Step 3: Create the module**

```python
"""The in-child TCP→unix egress shim (Spec C G7-4, #333).

Runs INSIDE the --unshare-net Discord adapter child. discord.py's
``Client(proxy="http://127.0.0.1:PORT")`` needs a TCP proxy URL; aiohttp has no unix-socket
proxy. This shim is the thin bridge: accept on child-loopback, splice each connection to the
bind-mounted gateway AF_UNIX egress socket. It is TRANSPORT GLUE, not a policy plane — zero
CONNECT parsing, zero allowlisting; the gateway proxy is the sole enforcement point.
"""
from __future__ import annotations

import asyncio

import structlog

from alfred.egress.adapter_egress_addr import (
    DISCORD_EGRESS_SHIM_PORT,
    DISCORD_EGRESS_SOCKET_PATH,
)
from alfred.egress.byte_splice import splice

_log = structlog.get_logger(__name__)


async def _bridge(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        up_reader, up_writer = await asyncio.open_unix_connection(str(DISCORD_EGRESS_SOCKET_PATH))
    except OSError as exc:
        _log.warning("discord.egress.shim.upstream_unavailable", error=repr(exc))
        writer.close()
        return
    try:
        await asyncio.gather(splice(reader, up_writer), splice(up_reader, writer))
    finally:
        for w in (up_writer, writer):
            try:
                w.close()
            except OSError:  # pragma: no cover - defensive close
                pass


async def start_shim() -> asyncio.AbstractServer:
    """Bind 127.0.0.1:PORT and serve the bridge. The caller AWAITS this (listening) before
    discord.py's first egress, and binds the returned server to the adapter crash discipline."""
    server = await asyncio.start_server(_bridge, "127.0.0.1", DISCORD_EGRESS_SHIM_PORT)
    _log.info("discord.egress.shim.listening", port=DISCORD_EGRESS_SHIM_PORT)
    return server
```

- [ ] **Step 4: Run** → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/egress/adapter_proxy_shim.py tests/unit/egress/test_adapter_proxy_shim.py
git commit -m "feat(egress): in-child TCP->unix egress shim for the Discord adapter (#333)"
```

---

### Task 7: Mount the listener + exit 9 + except-ordering

**Files:**

- Modify: `src/alfred/cli/gateway/_commands.py`
- Test: `tests/unit/cli/gateway/test_adapter_egress_mount.py` (create or extend the existing gateway-start test)

**Interfaces:**

- Consumes: `build_adapter_egress_proxy`, `serve_adapter_egress_failclosed`, `EgressAdapterProxyUnavailableError`.
- Produces: `_EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED = 9`; a 4th fail-closed TaskGroup task.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/cli/gateway/test_adapter_egress_mount.py
import alfred.cli.gateway._commands as c

def test_adapter_exit_code_is_nine_and_distinct():
    assert c._EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED == 9
    assert len({c._EXIT_EGRESS_PROXY_BIND_FAILED,
                c._EXIT_EGRESS_RELAY_BIND_FAILED,
                c._EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED}) == 3

def test_adapter_except_precedes_io_plane(monkeypatch):
    # Static guard: the source orders the adapter except-clause before the IOPlane one.
    import inspect
    src = inspect.getsource(c.start_gateway if hasattr(c, "start_gateway") else c._run_gateway)
    a = src.index("EgressAdapterProxyUnavailableError")
    i = src.index("except IOPlaneUnavailableError")
    assert a < i, "adapter except-clause (subtype) must precede IOPlaneUnavailableError"
```

(If `start_gateway`'s handlers live in a different function, point `inspect.getsource` at it; the existing `EgressRelayUnavailableError` handler at `_commands.py:354` is in the same function — clone its placement.)

- [ ] **Step 2: Run to verify fail** → `AttributeError: _EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED`.

- [ ] **Step 3: Implement** in `_commands.py`:

1. Add `_EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED = 9` next to the existing exit codes (`:67`/`:74`).
2. Add a `_serve_adapter_egress_failclosed` wrapper mirroring `_serve_egress_relay_failclosed` (`:179-193`) — or call `serve_adapter_egress_failclosed` from the listener module directly.
3. In `_main`: `from alfred.gateway.adapter_egress_listener import build_adapter_egress_proxy, serve_adapter_egress_failclosed`; build `adapter_proxy, adapter_sock = build_adapter_egress_proxy(extra_allowlist=os.environ.get("ALFRED_DISCORD_EGRESS_ALLOWLIST", ""))` in the same construct-before-TaskGroup block (next to `proxy`/`relay`); add `tg.create_task(serve_adapter_egress_failclosed(adapter_proxy, adapter_sock, shutdown_event))` to the TaskGroup (`:345-348`).
4. Add the handler **before** `except IOPlaneUnavailableError` (`:362`) — i.e. alongside the relay's (`:354`):

```python
        except EgressAdapterProxyUnavailableError as exc:
            _emit_friendly_failure("gateway.start.egress_adapter_bind_failed", exc)
            raise typer.Exit(code=_EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED) from exc
```

Import `EgressAdapterProxyUnavailableError` in the same `from alfred.egress.errors import ...` line (`:233`), placed first in the catch order (subtype before `IOPlaneUnavailableError`; sibling to `EgressRelayUnavailableError` — order between siblings is irrelevant, both before the base).

- [ ] **Step 4: Run** → PASS; then `make check`.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/gateway/_commands.py tests/unit/cli/gateway/test_adapter_egress_mount.py
git commit -m "feat(egress): mount the Discord egress listener fail-closed (exit 9, subtype-first catch) (#333)"
```

---

### Task 8: discord.py `proxy=` threading + the shim in `server.serve()`

**Files:**

- Modify: `plugins/alfred_discord/discord_gateway.py`, `plugins/alfred_discord/server.py`
- Test: `tests/unit/plugins/alfred_discord/test_proxy_threading.py` (create)

**Interfaces:**

- Consumes: `discord_proxy_url`, `start_shim` (Tasks 4/6).
- Produces: `AlfredDiscordBot(*, proxy: str | None = None, ...)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/plugins/alfred_discord/test_proxy_threading.py
import inspect
from plugins.alfred_discord.discord_gateway import AlfredDiscordBot
import plugins.alfred_discord.server as server

def test_bot_accepts_and_forwards_proxy():
    sig = inspect.signature(AlfredDiscordBot.__init__)
    assert "proxy" in sig.parameters
    src = inspect.getsource(AlfredDiscordBot.__init__)
    assert "proxy=proxy" in src  # forwarded to super().__init__

def test_server_starts_shim_before_stdin_loop():
    src = inspect.getsource(server.serve)
    assert "start_shim" in src
    assert src.index("start_shim") < src.index("_serve_stdin_stdout")

def test_no_webhook_or_voice_egress():
    # Guard: the adapter must not introduce webhook/voice egress (they bypass Client.proxy).
    import plugins.alfred_discord.server as s
    text = inspect.getsource(s)
    assert "Webhook" not in text and "VoiceClient" not in text
```

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement**

`discord_gateway.py` (`:72-81`): add `proxy: str | None = None` to `__init__` params and forward it:

```python
        super().__init__(
            command_prefix="!", intents=_least_privilege_intents(), proxy=proxy
        )
```

`server.py`:

- In `_build_server` (`:241`/`:257`) pass `proxy=discord_proxy_url()` to `AlfredDiscordBot(...)` (import `from alfred.egress.adapter_egress_addr import discord_proxy_url`).
- In `serve()` (`:279`), after `configure_stderr_json_logging()` (`:286`) and **before** `await _serve_stdin_stdout(server)`:

```python
    from alfred.egress.adapter_proxy_shim import start_shim
    shim = await start_shim()  # listening before discord.py's first egress
    server.bind_shim(shim)     # bind to the crash discipline (see below)
```

- Add supervised termination: have the shim server's lifetime owned by the adapter's structured concurrency. The cleanest in-pattern hook is the bot's `crash_forwarder` (`discord_gateway.py:89`) — attach a done-callback so a shim-serving-task exception routes through `handle_crash` (a terminal, audited adapter exit), NOT a bare orphan task. Implement `DiscordServer.bind_shim` to register `shim` for close on teardown and wrap its `serve_forever` task with `task.add_done_callback(self._on_shim_done)` where `_on_shim_done` calls the crash forwarder on a non-cancellation exception (mirror `egress_proxy._on_connection_done`, `:189`).

- [ ] **Step 4: Run** → PASS; `make check`.

- [ ] **Step 5: Commit**

```bash
git add plugins/alfred_discord/discord_gateway.py plugins/alfred_discord/server.py tests/unit/plugins/alfred_discord/test_proxy_threading.py
git commit -m "feat(discord): route adapter egress via Client(proxy=) + supervised in-child shim (#333)"
```

---

### Task 9: bwrap policy migration + migrate the policy test

**Files:**

- Modify: `config/sandbox/discord-adapter.linux.bwrap.policy`
- Modify: `tests/unit/plugins/test_discord_adapter_sandbox_policy.py`
- Test: the same test file (flip the `#230`-deferral assertions to enforced).

- [ ] **Step 1: Update the policy test FIRST (TDD)** — find the assertion that `net` is NOT in `policy.unshare` (the `#230`-deferral) and INVERT it:

```python
def test_discord_policy_unshares_net_for_egress_containment():
    policy = read_policy_toml(_DISCORD_POLICY_PATH)
    assert "net" in policy.unshare  # G7-4: empty netns; egress only via the bind-mounted proxy socket
```

Add an assertion that the policy ro-binds the egress socket dir (the parent of `DISCORD_EGRESS_SOCKET_PATH`).

- [ ] **Step 2: Run to verify fail** → the current policy has no `net` in `unshare`.

- [ ] **Step 3: Edit the policy file**

- `unshare = ["pid", "uts", "cgroup", "ipc"]` → `unshare = ["pid", "uts", "cgroup", "ipc", "net"]`.
- Add to `ro_binds`: `["/home/alfred/.egress/discord", "/home/alfred/.egress/discord"]` (the gateway-only egress socket dir; ro-bind preferred per §3 #6 — verify `connect()` works in the bookworm repro, fall back to `rw_binds` only if it fails).
- Rewrite BOTH egress comment blocks (the "DELIBERATELY DO NOT unshare net" note ~L76-78 AND the "EGRESS IS CURRENTLY UNRESTRICTED — #230" header ~L92-115) to the enforced posture: net is unshared; egress is ONLY via the bind-mounted gateway proxy socket; reference ADR-0043. **Do NOT touch the unrelated `#230` `/usr`-prefix-tightening reference at ~L46-48.**

- [ ] **Step 4: Run** the migrated policy test → PASS.

- [ ] **Step 5: Commit**

```bash
git add config/sandbox/discord-adapter.linux.bwrap.policy tests/unit/plugins/test_discord_adapter_sandbox_policy.py
git commit -m "feat(sandbox): Discord policy --unshare-net + bind-mounted egress socket (#333)"
```

---

### Task 10: Compose — gateway-only volume + env + invariants

**Files:**

- Modify: `docker-compose.yaml`
- Modify: `tests/unit/test_compose_invariants.py`

- [ ] **Step 1: Write the failing compose-invariant tests**

```python
# in tests/unit/test_compose_invariants.py
def test_discord_egress_volume_gateway_only(compose):
    gw = compose["services"]["alfred-gateway"]["volumes"]
    core = compose["services"]["alfred-core"].get("volumes", [])
    assert any("alfred_discord_egress" in v for v in gw)
    assert not any("alfred_discord_egress" in v for v in core), \
        "devops-001: the Discord egress volume must NOT be mounted into the core"

def test_discord_egress_allowlist_env_gateway_only(compose):
    gw = compose["services"]["alfred-gateway"]["environment"]
    core = compose["services"]["alfred-core"]["environment"]
    assert "ALFRED_DISCORD_EGRESS_ALLOWLIST" in gw
    assert "ALFRED_DISCORD_EGRESS_ALLOWLIST" not in core
```

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Edit `docker-compose.yaml`**

- Add a top-level volume: `alfred_discord_egress:` (next to `alfred_run:` at `:281`).
- Mount it into **`alfred-gateway` ONLY** (`:254` area): `- alfred_discord_egress:/home/alfred/.egress`. Do NOT add it to `alfred-core`.
- Add `ALFRED_DISCORD_EGRESS_ALLOWLIST: ${ALFRED_DISCORD_EGRESS_ALLOWLIST:-}` to the **gateway** environment only.
- `.env.example`: document `ALFRED_DISCORD_EGRESS_ALLOWLIST=` (empty default = the built-in discord.com + *.discord.gg set).

- [ ] **Step 4: Run** → PASS.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py .env.example
git commit -m "feat(compose): gateway-only alfred_discord_egress volume + Discord allowlist env (#333)"
```

---

### Task 11: CI coverage gates for the new boundary modules

**Files:**

- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1:** Add a per-file 100% step (mirroring `ci.yml:114`/`:133`) in **both** the `python` job and the `coverage-gates` job, for the 3 new modules:

```yaml
      - name: Egress adapter-bridge per-file coverage gate
        if: steps.check.outputs.has_py == 'true' && hashFiles('src/alfred/egress/byte_splice.py') != ''
        run: |
          uv run coverage report \
            --include='src/alfred/egress/byte_splice.py,src/alfred/egress/adapter_proxy_shim.py,src/alfred/egress/adapter_egress_addr.py,src/alfred/gateway/adapter_egress_listener.py' \
            --fail-under=100
```

(`allowlist.py` and `egress_proxy.py` are already in their existing gates; the matcher additions ride those — confirm they stay at 100%.)

- [ ] **Step 2: Verify locally** that the new modules hit 100% line+branch:

```bash
uv run coverage run -m pytest tests/unit/egress tests/unit/gateway/test_adapter_egress_listener.py
uv run coverage report --include='src/alfred/egress/byte_splice.py,src/alfred/egress/adapter_proxy_shim.py,src/alfred/egress/adapter_egress_addr.py,src/alfred/gateway/adapter_egress_listener.py' --fail-under=100
```

Expected: `TOTAL ... 100%`. Add tests for any uncovered branch.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(egress): per-file 100% coverage gate for the Discord egress-bridge modules (#333)"
```

---

### Task 12: Adversarial corpus + docker-gated kernel proof

**Files:**

- Create: `tests/adversarial/sandbox_escape/sbx_2026_014_discord_outbound_network_contained.yaml`
- Modify: `tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py`
- Create: `tests/integration/egress/test_discord_policy_kernel_enforced.py`

- [ ] **Step 1: Create the corpus entry** (mint the next-free id — confirm `014` is free; `sbx-2026-005` is the quarantine marker, leave it):

```yaml
id: sbx-2026-014
category: sandbox_escape
threat: >-
  A runtime-compromised Discord adapter opens an outbound TCP connection to an
  arbitrary attacker host to exfiltrate the T3 content it relays + its bot token.
  Spec C G7-4 (#333) --unshare-net's it into an EMPTY network namespace; egress is
  ONLY via the bind-mounted gateway L7 CONNECT proxy socket (Discord allowlist). The
  direct connection is refused at the kernel.
ingestion_path: sandbox_policy_load
payload:
  attack: outbound_network_egress_to_arbitrary_host
  policy_ref: config/sandbox/discord-adapter.linux.bwrap.policy
  probe: socket.create_connection(('attacker.example', 443))
expected_outcome: refused
provenance: >-
  G7-4 (#333) ships the Discord adapter under ``--unshare-net`` (ADR-0043),
  closing the egress gap deferred in pre-G7-4 policy versions. All outbound
  network access routes exclusively through the bind-mounted gateway L7 CONNECT
  forward-proxy socket; a direct ``connect(2)`` is refused at the kernel.
references:
  - "config/sandbox/discord-adapter.linux.bwrap.policy (EGRESS via gateway proxy only — unshare net)"
  - "docs/adr/0043-discord-adapter-egress-l7-proxy-netns-bridge.md"
```

- [ ] **Step 2: Add the executable assertion** to `test_sbx_corpus_executable.py` (mirror `test_sbx_2026_005_*` at `:530`, keyed to the DISCORD policy; do not touch the 005 assertion):

```python
def test_sbx_2026_014_discord_outbound_contained() -> None:
    payload = _load("sbx-2026-014")
    policy = read_policy_toml(payload["payload"]["policy_ref"])
    assert "net" in policy.unshare
```

Add `"sbx-2026-014"` to the corpus-id completeness list (`:553`).

- [ ] **Step 3: Create the kernel proof** in the `integration-privileged` lane (clone `tests/integration/test_quarantined_llm_policy_kernel_enforced.py`; run euid-0 so the netns is configurable). Assert: (a) direct external connect blocked, (b) `getaddrinfo` external fails, (c) an allowlisted host via the bridge succeeds, (d) a non-allowlisted host via the bridge denied. Reuse the `RTM_NEWADDR` skip-guard for restricted runners + a **per-test not-skipped** assertion pinned to the privileged lane (do NOT use the plain-lane `#245` guard — opposite skip semantics).

- [ ] **Step 4: Run** the unit-runnable parts; run the docker-gated proof under `DOCKER_HOST=unix://$HOME/.docker/run/docker.sock`. Then `uv run pytest tests/adversarial -q` (release-blocking).

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/sandbox_escape/sbx_2026_014_*.yaml tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py tests/integration/egress/test_discord_policy_kernel_enforced.py
git commit -m "test(egress): sbx-2026-014 Discord egress-contained + docker-gated kernel proof (#333)"
```

---

### Task 13: Docs, ADR-0043, i18n

**Files:**

- Create: `docs/adr/0043-discord-adapter-egress-l7-proxy-netns-bridge.md`
- Modify: `docs/adr/0016-*.md`, `docs/adr/0015-*.md`, `docs/subsystems/comms.md`, `docs/subsystems/security.md`, `config/sandbox/README.md`, the Spec C design doc, `locale/en/LC_MESSAGES/alfred.po`.

- [ ] **Step 1: Write ADR-0043** per §10 of the spec (the AF_UNIX bridge; second proxy instance; per-caller allowlist via listener reachability + why SO_PEERCRED was dropped; the non-enforcing shim; decision-10 reconciliation; honest residuals incl. the kernel-blocked-egress audit blind-spot; **why the socket is on a gateway-only volume — devops-001**).
- [ ] **Step 2: Amend ADR-0016** (G7-4 block → ADR-0043; close the **Discord half** of `#230`; flip status). **Amend ADR-0015** to record Discord egress closed but **PRESERVE its 2c real-LLM deferral** (`#230` is NOT fully closed). Cross-ref ADR-0036.
- [ ] **Step 3: Update deep-docs** — `comms.md` (~L341-372: the policy now `--unshare-net`s, egress via the proxy); **ADD** a brief egress-planes note to `security.md` (it has none today); `config/sandbox/README.md` (Discord egress closed; preserve the 2c `#230` deferral, same surgical exclusion the policy got).
- [ ] **Step 4: Spec erratum note** in the Spec C design doc (mirror the G7-1 §3 TCP-proxy reconciliation note): factual decision-10 reconciliation; correct "one L7 CONNECT *listener*" → "one *implementation*, per-caller instances". (CLAUDE.md #9 + PRD §5/§7.1 + ADR-0040 stay human-gated → G7-5 — do NOT edit.)
- [ ] **Step 5: i18n** — add the operator strings (`gateway.start.egress_adapter_bind_failed`, any shim-failure message) to the catalog source; run `pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins` → `pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching` → fill the English msgstr → `pybabel compile -d locale -D alfred --statistics`. Verify `pybabel ... --check` (CI uses `--ignore-pot-creation-date`) exits 0.
- [ ] **Step 6: Lint + commit** — `npx markdownlint-cli2 docs/**` (no `--fix`; fix tables by hand).

```bash
git add docs/adr/0043-*.md docs/adr/0016-*.md docs/adr/0015-*.md docs/subsystems/comms.md docs/subsystems/security.md config/sandbox/README.md docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo
git commit -m "docs(egress): ADR-0043 + G7-4 deep-doc + i18n for the Discord egress bridge (#333)"
```

---

## Final verification (before the PR)

- [ ] `make check` (lint + format + mypy + pyright + unit/integration) green.
- [ ] `uv run pytest tests/adversarial -q` green (release-blocking — security/sandbox boundary touched).
- [ ] Docker-gated kernel proof green under `DOCKER_HOST=unix://$HOME/.docker/run/docker.sock`.
- [ ] The two-pass review: full `/review-pr` fleet (security ALWAYS) + CodeRabbit CLI (`--base origin/main`) + cloud.

## Punch-list (Low — carry into implementation, no separate task)

- A caller label on the shared egress audit row (sec-001).
- A test asserting the TOML policy bind-path string equals `DISCORD_EGRESS_SOCKET_PATH`'s parent (comms Low — the TOML can't import the Python constant).
- The `--ro-bind`-vs-`--bind` socket `connect()` bookworm-repro result decides Task 9's bind mode.
- CDN/media hosts (`cdn.discordapp.com`/`media.discordapp.net`) stay out until attachment-fetch is added (text-only inbound today).
