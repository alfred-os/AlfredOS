"""alfred-web-fetch MCP plugin — Slice 3 (spec §7.1).

MCP server subprocess loaded by :class:`AlfredPluginSession` (PR-S3-3a)
via :class:`alfred.plugins.stdio_transport.StdioTransport`. Exposes a
single JSON-RPC method, ``web.fetch(url, headers, redis_url)``, which
returns a ``ContentHandleJSON`` payload.

Architecture (host owns the trust-boundary primitives; the plugin owns
the network call and the local content-store write):

  1. Validate URL against the effective allowlist — HOST-SIDE before
     dispatch. The plugin assumes the host already capped to the
     three-way intersection; no per-call recheck here.
  2. Lua-atomic rate-limit check — HOST-SIDE before dispatch.
  3. Make HTTPS GET (TLS fail-closed per :class:`TlsPolicy`).
  4. Enforce MIME-type + size limits.
  5. Persist body to the Redis content store keyed under
     ``alfred:content:{handle_id}``.
  6. Return ``ContentHandleJSON`` to the host.

The host (``StdioTransport``) fires the ``tool.web.fetch`` hookpoint
AFTER receiving the handle; the system-tier
:class:`InboundCanaryScanner` runs as a post-subscriber on that
hookpoint.

err-004 boundary discipline: the JSON-decode arm of the stdio loop
emits a structured ``-32700`` parse-error frame so the orchestrator
never hangs waiting for a response. Any OTHER exception in
``_handle_fetch`` is a programming bug, not a protocol event — we
deliberately do NOT catch it so the subprocess exits with a non-zero
code and the host detects the crash via the ``plugin.lifecycle.crashed``
exit-code path.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import aiohttp
import structlog

# perf-006 fix: ContentStore is imported at module top so the
# ``_SHARED_STORE: ContentStore | None`` annotation resolves at runtime
# without ``from __future__ import annotations`` games and without a
# duplicate local import inside ``_handle_fetch``. The plugin runs in
# the same venv as the host (no separate sandbox process boundary on
# the Python layer), so the import is cheap and the type stays honest.
from alfred.plugins.web_fetch.content_store import ContentStore
from alfred.plugins.web_fetch.errors import WebFetchInternalIPRefused
from alfred.plugins.web_fetch.host_ip_guard import check_url_host_ips
from alfred.plugins.web_fetch.tls_policy import TlsConfigError, TlsPolicy

log = structlog.get_logger(__name__)

# Allowed MIME types — closed set. Adding a MIME requires an explicit
# manifest declaration and a security-review pass so the surface area
# for content-type-laundering attacks stays narrow (spec §7.1).
_ALLOWED_MIME_TYPES = frozenset(
    {
        "text/html",
        "text/plain",
        "application/json",
        "application/xml",
        "text/markdown",
    }
)

# 5 MB default size limit. Operator can narrow per-call via the
# ``size_limit_bytes`` parameter, but not widen — the host caps at this
# value before dispatch.
_DEFAULT_SIZE_LIMIT_BYTES = 5 * 1024 * 1024


def _clamp_size_limit(raw: Any) -> int:
    """Return a sane positive size limit, capped at the plugin hard cap.

    CR-146 major: the plugin's module comment promises callers may
    narrow the 5 MiB default but never widen — trusting the param
    verbatim let a buggy or compromised caller make the subprocess
    buffer arbitrary data into memory + Redis. Defence-in-depth: the
    host already caps before dispatch, but the plugin owns its own
    ceiling so a capability-bypass exploit at the host layer cannot
    widen here.

    Coercion shape:

    * Non-int (str / float / None / list / dict) → default. ``int(...)``
      raises on dict / list; we catch and silently normalise the
      param-value layer because a malformed config is a quieter
      operator misconfiguration class than a protocol-shape bug
      (err-004 still handles the framing-layer cases loud).
    * Non-positive (zero / negative) → default. A zero-cap fetch is a
      pathological config; defaulting matches the "narrow not widen"
      intent (the operator can configure a real lower bound via
      host-side policy, this plugin never advertises a sub-1 cap).
    * Above the hard cap → hard cap.

    Pulled out as a pure helper so the trust-boundary clamp can be
    unit-tested directly without spinning up the aiohttp / Redis stack.
    """
    try:
        candidate = int(raw)
    except (TypeError, ValueError):
        candidate = _DEFAULT_SIZE_LIMIT_BYTES
    if candidate <= 0:
        candidate = _DEFAULT_SIZE_LIMIT_BYTES
    return min(candidate, _DEFAULT_SIZE_LIMIT_BYTES)


# perf-006 fix: a single ``ContentStore`` (and its Redis connection
# pool) is shared across every dispatch in the plugin-subprocess
# lifetime. Constructing a fresh store per dispatch would re-open a TCP
# + Redis handshake (1-3 ms) on every fetch AND exhaust FDs under
# concurrency. ``_get_or_init_store`` lazily initialises the singleton
# on first call so the redis_url plumbing stays explicit in the
# request payload rather than env-var smuggling.
_SHARED_STORE: ContentStore | None = None


async def _get_or_init_store(redis_url: str) -> ContentStore:
    """Return the module-level :class:`ContentStore`, initialising once.

    The store is keyed by the ``redis_url`` of the FIRST call; subsequent
    calls with a different URL reuse the existing store. This matches
    the plugin-subprocess lifetime model — one host, one Redis, one
    pool. Cross-tenancy across Redis URLs would need a per-URL map and
    is out of scope for Slice 3.
    """
    global _SHARED_STORE  # module-level cache; see docstring.
    if _SHARED_STORE is None:
        _SHARED_STORE = ContentStore(redis_url=redis_url)
    return _SHARED_STORE


async def _handle_fetch(params: dict[str, Any]) -> dict[str, Any]:
    """Execute a single ``web.fetch`` call and return ``ContentHandleJSON``.

    Returns a JSON-RPC result envelope on success (``{"result": {...}}``)
    or a JSON-RPC error envelope on a typed failure (``{"error": {...}}``).
    Untyped exceptions propagate to the stdio loop and crash the
    subprocess — see module docstring on the err-004 discipline.
    """
    url: str = params["url"]
    headers: dict[str, str] = params.get("headers", {})
    redis_url: str = params["redis_url"]
    skip_tls: bool = params.get("skip_tls_verify", False)

    # CR-146 major: plugin-side hard cap. See ``_clamp_size_limit``
    # docstring for the coercion shape and rationale.
    size_limit: int = _clamp_size_limit(params.get("size_limit_bytes", _DEFAULT_SIZE_LIMIT_BYTES))

    try:
        tls_policy = TlsPolicy(skip_tls_verify=skip_tls)
    except TlsConfigError as e:
        # TLS config refused (production + skip_tls_verify=True without
        # the ALFRED_ENV=development escape hatch). Surface as JSON-RPC
        # error -32001 so the host maps to WebFetchTlsError.
        return {
            "error": {
                "code": -32001,
                "message": str(e),
                "data": {"type": "TlsConfigError"},
            }
        }

    # sec-pr-s3-5-003 / H3 — subprocess-side IP guard (defence-in-depth).
    # The host-side guard in ``dispatch_web_fetch`` is the authoritative
    # gate; this second pass closes the DNS-rebinding race window
    # (parent resolved to a safe IP, subprocess's resolution returns an
    # internal one). Code -32006 routes to WebFetchInternalIPRefused via
    # the host-side ``_ERROR_TYPE_MAP``; the ``reason`` data field
    # preserves the closed refusal vocabulary so the audit row gets the
    # same attack-class string the parent-side guard would have emitted.
    try:
        check_url_host_ips(url, tls_policy)
    except WebFetchInternalIPRefused as ip_exc:
        return {
            "error": {
                "code": -32006,
                "message": str(ip_exc),
                "data": {
                    "type": "WebFetchInternalIPRefused",
                    "resolved_ip": ip_exc.resolved_ip,
                    "reason": ip_exc.reason,
                    "dlp_scan_result": "internal_ip_refused",
                },
            }
        }

    # perf-004 fix: 25s total timeout — under the 30s orchestrator action
    # deadline, leaving 5s slack for the host's canary scan + audit
    # write. aiohttp's default is 5min (total=300s) which would consume
    # the full user action budget on a single slow-loris endpoint.
    fetch_timeout = aiohttp.ClientTimeout(total=25.0, connect=5.0, sock_read=20.0)

    connector = aiohttp.TCPConnector(ssl=tls_policy.verify_ssl)
    async with aiohttp.ClientSession(connector=connector, timeout=fetch_timeout) as session:
        try:
            # SSRF defence (spec §7.4, CR-145 security review): refuse
            # redirects in-subprocess. The host validated the ORIGINAL
            # URL against the three-way allowlist before dispatching;
            # an HTTP 3xx hand-off would let an allowlisted endpoint
            # redirect to an internal-IP / non-allowlisted target,
            # silently widening the surface past the operator's cap.
            # The host can re-dispatch to the redirect target through
            # the full allowlist + rate-limit + audit machinery if it
            # actually wants to follow.
            async with session.get(url, headers=headers, allow_redirects=False) as resp:
                if 300 <= resp.status < 400:
                    redirect_target = resp.headers.get("Location", "")
                    return {
                        "error": {
                            "code": -32005,
                            "message": (
                                f"Redirect refused: {resp.status} -> "
                                f"{redirect_target!r}. Host must re-dispatch the "
                                "redirect target through the allowlist."
                            ),
                            "data": {
                                "type": "WebFetchRedirectRefused",
                                "status_code": resp.status,
                                "redirect_target": redirect_target,
                                "dlp_scan_result": "redirect_refused",
                            },
                        }
                    }
                # MIME enforcement BEFORE reading body — refusing on
                # content-type lets us bail before pulling a multi-MB
                # payload that the host would reject anyway.
                content_type = resp.headers.get("Content-Type", "").split(";")[0].strip()
                if content_type not in _ALLOWED_MIME_TYPES:
                    return {
                        "error": {
                            "code": -32002,
                            "message": f"MIME type {content_type!r} not allowed",
                            "data": {
                                "type": "WebFetchMimeTypeNotAllowed",
                                "mime_type": content_type,
                            },
                        }
                    }
                # perf-003 fix: stream the body in chunks and enforce
                # the size cap as we go. Reading the full body first
                # (``resp.read()``) OOMs the subprocess on a malicious
                # endpoint serving a streamed 1 GB body — the size check
                # would fire after the damage is done. Streaming lets us
                # bail at the byte that breaches the limit.
                chunks: list[bytes] = []
                total_bytes = 0
                async for chunk, _ in resp.content.iter_chunks():
                    total_bytes += len(chunk)
                    if total_bytes > size_limit:
                        return {
                            "error": {
                                "code": -32003,
                                "message": (f"Response body exceeded limit {size_limit} bytes"),
                                "data": {
                                    "type": "WebFetchSizeLimitExceeded",
                                    "size_bytes": total_bytes,
                                    "limit_bytes": size_limit,
                                },
                            }
                        }
                    chunks.append(chunk)
                body = b"".join(chunks)
                status_code = resp.status
        except aiohttp.ClientSSLError as e:
            # TLS verification failed — distinct from TlsConfigError
            # (which fires at policy construction). Surfacing as
            # -32004 so the host's error-type-map routes to
            # WebFetchTlsError.
            return {
                "error": {
                    "code": -32004,
                    "message": f"TLS verification failed: {e}",
                    "data": {
                        "type": "WebFetchTlsError",
                        "dlp_scan_result": "tls_verification_failed",
                    },
                }
            }
        except aiohttp.ClientError as e:
            # Other client-side failures (DNS, connection reset, etc.).
            # Generic WebFetchError so the host surfaces a recoverable
            # operational error without leaking the underlying type.
            return {
                "error": {
                    "code": -32000,
                    "message": str(e),
                    "data": {"type": "WebFetchError"},
                }
            }

    # perf-006: use the shared pool (not per-call construct+close).
    store = await _get_or_init_store(redis_url)
    handle = await store.write(body=body, source_url=url)

    return {
        "result": {
            "id": handle.id,
            "source_url": handle.source_url,
            "fetch_timestamp": handle.fetch_timestamp.isoformat(),
            "status_code": status_code,
        }
    }


async def _serve_stdin_stdout() -> None:
    """MCP stdio server loop: read JSON-RPC requests; write responses.

    err-004 fix: malformed JSON returns a structured ``-32700`` parse
    error so the orchestrator gets a response frame and does not hang.
    All other exceptions are deliberately uncaught so the subprocess
    exits with a non-zero code and the host detects the crash via the
    ``plugin.lifecycle.crashed`` audit row — silent swallowing produces
    a hung orchestrator waiting for a frame that never arrives.
    """
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    writer_transport, _writer_protocol = await loop.connect_write_pipe(
        lambda: asyncio.BaseProtocol(), sys.stdout.buffer
    )

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            log.warning("plugin.json_decode_error", detail=str(e))
            err_response = json.dumps(
                {
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": "Parse error",
                        "data": {"detail": str(e)},
                    },
                }
            )
            writer_transport.write((err_response + "\n").encode())
            continue

        method = request.get("method", "")
        req_id = request.get("id")

        if method == "web.fetch":
            response = await _handle_fetch(request.get("params", {}))
        else:
            response = {
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                }
            }

        response["id"] = req_id
        out = (json.dumps(response) + "\n").encode()
        writer_transport.write(out)


if __name__ == "__main__":
    asyncio.run(_serve_stdin_stdout())
