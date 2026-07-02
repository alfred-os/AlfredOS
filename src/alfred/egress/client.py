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
    from alfred.egress._config_protocols import EgressProxyConfig

_log = structlog.get_logger(__name__)


class EgressClient:
    def __init__(self, *, proxy_url: str) -> None:
        self._proxy_url = proxy_url

    @classmethod
    def from_settings(cls, config: EgressProxyConfig) -> EgressClient:
        # Fail closed on any falsy proxy URL (None OR ""). A real Settings never yields ""
        # (the mode="before" _normalize_egress_proxy_url collapses blank->None), so this is
        # zero-behaviour-change for the sole prod caller; but narrowing the param to
        # EgressProxyConfig admits an unnormalized value, so the seam self-defends rather
        # than trusting the producer's normalizer — an empty proxy URL must never build a
        # client. G7-3 (ADR-0042): the connectivity-free core has no direct-egress fallback.
        if not config.egress_proxy_url:
            raise IOPlaneUnavailableError(
                detail=(
                    "ALFRED_EGRESS_PROXY_URL is unset — the connectivity-free core has "
                    "no direct-egress fallback; set it to the gateway L7 CONNECT proxy "
                    "(compose default http://alfred-gateway:8889)."
                )
            )
        return cls(proxy_url=config.egress_proxy_url)

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
