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
from urllib.parse import urlsplit

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
        # HTTPS_PROXY / NO_PROXY in the core container env must NOT be able to
        # redirect or BYPASS the gateway proxy (NO_PROXY would otherwise let httpx
        # connect a matching host directly, escaping the connectivity-free-core
        # invariant). Only proxy + follow_redirects are otherwise set, so the client
        # uses httpx's default connection limits / HTTP-version / transport timeouts,
        # NOT the provider SDK's _Default*HttpxClient tuning (those apply only to the
        # SDK-built client, which the injected client replaces). Acceptable for the
        # G7-1 forward-proxy hop; revisit the limits before G7-3 deletes the direct
        # fallback and the proxied path becomes the only egress.
        return httpx.AsyncClient(proxy=self._proxy_url, follow_redirects=False, trust_env=False)


__all__ = ["EgressClient"]
