"""The closed web.fetch auth-secret allowlist + the broker-substituter seam.

Confused-deputy defence for authenticated ``web.fetch`` (#347 blocker 4, ADR-0048):
a ``{{secret:<name>}}`` placeholder in a request header may reference ONLY a secret
name in :data:`WEB_FETCH_AUTH_SECRET_ALLOWLIST`. Mirrors
``adapter_credential_resolver._ADAPTER_SECRET_ALLOWLIST``.

Ships EMPTY: no ``SUPPORTED_SECRET`` is a third-party web-auth token, so there is
no live binding in #339. A future authenticated integration adds both a new
``SUPPORTED_SECRET`` and an entry here (behind operator config + its own review).
"""

from __future__ import annotations

from typing import Final, Protocol

WEB_FETCH_AUTH_SECRET_ALLOWLIST: Final[frozenset[str]] = frozenset()


class _SecretSubstituter(Protocol):
    """Structural shape of the broker surface ``dispatch_web_fetch`` consumes.

    Matches :meth:`alfred.security.secrets.SecretBroker.substitute`. A Protocol
    (not the concrete class) so unit tests can inject a fake without a real broker.
    """

    def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str: ...


__all__ = ["WEB_FETCH_AUTH_SECRET_ALLOWLIST", "_SecretSubstituter"]
