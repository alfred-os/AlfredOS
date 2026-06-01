"""TLS verification policy for web.fetch (spec §7.11).

TLS verification is fail-closed: no operator override for production.
``ALFRED_ENV=development`` accepts ``skip_tls_verify=true``.
Localhost/loopback addresses are allowed without TLS (test fixtures,
local integrations).

sec-011 fix — the plugin subprocess runs with a minimal env (PR-S3-3a
Task 6 passes only PATH in the minimal_env). ``ALFRED_ENV`` is NOT in
the minimal env by default, so the subprocess sees ``ALFRED_ENV`` unset,
defaults to ``'production'``, and rejects ``skip_tls=True`` — which is
the correct fail-closed behaviour. However it also means the documented
dev escape hatch (spec §7.11) is broken in the subprocess unless the
parent forwards the var.

Resolution (two-part):

  1. PR-S3-3a Task 6 MUST pass ``ALFRED_ENV`` through in ``minimal_env``
     if set in the parent:

         minimal_env['ALFRED_ENV'] = os.environ.get('ALFRED_ENV', 'production')

     This is a PR-S3-3a fix that PR-S3-5 depends on; documented here so
     reviewers flag it.
  2. :class:`TlsPolicy` validates ``skip_tls=True`` against the
     parent-side ``ALFRED_ENV`` BEFORE dispatching to the subprocess (in
     ``FetchDispatchConfig``). A compromised orchestrator caller or bug
     in the dispatcher cannot rely solely on subprocess-side enforcement.
     The parent-side check is the authoritative gate; the subprocess-side
     check is defence-in-depth only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

import structlog

from alfred.errors import AlfredError
from alfred.i18n import t

log = structlog.get_logger(__name__)

# Loopback hosts that are allowed without TLS — covers IPv4 / IPv6
# localhost and the wildcard ``0.0.0.0`` which testcontainers and the
# integration harness sometimes bind to. ``frozenset`` so module-level
# mutation cannot relax the policy at runtime.
_LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",  # noqa: S104 -- host-name match, not a bind address
    }
)


class TlsConfigError(AlfredError):
    """Raised when TLS skip is configured in a non-development environment."""


@dataclass(frozen=True, slots=True)
class TlsPolicy:
    """Immutable TLS verification policy.

    ``skip_tls_verify=True`` is only valid when ``ALFRED_ENV=development``.
    Any other environment raises :class:`TlsConfigError` at construction
    time (fail-closed). The constructor reads ``ALFRED_ENV`` from the
    process env exactly once and never re-reads it — so a runtime env
    flip cannot relax an already-built policy.
    """

    skip_tls_verify: bool = False

    def __post_init__(self) -> None:
        if self.skip_tls_verify:
            env = os.environ.get("ALFRED_ENV", "production")
            if env != "development":
                # Operator-facing message — routed through t() per
                # CLAUDE.md i18n hard rule #1. The exception surfaces to
                # operator CLI/TUI/logs when skip_tls_verify is turned on
                # outside ALFRED_ENV=development. The msgid carries the
                # spec §7.11 rationale (MITM = canonical T3 ingestion
                # attack; TLS skip is the bypass) so the catalog edit is
                # the single source of truth for the operator-visible
                # wording across every locale.
                raise TlsConfigError(t("web.fetch.tls.skip_refused_in_non_dev", env=env))
            log.warning(
                "tls_policy.skip_enabled",
                env=env,
                note="INSECURE — development mode only",
            )

    @property
    def verify_ssl(self) -> bool:
        """``True`` when TLS verification is enabled (the default)."""
        return not self.skip_tls_verify

    def requires_tls(self, url: str) -> bool:
        """Return ``False`` for loopback hosts (allowed without TLS).

        Loopback exemption covers test fixtures and local integrations
        that legitimately speak plain HTTP. Any other host MUST use HTTPS
        with verification; the dispatcher consults this method before
        constructing the request.
        """
        host = urlparse(url).hostname or ""
        return host not in _LOOPBACK_HOSTS


__all__ = ["TlsConfigError", "TlsPolicy"]
