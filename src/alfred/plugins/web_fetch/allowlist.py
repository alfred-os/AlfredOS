"""Three-way allowlist intersection for web.fetch (spec §7.4).

A URL is reachable iff::

    manifest ∩ operator_config ∩ per_session

…all permit the (domain, path_prefix) pair. The intersection is
*conjunctive* — any one tier refusing the domain refuses the URL.

Tier roles:

* **Manifest** — the plugin author declares the *upper bound* of what
  the plugin is willing to dial. The operator may narrow this; the
  plugin can never widen past its own declaration.
* **Operator config** — the system-tier cap. Defines what the operator
  permits regardless of what plugins or sessions ask for. Lives in
  ``config/policies.yaml`` for low-blast updates and in the state.git
  proposal flow for domain-level changes (PR-S3-7 ships the CLI).
* **Per-session grant** — a *narrowing* further restriction issued at
  conversation-start time. A session grant can refuse a domain the
  operator and manifest both permit; it cannot ADD a domain the operator
  does not permit. The narrowing-only invariant defends against a
  compromised orchestrator caller forging a session grant to widen the
  surface — the operator config remains the ceiling.

Broadening cap: when the manifest declares domains the operator does
not permit, the effective allowlist is capped to the operator set AND
a :class:`BroadeningCapEvent` is emitted on every manifest load. The
capped domains are NOT silently accepted — the event flows to the
``web.allowlist.manifest_broadening_capped`` audit row (spec §7.4, §13
``WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS``). This gives the
operator a forensic trail of "the plugin tried to widen, we capped it"
without surfacing a runtime refusal at fetch time (the capping is
done at intersection-construction time, not at check time).

Path-prefix granularity: each :class:`AllowlistEntry` carries a
``path_prefix`` (default ``/``) so an operator can permit
``example.com/public/`` while refusing ``example.com/admin/``. The
intersection checks both the domain AND the path prefix at
:meth:`AllowlistIntersection.check` time.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from alfred.plugins.web_fetch.errors import WebFetchDomainNotAllowed


class DomainNotAllowed(WebFetchDomainNotAllowed):
    """Alias raised by :meth:`AllowlistIntersection.check` so tests can
    pin against a single concrete type.

    Identical surface to :class:`WebFetchDomainNotAllowed`; the alias
    exists for caller clarity ("this came from the three-way
    intersection") without breaking the inheritance chain that the
    orchestrator's operational-error arm catches.
    """


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    """A single (domain, path_prefix) allowlist tuple.

    ``path_prefix`` defaults to ``/`` so the common case (allow whole
    domain) needs only a domain string. Both fields are matched
    case-sensitively at :meth:`AllowlistIntersection.check` time —
    domain comparison is byte-for-byte against ``urlparse(url).netloc``,
    so an operator entry of ``example.com`` does NOT match
    ``Example.com`` (web servers are typically case-insensitive on
    domain, but the spec keeps the comparison literal to avoid surprise
    matches across operator typos).
    """

    domain: str
    path_prefix: str = "/"


@dataclass(frozen=True, slots=True)
class BroadeningCapEvent:
    """Emitted when manifest declares domains the operator config does not permit.

    Maps to ``WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS`` audit row
    (spec §13). The audit row records:

    * ``manifest_domains`` — every domain the manifest declared.
    * ``operator_allowed_domains`` — every domain the operator permits.
    * ``capped_domains`` — the AllowlistEntry tuples that were dropped
      from the effective set. Carries the path-prefix granularity so
      reviewers can see exactly which entries the manifest tried to
      add.

    The event is constructed once per manifest load (not per fetch); the
    plugin-host bootstrap reads
    :meth:`AllowlistIntersection.broadening_cap_events` and forwards each
    event to the audit writer.
    """

    manifest_domains: frozenset[str]
    operator_allowed_domains: frozenset[str]
    capped_domains: tuple[AllowlistEntry, ...]


class AllowlistIntersection:
    """Computes the effective allowlist as ``manifest ∩ operator ∩ session``.

    Construction is one-shot per session: the intersection is computed
    once when the session is established and reused for every
    :meth:`check` call within the session. This avoids re-walking three
    lists per fetch and keeps the per-fetch hot path to a linear scan of
    a tuple at most as long as the operator's allow-list.

    Narrowing-only session grant: the constructor drops session entries
    whose domain is not in the manifest-capped (i.e. operator-permitted)
    set. A session entry pointing at a domain the operator does NOT
    permit is silently dropped from the effective set — it never widens
    the surface, even if a downstream caller passes one.
    """

    def __init__(
        self,
        *,
        manifest: list[AllowlistEntry],
        operator: list[AllowlistEntry],
        session: list[AllowlistEntry],
    ) -> None:
        # Step 1: cap manifest against operator (narrowing). Any manifest
        # entry whose domain is not in operator_domains is dropped. This
        # is the "manifest cannot widen past operator" rule.
        operator_domains = frozenset(e.domain for e in operator)
        self._manifest_entries: tuple[AllowlistEntry, ...] = tuple(manifest)
        self._operator_entries: tuple[AllowlistEntry, ...] = tuple(operator)
        manifest_capped: tuple[AllowlistEntry, ...] = tuple(
            e for e in manifest if e.domain in operator_domains
        )

        # Step 2: narrow session against the manifest-capped set. A
        # session entry whose domain is not in manifest_capped is
        # dropped — this is the "session cannot broaden past operator"
        # rule (session ⊆ manifest_capped ⊆ operator).
        capped_domain_names = frozenset(e.domain for e in manifest_capped)
        narrowed_session = tuple(e for e in session if e.domain in capped_domain_names)

        # Step 3: final effective set = manifest_capped entries whose
        # domain is in the session set. The intersection preserves the
        # MANIFEST entry's path_prefix (manifest authors are the canonical
        # source for which sub-paths the plugin will dial).
        session_domain_names = frozenset(e.domain for e in narrowed_session)
        self._effective: tuple[AllowlistEntry, ...] = tuple(
            e for e in manifest_capped if e.domain in session_domain_names
        )

    def check(self, url: str) -> None:
        """Raise :class:`DomainNotAllowed` if ``url`` is not in the
        effective allowlist.

        Returns ``None`` on permit. The void-on-success shape mirrors
        :func:`alfred.security.tag` so callers can write
        ``allowlist.check(url)`` as a guard line without binding a
        return value.

        Args:
            url: The full URL to check. Parsed via :func:`urllib.parse.urlparse`;
                the comparison uses ``netloc`` (which excludes port-stripping
                logic — Slice-3 spec does not narrow ports, so the comparison
                is "domain-string-equals" only).

        Raises:
            DomainNotAllowed: domain (or domain+path-prefix) is not in
                the effective allowlist. The exception's ``.domain``
                attribute records what was refused so the audit row can
                be populated without parsing the message.
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        # A URL like "https://example.com" parses to path="" — normalise
        # to "/" so a manifest entry path_prefix="/" still matches.
        path = parsed.path or "/"
        for entry in self._effective:
            if entry.domain == domain and path.startswith(entry.path_prefix):
                return
        raise DomainNotAllowed(domain)

    def broadening_cap_events(self) -> list[BroadeningCapEvent]:
        """Return a list of broadening-cap events for this manifest load.

        The list is at most length 1 in the current spec (one event per
        manifest load summarises all capped entries), but the API
        returns a list so a future "per-domain event" refinement does
        not break callers. The plugin-host bootstrap iterates the list
        and emits one audit row per event.

        Returns:
            Empty list if the manifest declared no domains outside the
            operator allow-list. Otherwise a single
            :class:`BroadeningCapEvent` summarising the cap.
        """
        operator_domains = frozenset(e.domain for e in self._operator_entries)
        capped = tuple(e for e in self._manifest_entries if e.domain not in operator_domains)
        if not capped:
            return []
        return [
            BroadeningCapEvent(
                manifest_domains=frozenset(e.domain for e in self._manifest_entries),
                operator_allowed_domains=operator_domains,
                capped_domains=capped,
            )
        ]


__all__ = [
    "AllowlistEntry",
    "AllowlistIntersection",
    "BroadeningCapEvent",
    "DomainNotAllowed",
]
