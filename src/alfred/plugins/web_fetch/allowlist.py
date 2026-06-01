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

Broadening cap: when a manifest entry cannot pair with any operator
entry the effective allowlist drops it AND a
:class:`BroadeningCapEvent` is emitted on every manifest load. Two
cap shapes flow through:

* **Domain cap** — the operator declares no entry on the manifest
  entry's domain.
* **Path-prefix cap** (sec-pr-s3-5-002) — the operator declares
  entries on the domain but every operator path_prefix is disjoint
  from the manifest's (e.g. operator ``/public/`` vs manifest
  ``/admin/``). The manifest entry is dropped — silently preserving
  the manifest's path_prefix would let it widen past the operator's
  narrowing.

The event flows to the ``web.allowlist.manifest_broadening_capped``
audit row (spec §7.4, §13
``WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS``). This gives the
operator a forensic trail of "the plugin tried to widen, we capped it"
without surfacing a runtime refusal at fetch time (the capping is
done at intersection-construction time, not at check time).

Path-prefix granularity: each :class:`AllowlistEntry` carries a
``path_prefix`` (default ``/``) so an operator can permit
``example.com/public/`` while refusing ``example.com/admin/``. The
intersection pairs manifest/operator/session entries that lie on a
common prefix chain — the narrowest (longest) wins per pair — and
the per-fetch check matches both the domain AND the path prefix at
:meth:`AllowlistIntersection.check` time.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from urllib.parse import urlparse

from alfred.plugins.web_fetch.errors import WebFetchDomainNotAllowed


def _prefix_chain_compatible(a: str, b: str) -> bool:
    """Return ``True`` iff ``a`` and ``b`` lie on a common prefix chain.

    Both inputs are path_prefix strings guaranteed by
    :meth:`AllowlistEntry.__post_init__` to start AND end with ``/``.
    Two prefixes are prefix-chain compatible when one is an ancestor of
    the other in the path tree — equivalently, the shorter prefix is a
    leading segment of the longer one. Since both end in ``/``, a single
    ``startswith`` either way is segment-aligned (CR-145).

    The equal case (``a == b``) is handled trivially by either branch.
    """
    return a.startswith(b) or b.startswith(a)


def _narrower(a: str, b: str) -> str:
    """Return whichever of ``a``/``b`` describes the deeper sub-tree.

    Callers MUST first establish that the two prefixes are prefix-chain
    compatible via :func:`_prefix_chain_compatible`; this function is a
    pure "pick the longer" helper. Length is a valid stand-in for depth
    because both prefixes share their leading characters by construction.
    """
    return a if len(a) >= len(b) else b


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

    ``path_prefix`` is normalised at construction time to end with ``/``
    so segment-aligned matching is unambiguous: an entry for
    ``/public`` matches ``/public/`` and ``/public/file`` but NOT
    ``/publicadmin`` (CR-145 web-fetch security review — path-prefix
    substring/traversal bypass).
    """

    domain: str
    path_prefix: str = "/"

    def __post_init__(self) -> None:
        # Normalise the path_prefix so segment-aligned matching is
        # unambiguous. Without this, ``path_prefix="/public"`` would
        # match request path ``/publicadmin/secret`` via str.startswith
        # — a substring bypass that lets a path-prefix narrowing be
        # silently widened. Storing the trailing slash forces
        # segment-aligned comparison at check() time.
        if not self.path_prefix.startswith("/"):
            msg = f"AllowlistEntry.path_prefix must start with '/'; got {self.path_prefix!r}"
            raise ValueError(msg)
        normalised = self.path_prefix if self.path_prefix.endswith("/") else self.path_prefix + "/"
        # frozen=True forbids __setattr__; use object.__setattr__ to
        # bypass for the init-time normalisation (canonical Python idiom
        # for frozen dataclass post-init coercion).
        object.__setattr__(self, "path_prefix", normalised)


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
    that fail to pair with any (manifest ∩ operator) entry on a common
    prefix chain. A session entry pointing at a domain the operator
    does NOT permit — or a path sub-tree disjoint from every operator
    permission on that domain — is silently dropped from the effective
    set. The session never widens the surface; it can only narrow
    further within the (manifest ∩ operator) sub-trees.
    """

    def __init__(
        self,
        *,
        manifest: list[AllowlistEntry],
        operator: list[AllowlistEntry],
        session: list[AllowlistEntry],
    ) -> None:
        self._manifest_entries: tuple[AllowlistEntry, ...] = tuple(manifest)
        self._operator_entries: tuple[AllowlistEntry, ...] = tuple(operator)

        # sec-pr-s3-5-002: the intersection must respect path-prefix
        # narrowing across tiers. The pre-fix construction was domain-
        # keyed only — it dropped manifest entries whose ``domain`` was
        # absent from ``operator_domains`` but then unconditionally
        # preserved the manifest entry's path_prefix on every surviving
        # entry. That silently widened operator narrowing: operator
        # ``(d, /public/)`` + manifest ``(d, /admin/)`` produced an
        # effective entry of ``(d, /admin/)``, so ``/admin/secret``
        # passed the check.
        #
        # The corrected rule pairs each (manifest, operator) entry on the
        # same domain and only produces an effective entry when one
        # prefix is a *prefix-chain ancestor* of the other (so the two
        # describe the same sub-tree at different depths). The narrower
        # — i.e. longer — prefix wins. Disjoint sub-trees (e.g.
        # ``/public/`` vs ``/admin/``) produce no effective entry AND
        # surface as a BroadeningCapEvent.capped_domains entry so the
        # audit graph records the attempted widening.

        # Step 1: pair manifest entries with operator entries on the same
        # domain. Each (manifest, operator) pair that shares a prefix
        # chain produces one effective entry whose path_prefix is the
        # narrower (longer) of the two. A manifest entry that matches no
        # operator entry on a prefix chain is fully capped.
        manifest_operator: list[AllowlistEntry] = []
        manifest_capped_entries: list[AllowlistEntry] = []
        for m_entry in manifest:
            # Find every operator entry that shares a prefix chain with
            # this manifest entry on the same domain. ``m_entry`` can
            # legitimately pair with multiple operator paths (e.g.
            # manifest ``(d, /)`` + operator ``[(d, /api/), (d, /public/)]``
            # → both pairs survive, producing two effective entries).
            pairs = [
                AllowlistEntry(
                    domain=m_entry.domain,
                    path_prefix=_narrower(m_entry.path_prefix, o_entry.path_prefix),
                )
                for o_entry in operator
                if o_entry.domain == m_entry.domain
                and _prefix_chain_compatible(m_entry.path_prefix, o_entry.path_prefix)
            ]
            if pairs:
                manifest_operator.extend(pairs)
            else:
                # Either the domain is absent from operator (classic
                # domain cap) or every operator entry on this domain
                # describes a disjoint sub-tree (path cap). Both surface
                # via the same BroadeningCapEvent so reviewers see the
                # full forensic trail.
                manifest_capped_entries.append(m_entry)
        self._manifest_capped_entries: tuple[AllowlistEntry, ...] = tuple(manifest_capped_entries)

        # Step 2: narrow session against the (manifest ∩ operator) set
        # using the same prefix-chain rule. A session entry on a domain
        # absent from manifest_operator is dropped (domain narrowing); a
        # session entry on a present domain but with a disjoint path
        # sub-tree is also dropped (path narrowing). Session cannot
        # broaden — only further restrict.
        #
        # Each (mo_entry, session_entry) pair that shares a prefix chain
        # contributes one effective entry whose path_prefix is the
        # narrower of the two. Multiple session entries can pair with
        # one mo_entry — operators declaring e.g. ``[/api/v1/, /api/v2/]``
        # against an mo_entry of ``/api/`` produce TWO effective entries,
        # one per session declaration. The check loop is a linear scan
        # and any matching effective entry permits the URL, so emitting
        # multiple entries is "union of permitted sub-trees" — the
        # semantics callers expect.
        effective: list[AllowlistEntry] = []
        for mo_entry in manifest_operator:
            for s_entry in session:
                if s_entry.domain != mo_entry.domain:
                    continue
                if not _prefix_chain_compatible(mo_entry.path_prefix, s_entry.path_prefix):
                    continue
                candidate_prefix = _narrower(mo_entry.path_prefix, s_entry.path_prefix)
                effective.append(
                    AllowlistEntry(
                        domain=mo_entry.domain,
                        path_prefix=candidate_prefix,
                    )
                )
        self._effective: tuple[AllowlistEntry, ...] = tuple(effective)

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
        raw_path = parsed.path or "/"

        # CR-145 web-fetch security review — path-prefix substring /
        # traversal bypass. Two defences must compose:
        #
        # 1) Reject explicit ``..`` segments OUTRIGHT. We deliberately
        #    do NOT silently normalise these away because a path
        #    containing ``..`` reaching here means upstream
        #    URL-construction is buggy or the caller is malicious —
        #    silently collapsing would let the audit row claim the
        #    requested URL matched the allowlist when the operator-
        #    submitted URL did not. The audit graph stays honest.
        # 2) Normalise the request path with ``posixpath.normpath`` so
        #    a benign ``/public//file`` (double slash) compares correctly
        #    against ``/public/file``. Then append a trailing slash to
        #    match the trailing-slash convention enforced on entries by
        #    ``AllowlistEntry.__post_init__``.
        if ".." in raw_path.split("/"):
            raise DomainNotAllowed(domain)
        norm_path = posixpath.normpath(raw_path)
        if norm_path == ".":
            norm_path = "/"
        candidate = norm_path if norm_path.endswith("/") else norm_path + "/"

        for entry in self._effective:
            # entry.path_prefix is guaranteed to end with "/" by
            # AllowlistEntry.__post_init__, so this startswith is
            # segment-aligned: "/public/" only matches "/public/..." and
            # NEVER "/publicadmin/...". Defence-in-depth against the
            # substring bypass.
            if entry.domain == domain and candidate.startswith(entry.path_prefix):
                return
        raise DomainNotAllowed(domain)

    def broadening_cap_events(self) -> list[BroadeningCapEvent]:
        """Return a list of broadening-cap events for this manifest load.

        The list is at most length 1 in the current spec (one event per
        manifest load summarises all capped entries), but the API
        returns a list so a future "per-domain event" refinement does
        not break callers. The plugin-host bootstrap iterates the list
        and emits one audit row per event.

        A manifest entry is "capped" when it failed to produce ANY
        effective entry during construction. Two cap shapes flow through:

        * **Domain cap** — the operator declares no entry on this
          manifest entry's domain at all.
        * **Path-prefix cap** (sec-pr-s3-5-002) — the operator declares
          one or more entries on the domain but every operator
          path_prefix describes a disjoint sub-tree from the manifest's
          path_prefix. The manifest entry is silently dropped from the
          effective set; the audit row records WHAT the manifest tried
          to dial so reviewers can see the attempted widening.

        Returns:
            Empty list if every manifest entry produced at least one
            effective entry. Otherwise a single
            :class:`BroadeningCapEvent` summarising the cap. The
            ``capped_domains`` tuple carries the ORIGINAL manifest entry
            (domain + path_prefix) so the forensic trail preserves the
            manifest author's declared intent.
        """
        if not self._manifest_capped_entries:
            return []
        return [
            BroadeningCapEvent(
                manifest_domains=frozenset(e.domain for e in self._manifest_entries),
                operator_allowed_domains=frozenset(e.domain for e in self._operator_entries),
                capped_domains=self._manifest_capped_entries,
            )
        ]


__all__ = [
    "AllowlistEntry",
    "AllowlistIntersection",
    "BroadeningCapEvent",
    "DomainNotAllowed",
]
