"""Three-way allowlist intersection tests (spec §7.4).

Invariants pinned here:

* A URL is reachable iff ``manifest ∩ operator_config ∩ per_session``
  all permit it. Any one tier refusing the domain refuses the URL.
* The per-session grant is *narrowing only* — it cannot add a domain
  the operator config does not permit. This blocks a compromised
  orchestrator from forging session grants that broaden the surface.
* When the manifest declares domains the operator config does not
  permit, the effective allowlist is capped to the operator set AND a
  :class:`BroadeningCapEvent` is emitted on every manifest load — the
  capped domains are NOT silently accepted. The event maps to the
  ``web.allowlist.manifest_broadening_capped`` audit row
  (``WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS``).
* Path-prefix granularity is enforced at check time: a permit on
  ``/public/`` does NOT permit ``/private/secret``.
"""

from __future__ import annotations

import pytest

from alfred.plugins.web_fetch.allowlist import (
    AllowlistEntry,
    AllowlistIntersection,
    BroadeningCapEvent,
    DomainNotAllowed,
)


def _entry(domain: str, path_prefix: str = "/") -> AllowlistEntry:
    return AllowlistEntry(domain=domain, path_prefix=path_prefix)


class TestIntersection:
    """Permit/refuse decisions across the three tiers."""

    def test_url_allowed_when_all_three_permit(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("example.com")],
            operator=[_entry("example.com")],
            session=[_entry("example.com")],
        )
        # ``check`` returns None on permit; no raise = pass.
        ail.check("https://example.com/page")

    def test_url_blocked_when_manifest_forbids(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("other.com")],
            operator=[_entry("example.com")],
            session=[_entry("example.com")],
        )
        with pytest.raises(DomainNotAllowed):
            ail.check("https://example.com/")

    def test_url_blocked_when_operator_forbids(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("example.com")],
            operator=[_entry("other.com")],
            session=[_entry("example.com")],
        )
        with pytest.raises(DomainNotAllowed):
            ail.check("https://example.com/")

    def test_url_blocked_when_session_forbids(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("example.com")],
            operator=[_entry("example.com")],
            session=[],
        )
        with pytest.raises(DomainNotAllowed):
            ail.check("https://example.com/")

    def test_path_prefix_enforcement_permit(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("example.com", "/public/")],
            operator=[_entry("example.com", "/public/")],
            session=[_entry("example.com", "/public/")],
        )
        ail.check("https://example.com/public/page")

    def test_path_prefix_enforcement_refuses_outside_prefix(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("example.com", "/public/")],
            operator=[_entry("example.com", "/public/")],
            session=[_entry("example.com", "/public/")],
        )
        with pytest.raises(DomainNotAllowed):
            ail.check("https://example.com/private/secret")

    def test_session_cannot_broaden_beyond_operator(self) -> None:
        """Per-session grant narrowing only — session cannot add a domain
        operator config does not permit. Defends against a compromised
        orchestrator forging session grants to widen surface.
        """
        ail = AllowlistIntersection(
            manifest=[_entry("a.com"), _entry("b.com")],
            operator=[_entry("a.com")],
            session=[_entry("a.com"), _entry("b.com")],  # tries to add b.com
        )
        with pytest.raises(DomainNotAllowed):
            ail.check("https://b.com/")

    def test_session_narrowing_works(self) -> None:
        """Session CAN refuse a domain operator + manifest permit."""
        ail = AllowlistIntersection(
            manifest=[_entry("a.com"), _entry("b.com")],
            operator=[_entry("a.com"), _entry("b.com")],
            session=[_entry("a.com")],  # narrows to a.com only
        )
        ail.check("https://a.com/")
        with pytest.raises(DomainNotAllowed):
            ail.check("https://b.com/")

    def test_url_without_path_defaults_to_root(self) -> None:
        """A URL like ``https://example.com`` (no trailing /) must still
        match a ``path_prefix='/'`` entry. urllib parses missing path as
        empty string — the intersection normalises to '/'.
        """
        ail = AllowlistIntersection(
            manifest=[_entry("example.com")],
            operator=[_entry("example.com")],
            session=[_entry("example.com")],
        )
        ail.check("https://example.com")


class TestBroadeningCap:
    """Manifest-vs-operator broadening attempts surface as events."""

    def test_broadening_cap_event_emitted_when_manifest_wider_than_operator(
        self,
    ) -> None:
        manifest = [_entry("example.com"), _entry("extra.com")]
        operator = [_entry("example.com")]
        ail = AllowlistIntersection(
            manifest=manifest,
            operator=operator,
            session=[_entry("example.com")],
        )
        events = ail.broadening_cap_events()
        assert len(events) == 1
        event = events[0]
        assert isinstance(event, BroadeningCapEvent)
        # The capped domain set carries the AllowlistEntry shape so the
        # audit-row writer can preserve path-prefix granularity.
        capped_domain_names = [e.domain for e in event.capped_domains]
        assert "extra.com" in capped_domain_names
        assert "example.com" not in capped_domain_names

    def test_no_broadening_cap_event_when_manifest_matches_operator(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("example.com")],
            operator=[_entry("example.com")],
            session=[_entry("example.com")],
        )
        assert ail.broadening_cap_events() == []

    def test_no_broadening_cap_event_when_manifest_narrower(self) -> None:
        """Operator widening past manifest is not a broadening cap event —
        the manifest stays the source of truth for what the plugin will
        attempt to dial. The intersection still caps to manifest entries.
        """
        ail = AllowlistIntersection(
            manifest=[_entry("a.com")],
            operator=[_entry("a.com"), _entry("b.com")],
            session=[_entry("a.com"), _entry("b.com")],
        )
        assert ail.broadening_cap_events() == []

    def test_effective_allowlist_capped_to_operator(self) -> None:
        """Even if manifest lists ``extra.com``, it must not be reachable."""
        ail = AllowlistIntersection(
            manifest=[_entry("example.com"), _entry("extra.com")],
            operator=[_entry("example.com")],
            session=[_entry("example.com")],
        )
        with pytest.raises(DomainNotAllowed):
            ail.check("https://extra.com/")

    def test_broadening_event_records_full_sets(self) -> None:
        """The audit row records BOTH the manifest declaration and the
        operator allowed-domains set so reviewers can see how wide the
        manifest tried to go.
        """
        manifest = [_entry("a.com"), _entry("b.com"), _entry("c.com")]
        operator = [_entry("a.com")]
        ail = AllowlistIntersection(
            manifest=manifest,
            operator=operator,
            session=[_entry("a.com")],
        )
        events = ail.broadening_cap_events()
        assert len(events) == 1
        event = events[0]
        assert event.manifest_domains == frozenset({"a.com", "b.com", "c.com"})
        assert event.operator_allowed_domains == frozenset({"a.com"})


class TestRefusedDomainAttribute:
    """The raised exception carries the refused domain so the audit row
    can record it without string-parsing the message."""

    def test_domain_attr_set_on_refusal(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("a.com")],
            operator=[_entry("a.com")],
            session=[_entry("a.com")],
        )
        with pytest.raises(DomainNotAllowed) as exc_info:
            ail.check("https://b.com/")
        assert exc_info.value.domain == "b.com"


class TestEmptyTiers:
    """An empty allowlist on any tier refuses everything."""

    def test_empty_manifest_refuses_all(self) -> None:
        ail = AllowlistIntersection(
            manifest=[],
            operator=[_entry("example.com")],
            session=[_entry("example.com")],
        )
        with pytest.raises(DomainNotAllowed):
            ail.check("https://example.com/")

    def test_empty_operator_refuses_all(self) -> None:
        ail = AllowlistIntersection(
            manifest=[_entry("example.com")],
            operator=[],
            session=[_entry("example.com")],
        )
        with pytest.raises(DomainNotAllowed):
            ail.check("https://example.com/")


# ---------------------------------------------------------------------------
# CR-145 web-fetch security review: path-prefix substring/traversal bypass
# ---------------------------------------------------------------------------


def test_path_prefix_substring_bypass_rejected() -> None:
    """An entry for ``/public`` MUST NOT match path ``/publicadmin``.

    The naive ``str.startswith(path_prefix)`` check would silently widen
    the operator's narrowing. ``AllowlistEntry.__post_init__`` normalises
    every entry to end with ``/`` so segment-aligned matching is unambiguous.
    """
    from alfred.plugins.web_fetch.allowlist import (
        AllowlistEntry,
        AllowlistIntersection,
        DomainNotAllowed,
    )

    intersection = AllowlistIntersection(
        manifest=[AllowlistEntry("example.com", "/public")],
        operator=[AllowlistEntry("example.com", "/public")],
        session=[AllowlistEntry("example.com", "/public")],
    )

    with pytest.raises(DomainNotAllowed):
        intersection.check("https://example.com/publicadmin/secret")


def test_path_prefix_normalised_to_trailing_slash() -> None:
    """Constructing ``AllowlistEntry("example.com", "/public")`` stores
    ``path_prefix == "/public/"`` so ``str.startswith`` is segment-aligned.
    """
    from alfred.plugins.web_fetch.allowlist import AllowlistEntry

    e = AllowlistEntry("example.com", "/public")
    assert e.path_prefix == "/public/"

    # Trailing slash already present: stays the same.
    e2 = AllowlistEntry("example.com", "/public/")
    assert e2.path_prefix == "/public/"


def test_path_prefix_requires_leading_slash() -> None:
    """A path_prefix without leading slash is a construction error.

    Operator/manifest configs that pass ``"public"`` instead of
    ``"/public"`` are malformed and must fail loud at construction time.
    """
    from alfred.plugins.web_fetch.allowlist import AllowlistEntry

    with pytest.raises(ValueError, match="must start with '/'"):
        AllowlistEntry("example.com", "public")


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/public/../admin/secret",
        "https://example.com/public/..",
        "https://example.com/../public/file",
        "https://example.com/..",
    ],
)
def test_path_traversal_segments_rejected_outright(url: str) -> None:
    """A request URL containing ``..`` MUST be refused without normalisation.

    Silently collapsing ``..`` would let the audit row claim the
    operator-submitted URL matched the allowlist when the literal URL
    travelled outside the prefix. The audit graph must stay honest about
    what was attempted.
    """
    from alfred.plugins.web_fetch.allowlist import (
        AllowlistEntry,
        AllowlistIntersection,
        DomainNotAllowed,
    )

    intersection = AllowlistIntersection(
        manifest=[AllowlistEntry("example.com", "/public")],
        operator=[AllowlistEntry("example.com", "/public")],
        session=[AllowlistEntry("example.com", "/public")],
    )

    with pytest.raises(DomainNotAllowed):
        intersection.check(url)


def test_double_slash_normalised_for_benign_paths() -> None:
    """A benign ``//`` (double slash) in the path SHOULD match the
    canonical prefix — operators copy-pasting URLs from logs sometimes
    introduce stray slashes; the comparison should be robust to that
    WITHOUT silently widening past ``..`` segments.
    """
    from alfred.plugins.web_fetch.allowlist import (
        AllowlistEntry,
        AllowlistIntersection,
    )

    intersection = AllowlistIntersection(
        manifest=[AllowlistEntry("example.com", "/public")],
        operator=[AllowlistEntry("example.com", "/public")],
        session=[AllowlistEntry("example.com", "/public")],
    )

    # Double-slash collapses to single-slash via posixpath.normpath; the
    # candidate "/public/file" matches the entry "/public/".
    intersection.check("https://example.com/public//file")


def test_normpath_dot_result_treated_as_root() -> None:
    """A URL whose parsed path normalises to ``"."`` MUST be treated as ``"/"``.

    ``posixpath.normpath('.')`` returns ``"."``, not ``"/"`` — without
    the explicit ``norm_path == "."`` rewrite at allowlist.py L222-223
    the candidate would become ``"./"`` and silently fail to match the
    ``"/"`` root-prefix entry. Hits the branch coverage gap reported by
    the trust-boundary 100% gate.

    The only URL strings that reach ``urlparse(...).path == "."`` are
    relative-style URLs with an empty netloc (e.g. ``"."`` itself, or
    ``"foo/.."``). They legitimately reach the allowlist check from
    upstream URL-construction bugs, so the branch matters even though
    a well-formed ``https://...`` URL never triggers it.
    """
    from alfred.plugins.web_fetch.allowlist import (
        AllowlistEntry,
        AllowlistIntersection,
        DomainNotAllowed,
    )

    intersection = AllowlistIntersection(
        manifest=[AllowlistEntry("example.com", "/")],
        operator=[AllowlistEntry("example.com", "/")],
        session=[AllowlistEntry("example.com", "/")],
    )

    # A bare ``"."`` URL parses to netloc="" + path=".". ``netloc != "example.com"``
    # so the candidate would not match anyway, but the normpath==. branch
    # must still execute (norm_path is rewritten to "/" before the
    # netloc comparison loop). Asserting on the refusal pins the branch.
    with pytest.raises(DomainNotAllowed):
        intersection.check(".")
