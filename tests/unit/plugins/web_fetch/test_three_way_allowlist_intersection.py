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
