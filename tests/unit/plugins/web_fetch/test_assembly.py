"""Unit tests for the ``web.fetch`` egress assembly factory (Spec C G7-2.5 PR2, #333).

Pin the construction-time contract of
:func:`alfred.plugins.web_fetch.assembly.build_web_fetch_egress_extractor`:

* the happy path wires an :class:`EgressResponseExtractor` REUSING the passed-in
  quarantine-graph components (gate / extractor / recorder — identity, not a
  re-spawn) and stamps web.fetch's Spec-C5 policy (5 MiB cap, MIME allowlist,
  ``canary=None`` residual);
* the fail-closed path refuses when ``settings.egress_relay_url`` is unset.

The end-to-end fetch+extract proof over a loopback relay lives in
``tests/integration/egress/test_web_fetch_assembly.py``; this module is the
non-Docker branch-coverage gate for ``assembly.py``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

import pytest

from alfred.config.settings import Settings
from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.plugins.web_fetch.assembly import (
    _WEB_FETCH_MIME_ALLOWLIST,
    _WEB_FETCH_RESPONSE_MAX_BYTES,
    build_web_fetch_egress_extractor,
)

_RELAY_URL = "tcp://127.0.0.1:8890"


def _settings(monkeypatch: pytest.MonkeyPatch, *, relay_url: str | None) -> Settings:
    """A real :class:`Settings` with the provider key satisfied + the relay URL pinned."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.delenv("ALFRED_EGRESS_RELAY_URL", raising=False)
    return Settings(egress_relay_url=relay_url)


def _collaborators() -> dict[str, Any]:
    """Inert daemon-graph doubles — the factory only STORES these at construction."""
    return {
        "gate": Mock(name="gate"),
        "extractor": Mock(name="extractor"),
        "recorder": Mock(name="recorder"),
        "outbound_dlp": Mock(name="outbound_dlp"),
        "audit_writer": Mock(name="audit_writer"),
        "session_scope": lambda: None,  # never invoked at construction
    }


def test_factory_reuses_graph_and_stamps_web_fetch_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The happy path returns an extractor REUSING the passed graph + web.fetch policy."""
    collab = _collaborators()
    extractor = build_web_fetch_egress_extractor(
        settings=_settings(monkeypatch, relay_url=_RELAY_URL),
        gate=collab["gate"],
        extractor=collab["extractor"],
        recorder=collab["recorder"],
        outbound_dlp=collab["outbound_dlp"],
        audit_writer=collab["audit_writer"],
        session_scope=collab["session_scope"],
    )

    assert isinstance(extractor, EgressResponseExtractor)
    # REUSE, not re-spawn: the exact instances passed in are threaded through
    # (§4.3 one production extractor; CORE-4 shared-child HoL).
    assert extractor._gate is collab["gate"]
    assert extractor._extractor is collab["extractor"]
    assert extractor._recorder is collab["recorder"]

    # Spec C5: web.fetch's 5 MiB cap + the MIME allowlist + the canary residual.
    policy = extractor._response_policy
    assert policy is not None
    assert policy.max_bytes == _WEB_FETCH_RESPONSE_MAX_BYTES == 5 * 1024 * 1024
    assert policy.mime_allowlist == _WEB_FETCH_MIME_ALLOWLIST
    assert "text/html" in policy.mime_allowlist
    # canary defaults to None — the inbound-canary source is a tracked #339 residual.
    assert policy.canary is None

    # The relay client dialed the configured host:port (no live socket here).
    assert extractor._relay_client._relay_host == "127.0.0.1"
    assert extractor._relay_client._relay_port == 8890


def test_factory_threads_canary_matcher_when_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A supplied canary matcher reaches the response policy (the #339 wiring point)."""
    from alfred.security.canary_matcher import CanaryMatcher, CanaryToken

    matcher = CanaryMatcher(tokens=[CanaryToken(value="CANARY-UNIT")])
    collab = _collaborators()
    extractor = build_web_fetch_egress_extractor(
        settings=_settings(monkeypatch, relay_url=_RELAY_URL),
        gate=collab["gate"],
        extractor=collab["extractor"],
        recorder=collab["recorder"],
        outbound_dlp=collab["outbound_dlp"],
        audit_writer=collab["audit_writer"],
        session_scope=collab["session_scope"],
        canary=matcher,
    )

    assert extractor._response_policy is not None
    assert extractor._response_policy.canary is matcher


def test_factory_fail_closed_when_relay_url_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unset ``egress_relay_url`` refuses — the core has no direct egress fallback."""
    collab = _collaborators()
    with pytest.raises(ValueError, match="egress_relay_url"):
        build_web_fetch_egress_extractor(
            settings=_settings(monkeypatch, relay_url=None),
            gate=collab["gate"],
            extractor=collab["extractor"],
            recorder=collab["recorder"],
            outbound_dlp=collab["outbound_dlp"],
            audit_writer=collab["audit_writer"],
            session_scope=collab["session_scope"],
        )
