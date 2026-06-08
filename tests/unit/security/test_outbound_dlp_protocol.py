"""``OutboundDlpProtocol`` structural-typing contract (PR-S4-2, #173).

The protocol exists so frozen dataclasses (``ProposalContext``) and other
injection surfaces can annotate a DLP-scanner dependency without binding
to the concrete ``OutboundDlp`` class. These tests pin:

* the concrete ``OutboundDlp`` satisfies the protocol structurally;
* a stub missing ``scan`` does NOT satisfy it;
* the protocol is ``runtime_checkable`` so ``isinstance`` works at the
  injection boundary (the AST guard in ``test_dispatch_loop_no_local_dlp_construct``
  pairs with this — the dispatch loop only ever sees the protocol).
"""

from __future__ import annotations

from collections.abc import Mapping

from alfred.security.dlp import OutboundDlp, OutboundDlpProtocol


class _StubBroker:
    def redact(self, text: str) -> str:
        return text


def _stub_audit(*, event: str, subject: Mapping[str, object]) -> None:
    return None


def test_outbound_dlp_satisfies_protocol() -> None:
    """The concrete OutboundDlp class satisfies OutboundDlpProtocol structurally."""
    dlp = OutboundDlp(broker=_StubBroker(), audit=_stub_audit)
    assert isinstance(dlp, OutboundDlpProtocol)


def test_non_matching_stub_does_not_satisfy_protocol() -> None:
    """A stub missing scan() does NOT satisfy the protocol."""

    class _NotADlp:
        def redact(self, text: str) -> str:
            return text

    assert not isinstance(_NotADlp(), OutboundDlpProtocol)


def test_protocol_runtime_checkable() -> None:
    """OutboundDlpProtocol is runtime_checkable (isinstance works)."""
    assert getattr(OutboundDlpProtocol, "_is_runtime_protocol", False) is True

    class _DuckScan:
        def scan(self, text: str) -> str:
            return text

    assert isinstance(_DuckScan(), OutboundDlpProtocol)
