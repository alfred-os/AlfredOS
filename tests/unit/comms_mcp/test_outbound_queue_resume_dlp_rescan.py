"""OutboundQueue re-runs DLP on resume (comms-2, #206).

The comms-2 round-2 closure: ``pause()`` / ``resume()`` MUST re-run the outbound
DLP scan on every queued message BEFORE re-emission, so a policy hot-reload that
tightens the rules during the pause window cannot let a now-prohibited secret
slip out on resume. When the re-scan redacts content the original scan did not,
``consume`` REFUSES the message (raising :class:`OutboundResumeDlpBlockedError`) rather
than emitting it.

The re-scan is opt-in via an injected ``dlp_rescanner`` so the existing
non-DLP queue tests (and PR-S4-10's TUI wiring) are unaffected when no rescanner
is wired.
"""

from __future__ import annotations

import pytest

from alfred.comms_mcp.outbound_queue import OutboundQueue, OutboundResumeDlpBlockedError


class _NoAudit:
    pass


class _StubRescanner:
    """Returns the redaction count a re-scan of ``body`` would produce now.

    ``strict`` flips after the pause to model a hot-reloaded stricter policy that
    now catches the planted secret.
    """

    def __init__(self) -> None:
        self.strict = False
        self.calls: list[str] = []

    def redactions_for(self, body: str) -> int:
        self.calls.append(body)
        return 1 if (self.strict and "sk-" in body) else 0


@pytest.mark.asyncio
async def test_resume_rescan_blocks_newly_prohibited_secret() -> None:
    rescanner = _StubRescanner()
    queue: OutboundQueue[str] = OutboundQueue(
        audit_writer=_NoAudit(), dlp_rescanner=rescanner.redactions_for
    )
    await queue.submit("discord", "sk-PLANTEDSECRET")
    queue.pause("discord", 0.01)
    # Hot-reload tightens the policy during the pause window.
    rescanner.strict = True
    queue.resume("discord")

    with pytest.raises(OutboundResumeDlpBlockedError):
        await queue.consume("discord")


@pytest.mark.asyncio
async def test_resume_rescan_passes_clean_message() -> None:
    rescanner = _StubRescanner()
    queue: OutboundQueue[str] = OutboundQueue(
        audit_writer=_NoAudit(), dlp_rescanner=rescanner.redactions_for
    )
    await queue.submit("discord", "perfectly benign reply")
    queue.pause("discord", 0.01)
    rescanner.strict = True
    queue.resume("discord")

    # A clean message survives the resume re-scan and is delivered.
    assert await queue.consume("discord") == "perfectly benign reply"


@pytest.mark.asyncio
async def test_no_rescanner_preserves_legacy_consume() -> None:
    queue: OutboundQueue[str] = OutboundQueue(audit_writer=_NoAudit())
    await queue.submit("discord", "sk-SECRET")
    queue.pause("discord", 0.01)
    queue.resume("discord")
    # No rescanner wired → consume returns the request unchanged (legacy path).
    assert await queue.consume("discord") == "sk-SECRET"


@pytest.mark.asyncio
async def test_rescan_runs_only_after_a_pause() -> None:
    rescanner = _StubRescanner()
    rescanner.strict = True
    queue: OutboundQueue[str] = OutboundQueue(
        audit_writer=_NoAudit(), dlp_rescanner=rescanner.redactions_for
    )
    # Never paused → no re-scan needed; the message flows without a rescan call.
    await queue.submit("discord", "sk-SECRET")
    assert await queue.consume("discord") == "sk-SECRET"
    assert rescanner.calls == []
