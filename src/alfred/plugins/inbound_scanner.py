"""InboundContentScanner — distinct from OutboundDlp (spec §4.5).

The threat models are inverted, so the dispositions are inverted:

* :class:`alfred.security.dlp.OutboundDlp` scans content the host writes
  to the subprocess. Disposition: **redact-and-continue** — secrets must
  not exfiltrate but the call should still complete.
* :class:`InboundContentScanner` (this module) scans content from the
  subprocess. Disposition: **SECURITY EVENT** — a canary trip is a
  quarantine trigger, never a recoverable error. There is no
  "redact-and-continue" path on T3 inbound frames.

The rule sets differ accordingly:

* Outbound rules detect secret shapes (API keys, broker-registered values).
* Inbound rules detect canary tokens (markers the host planted in
  outbound prompts that should not appear in plugin-derived content, per
  spec §7.6).

scan() is synchronous because the StdioTransport call site wraps it in
``asyncio.to_thread`` (perf-012 — keeps the event loop responsive on
regex-heavy frames). Making scan() ``async`` would invite mistakes where
a caller awaits the scan in the event-loop coroutine without thread
offload.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CanaryTrip:
    """SECURITY EVENT — a canary token was found in plugin output.

    The orchestrator treats this as a quarantine trigger, not a
    recoverable error. See spec §7.6 and §4.5.

    Attributes
    ----------
    matched_token
        The canary string that matched. Safe to log; canary registry is
        an operator-controlled vocabulary.
    frame_offset
        Byte offset of the match within the scanned frame. Useful for
        forensic correlation across replays of the same frame.
    """

    matched_token: str
    frame_offset: int


class InboundContentScanner:
    """Scans inbound JSON-RPC frames for canary tokens.

    Distinct from :class:`alfred.security.dlp.OutboundDlp`: a canary trip
    is a SECURITY EVENT, not a recoverable redact-and-continue case.

    Constructor takes the canary vocabulary explicitly so tests can pin
    the set deterministically. Production wiring (PR-S3-3a Task 6 + the
    bootstrap module) loads the operator's canary registry once at
    startup; rotating the registry mid-process is out of scope for
    Slice 3.
    """

    def __init__(
        self,
        *,
        canary_tokens: frozenset[str] | None = None,
    ) -> None:
        # ``re.escape`` so any regex metacharacters in canary strings are
        # treated as literals — canaries are arbitrary operator tokens,
        # not patterns.
        self._canary_tokens: frozenset[str] = canary_tokens or frozenset()
        self._canary_patterns: tuple[re.Pattern[str], ...] = tuple(
            re.compile(re.escape(tok)) for tok in self._canary_tokens
        )

    def scan(self, frame: bytes) -> CanaryTrip | None:
        """Scan a raw frame for canary tokens.

        Returns :class:`CanaryTrip` on the first match, ``None`` on a
        clean frame. The caller (``StdioTransport.dispatch``) must wrap
        this call in ``asyncio.to_thread`` per spec §7a.1 to keep the
        event loop responsive on large frames.

        ``errors="replace"`` so non-UTF-8 bytes never raise — T3 content
        may be binary (an image, a binary blob from a fetched URL) and
        the scanner has to remain a stable disposition gate regardless.
        """
        text = frame.decode("utf-8", errors="replace")
        for pattern in self._canary_patterns:
            match = pattern.search(text)
            if match:
                return CanaryTrip(
                    matched_token=match.group(0),
                    frame_offset=match.start(),
                )
        return None


__all__ = [
    "CanaryTrip",
    "InboundContentScanner",
]
