"""In-plugin DLP-lite secret-shape scrubber (closure sec-2, PR-S4-9 #206).

The Discord adapter NEVER sends a raw ``str(exc)`` over stdio: an exception's
rendered message can carry a leaked credential (a third-party SDK that put a key
in its ``__repr__``, a misconfigured token echoed back in an error body). Both
the ``_OutboundTerminal.detail_redacted`` send-failure field and the
``CrashedNotification.detail`` crash field route their exception text through
:func:`scrub_in_plugin` first.

This is **DLP-lite**, deliberately:

* **Regex-only.** No broker fetch, no canary lookup, no async I/O — it runs
  inside a crash handler and a synchronous send-path where a broker round-trip
  would be unsafe (the host may already be gone). The patterns are BUNDLED in
  the plugin (this module + the host's shared
  :func:`alfred.security.dlp.redact_secret_shapes`), not resolved at runtime.
* **Defence-in-depth, not the authority.** The host re-runs full
  :meth:`alfred.security.dlp.OutboundDlp.scan_for_outbound` (broker + canary +
  the same regex) on receive. The plugin's job is only to guarantee no raw
  secret-shape leaves the subprocess in the first place — closing the window
  where a crashing plugin's stdio frame is the leak vector.

The canonical generic-API-key pattern lives host-side as the shared
``redact_secret_shapes`` utility (its docstring names ``plugins`` + ``comms_mcp``
as sanctioned callers); this module composes it with the plugin's own bundled
Discord-shaped patterns (the bot-token shape) so the scrub is self-contained
*and* DRY against the host's audited pattern set.
"""

from __future__ import annotations

import re
from typing import Final

from alfred.security.dlp import redact_secret_shapes

_REDACTED: Final[str] = "[REDACTED:discord-secret-shape]"

# Discord bot-token shape: three dot-joined base64url segments (the JWT-like
# ``MTk...Gq.Cn...zw.HZ...XU`` layout) of substantial length. Anchored on a word
# boundary so a longer enclosing token still matches its leading shape. Bundled
# in-plugin because the host's generic ``sk-``/``pk_`` regex does not cover the
# platform-specific bot-token layout the Discord SDK could surface.
_DISCORD_BOT_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}\b"
)


def scrub_in_plugin(text: str) -> str:
    """Redact secret-shaped tokens from ``text`` before it crosses stdio.

    Runs the host's shared generic-API-key scrub (``sk-``/``pk_``/``tok-``/
    ``key_`` shapes) and the plugin's bundled Discord bot-token shape. Pure,
    synchronous, allocation-light — safe to call from a crash handler.
    """
    scrubbed = redact_secret_shapes(text)
    return _DISCORD_BOT_TOKEN_RE.sub(_REDACTED, scrubbed)


__all__ = ["scrub_in_plugin"]
