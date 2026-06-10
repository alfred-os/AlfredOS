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
# ``MTk...Gq.Cn...zw.HZ...XU`` layout) of substantial length. Bundled in-plugin
# because the host's generic ``sk-``/``pk_`` regex does not cover the
# platform-specific bot-token layout the Discord SDK could surface.
#
# L4: anchored with a NEGATIVE LOOKBEHIND ``(?<![A-Za-z0-9_-])`` rather than a
# leading ``\b``. base64url's alphabet includes ``-`` and ``_``, which are
# NON-word chars to ``\b`` — so a token whose first segment begins with ``-``/
# ``_`` would have its leading char left on the wire (``\b`` only fires after a
# word char). The lookbehind asserts "no base64url char precedes the token"
# without consuming it, so the ENTIRE token — leading ``-``/``_`` included — is
# matched and redacted from any boundary.
_DISCORD_BOT_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}\b"
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
