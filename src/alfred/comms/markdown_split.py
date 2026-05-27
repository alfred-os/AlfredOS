"""Markdown-aware splitter for chunking long outbound messages.

Discord enforces a 2000-character per-message cap; Telegram (Slice 4)
enforces 4096. A naive ``text[:N], text[N:]`` split corrupts the rendering
when the boundary lands inside a fenced code block or an inline-code
span: the second chunk renders as plain text with a stray closing
backtick.

:func:`_split_for_discord` walks the text once, tracking two pieces of
markdown state:

* whether we are inside a triple-backtick fenced block (``in_fence``)
  and the language tag of that fence (``fence_lang``);
* whether we are inside an inline single-backtick span (``in_inline``).

When the splitter must emit a chunk while either state is active it
closes the active marker on the trailing edge of the chunk and re-opens
it on the leading edge of the next chunk, preserving the language tag.
The concatenation of the chunks modulo the inserted close/re-open
markers equals the original text — the hypothesis property in
``tests/unit/comms/test_markdown_split.py`` enforces this invariant.

Pure function; no I/O, no global state. Slice-4 Telegram reuses with
``max_len=4096``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

# Markers we emit on close / re-open.
_FENCE: Final[str] = "```"
_INLINE: Final[str] = "`"
# Worst-case suffix we may have to append at chunk-end: a newline before
# the closing fence so Discord puts ``\`\`\``` on its own line. ``\n`` +
# three backticks = 4 chars.
_FENCE_CLOSE_SUFFIX: Final[str] = "\n" + _FENCE
_FENCE_CLOSE_SUFFIX_LEN: Final[int] = len(_FENCE_CLOSE_SUFFIX)
_INLINE_CLOSE_SUFFIX_LEN: Final[int] = len(_INLINE)


def _split_for_discord(text: str, *, max_len: int = 2000) -> Iterator[str]:
    """Yield chunks of ``text`` no longer than ``max_len`` characters each.

    State-aware: when a chunk boundary lands inside a fenced code block or
    inline-code span, the splitter closes the active marker before yielding
    and re-opens it (with the same language tag, if any) at the top of
    the next chunk.

    ``max_len`` is keyword-only so Slice-4 Telegram callers can pass
    ``max_len=4096`` without ambiguity at the call site.

    Boundary semantics:

    * Empty input yields nothing.
    * Input shorter than or equal to ``max_len`` yields exactly one chunk.
    * Input longer than ``max_len`` yields at least two chunks; every
      chunk (including state markers) is at most ``max_len`` chars.
    """
    if not text:
        return
    if max_len <= 0:
        raise ValueError(f"max_len must be positive, got {max_len}")

    if len(text) <= max_len:
        yield text
        return

    text_len = len(text)
    pos = 0
    # State carried across chunks.
    open_fence_lang: str | None = None
    open_inline: bool = False

    while pos < text_len:
        # Re-open prefix for THIS chunk (if previous chunk left state open).
        prefix = ""
        if open_fence_lang is not None:
            prefix = _FENCE + open_fence_lang + "\n"
        elif open_inline:
            prefix = _INLINE

        if len(prefix) >= max_len:
            raise ValueError(
                f"max_len={max_len} is too small to accommodate markdown state markers"
            )

        chunk_chars: list[str] = [prefix] if prefix else []
        chunk_len = len(prefix)  # number of chars already in this chunk

        # Mid-chunk state tracking (starts mirroring the entry state).
        local_in_fence = open_fence_lang is not None
        local_fence_lang: str | None = open_fence_lang
        local_in_inline = open_inline

        chunk_start = pos
        while pos < text_len:
            # Look for a fence opener/closer. While an inline-code span
            # is already open, triple-backticks read as three consecutive
            # inline backticks (closing + reopening + extra) rather than
            # a fence — so don't promote them into fence state here, or
            # ``open_inline`` resets at the bottom of the loop drift the
            # next chunk's prefix.
            if text.startswith(_FENCE, pos) and not local_in_inline:
                if local_in_fence:
                    # Closing fence.
                    after_state_in_fence = False
                    addition = _FENCE
                    after_state_lang: str | None = None
                else:
                    # Opening fence: include the language tag up to newline.
                    nl_idx = text.find("\n", pos + len(_FENCE))
                    end = nl_idx + 1 if nl_idx != -1 else text_len
                    addition = text[pos:end]
                    after_state_in_fence = True
                    after_state_lang = addition[len(_FENCE) :].rstrip("\n")
                # Can we fit this addition plus the suffix that the NEW
                # state would require if we cut right after it?
                projected_suffix = (_FENCE_CLOSE_SUFFIX_LEN if after_state_in_fence else 0) or (
                    _INLINE_CLOSE_SUFFIX_LEN if local_in_inline else 0
                )
                if chunk_len + len(addition) + projected_suffix > max_len:
                    break
                chunk_chars.append(addition)
                chunk_len += len(addition)
                pos += len(addition)
                local_in_fence = after_state_in_fence
                local_fence_lang = after_state_lang
                continue
            if text.startswith(_INLINE, pos) and not local_in_fence:
                addition = _INLINE
                # Toggle inline; the post-toggle suffix cost is 0 if we
                # close it here (was open before), else 1 (we just opened).
                next_inline = not local_in_inline
                projected_suffix = _INLINE_CLOSE_SUFFIX_LEN if next_inline else 0
                if chunk_len + len(addition) + projected_suffix > max_len:
                    break
                chunk_chars.append(addition)
                chunk_len += len(addition)
                pos += len(addition)
                local_in_inline = next_inline
                continue
            # Plain character. Suffix cost is state-dependent: if a cut
            # here would leave a fence/inline open we must reserve room
            # for the close marker.
            if local_in_fence:
                suffix_cost = _FENCE_CLOSE_SUFFIX_LEN
            elif local_in_inline:
                suffix_cost = _INLINE_CLOSE_SUFFIX_LEN
            else:
                suffix_cost = 0
            if chunk_len + 1 + suffix_cost > max_len:
                break
            chunk_chars.append(text[pos])
            chunk_len += 1
            pos += 1

        more_to_come = pos < text_len
        if more_to_come:
            if local_in_fence:
                if not chunk_chars or not chunk_chars[-1].endswith("\n"):
                    chunk_chars.append("\n")
                chunk_chars.append(_FENCE)
                open_fence_lang = local_fence_lang or ""
                open_inline = False
            elif local_in_inline:
                chunk_chars.append(_INLINE)
                open_fence_lang = None
                open_inline = True
            else:
                open_fence_lang = None
                open_inline = False
        else:
            open_fence_lang = None
            open_inline = False

        chunk = "".join(chunk_chars)
        if len(chunk) > max_len:
            raise RuntimeError(
                f"splitter produced chunk of length {len(chunk)} > max_len={max_len}; "
                "this is a programmer bug — please report"
            )
        if pos == chunk_start:
            # Zero source advance means we cannot make further progress —
            # max_len is too small for the prefix + suffix + at least one
            # character of content. Raise to avoid an infinite loop.
            raise RuntimeError("splitter made no forward progress; max_len too small for content")
        yield chunk
