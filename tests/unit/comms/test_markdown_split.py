"""Tests for the markdown-aware splitter.

Boundary cases + a hypothesis property. The splitter's invariant is that
chunks reconstructed (modulo splitter-introduced state markers) equal the
original input. The state markers the splitter inserts at chunk
boundaries (triple-backtick close + reopen, single-backtick close +
reopen) are removed by ``_strip_state_markers`` before comparison.
"""

from __future__ import annotations

import re
import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from alfred.comms.markdown_split import _split_for_discord

# ----- Helpers --------------------------------------------------------------


def _fresh_sentinel(chunks: list[str]) -> str:
    """Return a sentinel string guaranteed absent from every chunk.

    A fixed sentinel (the prior ``XSPLITX``) plus unconditional
    ``replace(_SENTINEL, "")`` deletes legitimate input the moment
    hypothesis or a future fixture happens to generate the substring.
    Loop on UUID4 hex tokens until none of the chunks contains the
    candidate. Two random 32-hex tokens colliding with finite text is
    astronomically unlikely on the first try; the loop is paranoia.
    """
    while True:
        candidate = f"__SENTINEL_{uuid.uuid4().hex}__"
        if not any(candidate in chunk for chunk in chunks):
            return candidate


def _strip_state_markers(chunks: list[str]) -> str:
    """Re-join chunks and remove the close+reopen pair at each join point.

    We don't know the cut points a priori, so we re-join with a sentinel,
    then peel any close/reopen pair that straddles the sentinel.

    The sentinel is generated per-call against the actual chunk content so
    a chunk that legitimately contains an earlier fixed sentinel does not
    have part of its body silently deleted by the cleanup pass.
    """
    sentinel = _fresh_sentinel(chunks)
    joined = sentinel.join(chunks)
    # Fence close + fence reopen across the sentinel.
    joined = re.sub(
        r"\n?```" + re.escape(sentinel) + r"```[^\n]*\n",
        "",
        joined,
    )
    # Inline backtick close + reopen across the sentinel.
    joined = re.sub(
        r"`" + re.escape(sentinel) + r"`",
        "",
        joined,
    )
    # Leftover sentinels (plain-text joins).
    return joined.replace(sentinel, "")


# ----- Boundary cases -------------------------------------------------------


def test_empty_input_yields_nothing() -> None:
    assert list(_split_for_discord("")) == []


def test_short_input_yields_single_chunk() -> None:
    text = "hello"
    chunks = list(_split_for_discord(text, max_len=2000))
    assert chunks == [text]


def test_exactly_max_len_yields_single_chunk() -> None:
    text = "x" * 2000
    chunks = list(_split_for_discord(text, max_len=2000))
    assert chunks == [text]


def test_one_over_max_yields_two_chunks() -> None:
    text = "x" * 2001
    chunks = list(_split_for_discord(text, max_len=2000))
    assert len(chunks) == 2
    assert chunks[0] == "x" * 2000
    assert chunks[1] == "x"


def test_non_positive_max_len_rejected() -> None:
    with pytest.raises(ValueError, match="max_len must be positive"):
        list(_split_for_discord("hello world", max_len=0))


def test_open_fence_at_boundary_closes_and_reopens() -> None:
    """Fence straddling the cap is closed then re-opened on the next chunk."""
    text = "```python\n" + ("x" * 1990) + "\n```"
    chunks = list(_split_for_discord(text, max_len=2000))
    assert len(chunks) >= 2
    for chunk in chunks:
        assert len(chunk) <= 2000
    assert _strip_state_markers(chunks) == text


def test_language_tag_preserved_across_reopen() -> None:
    text = "```rust\n" + ("y" * 1990) + "\n```"
    chunks = list(_split_for_discord(text, max_len=2000))
    assert "```rust\n" in chunks[1]


def test_inline_code_at_boundary() -> None:
    text = "`" + ("z" * 1998) + "`" + "tail"
    chunks = list(_split_for_discord(text, max_len=2000))
    assert len(chunks) >= 2
    for chunk in chunks:
        assert len(chunk) <= 2000


def test_all_fenced_text_every_chunk_carries_state() -> None:
    text = "```\n" + ("a" * 5000) + "\n```"
    chunks = list(_split_for_discord(text, max_len=2000))
    assert len(chunks) >= 3
    for chunk in chunks[1:]:
        assert chunk.startswith("```")


def test_telegram_size_works_too() -> None:
    """Slice-4 Telegram reuses with ``max_len=4096`` — same shape, larger cap."""
    text = "x" * 8000
    chunks = list(_split_for_discord(text, max_len=4096))
    assert all(len(c) <= 4096 for c in chunks)
    assert "".join(chunks) == text


# ----- Hypothesis property --------------------------------------------------


@settings(max_examples=200, deadline=2000, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(min_size=0, max_size=8000))
def test_concat_modulo_state_markers_equals_input(text: str) -> None:
    chunks = list(_split_for_discord(text, max_len=200))
    for chunk in chunks:
        assert len(chunk) <= 200
    reconstructed = _strip_state_markers(chunks)
    assert reconstructed == text


@settings(max_examples=100, deadline=2000)
@given(st.integers(min_value=20, max_value=200))
def test_property_with_varying_cap(cap: int) -> None:
    """Plain-text input under varying caps always reconstructs verbatim."""
    text = "abcdef" * 100
    chunks = list(_split_for_discord(text, max_len=cap))
    for chunk in chunks:
        assert len(chunk) <= cap
    assert "".join(chunks) == text
