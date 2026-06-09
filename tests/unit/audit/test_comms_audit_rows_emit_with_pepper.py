"""Task 26 — peppered-hash helper for comms audit rows (sec-010).

``_peppered_hash(raw, pepper=...)`` is HMAC-SHA256 keyed on the broker's
``audit.hash_pepper``, truncated to 32 hex chars. The raw value never appears
in the output. The pepper is fetched from the broker (sec-010), never the raw
secret echoed.
"""

from __future__ import annotations

import hashlib
import hmac

from alfred.comms_mcp.inbound import _peppered_hash


def test_peppered_hash_matches_hmac_recipe() -> None:
    pepper = "test-pepper-32-bytes-long-enough!"
    h = _peppered_hash("discord:123", pepper=pepper)
    expected = hmac.new(
        key=pepper.encode(),
        msg=b"discord:123",
        digestmod=hashlib.sha256,
    ).hexdigest()[:32]
    assert h == expected
    assert len(h) == 32
    assert "discord:123" not in h


def test_peppered_hash_differs_per_input() -> None:
    pepper = "test-pepper-32-bytes-long-enough!"
    assert _peppered_hash("a", pepper=pepper) != _peppered_hash("b", pepper=pepper)


def test_peppered_hash_differs_per_pepper() -> None:
    same_input = "discord:123"
    assert _peppered_hash(same_input, pepper="pepper-one") != _peppered_hash(
        same_input, pepper="pepper-two"
    )
