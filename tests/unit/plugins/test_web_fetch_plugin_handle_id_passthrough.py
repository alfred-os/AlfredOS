"""Smoke test: the alfred-web-fetch plugin subprocess forwards
params['content_handle_id'] verbatim to ContentStore.write (spec §3).

Task 13 — plugin contract change: ``_handle_fetch`` reads the host-
pre-minted ``content_handle_id`` from params and passes it to
``ContentStore.write(handle_id=...)``. No more internal uuid4() mint
inside the plugin. This test pins the passthrough contract so a future
refactor cannot silently re-introduce internal minting.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from alfred.security.quarantine import ContentHandle


def _make_mock_response(
    *,
    status: int = 200,
    content_type: str = "text/html",
    body: bytes = b"<html></html>",
) -> MagicMock:
    """Build a minimal aiohttp response mock for ``_handle_fetch``."""
    resp = MagicMock()
    resp.status = status
    resp.headers = {"Content-Type": content_type}

    # ``iter_chunks`` is called as ``async for chunk, _ in resp.content.iter_chunks()``.
    # We need an async generator that yields exactly one ``(bytes, bool)`` tuple.
    async def _iter_chunks() -> Any:
        yield (body, True)

    resp.content = MagicMock()
    resp.content.iter_chunks = _iter_chunks
    return resp


@pytest.mark.asyncio
async def test_handle_fetch_forwards_content_handle_id() -> None:
    """``_handle_fetch`` must pass ``params['content_handle_id']`` verbatim
    to ``ContentStore.write(handle_id=...)`` — spec §3 contract.

    Mocks the aiohttp stack via ``patch("aiohttp.ClientSession")`` and
    the store singleton via ``_get_or_init_store`` so the test runs
    without a live Redis or HTTP endpoint.
    """
    from plugins.alfred_web_fetch.web_fetch_plugin import _handle_fetch

    pre_minted_id = "test-pre-minted-id"
    pre_minted_handle = ContentHandle(
        id=pre_minted_id,
        source_url="https://example.com/",
        fetch_timestamp=datetime.now(tz=UTC),
    )
    mock_store = AsyncMock()
    mock_store.write = AsyncMock(return_value=pre_minted_handle)

    params: dict[str, Any] = {
        "url": "https://example.com/",
        "headers": {},
        "redis_url": "redis://localhost:6379",
        "content_handle_id": pre_minted_id,
    }

    mock_resp = _make_mock_response()

    # Build the mock session so ``session.get(...)`` returns a context
    # manager that yields ``mock_resp``.
    mock_get_cm = MagicMock()
    mock_get_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get_cm.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get_cm)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(
            "plugins.alfred_web_fetch.web_fetch_plugin._get_or_init_store",
            AsyncMock(return_value=mock_store),
        ),
        patch("aiohttp.ClientSession", return_value=mock_session),
    ):
        result = await _handle_fetch(params)

    # Successful fetch must return a result envelope (not an error).
    assert "result" in result, f"expected result envelope, got: {result!r}"
    assert result["result"]["id"] == pre_minted_id

    # The store write MUST have been called exactly once with the
    # host-pre-minted handle_id — not an internally generated uuid.
    mock_store.write.assert_called_once()
    kwargs = mock_store.write.call_args.kwargs
    assert kwargs["handle_id"] == pre_minted_id, (
        f"ContentStore.write received handle_id={kwargs.get('handle_id')!r}; "
        f"expected {pre_minted_id!r}. Plugin must forward the host-pre-minted "
        "id verbatim, not mint a new uuid internally."
    )
