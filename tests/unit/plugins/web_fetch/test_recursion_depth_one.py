"""Depth=1 enforcement tests (spec §7.9).

The quarantined LLM has no tool_calls capability — it emits structured data only.
The orchestrator may call web.fetch (depth=1). Recursive fetches (depth=2+) are
prevented by the quarantined LLM's capability set, not by a counter.
"""

from __future__ import annotations

import pytest


def test_quarantined_llm_manifest_declares_no_tool_calls() -> None:
    """The quarantined-LLM manifest must NOT declare tool.web.fetch subscription."""
    import pathlib
    import tomllib

    manifest_path = pathlib.Path("plugins/alfred_quarantined_llm/manifest.toml")
    if not manifest_path.exists():
        pytest.skip("PR-S3-4 not yet merged — quarantined-LLM manifest not present")
    with manifest_path.open("rb") as f:
        manifest = tomllib.load(f)
    hooks = manifest.get("hooks", [])
    for hook in hooks:
        assert "web.fetch" not in hook.get("action", ""), (
            "Quarantined LLM manifest must not subscribe to tool.web.fetch — "
            "depth=1 invariant: the quarantined LLM emits structured data only, "
            "no tool calls (spec §7.9, §5.1)"
        )


def test_web_fetch_hookpoint_system_only_blocks_user_plugin() -> None:
    """tool.web.fetch is system-only; user-plugin tier (which quarantined LLM uses
    for its sandbox_profile) cannot subscribe even if it tried."""
    from alfred.hooks import HookError, get_registry
    from alfred.plugins.web_fetch import register_hookpoints

    registry = get_registry()
    register_hookpoints(registry)

    async def fake_quarantine_fetch(ctx):  # type: ignore[type-arg]
        pass

    with pytest.raises(HookError):
        registry.register(
            hook_fn=fake_quarantine_fetch,
            hookpoint="tool.web.fetch",
            kind="pre",
            tier="user-plugin",  # quarantined LLM's sandbox_profile tier
        )


def test_content_handle_has_no_recursive_fetch_method() -> None:
    """ContentHandle exposes no method that could trigger a recursive web.fetch."""
    import datetime

    from alfred.plugins.web_fetch.content_store import ContentHandle

    handle = ContentHandle(
        id="test-id",
        source_url="https://example.com/",
        fetch_timestamp=datetime.datetime.now(tz=datetime.UTC),
    )
    # ContentHandle must not expose fetch, get, request, or any call-triggering method
    for attr in ("fetch", "get", "request", "call", "invoke"):
        assert not hasattr(handle, attr), (
            f"ContentHandle.{attr} would enable recursive fetch — violates depth=1 (spec §7.9)"
        )
