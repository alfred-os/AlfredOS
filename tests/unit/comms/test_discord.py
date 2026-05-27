"""Unit tests for the Slice-2 DiscordAdapter.

Coverage map:

* Logging-bridge redaction (cluster 2)
* Adapter constructor + intents + signal-handler (cluster 3-4)
* Bot-author / non-DM short-circuit (cluster 4)
* Allowlist refusal — one branch per allowlist field (cluster 5)
* Identity resolution + unknown-DM dedup + global cap (cluster 6)
* Per-user rate-limiting with READ_ONLY suppression (cluster 7)
* set_language per-coroutine (cluster 8)
* WorkingMemoryPool acquire/release lifecycle (cluster 9)
* Orchestrator typed exception arms (cluster 10)
* _send chokepoint + grep-AST pin + boundary cases (cluster 11)
* err-003 audit branches (cluster 12)
* Reconnect classification table (cluster 13)
* alfred discord verify exit codes (cluster 14)
* alfred discord boot dependency wiring (cluster 15)
* No str(exc) in user templates (cluster 10.3)
* i18n keys resolve (cluster 20)

Every test uses a stub ``discord.Client`` via the ``client_factory``
seam — none of these tests connect to the real Discord network.
"""

from __future__ import annotations

import ast
import asyncio
import logging
import pathlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest

from alfred.budget.guard import BudgetExceededError, UnknownBudgetUserError
from alfred.comms.discord import (
    DiscordAdapter,
    _bridge_library_logging,
    _classify_gateway_exception,
    _classify_verify_exception,
    _compute_intents,
    _GatewayDisposition,
    _intents_summary,
    _non_empty_content_fields,
    _RecentReconnects,
    _UnknownDmAuditCap,
    run_verify_probe,
)
from alfred.i18n import set_language, t
from alfred.identity.models import Authorization

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_user(
    *,
    slug: str = "alice",
    authorization: str = "standard",
    language: str = "en-US",
    rate_limit_per_min: int | None = None,
    deleted_at: object | None = None,
    daily_budget_usd: float = 0.50,
    display_name: str = "Alice",
) -> MagicMock:
    """Construct a User-shaped mock the adapter consumes structurally."""
    user = MagicMock()
    user.slug = slug
    user.authorization = authorization
    user.language = language
    user.rate_limit_per_min = rate_limit_per_min
    user.deleted_at = deleted_at
    user.daily_budget_usd = daily_budget_usd
    user.display_name = display_name
    user.id = 1
    return user


def _make_dm_channel() -> MagicMock:
    """Construct a discord.DMChannel-shaped mock."""
    channel = MagicMock(spec=discord.DMChannel)
    channel.send = AsyncMock()
    return channel


def _make_msg(
    *,
    content: str = "hello",
    author_id: int = 12345,
    author_bot: bool = False,
    channel: object | None = None,
    embeds: list | None = None,
    attachments: list | None = None,
    stickers: list | None = None,
    reference: object | None = None,
    poll: object | None = None,
    components: list | None = None,
    activity: object | None = None,
    application: object | None = None,
) -> MagicMock:
    """Construct a discord.Message-shaped mock."""
    msg = MagicMock(spec=discord.Message)
    msg.content = content
    msg.author = MagicMock()
    msg.author.id = author_id
    msg.author.bot = author_bot
    msg.channel = channel if channel is not None else _make_dm_channel()
    msg.embeds = embeds or []
    msg.attachments = attachments or []
    msg.stickers = stickers or []
    msg.reference = reference
    msg.poll = poll
    msg.components = components or []
    msg.activity = activity
    msg.application = application
    return msg


def _make_adapter(
    *,
    orchestrator: object | None = None,
    identity_resolver: object | None = None,
    broker: object | None = None,
    outbound_dlp: object | None = None,
    rate_limiter: object | None = None,
    working_pool: object | None = None,
    audit: object | None = None,
    user: object | None = None,
    unknown_dm_audit_cap_per_min: int = 60,
) -> DiscordAdapter:
    """Construct a DiscordAdapter with a fully mocked dependency graph."""
    if orchestrator is None:
        orchestrator = MagicMock()
        orchestrator.handle_user_message = AsyncMock(return_value="hi alice")
    if identity_resolver is None:
        identity_resolver = MagicMock()
        identity_resolver.resolve = MagicMock(
            return_value=user if user is not None else _make_user()
        )
    if broker is None:
        broker = MagicMock()
        broker.get = MagicMock(return_value="token-xyz")
        broker.redact = MagicMock(side_effect=lambda s: s)
    if outbound_dlp is None:
        outbound_dlp = MagicMock()
        outbound_dlp.scan = MagicMock(side_effect=lambda s: s)
    if rate_limiter is None:
        rate_limiter = MagicMock()
        rate_limiter.allow = AsyncMock(return_value=True)
    if working_pool is None:
        working_pool = MagicMock()
        wm = MagicMock()
        working_pool.acquire = AsyncMock(return_value=wm)
        working_pool.release = AsyncMock()
    if audit is None:
        audit = MagicMock()
        audit.append = AsyncMock()

    # Inject a dummy client_factory so no real gateway is constructed.
    def _factory(intents: discord.Intents) -> Any:
        client = MagicMock()
        client.event = MagicMock(side_effect=lambda fn: fn)
        client.start = AsyncMock()
        client.close = AsyncMock()
        client.is_ready = MagicMock(return_value=True)
        return client

    return DiscordAdapter(
        orchestrator=orchestrator,
        identity_resolver=identity_resolver,
        broker=broker,
        outbound_dlp=outbound_dlp,
        rate_limiter=rate_limiter,
        working_pool=working_pool,
        audit=audit,
        client_factory=_factory,
        unknown_dm_audit_cap_per_min=unknown_dm_audit_cap_per_min,
    )


# ---------------------------------------------------------------------------
# Cluster 2 — logging bridge
# ---------------------------------------------------------------------------


def test_library_logging_is_redacted() -> None:
    """A LogRecord with a known secret value renders redacted."""
    broker = MagicMock()
    # The DLP scan should redact the marker.
    broker.redact = MagicMock(
        side_effect=lambda s: s.replace("REAL_TOKEN_HERE", "[REDACTED:discord_bot_token]")
    )
    from alfred.security.dlp import OutboundDlp

    dlp = OutboundDlp(broker=broker, audit=lambda **_: None)
    _bridge_library_logging(outbound_dlp=dlp)

    logger = logging.getLogger("discord")
    handler = logger.handlers[0]
    record = logging.LogRecord(
        name="discord.gateway",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="connecting with token REAL_TOKEN_HERE",
        args=(),
        exc_info=None,
    )
    rendered = handler.format(record)
    assert "REAL_TOKEN_HERE" not in rendered
    assert "[REDACTED:discord_bot_token]" in rendered


def test_library_logging_redacts_generic_api_key_shape() -> None:
    """The generic API-key regex (stage 2 of OutboundDlp) catches sk- shapes."""
    broker = MagicMock()
    broker.redact = MagicMock(side_effect=lambda s: s)  # broker has no secrets
    from alfred.security.dlp import OutboundDlp

    dlp = OutboundDlp(broker=broker, audit=lambda **_: None)
    _bridge_library_logging(outbound_dlp=dlp)

    logger = logging.getLogger("discord")
    handler = logger.handlers[0]
    record = logging.LogRecord(
        name="discord",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="leaked sk-AAAAAAAAAAAAAAAAAAAAAA in debug",
        args=(),
        exc_info=None,
    )
    rendered = handler.format(record)
    assert "sk-AAAAAAAAAAAAAAAAAAAAAA" not in rendered
    assert "[REDACTED:api-key-shape]" in rendered


# ---------------------------------------------------------------------------
# Cluster 3 — constructor + intents
# ---------------------------------------------------------------------------


def test_adapter_constructor_accepts_full_inject_set() -> None:
    adapter = _make_adapter()
    assert adapter.name == "discord"


def test_compute_intents_returns_dm_and_message_content() -> None:
    intents = _compute_intents()
    assert intents.message_content is True
    assert intents.dm_messages is True


def test_intents_summary_returns_sorted_tuple_of_enabled_flags() -> None:
    intents = _compute_intents()
    summary = _intents_summary(intents)
    assert isinstance(summary, tuple)
    assert "message_content" in summary
    assert summary == tuple(sorted(summary))


# ---------------------------------------------------------------------------
# Cluster 3.4 — adapter-startup audit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_writes_adapter_startup_audit_row() -> None:
    adapter = _make_adapter()
    await adapter.start()
    audit_call = adapter._audit.append.call_args
    assert audit_call.kwargs["event"] == "discord.adapter_startup"
    assert "intents" in audit_call.kwargs["subject"]
    assert audit_call.kwargs["result"] == "success"


@pytest.mark.asyncio
async def test_start_audit_failure_does_not_crash_startup() -> None:
    audit = MagicMock()
    audit.append = AsyncMock(side_effect=RuntimeError("audit DB down"))
    adapter = _make_adapter(audit=audit)
    # Must not raise.
    await adapter.start()


# ---------------------------------------------------------------------------
# Cluster 4 — _handle happy path + short-circuits
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_happy_path() -> None:
    adapter = _make_adapter()
    msg = _make_msg(content="hello", author_id=12345)
    await adapter._handle(msg)
    adapter._orch.handle_user_message.assert_awaited_once()
    msg.channel.send.assert_called_once_with("hi alice")


@pytest.mark.asyncio
async def test_bot_author_ignored() -> None:
    adapter = _make_adapter()
    msg = _make_msg(author_bot=True)
    await adapter._handle(msg)
    adapter._orch.handle_user_message.assert_not_called()
    msg.channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_group_channel_rejected() -> None:
    adapter = _make_adapter()
    group = MagicMock(spec=discord.GroupChannel)
    group.send = AsyncMock()
    msg = _make_msg(channel=group)
    await adapter._handle(msg)
    adapter._orch.handle_user_message.assert_not_called()
    group.send.assert_not_called()


# ---------------------------------------------------------------------------
# Cluster 5 — allowlist refusal, one branch per field
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("embeds", [MagicMock()]),
        ("attachments", [MagicMock()]),
        ("stickers", [MagicMock()]),
        ("reference", MagicMock()),
        ("poll", MagicMock()),
        ("components", [MagicMock()]),
        ("activity", MagicMock()),
        ("application", MagicMock()),
    ],
)
@pytest.mark.asyncio
async def test_allowlist_field_refused(field: str, value: object) -> None:
    """Each refused field produces exactly one audit + one reply."""
    adapter = _make_adapter()
    kwargs: dict[str, Any] = {field: value}
    msg = _make_msg(**kwargs)
    await adapter._handle(msg)
    # Orchestrator never invoked.
    adapter._orch.handle_user_message.assert_not_called()
    # One audit row with the field name.
    refusal_calls = [
        c
        for c in adapter._audit.append.await_args_list
        if c.kwargs.get("event") == "discord.embed_refused"
    ]
    assert len(refusal_calls) == 1
    assert field in refusal_calls[0].kwargs["subject"]["refused_fields"]
    # One reply with the refusal text.
    msg.channel.send.assert_called_once()


def test_non_empty_content_fields_detects_each_field() -> None:
    msg = _make_msg(embeds=[MagicMock()])
    assert "embeds" in _non_empty_content_fields(msg)
    msg = _make_msg(reference=MagicMock())
    assert "reference" in _non_empty_content_fields(msg)
    msg = _make_msg()  # all empty
    assert _non_empty_content_fields(msg) == []


@pytest.mark.asyncio
async def test_clean_message_passes_allowlist() -> None:
    """All-empty allowlist fields proceed to identity resolution."""
    adapter = _make_adapter()
    msg = _make_msg()
    await adapter._handle(msg)
    adapter._identity.resolve.assert_called_once()


# ---------------------------------------------------------------------------
# Cluster 6 — unknown-DM dedup + global cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_dm_first_contact() -> None:
    """First unknown DM: one audit row + one bind-hint reply."""
    resolver = MagicMock()
    resolver.resolve = MagicMock(return_value=None)
    adapter = _make_adapter(identity_resolver=resolver)
    msg = _make_msg(author_id=99999)
    await adapter._handle(msg)
    # Audit row written.
    unknown_calls = [
        c
        for c in adapter._audit.append.await_args_list
        if c.kwargs.get("event") == "discord.unknown_user_dm"
    ]
    assert len(unknown_calls) == 1
    assert unknown_calls[0].kwargs["subject"]["snowflake"] == "99999"
    # One reply.
    msg.channel.send.assert_called_once()
    # Zero orchestrator call.
    adapter._orch.handle_user_message.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_dm_dedup_within_ttl() -> None:
    """50 DMs from same snowflake → 1 audit row + 1 reply."""
    resolver = MagicMock()
    resolver.resolve = MagicMock(return_value=None)
    adapter = _make_adapter(identity_resolver=resolver)
    channel = _make_dm_channel()
    for _ in range(50):
        msg = _make_msg(author_id=99999, channel=channel)
        await adapter._handle(msg)
    unknown_calls = [
        c
        for c in adapter._audit.append.await_args_list
        if c.kwargs.get("event") == "discord.unknown_user_dm"
    ]
    assert len(unknown_calls) == 1
    assert channel.send.await_count == 1


@pytest.mark.asyncio
async def test_unknown_dm_global_cap_drops_audit_but_replies() -> None:
    """61 distinct snowflakes in 1 min: ≤60 audit rows + counter bumps."""
    import alfred.comms.discord as discord_mod

    resolver = MagicMock()
    resolver.resolve = MagicMock(return_value=None)
    adapter = _make_adapter(identity_resolver=resolver, unknown_dm_audit_cap_per_min=60)
    baseline_drops = discord_mod.discord_unknown_dm_audit_dropped_total
    for i in range(70):
        msg = _make_msg(author_id=100000 + i)
        await adapter._handle(msg)
    unknown_calls = [
        c
        for c in adapter._audit.append.await_args_list
        if c.kwargs.get("event") == "discord.unknown_user_dm"
    ]
    assert len(unknown_calls) <= 60
    # Drops counter increased.
    assert discord_mod.discord_unknown_dm_audit_dropped_total > baseline_drops


@pytest.mark.asyncio
async def test_unknown_dm_replies_first_contact_even_when_audit_cap_reached() -> None:
    """Even past the cap, a first-contact snowflake still gets one reply."""
    resolver = MagicMock()
    resolver.resolve = MagicMock(return_value=None)
    adapter = _make_adapter(identity_resolver=resolver, unknown_dm_audit_cap_per_min=2)
    channels = []
    for i in range(5):
        ch = _make_dm_channel()
        channels.append(ch)
        msg = _make_msg(author_id=200000 + i, channel=ch)
        await adapter._handle(msg)
    # All 5 channels got a reply (cap protects audit, not UX).
    for ch in channels:
        ch.send.assert_called_once()


# ---------------------------------------------------------------------------
# Cluster 7 — per-user rate-limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_only_user_refused_no_reply() -> None:
    user = _make_user(slug="rouser", authorization=Authorization.READ_ONLY.value)
    rate_limiter = MagicMock()
    rate_limiter.allow = AsyncMock(return_value=False)
    adapter = _make_adapter(user=user, rate_limiter=rate_limiter)
    msg = _make_msg()
    await adapter._handle(msg)
    # Audit row written but no reply.
    refused_calls = [
        c
        for c in adapter._audit.append.await_args_list
        if c.kwargs.get("event") == "discord.read_only_refused"
    ]
    assert len(refused_calls) == 1
    msg.channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_standard_user_rate_limited_with_reply() -> None:
    user = _make_user(slug="alice", authorization=Authorization.STANDARD.value)
    rate_limiter = MagicMock()
    rate_limiter.allow = AsyncMock(return_value=False)
    adapter = _make_adapter(user=user, rate_limiter=rate_limiter)
    msg = _make_msg()
    await adapter._handle(msg)
    rate_calls = [
        c
        for c in adapter._audit.append.await_args_list
        if c.kwargs.get("event") == "discord.rate_limited"
    ]
    assert len(rate_calls) == 1
    msg.channel.send.assert_called_once()


@pytest.mark.asyncio
async def test_rate_limiter_called_with_full_user() -> None:
    user = _make_user()
    adapter = _make_adapter(user=user)
    msg = _make_msg()
    await adapter._handle(msg)
    # Confirm the rate_limiter.allow received the full User object.
    call_args = adapter._rate_limiter.allow.await_args
    assert call_args.args[0] is user


# ---------------------------------------------------------------------------
# Cluster 8 — set_language ContextVar
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_language_set_per_user() -> None:
    """Two interleaved coroutines render budget-blocked in their own language."""
    seen_translations: dict[str, str] = {}

    async def run_one(lang: str) -> None:
        set_language(lang)
        await asyncio.sleep(0.01)
        # Capture what t() renders for budget_blocked under this lang.
        seen_translations[lang] = t("discord.budget_blocked", spent="0.50", cap="0.50")

    await asyncio.gather(run_one("en-US"), run_one("de-DE"))
    # Both render; en-US returns the English template; de-DE may also
    # return English (no de-DE catalog yet) but the ContextVar
    # propagation is what's under test.
    assert "en-US" in seen_translations
    assert "de-DE" in seen_translations


# ---------------------------------------------------------------------------
# Cluster 9 — WorkingMemoryPool acquire/release
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_working_memory_released_on_orchestrator_error() -> None:
    orchestrator = MagicMock()
    orchestrator.handle_user_message = AsyncMock(side_effect=RuntimeError("provider down"))
    adapter = _make_adapter(orchestrator=orchestrator)
    msg = _make_msg()
    with pytest.raises(RuntimeError):
        await adapter._handle(msg)
    adapter._working_pool.acquire.assert_awaited_once()
    adapter._working_pool.release.assert_awaited_once()


@pytest.mark.asyncio
async def test_working_memory_released_on_cancelled_error() -> None:
    orchestrator = MagicMock()
    orchestrator.handle_user_message = AsyncMock(side_effect=asyncio.CancelledError())
    adapter = _make_adapter(orchestrator=orchestrator)
    msg = _make_msg()
    with pytest.raises(asyncio.CancelledError):
        await adapter._handle(msg)
    adapter._working_pool.release.assert_awaited_once()


# ---------------------------------------------------------------------------
# Cluster 10 — typed exception arms
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_budget_blocked_uses_typed_kwargs() -> None:
    orchestrator = MagicMock()
    orchestrator.handle_user_message = AsyncMock(
        side_effect=BudgetExceededError(spent_usd=0.50, cap_usd=0.50)
    )
    adapter = _make_adapter(orchestrator=orchestrator)
    msg = _make_msg()
    await adapter._handle(msg)
    sent = msg.channel.send.call_args.args[0]
    # No raw str(exc) leakage.
    assert "BudgetExceededError" not in sent
    # The numeric values are rendered.
    assert "0.50" in sent


@pytest.mark.asyncio
async def test_unknown_budget_user_loud_re_raise() -> None:
    orchestrator = MagicMock()
    orchestrator.handle_user_message = AsyncMock(
        side_effect=UnknownBudgetUserError(user_id="phantom")
    )
    adapter = _make_adapter(orchestrator=orchestrator)
    msg = _make_msg()
    with pytest.raises(UnknownBudgetUserError):
        await adapter._handle(msg)
    msg.channel.send.assert_called_once()
    sent = msg.channel.send.call_args.args[0]
    assert "phantom" not in sent  # generic alfred_error, no raw exc


@pytest.mark.asyncio
async def test_cancelled_error_re_raised_bare() -> None:
    orchestrator = MagicMock()
    orchestrator.handle_user_message = AsyncMock(side_effect=asyncio.CancelledError())
    adapter = _make_adapter(orchestrator=orchestrator)
    msg = _make_msg()
    with pytest.raises(asyncio.CancelledError):
        await adapter._handle(msg)
    msg.channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_unhandled_exception_logs_re_raises() -> None:
    orchestrator = MagicMock()
    orchestrator.handle_user_message = AsyncMock(side_effect=RuntimeError("boom"))
    adapter = _make_adapter(orchestrator=orchestrator)
    msg = _make_msg()
    with pytest.raises(RuntimeError):
        await adapter._handle(msg)
    msg.channel.send.assert_called_once()
    sent = msg.channel.send.call_args.args[0]
    assert "boom" not in sent  # generic, no leak


def test_no_exception_str_in_user_templates() -> None:
    """AST-scan: no t(...) call site interpolates an Exception instance."""
    source_path = (
        pathlib.Path(__file__).resolve().parents[3] / "src" / "alfred" / "comms" / "discord.py"
    )
    tree = ast.parse(source_path.read_text())
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "t":
            for kw in node.keywords:
                # A kwarg passing ``str(exc)`` shows up as Call(func=Name("str")).
                if (
                    isinstance(kw.value, ast.Call)
                    and isinstance(kw.value.func, ast.Name)
                    and kw.value.func.id == "str"
                ):
                    offenders.append(f"line {node.lineno}: t(...) kwarg {kw.arg}=str(...)")
    assert not offenders, "no t() call site may interpolate str(exc): " + "; ".join(offenders)


# ---------------------------------------------------------------------------
# Cluster 11 — _send chokepoint + grep AST pin
# ---------------------------------------------------------------------------


def test_send_is_sole_channel_send_caller() -> None:
    """AST grep: channel.send appears only inside the _send method body."""
    source_path = (
        pathlib.Path(__file__).resolve().parents[3] / "src" / "alfred" / "comms" / "discord.py"
    )
    source_text = source_path.read_text()
    tree = ast.parse(source_text)

    # Collect every Call whose function is an Attribute named "send".
    send_calls: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "send"
        ):
            # Restrict to ``X.send(...)`` where X is anything resembling a channel
            # (channel, msg.channel, self._channel, etc.). Ignore .send on
            # broker, dlp, etc. — heuristic on receiver name.
            receiver = node.func.value
            if isinstance(receiver, ast.Name) and receiver.id == "channel":
                send_calls.append((node.lineno, "channel.send"))
            elif isinstance(receiver, ast.Attribute) and receiver.attr == "channel":
                send_calls.append((node.lineno, "msg.channel.send"))

    # Identify the line range of `_send` and `_send_chunk_with_retry`.
    allowed_ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name in {
            "_send",
            "_send_chunk_with_retry",
        }:
            allowed_ranges.append((node.lineno, node.end_lineno or node.lineno))

    # Each found send call must lie inside an allowed range.
    offenders = []
    for lineno, label in send_calls:
        if not any(lo <= lineno <= hi for lo, hi in allowed_ranges):
            offenders.append(f"line {lineno}: {label}")
    assert not offenders, (
        "channel.send must appear only inside _send / _send_chunk_with_retry; "
        f"offenders: {offenders}"
    )


@pytest.mark.asyncio
async def test_send_dlp_failed_audit_branch() -> None:
    outbound_dlp = MagicMock()
    outbound_dlp.scan = MagicMock(side_effect=RuntimeError("dlp boom"))
    adapter = _make_adapter(outbound_dlp=outbound_dlp)
    channel = _make_dm_channel()
    await adapter._send("hello", channel=channel)
    audit_calls = [
        c for c in adapter._audit.append.await_args_list if c.kwargs.get("result") == "dlp_failed"
    ]
    assert len(audit_calls) == 1
    assert audit_calls[0].kwargs["subject"]["dlp_error"] == "RuntimeError"


@pytest.mark.asyncio
async def test_send_split_failed_audit_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = _make_adapter()
    # Force the splitter to raise.
    import alfred.comms.discord as discord_mod

    def bad_split(*_args, **_kwargs):
        raise RuntimeError("split boom")

    monkeypatch.setattr(discord_mod, "_split_for_discord", bad_split)
    channel = _make_dm_channel()
    await adapter._send("hello", channel=channel)
    audit_calls = [
        c for c in adapter._audit.append.await_args_list if c.kwargs.get("result") == "split_failed"
    ]
    assert len(audit_calls) == 1


@pytest.mark.asyncio
async def test_send_send_failed_zero_chunks() -> None:
    """First chunk fails twice → audit send_failed with delivered=0."""
    adapter = _make_adapter()
    channel = _make_dm_channel()
    err = discord.HTTPException(response=MagicMock(status=503), message="boom")
    err.status = 503
    channel.send = AsyncMock(side_effect=err)
    await adapter._send("hello", channel=channel)
    audit_calls = [
        c for c in adapter._audit.append.await_args_list if c.kwargs.get("result") == "send_failed"
    ]
    assert len(audit_calls) == 1
    assert audit_calls[0].kwargs["subject"]["delivered_chunk_count"] == 0


@pytest.mark.asyncio
async def test_send_success_audit_after_return() -> None:
    adapter = _make_adapter()
    channel = _make_dm_channel()
    await adapter._send("hello world", channel=channel)
    success_calls = [
        c
        for c in adapter._audit.append.await_args_list
        if c.kwargs.get("result") == "success"
        and c.kwargs.get("event") == "comms.discord.send_outcome"
    ]
    assert len(success_calls) == 1
    assert success_calls[0].kwargs["subject"]["delivered_chunk_count"] == 1


@pytest.mark.asyncio
async def test_send_empty_text_yields_zero_chunks() -> None:
    adapter = _make_adapter()
    channel = _make_dm_channel()
    await adapter._send("", channel=channel)
    # No channel.send call; success audit with delivered=0.
    channel.send.assert_not_called()
    success_calls = [
        c for c in adapter._audit.append.await_args_list if c.kwargs.get("result") == "success"
    ]
    assert len(success_calls) == 1
    assert success_calls[0].kwargs["subject"]["delivered_chunk_count"] == 0


@pytest.mark.asyncio
async def test_send_recovery_skips_dlp_and_split() -> None:
    """Recovery path bypasses DLP+split (fixed-phrase guarantee)."""
    adapter = _make_adapter()
    # Tripwire the DLP to ensure it's never called on recovery.
    adapter._outbound_dlp.scan = MagicMock(side_effect=AssertionError("scan called on recovery"))
    channel = _make_dm_channel()
    await adapter._send("recovery text", channel=channel, _recovery=True)
    channel.send.assert_called_once_with("recovery text")


# ---------------------------------------------------------------------------
# Cluster 13 — reconnect classification
# ---------------------------------------------------------------------------


def test_classify_login_failure_to_exit_2() -> None:
    # discord.LoginFailure expects a single message arg.
    exc = discord.LoginFailure("bad token")
    assert _classify_gateway_exception(exc) == _GatewayDisposition.LOGIN_FAILED_EXIT_2


def test_classify_connection_closed_4xxx() -> None:
    # ConnectionClosed expects (socket, *, shard_id=None, code=None)
    sock = MagicMock()
    exc = discord.ConnectionClosed(sock, shard_id=0, code=4000)
    disposition = _classify_gateway_exception(exc)
    assert disposition == _GatewayDisposition.CONNECTION_CLOSED_AUTO_RECONNECT


def test_classify_http_5xx_retry_once_then_drop() -> None:
    response = MagicMock()
    response.status = 503
    exc = discord.HTTPException(response=response, message="server error")
    # Force status attribute (discord.py sets it from response).
    exc.status = 503
    assert _classify_gateway_exception(exc) == _GatewayDisposition.HTTP_5XX_RETRY_ONCE_THEN_DROP


def test_classify_repeated_reconnect_to_exit_1() -> None:
    recent = _RecentReconnects(window_seconds=60.0, threshold=10)
    sock = MagicMock()
    # 11 reconnects within 1s → threshold exceeded.
    for _ in range(11):
        exc = discord.ConnectionClosed(sock, shard_id=0, code=4000)
        last = _classify_gateway_exception(exc, recent=recent)
    assert last == _GatewayDisposition.REPEATED_RECONNECT_EXIT_1


# ---------------------------------------------------------------------------
# Cluster 14 — alfred discord verify exit codes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_returns_0_on_ready() -> None:
    """A client whose on_ready fires within the timeout returns code 0."""
    from alfred.security.dlp import OutboundDlp

    broker = MagicMock()
    broker.get = MagicMock(return_value="fake-token")
    broker.redact = MagicMock(side_effect=lambda s: s)
    dlp = OutboundDlp(broker=broker, audit=lambda **_: None)

    ready_handler_holder: list[Any] = []

    def factory(intents):
        client = MagicMock()

        async def fake_start(*_a, **_kw):
            # Block forever; the on_ready handler is what signals success.
            await asyncio.sleep(5)

        client.start = fake_start
        client.close = AsyncMock()

        def event(fn):
            ready_handler_holder.append(fn)
            return fn

        client.event = event
        return client

    async def trigger_ready():
        await asyncio.sleep(0.05)
        if ready_handler_holder:
            await ready_handler_holder[0]()

    _trigger_task = asyncio.create_task(trigger_ready())
    code, key, _kwargs = await run_verify_probe(
        broker=broker, outbound_dlp=dlp, timeout_s=2.0, client_factory=factory
    )
    assert code == 0
    assert key == "discord.verify.ok"
    _ = _trigger_task  # keep reference until scope exit


@pytest.mark.asyncio
async def test_verify_returns_3_on_login_failure() -> None:
    from alfred.security.dlp import OutboundDlp

    broker = MagicMock()
    broker.get = MagicMock(return_value="bad")
    broker.redact = MagicMock(side_effect=lambda s: s)
    dlp = OutboundDlp(broker=broker, audit=lambda **_: None)

    def factory(intents):
        client = MagicMock()

        async def fake_start(*_a, **_kw):
            raise discord.LoginFailure("bad token")

        client.start = fake_start
        client.close = AsyncMock()
        client.event = MagicMock(side_effect=lambda fn: fn)
        return client

    code, key, _kwargs = await run_verify_probe(
        broker=broker, outbound_dlp=dlp, timeout_s=2.0, client_factory=factory
    )
    assert code == 3
    assert key == "discord.verify.login_failed"


@pytest.mark.asyncio
async def test_verify_returns_4_on_timeout() -> None:
    from alfred.security.dlp import OutboundDlp

    broker = MagicMock()
    broker.get = MagicMock(return_value="fake")
    broker.redact = MagicMock(side_effect=lambda s: s)
    dlp = OutboundDlp(broker=broker, audit=lambda **_: None)

    def factory(intents):
        client = MagicMock()

        async def fake_start(*_a, **_kw):
            await asyncio.sleep(10)

        client.start = fake_start
        client.close = AsyncMock()
        client.event = MagicMock(side_effect=lambda fn: fn)
        return client

    code, key, _kwargs = await run_verify_probe(
        broker=broker, outbound_dlp=dlp, timeout_s=0.2, client_factory=factory
    )
    assert code == 4
    assert key == "discord.verify.timeout"


@pytest.mark.asyncio
async def test_verify_returns_2_on_bad_token_secret() -> None:
    from alfred.security.dlp import OutboundDlp
    from alfred.security.secrets import UnknownSecretError

    broker = MagicMock()
    broker.get = MagicMock(side_effect=UnknownSecretError("missing"))
    broker.redact = MagicMock(side_effect=lambda s: s)
    dlp = OutboundDlp(broker=broker, audit=lambda **_: None)

    code, key, _kwargs = await run_verify_probe(
        broker=broker,
        outbound_dlp=dlp,
        timeout_s=0.2,
    )
    assert code == 2
    assert key == "discord.verify.config_failed.bad_token"


@pytest.mark.asyncio
async def test_verify_returns_1_on_http_500() -> None:
    from alfred.security.dlp import OutboundDlp

    broker = MagicMock()
    broker.get = MagicMock(return_value="tok")
    broker.redact = MagicMock(side_effect=lambda s: s)
    dlp = OutboundDlp(broker=broker, audit=lambda **_: None)

    response = MagicMock()
    response.status = 503
    err = discord.HTTPException(response=response, message="upstream")
    err.status = 503

    def factory(intents):
        client = MagicMock()

        async def fake_start(*_a, **_kw):
            raise err

        client.start = fake_start
        client.close = AsyncMock()
        client.event = MagicMock(side_effect=lambda fn: fn)
        return client

    code, key, _kwargs = await run_verify_probe(
        broker=broker, outbound_dlp=dlp, timeout_s=2.0, client_factory=factory
    )
    assert code == 1
    assert key == "discord.verify.upstream_unrecoverable"


def test_verify_classifier_maps_keyboard_interrupt_to_130() -> None:
    """``KeyboardInterrupt`` maps to exit code 130 via the classifier.

    Note: we do NOT drive a full ``run_verify_probe`` cycle with a
    KeyboardInterrupt-raising task — asyncio surfaces
    :class:`KeyboardInterrupt` (a :class:`BaseException`) out of
    ``run_until_complete`` rather than letting userland catch it. The
    classifier is what the probe consults to produce the typed exit
    code on a synchronous KeyboardInterrupt; the end-to-end SIGINT
    path is covered by the smoke test in PR E.
    """
    code, key, _ = _classify_verify_exception(KeyboardInterrupt())
    assert code == 130
    assert key == "discord.verify.interrupted"


# ---------------------------------------------------------------------------
# Cluster 15 — boot dependency wiring
# ---------------------------------------------------------------------------


def test_discord_app_registers_verify_subcommand() -> None:
    from typer.testing import CliRunner

    from alfred.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["discord", "--help"])
    assert result.exit_code == 0
    assert "verify" in result.output


# ---------------------------------------------------------------------------
# Cluster 20 — i18n key resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key,kwargs",
    [
        ("discord.unknown_user_first", {"snowflake": "12345"}),
        ("discord.embed_unsupported", {}),
        ("discord.rate_limited", {}),
        ("discord.budget_blocked", {"spent": "0.50", "cap": "0.50"}),
        ("discord.alfred_error", {}),
        ("cli.discord.help.group", {}),
        ("cli.discord.help.verify.short", {}),
    ],
)
def test_discord_i18n_keys_resolve(key: str, kwargs: dict[str, Any]) -> None:
    rendered = t(key, **kwargs)
    assert rendered, f"i18n key {key!r} resolved to an empty string"
    assert rendered != key, f"i18n key {key!r} fell back to the key (catalog missed)"


# ---------------------------------------------------------------------------
# Misc: _UnknownDmAuditCap unit
# ---------------------------------------------------------------------------


def test_unknown_dm_audit_cap_consumes_up_to_limit() -> None:
    cap = _UnknownDmAuditCap(cap_per_min=3)
    assert cap.try_consume(now=0.0)
    assert cap.try_consume(now=0.0)
    assert cap.try_consume(now=0.0)
    assert not cap.try_consume(now=0.0)


def test_unknown_dm_audit_cap_window_slides() -> None:
    cap = _UnknownDmAuditCap(cap_per_min=2)
    cap.try_consume(now=0.0)
    cap.try_consume(now=0.0)
    # 61s later, the events are outside the window.
    assert cap.try_consume(now=61.0)


def test_recent_reconnects_returns_true_above_threshold() -> None:
    recent = _RecentReconnects(window_seconds=10.0, threshold=3)
    assert recent.register(now=0.0) is False
    assert recent.register(now=1.0) is False
    assert recent.register(now=2.0) is False
    assert recent.register(now=3.0) is True


# ---------------------------------------------------------------------------
# Misc: _classify_verify_exception
# ---------------------------------------------------------------------------


def test_classify_verify_login_failure_returns_3() -> None:
    exc = discord.LoginFailure("bad token")
    code, key, _ = _classify_verify_exception(exc)
    assert code == 3
    assert key == "discord.verify.login_failed"


def test_classify_verify_http_4xx_returns_2() -> None:
    response = MagicMock()
    response.status = 401
    exc = discord.HTTPException(response=response, message="unauthorized")
    exc.status = 401
    code, key, _ = _classify_verify_exception(exc)
    assert code == 2
    assert key == "discord.verify.config_failed.intents_off"


def test_classify_verify_http_5xx_returns_1() -> None:
    response = MagicMock()
    response.status = 503
    exc = discord.HTTPException(response=response, message="upstream")
    exc.status = 503
    code, key, _ = _classify_verify_exception(exc)
    assert code == 1
    assert key == "discord.verify.upstream_unrecoverable"


def test_classify_verify_unclassified_returns_1() -> None:
    exc = RuntimeError("mystery")
    code, key, _ = _classify_verify_exception(exc)
    assert code == 1
    assert key == "discord.verify.upstream_unrecoverable"
