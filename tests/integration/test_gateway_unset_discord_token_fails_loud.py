"""#309 deploy-path guardrail: an unset Discord token produces a LOUD, AUDITED refusal.

Non-root in-process companion to the privileged real-spawn lane (Task 9). Drives the
real :class:`~alfred.comms_mcp.adapter_credential_resolver.CoreAdapterCredentialResolver`
with an empty secret broker (no ``discord_bot_token``) and asserts:

1. :class:`~alfred.comms_mcp.adapter_credential_resolver.AdapterCredentialError` is
   raised with ``reason == "missing_secret"`` — never silent-dark.
2. A signed ``result="refused"`` audit row was appended to the capturing sink (hard
   rules #5 and #7 — a failed credential resolution is a non-skippable security event).

**Known blast radius**: when the unset-token path fires at runtime the entire gateway
process aborts (fail-closed). The park-not-abort structural fix is tracked by #331.

**#469 Blocker 2**: this resolver behaviour is UNCHANGED — an operator who explicitly
opts Discord in (``ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]``) without also
setting ``ALFRED_DISCORD_BOT_TOKEN`` still hits this exact refusal path. What changed is
the *stock* ``docker-compose.yaml`` default: Discord is now opt-in
(``ALFRED_GATEWAY_HOSTED_ADAPTERS:-[]``), so a first-run `docker compose up -d` with no
Discord config no longer reaches this path at all — the gateway simply hosts no adapter
and boots healthy.

Fixture pattern mirrors ``tests/adversarial/comms/test_gateway_credential_corpus.py``
(the ``_CountingBroker`` / ``_FakeAudit`` / ``_resolver`` shapes); reused here as
inline helpers to keep this test self-contained on the standard integration gate
(not the adversarial release-blocking gate).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.adapter_credential_protocol import SpawnRequest
from alfred.comms_mcp.adapter_credential_resolver import (
    AdapterCredentialError,
    CoreAdapterCredentialResolver,
)
from alfred.security.secrets import UnknownSecretError

# ---------------------------------------------------------------------------
# Inline fixture helpers (mirror the adversarial corpus wiring)
# ---------------------------------------------------------------------------

_EPOCH = "0123456789abcdef0123456789abcdef"
_REQ_ID = "22222222222222222222222222222222"


class _EmptyBroker:
    """A broker with NO credentials — simulates ALFRED_DISCORD_BOT_TOKEN unset."""

    def get(self, name: str) -> str:
        raise UnknownSecretError(name)


class _CapturingAudit:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))


def _make_resolver(broker: _EmptyBroker, audit: _CapturingAudit) -> CoreAdapterCredentialResolver:
    return CoreAdapterCredentialResolver(broker=broker, audit=audit, now=lambda: datetime.now(UTC))


def _discord_request() -> SpawnRequest:
    return SpawnRequest(
        request_id=_REQ_ID,
        adapter_id="discord",
        host_restart_seq=0,
        epoch=_EPOCH,
    )


# ---------------------------------------------------------------------------
# The guardrail test
# ---------------------------------------------------------------------------


async def test_unset_discord_token_refuses_loud_and_audited() -> None:
    """#309 guardrail: an unset discord token yields a LOUD audited missing_secret
    refusal, never silent-dark.

    The gateway-abort blast radius (process dies on this path) is tracked by #331.
    """
    broker = _EmptyBroker()
    audit = _CapturingAudit()
    resolver = _make_resolver(broker, audit)

    with pytest.raises(AdapterCredentialError) as exc_info:
        await resolver.resolve(_discord_request())

    # 1. The refusal carries the closed-vocab reason — never a raw broker error.
    assert exc_info.value.reason == "missing_secret"
    assert exc_info.value.adapter_id == "discord"

    # 2. A signed result=refused audit row was appended (hard rules #5 + #7).
    refused_rows = [r for r in audit.rows if r.get("result") == "refused"]
    assert refused_rows, (
        "Expected at least one result=refused audit row for the missing_secret refusal; "
        "got none. Hard rules #5 and #7 require a signed audit entry on every "
        "security-boundary failure — a silent dark refusal is never acceptable."
    )
    row = refused_rows[0]
    subject = row.get("subject")
    assert isinstance(subject, dict) and subject.get("adapter_id") == "discord"
