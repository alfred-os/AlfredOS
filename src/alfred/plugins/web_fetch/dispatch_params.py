"""``WebFetchDispatchParams`` — host-side Pydantic schema for the
``web.fetch`` JSON-RPC params dict (issue #147 / spec §2.1).

Defence-in-depth: ``dispatch_web_fetch`` constructs this model BEFORE
``transport.dispatch``. A missing or wrong-typed field raises
``pydantic.ValidationError`` host-side; the dispatcher catches it,
releases the handle-cap reservation, emits a ``tool.web.fetch`` audit
row with ``dlp_scan_result="dispatch_param_invalid"``, and raises
typed ``WebFetchError``.

The plugin subprocess's err-004 crash-on-bad-params contract stays
as the secondary defence; this model is the primary.

Trust-boundary discipline (spec §3.2 / CLAUDE.md hard rule #7): the
Pydantic ``ValidationError`` message is NEVER surfaced in audit rows
or operator-visible structlog fields — Pydantic error messages embed
field names AND values that may carry secrets (URL query strings,
header values). Only ``type(exc).__name__`` is safe; forensic detail
rides on ``correlation_id`` in the audit row.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from alfred.plugins.web_fetch.constants import _DEFAULT_SIZE_LIMIT_BYTES


class WebFetchDispatchParams(BaseModel):
    """JSON-RPC params dict for ``web.fetch``.

    ``extra="forbid"`` so a dispatcher adding a key without updating
    the model fails loud (matches the C2 / arch-002 shape from
    PR-S3-5 — issue #147's root cause).

    ``strict=True`` so type coercion can't paper over a dispatcher
    bug (e.g. passing ``1`` for ``skip_tls_verify`` would otherwise
    coerce to ``True``).

    ``frozen=True`` so the validated payload is the wire format —
    nothing mutates it post-validation.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    url: str
    headers: Mapping[str, str]
    """Read-only mapping. ``Mapping`` honours the ``frozen=True``
    model_config's immutability claim without a runtime cost — Pydantic
    v2 accepts any Mapping for this field and the dispatcher only ever
    reads from the validated value (L-4 / REV-2)."""

    redis_url: str
    correlation_id: str
    content_handle_id: str
    """Host pre-minted UUID (added by #157). The plugin uses this
    exact key when writing the body to Redis; the dispatcher verifies
    equality on the success path (handle-cap PR's Task 19)."""

    skip_tls_verify: bool = False
    """Dev escape hatch (``ALFRED_ENV=development`` only). The
    parent-side ``TlsPolicy`` check is the authoritative gate; this
    flag is forwarded for the subprocess-side defence-in-depth check."""

    size_limit_bytes: int = Field(default=_DEFAULT_SIZE_LIMIT_BYTES, gt=0)
    """Response body cap. ``gt=0`` defends against a 0/negative value
    reaching the plugin; ``_clamp_size_limit`` in the plugin is the
    secondary defence (CR-146 major)."""


__all__ = ["WebFetchDispatchParams"]
