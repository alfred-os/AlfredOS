"""Pydantic v2 frozen models for ``config/policies.yaml`` (ADR-0023, #159).

``PoliciesV1`` is the validated shape the :class:`alfred.policies.watcher.
PolicyWatcher` parses the operator's ``config/policies.yaml`` into. Every
block is frozen + ``extra="forbid"`` so a typo'd operator key surfaces as a
loud ``validation_failure`` (CLAUDE.md hard rule 7) rather than a silently
ignored knob.

Low-blast vs high-blast partitioning (ADR-0023 §5 / closure arch-003).
The partition is a **default-refuse, allowlist-permit** classification, NOT a
high-blast denylist. The watcher hot-reloads a changed key ONLY when its
dotted path is enumerated in :data:`LOW_BLAST_ALLOWLIST`; EVERY other changed
key — top-level or nested — refuses hot-reload with ``high_blast_change``. The
secure shape is allowlist-permit precisely so a future field added to any
block defaults to refuse rather than silently slipping through a denylist gap.

* :class:`RateLimitPolicies`, :class:`HandleCapPolicies` — anti-abuse knobs.
  These are **high-blast** per ADR-0023 §5 / closure arch-003: an attacker
  with config-write could shrink ``web_fetch_per_user_per_hour`` /
  ``quarantined_extract_per_user_persona`` / ``web_fetch_per_session_total`` /
  ``operator_daily_budget_usd`` /
  ``web_fetch_max_concurrent_handles_per_user`` to 0 (DoS) or widen them to ∞
  (anti-abuse bypass). They are NOT in the low-blast allowlist, so the watcher
  refuses hot-reloading them. The BurstLimiter sub-policy is consumed by
  PR-S4-8 read-only off the boot-time snapshot.
* :class:`HighBlastPolicies` — keys whose blast radius is total
  (``quarantined_provider_url`` redirects every T3 extraction;
  ``secret_broker_config_ref`` repoints the broker). Also outside the
  allowlist; only the reviewer-gated proposal flow may change them.

:data:`LOW_BLAST_ALLOWLIST` is currently **empty** — the only fields modelled
so far (``rate_limits``, ``handle_caps``, ``high_blast``) are all high-blast.
The reserved members of the low-blast partition are UI strings, timezone /
locale, observability sample rates, and non-security log verbosity — none of
which exist in :class:`PoliciesV1` yet. When such a field lands it gets an
explicit allowlist entry plus a corpus + unit test proving it hot-reloads.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

# Dotted key paths (``<top_level>`` or ``<top_level>.<sub_field>``) whose
# change the watcher is permitted to hot-reload. EMPTY by design (ADR-0023 §5):
# every field currently modelled in ``PoliciesV1`` is high-blast. Membership is
# checked against the dotted diff produced by
# ``alfred.policies.snapshot_ref._diff_keys``; any changed key absent here is a
# ``high_blast_change`` refusal. This is the secure partition shape:
# default-refuse, allowlist-permit — never a high-blast denylist that could
# silently miss a future field.
LOW_BLAST_ALLOWLIST: Final[frozenset[str]] = frozenset()


class BurstLimiterPolicy(BaseModel):
    """Per-(canonical_user_id, persona) token bucket — consumed by PR-S4-8.

    Foundation gap #1 / closure arch-002: this model ships in PR-S4-4 (not
    PR-S4-0a as the cross-PR contract originally assumed). PR-S4-8's
    ``BurstLimiter`` reads ``capacity_tokens`` / ``refill_seconds`` from
    ``ref.current().rate_limits.quarantined_extract_per_user_persona``. The
    defaults (5 tokens, 5.0 s refill) are the cross-PR contract anchor pinned
    by ``tests/unit/policies/test_burst_limiter_policy_defaults.py``.
    """

    capacity_tokens: int = Field(default=5, ge=1, le=100)
    refill_seconds: float = Field(default=5.0, ge=0.5, le=60.0)
    model_config = ConfigDict(frozen=True, extra="forbid")


class RateLimitPolicies(BaseModel):
    """Web-fetch + budget rate-limit knobs (anti-abuse — high-blast family)."""

    web_fetch_per_user_per_hour: int = Field(ge=0)
    web_fetch_per_session_total: int = Field(ge=0)
    operator_daily_budget_usd: float = Field(ge=0.0)
    quarantined_extract_per_user_persona: BurstLimiterPolicy = Field(
        default_factory=BurstLimiterPolicy
    )
    model_config = ConfigDict(frozen=True, extra="forbid")


class HandleCapPolicies(BaseModel):
    """Concurrent ContentHandle cap (anti-abuse — high-blast family)."""

    web_fetch_max_concurrent_handles_per_user: int = Field(ge=1)
    model_config = ConfigDict(frozen=True, extra="forbid")


class HighBlastPolicies(BaseModel):
    """High-blast keys that REFUSE hot-reload; reviewer-gate only.

    A change to any field here aborts the watcher swap with
    ``reason="high_blast_change"`` (closure sec-3). The blast radius of an
    attacker-controlled ``quarantined_provider_url`` (redirect every T3
    extraction to attacker infrastructure) or ``secret_broker_config_ref``
    (point the broker at an attacker store) is total, so only the
    reviewer-gated proposal flow may change them.
    """

    quarantined_provider_url: HttpUrl
    secret_broker_config_ref: str = Field(min_length=1)
    model_config = ConfigDict(frozen=True, extra="forbid")


class PoliciesV1(BaseModel):
    """Top-level validated shape of ``config/policies.yaml`` (schema_version 1)."""

    schema_version: Literal[1]
    rate_limits: RateLimitPolicies
    handle_caps: HandleCapPolicies
    high_blast: HighBlastPolicies
    model_config = ConfigDict(frozen=True, extra="forbid")


__all__ = [
    "LOW_BLAST_ALLOWLIST",
    "BurstLimiterPolicy",
    "HandleCapPolicies",
    "HighBlastPolicies",
    "PoliciesV1",
    "RateLimitPolicies",
]
