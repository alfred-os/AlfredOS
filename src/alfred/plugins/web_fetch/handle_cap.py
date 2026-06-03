"""Per-user concurrent ContentHandle cap.

Spec §7.10 / docs/superpowers/specs/2026-06-02-handle-cap-design.md.

Sibling of :class:`~alfred.plugins.web_fetch.rate_limit.RateLimiter`. Where
the rate limiter bounds request rate, ``HandleCap`` bounds the number of
live :class:`~alfred.security.quarantine.ContentHandle` instances a single
user has outstanding in Redis — the resource the cap exists to protect.

See ``docs/superpowers/specs/2026-06-02-handle-cap-design.md`` for the
full design rationale, the disputed-item resolutions, and the review-pass
audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass

_DEFAULT_PER_USER_CAP: int = 5
"""Slice-3 spec §7.10 line 591 default. Operators tune via
``config/policies.yaml`` ``web_fetch.max_concurrent_handles_per_user``."""


@dataclass(frozen=True, slots=True)
class HandleCapConfig:
    """Per-deployment knobs for :class:`HandleCap`.

    A misconfigured cap (≤ 0) fails loud at config-load time, not silently
    at first fetch — matches the ``RateLimitConfig`` precedent.
    """

    per_user: int = _DEFAULT_PER_USER_CAP

    def __post_init__(self) -> None:
        if isinstance(self.per_user, bool) or not isinstance(self.per_user, int):
            msg = (
                f"HandleCapConfig.per_user must be an int >= 1; got {type(self.per_user).__name__}."
            )
            raise ValueError(msg)
        if self.per_user < 1:
            msg = (
                f"HandleCapConfig.per_user must be >= 1; got {self.per_user}. "
                "A cap of 0 would refuse every fetch."
            )
            raise ValueError(msg)


__all__ = ["HandleCapConfig"]
