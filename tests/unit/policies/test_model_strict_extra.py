"""``PoliciesV1`` strict-extra + range + frozen contract (PR-S4-4 Task 1).

Spec §5.2 / ADR-0023. ``PoliciesV1`` is the Pydantic v2 frozen model the
``PolicyWatcher`` validates ``config/policies.yaml`` into. ``extra="forbid"``
turns a typo'd operator key into a loud ``validation_failure`` rather than a
silently-ignored knob.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from alfred.policies.model import PoliciesV1


def _minimal_dict() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "rate_limits": {
            "web_fetch_per_user_per_hour": 60,
            "web_fetch_per_session_total": 200,
            "operator_daily_budget_usd": 5.0,
        },
        "handle_caps": {"web_fetch_max_concurrent_handles_per_user": 8},
        "high_blast": {
            "quarantined_provider_url": "https://quarantine.local/v1",
            "secret_broker_config_ref": "broker://default",
        },
    }


def _build_minimal_policies() -> PoliciesV1:
    return PoliciesV1.model_validate(_minimal_dict())


def test_policies_v1_minimal_loads() -> None:
    v = _build_minimal_policies()
    assert v.schema_version == 1
    assert v.rate_limits.web_fetch_per_user_per_hour == 60
    # The optional burst-limiter block defaults in (PR-S4-8 contract).
    assert v.rate_limits.quarantined_extract_per_user_persona.capacity_tokens == 5


def test_policies_v1_refuses_unknown_top_level_field() -> None:
    data = _minimal_dict()
    data["unknown_extra"] = "x"
    with pytest.raises(ValidationError) as excinfo:
        PoliciesV1.model_validate(data)
    assert "unknown_extra" in str(excinfo.value)


def test_policies_v1_refuses_unknown_nested_field() -> None:
    data = _minimal_dict()
    data["rate_limits"]["unexpected_knob"] = 1
    with pytest.raises(ValidationError) as excinfo:
        PoliciesV1.model_validate(data)
    assert "unexpected_knob" in str(excinfo.value)


def test_policies_v1_refuses_negative_rate_limit() -> None:
    data = _minimal_dict()
    data["rate_limits"]["web_fetch_per_user_per_hour"] = -1
    with pytest.raises(ValidationError):
        PoliciesV1.model_validate(data)


def test_policies_v1_refuses_bad_schema_version() -> None:
    data = _minimal_dict()
    data["schema_version"] = 2
    with pytest.raises(ValidationError):
        PoliciesV1.model_validate(data)


def test_policies_v1_refuses_non_http_provider_url() -> None:
    data = _minimal_dict()
    data["high_blast"]["quarantined_provider_url"] = "not-a-url"
    with pytest.raises(ValidationError):
        PoliciesV1.model_validate(data)


def test_policies_v1_refuses_empty_secret_broker_ref() -> None:
    data = _minimal_dict()
    data["high_blast"]["secret_broker_config_ref"] = ""
    with pytest.raises(ValidationError):
        PoliciesV1.model_validate(data)


def test_handle_cap_must_be_at_least_one() -> None:
    data = _minimal_dict()
    data["handle_caps"]["web_fetch_max_concurrent_handles_per_user"] = 0
    with pytest.raises(ValidationError):
        PoliciesV1.model_validate(data)


def test_policies_v1_is_frozen() -> None:
    v = _build_minimal_policies()
    with pytest.raises(ValidationError):
        v.schema_version = 1  # type: ignore[misc]
