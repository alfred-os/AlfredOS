"""``alfred.cli._settings_errors`` — the value-free settings-error renderer (#589).

Unit-level, no ``CliRunner``: this module is the ONE place either operator-facing
surface (daemon-boot, interactive CLI) may read a ``SettingsError``'s cause, and it
sits inside a 100%-line+branch coverage gate (``ci.yml``) — every branch below,
including the two defensive ``literal_error``-context arms, needs its own test or the
gate goes red. The end-to-end regression proving the actual LEAK is closed (a real
``alfred status`` invocation with a credential-shaped env var) lives in
``tests/unit/cli/test_main.py`` instead — this file is the narrower unit-level pin of
the renderer's own branch logic.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from pydantic_core import InitErrorDetails, PydanticCustomError

from alfred.cli._settings_errors import (
    SettingsFieldFault,
    cli_settings_error_lines,
    daemon_boot_settings_message,
    settings_error_field,
)
from alfred.config.settings import Settings, SettingsError
from alfred.i18n import t


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimal env for a real ``Settings()`` construction."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")


# ---------------------------------------------------------------------------
# settings_error_field
# ---------------------------------------------------------------------------


def test_field_fault_names_the_dotted_path_for_a_field_validator_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain (non-Literal) field-validator rejection names the field, no choices."""
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DEEPSEEK_MODEL", " ")
    with pytest.raises(SettingsError) as exc_info:
        Settings()  # type: ignore[call-arg]

    fault = settings_error_field(exc_info.value)

    assert fault == SettingsFieldFault(path="deepseek_model", choices=None)


def test_field_fault_carries_the_literal_choices_and_never_the_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The headline case: a rejected Literal names the field AND its accepted
    values — and the credential-shaped rejected value never appears anywhere in
    the fault, not even under ``repr()``."""
    _base_env(monkeypatch)
    credential = "not-a-real-secret-primary-provider-test-placeholder"
    monkeypatch.setenv("ALFRED_PRIMARY_PROVIDER", credential)
    with pytest.raises(SettingsError) as exc_info:
        Settings()  # type: ignore[call-arg]

    fault = settings_error_field(exc_info.value)

    assert fault is not None
    assert fault.path == "primary_provider"
    assert fault.choices == "'anthropic' or 'deepseek'"
    assert credential not in repr(fault)


def test_field_fault_none_when_cause_is_not_a_validation_error() -> None:
    """No chained ``ValidationError`` (e.g. a test double raising ``SettingsError``
    directly with no ``from``) — the caller falls back to a fully generic message."""
    try:
        raise SettingsError("settings blew up")
    except SettingsError as exc:
        assert settings_error_field(exc) is None


def test_field_fault_none_when_cause_has_no_errors() -> None:
    """Defensive branch: a chained ``ValidationError`` whose own ``errors()`` is
    empty falls back to ``None`` instead of indexing ``errors[0]``.

    A REAL ``Settings()`` construction failure can never produce this shape —
    pydantic only raises ``ValidationError`` when there is at least one line error,
    so there is no natural (non-synthetic) call path through ``Settings()`` that
    reaches it. It is still a reachable pydantic-core STATE, not dead code: any
    caller holding a ``ValidationError`` reference (a test double, a future pydantic
    version, a library that re-raises one after filtering its errors) can construct
    exactly this shape via pydantic's own public
    ``ValidationError.from_exception_data`` — the same constructor pydantic's own
    test suite uses to build ``ValidationError`` instances without a full model
    round-trip.
    """
    cause = ValidationError.from_exception_data("Settings", [])
    try:
        raise SettingsError("settings blew up") from cause
    except SettingsError as exc:
        assert settings_error_field(exc) is None


def test_field_fault_none_when_loc_is_empty_and_type_is_generic() -> None:
    """Defensive branch: a chained ``ValidationError`` whose single error has an
    empty ``loc`` tuple AND a generic ``value_error``/``assertion_error`` type falls
    back to ``None`` rather than joining an empty path into an empty-string field
    name.

    Reachable through a real pydantic model failure: a ``model_validator(mode=
    "after")`` that raises reports ``loc=()`` (verified directly against pydantic).
    ``Settings`` has a model-level connection-budget validator (#410 PR1), so this
    shape IS reachable — but the guard exists so a model-level validator raised as a
    BARE ``ValueError`` degrades to the generic message rather than rendering an
    empty field name; a deliberately-slugged ``PydanticCustomError`` instead
    surfaces its category slug (see the sibling test below).
    """
    line_errors: list[InitErrorDetails] = [
        InitErrorDetails(
            type=PydanticCustomError("value_error", "model-level failure"),
            loc=(),
            input="irrelevant",
        )
    ]
    cause = ValidationError.from_exception_data("Settings", line_errors)
    try:
        raise SettingsError("settings blew up") from cause
    except SettingsError as exc:
        assert settings_error_field(exc) is None


def test_field_fault_surfaces_a_custom_slug_at_empty_loc() -> None:
    """#410 PR1 (fleet finding H-3): a model-level (``loc=()``) refusal raised as a
    deliberately-slugged ``PydanticCustomError`` surfaces its slug — the DLP-safe
    category naming WHICH constraint failed — instead of degrading to the fully
    generic message. The sibling test above still holds: a BARE ``ValueError``
    raise arrives as pydantic's generic ``value_error`` wrapper type, which names
    nothing and stays swallowed. Slugs are authored string literals in settings.py
    — never interpolated from a value — so this is the same value-free contract as
    the field-path variant, and carries no choices."""
    line_errors: list[InitErrorDetails] = [
        InitErrorDetails(
            type=PydanticCustomError("db_pool_connection_budget_exceeded", "over budget"),
            loc=(),
            input="irrelevant",
        )
    ]
    cause = ValidationError.from_exception_data("Settings", line_errors)
    try:
        raise SettingsError("settings blew up") from cause
    except SettingsError as exc:
        assert settings_error_field(exc) == SettingsFieldFault(
            path="db_pool_connection_budget_exceeded", choices=None
        )


def test_field_fault_literal_choices_none_when_ctx_is_absent() -> None:
    """``_literal_choices`` defensive arm: a ``literal_error`` whose error dict
    carries NO ``ctx`` key at all (verified directly against pydantic-core: a
    ``PydanticCustomError`` built with no ``context`` argument omits ``ctx`` from
    ``errors()`` entirely, rather than including it as ``None``) still resolves —
    the field path is named, just without accepted-value choices."""
    line_errors: list[InitErrorDetails] = [
        InitErrorDetails(
            type=PydanticCustomError("literal_error", "bad value"),
            loc=("primary_provider",),
            input="irrelevant",
        )
    ]
    cause = ValidationError.from_exception_data("Settings", line_errors)
    try:
        raise SettingsError("settings blew up") from cause
    except SettingsError as exc:
        assert settings_error_field(exc) == SettingsFieldFault(
            path="primary_provider", choices=None
        )


def test_field_fault_literal_choices_none_when_expected_is_not_a_string() -> None:
    """``_literal_choices`` defensive arm: ``ctx['expected']`` present but not a
    ``str`` (pydantic-core's own contract allows arbitrary context values) — refuse
    to surface it rather than render a non-string via an implicit ``str()``, which
    could format unpredictably for an unanticipated type."""
    line_errors: list[InitErrorDetails] = [
        InitErrorDetails(
            type=PydanticCustomError("literal_error", "bad value {expected}", {"expected": 42}),
            loc=("primary_provider",),
            input="irrelevant",
        )
    ]
    cause = ValidationError.from_exception_data("Settings", line_errors)
    try:
        raise SettingsError("settings blew up") from cause
    except SettingsError as exc:
        assert settings_error_field(exc) == SettingsFieldFault(
            path="primary_provider", choices=None
        )


# ---------------------------------------------------------------------------
# daemon_boot_settings_message — the daemon-boot renderer's four arms
# ---------------------------------------------------------------------------


def test_daemon_boot_message_uses_the_placeholder_hint() -> None:
    exc = SettingsError(
        "1 validation error for Settings\ndeepseek_api_key\n  Value error, placeholder_api_key"
    )
    assert daemon_boot_settings_message(exc) == t("error.placeholder_api_key")


def test_daemon_boot_message_is_generic_when_no_field_is_recoverable() -> None:
    try:
        raise SettingsError("settings blew up")
    except SettingsError as exc:
        assert daemon_boot_settings_message(exc) == t("daemon.boot.settings_invalid")


def test_daemon_boot_message_names_the_field_without_choices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DEEPSEEK_MODEL", " ")
    with pytest.raises(SettingsError) as exc_info:
        Settings()  # type: ignore[call-arg]

    message = daemon_boot_settings_message(exc_info.value)

    assert message == t("daemon.boot.settings_invalid_field", field="deepseek_model")


def test_daemon_boot_message_lists_the_accepted_values_for_a_literal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """devex-001 on the daemon-boot surface: the message must name BOTH accepted
    values, and never the credential-shaped rejected one."""
    _base_env(monkeypatch)
    credential = "not-a-real-secret-primary-provider-test-placeholder"
    monkeypatch.setenv("ALFRED_PRIMARY_PROVIDER", credential)
    with pytest.raises(SettingsError) as exc_info:
        Settings()  # type: ignore[call-arg]

    message = daemon_boot_settings_message(exc_info.value)

    assert "anthropic" in message
    assert "deepseek" in message
    assert "primary_provider" in message
    assert credential not in message


# ---------------------------------------------------------------------------
# cli_settings_error_lines — the interactive-CLI renderer's four arms
# ---------------------------------------------------------------------------


def test_cli_lines_are_the_placeholder_hint_alone() -> None:
    exc = SettingsError(
        "1 validation error for Settings\ndeepseek_api_key\n  Value error, placeholder_api_key"
    )
    assert cli_settings_error_lines(exc) == (t("error.placeholder_api_key"),)


def test_cli_lines_are_generic_plus_the_env_example_hint() -> None:
    try:
        raise SettingsError("settings blew up")
    except SettingsError as exc:
        assert cli_settings_error_lines(exc) == (
            t("error.config_invalid"),
            t("hint.copy_env_example"),
        )


def test_cli_lines_name_the_field_without_the_env_example_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once a field is nameable, ``hint.copy_env_example`` is misdirection (the
    operator's .env is already populated; ONE value in it is wrong) — deliberately
    dropped on this branch, unlike the fully-generic one above."""
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DEEPSEEK_MODEL", " ")
    with pytest.raises(SettingsError) as exc_info:
        Settings()  # type: ignore[call-arg]

    lines = cli_settings_error_lines(exc_info.value)

    assert len(lines) == 1
    assert "deepseek_model" in lines[0]


def test_cli_lines_list_the_accepted_values_and_never_the_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The headline unit assertion: the rendered block names the field and both
    accepted values, and contains neither the rejected credential nor pydantic's
    own ``input_value=`` envelope — the exact leak this module exists to close."""
    _base_env(monkeypatch)
    credential = "not-a-real-secret-primary-provider-test-placeholder"
    monkeypatch.setenv("ALFRED_PRIMARY_PROVIDER", credential)
    with pytest.raises(SettingsError) as exc_info:
        Settings()  # type: ignore[call-arg]

    lines = cli_settings_error_lines(exc_info.value)
    flat = " ".join(lines)

    assert "primary_provider" in flat
    assert "anthropic" in flat
    assert "deepseek" in flat
    assert credential not in flat
    assert "input_value" not in flat
