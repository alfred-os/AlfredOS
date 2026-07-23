"""``_resolve_launch_target`` — env-gated, fail-closed launch-target override (G6-7-7).

Spec B G6-7-7 (#309) Task 1. The gateway adapter child factory gains a
constructor-injected ``override_map`` so a later docker-only e2e (Task 4) can
redirect the production ``"discord"`` launch target to a test PROBE module
WITHOUT touching the production Discord adapter. The override is honored ONLY in
a ``{"development", "test"}`` environment; anywhere else (incl. ``production``,
``staging``, unset, unrecognised) an injected override is a LOUD, FAIL-CLOSED
:class:`LaunchTargetOverrideRefusedError` — a :class:`GatewayAdapterSpawnError`
subclass the supervisor's spawn-error arm audits.

The refusal message is CONTENT-FREE (sec-003/sec-101): it flows verbatim into the
supervisor audit row (``detail=str(spawn_error)``), so it MUST carry only the
``adapter_id``, the active environment string, and the allowlist — NEVER the
rejected override module string (a canary leak into the audit log).
"""

from __future__ import annotations

import pytest

from alfred.config._environment_loader import (
    EnvironmentLoadResult,
    EnvironmentSource,
)
from alfred.gateway.adapter_child_factory import (
    _ADAPTER_LAUNCH_TARGETS,
    LaunchTargetOverrideRefusedError,
    _resolve_launch_target,
)
from alfred.gateway.adapter_supervisor import GatewayAdapterSpawnError

# The probe override Task 4 injects: redirect "discord" away from the production
# adapter to a test probe module. Used verbatim across the override cases.
_PROBE_OVERRIDE: dict[str, tuple[str, str]] = {
    "discord": ("alfred.discord_probe", "alfred.gateway.discord_probe"),
}
_PROBE_PLUGIN_ID = "alfred.discord_probe"
_PROBE_MODULE = "alfred.gateway.discord_probe"


def _patch_environment(monkeypatch: pytest.MonkeyPatch, value: str | None) -> list[bool]:
    """Patch ``resolve_environment`` where the factory imports it; return a consult flag.

    The returned single-element list flips to ``True`` the first time the factory
    calls ``resolve_environment`` so a test can assert the env was actually consulted
    (case (e)). ``value`` is the resolved environment string (or ``None`` for the
    unset/unrecognised posture) returned by the patched loader.
    """
    consulted: list[bool] = []
    source = EnvironmentSource.ENV_VAR if value is not None else EnvironmentSource.NONE

    def _fake_resolve_environment(**_kwargs: object) -> EnvironmentLoadResult:
        consulted.append(True)
        return EnvironmentLoadResult(value=value, source=source)

    monkeypatch.setattr(
        "alfred.gateway.adapter_child_factory.resolve_environment",
        _fake_resolve_environment,
    )
    return consulted


# --- (a) dev/test env + injected probe override -> resolves to the probe. ---


@pytest.mark.parametrize("env_value", ["development", "test"])
def test_override_in_allowlisted_env_resolves_to_probe(
    monkeypatch: pytest.MonkeyPatch, env_value: str
) -> None:
    _patch_environment(monkeypatch, env_value)

    target = _resolve_launch_target("discord", override_map=_PROBE_OVERRIDE)

    assert target == (_PROBE_PLUGIN_ID, _PROBE_MODULE)


# --- (b) non-allowlisted env + present override_map -> fail-closed refusal. ---


@pytest.mark.parametrize(
    "env_value",
    ["production", "staging", "", None, "bogus"],
    ids=["production", "staging", "empty", "unset", "unrecognised"],
)
def test_override_outside_allowlist_refuses(
    monkeypatch: pytest.MonkeyPatch, env_value: str | None
) -> None:
    # The loader maps "staging"/""/"bogus" to None (not in the Literal triple);
    # the factory treats a None resolved value as not-allowlisted -> refuse.
    resolved = env_value if env_value in {"development", "test"} else None
    _patch_environment(monkeypatch, resolved)

    with pytest.raises(LaunchTargetOverrideRefusedError) as excinfo:
        _resolve_launch_target("discord", override_map=_PROBE_OVERRIDE)

    # Load-bearing: the supervisor's spawn-error arm catches the BASE type.
    assert isinstance(excinfo.value, GatewayAdapterSpawnError)


# --- (c) no override_map -> production target unchanged, no refusal. ---


def test_no_override_map_resolves_production_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consulted = _patch_environment(monkeypatch, "production")

    target = _resolve_launch_target("discord", override_map=None)

    assert target == _ADAPTER_LAUNCH_TARGETS["discord"]
    # With override_map=None the resolver must NOT read the environment at all —
    # the no-override path is byte-for-byte the pre-G6-7-7 static lookup.
    assert consulted == [], "resolve_environment must not be consulted on the no-override path"


def test_no_override_map_unknown_adapter_raises_static_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Preserve the existing no-target path byte-for-byte: a non-subclass
    # GatewayAdapterSpawnError with the closed-static-map message.
    _patch_environment(monkeypatch, "production")

    with pytest.raises(GatewayAdapterSpawnError) as excinfo:
        _resolve_launch_target("telegram", override_map=None)

    assert not isinstance(excinfo.value, LaunchTargetOverrideRefusedError)
    assert "closed static map" in str(excinfo.value)
    assert "telegram" in str(excinfo.value)


def test_present_override_allowlisted_env_id_not_in_map_falls_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Resolved ambiguity: a present override_map + an allowlisted env + an
    # adapter_id NOT in the override_map falls through to the PRODUCTION default,
    # NOT a refusal. (The override only redirects ids it actually names.)
    _patch_environment(monkeypatch, "test")

    target = _resolve_launch_target("discord", override_map={"telegram": ("a", "b")})

    assert target == _ADAPTER_LAUNCH_TARGETS["discord"]


# --- (d) the refusal is CONTENT-FREE: no override module string anywhere. ---


def test_refusal_message_is_content_free(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_environment(monkeypatch, "production")

    with pytest.raises(LaunchTargetOverrideRefusedError) as excinfo:
        _resolve_launch_target("discord", override_map=_PROBE_OVERRIDE)

    err = excinfo.value
    rendered = str(err)
    joined_args = " ".join(str(a) for a in err.args)
    # sec-003/sec-101: the rejected override module/plugin id MUST NEVER appear in
    # the message or args (it flows verbatim into the supervisor audit row).
    for leak in (_PROBE_MODULE, _PROBE_PLUGIN_ID):
        assert leak not in rendered, f"override string {leak!r} leaked into str(err)"
        assert leak not in joined_args, f"override string {leak!r} leaked into err.args"
    # The message MUST still be actionable: the adapter_id, the environment, and
    # the allowlist hint (devex-002) are all content-free and present.
    assert "discord" in rendered
    assert "production" in rendered
    assert "development" in rendered
    assert "test" in rendered


# --- (e) the environment is read via ``resolve_environment`` (consulted). ---


def test_environment_read_via_resolve_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consulted = _patch_environment(monkeypatch, "test")

    _resolve_launch_target("discord", override_map=_PROBE_OVERRIDE)

    assert consulted == [True], "resolve_environment was not consulted on the override path"
