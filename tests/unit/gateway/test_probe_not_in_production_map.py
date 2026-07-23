"""Guard: the production launch map carries NO probe target (G6-7-7 Task 1).

Spec B G6-7-7 (#309). The constructor-injected ``override_map`` is the ONLY way a
probe launch target can reach :func:`_resolve_launch_target`; the production
:data:`_ADAPTER_LAUNCH_TARGETS` must never name a probe plugin id or module, and the
override must be consulted ONLY when an override map is injected AND the active
environment is allowlisted. With ``override_map=None`` the resolver is byte-for-byte the
pre-G6-7-7 static lookup: it never reads the environment and never returns a probe
target. This pins both the "no probe in the production map" invariant and the
"override is opt-in" gate so a future edit cannot quietly ship a probe redirect.
"""

from __future__ import annotations

import pytest

from alfred.config._environment_loader import (
    EnvironmentLoadResult,
    EnvironmentSource,
)
from alfred.gateway.adapter_child_factory import (
    _ADAPTER_LAUNCH_TARGETS,
    _resolve_launch_target,
)

_PROBE_TOKENS = ("probe", "discord_probe")


def test_production_map_has_no_probe_entry() -> None:
    for adapter_id, (plugin_id, module) in _ADAPTER_LAUNCH_TARGETS.items():
        haystack = f"{adapter_id} {plugin_id} {module}".lower()
        for token in _PROBE_TOKENS:
            assert token not in haystack, (
                f"production launch map names a probe target via {token!r}: "
                f"{adapter_id!r} -> ({plugin_id!r}, {module!r})"
            )


def test_no_override_map_never_reads_env_or_returns_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the resolver consulted the environment on the no-override path it could be
    # tricked into a probe redirect; assert it never reads it. A patched loader that
    # FAILS LOUDLY proves the path stays env-free even in a development environment.
    def _exploding_resolve_environment(**_kwargs: object) -> EnvironmentLoadResult:
        raise AssertionError("resolve_environment consulted on the no-override path")

    monkeypatch.setattr(
        "alfred.gateway.adapter_child_factory.resolve_environment",
        _exploding_resolve_environment,
    )

    target = _resolve_launch_target("discord", override_map=None)

    assert target == _ADAPTER_LAUNCH_TARGETS["discord"]
    for token in _PROBE_TOKENS:
        assert token not in " ".join(target).lower()


def test_override_consulted_only_when_injected_and_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = {"discord": ("alfred.discord_probe", "alfred.gateway.discord_probe")}

    def _dev_resolve_environment(**_kwargs: object) -> EnvironmentLoadResult:
        return EnvironmentLoadResult(value="development", source=EnvironmentSource.ENV_VAR)

    monkeypatch.setattr(
        "alfred.gateway.adapter_child_factory.resolve_environment",
        _dev_resolve_environment,
    )

    # Injected + allowlisted -> the probe is consulted and wins.
    assert _resolve_launch_target("discord", override_map=probe) == (
        "alfred.discord_probe",
        "alfred.gateway.discord_probe",
    )
    # Not injected -> the production default, even in the same allowlisted env.
    assert (
        _resolve_launch_target("discord", override_map=None) == (_ADAPTER_LAUNCH_TARGETS["discord"])
    )
