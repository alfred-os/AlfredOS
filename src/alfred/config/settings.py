"""AlfredOS configuration loading via pydantic-settings.

Loads from environment variables prefixed with ALFRED_. A `.env` file in the
working directory is read automatically. Secrets are wrapped in `SecretStr` so
they never leak into logs by accident.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    PostgresDsn,
    PrivateAttr,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from alfred.config._environment_loader import EnvironmentLoadResult, resolve_environment

# The literal placeholder shipped in .env.example. Rejected in both the setup
# script (bin/alfred-setup.sh) and the Settings validator below so an operator
# who skipped editing .env hits a friendly error before any provider call.
_PLACEHOLDER_API_KEY = "sk-..."

# Charset a comms-adapter id may use. Pinned tight so an id can never encode a
# multi-segment path traversal (``/``) or a shell-meaningful character before it
# is joined onto the ``plugins/<id>/manifest.toml`` probe path below. The charset
# alone still admits the bare ``.`` / ``..`` single-segment probes, so the
# validator rejects those explicitly (FIX 3) and asserts the resolved manifest
# path stays under ``plugins/``.
_COMMS_ADAPTER_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Repo root, resolved from this module's location (``src/alfred/config/``). The
# comms-adapter manifest probe joins ``plugins/<id>/manifest.toml`` onto it. We
# do NOT import ``alfred.cli._launcher_spawn.repo_root`` here: Settings loads
# very early in boot and pulling the CLI package into its import closure risks a
# cycle. The path arithmetic is identical (both modules live three levels under
# the repo root).
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _environment_keys(settings_cls: type[BaseSettings]) -> tuple[str, ...]:
    """Keys the ``_Without`` source filter must pop for the ``environment`` field.

    core-plan-09: the env/dotenv/secrets-file sources key a field by its FIELD
    NAME (``"environment"``), not by the env-prefixed form (``ALFRED_ENVIRONMENT``)
    — pydantic-settings strips the prefix before the merged dict ever reaches a
    ``model_validator``. Adding an env-prefixed key here would be dead code (verified
    via live repro: only the bare field name and any explicit ``validation_alias``
    ever appear as a key in a source's ``__call__()`` output).
    """
    field = settings_cls.model_fields["environment"]
    keys = {"environment"}
    # The ``environment`` field sets no ``validation_alias`` today, so this branch is
    # genuinely unreachable under the current field definition — forward-proofing per
    # #469 Task 2 ambiguity resolution (b), not dead code left uncovered by oversight.
    if isinstance(field.validation_alias, str):  # pragma: no cover
        keys.add(field.validation_alias)
    return tuple(keys)


class _Without(PydanticBaseSettingsSource):
    """Wraps a settings source, popping ``environment`` (+ alias) from its output.

    #469 Blocker 1: before this filter, pydantic-settings' own env/dotenv/secrets-file
    sources could populate ``environment`` directly (e.g. a stray ``.env`` in the
    working directory), bypassing ``resolve_environment()``'s three-layer precedence
    and conflict-audit logic entirely — a stray lower-priority source could silently
    downgrade a production deployment. Wrapping every non-init source in this filter
    makes the ``mode="wrap"`` ``_resolve_environment`` validator the ONLY path that can
    ever set the field: pydantic itself can never source it.
    """

    def __init__(self, inner: PydanticBaseSettingsSource, keys: tuple[str, ...]) -> None:
        super().__init__(inner.settings_cls)
        self._inner = inner
        self._keys = keys
        # I-2 (final-review): pydantic-settings keys its per-source `states` dict by
        # `source.__name__ if hasattr(source, "__name__") else type(source).__name__`
        # (pydantic_settings/main.py:469, 2.14.2). Without this, all three `_Without`
        # wrappers share the class name `"_Without"` and collide under ONE state-dict
        # key — the opposite of "forwards the per-source state protocol faithfully"
        # (ADR-0053 §6). Adopting the WRAPPED source's own name (matching the stock
        # `EnvSettingsSource` / `DotEnvSettingsSource` / `SecretsSettingsSource` keys)
        # keeps each wrapper's entry distinct, exactly as if `_Without` were not there.
        self.__name__ = getattr(inner, "__name__", type(inner).__name__)

    def _set_current_state(self, state: dict[str, Any]) -> None:
        # Forward pydantic-settings' per-source state protocol (2.14.x) to the
        # wrapped source unchanged — the wrapped source still needs to see what
        # higher-priority sources already resolved.
        self._inner._set_current_state(state)

    def _set_settings_sources_data(self, states: dict[str, dict[str, Any]]) -> None:
        self._inner._set_settings_sources_data(states)

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        """Abstract on the base class; never invoked — ``__call__`` is overridden below."""
        raise NotImplementedError  # pragma: no cover

    def __call__(self) -> dict[str, Any]:
        data = dict(self._inner())
        for key in self._keys:
            data.pop(key, None)
        return data


class SettingsError(ValueError):
    """Raised when Settings fail to load with a usable, operator-facing message.

    The CLI catches this and prints a friendly hint (`hint.copy_env_example`) instead
    of the pydantic ValidationError stack trace that would otherwise greet the first-time
    user. See `src/alfred/cli/main.py` for the catch site.
    """


class Settings(BaseSettings):
    """Top-level AlfredOS settings."""

    model_config = SettingsConfigDict(
        env_prefix="ALFRED_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Deployment classification (PRD §7.1, ADR-0053 #174/#469). Mandatory,
    # three-layer: env var ALFRED_ENVIRONMENT wins; /etc/alfred/environment is
    # the fallback; .env is the lowest gap-fill layer; disagreement between the
    # env var and /etc is audited by the daemon CLI and the env-var value
    # wins; neither set → the field stays absent and Pydantic's
    # required-field error fires (translated to SettingsError by
    # __init__). #469 Blocker 1: ``settings_customise_sources`` below strips
    # ``environment`` out of every non-init source, so pydantic itself can
    # NEVER populate this field — the ``mode="wrap"`` ``_resolve_environment``
    # validator is the ONLY path that sets it, via ``resolve_environment()``.
    environment: Literal["development", "production", "test"]

    # Provider config
    deepseek_api_key: SecretStr
    deepseek_base_url: str = "https://api.deepseek.com/v1"
    deepseek_model: str = "deepseek-chat"
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    primary_provider: str = "deepseek"
    fallback_provider: str = "anthropic"

    # Spec C / G7-3 (#333, ADR-0042): the core builds provider SDK clients with an
    # httpx proxy pointed at the gateway L7 CONNECT proxy (e.g. "http://alfred-gateway:8889").
    # MANDATORY — the connectivity-free core has no direct-egress fallback: an unset/blank
    # value fails closed at the EgressClient seam (IOPlaneUnavailableError). The field stays
    # optional here (a dumb config holder); the egress seam owns the "None is fatal" invariant.
    egress_proxy_url: str | None = None

    # Spec C / G7-2c (#333): when set, the in-core RelayEgressClient dials the
    # gateway's mode-(b) tool-egress relay at this URL (e.g. "http://alfred-gateway:8890").
    # UNSET => relay client is not constructed; tool egress is unavailable until G7-2.5
    # wires the live web.fetch re-home.  A blank/whitespace value is treated as None.
    egress_relay_url: str | None = None

    # Database
    database_url: PostgresDsn = Field(
        default=PostgresDsn("postgresql+asyncpg://alfred:alfred@localhost:5432/alfred")
    )

    # Redis (rate-limit counters, ContentHandle store, robots cache). The
    # docker-compose stack sets ALFRED_REDIS_URL to the internal service URL
    # (``redis://alfred-redis:6379/0``); the default below targets a local
    # single-host Redis for bare-metal / dev runs. PR-S4-235-1 (#235) promotes
    # this to a Settings field so the daemon's host-owned ContentStore (the
    # SubPayloadPromoter's sub-payload sink) reads from the same auditable config
    # surface as every other setting rather than an ad-hoc os.environ read.
    # Override via ALFRED_REDIS_URL.
    redis_url: str = Field(default="redis://localhost:6379/0")

    # #339 PR4a (blocker 5, #347): the core-side INBOUND-reflection canary token
    # source for web.fetch. The gateway runs the OUTBOUND exfil scan from
    # ALFRED_CANARY_TOKENS; this is the DISTINCT core env for the inbound tripwire
    # (a seeded canary reflected in a fetched RESPONSE body). A NEW env name is
    # needed because ALFRED_CANARY_TOKENS is hard-forbidden on the core container
    # (tests/unit/test_compose_invariants.py). Default () arms the ResponsePolicy
    # canary seam with an empty (no-op) matcher; operators populate it to enable
    # the reflection tripwire. Override via ALFRED_WEB_FETCH_CANARY_TOKENS
    # (comma-separated, blanks skipped). NoDecode: pydantic-settings JSON-decodes a
    # tuple env field BEFORE the mode="before" validator runs, so the comma-split
    # would never execute (and a plain comma list would raise SettingsError at boot)
    # without disabling per-field JSON decoding here.
    web_fetch_canary_tokens: Annotated[tuple[str, ...], NoDecode] = Field(default=())

    # Budget. Both must be > 0 — a zero or negative cap would make every
    # call an automatic refusal (daily_usd) or trivially-bypass-able
    # (per_call_max_usd), which contradicts the operator's intent of having
    # the gate at all. Pydantic raises ValidationError on load, which
    # ``_load_settings_or_die`` translates to a friendly t() message. The
    # complementary ``math.isfinite`` + non-negative guards inside
    # ``BudgetGuard`` cover hand-constructed sub-guards (tests, future
    # personas) that don't go through Settings.
    daily_budget_usd: float = Field(default=1.0, gt=0)
    per_call_max_usd: float = Field(default=0.10, gt=0)

    # Operator (single-user slice 1)
    operator_name: str = "operator"
    operator_language: str = "en-US"  # BCP-47; CLAUDE.md i18n rule #2 (Task 3.5 consumer)

    # PR-B Phase 5: WorkingMemoryPool cap override. ``None`` defers to the
    # pool's default policy (``max(50, active_user_count * 2)`` — see
    # ``alfred.memory.working_pool.WorkingMemoryPool._cap``). Operators can
    # pin a hard cap via ``ALFRED_WORKING_MEMORY_POOL_MAX`` when running on
    # constrained hardware; the ``ge=50`` floor stops single-user installs
    # from thrashing on the very first persona switch (CR finding — enforce
    # the docstring contract at the field level).
    working_memory_pool_max: int | None = Field(default=None, ge=50)

    # PR-S4-8 (#152, perf-003): per-adapter cap on concurrent inbound
    # notification handlers. ``AlfredPluginSession`` allocates one
    # ``asyncio.BoundedSemaphore(value=comms_max_in_flight_notifications)``
    # per session, so adapter A's rate-limit storm cannot starve adapter B
    # (the semaphore is per-session, not process-wide). Higher values trade
    # memory for throughput; back-pressure begins at this cap and flows into
    # the stdio reader's pending queue, then into kernel-pipe back-pressure
    # once the read buffer fills. ``ge=1`` because a zero cap would deadlock
    # every inbound dispatch; ``le=1024`` bounds the worst-case concurrent
    # handler fan-out per adapter. Override via
    # ALFRED_COMMS_MAX_IN_FLIGHT_NOTIFICATIONS.
    comms_max_in_flight_notifications: int = Field(default=32, ge=1, le=1024)

    # PR-S4-11b (#237): the daemon-spawned comms-adapter allowlist. Each entry is
    # an adapter id the daemon launches a comms plugin for at boot. The default
    # ``()`` keeps existing boot byte-for-byte unchanged — the daemon spawns no
    # comms plugin until an operator opts adapters in. The per-entry validator
    # below fails boot LOUDLY on a bad id (bad charset or no real manifest) rather
    # than silently skipping it: a typo'd adapter id that silently does not spawn
    # would leave an operator believing comms is live when it is not. Override via
    # ALFRED_COMMS_ENABLED_ADAPTERS.
    comms_enabled_adapters: tuple[str, ...] = Field(default=())

    # ADR-0021 #171: cadence of the supervisor's _proposal_dispatch_loop.
    # 30 s default — operator-action latency target per ADR-0021
    # §Consequences (Negative). ``gt=0`` because a zero or negative
    # interval would tight-loop or skip-forever; the dispatcher relies
    # on a positive sleep budget to avoid starving the rest of the
    # TaskGroup. Operators can lower for snappier dispatch on a
    # high-volume install via ``ALFRED_PROPOSAL_DISPATCH_INTERVAL_S``;
    # the field threads through Settings rather than an os.environ read
    # so the entire config surface stays auditable from one place.
    proposal_dispatch_interval_s: int = Field(default=30, gt=0)

    # ADR-0021 #174: state.git absolute path. Slice-3 hardcoded
    # /var/lib/alfred/state.git in src/alfred/cli/_state_git.py at the call
    # site; PR-S4-1 promotes it to a Settings field so the daemon boot
    # path and the operator CLI both read from the same source. Override
    # via ALFRED_STATE_GIT_PATH.
    state_git_path: Path = Field(
        default=Path("/var/lib/alfred/state.git"),
        description="Absolute path to the state.git repository. "
        "Override via ALFRED_STATE_GIT_PATH.",
    )

    # CR #6 (#174): the daemon boot snapshot-ref probe must NOT resolve
    # ``config/policies.yaml`` relative to the caller's CWD — the daemon's
    # working directory is not guaranteed to be the repo / install root, so
    # a CWD-relative read is fragile and could silently load the wrong file
    # (or refuse a real one). Anchor the policies file deterministically at
    # the documented ``/etc/alfred`` runtime-config root (same root as
    # ``/etc/alfred/environment`` and ``/etc/alfred/secrets.toml``). The
    # daemon CLI threads this into ``probe_snapshot_ref_init(config_path=…)``
    # rather than relying on the probe's CWD-relative default. Override via
    # ALFRED_POLICIES_PATH (e.g. a repo checkout pointing at
    # ``config/policies.yaml`` for local development).
    policies_path: Path = Field(
        default=Path("/etc/alfred/policies.yaml"),
        description="Absolute path to the policies.yaml the daemon loads at "
        "boot. Override via ALFRED_POLICIES_PATH.",
    )

    # #363: completes ADR-0012's layer-3 host-default secrets-file path. The
    # broker's `settings_default` plumbing (`_resolve_secrets_path` /
    # `SecretBroker.__init__`, see src/alfred/security/secrets.py) has existed
    # since Slice 2 and reads exactly this field; until now the field itself
    # was never added, so the layer was permanently dead (`bin/alfred-setup.sh`
    # creates `~/.config/alfred/secrets.toml` on first boot, but nothing read
    # it). See the description below for the deliberate env-var-collision
    # this activation surfaces (Blocker 1 of the #363 security plan review).
    secrets_file: Path = Field(
        default_factory=lambda: Path.home() / ".config/alfred/secrets.toml",
        description=(
            "Host-default secrets.toml path (ADR-0012 layer 3). NOTE: with env_prefix "
            "'ALFRED_', this field ALSO auto-maps from ALFRED_SECRETS_FILE — the same env "
            "var the broker reads directly for its layer-2 override — so ADR-0012 layers 2 "
            "and 3 collapse onto one env var by design (both read the same value). "
            "default_factory yields an absolute path (no '~'), so no expanduser is needed "
            "and the raw Path() the broker applies to ALFRED_SECRETS_FILE stays symmetric."
        ),
    )

    # PR-S4-4 (ADR-0023, #159): the PolicyWatcher mtime-poll cadence.
    policy_poll_interval_seconds: float = Field(
        default=1.0,
        ge=0.5,
        le=10.0,
        description=(
            "Polling interval (seconds) for PolicyWatcher's mtime check. "
            "0.5s is the floor (CPU/disk noise); 10s is the ceiling (operator "
            "patience). The 1s default suffices for operator-edit cadence. "
            "Spec §5.1 / ADR-0023. Override via ALFRED_POLICY_POLL_INTERVAL_SECONDS."
        ),
    )

    # arch-002 closure (#174): the three-layer environment lookup result —
    # value, source, conflict flag, conflicting /etc value, unrecognised raw
    # value — captured for any IN-PROCESS reader of ``environment_load_result``
    # below (ADR-0053). M-1 (final-review): the daemon CLI does NOT read this
    # property — ``_load_settings_or_die`` calls ``resolve_environment()``
    # itself and passes the result explicitly into ``Settings(environment=...)``,
    # so this PrivateAttr stays ``None`` on that path (see the property's own
    # docstring below) and the daemon emits its
    # ``daemon.boot.environment_source_conflict`` row from ITS OWN
    # ``EnvironmentLoadResult``, never from here. Held as a PrivateAttr (NOT a
    # model field) so the validated model surface stays clean and serialization
    # never carries it — no Pydantic data-smuggling. ``None`` when
    # ``environment`` was passed explicitly (the three-layer loader was
    # bypassed) — which is EVERY daemon-boot construction of ``Settings``.
    _environment_load_result: EnvironmentLoadResult | None = PrivateAttr(default=None)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Strip ``environment`` out of every non-init source (#469 Blocker 1).

        ``init_settings`` (explicit constructor kwargs — ``Settings(environment=...)``,
        used by tests and by any caller that has already resolved the value itself) is
        the ONLY source left untouched. Every other source — ``ALFRED_ENVIRONMENT``,
        ``.env``, the secrets file — has ``environment`` popped from its output by
        :class:`_Without`, so pydantic itself can never populate the field from any of
        them: :meth:`_resolve_environment` below, via ``resolve_environment()``, is the
        ONLY remaining path. Without this, a stray ``.env`` (or a misconfigured secrets
        file) could silently source ``environment`` directly through pydantic's own
        machinery, bypassing the three-layer loader's env-var > /etc > .env
        precedence and conflict-audit logic entirely — the security downgrade
        this closes.
        """
        keys = _environment_keys(settings_cls)
        return (
            init_settings,
            _Without(env_settings, keys),
            _Without(dotenv_settings, keys),
            _Without(file_secret_settings, keys),
        )

    @model_validator(mode="wrap")
    @classmethod
    def _resolve_environment(
        cls, data: Any, handler: ModelWrapValidatorHandler[Settings]
    ) -> Settings:
        """Populate ``environment`` from the three-layer loader when it is absent.

        A single ``mode="wrap"`` validator replaces the old before/after pair +
        ContextVar hand-off (#469 Blocker 1): ``settings_customise_sources`` above
        guarantees ``environment`` can be present in ``data`` ONLY via an explicit
        constructor kwarg (never sourced by pydantic from env/dotenv/secrets), so
        there is exactly one decision to make — inject if absent — and one capture
        to do afterwards, both in one place with no side channel needed.

        When ``environment`` is present (an explicit kwarg), the three-layer loader
        is bypassed entirely: ``resolve_environment()`` is not called, and
        ``environment_load_result`` stays ``None`` (the loader was never consulted,
        so there is nothing to audit). When absent, ``resolve_environment()`` runs
        exactly once; a resolved value is injected into ``data`` before ``handler``
        runs the rest of validation. If the loader resolves no value, ``environment``
        stays absent and Pydantic's normal "missing required field" error fires,
        which ``Settings.__init__``'s ``SettingsError`` adapter translates to the
        operator-facing message.

        The result is compared against the validated ``instance.environment`` before
        being stored on the private attribute — belt-and-braces: the loader and the
        Literal field both validate against the same value set, so they cannot
        disagree today, but the check keeps the private attribute provably in sync
        with what was actually validated rather than trusting the pre-validation value
        blindly.
        """
        result: EnvironmentLoadResult | None = None
        if isinstance(data, dict) and "environment" not in data:
            result = resolve_environment()
            if result.value is not None:
                data = {**data, "environment": result.value}
        instance = handler(data)
        if result is not None and result.value == instance.environment:
            instance._environment_load_result = result
        return instance

    @property
    def environment_load_result(self) -> EnvironmentLoadResult | None:
        """The three-layer environment lookup result, or ``None``.

        ``None`` when ``environment`` was supplied explicitly (the loader
        was bypassed) — e.g. unit tests constructing ``Settings(environment
        ="test")``. M-1 (final-review): this is ALWAYS ``None`` on the daemon
        boot path — the daemon CLI (``_load_settings_or_die`` in
        ``cli/daemon/_commands.py``) resolves the environment itself via
        ``resolve_environment()`` and passes it explicitly as
        ``Settings(environment=result.value)``, emitting the
        ``daemon.boot.environment_source_conflict`` audit row from that
        directly-held result, never from this property. This property has no
        production reader today; it exists for any FUTURE in-process caller
        that constructs ``Settings()`` without pre-resolving the environment
        itself and wants to know which source won.
        """
        return self._environment_load_result

    @field_validator("comms_enabled_adapters")
    @classmethod
    def _validate_comms_enabled_adapters(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject any adapter id that is mis-charset, traversal-shaped, or has no real manifest.

        Each entry must match :data:`_COMMS_ADAPTER_ID_RE` (so a multi-segment
        path-traversal-shaped id never reaches the filesystem probe), must NOT be
        the single-segment ``.`` / ``..`` traversal probes (FIX 3), must resolve
        to a manifest path UNDER ``plugins/``, AND name a real
        ``plugins/<id>/manifest.toml``. A bad entry raises ``ValueError`` —
        :meth:`Settings.__init__` lifts it to :class:`SettingsError`, so boot
        fails loudly instead of silently dropping an adapter the operator
        believes is enabled (CLAUDE.md hard rule #7). The message stays raw
        English (no ``t()``): Settings loads too early in boot to depend on the
        translator, matching ``_reject_placeholder_key``.
        """
        plugins_root = (_REPO_ROOT / "plugins").resolve()
        for adapter_id in value:
            if not _COMMS_ADAPTER_ID_RE.match(adapter_id):
                raise ValueError(f"invalid comms adapter id {adapter_id!r}")
            # FIX 3 (defence in depth): ``.`` and ``..`` are charset-clean under
            # _COMMS_ADAPTER_ID_RE but are single-segment path-traversal probes
            # (``.`` → ``plugins/manifest.toml``, ``..`` → escapes ``plugins/``).
            # ``/`` is already blocked so they are capped, but ``is_file()``
            # follows symlinks; refuse them explicitly rather than relying on the
            # escape target not existing.
            if adapter_id in {".", ".."}:
                raise ValueError(f"invalid comms adapter id {adapter_id!r}")
            manifest_path = _REPO_ROOT / "plugins" / adapter_id / "manifest.toml"
            # Belt-and-braces containment: the resolved manifest path must stay
            # under ``plugins/``. A traversal that slips past the charset/segment
            # guards (e.g. a future loosened regex) is refused here before the
            # filesystem probe trusts it.
            if not manifest_path.resolve().is_relative_to(plugins_root):
                raise ValueError(f"invalid comms adapter id {adapter_id!r}")
            if not manifest_path.is_file():
                raise ValueError(f"no manifest for comms adapter id {adapter_id!r}")
        return value

    @field_validator("egress_proxy_url", mode="before")
    @classmethod
    def _normalize_egress_proxy_url(cls, value: object) -> object:
        """Treat a blank/whitespace ``ALFRED_EGRESS_PROXY_URL`` as unset (None).

        Without this, ``ALFRED_EGRESS_PROXY_URL=`` (a common .env typo) would
        deserialize to ``""`` — a non-None string that forces the proxied path with
        an empty proxy URL, silently breaking egress. Normalizing blank to None makes
        an empty value fail closed identically to unset at the EgressClient seam
        (IOPlaneUnavailableError — Spec C G7-3, ADR-0042; there is no direct fallback).
        """
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @field_validator("egress_relay_url", mode="before")
    @classmethod
    def _normalize_egress_relay_url(cls, value: object) -> object:
        """Treat a blank/whitespace ``ALFRED_EGRESS_RELAY_URL`` as unset (None).

        Mirrors ``_normalize_egress_proxy_url``: a bare ``ALFRED_EGRESS_RELAY_URL=``
        in .env must not silently construct a RelayEgressClient with an empty URL
        (which would crash on the first dial with a confusing socket error). Spec C
        G7-2c — the relay URL is optional; None means "relay client not wired".
        """
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @field_validator("web_fetch_canary_tokens", mode="before")
    @classmethod
    def _normalize_web_fetch_canary_tokens(cls, value: object) -> object:
        """Parse ALFRED_WEB_FETCH_CANARY_TOKENS as a comma-separated token list.

        Mirrors the gateway's ``resolve_canary_tokens`` split (comma-separated,
        blanks skipped) so operators use ONE token format across the core inbound
        source and the gateway outbound scanner. Blank/whitespace → ``()`` (seam
        armed but empty = no-op matcher). A tuple/list (direct construction) passes
        through.
        """
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("deepseek_api_key")
    @classmethod
    def _reject_placeholder_key(cls, v: SecretStr) -> SecretStr:
        """Reject the literal placeholder shipped in .env.example.

        Belt-and-braces complement to the equivalent guard in
        ``bin/alfred-setup.sh`` (DEVEX-001 on PR #89). The setup script catches
        the typical first-run mistake; this validator catches every other path
        — direct ``docker compose run``, CI bootstrap that forgot to override
        the env, an operator who edited ``docker-compose.yaml`` directly. The
        message stays raw English here (no ``t()`` import — Settings is loaded
        too early in the boot to depend on the translator); the CLI catch site
        in ``_load_settings_or_die`` reroutes through
        ``t("error.placeholder_api_key")`` before printing.
        """
        if v.get_secret_value() == _PLACEHOLDER_API_KEY:
            raise ValueError("placeholder_api_key")
        return v

    def __init__(self, **kw):  # type: ignore[no-untyped-def]
        try:
            super().__init__(**kw)
        except Exception as exc:
            # Translate pydantic ValidationError into a SettingsError the CLI can render.
            raise SettingsError(str(exc)) from exc
