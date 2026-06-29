"""AlfredOS configuration loading via pydantic-settings.

Loads from environment variables prefixed with ALFRED_. A `.env` file in the
working directory is read automatically. Secrets are wrapped in `SecretStr` so
they never leak into logs by accident.
"""

from __future__ import annotations

import re
from contextvars import ContextVar
from pathlib import Path
from typing import Literal

from pydantic import Field, PostgresDsn, PrivateAttr, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from alfred.config._environment_loader import EnvironmentLoadResult, load_environment

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

# arch-002 / core-eng-pr222-2 / reviewer TOCTOU fix (#174): the dual-source
# environment loader must run EXACTLY ONCE per ``Settings()`` construction.
# ``extra="ignore"`` drops any stash key from the raw input dict before the
# ``mode='after'`` validator runs, so the ``mode='before'`` validator cannot
# hand the result over through the model. Threading it through a ContextVar
# lets the single ``load_environment()`` call in ``_resolve_environment`` be
# read by ``_capture_environment_load_result`` without a second disk read —
# closing the within-construction TOCTOU window where a mid-construction
# change to ALFRED_ENVIRONMENT / /etc/alfred/environment could make the
# audited result disagree with the validated field.
_ENVIRONMENT_LOAD_RESULT: ContextVar[EnvironmentLoadResult | None] = ContextVar(
    "_alfred_environment_load_result",
    default=None,
)


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

    # Deployment classification (spec §7.3 #174). Mandatory, dual-sourced:
    # env var ALFRED_ENVIRONMENT wins; /etc/alfred/environment is the
    # fallback; disagreement is audited by the daemon CLI and the env-var
    # value wins; neither set → the field stays absent and Pydantic's
    # required-field error fires (translated to SettingsError by __init__).
    # The ``_resolve_environment`` model-validator below populates the
    # field from the dual-source loader when it is not passed explicitly.
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

    # arch-002 closure (#174): the dual-source environment lookup result —
    # env-var value, file value, conflict flag — that the daemon CLI needs
    # to emit the ``daemon.boot.environment_source_conflict`` audit row.
    # Held as a PrivateAttr (NOT a model field) so the validated model
    # surface stays clean and serialization never carries it — no Pydantic
    # data-smuggling. ``None`` when ``environment`` was passed explicitly
    # (the dual-source loader was bypassed).
    _environment_load_result: EnvironmentLoadResult | None = PrivateAttr(default=None)

    @model_validator(mode="before")
    @classmethod
    def _resolve_environment(cls, data: object) -> object:
        """Populate ``environment`` from env-var > /etc/alfred/environment.

        Pydantic v2 model-validator (``mode='before'``) runs against the
        raw kwargs dict — when ``environment`` is missing we fall back to
        the dual-source loader. When the loader returns ``None`` we leave
        the field absent and let Pydantic's normal "missing required
        field" error fire, which ``Settings.__init__``'s ``SettingsError``
        adapter translates to the operator-facing message.

        The resolved :class:`EnvironmentLoadResult` is threaded to
        :meth:`_capture_environment_load_result` (``mode='after'``) via the
        ``_ENVIRONMENT_LOAD_RESULT`` ContextVar so the loader runs exactly
        once and the validated model surface never carries it (arch-002).
        """
        # Reset the per-construction side channel up front so a previous
        # construction's result never leaks into this one (the after-
        # validator may not run if validation fails).
        _ENVIRONMENT_LOAD_RESULT.set(None)
        if not isinstance(data, dict):
            return data
        # ``environment`` may already be present because pydantic-settings
        # populates it directly from ``ALFRED_ENVIRONMENT`` (env_prefix).
        # Run the dual-source loader EXACTLY ONCE here regardless, so the
        # conflict audit result is captured even when the field was sourced
        # by pydantic-settings (core-eng-pr222-2 point b), and inject the
        # value only when it is otherwise absent. The single result is
        # threaded to the after-validator via the ContextVar — no second
        # disk read, no TOCTOU window.
        loaded = load_environment()
        _ENVIRONMENT_LOAD_RESULT.set(loaded)
        if "environment" not in data:
            if loaded.value is not None:
                data["environment"] = loaded.value
        elif isinstance(data["environment"], str):
            # CR #7: pydantic-settings populates ``environment`` directly from
            # the RAW ``ALFRED_ENVIRONMENT`` value, bypassing the loader's
            # stripping. Normalize it here the SAME way the dual-source loader
            # strips both of its sources, so ``ALFRED_ENVIRONMENT=" production"``
            # validates exactly as the bare value (and matches the load result
            # the after-validator compares against). Leaves a non-str explicit
            # kwarg untouched.
            data["environment"] = data["environment"].strip()
        return data

    @model_validator(mode="after")
    def _capture_environment_load_result(self) -> Settings:
        """Lift the single load result onto the private attribute.

        ``mode='before'`` cannot set a :class:`PrivateAttr` (the instance
        does not exist yet); ``mode='after'`` reads the ContextVar the
        ``before`` validator populated from its single ``load_environment()``
        call. No second disk read — the audited result provably matches the
        value chosen above (reviewer / core-eng-pr222-2 TOCTOU fix). The
        ContextVar is ``None`` when ``environment`` was passed explicitly
        (the loader was bypassed), leaving the attribute ``None``.
        """
        loaded = _ENVIRONMENT_LOAD_RESULT.get()
        if loaded is not None and loaded.value == self.environment:
            self._environment_load_result = loaded
        return self

    @property
    def environment_load_result(self) -> EnvironmentLoadResult | None:
        """The dual-source environment lookup result, or ``None``.

        ``None`` when ``environment`` was supplied explicitly (the loader
        was bypassed) — e.g. unit tests constructing ``Settings(environment
        ="test")``. The daemon CLI reads this to emit the source-conflict
        audit row (arch-002 closure).
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
