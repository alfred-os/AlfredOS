"""Typed proposal payloads written into state.git via the reviewer-gate flow.

ADR-0018 — replaces the previous ``dict[str, object]`` payload surface
that ``StateGitProposalClient.create_proposal`` accepted. A typo at the
dispatcher (``subscribe_tier`` vs ``subscriber_tier``) used to land in
the proposal branch as-is and either get silently dropped by the
projection downstream or break the audit-graph join. With the typed
models the typo becomes a Pydantic :class:`ValidationError` at the
emit site instead.

Why a dedicated package (``alfred.state``) rather than placing the
models under ``alfred.cli._state_git`` or
``alfred.security.capability_gate.proposals``: both subsystems
consume the models. Anchoring the package under either would introduce
a reverse-direction import — the CLI imports from security, or the
security module imports from the CLI. Carrying the models in their own
neutral package keeps the dependency arrows pointing one way.

Hard rules honoured here:

* **No raw secret values in payloads (CLAUDE.md rule #6).** Every field
  is either an identifier, a closed-set enum, or a structured policy
  knob. Provider names, plugin ids, hookpoint names, and the config
  value pass through; secret material never does. The reviewer reads
  the payload and must be able to make the approve/reject decision
  without ever seeing key material.
* **Strict, frozen, extra='forbid' (CLAUDE.md SOLID + immutability rules).**
  Every model is ``frozen=True, extra='forbid', strict=True`` so:

    * a refactor cannot mutate the model post-construction (forensic
      log lines would otherwise drift from the on-disk payload);
    * an unknown field is rejected at the wire boundary rather than
      silently smuggled past;
    * an int-as-string at the dispatcher fails Pydantic validation
      instead of silently coercing.

* **Two-axis naming (ADR-0017 Decision 3).** ``subscriber_tier`` is
  the field name; ``content_tier`` is the trust-axis name; the two
  never alias. A typo on either side is a :class:`ValidationError`.
"""

from __future__ import annotations

import re
from typing import Annotated, ClassVar, Final, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

# CR-149 round-10 (3339361798): canonical field-shape patterns for the
# proposal payloads. Mirrored from ``alfred.cli._validators`` so a
# non-CLI producer (a future async writer, a state.git replay tool, a
# malformed test fixture) gets the same parse-time refusal semantics
# the CLI applies — without introducing a reverse-direction import
# from this neutral package back into ``alfred.cli``. The two sources
# are pinned in lockstep by the closed-set tests in
# :mod:`tests.unit.state.test_proposal_payloads` (paste-drift guard).
#
# * ``_PLUGIN_ID_PATTERN`` — dotted-lowercase identifier, every segment
#   begins with a letter and ends with an alphanumeric. Matches the
#   shape of every first-party plugin id today
#   (``alfred.web-fetch``, ``alfred_comms_test``).
# * ``_HOOKPOINT_PATTERN`` — dotted segments OR a single ``*`` wildcard.
#   The wildcard form anchors a plugin-load grant (every hookpoint);
#   the dotted form names a specific publisher boundary.
# * ``_DOMAIN_PATTERN`` — bare lowercase domain shape. Per-label rules
#   (RFC 1035 §2.3.1) are enforced via :data:`_DOMAIN_LABEL_PATTERN`.
_PLUGIN_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z](?:[a-z0-9_-]*[a-z0-9])?)*$"
)
# Hookpoint segments accept upper- and lower-case letters and digits in
# the body so production names like ``t3.downgrade_to_orchestrator`` and
# tier-tagged fixtures like ``tag.T3`` (the content-tier tag hookpoint
# used by the capability-gate round-trip suite) both pass. The shape
# stays restrictive enough to refuse path traversal (``..``), path
# separators (``/``), and whitespace — the load-bearing failure modes
# the closed-shape check exists to surface.
_HOOKPOINT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:\*|[A-Za-z](?:[A-Za-z0-9_-]*[A-Za-z0-9])?(?:\.[A-Za-z](?:[A-Za-z0-9_-]*[A-Za-z0-9])?)*)$"
)
_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
_DOMAIN_LABEL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _check_plugin_id(value: str) -> str:
    """Refuse plugin ids that do not match the dotted-lowercase shape.

    Mirrors :func:`alfred.cli._validators.validate_plugin_id` at the
    Pydantic-model boundary so a non-CLI producer that constructs a
    proposal payload directly cannot smuggle a malformed plugin_id
    (path traversal, uppercase, trailing separator) past the writer.
    """
    if not _PLUGIN_ID_PATTERN.fullmatch(value):
        msg = f"plugin_id {value!r} is not a valid dotted-lowercase identifier"
        raise ValueError(msg)
    return value


def _check_hookpoint(value: str) -> str:
    """Refuse hookpoints that are not a dotted name or the ``*`` wildcard.

    The closed shape pins the on-disk projection: a downstream consumer
    can split on ``.`` and route per-segment without first sanitising
    the value. Per-segment grammar accepts mixed casing + digits so the
    content-tier tag hookpoints (``tag.T3``) and the
    snake_case publisher names (``t3.downgrade_to_orchestrator``) both
    pass alongside the canonical lowercase tool hookpoints.
    """
    if not _HOOKPOINT_PATTERN.fullmatch(value):
        msg = (
            f"hookpoint {value!r} must be a dotted-segment name (letters / "
            "digits / underscores / hyphens, no path separators or whitespace) "
            "or the '*' wildcard"
        )
        raise ValueError(msg)
    return value


def _check_domain(value: str) -> str:
    """Refuse domains that look like URLs or include path traversal shapes.

    Mirrors :func:`alfred.cli._validators.validate_domain` minus the
    Typer-specific localised error messages — the model-layer refusal
    surfaces as a :class:`pydantic.ValidationError`.
    """
    if not value:
        msg = "domain must be a non-empty bare hostname"
        raise ValueError(msg)
    if ".." in value or "/" in value or "\\" in value:
        msg = f"domain {value!r} must not include path separators or traversal"
        raise ValueError(msg)
    if not _DOMAIN_PATTERN.fullmatch(value):
        msg = f"domain {value!r} is not a valid bare lowercase hostname"
        raise ValueError(msg)
    labels = value.split(".")
    if not all(_DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels):
        msg = f"domain {value!r} contains an invalid label per RFC 1035 §2.3.1"
        raise ValueError(msg)
    return value


# Closed set: providers the quarantined-LLM config knob may name. Mirrors
# :data:`alfred.cli._validators._ALLOWED_QUARANTINED_PROVIDERS`; the
# closed-set test in :mod:`tests.unit.state.test_proposal_payloads` pins
# the two sources in lockstep so a new provider lands by widening both
# constants in one commit.
_ALLOWED_QUARANTINED_PROVIDERS: Final[frozenset[str]] = frozenset({"anthropic", "deepseek"})


def _check_quarantined_provider(value: str) -> str:
    """Refuse provider ids outside the closed set.

    Mirrors :func:`alfred.cli._validators.validate_quarantined_provider`
    at the Pydantic-model boundary so a non-CLI producer cannot smuggle
    a non-declared provider id into ``ConfigSetProposal.value`` when
    ``config_key="quarantined-provider"``.
    """
    if value not in _ALLOWED_QUARANTINED_PROVIDERS:
        msg = (
            f"quarantined-provider {value!r} is not in the declared set "
            f"({sorted(_ALLOWED_QUARANTINED_PROVIDERS)})"
        )
        raise ValueError(msg)
    return value


class StateGitProposalPayload(BaseModel):
    """Base class for every state.git proposal payload.

    Carries the discriminator (``proposal_type``) used by the canonical
    writer to derive both the branch-name prefix and the on-disk
    layout. Subclasses MUST declare a ``proposal_type`` ClassVar; the
    writer reads it via ``type(payload).proposal_type`` rather than
    inspecting a field so the discriminator stays a class-level
    invariant and cannot drift between branches of the same type.

    ``operator_user_id`` is the only field shared across every
    subclass. PR-S3-7 wires the IdentityResolver; until then the field
    carries ``None``. The structlog redactor never sees this value
    (PII-discipline cross-reference: ``_write_proposal_to_state_git``'s
    ``operator_user_id_len`` log line in the legacy stub); the canonical
    audit-row family is the sole readout site.

    The field is bounded to 64 characters (matches the
    ``PluginGrant.operator_user_id`` / ``AuditEntry.actor_user_id``
    schema width) so an oversized payload cannot land in state.git
    and DoS the dispatcher by hitting the ledger's String(64) limit at
    write time — CR rework round-1 CRITICAL #4 hardens this at the
    Pydantic boundary so the proposal-write surface refuses early.
    """

    # Configured once on the base so every subclass inherits the same
    # discipline. Subclasses MUST NOT override this — the writer relies
    # on the invariants for byte-equality semantics.
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    # Subclasses override this ClassVar with a literal string. Used by
    # :meth:`StateGitProposalClient.create_proposal` to derive the
    # branch-name prefix and the on-disk layout selector. Not a model
    # field because the discriminator must be stable across every
    # instance of the subclass — a field would let a caller pass a
    # mismatched value.
    proposal_type: ClassVar[str]

    operator_user_id: Annotated[str, StringConstraints(max_length=64)] | None = Field(
        default=None,
        description=(
            "Canonical user id of the operator who queued the proposal. "
            "PR-S3-7 wires the IdentityResolver; until then the field "
            "is None on every emit site. Bounded to 64 chars at parse "
            "time so an oversized payload cannot land in state.git "
            "(matches PluginGrant.operator_user_id width)."
        ),
    )


class PluginGrantProposal(StateGitProposalPayload):
    """Reviewer-gated capability-grant proposal.

    Lands on disk at
    ``policies/grants/<plugin_id>/<grant_id>.json`` so the
    :func:`alfred.security.capability_gate._state_git_parser.parse_state_git_head`
    parser re-hydrates it directly on the post-merge rebuild. The
    nested layout (per-plugin directory) groups grants visually for
    operator review without forcing the parser into a single-flat-file
    scan.

    Field semantics:

    * ``plugin_id`` — dotted lowercase identifier (validator in
      :mod:`alfred.cli._validators`). Carried into the directory name
      so an operator inspecting ``policies/grants/`` sees one
      subdirectory per granted plugin.
    * ``subscriber_tier`` — the subscriber-capability axis
      (ADR-0017 Decision 3). NOT a content trust tier; the two axes
      are kept lexically distinct so a refactor cannot conflate them.
    * ``hookpoint`` — dotted action name or ``"*"`` for a wildcard
      plugin-load grant.
    * ``content_tier`` — orthogonal content trust tier
      (T0 / T1 / T2 / T3) or ``None`` for a subscriber-tier-only
      grant. Closed-set Literal so a typo (``"T4"``) fails at the
      dispatcher.
    """

    proposal_type: ClassVar[str] = "policy-grant"

    plugin_id: str
    subscriber_tier: Literal["system", "operator", "user-plugin"]
    hookpoint: str
    content_tier: Literal["T0", "T1", "T2", "T3"] | None = None

    # CR-149 round-10 (3339361798): enforce dotted-lowercase / wildcard
    # shapes at the model boundary so a non-CLI producer cannot land a
    # malformed plugin_id / hookpoint in state.git. Mirrors the closed
    # shapes the CLI validators apply at parse time.
    @field_validator("plugin_id")
    @classmethod
    def _validate_plugin_id(cls, value: str) -> str:
        return _check_plugin_id(value)

    @field_validator("hookpoint")
    @classmethod
    def _validate_hookpoint(cls, value: str) -> str:
        return _check_hookpoint(value)


class PluginRevokeProposal(StateGitProposalPayload):
    """Reviewer-gated revocation proposal — drops every grant against ``plugin_id``.

    The revoke side is intentionally non-tier-scoped: spec §11.2's
    ``alfred plugin revoke <id>`` targets the plugin in its entirety,
    not a single (tier, hookpoint) pair. A future scoped-revoke surface
    would land a sibling model rather than reusing this shape.
    """

    proposal_type: ClassVar[str] = "policy-revoke"

    plugin_id: str

    # CR-149 round-10 (3339361798): mirrors the grant-side refusal so
    # both proposal families share parse-time field-shape semantics.
    @field_validator("plugin_id")
    @classmethod
    def _validate_plugin_id(cls, value: str) -> str:
        return _check_plugin_id(value)


class WebAllowlistProposal(StateGitProposalPayload):
    """Reviewer-gated web-fetch allowlist mutation.

    ``action`` is the closed Literal ``"add" | "remove"`` so a future
    third value can land only via a typed update — not by a CLI typo.

    ``path_prefix`` semantics:

    * On ``action="add"`` the field defaults to ``"/"`` matching the
      spec §7.4 normalisation rule — an unspecified prefix scopes
      the entry to every path under the domain.
    * On ``action="remove"`` the field is ``None`` to encode
      whole-entry deletion. The previous shape left ``path_prefix``
      at its model default (``"/"``), so a reviewer reading the
      proposal saw "remove `/` prefix only" while the parallel
      audit row recorded ``path_prefix=None`` ("remove whole entry"),
      and the downstream merge-side consumer could silently turn a
      whole-entry delete into a root-prefix-only delete (CR-149 +
      spec §11.1 reviewer-gated intent). Making the field nullable
      keeps the payload, the audit row, and the eventual merge
      handler all agreeing on "remove targets the whole entry".

    Validation: when ``action="add"`` the field must be a string
    (``None`` is rejected); when ``action="remove"`` either ``None``
    OR a string is accepted, but the CLI always sends ``None`` so
    the on-disk shape stays uniform across the remove family.
    """

    # Two on-disk types share this model — ``web-allowlist-add`` and
    # ``web-allowlist-remove``. The base ClassVar carries the prefix
    # ``"web-allowlist"``; the writer composes the full type tag from
    # ``proposal_type`` + the ``action`` field so the branch name reads
    # naturally (``proposal/web-allowlist-add-<hex>``).
    proposal_type: ClassVar[str] = "web-allowlist"

    action: Literal["add", "remove"]
    domain: str

    # CR-149 round-10 (3339361798): refuse domains that look like URLs
    # or include path-traversal shapes at the model boundary so a
    # non-CLI producer cannot land a malformed domain in state.git.
    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        return _check_domain(value)

    # CR-149 round-6: the field default is ``None`` so every non-CLI
    # producer (a future async writer, a state.git replay tool, a
    # malformed test fixture) constructs the spec §11.1 canonical
    # whole-entry-delete shape unless it explicitly opts into a
    # per-prefix scope. The previous ``"/"`` default silently turned
    # a ``WebAllowlistProposal(action="remove", domain=...)`` into
    # "remove root-prefix only" — a Spec §11.1 ambiguity that
    # undermined reviewer-gated intent. The
    # :func:`_normalize_path_prefix_for_add` validator below restores
    # the ``"/"`` default for ``action="add"`` so the CLI's add path
    # keeps its previous shape when the operator omits the flag,
    # while ``action="remove"`` defaults to the whole-entry contract.
    path_prefix: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_path_prefix_for_add(cls, values: object) -> object:
        """Coerce omitted ``path_prefix`` to ``"/"`` on the add path.

        CR-149 round-6: paired with the field-default flip above, this
        validator keeps the historical CLI shape (``alfred web
        allowlist add example.com`` ≡ ``--path-prefix /``) while
        ensuring the remove path defaults to whole-entry deletion
        (``path_prefix=None``). The ``mode="before"`` hook only fires
        when the field was OMITTED from the input dict: an explicit
        ``path_prefix=None`` flows through unchanged, so the
        downstream ``_check_action_path_prefix_invariant`` still
        rejects ``action="add", path_prefix=None`` loud-and-clear.

        ``isinstance(values, dict)`` keeps Pydantic's accepted input
        shapes intact — model-from-dict, model-from-kwargs (which
        Pydantic normalises to dict before this hook), model-from-
        existing-instance round-trip (which arrives non-dict and
        already has the field set on the prior instance).
        """
        if (
            isinstance(values, dict)
            and values.get("action") == "add"
            and "path_prefix" not in values
        ):
            return {**values, "path_prefix": "/"}
        return values

    @model_validator(mode="after")
    def _check_action_path_prefix_invariant(self) -> Self:
        """Enforce the ``action``/``path_prefix`` invariant per spec §11.1.

        CR-149 round-3: the docstring already documents the contract
        (``add`` carries a real path-prefix; ``remove`` encodes
        whole-entry deletion via ``None``) but the model previously
        accepted ``action="add", path_prefix=None``. The CLI surface
        defaults ``path_prefix`` to ``"/"`` on the add path so the
        same shape never reached the model, but any non-CLI producer
        (a future async writer, a state.git replay tool, a malformed
        test fixture) could still emit an ambiguous add proposal and
        drift from spec §11.1's add-vs-remove semantics. Failing the
        construction at the model layer closes the boundary so the
        reviewer-side parser never sees the ambiguous shape.

        ``remove`` permits ``path_prefix=None`` (the CLI canonical
        shape for whole-entry deletion) AND a string (legacy
        per-prefix removal). The closed set keeps both shapes valid
        for the remove side while pinning the add side.
        """
        if self.action == "add" and self.path_prefix is None:
            msg = "WebAllowlistProposal: action='add' requires a non-None path_prefix"
            raise ValueError(msg)
        return self


class ConfigSetProposal(StateGitProposalPayload):
    """Reviewer-gated high-blast config-set proposal.

    ``config_key`` is the operator-facing CLI key (``"quarantined-provider"``
    today). The closed-set Literal locks the key set at the typed-payload
    layer so a future high-blast knob lands by widening the Literal in
    one place rather than by spreading a string check across the CLI +
    the writer.

    ``value`` is a free-form string at this layer; the per-key validator
    in :mod:`alfred.cli._validators` runs BEFORE the model is constructed
    so a bad value never reaches state.git.
    """

    # Composed branch type: ``config-<config_key>-<hex>``. Same pattern
    # as :class:`WebAllowlistProposal` — the writer derives the full
    # type tag from ``proposal_type`` + ``config_key``.
    proposal_type: ClassVar[str] = "config"

    config_key: Literal["quarantined-provider"]
    value: str

    # CR-149 round-10 (3339361798): pin the provider value to the
    # declared closed set at the model boundary so a non-CLI producer
    # cannot land an unknown provider id in state.git.
    @field_validator("value")
    @classmethod
    def _validate_value(cls, value: str) -> str:
        return _check_quarantined_provider(value)


class BreakerResetProposal(StateGitProposalPayload):
    """Operator request to reset a circuit breaker (OPEN → CLOSED).

    ADR-0021 — the first user of the side-effecting dispatch
    infrastructure. Reviewer-gated per ADR-0018; the supervisor's
    ``_proposal_dispatch_loop`` picks up the merged branch on its next
    cycle and calls
    :meth:`alfred.state.dispatch_registry.ProposalEffectsProtocol.reset_breaker`.

    The actual state mutation lives in Postgres (``circuit_breakers``);
    this proposal is the operator-intent + reviewer-gate record. It
    does NOT carry the breaker target's prior state — that is the
    runtime's concern at dispatch time, not the proposal payload's.

    On-disk path convention: ``policies/breaker-resets/<proposal_id>.json``.
    The dispatch loop's HEAD-diff walker keys the discriminator off the
    path prefix; drift between this convention and the writer's
    :func:`_on_disk_files_for` branch would silently misroute the
    proposal.

    ``component_id`` semantics: the runtime registry key the supervisor
    uses to look up the breaker (e.g. ``"alfred.web-fetch"``). The
    payload does not validate the shape — the dispatcher's
    ``_handle_breaker_reset`` returns
    :meth:`DispatchOutcome.failed` on
    :class:`alfred.supervisor.errors.NoSuchComponentError` so an
    operator-supplied typo surfaces as a ledger row with
    ``failure_kind="handler_returned_failed"`` rather than a parse
    refusal at proposal-write time. Catching it earlier would force
    the writer to maintain a copy of every registered component id,
    which drifts as plugins load and unload.
    """

    proposal_type: ClassVar[str] = "breaker-reset"

    # CR rework round-1 CRITICAL #4: bound ``component_id`` at the model
    # boundary. ``CircuitBreakerState.component_id`` is String(255), so
    # mirroring that width refuses oversized payloads at parse time
    # rather than at the supervisor's reset_breaker call.
    component_id: Annotated[str, StringConstraints(max_length=255)]

    reason: Literal["operator_initiated"] = "operator_initiated"

    # CR rework round-1 HIGH #16: ``operator_user_id`` is required on
    # the breaker-reset path (the supervisor's
    # :meth:`Supervisor.reset_breaker` signature requires it as a
    # keyword-only ``str`` arg). The base class declares it as
    # ``str | None`` to allow other proposal types to defer the
    # IdentityResolver wiring; the breaker-reset surface tightens that
    # with a model-validator refusal so the on-disk shape always
    # carries a non-empty id. Pyright/mypy keep the field annotation
    # compatible with the base class — the model_validator is the
    # narrowing primitive.
    @model_validator(mode="after")
    def _require_operator_user_id(self) -> Self:
        if not self.operator_user_id:
            msg = (
                "BreakerResetProposal: operator_user_id is required "
                "(empty / None is refused — Supervisor.reset_breaker "
                "needs an attribution string)"
            )
            raise ValueError(msg)
        return self


__all__ = [
    "BreakerResetProposal",
    "ConfigSetProposal",
    "PluginGrantProposal",
    "PluginRevokeProposal",
    "StateGitProposalPayload",
    "WebAllowlistProposal",
]
