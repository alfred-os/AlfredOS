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

from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field


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

    operator_user_id: str | None = Field(
        default=None,
        description=(
            "Canonical user id of the operator who queued the proposal. "
            "PR-S3-7 wires the IdentityResolver; until then the field "
            "is None on every emit site."
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


class PluginRevokeProposal(StateGitProposalPayload):
    """Reviewer-gated revocation proposal — drops every grant against ``plugin_id``.

    The revoke side is intentionally non-tier-scoped: spec §11.2's
    ``alfred plugin revoke <id>`` targets the plugin in its entirety,
    not a single (tier, hookpoint) pair. A future scoped-revoke surface
    would land a sibling model rather than reusing this shape.
    """

    proposal_type: ClassVar[str] = "policy-revoke"

    plugin_id: str


class WebAllowlistProposal(StateGitProposalPayload):
    """Reviewer-gated web-fetch allowlist mutation.

    ``action`` is the closed Literal ``"add" | "remove"`` so a future
    third value can land only via a typed update — not by a CLI typo.
    ``path_prefix`` defaults to ``"/"`` matching the spec §7.4
    normalisation rule (an unspecified prefix scopes the entry to every
    path under the domain).
    """

    # Two on-disk types share this model — ``web-allowlist-add`` and
    # ``web-allowlist-remove``. The base ClassVar carries the prefix
    # ``"web-allowlist"``; the writer composes the full type tag from
    # ``proposal_type`` + the ``action`` field so the branch name reads
    # naturally (``proposal/web-allowlist-add-<hex>``).
    proposal_type: ClassVar[str] = "web-allowlist"

    action: Literal["add", "remove"]
    domain: str
    path_prefix: str = "/"


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


__all__ = [
    "ConfigSetProposal",
    "PluginGrantProposal",
    "PluginRevokeProposal",
    "StateGitProposalPayload",
    "WebAllowlistProposal",
]
