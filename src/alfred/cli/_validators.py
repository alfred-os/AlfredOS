"""Closed-set parser-time validators for operator-supplied CLI strings.

sec-pr-s3-6-01 / devex-005. Three reviewer-gated commands accept free-form
operator strings that flow into state.git proposal payloads:

* ``alfred plugin grant <id> <tier> <hookpoint>``
* ``alfred web allowlist {add,remove} <domain>``
* ``alfred config set quarantined-provider <value>``

Without closed-set validation, a typo or maliciously-crafted argument
reaches the proposal branch as-is. The reviewer agent then has to either
notice the bad input or merge it — neither outcome is acceptable when the
boundary is supposed to be parse-time. The validators in this module
refuse the bad input at the Typer parse step (``typer.BadParameter``) so
nothing wedge-shaped ever lands in a proposal payload.

Design constraints honoured here:

* **Single source of truth.** All three sub-apps (``plugin``, ``web``,
  ``config``) import from this module so the regexes, the closed sets
  of allowed providers, and the difflib-suggestion shaping live in one
  place. A future fourth caller (Slice 4+ ``alfred memory ...`` flows)
  picks the validator up for free.
* **Localised error messages.** Every ``BadParameter`` raised through
  this module renders its message via :func:`alfred.i18n.t` — the same
  rule the rest of ``src/alfred/cli`` follows. Untranslated f-strings
  in a parser-error path would silently bypass the i18n catalogue
  (CLAUDE.md i18n rule #1).
* **Closed sets, not allowlists at the type level.** Tier validation
  uses a :class:`enum.StrEnum` rather than ``Literal[...]`` so Typer can
  emit a friendly ``--tier T0|T1|T2|T3`` shape at ``--help`` time and
  the runtime rejection of ``T5`` is a Typer-native ``BadParameter``
  rather than a Pydantic validation traceback.
* **No silent failure.** A rejected input raises loudly and the CLI
  returns exit code 2 (Typer's BadParameter convention). Hard rule #7
  applied at the parser boundary.

Module-level seams the tests patch:

* :data:`_known_hookpoints_provider` — returns the iterable of currently-
  registered hookpoint names. Defaults to the live HookRegistry singleton
  so production callers always validate against the system's actual
  registry. Tests inject a fixed set so they do not depend on whichever
  publisher modules happened to be imported by the test runner.
"""

from __future__ import annotations

import difflib
import re
import urllib.parse
from collections.abc import Callable, Iterable
from enum import StrEnum
from typing import Final

import typer

from alfred.hooks.registry import get_registry
from alfred.i18n import t

# ---------------------------------------------------------------------------
# Plugin id — dotted-lowercase identifier
# ---------------------------------------------------------------------------

# Per-segment shape: every dot-separated segment starts with a
# lowercase letter, must end with a lowercase letter or digit, and may
# carry any of ``a-z0-9._-`` in between. Matches the shape of every
# first-party plugin id shipped in this repo today
# (``alfred.web-fetch``, ``alfred_comms_test``, ``alfred.memory.episodic``).
# Critical refusals at this boundary:
#
# * Path traversal — ``../../../etc/passwd`` contains ``/`` which is outside
#   the allowed character set, so the regex rejects it before the string
#   reaches a proposal payload (or, worse, a future flow that interprets it
#   as a relative path).
# * Uppercase / whitespace — operator-typed plugin ids are case-insensitive
#   in the broader documentation, but the registry normalises to lowercase
#   internally; refusing uppercase at the CLI boundary surfaces the typo
#   immediately rather than after a confusing "no such plugin" message.
# * CR-149 round-3 — empty / leading / trailing dot or separator
#   segments. The previous shape ``^[a-z][a-z0-9._-]+$`` accepted
#   malformed ids like ``alfred.``, ``alfred-``, ``alfred_``, or
#   ``alfred..web-fetch`` that would reach reviewer-gated proposal
#   payloads as-is. The new pattern requires:
#   - every dot-separated segment to start with a lowercase letter,
#   - every segment to end with a lowercase letter or digit (no
#     trailing ``-`` / ``_`` / ``.``),
#   so ``alfred.``, ``alfred-``, ``alfred_``, ``alfred..x``, and ``.x``
#   all fail closed at the CLI boundary per PRD §11.3.
# * Empty plugin id — the head ``[a-z]`` plus the segment grammar
#   require at least one segment.
#
# Segment grammar: ``[a-z](?:[a-z0-9_-]*[a-z0-9])?`` — a single letter,
# OR a letter followed by zero-or-more interior chars and a final
# alphanumeric. Both ``a`` and ``a1`` and ``a-b`` are accepted; ``a-``
# is not.
_PLUGIN_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z](?:[a-z0-9_-]*[a-z0-9])?)*$"
)


def validate_plugin_id(value: str) -> str:
    """Refuse plugin ids that do not match the closed shape.

    Returns the input unchanged on success so callers can chain it through
    Typer's argument pipeline. On failure raises :class:`typer.BadParameter`
    with a localised message — Typer converts this into a clean stderr line
    plus exit code 2, never a Python traceback.
    """
    if not _PLUGIN_ID_PATTERN.fullmatch(value):
        raise typer.BadParameter(
            t("cli.validators.plugin_id_invalid", value=value),
            param_hint="'plugin_id'",
        )
    return value


# ---------------------------------------------------------------------------
# Subscriber tier — system | operator | user-plugin
# ---------------------------------------------------------------------------


class SubscriberTier(StrEnum):
    """Closed set of subscriber-capability tiers for ``plugin grant``.

    Spec §4.3 distinguishes two orthogonal axes:

    * **Subscriber tier** (this enum) — the capability axis. Used by the
      hook registry to decide whether a subscriber may register against
      a given hookpoint and to order chain execution.
    * **Content trust tier** (T0-T3) — the data-tag axis. Lives in
      :class:`alfred.cli.audit._TierChoice`; an audit row's
      ``trust_tier_of_trigger`` is one of those four values.

    Conflating the two would silently accept ``T2`` as a valid subscriber
    tier, and the proposal payload's ``subscriber_tier`` field would land
    in state.git with a value that the reviewer then has to mentally
    untangle. Keeping the enums physically separate prevents the typo at
    the CLI boundary.

    Values mirror :data:`alfred.hooks.registry._TIER_RANK`. A drift
    between the two sites would silently reject ``user-plugin`` at the
    CLI (or, worse, silently accept ``user_plugin`` with an underscore
    that the registry never matches). The membership test in
    :func:`validate_subscriber_tier` is the catch-all so the failure
    mode is loud either way.
    """

    SYSTEM = "system"
    OPERATOR = "operator"
    USER_PLUGIN = "user-plugin"


def validate_subscriber_tier(value: str) -> SubscriberTier:
    """Map an operator-typed string to a :class:`SubscriberTier`.

    Typer maps :class:`StrEnum` Argument annotations to a closed choice
    set in ``--help`` and rejects mismatches at parse time, but the
    declarative pathway requires a different shape (the ``grant`` command
    multiplexes positionals via :class:`typer.Context.args`). Callers that
    pull the tier off ``ctx.args`` invoke this helper directly so the same
    closed-set rejection applies.
    """
    try:
        return SubscriberTier(value)
    except ValueError as exc:
        raise typer.BadParameter(
            t(
                "cli.validators.subscriber_tier_invalid",
                value=value,
                valid_tiers=", ".join(member.value for member in SubscriberTier),
            ),
            param_hint="'subscriber_tier'",
        ) from exc


# ---------------------------------------------------------------------------
# Hookpoint — must be present in the global HookRegistry
# ---------------------------------------------------------------------------


def _default_known_hookpoints_provider() -> Iterable[str]:
    """Return the names of every currently-registered hookpoint.

    The registry's ``_hookpoints`` dict carries the names declared by
    every publisher imported into the process so far. ``alfred plugin``
    runs after the full CLI bootstrap, by which point every first-party
    publisher (``alfred.memory.episodic``, ``alfred.identity._ingest``,
    ``alfred.security.capability_gate.proposals``, …) has executed its
    module-init :func:`declare_hookpoints` call.

    Read-only iteration only — the validator never mutates the
    registry. Test seams replace this function wholesale rather than
    patching the registry singleton.
    """
    return tuple(get_registry()._hookpoints)


# Module-level seam. Tests patch this symbol with a closed iterable so
# the test suite does not depend on which publishers happened to be
# imported by the test runner.
_known_hookpoints_provider: Callable[[], Iterable[str]] = _default_known_hookpoints_provider

# Number of difflib candidate suggestions to surface alongside an
# unknown-hookpoint refusal. Five is enough to land the most likely typo
# fixes without flooding the operator's terminal.
_HOOKPOINT_SUGGESTION_LIMIT: Final[int] = 5


def validate_hookpoint(value: str) -> str:
    """Refuse hookpoints that no publisher has declared.

    A grant against an unknown hookpoint would land a never-firing entry
    in state.git: the reviewer approves it, the projection rebuilds, and
    the grant has no effect because no subscriber ever runs at the
    nonexistent hookpoint. The validator catches the typo at the boundary
    and offers the five closest declared names so the operator can
    self-correct without consulting a documentation page.

    Suggestions are computed via :func:`difflib.get_close_matches` against
    the full set of registered hookpoint names. The empty-set degenerate
    case (no publishers loaded — only possible in degraded test fixtures)
    short-circuits to a localised hint stating the registry is empty.
    """
    known = tuple(_known_hookpoints_provider())
    if value in known:
        return value
    if not known:
        raise typer.BadParameter(
            t("cli.validators.hookpoint_registry_empty", value=value),
            param_hint="'hookpoint'",
        )
    suggestions = difflib.get_close_matches(value, known, n=_HOOKPOINT_SUGGESTION_LIMIT)
    raise typer.BadParameter(
        t(
            "cli.validators.hookpoint_invalid",
            value=value,
            suggestions=", ".join(suggestions) if suggestions else "(no close matches)",
        ),
        param_hint="'hookpoint'",
    )


# ---------------------------------------------------------------------------
# Domain — bare lowercase domain, no scheme, no path
# ---------------------------------------------------------------------------

# ``^[a-z0-9.-]+\.[a-z]{2,}$`` — bare domain shape. Lowercase letters,
# digits, dot, hyphen; must contain at least one dot followed by a TLD of
# two or more letters. Deliberately strict:
#
# * No path / query / fragment — the allowlist's path component is a
#   separate ``--path-prefix`` flag; bundling it into the domain string
#   would let an operator silently widen the surface to ``example.com``
#   when they think they're scoping to ``example.com/v1/``.
# * No userinfo (``user:pass@host``) — the allowlist is a domain ACL, not
#   an auth surface.
# * No port — Slice-3's allowlist is scheme-agnostic; ports live in a
#   future scope.
# * No internationalised host — IDNA support requires Punycode
#   normalisation that the validator does not yet ship; until it does
#   the allowlist takes ASCII only. The reviewer rejects anything else.
_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")

# CR-149: a single DNS label per the DNS naming rules. ``^[a-z0-9]`` and
# ``[a-z0-9]$`` anchor each label so leading / trailing hyphens are
# refused (RFC 1035 §2.3.1). The middle character class ``[a-z0-9-]{0,61}``
# caps the label length at 63 and allows the hyphen only between
# alphanumerics. Used to validate every dot-separated label of the
# operator-supplied domain after the bulk-pattern check, so
# ``example..com`` (empty label), ``-foo.com`` (leading hyphen) and
# ``foo-.com`` (trailing hyphen) are rejected at the parser boundary
# rather than landing in a state.git proposal payload the reviewer
# would then either notice or accidentally merge.
_DOMAIN_LABEL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def validate_domain(value: str) -> str:
    """Refuse domains that look like URLs or include path traversal shapes.

    Three failure modes the parser must catch before the string lands in
    a proposal payload:

    1. **Operator pasted a URL** — ``https://example.com/path`` — the
       proposal's ``domain`` field expects the bare host. Detecting the
       scheme up-front means the operator gets a clear "drop the scheme"
       hint rather than a downstream ACL miss.
    2. **Path traversal hidden in the domain** — ``../../etc/passwd``
       parses as a domain with no dot, so the regex would refuse it
       anyway, but we additionally short-circuit on ``..`` substring or
       any path separator. A defence-in-depth refusal here is cheap.
    3. **Mixed-case / trailing whitespace** — the production allowlist
       is case-insensitive; refusing upper-case here surfaces the typo
       at the boundary rather than after a confusing "domain not in
       allowlist" miss when an operator types ``Example.com`` but the
       saved entry is ``example.com``.

    Returns the validated bare domain on success.
    """
    if not value:
        raise typer.BadParameter(
            t("cli.validators.domain_invalid", value=value),
            param_hint="'domain'",
        )
    parsed = urllib.parse.urlparse(value)
    # urlparse on a bare domain produces ``scheme=''`` and packs everything
    # into ``.path``. A non-empty scheme means the operator pasted a URL.
    if parsed.scheme:
        raise typer.BadParameter(
            t("cli.validators.domain_with_scheme", value=value),
            param_hint="'domain'",
        )
    # Even with an empty scheme, refuse any string carrying path-traversal
    # or path-separator characters. The regex below would already reject
    # them, but a dedicated branch produces a clearer localised message
    # for the operator who pasted a relative-path argument by mistake.
    if ".." in value or "/" in value or "\\" in value:
        raise typer.BadParameter(
            t("cli.validators.domain_with_path", value=value),
            param_hint="'domain'",
        )
    if not _DOMAIN_PATTERN.fullmatch(value):
        raise typer.BadParameter(
            t("cli.validators.domain_invalid", value=value),
            param_hint="'domain'",
        )
    # CR-149: the bulk pattern accepts ``example..com``, ``-foo.com``
    # and ``foo-.com`` because it does not constrain individual labels.
    # The per-label fullmatch closes those failure modes: empty labels
    # (consecutive dots), leading hyphens, and trailing hyphens are
    # all refused with the same localised body so the operator sees a
    # consistent "domain not in allowlist shape" hint regardless of
    # which RFC 1035 rule was violated.
    labels = value.split(".")
    if not all(_DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise typer.BadParameter(
            t("cli.validators.domain_invalid", value=value),
            param_hint="'domain'",
        )
    return value


# ---------------------------------------------------------------------------
# Quarantined provider — closed set of declared provider ids
# ---------------------------------------------------------------------------

# The two providers shipped today (see ``src/alfred/providers/anthropic_native.py``
# + ``src/alfred/providers/deepseek.py``). When a third provider lands,
# this constant gains a member and the closed-set rejection automatically
# extends. The closed set is intentionally hand-maintained rather than
# introspected from the provider registry — at CLI parse time the live
# provider registry may not have run its module-init wiring, so a
# runtime lookup risks false rejections. The trade-off is a maintenance
# burden of one line per future provider, paid for in deterministic
# parse-time rejection.
_ALLOWED_QUARANTINED_PROVIDERS: Final[frozenset[str]] = frozenset({"anthropic", "deepseek"})


def validate_quarantined_provider(value: str) -> str:
    """Refuse provider ids outside the closed set of declared providers.

    A typo (``anthropc``) or a malicious value (``../etc/passwd``) would
    otherwise reach the state.git proposal payload as-is; the reviewer
    then has to either notice the bad input or merge it. The validator
    is the parse-time refusal so neither outcome is reachable.

    Returns the value on success. Case-sensitive on purpose: the provider
    ids in ``src/alfred/providers`` are lowercase by convention and the
    downstream :func:`alfred.bootstrap.quarantine.assert_provider_separation`
    helper normalises with ``.strip().lower()``. Accepting mixed-case at
    the CLI would silently lower-case it before storage and surface as a
    "what I typed isn't what was saved" surprise on the next ``config get``.
    """
    if value not in _ALLOWED_QUARANTINED_PROVIDERS:
        raise typer.BadParameter(
            t(
                "cli.validators.quarantined_provider_invalid",
                value=value,
                valid_providers=", ".join(sorted(_ALLOWED_QUARANTINED_PROVIDERS)),
            ),
            param_hint="'value'",
        )
    return value


__all__ = [
    "SubscriberTier",
    "validate_domain",
    "validate_hookpoint",
    "validate_plugin_id",
    "validate_quarantined_provider",
    "validate_subscriber_tier",
]
