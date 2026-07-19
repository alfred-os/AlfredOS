"""``alfred config`` CLI — two-track set/get/list for operator policy.

PR-S3-6 Component D. Splits operator configuration into two tracks per
spec §11.1/§11.2:

* **Low-blast** knobs mutate ``config/policies.yaml`` directly — these
  narrow within the existing trust surface (e.g. tightening a
  per-domain rate limit). Hot-reload picks up the file change on the
  next mtime poll; no reviewer involvement.
* **High-blast** knobs (only ``quarantined-provider`` for PR-S3-6) widen
  the trust surface and queue a state.git proposal via the same
  :class:`StateGitProposalClient` the plugin + web allowlist CLIs use.

The closed sets of keys are intentional. An unknown key surfaces a
localised error listing every valid key (devex-012 in plan §1011) so
the operator has an immediate recovery path. Silent acceptance of an
unknown key would write dead data into ``policies.yaml`` that the
hot-reloader silently ignores.

Hard rules honoured at this layer (CLAUDE.md):

* **Rule #1 — operator-facing strings via** :func:`t`.
* **Rule #6 — payload structure, not raw secrets.** The high-blast
  payload is ``{"key": ..., "value": ...}`` — both are identifiers, not
  secret material. If a future high-blast knob needs a secret value,
  the broker layer (not the CLI) substitutes it.
* **Rule #7 — no silent failures in security paths.**
  :class:`StateGitError` from the client surfaces as a localised stderr
  message and a non-zero exit code.

Module-level seams the tests patch:

* ``_policies_yaml_path`` — the YAML file the low-blast path reads/writes.
* ``_state_git_client`` — production reviewer-gate writer.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path
from typing import Annotated, Final

import typer
import yaml

from alfred.cli._state_git import StateGitProposalClient, queue_proposal_or_exit
from alfred.cli._validators import validate_quarantined_provider
from alfred.i18n import t
from alfred.state.proposal_payloads import ConfigSetProposal


def _safe_load_yaml(yaml_path: Path) -> dict[str, object]:
    """Read + parse ``yaml_path`` with a localised error on malformed YAML.

    err-002: every ``yaml.safe_load`` site in this module previously
    re-raised the raw :class:`yaml.YAMLError` for the operator -- a
    Python traceback bypassing the t() localisation layer. The wrapper
    converts a parse failure into a :class:`typer.Exit(code=1)` with a
    localised stderr message that names the file path so the operator
    can recover (open the file, fix the syntax, retry the command).

    Returns an empty dict for a non-existent file so the missing-file
    leg of ``set`` / ``get`` / ``list`` keeps its previous semantics
    without each caller re-implementing the exists-check.

    ``data or {}`` collapses a YAML document that parses to ``None``
    (the empty-document case) into a dict so downstream key navigation
    keeps its dict contract.
    """
    if not yaml_path.exists():
        return {}
    # CR-149 round-6: ``read_text`` can raise :class:`OSError` /
    # :class:`PermissionError` (file unreadable, EACCES on the parent
    # dir, transient I/O error). The previous shape only routed
    # :class:`yaml.YAMLError` through the localised path, so an
    # unreadable file dumped a raw Python traceback to stderr instead
    # of the operator-recovery hint. CLAUDE.md hard rule #7 forbids
    # silent / raw failures on a T1 surface; route the read failure
    # through its own localised key so the operator sees the path +
    # the OS-level diagnostic without picking it out of a traceback.
    try:
        raw = yaml_path.read_text()
    except OSError as exc:
        typer.echo(
            t(
                "cli.config.error.read_failed",
                yaml_path=str(yaml_path),
                error=str(exc),
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        typer.echo(
            t(
                "cli.config.error.malformed_yaml",
                yaml_path=str(yaml_path),
                error=str(exc),
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    # CR-149 round-3: only the "empty document" case coalesces to ``{}``.
    # The previous shape ``yaml.safe_load(raw) or {}`` silently turned
    # falsy top-level shapes (``[]``, ``false``, ``0``, ``""``) into an
    # empty mapping — the next ``config set`` would then overwrite the
    # file rather than failing loud on the structural error. On an
    # operator surface that is a must-fix.
    if data is None:
        data = {}
    if not isinstance(data, dict):
        # A top-level list / scalar is structurally wrong for
        # policies.yaml; route through the same localised error so the
        # operator gets a recovery path instead of a downstream AttributeError.
        typer.echo(
            t(
                "cli.config.error.malformed_yaml",
                yaml_path=str(yaml_path),
                error=f"top-level YAML must be a mapping (got {type(data).__name__})",
            ),
            err=True,
        )
        raise typer.Exit(code=1)
    return data


# Module-level seams. Tests patch these symbols.
_state_git_client: StateGitProposalClient = StateGitProposalClient()
_policies_yaml_path: Path = Path("config/policies.yaml")

# Closed set: keys that widen the trust surface. Each one is gated
# through state.git per spec §11.1. Adding to this set is itself a
# spec-level decision and an ADR.
_HIGH_BLAST_KEYS: Final[frozenset[str]] = frozenset({"quarantined-provider"})

# CLI key → policies.yaml dotted path. Low-blast knobs only — high-blast
# keys never land in policies.yaml directly. The mapping is the closed
# set of allowed CLI surfaces: any key not in either this map or
# :data:`_HIGH_BLAST_KEYS` is refused.
_KEY_TO_YAML_PATH: Final[dict[str, str]] = {
    "web-fetch-budget": "web_fetch.user_daily_budget",
    "operator-fetch-budget": "web_fetch.operator_daily_budget",
    "extraction-max-retries": "quarantine.extraction_max_retries",
    "action-deadline": "orchestrator.action_deadline_seconds",
    "user-agent": "web_fetch.user_agent",
}


def _valid_keys_csv() -> str:
    """Return every valid CLI ``set`` key sorted + comma-separated.

    Used by the unknown-key error message so the operator sees the
    closed set in alphabetical order regardless of dict insertion
    order. Centralised so a future addition to either set is reflected
    automatically.

    Both the low-blast (``policies.yaml``-backed) keys and the
    high-blast (reviewer-gated) keys are valid set targets — ``set``
    is the surface that routes high-blast keys through the proposal
    flow.
    """
    return ", ".join(sorted(set(_KEY_TO_YAML_PATH) | _HIGH_BLAST_KEYS))


def _valid_get_keys_csv() -> str:
    """Return the keys ``config get`` can actually read.

    CR-149: the previous shape reused :func:`_valid_keys_csv` for the
    ``get`` unknown-key path, which advertised ``quarantined-provider``
    (a high-blast knob whose value never lives in ``policies.yaml``)
    as a readable key. The operator then read "key is valid" while
    the same command refused to render it — a Spec §11.2 UX
    contradiction. ``get`` is restricted to the low-blast key set
    that ``policies.yaml`` actually stores; high-blast keys are
    surfaced via the dedicated "reviewer-gated / set-only" branch in
    :func:`config_get`.
    """
    return ", ".join(sorted(_KEY_TO_YAML_PATH))


def _parse_scalar(value: str) -> int | float | str:
    """Parse a CLI scalar with YAML-like coercion (int → float → str).

    Mirrors policies.yaml's natural typing: ``"30"`` becomes ``30`` (int)
    so a subsequent ``yaml.safe_load`` round-trips identically. The
    fallback to ``str`` keeps strings like ``"AlfredOS/dev"`` intact.
    Deliberately does NOT parse booleans or YAML special tokens (``null``,
    ``yes``, ``no``) — booleans are not in the current low-blast key set,
    and accepting them would silently coerce ``no`` (a plausible user-
    agent fragment) to ``False``.
    """
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _reject_action_deadline_below_floor(key: str, parsed: object) -> None:
    """Refuse an ``action-deadline`` set that violates the quarantine timeout nesting.

    ``action-deadline`` (-> ``orchestrator.action_deadline_seconds``) is the OUTER bound
    of the quarantine timeout nesting: ``action_deadline(30) > host_read(25) >
    child_budget(20) > SDK_read(8)`` (#340 golive §17 / §4-P1e). Writing an
    ``action_deadline <=`` the host read-frame timeout
    (:data:`~alfred.security.quarantine_child_io._READ_FRAME_TIMEOUT_S`) would let the
    orchestrator tear a LIVE extraction at its deadline BEFORE the framing/child bounds
    fire — surfacing as a misleading "action deadline exceeded" with no hint the value is
    below the quarantine floor (devex-lens, spec §17). So a ``<= floor`` set (or a
    non-numeric value that can't satisfy the numeric floor at all) is refused with an
    actionable ``t()`` message naming the floor + why, rather than silently accepting a
    nesting-inverting value.

    Only ``action-deadline`` is floor-guarded — every other low-blast key returns early.

    The floor is bound to the REAL ``_READ_FRAME_TIMEOUT_S`` (LAZY import: the
    ``quarantine_child_io`` module carries an egress-adjacent import closure, so deferring
    it keeps ``alfred --help`` light and pins the floor to the actual host read-frame
    timeout so the two can never drift).
    """
    if key != "action-deadline":
        return
    from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S

    floor = _READ_FRAME_TIMEOUT_S
    # ``_parse_scalar`` returns ``int | float | str``; only a numeric value strictly
    # above the floor is safe. A ``str`` (non-numeric input) can never satisfy the floor,
    # so it falls into the reject branch alongside an in-range-but-too-low number.
    if not isinstance(parsed, int | float) or parsed <= floor:
        typer.echo(
            t(
                "cli.config.set.action_deadline_below_floor",
                value=str(parsed),
                floor=str(floor),
            ),
            err=True,
        )
        raise typer.Exit(code=1)


def _yaml_set(yaml_path: Path, dotted_key: str, value: object) -> None:
    """Set a value at ``dotted_key`` in ``yaml_path``, creating parents.

    Reads the file (treating absent as empty), navigates the dotted
    path creating intermediate dicts as needed, writes the new value,
    and dumps the YAML back with ``default_flow_style=False`` so the
    file stays human-diff-friendly.

    sec-pr-s3-6-06: the write uses a sibling tempfile + ``os.fsync`` +
    atomic ``os.replace`` so a process kill mid-write cannot leave
    ``policies.yaml`` truncated. The hot-reloader reading ``policies.yaml``
    concurrently sees either the pre-call contents or the post-call
    contents -- never a half-written file. The temp lives in the same
    directory as the target so the rename is guaranteed atomic by POSIX
    (cross-device rename is not).
    """
    data = _safe_load_yaml(yaml_path)
    keys = dotted_key.split(".")
    node: dict[str, object] = data
    for k in keys[:-1]:
        existing = node.get(k)
        if existing is None:
            new_child: dict[str, object] = {}
            node[k] = new_child
            node = new_child
        elif isinstance(existing, dict):
            node = existing
        else:
            # CR-149 round-3: an existing non-mapping path segment is a
            # structural error in ``policies.yaml`` — silently
            # replacing it with ``{}`` would destroy operator config
            # state. Fail loud on the malformed-YAML branch so the
            # operator's recovery lever (open the file, fix the
            # offending key, retry) surfaces instead of overwriting
            # the bad shape. The structural error message names the
            # offending key segment so the operator can grep
            # ``policies.yaml`` for it.
            typer.echo(
                t(
                    "cli.config.error.malformed_yaml",
                    yaml_path=str(yaml_path),
                    error=f"path segment {k!r} must be a mapping",
                ),
                err=True,
            )
            raise typer.Exit(code=1)
    node[keys[-1]] = value
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(yaml_path, yaml.dump(data, default_flow_style=False))


def _atomic_write_text(target: Path, content: str) -> None:
    """Write ``content`` to ``target`` via tempfile + fsync + atomic rename.

    sec-pr-s3-6-06: a crash between ``write_text`` open + flush
    previously left an empty ``policies.yaml`` -- the hot-reloader then
    reset every operator knob to its built-in default at the next mtime
    tick. The atomic-rename pattern is the standard POSIX recipe:

      1. ``mkstemp`` in the SAME directory as the target so the eventual
         rename stays on-device (atomic per POSIX).
      2. ``write`` + ``fsync`` so the tempfile's data hits disk before
         the rename publishes it.
      3. ``os.replace`` so the rename is atomic vs concurrent readers.

    On failure the tempfile is unlinked so we do not leak ``.tmp...``
    droppings into the target directory.
    """
    parent = target.parent
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        # ``os.replace`` (not ``Path.replace``) because the test seam
        # patches ``alfred.cli.config.os.replace`` to simulate rename
        # failures; routing via ``Path.replace`` would bypass the seam.
        os.replace(tmp_path, target)  # noqa: PTH105
        # CR-149: ``write + fsync(file) + rename`` guarantees the new
        # data hits disk and the rename is atomic vs concurrent
        # readers, but on POSIX the directory entry that points at the
        # renamed file is only durable once the *containing directory*
        # is also fsynced. Without the directory fsync, a power loss
        # between the rename and the next directory metadata flush can
        # lose the rename and leave the operator with the old
        # ``policies.yaml`` — defeating the sec-pr-s3-6-06 crash-safety
        # claim. The ``OSError`` suppression is the POSIX-portability
        # branch: some platforms (Windows, certain FUSE mounts) do not
        # support directory ``fsync``; the helper still publishes the
        # file atomically there even without the durability guarantee.
        with contextlib.suppress(OSError):
            dir_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except BaseException:
        # Clean up the tempfile on any failure path so a crash here
        # does not leave ``.policies.yaml.<random>.tmp`` debris.
        # ``FileNotFoundError`` is the documented benign branch: the
        # tempfile may already have been moved by ``os.replace`` before
        # the failing operation, or never created if the open failed.
        with contextlib.suppress(FileNotFoundError):
            Path(tmp_path).unlink()
        raise


def _yaml_get(yaml_path: Path, dotted_key: str) -> object | None:
    """Read the value at ``dotted_key`` from ``yaml_path``.

    Returns ``None`` if the file does not exist OR if any path segment
    is missing. Distinguishing "file absent" from "key absent" is left
    to callers that care; for the CLI surface both render the same
    "not set" message.

    err-002: parse failures route through :func:`_safe_load_yaml`'s
    localised malformed-YAML branch -- the operator sees a recovery
    hint, not a raw :class:`yaml.YAMLError` traceback.
    """
    if not yaml_path.exists():
        return None
    data: object = _safe_load_yaml(yaml_path)
    for k in dotted_key.split("."):
        if not isinstance(data, dict) or k not in data:
            return None
        data = data[k]
    return data


# ---------------------------------------------------------------------------
# Typer app
# ---------------------------------------------------------------------------

config_app = typer.Typer(
    help=t("cli.config.help.group"),
    no_args_is_help=True,
)


# ---------------------------------------------------------------------------
# set
# ---------------------------------------------------------------------------


@config_app.command("set", help=t("cli.config.set.help.short"))
def config_set(
    key: Annotated[
        str,
        typer.Argument(help=t("cli.config.set.arg.key")),
    ],
    value: Annotated[
        str,
        typer.Argument(help=t("cli.config.set.arg.value")),
    ],
) -> None:
    """Set an operator configuration key.

    High-blast keys queue a state.git proposal; low-blast keys write
    directly to policies.yaml. Unknown keys are refused with the valid
    set enumerated on stderr.
    """
    if key in _HIGH_BLAST_KEYS:
        # sec-pr-s3-6-01: validate the high-blast value against the
        # closed set BEFORE writing the proposal. A typo or malicious
        # string reaching state.git is exactly the parse-time refusal
        # surface :mod:`alfred.cli._validators` exists to close. The
        # dispatch is keyed on ``key`` so a future second high-blast
        # knob plugs in a per-key validator without touching this branch.
        # ``no branch`` because today ``_HIGH_BLAST_KEYS`` is the single
        # closed set ``{"quarantined-provider"}``; the ``else`` arm is
        # structurally unreachable until a second high-blast key lands
        # and the dispatch grows a real ``elif``. The discriminator is
        # kept for that day so the open-coded one-arm conditional is
        # not a soft-fail "all keys take the same validator" pattern.
        if key == "quarantined-provider":  # pragma: no branch
            value = validate_quarantined_provider(value)
        # perf-001: ``audit_row_schemas`` lives under the ``alfred.audit``
        # package whose ``__init__`` eagerly pulls in :class:`AuditEntry`
        # from :mod:`alfred.memory.models` (~140 ms of SQLAlchemy ORM).
        # The constant is only needed on the high-blast write path so the
        # import is deferred here rather than at module top, keeping the
        # ``alfred --help`` surface light.
        from alfred.audit.audit_row_schemas import CONFIG_SET_REQUESTED_FIELDS
        from alfred.cli.operator_session import resolve_operator_user_id_or_refuse

        # #153: resolve the authenticated operator session so the queued
        # proposal payload carries the canonical ``User.id`` instead of
        # ``None``. A missing/expired session refuses the command outright.
        operator_user_id = resolve_operator_user_id_or_refuse(
            refusal_key="cli.config.set.refused.not_logged_in"
        )

        # Stage 3 (arch-001 / cross-cutting R2): the audit-row stand-in
        # fires via :data:`CONFIG_SET_REQUESTED_FIELDS` BEFORE the
        # state.git write. CLAUDE.md hard rule #6: the audit row carries
        # ``config_key`` only — the value lives in the proposal payload
        # the reviewer reads, never in the audit log.
        queue_proposal_or_exit(
            payload=ConfigSetProposal(
                # The Literal["quarantined-provider"] on the model
                # rejects any other key at construction; the
                # ``_HIGH_BLAST_KEYS`` membership check above is the
                # parallel CLI guard, but the model is the typed seam
                # that ADR-0018 makes load-bearing.
                config_key=key,  # type: ignore[arg-type]
                value=value,
            ),
            denied_key="cli.config.set.denied",
            pending_review_key="cli.config.set.pending_review",
            pending_review_extra_kwargs={"key": key},
            audit_event="config.set.requested",
            audit_schema_name="CONFIG_SET_REQUESTED_FIELDS",
            audit_fields=CONFIG_SET_REQUESTED_FIELDS,
            audit_subject_partial={
                "config_key": key,
                # #153: canonical authenticated operator id (was None pre-S4-5).
                "operator_user_id": operator_user_id,
                # CR-149 round-6: operator-typed CLI ingress for a
                # high-blast config knob — T1 swimlane (PRD §7.1 +
                # CLAUDE.md hard rule #3). Same rationale as the other
                # reviewer-gated emit sites.
                "trust_tier_of_trigger": "T1",
            },
            client=_state_git_client,
        )
        return

    yaml_key = _KEY_TO_YAML_PATH.get(key)
    if yaml_key is None:
        typer.echo(
            t(
                "cli.config.set.unknown_key",
                key=key,
                valid_keys=_valid_keys_csv(),
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    parsed = _parse_scalar(value)
    # #340 golive Task 15: floor-guard action-deadline so an operator can't invert the
    # quarantine timeout nesting (action_deadline must stay > the host read-frame floor).
    # No-op for every other low-blast key.
    _reject_action_deadline_below_floor(key, parsed)
    _yaml_set(_policies_yaml_path, yaml_key, parsed)
    typer.echo(
        t(
            "cli.config.set.applied",
            key=key,
            value=str(parsed),
            yaml_path=str(_policies_yaml_path),
        )
    )


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


@config_app.command("get", help=t("cli.config.get.help.short"))
def config_get(
    key: Annotated[
        str,
        typer.Argument(help=t("cli.config.get.arg.key")),
    ],
) -> None:
    """Get the current value of an operator configuration key.

    Reads ``policies.yaml`` — high-blast keys are NOT queryable here
    because they don't live in ``policies.yaml`` (their value lives in
    routing.yaml + the supervisor config that the proposal merges into).
    """
    # CR-149: distinguish "high-blast key, not readable here" from
    # "unknown key". The high-blast set is a valid target for
    # ``set`` (it routes through the reviewer-gated proposal flow)
    # but the value never lands in ``policies.yaml``; the prior
    # shape rejected it with the same "did you mean..." message used
    # for typos, listing ``quarantined-provider`` among the "valid
    # keys" while simultaneously refusing to render it. The dedicated
    # branch below surfaces the truth: this key exists, but its
    # value lives in ``routing.yaml`` after the reviewer merges the
    # proposal — see ``alfred config set quarantined-provider ...``.
    if key in _HIGH_BLAST_KEYS:
        typer.echo(
            t("cli.config.get.reviewer_gated_set_only", key=key),
            err=True,
        )
        raise typer.Exit(code=1)
    yaml_key = _KEY_TO_YAML_PATH.get(key)
    if yaml_key is None:
        typer.echo(
            t(
                "cli.config.get.unknown_key",
                key=key,
                valid_keys=_valid_get_keys_csv(),
            ),
            err=True,
        )
        raise typer.Exit(code=1)
    value = _yaml_get(_policies_yaml_path, yaml_key)
    if value is None:
        typer.echo(t("cli.config.get.not_set", key=key))
        return
    typer.echo(t("cli.config.get.value", key=key, value=str(value)))


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def _walk_flat(data: object, prefix: str, lines: list[str]) -> None:
    """Recursively flatten YAML into ``key = value`` lines.

    Hoisted out of the Typer command so the recursion is testable as a
    pure function. Lists are rendered as YAML-flow strings (the
    operator surface here is human-eyeball; round-tripping back through
    ``set`` is not a documented operation).
    """
    if isinstance(data, dict):
        for k, v in data.items():
            child_prefix = f"{prefix}.{k}" if prefix else str(k)
            _walk_flat(v, child_prefix, lines)
    else:
        lines.append(f"{prefix} = {data}")


@config_app.command("list", help=t("cli.config.list.help.short"))
def config_list() -> None:
    """List all current operator configuration values from policies.yaml.

    err-002: malformed YAML routes through :func:`_safe_load_yaml`'s
    localised error so an operator who hand-edited the file mid-shift
    sees a recovery hint instead of a raw :class:`yaml.YAMLError`.
    """
    if not _policies_yaml_path.exists():
        typer.echo(t("cli.config.list.empty"))
        return
    data = _safe_load_yaml(_policies_yaml_path)
    if not data:
        typer.echo(t("cli.config.list.empty"))
        return
    lines: list[str] = []
    _walk_flat(data, prefix="", lines=lines)
    for line in lines:
        typer.echo(line)


def _register_proposal_keys_for_pybabel() -> tuple[str, ...]:
    """Surface the high-blast proposal-flow i18n keys to pybabel.

    Stage 3 (cross-cutting R5): :func:`queue_proposal_or_exit` consumes
    the ``denied_key`` + ``pending_review_key`` strings via parameter,
    so the pybabel AST walker would otherwise drop the keys. Same
    pattern as :func:`alfred.cli._state_git._register_hint_keys_for_pybabel`.
    """
    # CR-149 round-3: pass representative kwargs so each rendered
    # body fully substitutes its placeholders (``{reason}`` for
    # ``.denied``; ``{key}`` + ``{branch}`` + ``{proposal_id}`` for
    # ``.pending_review``). Without the kwargs the rendered string
    # carried the literal ``{...}`` placeholders, undercutting the
    # callable-validation seam the adjacent i18n-coverage tests rely
    # on.
    return (
        t("cli.config.set.denied", reason="example"),
        t(
            "cli.config.set.pending_review",
            key="example",
            branch="example",
            proposal_id="0123456789abcdef",
        ),
    )


__all__ = ["config_app"]
