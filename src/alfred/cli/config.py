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

from pathlib import Path
from typing import Annotated, Final

import typer
import yaml

from alfred.cli._state_git import StateGitError as _StateGitError
from alfred.cli._state_git import StateGitProposalClient
from alfred.i18n import t

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
    """Return every valid CLI key sorted + comma-separated.

    Used by the unknown-key error message so the operator sees the
    closed set in alphabetical order regardless of dict insertion
    order. Centralised so a future addition to either set is reflected
    automatically.
    """
    return ", ".join(sorted(set(_KEY_TO_YAML_PATH) | _HIGH_BLAST_KEYS))


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


def _yaml_set(yaml_path: Path, dotted_key: str, value: object) -> None:
    """Set a value at ``dotted_key`` in ``yaml_path``, creating parents.

    Reads the file (treating absent as empty), navigates the dotted
    path creating intermediate dicts as needed, writes the new value,
    and dumps the YAML back with ``default_flow_style=False`` so the
    file stays human-diff-friendly.
    """
    if yaml_path.exists():
        data: dict[str, object] = yaml.safe_load(yaml_path.read_text()) or {}
    else:
        data = {}
    keys = dotted_key.split(".")
    node: dict[str, object] = data
    for k in keys[:-1]:
        existing = node.get(k)
        if not isinstance(existing, dict):
            new_child: dict[str, object] = {}
            node[k] = new_child
            node = new_child
        else:
            node = existing
    node[keys[-1]] = value
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(yaml.dump(data, default_flow_style=False))


def _yaml_get(yaml_path: Path, dotted_key: str) -> object | None:
    """Read the value at ``dotted_key`` from ``yaml_path``.

    Returns ``None`` if the file does not exist OR if any path segment
    is missing. Distinguishing "file absent" from "key absent" is left
    to callers that care; for the CLI surface both render the same
    "not set" message.
    """
    if not yaml_path.exists():
        return None
    data: object = yaml.safe_load(yaml_path.read_text()) or {}
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
        try:
            result = _state_git_client.create_proposal(
                proposal_type=f"config-{key}",
                payload={"key": key, "value": value},
            )
        except _StateGitError as exc:
            typer.echo(
                t("cli.config.set.denied", reason=str(exc)),
                err=True,
            )
            raise typer.Exit(code=1) from exc
        typer.echo(
            t(
                "cli.config.set.pending_review",
                key=key,
                branch=result.branch,
                proposal_id=result.proposal_id,
            )
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
    yaml_key = _KEY_TO_YAML_PATH.get(key)
    if yaml_key is None:
        typer.echo(
            t(
                "cli.config.get.unknown_key",
                key=key,
                valid_keys=_valid_keys_csv(),
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
    """List all current operator configuration values from policies.yaml."""
    if not _policies_yaml_path.exists():
        typer.echo(t("cli.config.list.empty"))
        return
    raw = _policies_yaml_path.read_text()
    data = yaml.safe_load(raw) or {}
    if not data:
        typer.echo(t("cli.config.list.empty"))
        return
    lines: list[str] = []
    _walk_flat(data, prefix="", lines=lines)
    for line in lines:
        typer.echo(line)


__all__ = ["config_app"]
