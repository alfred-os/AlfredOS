"""Pre-launcher Python helper (spec §7.2 — bash launcher reads manifest here).

``bin/alfred-plugin-launcher.sh`` invokes this module as a one-shot
subprocess to read the manifest's ``[sandbox]`` block, resolve
``Settings.environment``, and translate a policy file into bwrap flags. The
launcher stays bash (sec-004 honest); this helper keeps the trust-boundary
logic in Python where it can be unit-tested.

CLI subcommands (mutually exclusive):

  --read-sandbox (--manifest-path <path> | --plugin-id <id>)
      Print JSON ``{"kind": ..., "policy_refs": {...}}`` from the manifest's
      [sandbox] block. Refuses on missing block / malformed TOML / invalid
      kind with a bare i18n key on stderr + non-zero exit.

  --read-environment
      Print the resolved ``Settings.environment`` value
      (development|production|test) via the dual-source loader (env var >
      /etc/alfred/environment; ``ALFRED_ETC_ENV_FILE`` overrides the file
      path for testing). Refuses (exit 1) if neither source resolves to a
      Literal value.

  --policy-to-bwrap-flags
      Read a TOML policy from stdin; print the bwrap CLI flags one per line.
      Used by the launcher's ``kind: full`` branch on Linux.

Each subcommand does the smallest thing so invocations are independent —
failure of one cannot corrupt a subsequent one. Refusals print a bare i18n
KEY (not a rendered sentence) on stderr per the launcher's bare-key
convention; the supervisor renders the localised audit row.

Note (sec-007 carve-out): ``--read-environment`` resolves the environment
through :func:`alfred.config._environment_loader.load_environment`, which is
the single sanctioned reader of ``ALFRED_ENVIRONMENT`` /
``/etc/alfred/environment``. The ``ALFRED_ETC_ENV_FILE`` override read below
is a non-secret test hook (the env-read AST guard only bans
``ALFRED_<SUPPORTED_SECRET>`` keys, never ``ALFRED_ETC_ENV_FILE``).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from alfred.config._environment_loader import EnvironmentSource, load_environment
from alfred.plugins.errors import ManifestError, ManifestSandboxMissingError
from alfred.plugins.manifest import parse_manifest
from alfred.plugins.sandbox_policy import (
    SandboxPolicyInvalid,
    policy_to_bwrap_flags,
    read_policy_toml,
)

# Charset for a plugin-id used in a filesystem lookup. A strict subset of the
# manifest-parser's tolerance (mirrors the bash launcher's PLUGIN_ID gate) so
# a traversal-shaped id (``../../etc/passwd``) is refused before any path
# resolution. Closed-vocabulary slug shape from spec §5.6.
_SAFE_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")

# Default install root for plugin manifests. ``plugins/<dir>/manifest.toml``
# where ``<dir>`` is the plugin-id with ``.`` and ``-`` mapped to ``_``
# (e.g. ``alfred.quarantined-llm`` -> ``alfred_quarantined_llm``). The
# ``ALFRED_PLUGINS_DIR`` override exists for tests.
_DEFAULT_PLUGINS_DIR: Path = Path("plugins")

_ENV_NOT_SET_KEY = "daemon.boot.environment_not_set"
_ENV_UNRECOGNISED_KEY = "daemon.boot.environment_unrecognised"
_PLUGIN_ID_INVALID_KEY = "plugin.launcher_plugin_id_invalid"
_MANIFEST_UNREADABLE_KEY = "plugin.manifest_unreadable"
_READ_SANDBOX_NO_SOURCE_KEY = "plugin.manifest_reader_no_source"


def _fail(key: str) -> int:
    """Print a bare i18n KEY to stderr and return the refusal exit code."""
    print(key, file=sys.stderr)
    return 1


def _plugin_id_is_safe(plugin_id: str) -> bool:
    return bool(plugin_id) and all(c in _SAFE_ID_CHARS for c in plugin_id)


def _manifest_path_for_plugin_id(plugin_id: str) -> Path:
    plugins_dir_raw = os.environ.get("ALFRED_PLUGINS_DIR")
    plugins_dir = Path(plugins_dir_raw) if plugins_dir_raw else _DEFAULT_PLUGINS_DIR
    dir_name = plugin_id.replace(".", "_").replace("-", "_")
    return plugins_dir / dir_name / "manifest.toml"


def _resolve_manifest_path(args: argparse.Namespace) -> Path | None:
    """Return the manifest path from --manifest-path or --plugin-id, or None.

    ``--manifest-path`` takes precedence (the launcher forwards it from the
    ``ALFRED_PLUGIN_MANIFEST_PATH`` test override). A traversal-shaped
    ``--plugin-id`` returns ``None`` so the caller refuses.
    """
    if args.manifest_path:
        return Path(args.manifest_path)
    if args.plugin_id:
        if not _plugin_id_is_safe(args.plugin_id):
            return None
        return _manifest_path_for_plugin_id(args.plugin_id)
    return None


def _cmd_read_sandbox(args: argparse.Namespace) -> int:
    manifest_path = _resolve_manifest_path(args)
    if manifest_path is None:
        if args.plugin_id and not _plugin_id_is_safe(args.plugin_id):
            return _fail(_PLUGIN_ID_INVALID_KEY)
        return _fail(_READ_SANDBOX_NO_SOURCE_KEY)
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except OSError:
        return _fail(_MANIFEST_UNREADABLE_KEY)
    try:
        manifest = parse_manifest(raw)
    except ManifestSandboxMissingError:
        # Stable bare key (matches the audit reason="sandbox_block_missing"
        # attribution path) rather than the rendered message, so the
        # launcher's bare-key-on-stderr convention holds.
        return _fail("plugin.manifest_sandbox_block_missing")
    except ManifestError:
        # Any other manifest-level refusal (invalid TOML / kind / policy_refs).
        # One stable key so the launcher + supervisor branch on a closed
        # vocabulary instead of parsing a rendered sentence.
        return _fail("plugin.manifest_invalid")
    print(manifest.sandbox.model_dump_json())
    return 0


def _cmd_read_environment() -> int:
    etc_override = os.environ.get("ALFRED_ETC_ENV_FILE")
    etc_path = Path(etc_override) if etc_override else None
    result = load_environment(etc_path=etc_path)
    if result.value is not None:
        print(result.value)
        return 0
    if result.source is EnvironmentSource.UNRECOGNISED:
        return _fail(_ENV_UNRECOGNISED_KEY)
    return _fail(_ENV_NOT_SET_KEY)


def _cmd_policy_to_bwrap_flags() -> int:
    raw = sys.stdin.read()
    try:
        policy = read_policy_toml(raw)
    except SandboxPolicyInvalid as exc:
        return _fail(exc.reason)
    for flag in policy_to_bwrap_flags(policy):
        print(flag)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alfred.plugins.manifest_reader",
        description="Pre-launcher manifest/environment/policy reader (spec §7.2).",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--read-sandbox", action="store_true")
    mode.add_argument("--read-environment", action="store_true")
    mode.add_argument("--policy-to-bwrap-flags", action="store_true")
    parser.add_argument("--manifest-path", default=None)
    parser.add_argument("--plugin-id", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.read_sandbox:
        return _cmd_read_sandbox(args)
    if args.read_environment:
        return _cmd_read_environment()
    # The mutually-exclusive required group guarantees exactly one mode; the
    # remaining branch is --policy-to-bwrap-flags.
    return _cmd_policy_to_bwrap_flags()


if __name__ == "__main__":  # pragma: no cover - manual entry
    sys.exit(main())
