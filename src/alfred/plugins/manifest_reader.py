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

  --check-bind-source --bind-source <path>
      Exit 0 iff ``<path>`` is an acceptable HARD bind source (not the host
      root, a non-allowlisted top-level root, or a ``/proc``/``/sys`` source
      — see ``is_over_broad_bind_source``, #428). Exit non-zero otherwise
      (including an empty path). Output is not consumed by callers; only the
      exit code matters.

Each subcommand does the smallest thing so invocations are independent —
failure of one cannot corrupt a subsequent one. Refusals print a bare i18n
KEY (not a rendered sentence) on stderr per the launcher's bare-key
convention; the supervisor renders the localised audit row.

Note (sec-007 carve-out): ``--read-environment`` resolves the environment
through :func:`alfred.config._environment_loader.resolve_environment`, which is
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

# BUG-1 (PR-S4-11c-2b0): this module's stdout is captured by
# ``bin/alfred-plugin-launcher.sh`` as bwrap flags. The ``from alfred...``
# imports below transitively load :mod:`alfred.i18n.translator`, which emits a
# missing-catalog WARNING at import time on a pip-installed alfred. Pin ALL
# stdlib logging to stderr BEFORE those imports run so no log byte can ever reach
# fd 1 and become a bogus bwrap argument. Must precede the alfred imports.
from alfred._stdio_logging import configure_stderr_logging

configure_stderr_logging()

from alfred.config._environment_loader import (  # noqa: E402 - after stderr-logging pin (BUG-1)
    EnvironmentSource,
    resolve_environment,
)
from alfred.plugins.errors import (  # noqa: E402 - after stderr-logging pin (BUG-1)
    ManifestError,
    ManifestSandboxMissingError,
)
from alfred.plugins.manifest import parse_manifest  # noqa: E402 - after stderr-logging pin (BUG-1)
from alfred.plugins.sandbox_policy import (  # noqa: E402 - after stderr-logging pin (BUG-1)
    SandboxPolicyInvalid,
    is_over_broad_bind_source,
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

# Default sandbox-policy root, relative to the install root. The
# ``ALFRED_SANDBOX_POLICY_DIR`` env override (forwarded by the launcher)
# relocates it; confinement follows the override.
_DEFAULT_POLICY_SUBDIR = "config/sandbox"

_ENV_NOT_SET_KEY = "daemon.boot.environment_not_set"
_ENV_UNRECOGNISED_KEY = "daemon.boot.environment_unrecognised"
_PLUGIN_ID_INVALID_KEY = "plugin.launcher_plugin_id_invalid"
_MANIFEST_UNREADABLE_KEY = "plugin.manifest_unreadable"
_READ_SANDBOX_NO_SOURCE_KEY = "plugin.manifest_reader_no_source"
_POLICY_REF_ESCAPES_ROOT_KEY = "supervisor.sandbox.refused.policy_ref_escapes_root"
_POLICY_REF_UNREADABLE_KEY = "supervisor.sandbox.refused.policy_ref_unreadable"


class PolicyRefEscapesRoot(Exception):  # noqa: N818 -- name pinned by sec-2 + audit reason vocab
    """A manifest ``policy_ref`` resolves outside the sandbox-policy root.

    sec-2 BLOCKER: an attacker who plants a manifest must not be able to point
    ``policy_ref`` at ``../../etc/passwd``, an absolute path outside the root,
    or a symlink escaping the root. ``reason`` is the shipped audit vocabulary
    value ``policy_ref_escapes_root``.
    """

    def __init__(self, ref: str) -> None:
        super().__init__(f"policy_ref_escapes_root: {ref!r}")
        self.ref = ref
        self.reason = "policy_ref_escapes_root"


def resolve_policy_ref(
    ref: str,
    *,
    install_root: Path,
    policy_dir: Path | None = None,
) -> Path:
    """Confine + resolve a manifest ``policy_ref`` to a real file path.

    sec-2 path-confinement. Refuses (``PolicyRefEscapesRoot``) any ref that:

    * contains a ``..`` path component (string-level, before resolution),
    * is an absolute path,
    * resolves (following symlinks) outside the policy root, or
    * does not resolve to a regular file under the root.

    Args:
        ref: The manifest's ``policy_refs.<host_os>`` value.
        install_root: The AlfredOS install root. When ``policy_dir`` is not
            given the root is ``install_root / "config/sandbox"`` and ``ref``
            is interpreted relative to ``install_root``.
        policy_dir: Explicit policy root (the ``ALFRED_SANDBOX_POLICY_DIR``
            override). When given, ``ref`` is interpreted relative to it.

    Returns:
        The canonical (symlink-resolved) absolute path to the policy file.
    """
    raw = Path(ref)
    # String-level: reject any parent-traversal component up front so a ref
    # that would resolve back inside the root is still refused (launderable
    # shape — defence in depth) and absolute paths never escape.
    if ".." in raw.parts:
        raise PolicyRefEscapesRoot(ref)
    if raw.is_absolute():
        raise PolicyRefEscapesRoot(ref)

    if policy_dir is not None:
        root = policy_dir
        candidate = policy_dir / raw
    else:
        root = install_root / _DEFAULT_POLICY_SUBDIR
        candidate = install_root / raw

    try:
        resolved = candidate.resolve(strict=True)
        root_resolved = root.resolve(strict=True)
    except OSError as exc:
        # Missing file / broken symlink / unreadable parent: not a confinement
        # breach per se, but the ref cannot be honoured — treat as an escape
        # so the launcher refuses loudly (it never reads an unresolvable ref).
        raise PolicyRefEscapesRoot(ref) from exc

    # The resolved file must live strictly under the resolved root and be a
    # regular file (a ref pointing at the root dir itself is not a policy).
    if root_resolved not in resolved.parents:
        raise PolicyRefEscapesRoot(ref)
    if not resolved.is_file():
        raise PolicyRefEscapesRoot(ref)
    return resolved


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
    # sec-001 (#469 Blocker 1, Critical): resolve TRUSTED-SOURCES-ONLY (env var
    # + /etc), never `.env`. This helper's stdout is the launcher's sole
    # signal for IS_PRODUCTION (bin/alfred-plugin-launcher.sh), which gates
    # the bwrap sandbox refusals + the dev escape hatch + the FAKE_UNAME
    # keystone. `resolve_environment`'s in-process callers (Settings) can
    # express a trust floor by checking EnvironmentLoadResult.source (see the
    # gateway launch-target override, dcfcc441) — but THIS interface is a bare
    # stdout string consumed by bash; it carries the resolved VALUE but not
    # the SOURCE that produced it, so a source-conditioned check is
    # unexpressable here. Source-EXCLUSION (`consult_dotenv=False`) is the
    # equivalent recourse: a CWD `.env` — writable by anything with CWD
    # access, unlike root-owned `/etc/alfred/environment` — can never resolve
    # a value this helper will hand to the launcher. On the `.env`-only path
    # (env var + /etc both unset) this now falls through to NONE instead of
    # silently downgrading to whatever `.env` claims, and the existing
    # NONE/UNRECOGNISED handling below refuses exactly as it already did for
    # a genuinely unresolved environment.
    result = resolve_environment(etc_path=etc_path, consult_dotenv=False)
    if result.value is not None:
        print(result.value)
        return 0
    if result.source is EnvironmentSource.UNRECOGNISED:
        return _fail(_ENV_UNRECOGNISED_KEY)
    return _fail(_ENV_NOT_SET_KEY)


def _cmd_policy_to_bwrap_flags(args: argparse.Namespace) -> int:
    """Translate a policy to bwrap flags, from a confined --policy-ref or stdin.

    When ``--policy-ref`` is given the path is FIRST confined to the
    sandbox-policy root (sec-2) and only then read — so a manifest pointing
    ``policy_ref`` outside the install tree is refused before any bytes are
    read. Without it, the policy TOML is read from stdin (the simple path used
    by unit tests of the translator itself).
    """
    if args.policy_ref is not None:
        install_root = Path(args.install_root) if args.install_root else Path.cwd()
        policy_dir_raw = os.environ.get("ALFRED_SANDBOX_POLICY_DIR")
        policy_dir = Path(policy_dir_raw) if policy_dir_raw else None
        try:
            resolved = resolve_policy_ref(
                args.policy_ref, install_root=install_root, policy_dir=policy_dir
            )
        except PolicyRefEscapesRoot:
            return _fail(_POLICY_REF_ESCAPES_ROOT_KEY)
        # Confinement succeeded, but the resolved file can still be unreadable
        # at read time (ENOENT/permission race between resolve() and read).
        # Refuse with the stable bare key rather than let an OSError traceback
        # leak into the launcher's stderr ``detail`` (CR #229 R2 finding-1).
        try:
            raw = resolved.read_text(encoding="utf-8")
        except OSError:
            return _fail(_POLICY_REF_UNREADABLE_KEY)
    else:
        raw = sys.stdin.read()
    try:
        policy = read_policy_toml(raw)
    except SandboxPolicyInvalid as exc:
        return _fail(exc.reason)
    for flag in policy_to_bwrap_flags(policy):
        print(flag)
    return 0


def _cmd_check_bind_source(args: argparse.Namespace) -> int:
    """Exit 0 iff ``--bind-source`` is an acceptable (not over-broad) bind source.

    The launcher (bin/alfred-plugin-launcher.sh) calls this for the interpreter
    prefix and maps a non-zero exit to its own ``interpreter_prefix_too_broad``
    refusal. The bare reason is machine-only; no operator-facing rendering here.
    """
    path = args.bind_source if args.bind_source is not None else ""
    if is_over_broad_bind_source(path):
        return _fail("bind_source_too_broad")
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
    mode.add_argument("--check-bind-source", action="store_true")
    parser.add_argument("--manifest-path", default=None)
    parser.add_argument("--plugin-id", default=None)
    # --policy-to-bwrap-flags options: a confined --policy-ref (sec-2) +
    # the install root it is relative to. Absent → read policy TOML from stdin.
    parser.add_argument("--policy-ref", default=None)
    parser.add_argument("--install-root", default=None)
    # --check-bind-source value (#428): a candidate bind source path to test.
    parser.add_argument("--bind-source", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.read_sandbox:
        return _cmd_read_sandbox(args)
    if args.read_environment:
        return _cmd_read_environment()
    if args.check_bind_source:
        return _cmd_check_bind_source(args)
    # The mutually-exclusive required group guarantees exactly one mode; the
    # remaining branch is --policy-to-bwrap-flags.
    return _cmd_policy_to_bwrap_flags(args)


if __name__ == "__main__":  # pragma: no cover - manual entry
    sys.exit(main())
