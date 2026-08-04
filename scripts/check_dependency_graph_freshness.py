#!/usr/bin/env python3
"""Is the submitted dependency graph alive and current? (#568)

LIVENESS IS THE PRIMARY SIGNAL. Content comparison is secondary and lagging:
replayed against the frozen 2026-06-19 graph, a content-only monitor is GREEN
AND BLIND for 16 days, reddening only via an unrelated bulk upgrade. The
per-channel run conclusion is a perfect step function — it would have gone red
at hour 0 instead of day 44.

Content comparison is guarded by five things that draft 1 lacked:
  * a coverage floor      -> an empty / zero-pypi SBOM cannot pass
  * two-way containment   -> a silently DROPPED package (in the lock, absent
                             from the graph) OR a silently KEPT-STALE one (in
                             the graph, absent from the lock and from
                             `_GRAPH_ONLY_ALLOWLIST`) cannot pass -- draft 2
                             only ever checked the first direction
  * purl-derived versions -> the live SBOM's version-less duplicate records
                             (`textual`, `alfred`) cannot cause false drift,
                             and two CONFLICTING versioned records for one
                             package cannot resolve by document order
  * versioned-record proof -> a lock package whose ONLY graph record is
                             version-less cannot pass by riding along on the
                             phantom-record allowance above -- a version-less
                             record is legitimate only when a VERSIONED
                             record for the same name also exists

Every unknown is fail-closed: a malformed document, a missing channel
conclusion, or an unreadable file is a FAILURE, never "no drift".

stdlib-only (`tomllib` is stdlib on 3.11+), so the workflow needs no `uv sync`.
"""

import argparse
import json
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

# NO `from __future__ import annotations` IN THIS FILE. Do not add it back.
#
# `tests/unit/meta/test_dependency_graph_freshness.py` loads this module the
# house way — `importlib.util.spec_from_file_location` +
# `importlib.util.module_from_spec` + `exec_module()` — WITHOUT registering it
# in `sys.modules` first (matching the `runner` fixture in
# tests/unit/meta/conftest.py). Combine that loader pattern with postponed
# annotations and a `@dataclass` below it, and CPython 3.14.6 raises a bare
# `AttributeError: 'NoneType' object has no attribute '__dict__'` at
# class-definition time: `@dataclass` resolves ClassVar/InitVar/KW_ONLY by
# string-evaling the postponed annotations against
# `sys.modules.get(cls.__module__).__dict__`, and that lookup is `None` for an
# unregistered module. Reproduced in isolation with a two-line probe script,
# and independently against `scripts/docs_check.py`'s own frozen dataclasses
# loaded the identical way — this is a latent trap in the load pattern itself,
# not something specific to this script's design.
#
# Leaving annotations un-postponed sidesteps the string-eval path entirely.
# PEP 604 (`X | Y`) and PEP 585 (`tuple[str, ...]`) are both native at runtime
# on 3.14 regardless of the future import, so nothing is lost by omitting it.
#
# See `Verdict` below for where this actually bites.

#: Channels that read `requires-python` and died together on 2026-06-21.
#:
#: TWO entries, not three. Dependabot's security-update and weekly-pip channels
#: are separate COMMANDS inside one workflow (282449388), so the runs API gives
#: them a single shared conclusion. Splitting them needs per-job inspection;
#: until that exists, claiming three independent signals would overstate what is
#: measured. `pip` had an unrelated failure on 2026-05-24, so the split is worth
#: doing later — tracked as a follow-up, not faked here.
REQUIRED_CHANNELS: Final[tuple[str, ...]] = (
    "dependency-graph",
    "dependabot-updates",
)

#: The package the repo itself publishes; it has no lockfile entry.
_SELF_PACKAGE: Final[str] = "alfred"

_PYPI_PURL_PREFIX: Final[str] = "pkg:pypi/"

#: Packages that legitimately appear in GitHub's live dependency graph but can
#: never have a `uv.lock` entry. This is an ALLOWLIST of specific, justified
#: names, NOT a snapshot of "whatever the graph contains today" -- extend it
#: only when you can name why the new entry belongs here. Anything else
#: present in the graph but absent from the lock is unexplained and must fail
#: closed (see `unexpected_in_sbom` on `Verdict`).
#:
#:   * "hatchling" -- the PEP 517 build backend declared in
#:     `[build-system].requires` (pyproject.toml). GitHub's dependency graph
#:     parses build-system requirements; `uv.lock` only resolves
#:     `[project]`/dependency-group entries, so this name can never land
#:     there.
#:   * "click" -- a real transitive dependency of `typer` (pulled in via
#:     `typer==0.25.1`) until #391 (2026-07-05) bumped `typer` to 0.26.8,
#:     which dropped it. GitHub's graph carried the old resolution forward as
#:     a stale leftover afterwards -- confirmed against the committed
#:     `sbom_stale_2026-06-19.json` fixture (predates #391), which names
#:     `click@8.4.1`, the exact version #391 removed from `uv.lock`.
_GRAPH_ONLY_ALLOWLIST: Final[frozenset[str]] = frozenset({"click", "hatchling"})


# This is the class whose existence forces the no-future-annotations rule at
# the top of this file — see that comment before "fixing" this by adding
# `from __future__ import annotations` back.
@dataclass(frozen=True, slots=True)
class Verdict:
    """Outcome of one freshness evaluation."""

    dead_channels: tuple[str, ...]
    missing_from_sbom: tuple[str, ...]
    version_mismatches: tuple[tuple[str, str, str], ...]
    package_count: int
    min_packages: int
    #: SBOM packages that are neither in `uv.lock` nor in
    #: `_GRAPH_ONLY_ALLOWLIST`. Reverse containment: `missing_from_sbom` above
    #: catches a lock package the graph silently DROPPED; this catches a
    #: stale package the graph silently KEPT after it left the lock.
    #: Defaulted to `()` so existing call sites that predate this field are
    #: unaffected.
    unexpected_in_sbom: tuple[str, ...] = ()
    #: Package names whose purls carry more than one distinct version in the
    #: SBOM. Two versions of one package in the graph is evidence of
    #: staleness in its own right, independent of which one (if either)
    #: matches `uv.lock` -- see `sbom_versions()`. Defaulted to `()` for the
    #: same reason as `unexpected_in_sbom`.
    conflicting_versions: tuple[str, ...] = ()
    #: Lock packages present in the graph ONLY via a versionless (phantom)
    #: purl -- no versioned record for that name exists anywhere in the
    #: document. `sbom_names()` counts a versionless purl as "present", so
    #: containment (`missing_from_sbom`) passes; `sbom_versions()` excludes
    #: versionless records entirely, so version comparison never runs for
    #: it either. Without this field, a graph in which EVERY lock package
    #: appears only as a versionless purl passes every other check. A
    #: versionless record stays legitimate only when a VERSIONED record for
    #: the same name also exists (the real `textual`/`alfred` duplicates --
    #: see `sbom_versions()`'s docstring). Defaulted to `()` for the same
    #: reason as `unexpected_in_sbom`.
    unversioned_in_sbom: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            not self.dead_channels
            and not self.missing_from_sbom
            and not self.unexpected_in_sbom
            and not self.unversioned_in_sbom
            and not self.version_mismatches
            and not self.conflicting_versions
            and self.package_count >= self.min_packages
        )

    def report(self) -> str:
        if self.ok:
            return (
                f"dependency graph healthy: {self.package_count} pypi packages, all channels live"
            )
        lines = ["dependency graph UNHEALTHY:"]
        if self.dead_channels:
            lines.append(f"  dead channels: {', '.join(self.dead_channels)}")
        if self.package_count < self.min_packages:
            lines.append(
                f"  coverage floor: {self.package_count} pypi packages < {self.min_packages}"
            )
        if self.missing_from_sbom:
            lines.append(f"  absent from graph: {', '.join(self.missing_from_sbom)}")
        if self.unexpected_in_sbom:
            lines.append(f"  unexpected in graph: {', '.join(self.unexpected_in_sbom)}")
        if self.unversioned_in_sbom:
            lines.append(f"  versionless-only in graph: {', '.join(self.unversioned_in_sbom)}")
        for name, graph_version, lock_version in self.version_mismatches:
            lines.append(f"  {name}: graph {graph_version} vs lock {lock_version}")
        if self.conflicting_versions:
            lines.append(f"  conflicting versions in graph: {', '.join(self.conflicting_versions)}")
        return "\n".join(lines)


def sbom_versions(sbom: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """Map pypi package name -> every distinct version its purls carry.

    Records whose purl carries no `@version` are PHANTOMS (the live document has
    duplicate `textual` / `alfred` entries shaped that way) and are excluded
    here so a phantom duplicate alongside a real versioned record can never
    cause a false version mismatch. :func:`sbom_names` still counts a
    version-less purl as present by name -- containment alone does NOT catch
    a lock package whose ONLY graph record is version-less; that is caught
    separately, by `evaluate()`'s `unversioned_in_sbom` (a name present here
    would exclude it from that check; a name absent here that IS present in
    `sbom_names()` is exactly the fail-closed case).

    Retains every DISTINCT versioned record per name instead of last-write-wins:
    a `{name: version}` map lets two conflicting versioned purls for the same
    package resolve by document order alone, silently flipping the verdict on
    identical content. A package appearing twice with two different versions is
    itself evidence the graph is stale, so the caller (`evaluate()`) must be
    able to see that a name has more than one version, not just whichever one
    a `dict` write happened to land on last. Keys of the per-name dict here
    (rather than a `set`) preserve encounter order for readability in
    `Verdict.report()` without needing an extra sort key.
    """
    versions: dict[str, dict[str, None]] = {}
    for package in sbom.get("sbom", {}).get("packages", []):
        for ref in package.get("externalRefs", []):
            locator = ref.get("referenceLocator", "")
            if not locator.startswith(_PYPI_PURL_PREFIX):
                continue
            remainder = locator.removeprefix(_PYPI_PURL_PREFIX)
            name, separator, version = remainder.partition("@")
            if separator and name != _SELF_PACKAGE:
                versions.setdefault(name, {})[version] = None
    return {name: tuple(seen) for name, seen in versions.items()}


def sbom_names(sbom: Mapping[str, Any]) -> set[str]:
    """Every pypi package name in the document, with or without a version."""
    names: set[str] = set()
    for package in sbom.get("sbom", {}).get("packages", []):
        for ref in package.get("externalRefs", []):
            locator = ref.get("referenceLocator", "")
            if locator.startswith(_PYPI_PURL_PREFIX):
                name = locator.removeprefix(_PYPI_PURL_PREFIX).partition("@")[0]
                if name != _SELF_PACKAGE:
                    names.add(name)
    return names


def lock_versions(lock: Mapping[str, Any]) -> dict[str, str]:
    """Map package name -> version from a parsed `uv.lock`."""
    return {
        package["name"]: package["version"]
        for package in lock.get("package", [])
        if package.get("name") != _SELF_PACKAGE and "version" in package
    }


def dead_channels(runs: Mapping[str, str]) -> tuple[str, ...]:
    """Channels whose latest conclusion is anything but ``success``.

    Fail-closed: a channel absent from ``runs`` counts as dead, because "we
    could not tell" and "it is fine" must never be the same answer.
    """
    return tuple(
        channel for channel in REQUIRED_CHANNELS if runs.get(channel, "unknown") != "success"
    )


def evaluate(
    sbom: Mapping[str, Any],
    lock: Mapping[str, str],
    runs: Mapping[str, str],
    *,
    min_packages: int,
) -> Verdict:
    """Combine all seven signals into one verdict."""
    graph_versions = sbom_versions(sbom)
    present = sbom_names(sbom)
    missing = tuple(sorted(name for name in lock if name not in present))
    # Reverse containment: `missing` above catches a lock package the graph
    # DROPPED; this catches a stale package the graph KEPT after it left the
    # lock. Anything present in the graph that isn't in the lock AND isn't a
    # justified graph-only package (see `_GRAPH_ONLY_ALLOWLIST`) is
    # unexplained and must fail closed.
    unexpected = tuple(
        sorted(name for name in present if name not in lock and name not in _GRAPH_ONLY_ALLOWLIST)
    )
    # A lock package can be `present` (sbom_names counts a versionless purl)
    # while never appearing in `graph_versions` (sbom_versions excludes
    # versionless records) -- that combination means the graph carries the
    # name only as a version-less phantom, and nothing else here ever
    # demands a versioned record exist. Fail closed on it explicitly rather
    # than letting version comparison silently skip the package.
    unversioned = tuple(
        sorted(name for name in lock if name in present and name not in graph_versions)
    )
    # A package with more than one distinct version in the graph is stale on
    # its own terms -- skip it for the lock-vs-graph comparison below (its
    # ambiguity is already reported via `conflicting_versions`) rather than
    # picking one of its versions arbitrarily to compare.
    conflicting = tuple(sorted(name for name, seen in graph_versions.items() if len(seen) > 1))
    mismatches = tuple(
        sorted(
            (name, graph_versions[name][0], lock[name])
            for name in lock
            if name in graph_versions
            and len(graph_versions[name]) == 1
            and graph_versions[name][0] != lock[name]
        )
    )
    return Verdict(
        dead_channels=dead_channels(runs),
        missing_from_sbom=missing,
        version_mismatches=mismatches,
        package_count=len(present),
        min_packages=min_packages,
        unexpected_in_sbom=unexpected,
        conflicting_versions=conflicting,
        unversioned_in_sbom=unversioned,
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"fail-closed: cannot read {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit(f"fail-closed: {path} is not a JSON object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, required=True, help="fetched SBOM JSON")
    parser.add_argument("--runs", type=Path, required=True, help="channel -> conclusion JSON")
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument(
        "--min-packages",
        type=int,
        required=True,
        help="coverage floor; below this the graph is treated as not submitted",
    )
    args = parser.parse_args(argv)

    try:
        lock = tomllib.loads(args.lock.read_bytes().decode())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"fail-closed: cannot read {args.lock}: {exc}") from exc

    verdict = evaluate(
        _read_json(args.sbom),
        lock_versions(lock),
        {str(k): str(v) for k, v in _read_json(args.runs).items()},
        min_packages=args.min_packages,
    )
    print(verdict.report())
    return 0 if verdict.ok else 1


if __name__ == "__main__":
    sys.exit(main())
