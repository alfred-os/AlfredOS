"""The monitor must not pass on a degenerate SBOM (#568).

Draft 1's algorithm passed on FOUR of these five inputs. The zero-pypi case is
literally #568 recurring: the channel dies, the graph serves nothing, and a
content-only monitor reports clean.

`scripts/` is not a package — the subject is loaded with
`spec_from_file_location`, matching the `runner` fixture in this directory's
conftest.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "dependency_graph"
_SCRIPT = _REPO_ROOT / "scripts" / "check_dependency_graph_freshness.py"


@pytest.fixture(scope="session")
def freshness() -> ModuleType:
    """Load `scripts/check_dependency_graph_freshness.py` — a script, not a package."""
    spec = importlib.util.spec_from_file_location("check_dependency_graph_freshness", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HEALTHY_RUNS = {"dependency-graph": "success", "dependabot-updates": "success"}
_LOCK = {"aiohttp": "3.14.3", "gitpython": "3.1.57", "certifi": "2026.7.1"}


def _sbom(*packages: tuple[str, str | None]) -> dict[str, Any]:
    return {
        "sbom": {
            "packages": [
                {
                    "name": name,
                    "versionInfo": version,
                    "externalRefs": [
                        {
                            "referenceLocator": (
                                f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
                            )
                        }
                    ],
                }
                for name, version in packages
            ]
        }
    }


class TestDegenerateSbomsMustFail:
    def test_empty_sbom_fails(self, freshness: ModuleType) -> None:
        verdict = freshness.evaluate(_sbom(), _LOCK, _HEALTHY_RUNS, min_packages=50)
        assert not verdict.ok

    def test_sbom_with_no_pypi_packages_fails(self, freshness: ModuleType) -> None:
        """The #568 shape: the channel dies and the graph serves nothing."""
        sbom = {"sbom": {"packages": [{"name": "actions/checkout", "externalRefs": []}]}}
        verdict = freshness.evaluate(sbom, _LOCK, _HEALTHY_RUNS, min_packages=50)
        assert not verdict.ok

    def test_dropped_package_fails_via_containment(self, freshness: ModuleType) -> None:
        fresh = tuple((name, version) for name, version in _LOCK.items() if name != "aiohttp")
        verdict = freshness.evaluate(_sbom(*fresh), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert not verdict.ok
        assert "aiohttp" in verdict.missing_from_sbom

    def test_stale_version_fails(self, freshness: ModuleType) -> None:
        stale = (("aiohttp", "3.13.5"), ("gitpython", "3.1.57"), ("certifi", "2026.7.1"))
        verdict = freshness.evaluate(_sbom(*stale), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert not verdict.ok
        assert ("aiohttp", "3.13.5", "3.14.3") in verdict.version_mismatches


class TestCoverageFloor:
    def test_a_too_small_but_otherwise_perfect_sbom_fails(self, freshness: ModuleType) -> None:
        """Isolates the coverage floor from containment.

        Every OTHER degenerate case also trips containment, and containment alone
        is sufficient to fail — so without this test, deleting the coverage floor
        is undetectable (proven by mutation). This SBOM carries every lock package
        at the right version, so containment and version comparison are both
        clean; it fails only because the graph is too small to be a plausible
        submission.
        """
        verdict = freshness.evaluate(_sbom(*_LOCK.items()), _LOCK, _HEALTHY_RUNS, min_packages=50)
        assert not verdict.ok
        assert verdict.package_count == len(_LOCK)
        assert not verdict.missing_from_sbom, (
            "containment must be clean or the floor is not isolated"
        )
        assert not verdict.version_mismatches, "versions must match or the floor is not isolated"


class TestPhantomRecords:
    def test_version_less_duplicates_do_not_cause_false_drift(self, freshness: ModuleType) -> None:
        """`textual` and `alfred` appear twice in the live SBOM, once with no version.

        Keying off a naive {name: version} map yields None and a monitor that can
        never go green.
        """
        packages = (
            ("aiohttp", "3.14.3"),
            ("aiohttp", None),
            ("gitpython", "3.1.57"),
            ("certifi", "2026.7.1"),
        )
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert verdict.ok, f"phantom record caused false drift: {verdict.version_mismatches}"


class TestLivenessIsPrimary:
    def test_a_dead_channel_fails_even_when_content_matches(self, freshness: ModuleType) -> None:
        """The lagging-signal problem: content can match while the channel is dead."""
        runs = {**_HEALTHY_RUNS, "dependabot-updates": "failure"}
        verdict = freshness.evaluate(_sbom(*_LOCK.items()), _LOCK, runs, min_packages=2)
        assert not verdict.ok
        assert "dependabot-updates" in verdict.dead_channels

    def test_a_missing_channel_conclusion_fails_closed(self, freshness: ModuleType) -> None:
        """Absent must never read as success."""
        verdict = freshness.evaluate(_sbom(*_LOCK.items()), _LOCK, {}, min_packages=2)
        assert not verdict.ok


class TestHealthyRepo:
    def test_all_signals_green_passes(self, freshness: ModuleType) -> None:
        verdict = freshness.evaluate(_sbom(*_LOCK.items()), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert verdict.ok


# ---------------------------------------------------------------------------
# CodeRabbit round 1 (#569): two fail-opens that both let the monitor report
# HEALTHY while blind, the exact class this script exists to catch.
#
#   Bug A: `evaluate()` only ever checked lock-not-in-graph (a DROPPED
#   package). The reverse -- a graph package that isn't in the lock -- was
#   never checked, so a graph carrying every current lock package PLUS stale
#   leftovers passed every existing guard.
#
#   Bug B: `sbom_versions()` did `versions[name] = version` -- last write
#   wins -- so two versioned purls for the same package resolved by document
#   order. Identical SBOM content in a different record order could flip the
#   verdict.
# ---------------------------------------------------------------------------


class TestReverseContainmentBugA:
    """A stale package the graph KEPT after it left `uv.lock` must fail --
    not just a package the graph DROPPED (already covered above)."""

    def test_graph_only_stale_extra_fails_and_is_named(self, freshness: ModuleType) -> None:
        """All lock packages present, correct versions, PLUS one stale extra
        (`requests`, not in `_GRAPH_ONLY_ALLOWLIST`) that pre-#569 sailed
        through every existing guard: liveness, coverage floor, containment
        (lock-in-graph direction only), and version checks were all clean."""
        packages = (*_LOCK.items(), ("requests", "2.32.0"))
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert not verdict.ok
        assert verdict.unexpected_in_sbom == ("requests",)
        assert "requests" in verdict.report()

    def test_allowlisted_graph_only_package_passes(self, freshness: ModuleType) -> None:
        """`click` is a real, justified graph-only leftover (see
        `_GRAPH_ONLY_ALLOWLIST`'s module comment) -- its presence alone must
        NOT fail the guard. Without this test, replacing the allowlist check
        with a blanket "fail on anything extra" would still pass every other
        test in this file."""
        packages = (*_LOCK.items(), ("click", "8.4.1"))
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert verdict.ok
        assert verdict.unexpected_in_sbom == ()


class TestConflictingVersionsBugB:
    """Two versioned purls for the same package must fail regardless of
    which record the document lists first -- not resolve by document order."""

    def test_conflicting_duplicate_versions_fail_stale_first(self, freshness: ModuleType) -> None:
        packages = (
            ("aiohttp", "3.13.5"),  # stale record first
            ("aiohttp", "3.14.3"),  # fresh record second
            ("gitpython", "3.1.57"),
            ("certifi", "2026.7.1"),
        )
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert not verdict.ok
        assert verdict.conflicting_versions == ("aiohttp",)
        assert "conflicting versions in graph: aiohttp" in verdict.report()

    def test_conflicting_duplicate_versions_fail_fresh_first(self, freshness: ModuleType) -> None:
        """Same data, reversed order. Pre-#569, this order combination was
        the one that (wrongly) reported healthy -- last-write-wins landed on
        the fresh record. The verdict must not depend on which record the
        document happens to list first."""
        packages = (
            ("aiohttp", "3.14.3"),  # fresh record first
            ("aiohttp", "3.13.5"),  # stale record second
            ("gitpython", "3.1.57"),
            ("certifi", "2026.7.1"),
        )
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert not verdict.ok
        assert verdict.conflicting_versions == ("aiohttp",)

    def test_phantom_alongside_real_record_still_passes(self, freshness: ModuleType) -> None:
        """A version-less phantom duplicate (see `TestPhantomRecords` above)
        next to ONE real versioned record is not a conflict -- there is only
        one distinct version -- and must not regress into a false failure
        now that duplicate handling changed."""
        packages = (
            ("aiohttp", "3.14.3"),
            ("aiohttp", None),  # phantom: excluded from sbom_versions entirely
            ("gitpython", "3.1.57"),
            ("certifi", "2026.7.1"),
        )
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert verdict.ok, f"phantom record caused a false conflict: {verdict.conflicting_versions}"
        assert verdict.conflicting_versions == ()


# ---------------------------------------------------------------------------
# CodeRabbit round 4 (#569): versionless-only purls let the monitor report
# healthy without proving ANY version. `sbom_names()` counts a versionless
# purl as present (containment passes); `sbom_versions()` excludes versionless
# records from version comparison entirely (so it never runs). Nothing ever
# demanded a VERSIONED record exist -- a graph in which every lock package
# appears only as a versionless purl passed everything. See
# `Verdict.unversioned_in_sbom`.
# ---------------------------------------------------------------------------


class TestUnversionedOnlyPurlsBugRound4:
    def test_lock_package_with_only_a_versionless_purl_fails_and_is_named(
        self, freshness: ModuleType
    ) -> None:
        """`aiohttp` appears in the graph exactly once, with no `@version` at
        all -- not a phantom duplicate alongside a real record (that is
        `TestPhantomRecords`/`TestConflictingVersionsBugB`'s case and must
        stay healthy), the *only* record for the name. Pre-fix this passed:
        containment saw the name as present, and version comparison silently
        skipped it because `sbom_versions()` never recorded a version."""
        packages = (
            ("aiohttp", None),
            ("gitpython", "3.1.57"),
            ("certifi", "2026.7.1"),
        )
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert not verdict.ok
        assert verdict.unversioned_in_sbom == ("aiohttp",)
        assert "aiohttp" in verdict.report()

    def test_versionless_duplicate_alongside_a_versioned_record_still_passes(
        self, freshness: ModuleType
    ) -> None:
        """Extends `TestPhantomRecords`: the real SBOM's `textual`/`alfred`
        shape (a versionless duplicate coexisting with a versioned record for
        the same name) must NOT trip the new guard -- only a name with no
        versioned record anywhere is unversioned-only."""
        packages = (
            ("aiohttp", "3.14.3"),
            ("aiohttp", None),  # versionless duplicate of a name that IS versioned elsewhere
            ("gitpython", "3.1.57"),
            ("certifi", "2026.7.1"),
        )
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert verdict.ok, (
            f"legitimate phantom flagged as unversioned: {verdict.unversioned_in_sbom}"
        )
        assert verdict.unversioned_in_sbom == ()


class TestAgainstTheRealFrozenGraph:
    def test_the_committed_stale_fixture_is_detected(self, freshness: ModuleType) -> None:
        """The real 2026-06-19 graph must be reported stale, forever.

        The live signal evaporates on merge; this fixture is what keeps the
        negative case executable.
        """
        sbom = json.loads((_FIXTURES / "sbom_stale_2026-06-19.json").read_text())
        lock = {"aiohttp": "3.14.3", "gitpython": "3.1.57", "pydantic-settings": "2.14.2"}
        verdict = freshness.evaluate(sbom, lock, _HEALTHY_RUNS, min_packages=50)
        assert not verdict.ok
        assert any(name == "aiohttp" for name, _, _ in verdict.version_mismatches)
        # The real document's only versionless-only record is `hatchling`
        # (a build-system dependency, never in `uv.lock`) -- the round-4
        # guard must not invent a NEW failure reason against this fixture.
        assert verdict.unversioned_in_sbom == ()


# ---------------------------------------------------------------------------
# #568 Task 6: the CLI shell. `evaluate()` and its helpers were mutation-tested
# by the classes above; `report()`'s formatting, `lock_versions()`'s
# self-package/versionless-entry branch, `_read_json()`'s fail-closed paths and
# `main()`'s argparse wiring were not — measured 59% unit-only on 2026-08-05,
# the exact surface Task 5 left omitted in pyproject.toml pending a caller.
# This task IS that caller (the ci.yml gate step added alongside these tests),
# so the omit entry comes out and this surface must reach 100% line+branch.
# ---------------------------------------------------------------------------


class TestReportFormatting:
    """`Verdict.report()` — never exercised by the classes above, which only
    ever inspect `.ok` / individual fields, not the printed message."""

    def test_healthy_report_names_the_package_count(self, freshness: ModuleType) -> None:
        verdict = freshness.Verdict(
            dead_channels=(),
            missing_from_sbom=(),
            version_mismatches=(),
            package_count=10,
            min_packages=5,
        )
        assert verdict.report() == "dependency graph healthy: 10 pypi packages, all channels live"

    def test_dead_channels_line_and_nothing_else(self, freshness: ModuleType) -> None:
        verdict = freshness.Verdict(
            dead_channels=("dependency-graph",),
            missing_from_sbom=(),
            version_mismatches=(),
            package_count=10,
            min_packages=5,
        )
        report = verdict.report()
        assert report.splitlines() == [
            "dependency graph UNHEALTHY:",
            "  dead channels: dependency-graph",
        ]

    def test_coverage_floor_line_and_nothing_else(self, freshness: ModuleType) -> None:
        verdict = freshness.Verdict(
            dead_channels=(),
            missing_from_sbom=(),
            version_mismatches=(),
            package_count=3,
            min_packages=50,
        )
        report = verdict.report()
        assert report.splitlines() == [
            "dependency graph UNHEALTHY:",
            "  coverage floor: 3 pypi packages < 50",
        ]

    def test_missing_from_sbom_line_and_nothing_else(self, freshness: ModuleType) -> None:
        verdict = freshness.Verdict(
            dead_channels=(),
            missing_from_sbom=("aiohttp",),
            version_mismatches=(),
            package_count=10,
            min_packages=5,
        )
        report = verdict.report()
        assert report.splitlines() == [
            "dependency graph UNHEALTHY:",
            "  absent from graph: aiohttp",
        ]

    def test_version_mismatch_lines_and_nothing_else(self, freshness: ModuleType) -> None:
        verdict = freshness.Verdict(
            dead_channels=(),
            missing_from_sbom=(),
            version_mismatches=(("aiohttp", "3.13.5", "3.14.3"),),
            package_count=10,
            min_packages=5,
        )
        report = verdict.report()
        assert report.splitlines() == [
            "dependency graph UNHEALTHY:",
            "  aiohttp: graph 3.13.5 vs lock 3.14.3",
        ]

    def test_every_unhealthy_reason_stacks_in_one_report(self, freshness: ModuleType) -> None:
        """All four sections can co-occur; order is dead/floor/missing/mismatch."""
        verdict = freshness.Verdict(
            dead_channels=("dependabot-updates",),
            missing_from_sbom=("gitpython",),
            version_mismatches=(("aiohttp", "3.13.5", "3.14.3"),),
            package_count=1,
            min_packages=50,
        )
        report = verdict.report()
        assert report.splitlines() == [
            "dependency graph UNHEALTHY:",
            "  dead channels: dependabot-updates",
            "  coverage floor: 1 pypi packages < 50",
            "  absent from graph: gitpython",
            "  aiohttp: graph 3.13.5 vs lock 3.14.3",
        ]


class TestLockVersionsSelfAndVersionlessEntries:
    """`lock_versions()` is called by `main()` on a real `uv.lock`; the
    existing tests above hand `evaluate()` a plain dict and never exercise the
    parser itself."""

    def test_self_package_and_versionless_entries_are_excluded(self, freshness: ModuleType) -> None:
        lock = {
            "package": [
                {"name": "alfred", "version": "0.0.1"},  # excluded: self package
                {"name": "textual"},  # excluded: no version key
                {"name": "aiohttp", "version": "3.14.3"},  # included
            ]
        }
        assert freshness.lock_versions(lock) == {"aiohttp": "3.14.3"}

    def test_empty_package_list_yields_empty_map(self, freshness: ModuleType) -> None:
        assert freshness.lock_versions({"package": []}) == {}


class TestReadJsonFailClosed:
    def test_missing_file_fails_closed(self, freshness: ModuleType, tmp_path: Path) -> None:
        missing = tmp_path / "missing.json"
        with pytest.raises(SystemExit, match=re.escape(f"fail-closed: cannot read {missing}")):
            freshness._read_json(missing)

    def test_malformed_json_fails_closed(self, freshness: ModuleType, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        with pytest.raises(SystemExit, match="fail-closed: cannot read"):
            freshness._read_json(bad)

    def test_non_object_json_fails_closed(self, freshness: ModuleType, tmp_path: Path) -> None:
        """A JSON array is valid JSON but not the object shape callers need."""
        array = tmp_path / "array.json"
        array.write_text("[1, 2, 3]")
        with pytest.raises(SystemExit, match="is not a JSON object"):
            freshness._read_json(array)

    def test_valid_object_round_trips(self, freshness: ModuleType, tmp_path: Path) -> None:
        obj = tmp_path / "obj.json"
        obj.write_text(json.dumps({"a": 1}))
        assert freshness._read_json(obj) == {"a": 1}


def _write_lock(tmp_path: Path, packages: tuple[tuple[str, str], ...]) -> Path:
    lines = ["version = 1"]
    for name, version in packages:
        lines.append("[[package]]")
        lines.append(f'name = "{name}"')
        lines.append(f'version = "{version}"')
    lock_path = tmp_path / "uv.lock"
    lock_path.write_text("\n".join(lines))
    return lock_path


class TestMainCli:
    """`main()` — the argv-in, exit-code-out shell the workflow step invokes."""

    def test_healthy_inputs_exit_zero_and_print_the_report(
        self, freshness: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sbom_path = tmp_path / "sbom.json"
        runs_path = tmp_path / "runs.json"
        sbom_path.write_text(json.dumps(_sbom(("aiohttp", "3.14.3"))))
        runs_path.write_text(json.dumps(_HEALTHY_RUNS))
        lock_path = _write_lock(tmp_path, (("aiohttp", "3.14.3"),))

        rc = freshness.main(
            [
                "--sbom",
                str(sbom_path),
                "--runs",
                str(runs_path),
                "--lock",
                str(lock_path),
                "--min-packages",
                "1",
            ]
        )

        assert rc == 0
        assert "healthy" in capsys.readouterr().out

    def test_unhealthy_inputs_exit_one_and_print_the_report(
        self, freshness: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sbom_path = tmp_path / "sbom.json"
        runs_path = tmp_path / "runs.json"
        sbom_path.write_text(json.dumps(_sbom()))
        runs_path.write_text(json.dumps(_HEALTHY_RUNS))
        lock_path = _write_lock(tmp_path, ())

        rc = freshness.main(
            [
                "--sbom",
                str(sbom_path),
                "--runs",
                str(runs_path),
                "--lock",
                str(lock_path),
                "--min-packages",
                "50",
            ]
        )

        assert rc == 1
        assert "UNHEALTHY" in capsys.readouterr().out

    def test_missing_lock_file_fails_closed(self, freshness: ModuleType, tmp_path: Path) -> None:
        sbom_path = tmp_path / "sbom.json"
        runs_path = tmp_path / "runs.json"
        sbom_path.write_text(json.dumps(_sbom()))
        runs_path.write_text(json.dumps(_HEALTHY_RUNS))

        with pytest.raises(SystemExit, match="fail-closed: cannot read"):
            freshness.main(
                [
                    "--sbom",
                    str(sbom_path),
                    "--runs",
                    str(runs_path),
                    "--lock",
                    str(tmp_path / "missing.lock"),
                    "--min-packages",
                    "1",
                ]
            )

    def test_malformed_lock_file_fails_closed(self, freshness: ModuleType, tmp_path: Path) -> None:
        sbom_path = tmp_path / "sbom.json"
        runs_path = tmp_path / "runs.json"
        sbom_path.write_text(json.dumps(_sbom()))
        runs_path.write_text(json.dumps(_HEALTHY_RUNS))
        lock_path = tmp_path / "bad.lock"
        lock_path.write_text("not valid toml {{{")

        with pytest.raises(SystemExit, match="fail-closed: cannot read"):
            freshness.main(
                [
                    "--sbom",
                    str(sbom_path),
                    "--runs",
                    str(runs_path),
                    "--lock",
                    str(lock_path),
                    "--min-packages",
                    "1",
                ]
            )
