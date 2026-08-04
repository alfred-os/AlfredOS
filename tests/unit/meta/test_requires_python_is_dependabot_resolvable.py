"""Dependabot resolves Python at SERIES granularity (#568).

A patch-level `requires-python` makes Dependabot abort with
`tool_version_not_supported` during file fetching, which silently killed three
channels for 44 days: dependency-graph submission, Dependabot security updates,
and the weekly pip updater. BOTH files carry the specifier and BOTH are parsed
by the `uv` updater, so both are pinned here — a pyproject-only check would
report green on a repo where the fix does not work.

The two manifests hold it at DIFFERENT depths: PEP 621 puts pyproject's under
`[project]`, while uv.lock carries it at top level. The accessor path is part of
each manifest's entry rather than a shared assumption, because assuming one
shape for both makes the pyproject case permanently red.

The real floor is enforced at import by `alfred._python_floor` (ADR-0061).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]

#: Pinned to the LITERAL current series, not just its shape: a shape-only check
#: (any major.minor) stays green if both manifests drift to a new series while
#: .python-version and alfred._python_floor.FLOOR stay behind, silently
#: unguarding the declared-vs-enforced contract ADR-0061 exists to record.
#: Raising the declared series requires moving .python-version and FLOOR
#: together — bump this literal in the same change.
_SERIES_LEVEL = re.compile(r"^>=3\.14$")

#: (manifest, key path to `requires-python`). The paths differ — see the docstring.
_MANIFESTS: tuple[tuple[Path, tuple[str, ...]], ...] = (
    (Path("pyproject.toml"), ("project", "requires-python")),
    (Path("uv.lock"), ("requires-python",)),
)

_MANIFEST_IDS = [manifest.as_posix() for manifest, _ in _MANIFESTS]


def _specifier(manifest: Path, key_path: tuple[str, ...]) -> str:
    """Read `requires-python` out of `manifest` by walking `key_path`."""
    node: Any = tomllib.loads((_REPO_ROOT / manifest).read_bytes().decode())
    for key in key_path:
        assert key in node, (
            f"{manifest.as_posix()} has no {'.'.join(key_path)} — the manifest layout "
            f"changed and this pin is reading the wrong place"
        )
        node = node[key]
    assert isinstance(node, str)
    return node


@pytest.mark.parametrize(("manifest", "key_path"), _MANIFESTS, ids=_MANIFEST_IDS)
def test_requires_python_is_series_level(manifest: Path, key_path: tuple[str, ...]) -> None:
    spec = _specifier(manifest, key_path)
    assert _SERIES_LEVEL.fullmatch(spec), (
        f"{manifest.as_posix()} declares requires-python = {spec!r}, but this pin expects "
        f"exactly {_SERIES_LEVEL.pattern!r}. Either it carries a patch component — "
        f"Dependabot cannot resolve that and will abort with tool_version_not_supported, "
        f"silently killing dependency-graph submission, security updates and the weekly "
        f"pip updater (#568) — or the declared series has moved. Raising the declared "
        f"series requires moving .python-version and alfred._python_floor.FLOOR together, "
        f"per ADR-0061; update this literal in the same change."
    )


def test_both_manifests_agree() -> None:
    """A lockfile that drifts from pyproject re-breaks Dependabot silently."""
    specs = {
        manifest.as_posix(): _specifier(manifest, key_path) for manifest, key_path in _MANIFESTS
    }
    assert len(set(specs.values())) == 1, (
        f"requires-python differs between manifests: {specs}. `uv sync --frozen` returns 0 "
        f"on this mismatch, so nothing else catches it — run `uv lock`."
    )


def _series_from_specifier(spec: str) -> tuple[int, int]:
    """Parse a bare `>=X.Y` specifier — see `_SERIES_LEVEL` — into `(X, Y)`."""
    match = re.fullmatch(r">=(\d+)\.(\d+)", spec)
    assert match, f"{spec!r} is not a bare series specifier (>=X.Y)"
    return int(match.group(1)), int(match.group(2))


def _series_from_version(version: str) -> tuple[int, int]:
    """Parse a dotted version string (`.python-version`, `FLOOR`) into `(major, minor)`."""
    parts = version.split(".")
    assert len(parts) >= 2, f"{version!r} is not a dotted major.minor[.patch] version string"
    return int(parts[0]), int(parts[1])


def test_declared_series_matches_dot_python_version_and_enforced_floor() -> None:
    """The declared (Dependabot-resolvable) series and the enforced floor's
    series must never diverge — only ADR-0061's declared-vs-enforced PATCH
    gap is deliberate.

    `test_requires_python_is_series_level` and `test_both_manifests_agree`
    above only ever look at `pyproject.toml` / `uv.lock`. Neither reads
    `.python-version` or `alfred._python_floor.FLOOR`, so if the enforced
    floor's series moved (e.g. to 3.15) while both manifests stayed pinned to
    `>=3.14`, Dependabot would keep resolving an interpreter series that
    fails closed at import — `alfred._python_floor.enforce()` raises
    `UnsupportedPythonError` before AlfredOS ever runs — and nothing here
    would go red. The ENFORCED patch (3.14.6, held above the true 3.14.5
    boundary — see `FLOOR`'s docstring) is legitimately ahead of the
    declared series; that is the point of ADR-0061 and is NOT asserted here.
    """
    from alfred._python_floor import FLOOR

    manifest_series = {
        manifest.as_posix(): _series_from_specifier(_specifier(manifest, key_path))
        for manifest, key_path in _MANIFESTS
    }
    python_version_text = (_REPO_ROOT / ".python-version").read_text().strip()
    python_version_series = _series_from_version(python_version_text)
    floor_series = FLOOR[:2]

    all_series = set(manifest_series.values()) | {python_version_series, floor_series}
    assert all_series == {floor_series}, (
        f"declared manifest series {manifest_series}, .python-version series "
        f"{python_version_series} (from {python_version_text!r}), and "
        f"alfred._python_floor.FLOOR series {floor_series} must all agree on "
        f"(major, minor). A mismatch means Dependabot can resolve an interpreter "
        f"series that alfred._python_floor.enforce() refuses at import — the exact "
        f"declared/enforced divergence ADR-0061 exists to bound, not create."
    )
