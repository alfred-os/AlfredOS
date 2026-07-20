"""``alembic.ini``'s ``script_location`` resolves from an INSTALLED package, not just src/.

UAT first-run finding: ``alembic.ini`` shipped ``script_location =
src/alfred/memory/migrations``, a SOURCE-TREE-relative path. Inside the built image the
package lives at ``site-packages/alfred/memory/migrations`` and no ``src/`` directory
exists, so the documented first-run step::

    docker compose run --rm alfred-core migrate

failed outright with ``Path doesn't exist: src/alfred/memory/migrations``. Verified
against a real unpacked wheel on a path with no repo checkout.

The fix uses Alembic's package-resource form (``alfred.memory:migrations``), which
:func:`alembic.util.pyfiles.coerce_resource_to_filename` resolves through
``importlib.resources`` — so it finds the migrations wherever ``alfred.memory`` is
importable from, both layouts.

That codepath carries an explicit ``# TODO: there seem to be zero tests for the package
resource codepath`` in Alembic's own source, so we do not take it on trust: the tests
below resolve it for real and assert the migrations are actually there.
"""

from __future__ import annotations

import configparser
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

_ROOT = Path(__file__).resolve().parents[3]
_ALEMBIC_INI = _ROOT / "alembic.ini"


@pytest.fixture()
def script_location() -> str:
    parser = configparser.ConfigParser()
    parser.read(_ALEMBIC_INI)
    return parser["alembic"]["script_location"]


def test_script_location_is_not_source_tree_relative(script_location: str) -> None:
    """A ``src/``-prefixed path only exists in a checkout — the image has no ``src/``."""
    assert not script_location.startswith("src/"), (
        "script_location is source-tree-relative again; `docker compose run --rm "
        "alfred-core migrate` cannot resolve it inside the image, where the package "
        "lives under site-packages/"
    )


def test_script_location_uses_the_package_resource_form(script_location: str) -> None:
    """``package:path`` is the form Alembic resolves via importlib.resources.

    Pinned explicitly because a plain relative path would still pass the test above
    while remaining CWD-dependent.
    """
    assert ":" in script_location, (
        "script_location must use Alembic's `package:relative_path` form so it resolves "
        "from wherever the package is importable"
    )
    package, _, relative = script_location.partition(":")
    assert package == "alfred.memory"
    assert relative == "migrations"


def test_script_location_resolves_to_a_real_migrations_directory() -> None:
    """Resolve it the way Alembic does and assert the versions are present.

    This is the assertion that would have caught the original bug: the string being
    well-formed is not the same as it pointing at anything.
    """
    from alembic.util.pyfiles import coerce_resource_to_filename

    parser = configparser.ConfigParser()
    parser.read(_ALEMBIC_INI)
    resolved = coerce_resource_to_filename(parser["alembic"]["script_location"])

    assert resolved.is_dir(), f"script_location does not resolve to a directory: {resolved}"
    assert (resolved / "env.py").is_file()
    assert (resolved / "script.py.mako").is_file(), (
        "script.py.mako missing — `alembic revision` would fail even though upgrade works"
    )
    versions = resolved / "versions"
    assert versions.is_dir() and any(versions.glob("*.py"))


def test_alembic_can_build_its_script_directory_from_the_shipped_ini() -> None:
    """End-to-end: Alembic itself loads the config and finds a head revision.

    Exercises the real ``ScriptDirectory.from_config`` path rather than re-implementing
    the resolution, so a future Alembic change to that codepath surfaces here.
    """
    script = ScriptDirectory.from_config(Config(str(_ALEMBIC_INI)))
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single migration head, got {heads}"
