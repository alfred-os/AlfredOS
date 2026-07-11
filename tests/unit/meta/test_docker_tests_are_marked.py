"""Anti-rot guard: Testcontainers usage in unit tests must be ``docker``-marked.

This is what unblocks running ``tests/unit`` on the daemon-less macOS / Windows
CI legs. The root-conftest auto-skip hook only skips ``docker``-MARKED items; an
unmarked Testcontainers file would ERROR at fixture setup and turn the macOS leg
red. Two static invariants keep the separation from silently rotting (the
maintainers' stated deferral reason), both enforced on every platform including
the Linux ``python`` job:

1. Every TEST MODULE that uses Testcontainers carries ``pytest.mark.docker``.
2. NO ``conftest.py`` under ``tests/unit`` uses Testcontainers — a conftest's
   container fixture cannot be effectively skip-marked (a ``pytestmark`` in a
   conftest does not apply to sibling modules' items), so container fixtures
   MUST live in a markable test module. This closes the "hoist the shared
   ``redis_url`` fixture into conftest" loophole that would blind invariant (1).
"""

from __future__ import annotations

import re
from pathlib import Path

_UNIT_ROOT = Path(__file__).resolve().parents[1]  # tests/unit
_META_DIR = Path(__file__).resolve().parent  # tests/unit/meta (holds pattern literals — excluded)
_REPO_ROOT = _UNIT_ROOT.parents[1]  # repo root, for readable failure paths

# Real Testcontainers usage: an import of the package, or instantiation of a
# *Container class. Prose mentions ("doesn't want testcontainers", a ``:class:``
# cross-ref) do NOT match — they are not import lines and carry no ``Container(``.
# ``_IMPORT_RE`` is the PRIMARY detector (every testcontainers file must import
# the package, whatever the container class); ``_CONTAINER_RE`` is a secondary
# belt-and-suspenders for the common container classes (an incomplete allowlist
# is fine because the import line is the real signal).
_IMPORT_RE = re.compile(r"^\s*(from|import)\s+testcontainers\b", re.MULTILINE)
_CONTAINER_RE = re.compile(
    r"\b(?:Redis|Postgres|Mongo|Kafka|MySql|MariaDb|RabbitMq|ElasticSearch"
    r"|Neo4j|Mssql|ClickHouse|LocalStack|Nginx|Docker|Generic)Container\s*\("
)
# ``_MARK_RE`` must match a real MODULE-LEVEL ``pytestmark = … mark.docker``
# assignment, NOT a bare ``mark.docker`` substring — else a comment/docstring
# mention (``# TODO: add pytest.mark.docker``) would read as "marked" and the
# unmarked file would ERROR on the daemon-less legs, defeating this guard. The
# line-start anchor excludes ``#``-comment lines. (Single-line assignment per the
# repo's module-mark convention; a multi-line list assignment is not used.)
_MARK_RE = re.compile(r"^\s*pytestmark\s*(?::[^=\n]+)?=.*\bmark\.docker\b", re.MULTILINE)


def _uses_testcontainers(src: str) -> bool:
    return bool(_IMPORT_RE.search(src)) or bool(_CONTAINER_RE.search(src))


def _is_docker_marked(src: str) -> bool:
    return bool(_MARK_RE.search(src))


def find_unmarked_docker_files(unit_root: Path, *, exclude: Path) -> list[Path]:
    """Return TEST MODULES that use Testcontainers but lack the ``docker`` marker."""
    offenders: list[Path] = []
    for path in sorted(unit_root.rglob("*.py")):
        if path.name == "conftest.py":
            continue  # conftests are handled by find_testcontainers_conftests
        if path.parent == exclude or exclude in path.parents:
            continue
        src = path.read_text(encoding="utf-8")
        if _uses_testcontainers(src) and not _is_docker_marked(src):
            offenders.append(path)
    return offenders


def find_testcontainers_conftests(unit_root: Path) -> list[Path]:
    """Return ``conftest.py`` files under ``unit_root`` that use Testcontainers."""
    return [
        path
        for path in sorted(unit_root.rglob("conftest.py"))
        if _uses_testcontainers(path.read_text(encoding="utf-8"))
    ]


def test_all_testcontainers_unit_files_are_docker_marked() -> None:
    offenders = find_unmarked_docker_files(_UNIT_ROOT, exclude=_META_DIR)
    assert offenders == [], (
        "These unit files use Testcontainers but are not `docker`-marked, so they "
        "would ERROR (not skip) on the daemon-less macOS/Windows CI legs. Add a "
        "module-level `pytestmark = pytest.mark.docker` to each:\n"
        + "\n".join(f"  - {p.relative_to(_REPO_ROOT)}" for p in offenders)
    )


def test_no_testcontainers_in_unit_conftests() -> None:
    offenders = find_testcontainers_conftests(_UNIT_ROOT)
    assert offenders == [], (
        "These conftest.py files use Testcontainers. A conftest's container "
        "fixture cannot be skip-marked (a `pytestmark` in a conftest does not "
        "apply to sibling modules' items), so it would ERROR on the daemon-less "
        "macOS/Windows legs with no way to skip it. Move the container fixture "
        "into a `docker`-marked test module instead:\n"
        + "\n".join(f"  - {p.relative_to(_REPO_ROOT)}" for p in offenders)
    )


def test_guard_flags_unmarked_synthetic_file(tmp_path: Path) -> None:
    (tmp_path / "test_bad.py").write_text(
        "from testcontainers.redis import RedisContainer\n\n"
        "def test_x() -> None:\n    RedisContainer('redis:8')\n",
        encoding="utf-8",
    )
    offenders = find_unmarked_docker_files(tmp_path, exclude=tmp_path / "nonexistent")
    assert [p.name for p in offenders] == ["test_bad.py"]


def test_guard_passes_marked_synthetic_file(tmp_path: Path) -> None:
    (tmp_path / "test_good.py").write_text(
        "import pytest\nfrom testcontainers.redis import RedisContainer\n\n"
        "pytestmark = pytest.mark.docker\n\n"
        "def test_x() -> None:\n    RedisContainer('redis:8')\n",
        encoding="utf-8",
    )
    offenders = find_unmarked_docker_files(tmp_path, exclude=tmp_path / "nonexistent")
    assert offenders == []


def test_guard_ignores_prose_mention(tmp_path: Path) -> None:
    (tmp_path / "test_prose.py").write_text(
        '"""This test uses a double rather than testcontainers Postgres."""\n\n'
        "def test_x() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    offenders = find_unmarked_docker_files(tmp_path, exclude=tmp_path / "nonexistent")
    assert offenders == []


def test_guard_flags_testcontainers_conftest(tmp_path: Path) -> None:
    (tmp_path / "conftest.py").write_text(
        "import pytest\nfrom testcontainers.redis import RedisContainer\n\n"
        "@pytest.fixture\ndef redis_url():\n"
        "    with RedisContainer('redis:8') as r:\n        yield r\n",
        encoding="utf-8",
    )
    offenders = find_testcontainers_conftests(tmp_path)
    assert [p.name for p in offenders] == ["conftest.py"]


def test_guard_flags_file_that_only_mentions_the_mark(tmp_path: Path) -> None:
    """A comment/docstring mention of ``mark.docker`` must NOT read as marked.

    This is the load-bearing false-negative the anti-rot guard must not have:
    the file uses Testcontainers but only *mentions* the marker in a comment, so
    it is genuinely unmarked and would ERROR on the daemon-less legs — the guard
    MUST flag it.
    """
    (tmp_path / "test_mention_only.py").write_text(
        "from testcontainers.redis import RedisContainer\n\n"
        "# TODO: add pytestmark = pytest.mark.docker to this module\n\n"
        "def test_x() -> None:\n    RedisContainer('redis:8')\n",
        encoding="utf-8",
    )
    offenders = find_unmarked_docker_files(tmp_path, exclude=tmp_path / "nonexistent")
    assert [p.name for p in offenders] == ["test_mention_only.py"]


def test_guard_marks_list_assignment_with_docker(tmp_path: Path) -> None:
    """A real ``pytestmark = [pytest.mark.integration, pytest.mark.docker]`` counts."""
    (tmp_path / "test_listmark.py").write_text(
        "import pytest\nfrom testcontainers.redis import RedisContainer\n\n"
        "pytestmark = [pytest.mark.integration, pytest.mark.docker]\n\n"
        "def test_x() -> None:\n    RedisContainer('redis:8')\n",
        encoding="utf-8",
    )
    offenders = find_unmarked_docker_files(tmp_path, exclude=tmp_path / "nonexistent")
    assert offenders == []
