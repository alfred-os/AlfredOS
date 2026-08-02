"""#555 — a ``subprocess`` call may not decode its output with the platform locale.

``text=True`` (and its older spelling ``universal_newlines=True``) with no
``encoding=`` decodes with :func:`locale.getpreferredencoding` — UTF-8 on every
dev box and both POSIX CI legs, **cp1252 on the ``windows-latest`` runner**.
Five byte values (``0x81 0x8d 0x8f 0x90 0x9d``) have no cp1252 mapping, so any
captured output carrying one of them raises ``UnicodeDecodeError`` there and
nowhere else. Forty tracked files in this repo contain such a byte today —
``PRD.md`` among them, via ``┐`` U+2510.

Why this is a *guard* and not just 100 fixed call sites: the failure is
invisible on the machine you write the code on. #555 fixed all 100; call 101
would reintroduce the class with every local gate green. The repo's recurring
lesson (#518, #536, #538) is to **default-deny the axis, not fix N spellings**.

Why it is worse on Windows than a plain crash. ``Popen._communicate`` reads
each pipe on a ``_readerthread`` there::

    def _readerthread(self, fh, buffer):
        buffer.append(fh.read())      # <- UnicodeDecodeError kills the THREAD
        fh.close()
    ...
    stdout = stdout[0] if stdout else None   # <- buffer empty, so stdout is None

The decode error survives only as a stray thread traceback; the caller sees
``AttributeError: 'NoneType' object has no attribute 'splitlines'``. So the bug
is both Windows-only *and* self-misdiagnosing — which is how it burned a review
cycle on #553 before being filed as #555. POSIX decodes on the main thread and
raises properly.

**The remedy is ``encoding="utf-8", errors="surrogateescape"``** — the codec
pair ``scripts/check_tag_t3.py::_git_tracked_python_files`` already uses
deliberately. ``surrogateescape`` never raises on odd bytes and round-trips
them back out unchanged, so it is strictly better than a crash for output the
caller only ever logs, greps or splits.

What this guard deliberately does **not** decide:

* **It checks that ``encoding=`` is present, not what it says.** An explicit
  ``encoding=locale.getpreferredencoding()`` would pass. That is a deliberate,
  visible act at the call site; implicitness is the axis being closed.
* **It does not require ``errors=``.** ``encoding="utf-8"`` alone still raises
  on non-UTF-8 bytes (a ``git show`` of a latin-1 blob, say). All 100 sites
  carry ``errors="surrogateescape"`` today; promoting that to a hard rule is a
  second axis and a separate decision, not a silent widening of this one.
* **It is name-based, so it over-approximates.** Any callee spelled ``run``,
  ``Popen``, ``check_output`` or ``check_call`` is in scope, not only
  ``subprocess.*``. That is the point: aliasing (``from subprocess import run``,
  ``sp = subprocess``, a thin local wrapper re-exported under the same name)
  is exactly how a keyed rule gets bypassed. There is no allowlist, on purpose.
  Today the over-approximation costs nothing — all 100 matches are literally
  ``subprocess.run``/``subprocess.Popen``.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path
from typing import Final, NamedTuple

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]

# The subprocess entry points that accept `text=`/`universal_newlines=`.
_SUBPROCESS_CALLEES: Final[frozenset[str]] = frozenset(
    {"run", "Popen", "check_output", "check_call"}
)

# Both spellings of "give me str, not bytes". `universal_newlines` is the
# pre-3.7 name and is still a live alias, so a rule keyed only on `text` is
# one `git commit` away from being bypassed.
_TEXT_MODE_KWARGS: Final[frozenset[str]] = frozenset({"text", "universal_newlines"})

# Anti-vacuity floors. A guard that passes by scanning nothing is worse than no
# guard: it reports green while measuring zero. Both numbers are asserted INSIDE
# the main test, not only in a sibling — a floor in a separate test still leaves
# the main assertion able to pass on an empty walk.
_MIN_FILES_SCANNED: Final = 900  # 1211 tracked .py at the time of writing
_MIN_CONFORMING_CALLS: Final = 80  # 100 at the time of writing


class _Scan(NamedTuple):
    """The outcome of walking one or more modules for text-mode subprocess calls."""

    violations: tuple[str, ...]
    """``path:lineno`` for every text-mode call with no explicit ``encoding=``."""

    conforming: int
    """Count of text-mode calls that DO pass ``encoding=``."""


def _scan_source(source: str, label: str) -> _Scan:
    """Classify every text-mode subprocess call in one module's source.

    Split out from the repo walk so the positive and negative controls below can
    drive the *same* predicate the repo-wide assertion uses. A control that
    exercised a re-implementation would prove nothing about the real gate.
    """
    violations: list[str] = []
    conforming = 0
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            name: str | None = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        else:
            name = None
        if name not in _SUBPROCESS_CALLEES:
            continue
        keywords = {kw.arg for kw in node.keywords if kw.arg}
        if not (_TEXT_MODE_KWARGS & keywords):
            continue  # bytes mode — no decoding happens, nothing to pin
        if "encoding" in keywords:
            conforming += 1
        else:
            violations.append(f"{label}:{node.lineno}")
    return _Scan(tuple(violations), conforming)


def _git_tracked_python_files() -> list[Path]:
    """Every ``.py`` file git knows about, as repo-relative paths.

    ``git ls-files`` rather than a filesystem walk, for the reasons
    ``scripts/check_tag_t3.py`` documents at length: a file that is not tracked
    cannot land in a PR, gitignored trees (the vendored ``plugins/alfred_tui/
    .venv``) disappear without anyone maintaining a skip list, and a symlinked
    package directory cannot hide its subtree from ``git`` the way it can from
    ``Path.rglob``.

    ``--others --exclude-standard`` is load-bearing: ``--cached`` alone lists the
    INDEX, so a brand-new, not-yet-``git add``ed file would be invisible to the
    local ``make check`` loop — precisely where the author needs the gate to
    speak. CI scans a committed ref, so the loss would have been local-only and
    therefore silent.

    Unlike ``check_tag_t3.py`` this fails LOUD rather than falling back to a
    filesystem walk. A test has no operator to warn, and "git could not answer"
    must not read as "clean".
    """
    # Inline-literal argv, no shell, no user-controlled executable — so S603
    # (untrusted input) does not fire here and only S607 (partial path) needs a
    # suppression. The two codes are reported on DIFFERENT lines, so a single
    # combined directive on the call line would suppress neither.
    proc = subprocess.run(
        [  # noqa: S607 — git is resolved from PATH by design; no user input
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "*.py",
        ],
        capture_output=True,
        check=True,
        cwd=_REPO_ROOT,
    )
    # Bytes + explicit decode rather than `text=True`: `-z` output is NUL
    # separated, and this mirrors the codec pair the gate mandates without the
    # gate having to depend on its own subject. A path git stores as non-UTF-8
    # bytes round-trips through `surrogateescape` instead of killing the walk.
    names = proc.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    # `--cached` also lists index entries whose working-tree file is gone (an
    # unstaged deletion). Those cannot hold a violation.
    return [p for name in names if name and (p := _REPO_ROOT / name).is_file()]


def test_no_subprocess_call_decodes_with_the_platform_locale() -> None:
    """Every text-mode subprocess call in the repo names its codec explicitly."""
    files = _git_tracked_python_files()

    # Anti-vacuity, part 1: the walk found the repo. `git ls-files` exits 0 with
    # empty output for an ignored, absent or submodule path, so an empty scan
    # root is otherwise indistinguishable from a clean one.
    assert len(files) >= _MIN_FILES_SCANNED, (
        f"only {len(files)} tracked .py files found (floor {_MIN_FILES_SCANNED}) — "
        "this gate is measuring nothing; check the git invocation, not the codebase"
    )

    violations: list[str] = []
    conforming = 0
    for path in files:
        result = _scan_source(
            path.read_text(encoding="utf-8"), path.relative_to(_REPO_ROOT).as_posix()
        )
        violations.extend(result.violations)
        conforming += result.conforming

    # Anti-vacuity, part 2: the predicate is still able to RECOGNISE a text-mode
    # subprocess call. Without this, gutting the classifier so it matches nothing
    # would leave `violations` empty and the assertion below green.
    assert conforming >= _MIN_CONFORMING_CALLS, (
        f"only {conforming} conforming text-mode subprocess calls found "
        f"(floor {_MIN_CONFORMING_CALLS}) — the detector has stopped recognising "
        "the shape it exists to police"
    )

    assert not violations, (
        f"{len(violations)} subprocess call(s) pass text=True/universal_newlines=True "
        "with no explicit encoding=, so they decode with the platform locale — cp1252 "
        "on the windows-latest runner, where a byte such as 0x90 kills the pipe "
        "reader thread and the caller sees AttributeError on None (#555).\n"
        'Remedy: add encoding="utf-8", errors="surrogateescape" to each call.\n'
        "Offenders:\n  " + "\n  ".join(violations)
    )


def test_detector_trips_on_a_synthetic_violation() -> None:
    """Positive control — the detector can tell a violation from a conforming call.

    An assertion that cannot distinguish fixed from broken is worse than none.
    This is the mutation the repo-wide test can no longer make on its own, now
    that the repo is clean: without it, a classifier that unconditionally counted
    every call as conforming would satisfy both floors above and never fail.
    """
    source = "import subprocess\nsubprocess.run(['git', 'status'], text=True)\n"
    result = _scan_source(source, "<synthetic>")
    assert result.violations == ("<synthetic>:2",)
    assert result.conforming == 0


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        pytest.param(
            "import subprocess\n"
            "subprocess.run(['git'], text=True, encoding='utf-8', errors='surrogateescape')\n",
            "the remedied shape",
            id="text-plus-encoding",
        ),
        pytest.param(
            "import subprocess\nsubprocess.run(['git'], capture_output=True)\n",
            "bytes mode decodes nothing",
            id="bytes-mode",
        ),
        pytest.param(
            "import subprocess\n"
            "subprocess.run(['git'], universal_newlines=True, encoding='utf-8')\n",
            "the legacy spelling, remedied",
            id="universal-newlines-plus-encoding",
        ),
    ],
)
def test_detector_does_not_trip_on_a_conforming_call(source: str, reason: str) -> None:
    """Negative control — the detector is not simply flagging everything."""
    result = _scan_source(source, "<synthetic>")
    assert not result.violations, f"false positive on {reason}"


def test_detector_sees_through_the_legacy_kwarg_and_a_bare_import() -> None:
    """Both bypass spellings the rule is keyed to survive.

    ``universal_newlines=True`` is the pre-3.7 alias for ``text=True``, and
    ``from subprocess import run`` drops the module qualifier. A rule keyed on
    ``subprocess.run(..., text=True)`` alone would miss both — the shape this
    repo has already been bitten by (see the alias-resolution lesson in #538).
    """
    source = (
        "from subprocess import run\n"
        "run(['git', 'log'], universal_newlines=True)\n"
        "import subprocess\n"
        "subprocess.Popen(['git', 'log'], text=True)\n"
    )
    result = _scan_source(source, "<synthetic>")
    assert result.violations == ("<synthetic>:2", "<synthetic>:4")
