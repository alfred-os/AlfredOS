"""Drift-net: validate every ``alfred`` CLI invocation in ``bin/alfred-setup.sh``
and ``README.md`` against the REAL Typer command tree (#591/#592/#593 Task 5).

Why this exists
----------------

Task 4 of this same combined PR fixed a real bug: ``bin/alfred-setup.sh`` and
``README.md`` both invoked ``alfred user bind`` with flags (``--slug``,
``--platform-id``) that never existed on the real CLI (``bind`` takes the slug
*positionally* and the id via ``--id``). That drift shipped and sat unnoticed
for months because nothing checked docs/scripts against the actual Typer
command definitions — an operator following the README, or running the setup
script's interactive Discord-bind prompt, would have hit ``typer``'s
"No such option" and exit 2, with `set -euo pipefail` killing the script.

Rather than pin the two known-good strings (which would only catch a
regression on those exact two lines), this module walks the REAL command
tree — ``typer.main.get_command(alfred.cli.main.app)`` — and validates
*every* ``alfred``/``docker compose run ... alfred-core`` invocation found in
the two source files: every ``--flag`` must exist on the resolved command,
and the positional-argument count must fall within that command's arity.
A future flag rename breaks this test the day it lands.

Typer's vendored click shape (verified against the installed typer==0.27.1,
not assumed)
------------------------------------------------------------------------

Newer typer versions do **not** depend on a standalone ``click`` package —
``import click`` raises ``ModuleNotFoundError`` in this repo's venv. typer
vendors its own fork under ``typer._click``, and ``typer.main.get_command``
returns a ``typer.core.TyperGroup`` (for the root app and every
``add_typer``-registered sub-app) whose ``.commands`` dict maps subcommand
names to either another ``TyperGroup`` or a leaf ``typer.core.TyperCommand``.
Each command's ``.params`` list holds ``typer.core.TyperOption`` /
``typer.core.TyperArgument`` instances — there is no separate
``click.Option``/``click.Argument`` base class to import here, so this
module isinstance-checks against ``typer.core`` directly. ``TyperOption``
carries ``.opts`` / ``.secondary_opts`` / ``.is_flag`` / ``.required``;
``TyperArgument`` carries ``.required`` / ``.nargs`` (verified via a REPL
walk of the real tree, not assumed from click's public docs, which describe
the un-vendored package).

Click/typer auto-injects a ``--help`` flag on every command outside
``.params`` (it only appears via ``command.get_params(ctx)``, which needs a
``Context``). Rather than construct one, ``--help`` is hardcoded as always
allowed below — every command gets it and none opt out.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

import typer.main
from typer.core import TyperArgument, TyperCommand, TyperGroup, TyperOption

from alfred.cli.main import app

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SETUP_SH = _REPO_ROOT / "bin" / "alfred-setup.sh"
_README = _REPO_ROOT / "README.md"


@dataclass(frozen=True)
class Invocation:
    """One extracted ``alfred`` CLI call site."""

    source: str
    line: int
    raw: str
    tokens: list[str]


# ---------------------------------------------------------------------------
# Shell-text extraction
# ---------------------------------------------------------------------------
#
# `docker compose run --rm alfred-core <argv>` is recognised either at the
# start of a (stripped) line, or immediately after a `$(` command-substitution
# open — the two shapes actually used in bin/alfred-setup.sh (a bare
# top-level call, and `var="$(docker compose run ... )"` capturing stdout).
# This deliberately does NOT match `docker compose run` appearing inside an
# already-quoted string (e.g. an `echo "... 'docker compose run ...' ..."`
# usage example) — neither anchor fires there, so that kind of prose mention
# is correctly left unextracted.
_DOCKER_RUN_ANCHOR_RE = re.compile(r"(?:^\s*|\$\()docker\s+compose\s+run\s+")
# Captures everything after `alfred-core `, having consumed any number of
# leading dash-flags (`--rm`, `-it`, ...) between `run` and `alfred-core`.
# An `--entrypoint <path>` invocation bypasses the `alfred` entrypoint
# entirely (runs a raw script instead), so it is detected and skipped
# *before* this pattern is even tried (see `_extract_invocation`) — for such
# a line this pattern would fail to match anyway (the entrypoint's path
# argument is not itself a dash-flag, so the `(?:-\S+\s+)*` repetition can
# never reach a literal `alfred-core`), but the explicit check makes the
# skip deliberate and countable rather than an implicit non-match.
_DOCKER_RUN_CAPTURE_RE = re.compile(
    r"(?:^\s*|\$\()docker\s+compose\s+run\s+(?:-\S+\s+)*alfred-core\s+(.*)"
)

# Trims trailing shell noise (redirects, `||`/`&&`, a `;` separator, or the
# closing `)"` of a `var="$(...)"` capture) off an extracted argv string, so
# `2>/dev/null`, `|| true`, `2>&1`, and the wrapping quote/paren never get
# handed to shlex as if they were CLI tokens.
_SHELL_TERMINATOR_RE = re.compile(r'\s+\d*>&?\d*\S*|\s+\|\|?|\s+&&|\s*;|\)"')


def _truncate_at_shell_terminator(argv_text: str) -> str:
    match = _SHELL_TERMINATOR_RE.search(argv_text)
    return argv_text[: match.start()] if match else argv_text


def _join_shell_continuations(text: str) -> list[tuple[int, str]]:
    """Join backslash-newline shell continuations into logical lines.

    Returns ``(first_physical_line_number, logical_line_text)`` pairs
    (1-indexed) so a failure can still point roughly at the right place in
    the source file even after several physical lines were merged into one
    logical command. Extra internal whitespace left behind by the join is
    harmless — ``shlex.split`` collapses runs of whitespace regardless.
    """
    physical_lines = text.split("\n")
    logical: list[tuple[int, str]] = []
    buffer: list[str] = []
    first_line_no: int | None = None
    for i, physical in enumerate(physical_lines, start=1):
        if first_line_no is None:
            first_line_no = i
        if physical.endswith("\\"):
            buffer.append(physical[:-1])
            continue
        buffer.append(physical)
        logical.append((first_line_no, " ".join(buffer)))
        buffer = []
        first_line_no = None
    if buffer:
        # Only reachable if the file's very last physical line ends with an
        # unterminated `\` continuation — malformed shell, but `first_line_no`
        # is still guaranteed set (it is only ever `None` right after a group
        # was flushed, and flushing also empties `buffer`, so a non-empty
        # `buffer` here means the group currently open started at a real line).
        assert first_line_no is not None
        logical.append((first_line_no, " ".join(buffer)))
    return logical


def _extract_invocation(
    source: str, line_no: int, logical_line: str
) -> tuple[Invocation | None, bool]:
    """Extract one ``docker compose run ... alfred-core <argv>`` invocation.

    Returns ``(invocation_or_None, was_entrypoint_skip)``. The second value
    lets callers count how many ``--entrypoint`` invocations were
    deliberately skipped, so that skip path can itself be asserted non-zero
    rather than trusted blindly.
    """
    if not _DOCKER_RUN_ANCHOR_RE.search(logical_line):
        return None, False
    if "--entrypoint" in logical_line:
        return None, True
    match = _DOCKER_RUN_CAPTURE_RE.search(logical_line)
    if match is None:
        return None, False
    argv_text = _truncate_at_shell_terminator(match.group(1))
    tokens = shlex.split(argv_text)
    return Invocation(source=source, line=line_no, raw=logical_line.strip(), tokens=tokens), False


def _extract_setup_script_invocations(text: str) -> tuple[list[Invocation], int]:
    """Extract every ``docker compose run [--rm] alfred-core <argv>`` call.

    Backslash-continuations are joined first (the real ``user add`` and
    ``user bind`` Discord-prompt calls in ``bin/alfred-setup.sh`` both wrap
    their flags across several lines). Returns ``(invocations,
    entrypoint_skipped_count)``.
    """
    invocations: list[Invocation] = []
    entrypoint_skipped = 0
    for line_no, logical_line in _join_shell_continuations(text):
        invocation, was_entrypoint_skip = _extract_invocation(
            "bin/alfred-setup.sh", line_no, logical_line
        )
        if was_entrypoint_skip:
            entrypoint_skipped += 1
        elif invocation is not None:
            invocations.append(invocation)
    return invocations, entrypoint_skipped


# README wraps its fenced ```sh blocks three different ways: plain, inside a
# markdown blockquote (every line prefixed `> `), and inside a numbered-list
# continuation (every line indented). Capturing the *opening* fence's exact
# prefix and requiring every subsequent line — including the closing fence —
# to share it is what makes the block boundary correct for all three shapes;
# a single `re.DOTALL` regex anchored on a bare "```" close (tried first,
# see the fix note in the Task 5 report) silently merges blockquoted/indented
# blocks into whatever bare "```" comes next in the document, or drops them
# entirely if none does.
_FENCE_OPEN_RE = re.compile(r"^(?P<prefix>[ \t]*>?[ \t]*)```sh\s*$")
_TRAILING_COMMENT_RE = re.compile(r"\s+#.*$")


def _iter_fenced_sh_blocks(text: str) -> list[tuple[int, list[str]]]:
    """Yield ``(first_content_line_no, content_lines)`` for every fenced ```sh block.

    ``content_lines`` has the opening fence's prefix (blockquote marker
    and/or leading indentation) already stripped from every line, so
    callers see the same shape regardless of how the block was wrapped.
    An unterminated fence (prefix mismatch before a closing ``` ``` `` is
    found) is skipped rather than silently swallowing the rest of the file.
    """
    lines = text.split("\n")
    blocks: list[tuple[int, list[str]]] = []
    i = 0
    n = len(lines)
    while i < n:
        open_match = _FENCE_OPEN_RE.match(lines[i])
        if open_match is None:
            i += 1
            continue
        prefix = open_match.group("prefix")
        content: list[str] = []
        j = i + 1
        closed = False
        while j < n:
            line = lines[j]
            if not line.startswith(prefix):
                break
            remainder = line[len(prefix) :]
            if remainder.rstrip() == "```":
                closed = True
                break
            content.append(remainder)
            j += 1
        if closed:
            blocks.append((i + 2, content))  # +2: 1-indexed, and skip the opening fence line itself
            i = j + 1
        else:
            i += 1
    return blocks


def _extract_readme_invocations(text: str) -> list[Invocation]:
    """Extract fenced-``sh`` lines starting ``alfred`` or ``docker compose run ... alfred-core``."""
    invocations: list[Invocation] = []
    for first_line_no, content_lines in _iter_fenced_sh_blocks(text):
        for offset, raw_line in enumerate(content_lines):
            line_no = first_line_no + offset
            normalised = _TRAILING_COMMENT_RE.sub("", raw_line).rstrip()
            if normalised.startswith("alfred "):
                argv_text = _truncate_at_shell_terminator(normalised[len("alfred ") :])
                tokens = shlex.split(argv_text)
                invocations.append(
                    Invocation(
                        source="README.md", line=line_no, raw=raw_line.strip(), tokens=tokens
                    )
                )
                continue
            invocation, _was_entrypoint_skip = _extract_invocation("README.md", line_no, normalised)
            if invocation is not None:
                invocations.append(invocation)
    return invocations


# ---------------------------------------------------------------------------
# Command-tree resolution + validation
# ---------------------------------------------------------------------------


def _resolve_chain(
    tree: TyperGroup, tokens: list[str]
) -> tuple[TyperGroup | TyperCommand, list[str], list[str]]:
    """Consume leading non-flag tokens while they name a subcommand.

    Returns ``(node, chain_consumed, remaining_argv)`` — ``node`` is the
    deepest ``TyperGroup``/``TyperCommand`` reached; ``remaining_argv`` is
    whatever argv is left to validate against it (or, if ``node`` is still a
    group, an unresolved subcommand name / genuinely-empty invocation).
    """
    node: TyperGroup | TyperCommand = tree
    chain: list[str] = []
    idx = 0
    while idx < len(tokens):
        candidate = tokens[idx]
        if candidate.startswith("-"):
            break
        if not isinstance(node, TyperGroup) or candidate not in node.commands:
            break
        sub_command = node.commands[candidate]
        if not isinstance(sub_command, (TyperGroup, TyperCommand)):
            # Defensive: every command in this app's tree is registered via Typer, so
            # `.commands` values are always TyperGroup/TyperCommand in practice —
            # `.commands` is merely *declared* as `dict[str, Command]` upstream. Stop
            # resolving rather than assume; `node` stays put and `candidate` remains
            # unconsumed, so the caller reports it as an unresolved subcommand.
            break
        node = sub_command
        chain.append(candidate)
        idx += 1
    return node, chain, tokens[idx:]


def _validate_leaf_argv(command: TyperCommand, argv: list[str]) -> str | None:
    """Return an error string if ``argv`` doesn't fit ``command``'s real signature, else ``None``.

    Every ``--flag`` token must be a real option (or its ``--flag=value``
    form); a non-flag option consumes the next token as its value while a
    boolean flag does not (``gateway adapters --wait-ready discord`` is the
    real example pinning this — ``--wait-ready`` must NOT eat ``discord``).
    Every REQUIRED option must actually appear (a required option silently
    added to a command, with the script left unmodified, is the same shape
    of drift as a rename — the script/README would omit a flag the CLI now
    demands, and `alfred` would refuse with a "Missing option" error).
    Remaining positionals are counted against the command's ``TyperArgument``
    arity: this is what would have caught the historical `bind --slug X`
    bug even had `--slug` existed as a real option — `bind` is still
    missing its required positional slug.
    """
    options = [p for p in command.params if isinstance(p, TyperOption)]
    arguments = [p for p in command.params if isinstance(p, TyperArgument)]

    # `--help` is injected by click/typer outside `.params` (it only shows up
    # via `command.get_params(ctx)`, which needs a live Context) — every
    # command accepts it, so it is always allowed rather than derived.
    allowed_flags: set[str] = {"--help"}
    flag_only: set[str] = {"--help"}
    for opt in options:
        strings = [*opt.opts, *opt.secondary_opts]
        allowed_flags.update(strings)
        if opt.is_flag:
            flag_only.update(strings)

    positionals: list[str] = []
    used_flags: set[str] = set()
    i = 0
    while i < len(argv):
        next_arg = argv[i]
        if next_arg.startswith("-") and next_arg != "-":
            name = next_arg.split("=", 1)[0]
            if name not in allowed_flags:
                return f"has no option {name!r}"
            used_flags.add(name)
            i += 1
            if "=" in next_arg:
                continue
            if name not in flag_only:
                if i >= len(argv):
                    return f"option {name!r} is missing its value"
                i += 1
        else:
            positionals.append(next_arg)
            i += 1

    missing_required = [
        opt.opts[0]
        for opt in options
        if opt.required and used_flags.isdisjoint([*opt.opts, *opt.secondary_opts])
    ]
    if missing_required:
        return f"is missing required option(s) {missing_required!r}"

    n = len(positionals)
    required_arity = 0
    max_arity = 0
    unbounded = False
    for arg in arguments:
        nargs = arg.nargs if arg.nargs is not None else 1
        if nargs == -1:
            unbounded = True
            if arg.required:
                required_arity += 1
            continue
        width = max(nargs, 1)
        if arg.required:
            required_arity += width
        max_arity += width

    if unbounded:
        if n < required_arity:
            return f"expects >= {required_arity} positional argument(s), got {n} ({positionals!r})"
    elif not (required_arity <= n <= max_arity):
        return (
            f"expects between {required_arity} and {max_arity} positional argument(s), "
            f"got {n} ({positionals!r})"
        )
    return None


def _check_invocation(tree: TyperGroup, invocation: Invocation) -> str | None:
    """Return a human-readable error, or ``None`` if ``invocation`` resolves cleanly."""
    node, chain, remaining = _resolve_chain(tree, invocation.tokens)
    command_name = f"alfred {' '.join(chain)}".rstrip() if chain else "alfred"
    if isinstance(node, TyperGroup):
        if remaining:
            return (
                f"{invocation.source}:{invocation.line}: `{command_name}` has no subcommand "
                f"{remaining[0]!r} (raw: {invocation.raw!r})"
            )
        return None
    error = _validate_leaf_argv(node, remaining)
    if error is None:
        return None
    return (
        f"{invocation.source}:{invocation.line}: `{command_name}` {error} (raw: {invocation.raw!r})"
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _command_tree() -> TyperGroup:
    tree = typer.main.get_command(app)
    assert isinstance(tree, TyperGroup)
    return tree


def _setup_script_invocations() -> tuple[list[Invocation], int]:
    return _extract_setup_script_invocations(_SETUP_SH.read_text())


def _readme_invocations() -> list[Invocation]:
    return _extract_readme_invocations(_README.read_text())


# ---------------------------------------------------------------------------
# Anti-vacuity: the extraction must actually be finding real invocations,
# not silently matching nothing (which would make the validation tests
# below pass trivially over an empty list).
# ---------------------------------------------------------------------------


def test_setup_script_extraction_is_not_vacuous() -> None:
    invocations, _entrypoint_skipped = _setup_script_invocations()
    assert len(invocations) >= 5, (
        f"Expected at least 5 `docker compose run ... alfred-core` invocations in "
        f"bin/alfred-setup.sh; found {len(invocations)}: {invocations!r}. Either the "
        f"extraction regex broke, or the script genuinely lost invocations — check both "
        f"before assuming this floor should just be lowered."
    )


def test_setup_script_entrypoint_skip_actually_fires() -> None:
    """The state.git seed step deliberately bypasses the `alfred` entrypoint via
    `--entrypoint /bin/sh` — it is not a validatable CLI invocation and must be
    skipped, not silently mismatched. Assert the skip counter is non-zero so
    that behaviour is proven exercised, not merely assumed from reading the
    regex.
    """
    _invocations, entrypoint_skipped = _setup_script_invocations()
    assert entrypoint_skipped >= 1, (
        "Expected at least one `--entrypoint` invocation to be found-and-skipped in "
        "bin/alfred-setup.sh. Zero means either the skip logic broke, or the "
        "state.git-seed `--entrypoint` call was removed — either way this needs a look."
    )


def test_readme_extraction_is_not_vacuous() -> None:
    invocations = _readme_invocations()
    assert len(invocations) >= 3, (
        f"Expected at least 3 fenced-`sh` `alfred`/`docker compose run ... alfred-core` "
        f"invocations in README.md; found {len(invocations)}: {invocations!r}."
    )


# ---------------------------------------------------------------------------
# The actual drift-net: every real invocation must resolve against the real
# CLI. Errors are accumulated (not raised on the first one) so a single test
# run reports every mismatch at once — mirrors the setup script's own
# "accumulate all config problems, report together" convention.
# ---------------------------------------------------------------------------


def test_every_setup_script_invocation_matches_the_real_cli() -> None:
    tree = _command_tree()
    invocations, _entrypoint_skipped = _setup_script_invocations()
    errors = [error for inv in invocations if (error := _check_invocation(tree, inv)) is not None]
    detail = "\n".join(errors)
    assert not errors, f"bin/alfred-setup.sh invokes args the real CLI rejects:\n{detail}"


def test_every_readme_invocation_matches_the_real_cli() -> None:
    tree = _command_tree()
    invocations = _readme_invocations()
    errors = [error for inv in invocations if (error := _check_invocation(tree, inv)) is not None]
    detail = "\n".join(errors)
    assert not errors, f"README.md invokes `alfred` with flags/args the real CLI rejects:\n{detail}"


# ---------------------------------------------------------------------------
# Self-test: prove the validator actually discriminates, running the FULL
# extraction -> resolution -> validation pipeline end-to-end (not a small
# helper called in isolation) against synthetic setup.sh-shaped text
# carrying the literal historical broken string and its fix.
# ---------------------------------------------------------------------------

_OLD_BROKEN_SETUP_SH = """\
#!/usr/bin/env bash
set -euo pipefail
docker compose run --rm alfred-core user bind --slug x --platform discord --platform-id y
"""

_NEW_FIXED_SETUP_SH = """\
#!/usr/bin/env bash
set -euo pipefail
docker compose run --rm alfred-core user bind x --platform discord --id y
"""


def test_validator_rejects_the_historical_broken_bind_invocation() -> None:
    """#591/#592 Task 4: `--slug`/`--platform-id` never existed on `alfred user bind` —
    this drifted unnoticed for months. `bind` takes the slug positionally and the id
    via `--id`, so the old string is wrong on *two* independent counts (unknown
    options, and a missing required positional) — either one alone should already
    fail this.
    """
    tree = _command_tree()
    invocations, _entrypoint_skipped = _extract_setup_script_invocations(_OLD_BROKEN_SETUP_SH)
    assert len(invocations) == 1, invocations
    error = _check_invocation(tree, invocations[0])
    assert error is not None, (
        "Validator failed to reject the historical broken invocation "
        "`user bind --slug x --platform discord --platform-id y` — it should have "
        "flagged the nonexistent `--slug`/`--platform-id` options."
    )


def test_validator_accepts_the_fixed_bind_invocation() -> None:
    """The Task 4 fix: positional slug + `--platform` + `--id`."""
    tree = _command_tree()
    invocations, _entrypoint_skipped = _extract_setup_script_invocations(_NEW_FIXED_SETUP_SH)
    assert len(invocations) == 1, invocations
    error = _check_invocation(tree, invocations[0])
    assert error is None, f"Validator incorrectly rejected the fixed invocation: {error}"


_MISSING_REQUIRED_OPTION_SETUP_SH = """\
#!/usr/bin/env bash
set -euo pipefail
docker compose run --rm alfred-core user bind x --platform discord
"""


def test_validator_rejects_a_bind_invocation_missing_a_required_option() -> None:
    """Self-review gap check: syntactically-valid-looking argv that simply omits a
    required option (here `--id`) must also be caught — not just unknown flags and
    positional-count mismatches. This is the shape a *newly-added* required option
    would take: the script stays textually unchanged but the CLI now demands
    something it doesn't provide.
    """
    tree = _command_tree()
    invocations, _entrypoint_skipped = _extract_setup_script_invocations(
        _MISSING_REQUIRED_OPTION_SETUP_SH
    )
    assert len(invocations) == 1, invocations
    error = _check_invocation(tree, invocations[0])
    assert error is not None, (
        "Validator failed to reject `user bind x --platform discord` — it is missing "
        "the required `--id` option and should have been flagged."
    )
