"""Unit tests for :func:`alfred.security.capability_gate._state_git_parser.parse_state_git_head`.

PR-S3-6 Component N (plan §2497-2640) — the err-002 fix that PR-S3-2
intentionally deferred. The state.git ``policies/grants/`` tree is the
source of truth for capability grants (spec §8.1, Fork 7); this parser
projects it into :class:`frozenset[GrantRow]` for
:meth:`RealGate._apply_grants` to upsert into Postgres.

The test harness boots a temporary bare git repo (same shape as
``tests/unit/cli/test_state_git.py``'s ``bare_repo`` fixture), seeds a
``policies/grants/<id>.json`` tree at a known commit hash, and asserts:

* **Happy path** — every well-formed grant blob projects into a
  :class:`GrantRow`.
* **Empty grants tree** — a commit with no ``policies/grants/`` path
  returns the empty frozenset rather than raising (the bootstrap state
  before the first grant lands).
* **Invalid grant files are SKIPPED, not silently accepted** —
  CLAUDE.md hard rule #7. The parser logs at WARNING and continues; a
  malformed blob does not abort the rebuild and does not silently
  authorise an unparsable grant.
* **The wildcard hookpoint round-trips** — ``"*"`` is preserved so the
  in-memory wildcard semantics in :meth:`GatePolicy.check_plugin_load`
  keep matching after a rebuild.

This module also pins the :func:`parse_state_git_head` callsite shape:
``(state_git_path, commit_hash)``. The integration with
:meth:`RealGate.rebuild_from_state_git` (the gitpython wiring that
replaces PR-S3-2's fail-loud stub) lives in
``test_real_gate_rebuild_wiring.py``.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from alfred.security.capability_gate._state_git_parser import parse_state_git_head
from alfred.security.capability_gate.policy import GrantRow


def _git_env(home: Path) -> dict[str, str]:
    """Minimal env so git ignores the developer's global config.

    CR-149 round-3: inherit the current ``PATH`` rather than
    hard-coding ``/usr/bin:/bin``. The hard-coded literal broke on
    runners where git lives elsewhere (macOS Homebrew under
    ``/opt/homebrew``, Nix profiles, AlfredOS dev containers with a
    pinned git under ``/usr/local``). Only ``HOME`` + the git identity
    are sandboxed here; the binary discovery path inherits.
    """
    return {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
        "HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
    }


def _seed_repo_with_grants(
    tmp_path: Path,
    grant_payloads: dict[str, dict[str, object]],
) -> tuple[Path, str]:
    """Build a bare state.git repo with ``policies/grants/`` at the head.

    Returns ``(state_git_path, commit_hash)``. Each entry in
    ``grant_payloads`` becomes one ``policies/grants/<filename>.json`` blob.
    A malformed payload (e.g. an empty dict) lets the test pin the
    skip-invalid-grant path; valid payloads include every closed-domain
    field required by :class:`GrantRow`.
    """
    repo = tmp_path / "state.git"
    env = _git_env(tmp_path)
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "--initial-branch=main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    work = tmp_path / "seed"
    work.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "clone", str(repo), str(work)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    grants_dir = work / "policies" / "grants"
    grants_dir.mkdir(parents=True)
    for filename, payload in grant_payloads.items():
        (grants_dir / filename).write_text(json.dumps(payload))
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "add", "."],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(work),
            "commit",
            "-m",
            "seed grants",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    head_proc = subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    commit_hash = head_proc.stdout.strip()
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    return repo, commit_hash


def _seed_empty_repo(tmp_path: Path) -> tuple[Path, str]:
    """Build a bare state.git repo with NO ``policies/grants/`` tree.

    Returns ``(state_git_path, commit_hash)``. Used to pin the
    no-grants-tree branch of :func:`parse_state_git_head`.
    """
    repo = tmp_path / "state.git"
    env = _git_env(tmp_path)
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "--initial-branch=main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    work = tmp_path / "seed"
    work.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "clone", str(repo), str(work)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    (work / "README").write_text("seeded")
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "add", "."],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(work),
            "commit",
            "-m",
            "seed",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    head_proc = subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    commit_hash = head_proc.stdout.strip()
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    return repo, commit_hash


# ---------------------------------------------------------------------------
# parse_state_git_head
# ---------------------------------------------------------------------------


def test_parse_state_git_head_returns_grants_for_well_formed_blob(
    tmp_path: Path,
) -> None:
    """A well-formed grant blob projects into a :class:`GrantRow`."""
    payload = {
        "plugin_id": "alfred.web-fetch",
        "subscriber_tier": "operator",
        "hookpoint": "tool.web.fetch",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-abc",
    }
    repo_path, commit_hash = _seed_repo_with_grants(tmp_path, {"grant1.json": payload})

    grants = parse_state_git_head(repo_path, commit_hash)

    assert grants == frozenset(
        {
            GrantRow(
                plugin_id="alfred.web-fetch",
                subscriber_tier="operator",
                hookpoint="tool.web.fetch",
                content_tier=None,
                proposal_branch="proposal/policy-grant-abc",
            )
        }
    )


def test_parse_state_git_head_returns_empty_for_missing_grants_tree(
    tmp_path: Path,
) -> None:
    """A commit with no ``policies/grants/`` path returns the empty frozenset."""
    repo_path, commit_hash = _seed_empty_repo(tmp_path)

    grants = parse_state_git_head(repo_path, commit_hash)

    assert grants == frozenset()


def test_parse_state_git_head_skips_invalid_grant_files(tmp_path: Path) -> None:
    """A malformed grant file is logged + skipped, not silently accepted.

    CLAUDE.md hard rule #7: no silent failures in security paths. A
    blob that fails :class:`GrantRow` validation MUST surface in the
    structured log so an operator can investigate the corrupted grant,
    AND the rebuild MUST continue for the remaining well-formed grants.

    Uses :func:`structlog.testing.capture_logs` because this project
    routes structlog through its own ConsoleRenderer pipeline rather
    than the stdlib ``logging`` bridge; pytest's ``caplog`` fixture
    therefore misses the warning even though it lands on stdout.
    """
    import structlog.testing

    valid_payload = {
        "plugin_id": "good.plugin",
        "subscriber_tier": "operator",
        "hookpoint": "tool.web.fetch",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-good",
    }
    # Missing required key + invalid subscriber_tier.
    invalid_payload = {"plugin_id": "broken", "subscriber_tier": "not-a-real-tier"}

    repo_path, commit_hash = _seed_repo_with_grants(
        tmp_path,
        {"good.json": valid_payload, "broken.json": invalid_payload},
    )

    with structlog.testing.capture_logs() as captured:
        grants = parse_state_git_head(repo_path, commit_hash)

    # The valid grant lands; the invalid one is skipped.
    assert any(g.plugin_id == "good.plugin" for g in grants)
    assert not any(g.plugin_id == "broken" for g in grants)

    # The skip emits one structured warning. The event tag is the
    # load-bearing identifier the operator dashboards on; the path
    # field surfaces the offending blob for correlation.
    skipped = [
        c for c in captured if c.get("event") == "capability_gate.rebuild.skip_invalid_grant"
    ]
    assert len(skipped) == 1, f"expected one skip warning, got: {captured!r}"
    assert skipped[0]["log_level"] == "warning"
    assert skipped[0]["path"] == "policies/grants/broken.json"
    assert skipped[0]["commit_hash"] == commit_hash


def test_parse_state_git_head_round_trips_wildcard_hookpoint(
    tmp_path: Path,
) -> None:
    """The wildcard ``"*"`` hookpoint is preserved across the rebuild.

    :meth:`GatePolicy.check_plugin_load` relies on the ``"*"`` literal
    for "covers every hookpoint at this (plugin_id, subscriber_tier) pair"
    semantics; if the parser stripped or transformed it, a plugin-load
    grant would silently stop covering every hookpoint after a rebuild.
    """
    payload = {
        "plugin_id": "wild.plugin",
        "subscriber_tier": "system",
        "hookpoint": "*",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-wild",
    }
    repo_path, commit_hash = _seed_repo_with_grants(tmp_path, {"wild.json": payload})

    grants = parse_state_git_head(repo_path, commit_hash)

    assert any(g.hookpoint == "*" for g in grants)


def _seed_repo_with_nested_grants_and_sidecars(tmp_path: Path) -> tuple[Path, str]:
    """Seed a state.git with a nested subtree + non-JSON sidecars.

    Layout:
      ``policies/grants/.gitkeep``                       (non-JSON top-level)
      ``policies/grants/README.md``                      (non-JSON top-level)
      ``policies/grants/flat.json``                      (legacy flat layout)
      ``policies/grants/nested-plugin/grant1.json``      (ADR-0018 nested)
      ``policies/grants/nested-plugin/.gitkeep``         (non-JSON in subtree)

    Pins both ``parse_state_git_head`` skip branches:
    * non-JSON siblings at every depth are ignored by the suffix guard
      (line 120 — :func:`alfred.security.capability_gate._state_git_parser`).
    * intermediate Tree nodes returned by ``tree.traverse()`` are skipped
      by the type discriminator (line 115).
    """
    repo = tmp_path / "state.git"
    env = _git_env(tmp_path)
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "--initial-branch=main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    work = tmp_path / "seed"
    work.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "clone", str(repo), str(work)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    grants_dir = work / "policies" / "grants"
    nested_dir = grants_dir / "nested-plugin"
    nested_dir.mkdir(parents=True)

    # Non-JSON sidecars at top level — exercise the .json suffix guard.
    (grants_dir / ".gitkeep").write_text("")
    (grants_dir / "README.md").write_text("# operator note")

    # Legacy flat-layout grant.
    (grants_dir / "flat.json").write_text(
        json.dumps(
            {
                "plugin_id": "legacy.flat",
                "subscriber_tier": "operator",
                "hookpoint": "tool.web.fetch",
                "content_tier": None,
                "proposal_branch": "proposal/policy-grant-flat",
            }
        )
    )

    # Nested grant — the ADR-0018 canonical layout.
    (nested_dir / "grant1.json").write_text(
        json.dumps(
            {
                "plugin_id": "nested.plugin",
                "subscriber_tier": "system",
                "hookpoint": "tool.web.fetch",
                "content_tier": None,
                "proposal_branch": "proposal/policy-grant-nested",
            }
        )
    )
    # Non-JSON sidecar inside the subtree — exercises the suffix guard
    # after ``tree.traverse()`` has descended past the Tree node.
    (nested_dir / ".gitkeep").write_text("")

    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "add", "."],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(work),
            "commit",
            "-m",
            "seed nested + sidecars",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    head_proc = subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    commit_hash = head_proc.stdout.strip()
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    return repo, commit_hash


def test_parse_state_git_head_skips_non_json_sidecars(tmp_path: Path) -> None:
    """``.gitkeep`` + ``README.md`` siblings under ``policies/grants/`` are skipped.

    Pins the suffix guard at line 120 of ``_state_git_parser.py``: a
    future YAML peer file or operator README MUST NOT throw the parser
    into a :class:`json.JSONDecodeError` warn-skip loop. The structural
    guard sidesteps the JSON parser entirely.

    Asserts:
    * The two legitimate grants still project (legacy flat + nested).
    * NO ``capability_gate.rebuild.skip_invalid_grant`` warning fires
      for the sidecars (the suffix guard is BEFORE the json.loads try).
    """
    import structlog.testing

    repo_path, commit_hash = _seed_repo_with_nested_grants_and_sidecars(tmp_path)

    with structlog.testing.capture_logs() as captured:
        grants = parse_state_git_head(repo_path, commit_hash)

    plugin_ids = {g.plugin_id for g in grants}
    assert plugin_ids == {"legacy.flat", "nested.plugin"}, (
        f"expected both legacy flat + nested grants; got {plugin_ids!r}"
    )

    # The skip-invalid-grant warning is for malformed BLOBS, never for
    # sidecars filtered out by the structural guard.
    skipped = [
        c for c in captured if c.get("event") == "capability_gate.rebuild.skip_invalid_grant"
    ]
    assert skipped == [], (
        f"sidecars MUST be skipped by suffix guard before the warn-skip "
        f"loop; got warnings: {skipped!r}"
    )


def _seed_repo_with_raw_blobs(
    tmp_path: Path,
    raw_blobs: dict[str, bytes],
) -> tuple[Path, str]:
    """Build a bare state.git repo with ``policies/grants/`` raw-byte payloads.

    CR-149 round-3 (UnicodeDecodeError coverage): the JSON-string seeder
    only round-trips valid UTF-8 text. To exercise the parser's
    ``UnicodeDecodeError`` skip-and-log path we need to write bytes
    that the JSON layer's UTF-8 decode rejects BEFORE the JSON parse
    runs. This helper writes the raw bytes verbatim so the resulting
    git blob carries the exact byte sequence the test supplies.
    """
    repo = tmp_path / "state.git"
    env = _git_env(tmp_path)
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "--initial-branch=main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    work = tmp_path / "seed"
    work.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "clone", str(repo), str(work)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    grants_dir = work / "policies" / "grants"
    grants_dir.mkdir(parents=True)
    for filename, blob in raw_blobs.items():
        (grants_dir / filename).write_bytes(blob)
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "add", "."],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(work),
            "commit",
            "-m",
            "seed raw blobs",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    head_proc = subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    commit_hash = head_proc.stdout.strip()
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    return repo, commit_hash


def test_parse_state_git_head_skips_invalid_utf8_grant_blobs(tmp_path: Path) -> None:
    """A grant blob with invalid UTF-8 bytes is logged + skipped.

    CR-149 round-3 + PRD §7.1 + CLAUDE.md hard rule #7: ``json.loads``
    on bytes decodes UTF-8 BEFORE the JSON parse, raising
    :class:`UnicodeDecodeError` on a malformed byte sequence. The
    parser MUST treat that exception identically to the JSON parse
    errors: skip-and-log, never silently accept and never abort the
    rebuild. A single corrupted blob would otherwise wedge the gate
    against every subsequent grant in the same commit.
    """
    import structlog.testing

    valid_payload = {
        "plugin_id": "good.plugin",
        "subscriber_tier": "operator",
        "hookpoint": "tool.web.fetch",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-good",
    }
    # 0xff alone is not a valid UTF-8 byte. Pairing it with otherwise
    # well-formed JSON syntax pins that the failure is the UTF-8
    # decode, not the JSON parse.
    invalid_utf8 = b'{"plugin_id": "x"}\xff'

    repo_path, commit_hash = _seed_repo_with_raw_blobs(
        tmp_path,
        {
            "good.json": json.dumps(valid_payload).encode("utf-8"),
            "bad-utf8.json": invalid_utf8,
        },
    )

    with structlog.testing.capture_logs() as captured:
        grants = parse_state_git_head(repo_path, commit_hash)

    # The valid grant still projects.
    assert any(g.plugin_id == "good.plugin" for g in grants)
    # The malformed-UTF-8 blob is skipped (no row for it).
    assert not any(g.plugin_id == "x" for g in grants)

    # And the skip path emits the structured warning — pinning the
    # rebuild's forensic surface against a future regression that
    # swallows the failure silently.
    skipped = [
        c for c in captured if c.get("event") == "capability_gate.rebuild.skip_invalid_grant"
    ]
    assert len(skipped) == 1, f"expected one skip warning, got: {captured!r}"
    assert skipped[0]["log_level"] == "warning"
    assert skipped[0]["path"] == "policies/grants/bad-utf8.json"
    # The exception type name confirms the new UnicodeDecodeError arm
    # caught the bytes — a regression that drops the new arm would
    # surface as a raised UnicodeDecodeError, not a skip log.
    assert skipped[0]["error_type"] == "UnicodeDecodeError"


def test_parse_state_git_head_recurses_into_nested_plugin_subtree(
    tmp_path: Path,
) -> None:
    """ADR-0018 nested ``policies/grants/<plugin>/<grant>.json`` round-trips.

    Pins the type discriminator at line 114-115 of
    ``_state_git_parser.py``: ``tree.traverse()`` yields the subtree
    node ``nested-plugin`` itself BEFORE the contained blobs, and the
    parser MUST skip the Tree object to avoid a TypeError on
    ``blob.path.endswith``. Without the type guard the parser would
    surface a misleading skip warning on the directory entry; with it,
    only real blobs reach the JSON path.
    """
    repo_path, commit_hash = _seed_repo_with_nested_grants_and_sidecars(tmp_path)

    grants = parse_state_git_head(repo_path, commit_hash)

    nested = [g for g in grants if g.plugin_id == "nested.plugin"]
    assert len(nested) == 1
    assert nested[0].subscriber_tier == "system"
    assert nested[0].proposal_branch == "proposal/policy-grant-nested"
