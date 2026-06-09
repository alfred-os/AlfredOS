"""Confirm docker/alfred-core.Dockerfile installs bubblewrap.

PR-S4-6's ``bin/alfred-plugin-launcher.sh`` invokes ``bwrap`` directly
with per-plugin policy files (spec §7.5 / ADR-0015). Without
bubblewrap in the runtime layer, Linux production refuses to launch
the quarantined-LLM with ``policy_ref_unreadable`` because no binary
can apply the policy.

Debian Bookworm ships bubblewrap 0.8.x which has ``--sync-fd``
(introduced in 0.5.0) — the flag PR-S4-6 round-2 closure 5 requires
for fd-3 provider-key inheritance.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_DOCKERFILE = Path("docker/alfred-core.Dockerfile")


@pytest.fixture
def dockerfile_contents() -> str:
    """Yield the Dockerfile body (read once, shared by all tests)."""
    return _DOCKERFILE.read_text()


def test_dockerfile_exists() -> None:
    """The Slice-3 Dockerfile path that Slice-4 extends MUST exist."""
    assert _DOCKERFILE.is_file(), f"missing: {_DOCKERFILE}"


def test_bubblewrap_apt_installed_in_runtime_layer(
    dockerfile_contents: str,
) -> None:
    """bubblewrap appears in the Dockerfile body."""
    assert "bubblewrap" in dockerfile_contents, (
        "bubblewrap missing from docker/alfred-core.Dockerfile. "
        "PR-S4-6 bash launcher needs /usr/bin/bwrap."
    )


def test_bubblewrap_on_apt_get_install_line(
    dockerfile_contents: str,
) -> None:
    """bubblewrap is on an ``apt-get install`` line, not buried in a comment.

    Defensive: a future refactor that moves the install into a separate
    layer (or comments it out) silently breaks the launcher; this test
    catches that drift.
    """
    apt_install_lines = [
        ln
        for ln in dockerfile_contents.splitlines()
        if "apt-get install" in ln and not ln.lstrip().startswith("#")
    ]
    assert any("bubblewrap" in ln for ln in apt_install_lines), (
        f"bubblewrap not on any apt-get install line. apt install lines: {apt_install_lines}"
    )


def test_bubblewrap_install_keeps_no_install_recommends(
    dockerfile_contents: str,
) -> None:
    """The bubblewrap install retains ``--no-install-recommends`` discipline.

    The Slice-3 install line uses ``--no-install-recommends`` to keep
    the runtime image small. A regression that drops that flag would
    silently inflate the image with recommended-but-unneeded packages.
    """
    apt_lines = [
        ln
        for ln in dockerfile_contents.splitlines()
        if "apt-get install" in ln and "bubblewrap" in ln and not ln.lstrip().startswith("#")
    ]
    assert apt_lines, "no apt-get install line carries bubblewrap"
    for ln in apt_lines:
        assert "--no-install-recommends" in ln, (
            f"apt install line dropped --no-install-recommends: {ln}"
        )


def test_dockerfile_last_user_directive_is_alfred(
    dockerfile_contents: str,
) -> None:
    """The LAST ``USER`` directive in the Dockerfile is ``alfred`` (non-root).

    Round-2 sec-2 closure: a substring match for ``USER alfred`` would
    tolerate a trailing ``USER root`` that re-elevates the runtime.
    Bubblewrap is suid-root by default on Debian, so the in-container
    launcher can invoke it from the alfred UID without the container
    itself needing root — and a regression that flips the final
    runtime user back to root would silently widen the trust posture.
    """
    user_directives = [
        ln.strip()
        for ln in dockerfile_contents.splitlines()
        if ln.strip().startswith("USER ") and not ln.lstrip().startswith("#")
    ]
    assert user_directives, "Dockerfile carries no USER directive"
    assert user_directives[-1] == "USER alfred", (
        f"final USER directive is {user_directives[-1]!r}, not 'USER alfred'. "
        f"all USER directives: {user_directives}"
    )
