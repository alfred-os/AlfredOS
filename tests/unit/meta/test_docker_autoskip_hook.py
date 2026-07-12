"""Unit tests for the root-conftest docker auto-skip collection hook."""

from __future__ import annotations

import sys

import pytest

from tests import conftest as root_conftest


class _FakeItem:
    """Minimal ``pytest.Item`` stand-in exposing only what the hook touches."""

    def __init__(self, *, marked: bool) -> None:
        self._marked = marked
        self.added: list[pytest.MarkDecorator] = []

    def get_closest_marker(self, name: str) -> object | None:
        return object() if (name == "docker" and self._marked) else None

    def add_marker(self, marker: pytest.MarkDecorator) -> None:
        self.added.append(marker)


def test_docker_items_skipped_when_daemon_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force non-Windows so this exercises the daemon-absent branch, not the
    # unconditional win32 skip (#246 Phase B) — which has its own test below.
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(root_conftest, "docker_available", lambda: False)
    monkeypatch.setattr(root_conftest, "docker_unavailable_reason", lambda: "no daemon")
    docker_item = _FakeItem(marked=True)
    plain_item = _FakeItem(marked=False)
    root_conftest.pytest_collection_modifyitems(items=[docker_item, plain_item])
    assert len(docker_item.added) == 1
    assert docker_item.added[0].name == "skip"
    assert plain_item.added == []


def test_nothing_skipped_when_daemon_present(monkeypatch: pytest.MonkeyPatch) -> None:
    # Daemon-present → no skip is a NON-Windows path; on win32 docker items skip
    # unconditionally (see the win32 test below), so pin the platform here.
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(root_conftest, "docker_available", lambda: True)
    docker_item = _FakeItem(marked=True)
    root_conftest.pytest_collection_modifyitems(items=[docker_item])
    assert docker_item.added == []


def test_docker_items_skipped_on_win32_even_with_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    """On native Windows, docker-marked items skip regardless of the daemon.

    Docker Desktop reports the CLI available on the Windows runner, but the
    Linux-container Testcontainers cannot run there (the /var/run/docker.sock
    bind is invalid), so the hook skips them unconditionally rather than letting
    them ERROR (#246 Phase B). ``docker_available`` must NOT even be consulted.
    """

    def _must_not_probe() -> bool:
        raise AssertionError("docker_available must not be probed on win32")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(root_conftest, "docker_available", _must_not_probe)
    docker_item = _FakeItem(marked=True)
    root_conftest.pytest_collection_modifyitems(items=[docker_item])
    assert len(docker_item.added) == 1
    assert docker_item.added[0].name == "skip"


def test_no_probe_when_no_docker_items(monkeypatch: pytest.MonkeyPatch) -> None:
    """Short-circuit: with zero docker-marked items, the probe is never called."""

    def _boom() -> bool:
        raise AssertionError("docker_available must not be probed when no docker items")

    monkeypatch.setattr(root_conftest, "docker_available", _boom)
    plain_item = _FakeItem(marked=False)
    root_conftest.pytest_collection_modifyitems(items=[plain_item])
    assert plain_item.added == []


def test_docker_marked_test_skips_not_errors_when_daemon_absent(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """END-TO-END: a real ``docker``-marked test SKIPS (its module-scoped fixture
    never runs) when the daemon is absent.

    Proves the load-bearing chain the ``_FakeItem`` tests cannot: real marker
    propagation + skip-at-collection pre-empting module-scoped fixture setup.
    Runs on every platform (incl. the Linux ``python`` job) — no daemon needed,
    because we force ``docker_available`` False.
    """
    monkeypatch.setattr(root_conftest, "docker_available", lambda: False)
    monkeypatch.setattr(root_conftest, "docker_unavailable_reason", lambda: "forced-absent")
    # The sandbox re-uses the REAL hook from tests.conftest (same process, same
    # module object → the monkeypatch above is honoured).
    pytester.makeconftest("from tests.conftest import pytest_collection_modifyitems\n")
    pytester.makepyfile(
        """
        import pytest

        pytestmark = pytest.mark.docker

        @pytest.fixture(scope="module")
        def exploding_container():
            raise RuntimeError("fixture setup must not run for a skipped test")

        def test_needs_docker(exploding_container):
            assert True
        """
    )
    result = pytester.runpytest("-p", "no:cacheprovider")
    # skipped (not errored) proves the fixture never entered setup.
    result.assert_outcomes(skipped=1, passed=0, failed=0, errors=0)
