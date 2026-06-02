"""Per-package fixtures for ``tests/unit/plugins/web_fetch/``.

Provides the ``fresh_registry_allow_system`` fixture without importing
``tests.unit.hooks.conftest`` as a pytest plugin (that path triggers
``pluggy``'s duplicate-registration error when the hooks conftest is
already loaded via ``tests/unit/hooks/`` collection).

The fixture mirrors the shape in ``tests/unit/hooks/conftest.py`` —
fresh :class:`HookRegistry` with ``allow_system=True`` and
``strict_declarations=False`` — but is defined locally so each test
package owns its own copy of the registry-swap discipline.

sec-pr-s3-5-003 / H3: also auto-stubs :func:`socket.getaddrinfo` so the
host-IP guard (see :mod:`alfred.plugins.web_fetch.host_ip_guard`) does
not hit real DNS in the unit suite. Tests that exercise the guard's
behaviour patch ``getaddrinfo`` themselves with the per-test fake; the
autouse default just returns a benign public IP so tests written before
the guard landed keep passing.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any

import pytest

from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from tests.helpers.gates import make_default_test_gate


@pytest.fixture(autouse=True)
def _stub_getaddrinfo_for_public_ip(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auto-stub ``socket.getaddrinfo`` for the IP-guard hostnames only.

    Slice-3 PR-S3-5 wired a host-IP allowlist guard into the dispatcher
    (sec-pr-s3-5-003). Existing unit tests use ``example.com`` as a
    convenience hostname; without a stub they would either hit real
    DNS (network dependency) or get refused depending on what the
    resolver returned. We stub a closed set of "test fixture" hostnames
    (the dispatcher-test convenience names) to ``8.8.8.8`` — a public
    IP that passes ``classify_ip_refusal`` — and pass every OTHER
    hostname through to the real resolver so testcontainers-backed
    Redis / Postgres tests still bootstrap correctly.

    Tests that need to exercise the guard's refusal arms (see
    ``test_host_ip_guard.py``) override the stub by patching the same
    symbol with their own fake INSIDE the test body; pytest's
    monkeypatch resolves the per-test patch over the autouse default.
    The ``test_host_ip_guard`` module opts out entirely via a
    module-level marker so we don't double-patch.
    """
    if request.node.get_closest_marker("no_getaddrinfo_stub"):
        return

    # The closed set of hostnames the dispatcher-suite uses as the
    # convenience public-domain placeholder. Anything outside this set
    # falls through to the real resolver — testcontainers-backed Redis
    # tests resolve ``localhost`` / ``127.0.0.1`` / docker-host names
    # that must hit the real resolution path.
    _stub_hosts: frozenset[str] = frozenset({"example.com", "dns.google"})
    real_getaddrinfo = socket.getaddrinfo

    def _fake(host: str, port: int | None, *args: Any, **kwargs: Any) -> Any:
        if host in _stub_hosts:
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake)


@pytest.fixture
def fresh_registry_allow_system() -> Iterator[HookRegistry]:
    """Yield a brand-new :class:`HookRegistry` with ``allow_system=True``.

    Captures the pre-test registry at fixture entry; restores it on
    teardown so the module-level singleton is bit-for-bit identical
    after the test. ``strict_declarations=False`` so a test body can
    register-then-subscribe without tripping the strict-declaration
    contract on un-declared hookpoints.
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_default_test_gate(allow_system=True),
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)
