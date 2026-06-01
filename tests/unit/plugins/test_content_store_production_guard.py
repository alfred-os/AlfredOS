"""sec-S3-003 — ``InMemoryContentStore`` refuses to construct in production.

The in-memory stub lacks production-safety properties (no TTL, no
single-use enforcement, no cross-process visibility). A bootstrap that
forgets to inject the Redis store would silently fall back to it.

The constructor reads ``ALFRED_ENV`` and raises
:class:`InMemoryContentStoreProductionError` when the value is anything
outside the dev/test allowlist. The pytest suite runs with ``ALFRED_ENV``
unset (or set to ``test``), so existing tests are unaffected.
"""

from __future__ import annotations

import pytest

from alfred.plugins.content_store_base import (
    InMemoryContentStore,
    InMemoryContentStoreProductionError,
)


def test_constructor_succeeds_when_alfred_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset ``ALFRED_ENV`` mirrors the gate-factory "unset = development" rule."""
    monkeypatch.delenv("ALFRED_ENV", raising=False)
    # No exception expected.
    store = InMemoryContentStore()
    # Store is functional, not a degenerate stub.
    assert store.get("anything") is None


def test_constructor_succeeds_when_alfred_env_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ALFRED_ENV=development`` is the explicit dev sentinel."""
    monkeypatch.setenv("ALFRED_ENV", "development")
    InMemoryContentStore()  # no raise


def test_constructor_succeeds_when_alfred_env_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ALFRED_ENV=test`` is the pytest fixture environment."""
    monkeypatch.setenv("ALFRED_ENV", "test")
    InMemoryContentStore()  # no raise


def test_constructor_succeeds_on_whitespace_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A whitespace-only ``ALFRED_ENV=" "`` is normalised to empty / dev.

    Same edge case the gate-factory's :func:`is_production` handles —
    a shell-export chain ``export ALFRED_ENV=$UNSET_VAR`` produces a
    present-but-empty value; treating it as production would surprise
    operators who think they're in dev.
    """
    monkeypatch.setenv("ALFRED_ENV", "   ")
    InMemoryContentStore()  # no raise


def test_constructor_raises_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ALFRED_ENV=production`` trips the guard at construction time.

    The check is loud, not silent: a misconfigured production host
    receives a ``RuntimeError``-shaped failure (the
    :class:`InMemoryContentStoreProductionError` derives from
    :class:`AlfredError`) at bootstrap rather than running under a stub
    store that drops single-use semantics on the floor.
    """
    monkeypatch.setenv("ALFRED_ENV", "production")
    with pytest.raises(InMemoryContentStoreProductionError) as excinfo:
        InMemoryContentStore()
    # Error mentions the offending env value AND points at the fix
    # (inject a Redis-backed store via the StdioTransport kwarg).
    msg = str(excinfo.value)
    assert "production" in msg
    assert "Redis" in msg or "content_store=" in msg


def test_constructor_raises_for_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ALFRED_ENV=staging`` is rejected — closed allowlist, not an open list.

    Same posture as the gate factory: anything outside the dev/test
    sentinels is treated as production-equivalent so a typo'd label
    (``"prdouction"``, ``"staging"``, ``"prod"``) trips the safer path.
    """
    monkeypatch.setenv("ALFRED_ENV", "staging")
    with pytest.raises(InMemoryContentStoreProductionError):
        InMemoryContentStore()


def test_constructor_raises_for_typo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo'd env value (``"developement"``) is treated as production.

    The misspelling tested here was specifically called out in the
    gate-factory rationale: the safer gate wins on operator error.
    """
    monkeypatch.setenv("ALFRED_ENV", "developement")
    with pytest.raises(InMemoryContentStoreProductionError):
        InMemoryContentStore()
