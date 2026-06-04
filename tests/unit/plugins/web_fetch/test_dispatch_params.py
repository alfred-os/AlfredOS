"""WebFetchDispatchParams model — host-side validation matrix.

Per spec §2.1: extra="forbid", strict=True, frozen=True.
Defence-in-depth before transport.dispatch crosses the wire to the
plugin subprocess (issue #147).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.plugins.web_fetch.dispatch_params import WebFetchDispatchParams

_VALID_KWARGS: dict[str, object] = {
    "url": "https://example.com/",
    "headers": {"Accept": "text/html"},
    "redis_url": "redis://localhost:6379",
    "correlation_id": "cid-test",
    "content_handle_id": "00000000-0000-0000-0000-000000000001",
}


def test_valid_construction_works() -> None:
    """Full required kwarg set succeeds; defaults populate skip_tls_verify
    + size_limit_bytes (spec §2.1)."""
    params = WebFetchDispatchParams(**_VALID_KWARGS)  # type: ignore[arg-type]
    assert params.url == "https://example.com/"
    assert params.skip_tls_verify is False
    assert params.size_limit_bytes == 5 * 1024 * 1024


def test_model_dump_roundtrip() -> None:
    """``.model_dump()`` produces the wire-format dict consumed by
    ``transport.dispatch`` (spec §2 architecture diagram)."""
    params = WebFetchDispatchParams(**_VALID_KWARGS)  # type: ignore[arg-type]
    d = params.model_dump()
    assert d["url"] == "https://example.com/"
    assert d["skip_tls_verify"] is False
    assert d["size_limit_bytes"] == 5 * 1024 * 1024
    assert d["headers"] == {"Accept": "text/html"}
    assert d["redis_url"] == "redis://localhost:6379"
    assert d["correlation_id"] == "cid-test"
    assert d["content_handle_id"] == "00000000-0000-0000-0000-000000000001"


@pytest.mark.parametrize(
    "missing",
    ["url", "headers", "redis_url", "correlation_id", "content_handle_id"],
)
def test_missing_required_field_raises(missing: str) -> None:
    """Each required field is enforced — a missing kwarg raises
    ``ValidationError`` (spec §5.1)."""
    kwargs = {k: v for k, v in _VALID_KWARGS.items() if k != missing}
    with pytest.raises(ValidationError):
        WebFetchDispatchParams(**kwargs)  # type: ignore[arg-type]


def test_extra_field_forbidden() -> None:
    """``extra="forbid"`` — a future dispatcher adding a key without
    updating the model fails loud at construction (spec §2.1)."""
    with pytest.raises(ValidationError):
        WebFetchDispatchParams(**_VALID_KWARGS, unexpected_key="x")  # type: ignore[arg-type]


def test_wrong_type_url_strict() -> None:
    """``strict=True`` rejects int for str fields (spec §2.1)."""
    with pytest.raises(ValidationError):
        WebFetchDispatchParams(**{**_VALID_KWARGS, "url": 42})  # type: ignore[arg-type]


def test_wrong_type_headers_strict() -> None:
    """``strict=True`` rejects str where a dict was declared."""
    with pytest.raises(ValidationError):
        WebFetchDispatchParams(  # type: ignore[arg-type]
            **{**_VALID_KWARGS, "headers": "Accept: text/html"}
        )


def test_wrong_type_correlation_id_strict() -> None:
    """``strict=True`` rejects int where a str was declared."""
    with pytest.raises(ValidationError):
        WebFetchDispatchParams(**{**_VALID_KWARGS, "correlation_id": 99})  # type: ignore[arg-type]


def test_size_limit_must_be_positive() -> None:
    """``Field(gt=0)`` defends against a 0/negative value reaching
    the plugin (spec §2.1)."""
    for bad in (0, -1, -1000):
        with pytest.raises(ValidationError):
            WebFetchDispatchParams(**_VALID_KWARGS, size_limit_bytes=bad)  # type: ignore[arg-type]


def test_size_limit_must_be_int_strict() -> None:
    """``strict=True`` rejects float for int field — no silent
    truncation."""
    with pytest.raises(ValidationError):
        WebFetchDispatchParams(**_VALID_KWARGS, size_limit_bytes=1.5)  # type: ignore[arg-type]


def test_skip_tls_verify_strict_bool() -> None:
    """``strict=True`` rejects int 1 for bool — no silent coercion of
    a truthy value into ``True`` for the TLS escape hatch."""
    with pytest.raises(ValidationError):
        WebFetchDispatchParams(**_VALID_KWARGS, skip_tls_verify=1)  # type: ignore[arg-type]


def test_frozen() -> None:
    """``frozen=True`` — the validated payload is the wire format; nothing
    mutates it post-validation (spec §2.1)."""
    params = WebFetchDispatchParams(**_VALID_KWARGS)  # type: ignore[arg-type]
    with pytest.raises((ValidationError, TypeError, AttributeError)):
        params.url = "https://changed.example/"  # type: ignore[misc]


def test_defaults_when_optional_kwargs_omitted() -> None:
    """The two optional kwargs default — skip_tls_verify=False,
    size_limit_bytes=5MB."""
    params = WebFetchDispatchParams(**_VALID_KWARGS)  # type: ignore[arg-type]
    assert params.skip_tls_verify is False
    assert params.size_limit_bytes == 5 * 1024 * 1024


def test_skip_tls_verify_true_accepted() -> None:
    """Explicit ``True`` is accepted (dev escape hatch — the parent-side
    ``TlsPolicy`` check is the authoritative gate)."""
    params = WebFetchDispatchParams(**_VALID_KWARGS, skip_tls_verify=True)  # type: ignore[arg-type]
    assert params.skip_tls_verify is True
