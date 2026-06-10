"""Host-owned inbound-classifier registry (PR-S4-8, #152).

sec-002 round-3: the set of content classifiers run on an inbound message is
owned **host-side**, keyed by ``adapter_kind``. A plugin cannot opt out of
its required classifier set — the host loads :data:`REQUIRED_CLASSIFIERS_BY_KIND`
and runs every named classifier regardless of what the plugin manifest
declares (a manifest may opt *in* to additional registered classifiers, never
*out* of the required set).

An empty required set is permitted only with a
:data:`MARKER_NO_CLASSIFIERS_NEEDED` justification (the plain-text / TUI
exception per spec §8.5). The AST guard
``tests/unit/comms_mcp/test_required_classifiers_complete.py`` refuses any
adapter-kind addition that lands an empty set without a marker — mirroring
the ``cib-2026-004`` adversarial corpus entry.

Classifier implementations register themselves at import time via
:func:`register_classifier`. The registry is a private module-level dict
keyed by ``(kind, name)``; the decorator is idempotent under module reload
(re-registering the same class is a no-op) but loud on a genuine key
collision with a different class (a silent overwrite could swap a strict
classifier for a lax one).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from types import MappingProxyType
from typing import Final

from alfred.errors import AlfredError

# Per adapter kind, the frozenset of classifier NAMES the host MUST run on
# every inbound message. Every ``adapter_kind`` member needs an entry here
# (completeness is pinned by the test). PR-S4-9 adds the ``"discord"`` entry
# (``frozenset({"discord_sub_payloads"})``); PR-S4-10 adds ``"tui"``.
REQUIRED_CLASSIFIERS_BY_KIND: Final[MappingProxyType[str, frozenset[str]]] = MappingProxyType(
    {
        "alfred_comms_test": frozenset(),  # plain-text only — see MARKER below
        "discord": frozenset({"discord_sub_payloads"}),  # PR-S4-9
        "tui": frozenset(),  # PR-S4-10 — plain-text only; see MARKER below
    }
)

# Justification for every adapter kind whose required-classifier set is empty
# (spec §8.5). An empty set without an entry here is a release blocker caught
# by the AST guard — it would silently disable host-side content scanning for
# that adapter kind.
MARKER_NO_CLASSIFIERS_NEEDED: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "alfred_comms_test": ("reference plugin emits plain-text only; no sub-payloads possible"),
        "tui": (
            "operator-local terminal: the operator types plain text into the "
            "input widget; the TUI has no platform sub-payloads (no embeds, "
            "attachments, link unfurls) — nothing for a classifier to promote"
        ),
    }
)


class UnknownClassifierError(AlfredError):
    """Raised when :func:`get_classifier` is asked for an unregistered classifier."""


# Private registry: ``(kind, name) -> classifier class``. Populated at import
# time by ``register_classifier``. Not exported — access is via the decorator
# (write) and ``get_classifier`` (read) only.
_REGISTRY: dict[tuple[str, str], type] = {}

# Guards the read-check-write in ``register_classifier``. Registration is
# import-time (single-threaded under the import lock in practice), but the lock
# makes the check+write atomic regardless of how/when the decorator runs — so a
# concurrent registration can never race the collision check into a silent
# overwrite.
_REGISTRY_LOCK: Final[threading.Lock] = threading.Lock()


def register_classifier(*, kind: str, name: str) -> Callable[[type], type]:
    """Register a classifier class under ``(kind, name)``; return it unchanged.

    Idempotent under module reload: re-registering the identical class under
    the same key is a no-op. A collision with a *different* class raises
    ``ValueError`` — a silent overwrite could substitute a permissive
    classifier for a strict one, weakening the inbound scan.

    The collision check and the write are held under :data:`_REGISTRY_LOCK` so
    they are atomic even if registration is ever driven concurrently.
    """

    def _decorate(cls: type) -> type:
        key = (kind, name)
        with _REGISTRY_LOCK:
            existing = _REGISTRY.get(key)
            if existing is not None and existing is not cls:
                msg = (
                    f"classifier {name!r} for kind {kind!r} already registered to "
                    f"{existing!r}; refusing to overwrite with {cls!r}"
                )
                raise ValueError(msg)
            _REGISTRY[key] = cls
        return cls

    return _decorate


def get_classifier(*, kind: str, name: str) -> type:
    """Return the classifier class registered under ``(kind, name)``.

    Raises:
        UnknownClassifierError: If no classifier is registered under the key.
    """
    try:
        return _REGISTRY[(kind, name)]
    except KeyError as exc:
        msg = f"no classifier registered for kind={kind!r} name={name!r}"
        raise UnknownClassifierError(msg) from exc


def is_registered(*, kind: str, name: str) -> bool:
    """Return ``True`` iff a classifier is registered under ``(kind, name)``.

    The non-raising companion to :func:`get_classifier`. Callers that decide
    whether to dispatch an *optional* classifier use this rather than catching
    :class:`UnknownClassifierError` — exception-class identity is unstable under
    ``importlib.reload`` (a reloaded module's ``UnknownClassifierError`` is a
    distinct class object), so a membership predicate is the reload-safe seam.
    """
    return (kind, name) in _REGISTRY


__all__ = [
    "MARKER_NO_CLASSIFIERS_NEEDED",
    "REQUIRED_CLASSIFIERS_BY_KIND",
    "UnknownClassifierError",
    "get_classifier",
    "is_registered",
    "register_classifier",
]
