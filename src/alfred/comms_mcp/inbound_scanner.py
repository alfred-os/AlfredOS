"""Host-side inbound content scanner (PR-S4-8, #152).

:class:`InboundContentScanner` is the host-owned step that, for a given
``adapter_kind``:

* locates the plain-text body field via
  :data:`alfred.comms_mcp.protocol.BODY_FIELD_BY_KIND` (comms-011); and
* runs the host-owned
  :data:`alfred.comms_mcp.classifier_registry.REQUIRED_CLASSIFIERS_BY_KIND` set
  (sec-002 round-3 — a plugin manifest may opt *in* to additional registered
  classifiers but can never opt *out* of the required set).

The required set is **authoritative**: an optional set is unioned in only for
classifiers that are both requested AND registered, and the required members
always run regardless of what the plugin declares. A missing / non-string body
field yields an empty ``body_text`` plus an advisory structlog event — never a
crash — because a malformed body is a (T3) data condition, not a host fault.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import structlog

from alfred.comms_mcp.classifier_registry import (
    REQUIRED_CLASSIFIERS_BY_KIND,
    get_classifier,
    is_registered,
)
from alfred.comms_mcp.errors import UnknownAdapterKindError
from alfred.comms_mcp.protocol import BODY_FIELD_BY_KIND, adapter_kind

_log = structlog.get_logger(__name__)

# Structural contract for a registered classifier: ``classify(body)`` inspects
# the (T3) body and returns zero or more opaque sub-payload markers. The
# concrete sub-payload type is owned by the adapter that registers the
# classifier (PR-S4-9's Discord sub-payload classifier); this module treats
# them as opaque ``object`` values and duck-types ``classify``.


@dataclass(frozen=True, slots=True)
class ScannedInbound:
    """Result of scanning one inbound body.

    ``body_text`` is the located plain-text (empty when absent / non-string).
    ``classifiers_run`` names every classifier the host actually dispatched.
    ``sub_payloads`` are the opaque markers the classifiers emitted.
    """

    body_text: str
    classifiers_run: frozenset[str]
    sub_payloads: tuple[object, ...] = field(default=())


class InboundContentScanner:
    """Locates the body text + runs the host-owned required classifier set."""

    def scan(
        self,
        *,
        adapter_kind: str,
        body: Mapping[str, object],
        classifiers_optional: frozenset[str] = frozenset(),
        _required_override: frozenset[str] | None = None,
    ) -> ScannedInbound:
        """Scan ``body`` for ``adapter_kind``.

        Args:
            adapter_kind: The adapter kind; MUST be a known
                :data:`adapter_kind` member, else
                :class:`UnknownAdapterKindError`.
            body: The raw (T3) adapter-specific body blob.
            classifiers_optional: Names the plugin manifest opted into. Only
                those that are also registered run; they can never displace the
                required set.
            _required_override: Test seam — substitutes the required set so a
                test can drive a registered classifier without mutating the
                frozen module-level table.
        """
        self._reject_unknown_kind(adapter_kind)
        body_text = self._locate_body_text(adapter_kind=adapter_kind, body=body)
        required = (
            _required_override
            if _required_override is not None
            else REQUIRED_CLASSIFIERS_BY_KIND.get(adapter_kind, frozenset())
        )
        classifiers_run, sub_payloads = self._run_classifiers(
            adapter_kind=adapter_kind,
            body=body,
            required=required,
            optional=classifiers_optional,
        )
        return ScannedInbound(
            body_text=body_text,
            classifiers_run=classifiers_run,
            sub_payloads=sub_payloads,
        )

    @staticmethod
    def _reject_unknown_kind(kind: str) -> None:
        if kind not in adapter_kind:
            msg = f"unknown adapter_kind {kind!r}; known: {sorted(adapter_kind)}"
            raise UnknownAdapterKindError(msg)

    def _locate_body_text(self, *, adapter_kind: str, body: Mapping[str, object]) -> str:
        field_name = BODY_FIELD_BY_KIND[adapter_kind]
        value = body.get(field_name)
        if not isinstance(value, str):
            _log.warning(
                "comms.scanner.body_field_missing",
                adapter_kind=adapter_kind,
                body_field=field_name,
                value_type=type(value).__name__,
            )
            return ""
        return value

    def _run_classifiers(
        self,
        *,
        adapter_kind: str,
        body: Mapping[str, object],
        required: frozenset[str],
        optional: frozenset[str],
    ) -> tuple[frozenset[str], tuple[object, ...]]:
        # Required is authoritative; optional adds only registered extras. The
        # registered-check is a non-raising membership predicate (reload-safe;
        # see ``is_registered``) rather than a catch on UnknownClassifierError.
        to_run = set(required)
        for name in optional:
            if not is_registered(kind=adapter_kind, name=name):
                _log.warning(
                    "comms.scanner.optional_classifier_unregistered",
                    adapter_kind=adapter_kind,
                    classifier=name,
                )
                continue
            to_run.add(name)

        ran: set[str] = set()
        sub_payloads: list[object] = []
        for name in sorted(to_run):
            classifier_cls = get_classifier(kind=adapter_kind, name=name)
            classifier = classifier_cls()
            sub_payloads.extend(classifier.classify(body))
            ran.add(name)
        return frozenset(ran), tuple(sub_payloads)


__all__ = ["InboundContentScanner", "ScannedInbound"]
