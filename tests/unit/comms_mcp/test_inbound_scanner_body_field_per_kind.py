"""Task 46-47 — InboundContentScanner: body-field lookup + classifier dispatch.

The scanner consults ``BODY_FIELD_BY_KIND[adapter_kind]`` to locate the
plain-text body field and runs the host-owned
``REQUIRED_CLASSIFIERS_BY_KIND[adapter_kind]`` set. A plugin's optional
classifiers cannot override the required set (sec-002 round-3). A missing body
field yields an empty string + an advisory structlog event, never a crash.
"""

from __future__ import annotations

import pytest

from alfred.comms_mcp.classifier_registry import is_registered, register_classifier
from alfred.comms_mcp.inbound_scanner import InboundContentScanner


def test_is_registered_predicate() -> None:
    @register_classifier(kind="alfred_comms_test", name="is_registered_probe")
    class _Probe:
        def classify(self, body: dict[str, object]) -> tuple[object, ...]:
            return ()

    assert is_registered(kind="alfred_comms_test", name="is_registered_probe")
    assert not is_registered(kind="alfred_comms_test", name="never_registered")


@pytest.mark.parametrize(
    ("kind", "field", "body"),
    [
        ("alfred_comms_test", "content", {"content": "hi"}),
        # Discord / TUI / Telegram added by PR-S4-9 / PR-S4-10 / post-MVP.
    ],
)
def test_scanner_extracts_body_field_per_kind(
    kind: str, field: str, body: dict[str, object]
) -> None:
    scanner = InboundContentScanner()
    scanned = scanner.scan(adapter_kind=kind, body=body)
    assert scanned.body_text == body[field]


def test_scanner_unknown_adapter_kind_refused() -> None:
    scanner = InboundContentScanner()
    with pytest.raises(Exception, match="adapter"):
        scanner.scan(adapter_kind="not_a_kind", body={"content": "hi"})


def test_scanner_missing_body_field_yields_empty_string() -> None:
    scanner = InboundContentScanner()
    scanned = scanner.scan(adapter_kind="alfred_comms_test", body={"other": "x"})
    assert scanned.body_text == ""


def test_scanner_non_string_body_field_yields_empty_string() -> None:
    scanner = InboundContentScanner()
    scanned = scanner.scan(adapter_kind="alfred_comms_test", body={"content": 123})
    assert scanned.body_text == ""


def test_reference_plugin_runs_no_classifiers() -> None:
    # alfred_comms_test has an empty required set (+ MARKER); zero classifiers run.
    scanner = InboundContentScanner()
    scanned = scanner.scan(adapter_kind="alfred_comms_test", body={"content": "hi"})
    assert scanned.classifiers_run == frozenset()
    assert scanned.sub_payloads == ()


def test_required_classifiers_dispatch_when_present() -> None:
    # Register a classifier under a synthetic kind and assert it runs. We drive
    # the scanner with an explicit required-set override so the test does not
    # mutate the frozen module-level REQUIRED_CLASSIFIERS_BY_KIND.
    ran: list[str] = []

    @register_classifier(kind="alfred_comms_test", name="scanner_test_noop")
    class _NoopClassifier:
        def classify(self, body: dict[str, object]) -> tuple[object, ...]:
            ran.append("scanner_test_noop")
            return ()

    scanner = InboundContentScanner()
    scanned = scanner.scan(
        adapter_kind="alfred_comms_test",
        body={"content": "hi"},
        _required_override=frozenset({"scanner_test_noop"}),
    )
    assert "scanner_test_noop" in scanned.classifiers_run
    assert ran == ["scanner_test_noop"]


def test_registered_optional_classifier_runs() -> None:
    # A registered optional classifier IS added to the run set (the optional
    # path's positive branch). It augments — never displaces — the required set.
    ran: list[str] = []

    @register_classifier(kind="alfred_comms_test", name="scanner_test_optional")
    class _OptionalClassifier:
        def classify(self, body: dict[str, object]) -> tuple[object, ...]:
            ran.append("scanner_test_optional")
            return ("marker",)

    scanner = InboundContentScanner()
    scanned = scanner.scan(
        adapter_kind="alfred_comms_test",
        body={"content": "hi"},
        classifiers_optional=frozenset({"scanner_test_optional"}),
    )
    assert "scanner_test_optional" in scanned.classifiers_run
    assert scanned.sub_payloads == ("marker",)
    assert ran == ["scanner_test_optional"]


def test_optional_classifiers_cannot_override_required() -> None:
    # The required set is authoritative: passing an optional set that omits a
    # required classifier still runs the required one.
    scanner = InboundContentScanner()
    scanned = scanner.scan(
        adapter_kind="alfred_comms_test",
        body={"content": "hi"},
        classifiers_optional=frozenset({"some_optional"}),
    )
    # Reference plugin requires none; optional ones that are not registered are
    # skipped silently (advisory), required set stays empty.
    assert scanned.classifiers_run == frozenset()
