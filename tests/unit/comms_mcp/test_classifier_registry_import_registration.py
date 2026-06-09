"""``register_classifier`` decorator import-time registration (Task 12)."""

from __future__ import annotations

import importlib

import pytest

import alfred.comms_mcp.classifier_registry as registry_mod
from alfred.comms_mcp.classifier_registry import (
    UnknownClassifierError,
    get_classifier,
    register_classifier,
)


def test_decorator_registers_class() -> None:
    @register_classifier(kind="alfred_comms_test", name="noop_classifier")
    class NoopClassifier: ...

    assert get_classifier(kind="alfred_comms_test", name="noop_classifier") is NoopClassifier


def test_decorator_returns_class_unchanged() -> None:
    @register_classifier(kind="alfred_comms_test", name="passthrough")
    class Passthrough: ...

    assert Passthrough.__name__ == "Passthrough"


def test_get_classifier_unknown_raises() -> None:
    with pytest.raises(UnknownClassifierError):
        get_classifier(kind="alfred_comms_test", name="does_not_exist")


def test_decorator_idempotent_on_reimport() -> None:
    # Importing the module twice must not raise "double registration".
    importlib.reload(registry_mod)
    importlib.reload(registry_mod)  # second reload must not error


def test_re_registration_same_class_is_noop() -> None:
    @register_classifier(kind="alfred_comms_test", name="stable")
    class Stable: ...

    # Re-registering the exact same class under the same key is tolerated.
    register_classifier(kind="alfred_comms_test", name="stable")(Stable)
    assert get_classifier(kind="alfred_comms_test", name="stable") is Stable


def test_re_registration_different_class_raises() -> None:
    @register_classifier(kind="alfred_comms_test", name="conflict")
    class First: ...

    with pytest.raises(ValueError, match="already registered"):

        @register_classifier(kind="alfred_comms_test", name="conflict")
        class Second: ...
