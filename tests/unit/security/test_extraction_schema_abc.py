"""ai-001 (slice-3 retrospective) — ``ExtractionSchema`` ABC enforces v1.

ADR-0017 Decision 7 calls for a ``schema_version: Literal[1]`` invariant
on every quarantined-LLM extraction schema. Pre-fix the audit row's
``QUARANTINE_EXTRACT_FIELDS`` referenced ``schema_version`` but no
Pydantic ABC enforced it on the schema classes themselves — a Slice-4
author could ship a schema with no version, or with version 2, and the
audit row would silently carry whatever was bound at the call site.

The ABC enforces the invariant at class-construction time (not at
extraction-call time): a subclass that rebinds ``schema_version`` to
anything but ``1`` raises ``TypeError`` during ``import`` — the failure
is impossible to ship past a `make check` pass.
"""

from __future__ import annotations

from typing import ClassVar, Literal

import pytest

from alfred.security.quarantine import ExtractionSchema


def test_base_class_pins_schema_version_to_1() -> None:
    """The ABC itself binds ``schema_version`` to ``1`` as a ClassVar.

    Reading the attribute through the class (not an instance) returns
    the pinned value. The audit-row consumer reads it the same way.
    """
    assert ExtractionSchema.schema_version == 1


def test_subclass_without_override_inherits_version_1() -> None:
    """A subclass that omits ``schema_version`` inherits the parent's value.

    This is the common case: schema authors write a normal Pydantic
    model with fields and don't think about versioning. Inheritance
    of the ``1`` keeps that path frictionless until Slice 4+ widens
    the literal.
    """

    class SearchResult(ExtractionSchema):
        title: str
        url: str

    assert SearchResult.schema_version == 1


def test_subclass_can_be_instantiated_with_fields() -> None:
    """The ABC inherits from Pydantic ``BaseModel`` — instantiation works.

    Smoke check that the ABC is a normal Pydantic model from the
    instance's POV: ``schema_version`` is a ``ClassVar`` so it is NOT
    a model field (``model_dump`` does not include it) and does NOT
    take a constructor kwarg.
    """

    class SearchResult(ExtractionSchema):
        title: str
        url: str

    instance = SearchResult(title="hello", url="https://example.com")
    assert instance.title == "hello"
    assert instance.url == "https://example.com"
    # ``model_dump`` returns ONLY the model fields, not ClassVars —
    # the audit row writer pulls ``schema_version`` from the *class*,
    # not from ``model_dump``.
    dumped = instance.model_dump()
    assert "schema_version" not in dumped


def test_subclass_with_wrong_version_raises_type_error() -> None:
    """Re-binding ``schema_version`` to a value other than ``1`` fails.

    The bypass path the ABC closes: an author who deliberately widens
    ``schema_version: ClassVar[Literal[2]] = 2`` to dodge the type-
    checker's Literal[1] narrowing trips the runtime equality check
    inside ``__init_subclass__``.

    The failure is at class-construction time — ``import`` fails, not
    just instantiation. A schema file shipped with the wrong version
    cannot be loaded by the application.
    """
    with pytest.raises(TypeError) as excinfo:
        # The class body executes at the ``class`` statement; the
        # ``__init_subclass__`` hook fires there. We wrap in a function
        # so pytest sees the raise without aborting the module collection.

        class _Bad(ExtractionSchema):
            schema_version: ClassVar[Literal[2]] = 2  # type: ignore[assignment]
            field: str

        # If the ABC fails to refuse the subclass, this assert would
        # never run; making it explicit (and using the class) prevents
        # the linter from flagging the body as unused.
        assert _Bad.schema_version == 2

    msg = str(excinfo.value)
    assert "schema_version" in msg
    assert "_Bad" in msg


def test_subclass_with_wrong_version_three_also_rejected() -> None:
    """Closed-allowlist check — any value other than ``1`` is rejected.

    The runtime check is equality, not range, so version ``3`` /
    ``42`` / ``-1`` all trip the same TypeError. Pinning this here so
    a future ``__init_subclass__`` rewrite that accidentally narrows
    the check (e.g. ``< 1``) surfaces immediately.
    """
    with pytest.raises(TypeError):

        class _Bad3(ExtractionSchema):
            schema_version: ClassVar[Literal[3]] = 3  # type: ignore[assignment]


def test_subclass_can_be_used_as_quarantined_to_structured_schema_arg() -> None:
    """The ABC type-hint on ``quarantined_to_structured.schema`` accepts a subclass.

    The point of the ABC is to be the schema parameter type on the
    full ``QuarantinedExtractor.extract`` (PR-S3-4) and on the stub
    ``quarantined_to_structured`` here. This test ensures a subclass
    is type-checker-acceptable as the schema arg today — so
    PR-S3-4's wiring lands without an additional type-system delta.
    """

    class Bio(ExtractionSchema):
        name: str
        affiliation: str

    # We don't await the function here — it's a NotImplementedError stub.
    # The point is that ``type[Bio]`` is assignable to
    # ``type[ExtractionSchema]``. Successful binding to a local variable
    # of the parameter's annotated type is the assertion.
    schema_arg: type[ExtractionSchema] = Bio
    assert schema_arg is Bio
    assert schema_arg.schema_version == 1
