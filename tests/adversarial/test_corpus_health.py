"""Cross-cutting health checks for the adversarial corpus.

Three assertions that hold on the empty Slice-2 corpus and remain meaningful
as Slice 3 populates it:

* every payload parses against `AdversarialPayload` (enforced by the
  `corpus_payloads` fixture; this test is a tripwire making the contract
  explicit);
* every payload `id` is unique across categories (also fixture-enforced; the
  belt-and-braces assertion gives a readable failure message);
* every canonical category directory carries a `README.md` so contributors
  always have the per-category context one `ls` away.

The schema-validity and uniqueness guards already fail collection via
`pytest.UsageError` inside the fixture. These tests keep the contracts
visible in the test suite output and protect against fixture-rewrite
regressions.
"""

from __future__ import annotations

from pathlib import Path

from tests.adversarial.payload_schema import AdversarialPayload


def test_all_payloads_schema_valid(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    # The fixture itself runs `AdversarialPayload.model_validate` on every
    # file and raises `pytest.UsageError` on failure. By the time this test
    # runs, every member is guaranteed to be an `AdversarialPayload`. We
    # assert the type contract explicitly so a future fixture refactor that
    # drops the validation step fails *this* test loudly, not later via a
    # confusing AttributeError elsewhere.
    for payload in corpus_payloads:
        assert isinstance(payload, AdversarialPayload)


def test_all_payload_ids_unique(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    # Belt-and-braces: the conftest's UsageError catches this earlier with
    # full path context, but the explicit assertion keeps the invariant in
    # the test suite output where contributors look first.
    ids = [p.id for p in corpus_payloads]
    assert len(set(ids)) == len(ids), f"duplicate adversarial payload ids: {ids}"


def test_every_category_directory_has_readme(
    corpus_root: Path,
    corpus_categories: tuple[str, ...],
) -> None:
    missing = [
        category
        for category in corpus_categories
        if not (corpus_root / category / "README.md").is_file()
    ]
    assert not missing, (
        f"adversarial categories missing README.md: {missing}. "
        "Every category dir documents its threat model + ingestion paths."
    )
