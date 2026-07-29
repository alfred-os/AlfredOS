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

import yaml

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


# Payloads that predate this gate and are not yet named in their category README.
# ENUMERATED, not date-gated or count-gated: an explicit allow-list means any NEW
# undocumented payload fails immediately, while the existing debt stays visible instead
# of being silently tolerated by a weaker check. Shrink this list, never grow it —
# a new entry here should be a review conversation, not a convenience.
_README_UNDOCUMENTED_BACKLOG: frozenset[str] = frozenset(
    {
        "cap-2026-001", "cap-2026-002", "cap-2026-003", "cap-2026-004",
        "cap-2026-005", "cap-2026-006", "cap-2026-007", "cap-2026-008",
        "cap-2026-009", "cap-2026-010", "cap-2026-011", "cap-2026-012",
        "cib-2026-007", "de-2026-017", "de-2026-018", "de-2026-019",
        "de-2026-020", "dlp-2026-001", "hk-2026-001", "hk-2026-002",
        "hk-2026-003", "hk-2026-004", "hk-2026-005", "hk-2026-006",
        "pi-2026-001", "pi-2026-002", "pi-2026-003", "pi-2026-004",
        "pi-2026-005", "pi-2026-006", "pi-2026-007", "pi-2026-008",
        "pi-2026-009", "pi-2026-010", "pi-2026-011", "pi-2026-012",
        "pi-2026-013", "pi-2026-014", "pi-2026-015", "sbx-2026-021",
        "sbx-2026-022", "sbx-2026-023", "sbx-2026-024", "sbx-2026-025",
        "sbx-2026-026", "sbx-2026-027", "sbx-2026-028", "tl-2026-008",
        "tl-2026-009",
    }
)  # fmt: skip


def _source_filename(corpus_root: Path, payload: AdversarialPayload) -> str | None:
    """Return the basename of the YAML whose top-level ``id`` IS ``payload.id``.

    Parses the ``id`` key rather than substring-searching the file text. Payloads
    routinely cite each other in ``provenance``/``references`` prose — 23 such
    in-category cross-references exist — so a substring match resolved an id to a
    DIFFERENT payload's filename and let it count as documented because that other
    file appeared in the README. A fail-open in a drift gate (CodeRabbit).
    """
    for path in sorted((corpus_root / payload.category).glob("*.yaml")):
        try:
            parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:  # pragma: no cover - the fixture already rejects these
            continue
        if isinstance(parsed, dict) and parsed.get("id") == payload.id:
            return path.name
    return None


def _is_documented(corpus_root: Path, payload: AdversarialPayload) -> bool:
    """True when the category README names the payload by id or by its source filename.

    Either key counts: the older matrices cite the YAML filename, the newer ones cite
    the id, and both make the payload findable from the README.
    """
    readme = corpus_root / payload.category / "README.md"
    if not readme.is_file():
        return False
    text = readme.read_text(encoding="utf-8")
    if payload.id in text:
        return True
    filename = _source_filename(corpus_root, payload)
    return filename is not None and filename in text


def test_every_new_payload_appears_in_its_category_readme(
    corpus_root: Path,
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """A payload absent from its category's coverage matrix is undocumented drift.

    `tier_laundering/README.md` calls its matrix "the contract between this category's
    threat model and the slice's task graph — drift between the two is a release-blocker",
    but nothing enforced it: only the README's EXISTENCE was checked, so three payloads
    landed in one PR with no matrix row and the suite stayed green.
    """
    orphans = sorted(
        payload.id
        for payload in corpus_payloads
        if not _is_documented(corpus_root, payload)
        and payload.id not in _README_UNDOCUMENTED_BACKLOG
    )
    assert not orphans, (
        f"payloads missing from their category README coverage matrix: {orphans}. "
        "Add a matrix row naming the attack vector and the owning PR/task."
    )


def test_the_readme_backlog_has_no_stale_entries(
    corpus_root: Path,
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """The backlog must shrink as READMEs are filled in, not linger.

    Without this, a documented-or-deleted payload stays listed forever and the allow-list
    stops describing reality — the failure mode that turns an allow-list into a
    rubber stamp.
    """
    by_id = {payload.id: payload for payload in corpus_payloads}
    stale = sorted(
        payload_id
        for payload_id in _README_UNDOCUMENTED_BACKLOG
        if payload_id not in by_id or _is_documented(corpus_root, by_id[payload_id])
    )
    assert not stale, (
        f"backlog entries that are now documented or deleted: {stale}. "
        "Remove them from _README_UNDOCUMENTED_BACKLOG."
    )
