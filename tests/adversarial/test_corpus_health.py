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

import hashlib
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
# of being silently tolerated by a weaker check.
#
# It may only ever SHRINK, and that is ENFORCED by the digest pin below rather than
# asserted in prose. An earlier revision kept a second `_README_BACKLOG_BASELINE` name
# aliased to this same frozenset and compared the two — set difference against itself,
# always empty, so the shrink test could never fire. A gate written to prevent silent
# exemptions that was itself structurally incapable of failing (CodeRabbit).
_README_UNDOCUMENTED_BACKLOG: frozenset[str] = frozenset(
    {
        "cap-2026-001", "cap-2026-002", "cap-2026-003", "cap-2026-004",
        "cap-2026-005", "cap-2026-006", "cap-2026-007", "cap-2026-008",
        "cap-2026-009", "cap-2026-010", "cap-2026-011", "cap-2026-012",
        "cib-2026-006", "cib-2026-007", "de-2026-017", "de-2026-018",
        "de-2026-019",
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

# Digest of the sorted allow-list above. Pinned rather than derived from the same literal:
# any ADDITION changes the digest, so growing the list forces a deliberate edit to a
# constant whose test says it must only shrink — visible in review instead of silent.
# `_EXPECTED_BACKLOG_COUNT` is redundant with the digest but names the drift direction in
# the failure message, which a bare hash mismatch cannot.
_EXPECTED_BACKLOG_COUNT: int = 50
_EXPECTED_BACKLOG_SHA256: str = "7c8c8bde4a6c9cb45f669caf14792f012e5c7cee42b9b402ccf666be3e9171fe"


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
    # Only markdown TABLE ROWS count — the coverage matrix. Searching the whole file let
    # prose, a cross-reference in another row's narrative, or a code sample satisfy the
    # gate, so a payload could read as documented without ever having a matrix row
    # (CodeRabbit).
    rows = [
        line
        for line in readme.read_text(encoding="utf-8").splitlines()
        if line.lstrip().startswith("|")
    ]
    if not rows:
        return False
    matrix = "\n".join(rows)
    if payload.id in matrix:
        return True
    filename = _source_filename(corpus_root, payload)
    return filename is not None and filename in matrix


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


def test_the_readme_backlog_can_only_shrink() -> None:
    """A new undocumented payload must not be waved through by extending the allow-list.

    The backlog carries PRE-EXISTING debt. Growing it converts the gate into a rubber
    stamp one line at a time — the failure mode an enumerated allow-list exists to
    prevent.

    Pinned by DIGEST, not by comparing the set to a second name for itself: the previous
    revision did exactly that (`_README_BACKLOG_BASELINE` was an alias of this frozenset),
    so the difference was always empty and the test could not fail. Any addition changes
    the digest and reds here.

    Honest limit: a determined author can update the digest alongside the addition. That
    is a two-place edit naming this constant, which shows up in review — as opposed to a
    silent one-line exemption. Shrinking legitimately also requires updating the pin, and
    the failure message says which direction moved.
    """
    ids = sorted(_README_UNDOCUMENTED_BACKLOG)
    digest = hashlib.sha256("\n".join(ids).encode()).hexdigest()

    assert len(ids) <= _EXPECTED_BACKLOG_COUNT, (
        f"the README allow-list GREW from {_EXPECTED_BACKLOG_COUNT} to {len(ids)} entries. "
        "It may only shrink — give the payload a coverage-matrix row, not an exemption."
    )
    assert digest == _EXPECTED_BACKLOG_SHA256, (
        f"the README allow-list changed ({len(ids)} entries, digest {digest[:12]}…). "
        f"If you REMOVED an entry, update _EXPECTED_BACKLOG_COUNT to {len(ids)} and "
        f"_EXPECTED_BACKLOG_SHA256 to {digest}. If you ADDED one, don't — document the "
        "payload in its category README instead."
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
