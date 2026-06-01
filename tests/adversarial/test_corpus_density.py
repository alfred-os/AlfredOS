"""Corpus-density guard tests for Slice-3 adversarial categories.

PR-S3-0a ships the `tier_laundering` and `dlp_egress` category dirs as
README-only stubs. The actual payloads (YAML files + pytest modules) land
across PR-S3-1, PR-S3-3a, PR-S3-4, and PR-S3-5. Without these guards,
those follow-on PRs could ship green even if a category dir stays empty —
the existing `corpus_payloads` fixture happily walks an empty tree.

The two tests below are marked `xfail(strict=True)` so today (zero payloads
under each dir) they show as `XFAIL` rather than `FAIL`. The `strict=True`
flag flips the contract: the moment a payload-bearing PR lands, the test
passes, and the strict-xfail marker itself fails — forcing the implementer
to delete the marker and formalise the "this category is populated" guard
in the test suite. From that point forward, deleting all payloads from
the dir would fail CI loudly.

Provenance: review-feedback findings on PR-S3-0a (test-engineer + reviewer
+ security), `docs/superpowers/plans/2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md`.
"""

from __future__ import annotations

from pathlib import Path


def _count_payload_artifacts(category_dir: Path) -> int:
    """Return the number of YAML payloads + pytest modules under `category_dir`.

    A payload is either a `<short-name>.yaml` file (declarative) or a
    `test_*.py` module (Python-level attack vector — see spec §12.2
    fixture-vs-pytest allocation). `__init__.py` and `README.md` do not
    count; they are scaffolding.
    """
    if not category_dir.is_dir():
        return 0
    yaml_payloads = list(category_dir.glob("*.yaml"))
    pytest_modules = [p for p in category_dir.glob("test_*.py") if p.name != "__init__.py"]
    return len(yaml_payloads) + len(pytest_modules)


def test_tier_laundering_corpus_has_payloads() -> None:
    """`tests/adversarial/tier_laundering/` must carry at least one payload.

    Forever-green density guard. The owning PR (S3-1) landed
    ``tl_cast_bypass.yaml`` + sibling payloads; from this point forward,
    deleting every payload from the dir fails CI loudly. The previous
    ``xfail(strict=True)`` marker self-destructed on the first arriving
    payload, by design — its purpose was to force this assertion to be
    promoted to a real guard the moment the contract was satisfied.
    """
    category_dir = Path(__file__).parent / "tier_laundering"
    count = _count_payload_artifacts(category_dir)
    assert count > 0, (
        f"tier_laundering corpus has 0 payloads — expected ≥1 after the "
        f"owning PR (S3-1 / S3-3a / S3-4) merges. Searched: {category_dir}"
    )


def test_dlp_egress_corpus_has_payloads() -> None:
    """`tests/adversarial/dlp_egress/` must carry at least one payload.

    PR-S3-5 (`web.fetch` plugin) ships the first two payloads here —
    ``de-2026-001`` (canary token in HTML) and ``de-2026-002`` (the
    documented cross-field secret-leak gap deferred to Slice 4). The
    earlier `xfail(strict=True)` placeholder enforced the "dir
    populated by Slice 3" contract; with payloads landed the marker
    is gone and the count assertion stands on its own.
    """
    category_dir = Path(__file__).parent / "dlp_egress"
    count = _count_payload_artifacts(category_dir)
    assert count > 0, (
        f"dlp_egress corpus has 0 payloads — expected ≥1 after the "
        f"owning PR (S3-5) merges. Searched: {category_dir}"
    )
