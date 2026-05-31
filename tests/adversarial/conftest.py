"""Pytest fixtures for the adversarial corpus.

Walks every `tests/adversarial/<category>/<short-name>.yaml`, validates each
through `AdversarialPayload`, and exposes the result as the
`corpus_payloads` session-scoped fixture. Two cross-file invariants are
enforced at collection time via `pytest.UsageError` (fails loud, fails
collection — no individual test can mask a corpus-shape regression):

* **id uniqueness** across the entire corpus;
* **filesystem layout** — every payload must live under the category dir
  whose name matches its declared `category` field.

Both fail-modes carry remediation text in the error message.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Final, get_args

import pytest
import yaml

from tests.adversarial.payload_schema import AdversarialPayload, Category

# Canonical category directories — derived from the `Category` Literal in
# `payload_schema.py` so the two can never drift. Adding a new variant to
# `Category` automatically extends every README/density/layout invariant
# below; deleting a variant from the Literal makes the corresponding
# category-dir contracts disappear in lock-step. The SKILL.md table is the
# external doc that mirrors this set.
_CATEGORIES: Final[tuple[str, ...]] = get_args(Category)


def _iter_payload_paths(root: Path) -> Iterator[Path]:
    """Yield every `<category>/<short-name>.yaml` path under `root`.

    Split from the validator so unit tests can mock the file layer without
    touching pytest internals.
    """
    yield from sorted(root.glob("*/*.yaml"))


@pytest.fixture(scope="session")
def corpus_root() -> Path:
    """Directory containing the adversarial corpus tree (this file's parent)."""
    return Path(__file__).parent


@pytest.fixture(scope="session")
def corpus_payloads(corpus_root: Path) -> tuple[AdversarialPayload, ...]:
    """Every adversarial payload, schema-validated and de-duplicated.

    Raises `pytest.UsageError` (collection failure) if any of:

    * a YAML file fails schema validation;
    * two payloads declare the same `id`;
    * a payload's filesystem location does not match its `category` field.
    """
    seen_ids: dict[str, Path] = {}
    payloads: list[AdversarialPayload] = []

    for path in _iter_payload_paths(corpus_root):
        raw = yaml.safe_load(path.read_text())
        try:
            payload = AdversarialPayload.model_validate(raw)
        except Exception as exc:
            msg = f"adversarial payload {path} failed schema validation: {exc}"
            raise pytest.UsageError(msg) from exc

        # Category-vs-directory cross-check. `path.parts[-2]` is the
        # `<category>` segment because the layout is
        # `tests/adversarial/<category>/<short-name>.yaml`.
        dir_category = path.parts[-2]
        if dir_category != payload.category:
            msg = (
                f"adversarial payload {path} declares category="
                f"{payload.category!r} but lives under {dir_category!r}/. "
                f"move it to tests/adversarial/{payload.category}/."
            )
            raise pytest.UsageError(msg)

        # ID-uniqueness guard.
        if payload.id in seen_ids:
            existing = seen_ids[payload.id]
            msg = (
                f"duplicate adversarial payload id={payload.id!r} at {path} "
                f"and {existing}. Pick the next monotonic NNN for the "
                f"{payload.category} category."
            )
            raise pytest.UsageError(msg)
        seen_ids[payload.id] = path
        payloads.append(payload)

    return tuple(payloads)


@pytest.fixture(scope="session")
def corpus_categories() -> tuple[str, ...]:
    """Canonical category-directory names (used by corpus-health checks)."""
    return _CATEGORIES
