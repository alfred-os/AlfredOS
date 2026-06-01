"""Pin the [quarantine] block in ``config/routing.yaml`` (AI-2 / devex-001).

The routing.yaml loader lands in Slice 4 — until then this YAML file is
the declarative source of truth for two trust-tier-sensitive contracts:

* ``[quarantine] provider`` MUST differ from the privileged provider id
  by default (spec §5.4, PRD §6.4). The bootstrap-time check in
  :mod:`alfred.bootstrap.quarantine` enforces this at startup once the
  loader is wired; until then the YAML's documented default is the
  contract.
* ``[quarantine] max_tokens_per_extraction`` is the per-extraction
  budget knob (AI-2 fix). Reading it from this file at boot is a
  Slice-4 task, but the field MUST exist now so operators can configure
  the cap before the loader catches up.

The tests parse the live ``config/routing.yaml`` and assert the shape;
catching drift here is cheap and prevents a future PR from quietly
dropping the contract.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def _load_routing_yaml() -> dict[str, Any]:
    """Parse ``config/routing.yaml`` from the repo root.

    The repo root is derived from this file's location: ``tests/unit/
    security/<file>`` → ``../../..``. Hard-coding the relative walk is
    deliberate — the test does not depend on pytest's rootdir or any
    other implicit context.
    """
    repo_root = Path(__file__).resolve().parents[3]
    raw = (repo_root / "config" / "routing.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert isinstance(parsed, dict), "routing.yaml must decode to a top-level mapping"
    return parsed


def test_routing_yaml_quarantine_provider_default_is_anthropic() -> None:
    """The shipped default pins ``anthropic`` so a fresh deploy with
    deepseek-as-privileged stays on the dual-LLM split (spec §5.4).
    """
    parsed = _load_routing_yaml()
    quarantine = parsed["quarantine"]
    assert quarantine["provider"] == "anthropic"


def test_routing_yaml_quarantine_block_carries_secret_id_not_literal_key() -> None:
    """The secret broker id is the only credential reference; no API
    key string ever lives in routing.yaml (CLAUDE.md security rule #6).
    """
    parsed = _load_routing_yaml()
    quarantine = parsed["quarantine"]
    # Closed-vocab secret-id pin. The literal is a broker lookup key,
    # not a credential — S105 false positive.
    expected_secret_id = "quarantine_provider_api_key"  # noqa: S105
    assert quarantine["secret_id"] == expected_secret_id
    # Defence in depth: no key field on the block.
    assert "api_key" not in quarantine


def test_routing_yaml_max_tokens_per_extraction_is_positive_int() -> None:
    """AI-2 fix: the per-extraction budget field is declared and is a
    positive int so the Slice-4 loader can pass it straight through.
    """
    parsed = _load_routing_yaml()
    quarantine = parsed["quarantine"]
    cap = quarantine["max_tokens_per_extraction"]
    assert isinstance(cap, int)
    assert cap > 0
