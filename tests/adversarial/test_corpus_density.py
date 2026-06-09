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


def _count_yaml_payloads(category_dir: Path) -> int:
    """Return the number of ``*.yaml`` payload files under ``category_dir``.

    Stricter than :func:`_count_payload_artifacts` — used by the Slice-4
    xfail-strict density guards so a follow-on PR cannot flip the marker
    by shipping a stub ``test_*.py`` without a real YAML payload (CR
    finding #207-csb-001).
    """
    if not category_dir.is_dir():
        return 0
    return sum(1 for p in category_dir.glob("*.yaml") if p.is_file())


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

    PR-S3-5 (`web.fetch` plugin) ships the first three payloads here —
    ``de-2026-001`` (canary token in HTML), ``de-2026-002`` (the
    documented cross-field secret-leak gap deferred to Slice 4), and
    ``de-2026-003`` (DNS rebinding SSRF to cloud metadata / RFC1918).
    The earlier `xfail(strict=True)` placeholder enforced the "dir
    populated by Slice 3" contract; with payloads landed the marker
    is gone and the count assertion stands on its own.
    """
    category_dir = Path(__file__).parent / "dlp_egress"
    count = _count_payload_artifacts(category_dir)
    assert count > 0, (
        f"dlp_egress corpus has 0 payloads — expected ≥1 after the "
        f"owning PR (S3-5) merges. Searched: {category_dir}"
    )


# ---------------------------------------------------------------------------
# Slice-4 density guards — each marked xfail(strict=True) until owning PR
# ships payloads. The strict marker FLIPS to pass when payloads arrive,
# which then fails the test (strict=True), forcing the implementer to
# remove the xfail decoration as part of the same PR. This closes the
# "follow-on PR ships green with empty corpus tree" loophole.
# ---------------------------------------------------------------------------


def test_sandbox_escape_corpus_has_payloads() -> None:
    """`tests/adversarial/sandbox_escape/` carries ≥10 PR-S4-6/7 payloads.

    PR-S4-6 ships sbx-2026-001 (manifest omits [sandbox]), -002 (kind:stub in
    production), -007 (policy_ref traversal → policy_ref_escapes_root), -008
    (fd-3 partial-write refusal), -009 (sandbox_info handshake mismatch), and
    -010 (FAKE_UNAME production bypass). PR-S4-7 adds the kernel-observable
    bwrap-escape payloads against the REAL quarantined-LLM Linux policy:
    -003 (host /etc/passwd read contained), -004 (/bin/sh exec contained),
    -005 (outbound egress UNRESTRICTED — out_of_scope, #230), -006 (host
    /proc/1/environ read contained), and -011 (policy_ref symlink-follow
    refused). The xfail-strict placeholder self-destructed when the payloads
    arrived, by design; the floor of 10 catches a silent deletion regression.
    """
    category_dir = Path(__file__).parent / "sandbox_escape"
    count = _count_yaml_payloads(category_dir)
    assert count >= 10, (
        f"expected ≥10 *.yaml payloads under {category_dir} "
        f"(sbx-2026-001..011, modulo gaps), found {count} — a payload was "
        "deleted or renamed"
    )


def test_config_reload_bypass_corpus_has_payloads() -> None:
    """`tests/adversarial/config_reload_bypass/` carries ≥6 PR-S4-4 payloads.

    PR-S4-4 (ADR-0023) ships csb-2026-001..005: TOCTOU inode-swap refusal,
    high-blast-change refusal, audit-write-failure abort, cached-mtime
    rejection re-emit, and the >256 KB oversize-file refusal. PR-S4-4 round-3
    adds csb-2026-007: rate-limit / burst-limiter anti-abuse-knob refusal
    (ADR-0023 §5 / Finding 1). The earlier ``xfail(strict=True)`` placeholder
    self-destructed on the first arriving payload, by design; the floor of 6
    catches a silent deletion regression.
    """
    category_dir = Path(__file__).parent / "config_reload_bypass"
    count = _count_yaml_payloads(category_dir)
    assert count >= 6, (
        f"expected ≥6 *.yaml payloads under {category_dir} (csb-2026-001..005, 007), "
        f"found {count} — a payload was deleted or renamed"
    )


def test_carrier_substitution_tamper_corpus_has_payloads() -> None:
    """`tests/adversarial/carrier_substitution_tamper/` carries ≥4 PR-S4-3 payloads.

    PR-S4-3 (ADR-0022) ships crf-2026-001..004: tier-upgrade refusal,
    malformed substitute, wrong-type substitute, meta-hookpoint
    recursion. The xfail-strict guard was removed when the payloads
    landed; the floor of 4 catches a silent deletion regression.
    """
    category_dir = Path(__file__).parent / "carrier_substitution_tamper"
    count = _count_yaml_payloads(category_dir)
    assert count >= 4, (
        f"expected ≥4 *.yaml payloads under {category_dir} (crf-2026-001..004), "
        f"found {count} — a payload was deleted or renamed"
    )


def test_operator_session_forgery_corpus_has_payloads() -> None:
    """`tests/adversarial/operator_session_forgery/` carries ≥7 PR-S4-5 payloads.

    PR-S4-5 (#153) ships osf-2026-001..007: forged session file (token_unknown),
    replay from another host (host_mismatch), replay from another machine
    (machine_mismatch), stat-then-open TOCTOU race (closed by open-then-fstat),
    symlink to attacker file (O_NOFOLLOW boundary refusal), token/user mismatch
    (token-authoritative, round-2 closure 11), and planted-user-id log injection
    (round-2 closure 4). The xfail-strict guard was removed when the payloads
    landed; the floor of 7 catches a silent deletion regression.
    """
    category_dir = Path(__file__).parent / "operator_session_forgery"
    count = _count_yaml_payloads(category_dir)
    assert count >= 7, (
        f"expected ≥7 *.yaml payloads under {category_dir} (osf-2026-001..007), "
        f"found {count} — a payload was deleted or renamed"
    )


def test_comms_identity_boundary_corpus_has_payloads() -> None:
    """`tests/adversarial/comms_identity_boundary/` carries ≥5 PR-S4-8 payloads.

    PR-S4-8 (#152) ships cib-2026-001..005: forged canonical_user_id in
    platform_metadata (ignored, resolver-state authoritative), inter-persona
    T2-as-T3 relay (inert claim, always T3), canonical-id outbound leakage
    (never echoed), empty-classifier-set bypass (AST guard refuses), and
    handler-exception-silenced (positive/negative control). The xfail-strict
    placeholder self-destructed when the payloads arrived, by design; the floor
    of 5 catches a silent deletion regression. PR-S4-9 extends the category with
    the Discord-specific entries.
    """
    category_dir = Path(__file__).parent / "comms_identity_boundary"
    count = _count_yaml_payloads(category_dir)
    assert count >= 5, (
        f"expected ≥5 *.yaml payloads under {category_dir} (cib-2026-001..005), "
        f"found {count} — a payload was deleted or renamed"
    )
