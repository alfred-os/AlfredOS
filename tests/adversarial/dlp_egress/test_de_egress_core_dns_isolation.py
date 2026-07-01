"""Executable proof for de-2026-013 — the connectivity-free core cannot resolve
an external name in the split topology (Spec C §7 external-name-must-fail probe,
§9 class 3 DNS exfil).

Two assertions, each adding a signal the compose-invariant lint does NOT:

1. The SHIPPED compose precondition that makes external resolution fail — the
   core stays on the internal-only network and is not attached to the external
   network (with a positive control so it cannot pass vacuously on an empty
   networks list). This overlaps the required test_compose_invariants.py lint by
   design (defense-in-depth, framed as the DNS-exfil adversarial class).
2. Anti-rot on the runtime proof: the docker-gated kernel proof
   tests/integration/egress/test_core_network_isolation_kernel.py must still
   EXIST and still assert the DNS hole is closed (EXTERNAL_DNS_BLOCKED). If that
   proof is deleted or gutted, this corpus entry goes red — a signal no compose
   lint provides. This is the sbx-2026-005/014 static-bytes / anti-rot pattern
   applied to the core's DNS-exfil class.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.adversarial.payload_schema import AdversarialPayload

_YAML = Path(__file__).parent / "de_egress_core_dns_isolation.yaml"
_REPO_ROOT = Path(__file__).resolve().parents[3]
_COMPOSE = _REPO_ROOT / "docker-compose.yaml"
_KERNEL_PROOF = (
    _REPO_ROOT / "tests" / "integration" / "egress" / "test_core_network_isolation_kernel.py"
)


def _load() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_YAML.read_text()))


def test_de_2026_013_schema_valid_and_defended() -> None:
    payload = _load()
    assert payload.id == "de-2026-013"
    assert payload.category == "dlp_egress"
    assert payload.out_of_scope is False
    assert payload.expected_outcome == "refused"


def test_de_2026_013_core_cannot_resolve_external_name() -> None:
    compose = yaml.safe_load(_COMPOSE.read_text())
    # Safe lookups so compose drift produces a clear assertion, not a bare KeyError.
    networks = compose.get("networks", {})
    assert "alfred_internal" in networks, "alfred_internal network missing from docker-compose.yaml"
    internal = networks["alfred_internal"] or {}
    assert internal.get("internal") is True, (
        "alfred_internal must be internal:true — the connectivity-free core has "
        "no route to an external resolver (de-2026-013 DNS-exfil defense)"
    )
    services = compose.get("services", {})
    assert "alfred-core" in services, "alfred-core service missing from docker-compose.yaml"
    # compose 'networks' may be a list (short form) or a dict (long form);
    # set(...) yields network NAMES for both.
    core_net_names = set(services["alfred-core"]["networks"])
    # Positive control: the core must STAY on the internal plane — guards against
    # an empty networks list making the absence check below pass vacuously.
    assert "alfred_internal" in core_net_names, (
        "alfred-core must stay attached to the internal-only network"
    )
    assert "alfred_external" not in core_net_names, (
        "alfred-core must not be attached to alfred_external — re-attaching it "
        "re-opens external DNS/egress from the core (de-2026-013)"
    )


def test_de_2026_013_kernel_proof_still_asserts_dns_hole_closed() -> None:
    # Anti-rot cross-reference: the runtime proof this corpus class relies on must
    # still exist and still assert the external-DNS hole is closed. If someone
    # deletes/guts test_core_network_isolation_kernel.py, this goes red — the
    # signal the compose lint cannot give.
    assert _KERNEL_PROOF.exists(), (
        "the connectivity-free-core kernel proof is missing — de-2026-013's "
        "runtime evidence has rotted away"
    )
    src = _KERNEL_PROOF.read_text(encoding="utf-8")
    # Tie the sentinel to the proof's test function AND the `assert` form, so a
    # gut-but-keep-echo refactor (the token surviving only in the shell heredoc
    # `echo EXTERNAL_DNS_BLOCKED`) still trips this gate rather than passing on a
    # stray substring.
    assert "def test_internal_network_blocks_egress_and_dns" in src, (
        "the connectivity-free-core kernel-proof test function is gone — "
        "de-2026-013's runtime evidence has rotted away"
    )
    assert 'assert "EXTERNAL_DNS_BLOCKED"' in src, (
        "the kernel proof no longer asserts the external-DNS hole is closed — "
        "de-2026-013's §9 class-3 coverage lost its runtime backing"
    )
