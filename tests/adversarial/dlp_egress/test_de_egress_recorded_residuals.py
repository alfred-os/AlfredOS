"""Recorded-residual acknowledgements for the two Spec C §9 egress residuals that
survive the destination-allowlist / TLS-passthrough design by construction:

* de-2026-014 — mode-(a) provider-prompt exfil (TLS-passthrough is destination-
  gated only; the proxy never inspects the wrapped request body).
* de-2026-016 — Discord SNI-spoof-to-cotenant / CDN-cotenant (TLS-passthrough is
  SNI-blind; a co-tenant behind the same CDN fronting is indistinguishable).

Neither is a defended vector — each is an ACCEPTED design residual to be ratified
in ADR-0040's honest-scope section. These tests assert the honest encoding is
present (out_of_scope=true + a non-empty rationale) so the absence of a catch is a
documented invariant, not a silent gap — the tl-2026-003 acknowledgement pattern.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_DIR = Path(__file__).parent


@pytest.mark.parametrize(
    "filename",
    [
        "de_egress_mode_a_provider_prompt_residual.yaml",
        "de_egress_sni_spoof_cotenant_residual.yaml",
    ],
)
def test_recorded_residual_carries_out_of_scope_acknowledgement(filename: str) -> None:
    path = _DIR / filename
    assert path.exists(), f"missing recorded-residual payload {filename}"
    payload = yaml.safe_load(path.read_text())
    assert payload.get("out_of_scope") is True, (
        f"{filename} records an accepted design residual — it must be marked "
        "out_of_scope=true, not claimed caught"
    )
    rationale = (payload.get("out_of_scope_rationale") or "").strip()
    assert rationale, f"{filename} must carry a non-empty out_of_scope_rationale (the WHY)"
