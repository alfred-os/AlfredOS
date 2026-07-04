# Design — #374: fail closed on an unknown comms `adapter_kind`

- **Issue:** #374 (the one remaining #256 follow-up)
- **Date:** 2026-07-04
- **Base:** `main` @ `b9c78a71`
- **Type:** security hardening — a genuine **behaviour change** (an unknown/typo'd
  `adapter_kind` now *refuses boot* instead of silently skipping promoter enforcement)
- **Blast radius:** low real-world exposure (`adapter_kind` comes from a
  source-controlled manifest of an operator-enabled adapter, already validated
  non-empty), but the fail-closed direction is the CLAUDE.md #5/#7 bar.

## Decision flagged for the reviewer

The issue body (CodeRabbit's proposal) asks for a literal **3-site membership
check** at the `.get(adapter_kind, frozenset())` sites in `_comms_boot.py`
(`_build_sub_payload_promoter` L210, `_build_forwarded_inbound_registry` L306,
`_build_comms_adapter_wiring` L881). Exploring the code surfaced two facts that
make a **manifest-chokepoint** fix strictly better, so this design diverges from
the literal wording. **The approach question was put to the maintainer but went
unanswered (away from keyboard); this is the best-judgment, lowest-regret choice —
please confirm or redirect at the spec-review gate.**

Why the chokepoint dominates the 3 literal sites:

1. **The real threat also flows through carrier selection, which the 3 sites
   miss.** A manifest `adapter_kind` is consumed not just by the promoter/wiring
   path but by `_resolve_adapter_carrier_kind` → `_is_socket_backed_adapter_kind`
   (L327), which returns `False` for an unknown kind → the adapter is spawned on
   the **stdio-pipe carrier with a `None` promoter and no host classifiers** — T3
   sub-payloads then flow unpromoted/unclassified. That is the actual hole, and a
   fix at the three promoter sites does not close it. The single manifest
   chokepoint `_resolve_comms_adapter_wire_spec` (L146) feeds **both** carrier
   selection and wiring, so validating there closes every downstream path at once.

2. **The literal 3-site check fights the per-file 100% line+branch gate.** The
   factory (L210) is called *before* the L306/L881 misconfiguration guards, so if
   the factory raises on an unknown kind, the guards' unknown-branch becomes dead
   code — uncoverable, and `# pragma: no cover` on a fail-closed arm is forbidden
   (the #256 anti-pragma rule).

## Approach

Two changes, one behavioural + one defence-in-depth:

### 1. Primary (closes the reachable hole): validate at the manifest chokepoint

In `_resolve_comms_adapter_wire_spec` (`src/alfred/cli/daemon/_comms_boot.py`,
after the existing non-empty-string check on `adapter_kind` at L170-171), add a
registry-membership check:

```python
from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND
...
if not isinstance(adapter_kind, str) or not adapter_kind:
    raise _CommsAdapterManifestError(adapter_id, "adapter_kind")
if adapter_kind not in REQUIRED_CLASSIFIERS_BY_KIND:
    raise _UnknownAdapterKindError(adapter_id, adapter_kind)
```

The import is function-local, matching the module's established lazy-import
convention (L206/L296/L879 already import this symbol function-locally).

`_UnknownAdapterKindError` is a **subtype** of the existing
`_CommsAdapterManifestError`:

```python
class _UnknownAdapterKindError(_CommsAdapterManifestError):
    """An enabled comms adapter declares an adapter_kind absent from the host registry.

    The manifest's adapter_kind is a non-empty string but not a member of the
    host's closed vocabulary (REQUIRED_CLASSIFIERS_BY_KIND) — a typo'd or
    unregistered kind. Refusing boot here (fail-closed, CLAUDE.md #5/#7) stops the
    adapter being spawned with a None promoter + no host classifiers, which would
    let raw T3 sub-payloads reach the orchestrator unpromoted.
    """

    def __init__(self, adapter_id: str, adapter_kind: str) -> None:
        super().__init__(adapter_id, "adapter_kind")
        self.adapter_kind = adapter_kind
        # Override the parent's "missing field" message — the field is PRESENT but
        # unregistered.
        self.args = (
            f"comms adapter {adapter_id!r} manifest declares unknown adapter_kind "
            f"{adapter_kind!r} (not in REQUIRED_CLASSIFIERS_BY_KIND)",
        )
```

**Why a subtype, not a new independent error or a reused base:**

- Subclassing means the existing catch arms — `except (OSError, ManifestError,
  _CommsAdapterManifestError)` at L354 (`_resolve_adapter_carrier_kind`) and L846
  (`_build_comms_adapter_wiring`) — catch it **with zero wiring change**, routing
  it to the existing audited `_refuse_boot(... comms_adapter_spawn_failed ...)`
  (exit 2). **No new `t()` key, no new failure class, no new audit reason.**
- It is semantically honest: the base class means "manifest is *missing* a
  required field"; an unregistered-but-present kind is a distinct failure the
  subtype names accurately (its own message + `.adapter_kind` attribute), while
  still carrying `.adapter_id` and `.field == "adapter_kind"` for continuity with
  the existing debugging conventions.

The operator-facing outcome is identical to any other malformed-manifest refusal:
audited `comms_adapter_spawn_failed`, exit 2, the existing
`daemon.boot.comms_adapter_spawn_failed` t() message. Only the internal exception
message/type is new.

### 2. Defence-in-depth: replace the `.get(…, frozenset())` typo-masking at all 3 sites

Convert the three `REQUIRED_CLASSIFIERS_BY_KIND.get(adapter_kind, frozenset())`
reads to plain subscripts `REQUIRED_CLASSIFIERS_BY_KIND[adapter_kind]`:

- L210 `_build_sub_payload_promoter`: `if not REQUIRED_CLASSIFIERS_BY_KIND[adapter_kind]: return None`
- L306 `_build_forwarded_inbound_registry`: `if promoter is None and REQUIRED_CLASSIFIERS_BY_KIND[kind]:`
- L881 `_build_comms_adapter_wiring`: `if sub_payload_promoter is None and REQUIRED_CLASSIFIERS_BY_KIND[wire.adapter_kind]:`

After the chokepoint, every one of these provably sees a **registered** kind
(L306 iterates the hardcoded `_FORWARDED_INBOUND_KINDS = ("discord",)`; L210/L881
receive a chokepoint-validated `wire.adapter_kind`). The subscript **fails loud
(KeyError)** if a future caller ever bypasses the chokepoint, instead of silently
equating an unknown kind with an intentional empty-classifier kind. This removes
the exact `.get(…, frozenset())` smell CodeRabbit flagged, at all three named
sites, **without** introducing a second refusal mechanism or any dead branch.

This satisfies the issue's "apply the check at all 3 sites" intent while keeping
the *audited* refusal in one place (the chokepoint).

## Why this is coverage-clean (no new pragma)

`_comms_boot.py` carries a per-file 100% line+branch gate in **both** CI jobs.

- **Chokepoint `if adapter_kind not in …:`** — True arc (unknown → raise) covered
  by a new direct unit test; False arc (registered → continue) covered by the
  existing full-boot suite, which runs the **real** `_resolve_comms_adapter_wire_spec`
  against the real `alfred_comms_test` manifest (`_patch_comms_seams` stubs only
  `CommsStdioTransport` + `CommsPluginRunner`, not the resolver).
- **`_UnknownAdapterKindError.__init__`** — covered by the new direct unit test.
- **The three `.get → []` conversions** — a subscript is not a branch; the
  enclosing `if`/`and` arcs are already covered (tui → empty → None; discord →
  non-empty → build/guard). No new branch arc introduced. (The KeyError exit is an
  exception propagation, not a statically-recognized branch of the `if`, so it does
  not create an uncovered arc — distinct from the #256 PR-4 `# pragma: no branch`
  case, which was a *normal* arc only reachable during exception unwinding.)

No `# pragma` is added on any arm.

## Test plan (TDD — write failing first)

New/confirmed tests in `tests/unit/cli/daemon/`:

1. **Refusal (new behaviour)** — `test_resolve_wire_spec_raises_on_unregistered_adapter_kind`
   in `test_comms_boot_refusal_arms.py`. Mirrors the existing
   `test_resolve_wire_spec_raises_when_adapter_kind_key_absent`: seed a manifest
   whose `[comms_mcp].adapter_kind = "bogus_typo"`, run the real resolver, assert
   `pytest.raises(_UnknownAdapterKindError)`, `.adapter_kind == "bogus_typo"`, and
   that it `isinstance`s `_CommsAdapterManifestError` (so the existing catch arms
   cover it).
2. **Refusal routes to the audited refusal end-to-end** —
   `test_build_wiring_refuses_on_unregistered_adapter_kind`: fault-inject the
   resolver to raise `_UnknownAdapterKindError`, assert `_build_comms_adapter_wiring`
   refuses with `_BootRefusedError` code 2 and audit reason
   `comms_adapter_spawn_failed` (proves the subtype is caught by the existing arm).
3. **Factory fails loud (defence-in-depth tripwire)** —
   `test_factory_fails_loud_on_unregistered_kind` in `test_daemon_promoter_wiring.py`:
   `_build_sub_payload_promoter(adapter_kind="bogus_unregistered", content_store=…)`
   raises `KeyError`. Documents the subscript contract.
4. **Happy paths (already covered — re-assert, do not regress):** discord builds a
   promoter; reference (`alfred_comms_test`) and `tui` empty-set kinds return
   `None`; full boot of the enabled reference adapter exits 0
   (`test_factory_builds_promoter_for_classifier_bearing_kind`,
   `test_factory_returns_none_for_empty_set_kind`,
   `test_enabled_empty_set_adapter_wires_none_promoter`).

## Safety checks before shipping (behaviour change)

- **No in-tree manifest declares an unregistered kind.** Verified: the four comms
  manifests declare only `alfred_comms_test` / `tui` / `discord`, all present in
  `REQUIRED_CLASSIFIERS_BY_KIND` (empty-set kinds carry a
  `MARKER_NO_CLASSIFIERS_NEEDED` justification). So no in-tree adapter's boot breaks.
- **No test fixture seeds a *present-but-unregistered* `adapter_kind` expecting
  success.** To confirm during implementation (grep test manifests / seeded TOML);
  the existing refusal-arm fixtures use *absent* `adapter_kind`, which trips the
  earlier non-empty check, not the new membership check.

## i18n

No new `t()` key (reuses `daemon.boot.comms_adapter_spawn_failed`). But the added
lines in `_comms_boot.py` shift the `#:` location refs of `t()` sites below them,
so **the pybabel flow must be re-run** (`extract` → `update` → `compile`) and the
updated `locale/en/LC_MESSAGES/alfred.po` committed, or the CI
`pybabel update --check` (which does not pass `--no-location`) goes red. Re-run
this **after the last code edit** (the #256 PR-1 lesson).

## CI / gates

- `_comms_boot.py` is already per-file 100%-gated in both jobs — no new gate step.
- `make check` before every push. Full `/review-pr` fleet (security always) + CR
  CLI locally before pushing (save CR-cloud credits). Path-to-green. Plain
  `gh pr merge --rebase` — never `--admin`.

## Out of scope

- No decomposition or restructuring of `_comms_boot.py`.
- No change to `classifier_registry.py` or the registry contents.
- The `ContentStore`-leak / cleanup-masking items originally bundled under #374
  were already fixed in #256 PR-3 (56b32e4c); #374 is now scoped to the
  unknown-`adapter_kind` hardening only.
