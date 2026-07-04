# Design — #364: sink-local containment assertion in `comms_adapter_load_grants`

- **Issue:** #364 (config-DIP loose-ends batch, PR-S4-11b/#351 PR3 security-lens R1)
- **Date:** 2026-07-04
- **Branch:** `364-sink-local-containment`
- **Scope:** defense-in-depth only; no coded invariant changes.

## Problem

`comms_adapter_load_grants`
(`src/alfred/security/capability_gate/_comms_adapter_grants.py`) turns each
`config.comms_enabled_adapters` id into a filesystem path and `read_text()`s
it:

```python
manifest_path = _REPO_ROOT / "plugins" / adapter_id / "manifest.toml"
raw = manifest_path.read_text(encoding="utf-8")
```

Path-traversal safety currently relies **entirely** on the construction-time
`_validate_comms_enabled_adapters` field validator
(`settings.py:325-362`): charset regex, `.`/`..` rejection, containment-under-
`plugins/`, `is_file`. The builder does **not** re-check containment at the
sink.

This is fine in production — the sole caller (`cli/daemon/_commands.py`)
passes a real, validated `Settings`, so a traversal id never reaches the
builder. But the parameter is typed as the `CommsAdapterGrantsConfig`
Protocol; typing it `Settings` never implied "validated" (`model_construct`
bypasses validators). A validator-bypassing construction of the real type
(`Settings.model_construct(comms_enabled_adapters=("../../etc",))`) would let
a traversal-shaped id reach `read_text()`.

The attack requires developer-authored code (outside the external-content
threat model), and the builder fails loud on any unreadable manifest with no
exfil channel — so this is **defense-in-depth**, not a live vulnerability. It
extends the same posture the module *already* applies to `subscriber_tier`
(FIX 1 re-checks the manifest tier at the sink rather than trusting the
validator — "the tool layer is the perimeter") to the path-traversal
property.

## Non-goals (explicit)

- **NOT** to be satisfied by copying `_validate_comms_enabled_adapters` into
  the builder. This is one containment property, not the 4-check validator —
  no charset, no `.`/`..` probe, no `is_file`.
- No change to the production caller or to `Settings` validation (both already
  correct).
- No *new/dedicated* ADR. The documentation surface is docstrings **plus a
  short dated amendment to the existing ADR-0027** — matching the FIX 1
  precedent, which is a dedicated "Tier ceiling (FIX 1)" paragraph in
  ADR-0027's body (not docstrings-only). The shipped operator error message
  and the `cap-2026-005` corpus both point at ADR-0027, so ADR-0027 must
  actually describe this defense or those references dangle.

## Design

### 1. The assertion (sink-local self-defense)

Insert a single containment check between path construction and the
`read_text()` sink. Compute `plugins_root` **inside** the function (once,
before the loop) so it tracks a monkeypatched `_REPO_ROOT` — mirroring how the
Settings validator computes `plugins_root` inside its body:

```python
def comms_adapter_load_grants(config: CommsAdapterGrantsConfig) -> tuple[GrantRow, ...]:
    grants: list[GrantRow] = []
    plugins_root = (_REPO_ROOT / "plugins").resolve()
    for adapter_id in config.comms_enabled_adapters:
        manifest_path = _REPO_ROOT / "plugins" / adapter_id / "manifest.toml"
        # Sink-local containment (DiD, #364): re-check that the resolved
        # manifest path stays under plugins/ rather than trusting the Settings
        # validator — the same "re-check at the sink" posture FIX 1 applies to
        # subscriber_tier. Fires only on a validator-bypassing construction
        # (model_construct / a stub Config); refuses fail-closed.
        if not manifest_path.resolve().is_relative_to(plugins_root):
            raise CommsAdapterManifestEscapeError(adapter_id)
        raw = manifest_path.read_text(encoding="utf-8")
        ...
```

`.resolve()` follows symlinks and `is_relative_to` is a pure lexical check on
the resolved path — identical semantics to `settings.py:358`. The escaping
path need not exist: the check fires before any read.

### 2. Error leaf

New dedicated leaf in `src/alfred/plugins/errors.py`, mirroring
`CommsAdapterSystemTierError` exactly:

```python
class CommsAdapterManifestEscapeError(ManifestError):
    """An enabled comms adapter's manifest path resolves OUTSIDE plugins/.

    Sink-local containment defense (DiD, #364) ... [full docstring]

    adapter_id is the operator-config adapter id and is safe in audit rows.
    """

    def __init__(self, adapter_id: str) -> None:
        super().__init__(t("plugin.comms_adapter_manifest_escape_refused", adapter_id=adapter_id))
        self.adapter_id = adapter_id
```

- Subclasses `ManifestError` → the daemon boot's
  `except (SQLAlchemyError, HookError, ManifestError, OSError)`
  (`_commands.py:457` / `_gate_boot.py`) maps it to the audited
  `boot_infra_install_failed` refusal (exit 2 + `daemon.boot.failed`
  hookpoint), not a raw traceback.
- Carries a structured `adapter_id` (charset-validated closed vocabulary in
  production, T3-free) — audit-safe per spec §5.6.
- Added to `errors.py` `__all__`.

### 3. i18n

New key `plugin.comms_adapter_manifest_escape_refused`. Add the `t()` call
site, then run the extract/update/compile flow
(`pybabel extract -F babel.cfg` → `pybabel update --no-fuzzy-matching` →
`pybabel compile`, never `--omit-header`) and fill the English `msgstr` by
hand. The message names the offending `adapter_id`, states the manifest path
resolved outside `plugins/`, and refuses boot.

### 4. Documentation

- `_comms_adapter_grants.py` module docstring: a new "Sink-local containment
  (DiD, #364)" section paragraph, sibling to the existing "Tier ceiling (FIX
  1)" and "Fail-closed" sections.
- The function's `Raises:` block gains a `CommsAdapterManifestEscapeError`
  entry.
- `errors.py` leaf docstring as above.

## Tests

### Unit (`tests/unit/security/capability_gate/test_comms_adapter_grants.py`)

Add one case covering the new `is_relative_to` **True** branch (escape →
raise). The **False** branch (contained → proceed) is already covered by every
existing passing test, so the per-file 100% line+branch gate
(`ci.yml:196` / `ci.yml:1552`) holds.

```python
def test_builder_refuses_traversal_shaped_adapter_id() -> None:
    # Settings.model_construct bypasses the field validator, so a traversal id
    # reaches the builder — the sink-local assertion is the last line of defense.
    settings = Settings.model_construct(comms_enabled_adapters=("../../../../etc",))
    with pytest.raises(CommsAdapterManifestEscapeError) as excinfo:
        comms_adapter_load_grants(settings)
    assert isinstance(excinfo.value, ManifestError)
    assert excinfo.value.adapter_id == "../../../../etc"
```

### Adversarial (`tests/adversarial/capability_bypass/`, `cap-2026-005`)

New YAML payload + Python wiring-smoke test mirroring cap-2026-004's
positive/negative-control shape, driving the **real** production builder (never
a permissive shim — CLAUDE.md hard rule #2):

- **Payload YAML** (`sink_local_containment_traversal_refused.yaml`):
  `id: cap-2026-005`, `category: capability_bypass`,
  `ingestion_path: capability_gate`, `builder: comms_adapter_load_grants`,
  `enabled_adapter_id: "../../../../etc"`, `expected_outcome: refused`, prose
  `provenance` (str, min_length 1) + a `references` list (tuple[str,...]) —
  matching `payload_schema.py` (`extra=forbid`). **No** `provenance→list`
  reshaping (release-blocking schema).
- **Test:** positive control (real repo root + real `alfred_comms_test` →
  seeds one grant, proving the assertion is not a blanket refusal) + the
  defense (`Settings.model_construct` traversal id → `CommsAdapterManifestEscapeError`,
  `isinstance ManifestError`, `adapter_id` preserved). No monkeypatch/tmp
  needed — the assertion fires before any read.

## Blast radius & verification

- Touches `src/alfred/security/capability_gate/` → **run the release-blocking
  adversarial suite** (`uv run pytest tests/adversarial`).
- Per-file 100% line+branch coverage on `_comms_adapter_grants.py`.
- `make check` before push; full `/review-pr` fleet (security always) + CR CLI
  locally before pushing; path-to-green; plain `gh pr merge --rebase`.

## Alternatives considered

- **Generic `ManifestError` raise** instead of a dedicated leaf — rejected:
  loses the audit-precise leaf + `adapter_id` attribute the codebase pattern
  (`CommsAdapterSystemTierError`) establishes.
- **ADR-0027 addendum** — ADOPTED (the docs/architect review corrected the
  initial "docstrings-only" call): FIX 1 is itself a dedicated paragraph in
  ADR-0027's body, so the faithful precedent is a parallel ADR-0027 amendment,
  not docstrings-only. The shipped error message + `cap-2026-005` corpus point
  at ADR-0027, so a "Sink-local containment (DiD #364)" amendment is required
  for those references to resolve (added as a dated amendment sibling to the
  FIX 1 paragraph).
- **Module-level `_PLUGINS_ROOT` constant** — rejected: would not track the
  monkeypatched `_REPO_ROOT` the existing tests rely on.
