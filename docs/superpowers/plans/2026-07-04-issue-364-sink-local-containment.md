# Sink-Local Containment Assertion (#364) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sink-local containment assertion to `comms_adapter_load_grants` so a validator-bypassing traversal-shaped adapter id is refused before `read_text()`, extending the module's existing "re-check at the sink" posture to the path-traversal property.

**Architecture:** One containment check (`manifest_path.resolve().is_relative_to(plugins_root)`) inside the builder, computed against the current `_REPO_ROOT` so it tracks monkeypatching. A new dedicated `CommsAdapterManifestEscapeError(ManifestError)` leaf maps the refusal to the audited `boot_infra_install_failed` daemon-boot refusal. Proven by a new unit branch (via `model_construct`) and a new `cap-2026-005` adversarial corpus entry against the real builder.

**Tech Stack:** Python 3.12+, Pydantic v2 / pydantic-settings, pytest, Babel (`t()` i18n), pytest-cov.

## Global Constraints

- **Do NOT copy `_validate_comms_enabled_adapters` into the builder.** This is the single containment property only — no charset, no `.`/`..` probe, no `is_file` (issue #364 explicit non-goal).
- **No silent failures in security paths** (CLAUDE.md hard rule #7): the assertion raises loudly.
- **Adversarial drivers use the REAL production builder**, never a permissive shim (CLAUDE.md hard rule #2).
- **i18n:** every operator-facing string through `t()`. Extract/update/compile flow, never `--omit-header`; fill the English `msgstr` by hand.
- **Adversarial payload schema** (`tests/adversarial/payload_schema.py`, `extra=forbid`): `provenance` is `str` (min_length 1) prose; `references` is a list. Do NOT reshape `provenance` to a list.
- **Per-file 100% line+branch coverage** on `src/alfred/security/capability_gate/_comms_adapter_grants.py` (`ci.yml:196`, `ci.yml:1552`).
- **Run the release-blocking adversarial suite** — this touches `src/alfred/security/`.
- **Commit subjects** must contain a literal `#364` (Conventional-commit required check). Commit trailer: `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`.

---

### Task 1: Sink-local assertion + error leaf + i18n + docstrings

**Files:**

- Modify: `src/alfred/plugins/errors.py` (add leaf near `CommsAdapterSystemTierError` ~line 197; add to `__all__` ~line 268)
- Modify: `src/alfred/security/capability_gate/_comms_adapter_grants.py` (import the leaf; add the assertion in the loop ~line 130-134; module docstring; function `Raises:` block)
- Modify: `locale/en/LC_MESSAGES/alfred.po` + `alfred.mo` (via pybabel)
- Test: `tests/unit/security/capability_gate/test_comms_adapter_grants.py` (add one branch test + import)

**Interfaces:**

- Produces: `alfred.plugins.errors.CommsAdapterManifestEscapeError(adapter_id: str)` — subclass of `ManifestError`, attribute `adapter_id: str`, message via `t("plugin.comms_adapter_manifest_escape_refused", adapter_id=...)`.
- Consumes: existing `alfred.plugins.errors.ManifestError`, `alfred.i18n.t`, module global `_REPO_ROOT`.

- [ ] **Step 1: Write the failing unit test**

Add to `tests/unit/security/capability_gate/test_comms_adapter_grants.py`. First extend the existing import line:

```python
from alfred.plugins.errors import (
    CommsAdapterManifestEscapeError,
    CommsAdapterSystemTierError,
    ManifestError,
)
```

Then append this test:

```python
def test_builder_refuses_traversal_shaped_adapter_id() -> None:
    """A traversal-shaped id (validator-bypassed) is REFUSED at the sink.

    Path-traversal safety otherwise rests entirely on the construction-time
    ``comms_enabled_adapters`` validator. ``Settings.model_construct`` bypasses
    that validator, so a traversal-shaped id reaches the builder — the
    sink-local containment assertion (DiD, #364) is the last line of defense.
    It re-checks that the resolved manifest path stays under ``plugins/``,
    the same "re-check at the sink" posture FIX 1 applies to ``subscriber_tier``.
    The refusal leaf subclasses ``ManifestError`` so the daemon boot maps it to
    the audited ``boot_infra_install_failed`` refusal.
    """
    # model_construct bypasses _validate_comms_enabled_adapters — a real
    # production Settings type carrying an id the validator would have rejected.
    settings = Settings.model_construct(comms_enabled_adapters=("../../../../etc",))

    with pytest.raises(CommsAdapterManifestEscapeError) as excinfo:
        comms_adapter_load_grants(settings)

    assert isinstance(excinfo.value, ManifestError)
    assert excinfo.value.adapter_id == "../../../../etc"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/security/capability_gate/test_comms_adapter_grants.py::test_builder_refuses_traversal_shaped_adapter_id -v`
Expected: FAIL — `ImportError: cannot import name 'CommsAdapterManifestEscapeError'`.

- [ ] **Step 3: Add the error leaf to `src/alfred/plugins/errors.py`**

Insert directly after `CommsAdapterSystemTierError` (after its `__init__`, ~line 197):

```python
class CommsAdapterManifestEscapeError(ManifestError):
    """An enabled comms adapter's manifest path resolves OUTSIDE ``plugins/``.

    Sink-local containment defense (DiD, #364): the config-sourced
    comms-adapter LOAD-grant builder
    (:func:`alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants`)
    turns each ``comms_enabled_adapters`` id into a
    ``plugins/<id>/manifest.toml`` path and reads it. Path-traversal safety
    otherwise rests entirely on the construction-time
    ``_validate_comms_enabled_adapters`` validator; a validator-bypassing
    construction of the real ``Settings`` type (``model_construct`` / a stub
    Config) could route a traversal-shaped id to the read sink. The builder
    RE-CHECKS containment at the sink rather than trusting the validator — the
    same "the tool layer is the perimeter" posture FIX 1 applies to
    ``subscriber_tier`` — and REFUSES fail-closed with this dedicated leaf
    (CLAUDE.md hard rule #7). Subclasses :class:`ManifestError` so the daemon's
    boot ``except`` maps it to the audited ``boot_infra_install_failed``
    refusal rather than a raw traceback.

    ``adapter_id`` is the operator-config adapter id (charset-validated by the
    ``comms_enabled_adapters`` Settings field in production) and is safe in
    audit rows (spec §5.6).
    """

    def __init__(self, adapter_id: str) -> None:
        super().__init__(t("plugin.comms_adapter_manifest_escape_refused", adapter_id=adapter_id))
        self.adapter_id = adapter_id
```

Then add the new leaf to `__all__` (alphabetical, before `DlpOutboundRefusedError`). NOTE: the sibling `CommsAdapterSystemTierError` was never in `__all__` on `origin/main` (a pre-existing omission — imported by name in the builder + tests but not exported for `import *`). Since we are editing this file and adding its structural sibling, promote BOTH comms-adapter leaves so the two are treated consistently:

```python
__all__ = [
    "CommsAdapterManifestEscapeError",
    "CommsAdapterSystemTierError",
    "DlpOutboundRefusedError",
    "ManifestError",
    ...
]
```

- [ ] **Step 4: Add the assertion to the builder**

In `src/alfred/security/capability_gate/_comms_adapter_grants.py`, extend the import:

```python
from alfred.plugins.errors import CommsAdapterManifestEscapeError, CommsAdapterSystemTierError
```

Then in `comms_adapter_load_grants`, compute `plugins_root` once before the loop and add the check before `read_text`:

```python
    grants: list[GrantRow] = []
    # Sink-local containment root (DiD, #364). Computed inside the function
    # (not a module constant) so it tracks a monkeypatched ``_REPO_ROOT`` and
    # mirrors how the Settings validator computes ``plugins_root`` in its body.
    plugins_root = (_REPO_ROOT / "plugins").resolve()
    for adapter_id in config.comms_enabled_adapters:
        manifest_path = _REPO_ROOT / "plugins" / adapter_id / "manifest.toml"
        # Sink-local containment (DiD, #364): re-check the resolved manifest
        # path stays under ``plugins/`` rather than trusting the construction
        # validator — the same "re-check at the sink, the tool layer is the
        # perimeter" posture FIX 1 applies to ``subscriber_tier``. Fires only on
        # a validator-bypassing construction (model_construct / a stub Config);
        # refuses fail-closed before the read. NOT the 4-check validator: one
        # containment property, no charset / no is_file (issue #364).
        if not manifest_path.resolve().is_relative_to(plugins_root):
            raise CommsAdapterManifestEscapeError(adapter_id)
        # Loud on a missing/unreadable file — the Settings validator proved
        # the file existed at construction, but the builder must never seed
        # nothing-and-continue if it cannot read it.
        raw = manifest_path.read_text(encoding="utf-8")
```

- [ ] **Step 5: Add the docstrings**

In `_comms_adapter_grants.py` module docstring, add a new section after the "Tier ceiling (FIX 1)" section and before "Fail-closed":

```text
Sink-local containment (DiD, #364)
----------------------------------
Path-traversal safety of the ``comms_enabled_adapters`` -> manifest path
rests on the construction-time ``_validate_comms_enabled_adapters`` validator.
A validator-bypassing construction of the real ``Settings`` type
(``model_construct`` / a stub ``CommsAdapterGrantsConfig``) could route a
traversal-shaped id to the read sink. The builder RE-CHECKS that the resolved
manifest path stays under ``plugins/`` before reading — the same "re-check at
the sink, the tool layer is the perimeter" posture the tier ceiling applies to
``subscriber_tier`` — and REFUSES fail-closed
(:class:`alfred.plugins.errors.CommsAdapterManifestEscapeError`, a
:class:`ManifestError` subclass mapped to the audited
``boot_infra_install_failed`` refusal). This is the single containment
property, NOT the 4-check validator copied into the builder.
```

Add to the function's `Raises:` block (after the `CommsAdapterSystemTierError` entry):

```text
        alfred.plugins.errors.CommsAdapterManifestEscapeError: An enabled
            adapter's manifest path resolves OUTSIDE ``plugins/`` (a
            validator-bypassing traversal-shaped id, DiD #364). Refused
            fail-closed before the read. The leaf subclasses
            :class:`ManifestError`, so the daemon's boot ``except`` maps it to
            the audited ``boot_infra_install_failed`` refusal.
```

- [ ] **Step 6: Run the unit test to verify it passes**

Run: `uv run pytest tests/unit/security/capability_gate/test_comms_adapter_grants.py -v`
Expected: PASS (all cases, including the new one). `t()` returns the key string until the catalog entry ships, so the error constructs fine.

- [ ] **Step 7: Add the i18n catalog entry**

Extract + update the catalog:

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching
```

Then in `locale/en/LC_MESSAGES/alfred.po`, find the new empty entry:

```
#: src/alfred/plugins/errors.py:NNN
msgid "plugin.comms_adapter_manifest_escape_refused"
msgstr ""
```

Fill the `msgstr` by hand:

```
msgstr ""
"Comms adapter '{adapter_id}' manifest path resolves outside the plugins/ "
"directory. A comms adapter id must name an in-repo plugins/<id>/manifest.toml; "
"a path-traversal-shaped id is refused. Refusing to boot. Fix or unset the id "
"in ALFRED_COMMS_ENABLED_ADAPTERS (see ADR-0027, issue #364)."
```

Compile:

```bash
uv run pybabel compile -d locale -D alfred --statistics
```

- [ ] **Step 8: Verify i18n drift-clean + coverage**

Run (mirrors the CI drift gate — must exit 0):

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update --check -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching --ignore-pot-creation-date
```

Expected: exit 0 (no drift).

Run per-file coverage (mirrors `ci.yml:196`):

```bash
uv run pytest tests/unit/security/capability_gate/test_comms_adapter_grants.py \
  --cov=alfred.security.capability_gate._comms_adapter_grants --cov-branch -q
uv run coverage report --include='src/alfred/security/capability_gate/_comms_adapter_grants.py' --fail-under=100
```

Expected: `100%` for `_comms_adapter_grants.py`, exit 0.

- [ ] **Step 9: Commit**

```bash
git add src/alfred/plugins/errors.py \
  src/alfred/security/capability_gate/_comms_adapter_grants.py \
  tests/unit/security/capability_gate/test_comms_adapter_grants.py \
  locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo
git commit -m "fix(security): sink-local containment assertion in comms_adapter_load_grants (#364)

Re-check each enabled comms adapter's manifest path resolves under plugins/
before reading it, rather than trusting the construction-time Settings
validator (which model_construct bypasses). Extends the module's existing
're-check at the sink' posture (FIX 1 re-checks subscriber_tier) to the
path-traversal property. New CommsAdapterManifestEscapeError(ManifestError)
maps to the audited boot_infra_install_failed refusal. DiD only; not the
4-check validator copied into the builder.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task 2: `cap-2026-005` adversarial corpus entry

**Files:**

- Create: `tests/adversarial/capability_bypass/sink_local_containment_traversal_refused.yaml`
- Create: `tests/adversarial/capability_bypass/test_cap_2026_005_sink_local_containment_traversal_refused.py`

**Interfaces:**

- Consumes: `alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants`, `alfred.config.settings.Settings`, `alfred.plugins.errors.CommsAdapterManifestEscapeError` / `ManifestError`, `tests.adversarial.payload_schema.AdversarialPayload`, the session-scoped `corpus_payloads` fixture.

- [ ] **Step 1: Write the payload YAML**

Create `tests/adversarial/capability_bypass/sink_local_containment_traversal_refused.yaml`:

```yaml
id: cap-2026-005
category: capability_bypass
threat: "A traversal-shaped comms-adapter id bypasses the construction-time comms_enabled_adapters validator (via model_construct / a stub Config) and reaches the config-sourced load-grant builder's manifest read sink, escaping the plugins/ directory to read an arbitrary manifest.toml off the host."
ingestion_path: capability_gate
payload:
  builder: comms_adapter_load_grants
  enabled_adapter_id: "../../../../etc"
  attempted_action: read_manifest_outside_plugins
expected_outcome: refused
provenance: "Path-traversal safety of the comms_enabled_adapters -> plugins/<id>/manifest.toml read rests on the construction-time _validate_comms_enabled_adapters validator (charset, ./.. rejection, containment, is_file). The comms_adapter_load_grants param is typed as the CommsAdapterGrantsConfig Protocol; typing it Settings never implied 'validated' — model_construct bypasses validators. A validator-bypassing construction of the real Settings type carrying a traversal-shaped id (e.g. '../../../../etc') would route it to read_text(). Defense-in-depth (#364, PR-S4-11b/#351 PR3 security-lens R1): the builder RE-CHECKS that the resolved manifest path stays under plugins/ at the sink rather than trusting the validator — the same 'the tool layer is the perimeter' posture FIX 1 (cap-2026-004) applies to subscriber_tier — and REFUSES fail-closed with CommsAdapterManifestEscapeError, a ManifestError subclass the daemon boot maps to the audited boot_infra_install_failed refusal. Not the 4-check validator copied into the builder: one containment property. The attack requires developer-authored code (outside the external-content threat model); this entry pins the sink-local defense fired."
references:
  - "ADR-0027"
  - "issue #364"
  - "issue #351"
  - "CLAUDE.md hard rule #7"
  - "cap-2026-004"
```

- [ ] **Step 2: Write the adversarial wiring-smoke test**

Create `tests/adversarial/capability_bypass/test_cap_2026_005_sink_local_containment_traversal_refused.py`:

```python
"""Adversarial wiring-smoke for the ``cap-2026-005`` corpus payload.

Asserts the sink-local containment defense (#364) fired at the config-sourced
comms-adapter load-grant builder: a validator-bypassing traversal-shaped
adapter id (constructed via ``Settings.model_construct``, which bypasses
``_validate_comms_enabled_adapters``) is REFUSED at the builder BEFORE the
manifest read sink, proving no arbitrary-file read outside ``plugins/`` rides
the config-sourced seed.

Path-traversal safety of the ``comms_enabled_adapters`` -> manifest read
otherwise rests entirely on the construction-time validator. The builder is the
perimeter (CLAUDE.md: the tool layer, not the model, is the perimeter): it
RE-CHECKS containment at the sink and REFUSES a traversal-shaped id fail-closed
(:class:`CommsAdapterManifestEscapeError`, a :class:`ManifestError` subclass the
daemon boot maps to the audited ``boot_infra_install_failed`` refusal). A pass
here would let a validator-bypassed id read an arbitrary manifest off the host.

The test drives the REAL production
:func:`alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants`
builder — NEVER a permissive shim (CLAUDE.md hard rule #2). Mirrors the
positive/negative-control shape of ``cap-2026-004``.
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.config.settings import Settings
from alfred.plugins.errors import CommsAdapterManifestEscapeError, ManifestError
from alfred.security.capability_gate._comms_adapter_grants import comms_adapter_load_grants
from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_ID: Final[str] = "cap-2026-005"

# A real in-repo adapter id (positive control) and the traversal-shaped id the
# payload pins (the defense).
_REAL_ADAPTER: Final[str] = "alfred_comms_test"
_TRAVERSAL_ID: Final[str] = "../../../../etc"


@pytest.fixture
def sink_containment_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus to the wiring-smoke payload.

    Fails loudly if the payload is missing/duplicated so a future rename or
    delete surfaces here (the drift-guard pattern shared across the corpus).
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; expected at "
            "tests/adversarial/capability_bypass/sink_local_containment_traversal_refused.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def test_sink_local_containment_traversal_refused(
    sink_containment_payload: AdversarialPayload,
) -> None:
    """A traversal-shaped comms adapter id is REFUSED at the builder's read sink.

    Positive control + negative control through the SAME production builder:

    * a REAL in-repo adapter (``alfred_comms_test``) against the real repo root
      seeds exactly one wildcard load grant — the builder really reads a
      contained manifest, so the refusal below is a containment verdict, not a
      blanket refusal; and
    * a traversal-shaped id constructed via ``model_construct`` (bypassing the
      Settings validator) is REFUSED before the read — proving no arbitrary-file
      read outside ``plugins/`` rides the config-sourced seed.
    """
    payload_fields = sink_containment_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["builder"] == "comms_adapter_load_grants"
    assert payload_fields["enabled_adapter_id"] == _TRAVERSAL_ID
    assert sink_containment_payload.expected_outcome == "refused"

    # Positive control: a real in-repo adapter seeds one wildcard grant — the
    # builder reads a contained manifest, so the refusal below is a containment
    # verdict, not a blanket refusal.
    ok_settings = Settings(
        environment="test",
        deepseek_api_key="not-a-real-secret-adversarial-test-placeholder",
        comms_enabled_adapters=(_REAL_ADAPTER,),
    )
    (grant,) = comms_adapter_load_grants(ok_settings)
    assert grant.hookpoint == "*"

    # The defense: a traversal-shaped id (validator-bypassed via model_construct)
    # is REFUSED before the read. The assertion fires before any file access, so
    # the escaping path need not exist.
    evil_settings = Settings.model_construct(comms_enabled_adapters=(_TRAVERSAL_ID,))
    with pytest.raises(CommsAdapterManifestEscapeError) as excinfo:
        comms_adapter_load_grants(evil_settings)

    # The refusal leaf is caught by the daemon boot's manifest-family ``except``,
    # so it maps to the audited ``boot_infra_install_failed`` refusal rather than
    # a raw traceback.
    assert isinstance(excinfo.value, ManifestError), (
        "CommsAdapterManifestEscapeError must subclass ManifestError so the daemon "
        "boot maps the traversal refusal to the audited boot_infra_install_failed"
    )
    assert excinfo.value.adapter_id == _TRAVERSAL_ID
```

- [ ] **Step 3: Run the new adversarial test**

Run: `uv run pytest tests/adversarial/capability_bypass/test_cap_2026_005_sink_local_containment_traversal_refused.py -v`
Expected: PASS.

- [ ] **Step 4: Run the full release-blocking adversarial suite**

Run: `uv run pytest tests/adversarial -q`
Expected: all pass (the corpus schema-validates the new YAML; the payload-count/uniqueness guards stay green).

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/capability_bypass/sink_local_containment_traversal_refused.yaml \
  tests/adversarial/capability_bypass/test_cap_2026_005_sink_local_containment_traversal_refused.py
git commit -m "test(security): cap-2026-005 adversarial entry for sink-local containment (#364)

Drives the real comms_adapter_load_grants builder with a model_construct
traversal id (validator-bypassed) + a real-adapter positive control. Pins the
sink-local containment defense fired: a traversal-shaped id is refused before
the manifest read, no arbitrary-file read outside plugins/ rides the seed.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Final verification (before PR)

- [ ] `make check` (lint + format + type + unit/integration) — verify exit 0.
- [ ] `uv run pytest tests/adversarial -q` — release-blocking suite green.
- [ ] Per-file coverage gate (Task 1 Step 8) — 100% on `_comms_adapter_grants.py`.
- [ ] i18n drift check (Task 1 Step 8) — exit 0.
- [ ] Full `/review-pr` fleet (security always) + CR CLI locally before pushing.

## Self-Review notes

- **Spec coverage:** assertion (Task 1 Step 4), error leaf → `boot_infra_install_failed` (Task 1 Step 3 + docstrings Step 5), i18n (Step 7), unit branch via `model_construct` (Step 1), per-file 100% coverage (Step 8), `cap-2026-005` adversarial entry (Task 2), docs = docstrings-only (Task 1 Step 5). All spec sections mapped.
- **Type consistency:** `CommsAdapterManifestEscapeError(adapter_id: str)` with `.adapter_id` attribute used identically across errors.py, the builder, both tests, and the docstrings.
- **No ADR** per the FIX 1 precedent (spec Alternatives); revisit only if docs-reviewer flags drift.

### Review-fix addenda (local `/review-pr` fleet + CodeRabbit, pre-push)

- **`__all__` divergence (intentional, on the record):** the impl promoted BOTH `CommsAdapterManifestEscapeError` and the pre-existing-unexported sibling `CommsAdapterSystemTierError` to `errors.py __all__`, diverging from the original "leave `__all__` unchanged" step. Kept — symmetric completion of a public-surface omission; disclosed in the fix commit body.
- **ADR-0027 addendum ADOPTED (docs-reviewer High):** the "docstrings-only" call rested on a wrong premise — FIX 1 is a dedicated paragraph IN ADR-0027, and the shipped error message + `cap-2026-005` corpus point at ADR-0027, so a dangling reference would result. Added a dated "Sink-local containment (DiD #364)" amendment to ADR-0027 + corrected the spec's precedent claim.
- **Symlink-escape test ADDED (test-eng Medium):** the lexical vectors alone wouldn't catch a `.resolve()→lexical` refactor; added a symlink-escape unit test (negative-control-verified: lexical-both-sides would pass the escape) + parametrized the lexical vectors over `{"../../../../etc", "/etc", ".."}`.
- **Read the resolved path (CodeRabbit MAJOR):** resolve once, validate the resolved path, and read THAT resolved path (was reading the un-resolved `manifest_path` after checking the resolved one — a check/use TOCTOU gap). Zero happy-path behavior change.
- **Docstring softened (reviewer Low):** the leaf's `adapter_id` is arbitrary on the bypass path this leaf guards (not "charset-validated"); `_refuse_boot` projects a fixed audit subject so the raw id never reaches an audit row.
- **Dropped `, issue #364` from the operator msgstr (devex Low):** keeps the in-repo `(see ADR-0027)` pointer only, matching the sibling message; the `#364` provenance lives in docstrings/corpus.
