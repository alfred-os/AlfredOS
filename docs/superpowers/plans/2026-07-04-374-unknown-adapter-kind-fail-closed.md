# #374 — Fail closed on unknown comms `adapter_kind` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An enabled comms adapter whose manifest declares an unregistered `adapter_kind` refuses boot (audited, exit 2) instead of silently spawning with a `None` promoter and no host classifiers.

**Architecture:** Add a registry-membership check at the single manifest chokepoint `_resolve_comms_adapter_wire_spec` (feeds both carrier selection and wiring), reusing the existing audited `comms_adapter_spawn_failed` refusal via a new `_UnknownAdapterKindError` subtype of `_CommsAdapterManifestError`. Separately convert the three `REQUIRED_CLASSIFIERS_BY_KIND.get(adapter_kind, frozenset())` typo-masking reads to plain subscripts (defence-in-depth, fail-loud on any future chokepoint bypass).

**Tech Stack:** Python 3.12, pytest, typer CliRunner, pybabel (i18n), uv.

**Spec:** `docs/superpowers/specs/2026-07-04-374-unknown-adapter-kind-fail-closed-design.md`

## Global Constraints

- **Branch:** `fix/374-unknown-adapter-kind-fail-closed` (already created, spec committed at `2c2bb69a`).
- **Every commit subject contains a literal `#374`** (the `Conventional commit format` required check: regex `^[a-z]+(\([^)]+\))?(!)?: .*#[0-9]+.*$`). Never use a digit-containing conventional-commit *type* (e.g. `i18n:`); use it as a scope (`chore(i18n):`).
- **Every commit ends with the trailer:** `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`.
- **`_comms_boot.py` has a per-file 100% line+branch gate in BOTH ci.yml jobs.** No `# pragma` on any fail-closed arm. Every new branch must be covered by a test.
- **No new `t()` key** (reuse `daemon.boot.comms_adapter_spawn_failed`). Added lines shift `#:` location refs → the pybabel catalog MUST be regenerated after the *last* code edit.
- **No `--no-verify`, no `--admin` merge.** `make check` before every push.

---

## Pre-flight: confirm no fixture relies on an unregistered kind

- [ ] **Step 0: Verify the behaviour change breaks nothing in-tree**

Run:
```bash
cd /Users/iandominey/projects/AlfredOS
grep -rn 'adapter_kind' plugins/*/manifest.toml | grep -v '^.*#'
grep -rn 'adapter_kind' tests/ | grep -iE '=\s*"|= "' | grep -viE 'discord|tui|alfred_comms_test|bogus|typo|unknown|unregistered|phantom'
```
Expected: the first lists only `alfred_comms_test` / `tui` / `discord` (all registered). The second returns nothing (no test seeds a *present-but-unregistered* `adapter_kind` expecting success). If the second returns a hit, inspect it — a fixture using an unregistered kind on a success path must be updated to a registered kind before proceeding.

---

## Task 1: Chokepoint membership check + `_UnknownAdapterKindError` subtype

**Files:**
- Modify: `src/alfred/cli/daemon/_comms_boot.py` (add class after `_CommsAdapterManifestError` ~L225; add check in `_resolve_comms_adapter_wire_spec` after L171)
- Test: `tests/unit/cli/daemon/test_comms_boot_refusal_arms.py`

**Interfaces:**
- Produces: `_UnknownAdapterKindError(adapter_id: str, adapter_kind: str)` — subtype of `_CommsAdapterManifestError`; attributes `.adapter_id: str`, `.field == "adapter_kind"`, `.adapter_kind: str`.
- Consumes: existing `_resolve_comms_adapter_wire_spec(adapter_id: str) -> _CommsAdapterWireSpec`, `_build_comms_adapter_wiring(...)`, `_BootRefusedError`, `FakeAuditWriter`, `_seed_manifest`, `_StubManifest`.

- [ ] **Step 1: Add the two failing tests + import**

In `tests/unit/cli/daemon/test_comms_boot_refusal_arms.py`, add `_UnknownAdapterKindError` to the import block (currently importing `_build_comms_adapter_wiring, _CommsAdapterManifestError, _CommsAdapterWireSpec, _make_control_reject_auditor, _resolve_comms_adapter_wire_spec`):

```python
from alfred.cli.daemon._comms_boot import (
    _build_comms_adapter_wiring,
    _CommsAdapterManifestError,
    _CommsAdapterWireSpec,
    _make_control_reject_auditor,
    _resolve_comms_adapter_wire_spec,
    _UnknownAdapterKindError,
)
```

Append these two tests (place the first after the existing `_resolve_comms_adapter_wire_spec` arm tests ~L149, and the second after the existing `_build_comms_adapter_wiring` arm tests ~L254):

```python
def test_resolve_wire_spec_raises_on_unregistered_adapter_kind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A present-but-unregistered ``adapter_kind`` refuses fail-closed (#374).

    The manifest declares a syntactically-valid ``adapter_kind`` that is NOT a member
    of the host's closed vocabulary (``REQUIRED_CLASSIFIERS_BY_KIND``) — a typo'd or
    unregistered kind. Instead of silently treating it as an empty-classifier kind (a
    ``None`` promoter, no host classifiers), the resolver raises
    ``_UnknownAdapterKindError`` (a ``_CommsAdapterManifestError`` subtype the boot's
    refusal arms catch) so the daemon refuses boot (CLAUDE.md hard rules #5 + #7).
    """
    adapter_id = "alfred_comms_test"
    _seed_manifest(
        tmp_path,
        adapter_id,
        '[plugin]\nid = "alfred.comms-test"\n'
        '[comms_mcp]\nmodule = "alfred_comms_test.main"\nadapter_kind = "bogus_typo"\n',
    )
    monkeypatch.setattr("alfred.cli._launcher_spawn.repo_root", lambda: tmp_path)
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot.parse_manifest",
        lambda _raw: _StubManifest(comms_mcp_module="alfred_comms_test.main"),
    )

    with pytest.raises(_UnknownAdapterKindError) as excinfo:
        _resolve_comms_adapter_wire_spec(adapter_id)

    assert excinfo.value.adapter_id == adapter_id
    assert excinfo.value.adapter_kind == "bogus_typo"
    assert excinfo.value.field == "adapter_kind"
    # It IS a _CommsAdapterManifestError, so the existing except arms catch it.
    assert isinstance(excinfo.value, _CommsAdapterManifestError)
    assert "bogus_typo" in str(excinfo.value)


@pytest.mark.asyncio
async def test_build_wiring_refuses_on_unregistered_adapter_kind(
    monkeypatch: pytest.MonkeyPatch,
    fake_audit_writer: FakeAuditWriter,
) -> None:
    """An unregistered ``adapter_kind`` routes through the existing audited refusal (#374).

    ``_UnknownAdapterKindError`` is a ``_CommsAdapterManifestError`` subtype, so the
    existing ``except (OSError, ManifestError, _CommsAdapterManifestError)`` arm in
    ``_build_comms_adapter_wiring`` catches it and refuses fail-closed (exit 2,
    ``comms_adapter_spawn_failed``) with NO new wiring — proving the subtype is covered
    by the established refusal path (CLAUDE.md hard rule #7).
    """

    def _boom(_adapter_id: str) -> _CommsAdapterWireSpec:
        raise _UnknownAdapterKindError(_adapter_id, "bogus_typo")

    monkeypatch.setattr("alfred.cli.daemon._comms_boot._resolve_comms_adapter_wire_spec", _boom)

    with pytest.raises(_BootRefusedError) as excinfo:
        await _build_comms_adapter_wiring(
            adapter_id="alfred_comms_test",
            settings=object(),  # type: ignore[arg-type]
            audit=fake_audit_writer,  # type: ignore[arg-type]
            gate=object(),
            supervisor=object(),  # type: ignore[arg-type]
            graph=object(),  # type: ignore[arg-type]
            boot_id="boot-374",
            environment_source="test",
        )

    assert excinfo.value.code == 2
    rows = fake_audit_writer.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert reasons == {"comms_adapter_spawn_failed"}
```

- [ ] **Step 2: Run the new tests — verify they FAIL**

Run:
```bash
uv run pytest tests/unit/cli/daemon/test_comms_boot_refusal_arms.py::test_resolve_wire_spec_raises_on_unregistered_adapter_kind tests/unit/cli/daemon/test_comms_boot_refusal_arms.py::test_build_wiring_refuses_on_unregistered_adapter_kind -v
```
Expected: FAIL — `ImportError: cannot import name '_UnknownAdapterKindError'` (the symbol doesn't exist yet).

- [ ] **Step 3: Add `_UnknownAdapterKindError` + the chokepoint check**

In `src/alfred/cli/daemon/_comms_boot.py`, add the class immediately after the `_CommsAdapterManifestError` definition (after its `self.field = field` line, ~L225):

```python
class _UnknownAdapterKindError(_CommsAdapterManifestError):
    """An enabled comms adapter declares an ``adapter_kind`` absent from the host registry.

    The manifest's ``adapter_kind`` is a non-empty string but NOT a member of the
    host's closed vocabulary (:data:`alfred.comms_mcp.classifier_registry.REQUIRED_CLASSIFIERS_BY_KIND`)
    — a typo'd or unregistered kind (#374). Refusing boot here (fail-closed, CLAUDE.md
    hard rules #5 + #7) stops the adapter being spawned with a ``None`` promoter and no
    host classifiers, which would let raw (T3) sub-payloads reach the orchestrator
    unpromoted. A subtype of :class:`_CommsAdapterManifestError` so the existing
    ``except (OSError, ManifestError, _CommsAdapterManifestError)`` refusal arms catch
    it unchanged (audited ``comms_adapter_spawn_failed``, exit 2).
    """

    def __init__(self, adapter_id: str, adapter_kind: str) -> None:
        super().__init__(adapter_id, "adapter_kind")
        self.adapter_kind = adapter_kind
        # The parent ctor built a "manifest missing 'adapter_kind'" message, but here
        # the field is PRESENT and names an unregistered kind — restate accurately.
        self.args = (
            f"comms adapter {adapter_id!r} manifest declares unknown adapter_kind "
            f"{adapter_kind!r} (not in REQUIRED_CLASSIFIERS_BY_KIND)",
        )
```

Then in `_resolve_comms_adapter_wire_spec`, immediately after the existing non-empty-string guard (the `if not isinstance(adapter_kind, str) or not adapter_kind: raise _CommsAdapterManifestError(adapter_id, "adapter_kind")` block, ~L170-171), add:

```python
    from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND

    if adapter_kind not in REQUIRED_CLASSIFIERS_BY_KIND:
        raise _UnknownAdapterKindError(adapter_id, adapter_kind)
```

(Function-local import — matches the module's established convention: the same symbol is imported function-locally in `_build_sub_payload_promoter`, `_build_forwarded_inbound_registry`, and `_build_comms_adapter_wiring`.)

- [ ] **Step 4: Run the new tests — verify they PASS**

Run:
```bash
uv run pytest tests/unit/cli/daemon/test_comms_boot_refusal_arms.py -v
```
Expected: PASS (all arms, including the two new ones).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_comms_boot.py tests/unit/cli/daemon/test_comms_boot_refusal_arms.py
git commit -m "$(cat <<'EOF'
fix(comms-boot): refuse boot on an unregistered adapter_kind (#374)

Add a REQUIRED_CLASSIFIERS_BY_KIND membership check at the manifest
chokepoint _resolve_comms_adapter_wire_spec (feeds both carrier selection
and wiring). A typo'd/unregistered adapter_kind now raises the new
_UnknownAdapterKindError (a _CommsAdapterManifestError subtype the existing
refusal arms catch) -> audited comms_adapter_spawn_failed, exit 2 -- instead
of silently spawning with a None promoter and no host classifiers.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 2: Convert the three `.get(…, frozenset())` reads to subscripts

**Files:**
- Modify: `src/alfred/cli/daemon/_comms_boot.py` (L210, L306, L881 + the L871-878 comment + the L188-204 docstring parenthetical)
- Test: `tests/unit/cli/daemon/test_daemon_promoter_wiring.py`

**Interfaces:**
- Consumes: existing `_build_sub_payload_promoter(*, adapter_kind: str, content_store: object) -> object | None`, `_StoreSpy`.

- [ ] **Step 1: Add the failing factory-tripwire test**

In `tests/unit/cli/daemon/test_daemon_promoter_wiring.py`, add (after `test_factory_returns_none_for_empty_set_kind`, ~L87):

```python
def test_factory_fails_loud_on_unregistered_kind() -> None:
    """The promoter factory fails LOUD on an unregistered kind (#374 defence-in-depth).

    Post-#374 the factory reads ``REQUIRED_CLASSIFIERS_BY_KIND[adapter_kind]`` (a plain
    subscript, not ``.get(..., frozenset())``), so a kind the manifest chokepoint would
    already have refused — reachable only if a future caller bypasses that chokepoint —
    raises ``KeyError`` rather than silently masking the typo as an empty-classifier
    kind (a ``None`` promoter). The chokepoint (``_resolve_comms_adapter_wire_spec``) is
    the audited refusal; this subscript is the internal tripwire against drift.
    """
    store = _StoreSpy()
    with pytest.raises(KeyError):
        _build_sub_payload_promoter(adapter_kind="bogus_unregistered", content_store=store)
```

- [ ] **Step 2: Run it — verify it FAILS**

Run:
```bash
uv run pytest tests/unit/cli/daemon/test_daemon_promoter_wiring.py::test_factory_fails_loud_on_unregistered_kind -v
```
Expected: FAIL — currently `.get("bogus_unregistered", frozenset())` returns `frozenset()`, so the factory returns `None` (no `KeyError` raised); the test's `pytest.raises(KeyError)` fails with "DID NOT RAISE".

- [ ] **Step 3: Convert the three reads to subscripts + reconcile the nearby prose**

In `src/alfred/cli/daemon/_comms_boot.py`:

**L210** (in `_build_sub_payload_promoter`):
```python
    if not REQUIRED_CLASSIFIERS_BY_KIND[adapter_kind]:
        return None
```

**L306** (in `_build_forwarded_inbound_registry`):
```python
        if promoter is None and REQUIRED_CLASSIFIERS_BY_KIND[kind]:
            raise _ForwardedInboundRegistryMisconfiguredError(kind)
```

**L881** (in `_build_comms_adapter_wiring`):
```python
    if sub_payload_promoter is None and REQUIRED_CLASSIFIERS_BY_KIND[wire.adapter_kind]:
```
(collapse the two-line `.get(\n wire.adapter_kind, frozenset()\n )` call into the single-line subscript).

Reconcile the docstring parenthetical in `_build_sub_payload_promoter` (~L195-196): change "so the default-empty path stays byte-for-byte unchanged (``frozenset()`` -> ``None`` ..." to "so the registered-empty path stays byte-for-byte unchanged (an empty required set -> ``None`` -> the existing inbound behaviour)." — the `.get` default no longer exists; an unregistered kind is refused upstream, and a *registered* empty-set kind still yields `None`.

Reconcile the comment above L881 (~L871-878): where it explains the guard, ensure it does not claim the `.get` default masks anything; the subscript now assumes a chokepoint-validated registered kind. Add one clause: "Post-#374 ``wire.adapter_kind`` is chokepoint-validated as a registered kind, so this reads ``REQUIRED_CLASSIFIERS_BY_KIND[...]`` directly (a subscript, not ``.get(..., frozenset())``); an unregistered kind was already refused at manifest resolution."

- [ ] **Step 4: Run the affected suites — verify PASS**

Run:
```bash
uv run pytest tests/unit/cli/daemon/test_daemon_promoter_wiring.py tests/unit/cli/daemon/test_comms_boot_refusal_arms.py tests/unit/cli/daemon/test_daemon_comms_spawn.py -v
```
Expected: PASS (the new tripwire test raises `KeyError`; every existing promoter/refusal/spawn test still passes — the subscripts see only registered kinds on their live paths).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_comms_boot.py tests/unit/cli/daemon/test_daemon_promoter_wiring.py
git commit -m "$(cat <<'EOF'
fix(comms-boot): read REQUIRED_CLASSIFIERS_BY_KIND by subscript, not .get default (#374)

Replace the three .get(adapter_kind, frozenset()) typo-masking reads with
plain subscripts. Backed by the manifest chokepoint, every one provably sees
a registered kind; a future chokepoint bypass now fails LOUD (KeyError)
instead of silently equating an unknown kind with an empty-classifier kind.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 3: i18n catalog regen (after the last code edit)

**Files:**
- Modify: `locale/en/LC_MESSAGES/alfred.po` (regenerated `#:` location refs; no msgid change)

- [ ] **Step 1: Regenerate the catalog**

The Task 1/2 edits shifted the line numbers of `t()` sites in `_comms_boot.py`, so the catalog's `#:` refs are stale. Run:
```bash
cd /Users/iandominey/projects/AlfredOS
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching
uv run pybabel compile -d locale -D alfred --statistics
```

- [ ] **Step 2: Verify no drift remains (mirror the CI check)**

Run:
```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update --check -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching --ignore-pot-creation-date
echo "exit: $?"
```
Expected: exit 0 (no drift). Also confirm the diff is location-only:
```bash
git diff --stat locale/
git diff locale/ | grep -E '^\+msgid|^\-msgid' || echo "no msgid changes (location-only, as expected)"
```
Expected: only `alfred.po` changed; no `msgid` add/remove.

- [ ] **Step 3: Commit**

```bash
git add locale/
git commit -m "$(cat <<'EOF'
chore(i18n): refresh catalog #: refs after comms-boot line shift (#374)

No msgid change (the unregistered-adapter_kind refusal reuses the existing
daemon.boot.comms_adapter_spawn_failed message); the added lines in
_comms_boot.py shifted the t() site #: location refs.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 4: Full local verification

- [ ] **Step 1: Per-file 100% coverage of `_comms_boot.py`**

Run:
```bash
uv run pytest tests/unit/cli/daemon/ \
  --cov=alfred.cli.daemon._comms_boot --cov-branch \
  --cov-report=term-missing --cov-fail-under=100
```
Expected: `_comms_boot.py` 100% line + branch, exit 0. If any line/arc is missing, it will be listed — add a covering test (no `# pragma` on fail-closed arms).

- [ ] **Step 2: `make check` (lint + format + type + unit/integration)**

Run:
```bash
make check; echo "make check exit: $?"
```
Expected: exit 0. (Per project memory, the macOS integration lane can throw false `EE` in untouched capability_gate timing tests under load — if that is the only failure, verify the touched suites pass in isolation and trust CI; do not weaken anything.)

- [ ] **Step 3: Release-blocking adversarial suite (trust-boundary path touched)**

Run:
```bash
uv run pytest tests/adversarial -q; echo "adversarial exit: $?"
```
Expected: PASS (269+ passed). `_comms_boot.py` is a trust-boundary boot path; keep the adversarial suite green.

- [ ] **Step 4: Confirm the branch is clean and ready**

Run:
```bash
git status -sb
git log --oneline origin/main..HEAD
```
Expected: 4 commits ahead (spec + Task 1 + Task 2 + i18n), clean tree.

---

## Task 5: Review, push, merge

- [ ] **Step 1: Full `/review-pr` fleet LOCALLY before push** (save CR-cloud credits). All always-include reviewers; security ALWAYS; devops (ci not touched here, so devops optional). Give reviewer subagents a stable scratchpad diff copy + "read-only, no checkout/switch/stash". Run CodeRabbit CLI in parallel with `--base origin/main`.
- [ ] **Step 2: Fix any findings** in-branch (new trailing commits; each subject carries `#374`).
- [ ] **Step 3: Push + open PR.** Then immediately `gh pr checks <N>` (catch the conventional-commit / i18n / markdown-lint reds independent of the fleet).
- [ ] **Step 4: path-to-green** — poll CI + CR-cloud, resolve every thread (verify each fix in HEAD first), plain `gh pr merge --rebase` on all-green. NEVER `--admin`.

---

## Self-Review (checklist run against the spec)

**1. Spec coverage:**
- Chokepoint membership check → Task 1. ✓
- `_UnknownAdapterKindError` subtype reusing `comms_adapter_spawn_failed` → Task 1. ✓
- Three `.get → []` conversions → Task 2. ✓
- Coverage-clean / no pragma → Task 4 Step 1. ✓
- Test plan (refusal + end-to-end + factory tripwire + happy paths preserved) → Tasks 1, 2, 4. ✓
- Safety check (no in-tree/fixture unregistered kind) → Pre-flight Step 0. ✓
- i18n regen (no new key) → Task 3. ✓
- CI gate / make check / adversarial → Task 4. ✓

**2. Placeholder scan:** No TBD/TODO; all code + commands are concrete. ✓

**3. Type consistency:** `_UnknownAdapterKindError(adapter_id, adapter_kind)` signature + `.adapter_id`/`.field`/`.adapter_kind` attributes used consistently in Task 1's tests and class. `_build_sub_payload_promoter(*, adapter_kind, content_store)` matches the existing signature used in Task 2's test. ✓
