# #437 — policy_ref charset guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refuse a `policy_ref` value containing any character outside the path-safe set `[A-Za-z0-9._/-]`, at both the manifest parser (producer, primary) and the launcher (defense-in-depth), closing the audit-JSON injection where `POLICY_REF` is interpolated raw into `printf` rows.

**Architecture:** Two layers using identical negated-class semantics. `manifest.py` raises a typed `ManifestError` on a bad value before `SandboxBlock` construction. `bin/alfred-plugin-launcher.sh` adds a `case` guard at the single `POLICY_REF` chokepoint (L290) mirroring the existing `PLUGIN_ID` guard, emitting a new `policy_ref_charset_invalid` refusal reason **without echoing the tainted value**. The reason joins `SANDBOX_REFUSED_REASONS`, which the #432 vocab-sync test enforces.

**Tech Stack:** Python 3.14 (`re`, Pydantic v2, hypothesis), POSIX sh, pytest, the sandbox_escape adversarial corpus (YAML + `test_sbx_corpus_executable.py`).

**Spec:** [`docs/superpowers/specs/2026-07-15-issue-437-policy-ref-charset-guard-design.md`](../specs/2026-07-15-issue-437-policy-ref-charset-guard-design.md)

**Issue:** [#437](https://github.com/MrReasonable/AlfredOS/issues/437). Branch `fix/437-policy-ref-charset-guard`.

## Global Constraints

- **Path-safe allowlist = `[A-Za-z0-9._/-]`** (verified against every shipped `policy_ref`). Both layers use the **negated** form (reject if any char is OUTSIDE the set): manifest.py `re.compile(r"[^A-Za-z0-9._/-]")`, launcher `case … in *[!A-Za-z0-9._/-]*)`. Empty is tolerated (no bad char) — the existing missing/non-empty checks own that case.
- **Anti-echo (security crux):** the launcher's charset-refusal `printf` MUST NOT interpolate `${POLICY_REF}`. It carries `plugin_id` (already validated), `reason`, `environment`, `host_os` — no `policy_ref` field.
- **New reason `policy_ref_charset_invalid`** must be added to `SANDBOX_REFUSED_REASONS`; the #432 vocab-sync test fails otherwise. `test_sandbox_reason_vocab_sync.py:56`'s `== 25` becomes `== 26` (one deliberate count bump — the #432 binding working as designed).
- **Security boundary:** 100% line + branch coverage on the new manifest.py branch and launcher guard. The adversarial suite is release-blocking.
- **i18n:** operator-facing strings via `t()`; `pybabel` catalog clean. New keys filled in `locale/en/LC_MESSAGES/alfred.po`.
- Every commit subject carries a literal `#437` **after** the colon. No `--no-verify`. `make check` before every push (check `$?`).
- New launcher **subprocess** tests carry `@pytest.mark.skipif(sys.platform == "win32", …)` (the #428 winsock lesson); pair with an in-process twin for coverage the subprocess can't reach.

## File structure

| File | Responsibility |
| --- | --- |
| `src/alfred/plugins/manifest.py` | **Modify.** `import re` + module const `_POLICY_REF_BAD_CHAR`; charset check in the `policy_refs_raw.items()` loop after the `isinstance(str)` check (~L314). |
| `locale/en/LC_MESSAGES/alfred.po` | **Modify.** New msgid `plugin.manifest_sandbox_policy_refs_value_charset` + `supervisor.sandbox.refused.policy_ref_charset_invalid`. |
| `tests/unit/plugins/test_manifest_sandbox_block.py` | **Modify.** Refusal test + hypothesis property test. |
| `bin/alfred-plugin-launcher.sh` | **Modify.** `case` guard after the empty-check `fi` (~L295). |
| `src/alfred/audit/audit_row_schemas.py` | **Modify.** Add `policy_ref_charset_invalid` to `SANDBOX_REFUSED_REASONS`. |
| `src/alfred/plugins/_sandbox_i18n.py` | **Modify.** Add the operator key entry. |
| `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` | **Modify.** `== 25` → `== 26`. |
| `tests/unit/plugins/test_plugin_launcher_*.py` | **Modify/Create.** Launcher subprocess + in-proc guard tests incl. the anti-echo assertion. |
| `tests/adversarial/sandbox_escape/sbx_2026_017_policy_ref_charset_injection.yaml` | **Create.** The corpus payload. |

---

### Task 1: manifest.py producer-side charset validator

**Files:**

- Modify: `src/alfred/plugins/manifest.py` (add `import re` near L34; a module const; a check after L314)
- Modify: `locale/en/LC_MESSAGES/alfred.po` (after the `…value_type` entry at L2961-2963)
- Test: `tests/unit/plugins/test_manifest_sandbox_block.py`

**Interfaces:**

- Consumes: `parse_manifest(raw: str)`, `ManifestError`, `t` (all already imported/defined).
- Produces: `parse_manifest` now raises `ManifestError` when a `policy_refs` value contains a char outside `[A-Za-z0-9._/-]`.

- [ ] **Step 1: Write the failing refusal test**

Append to `tests/unit/plugins/test_manifest_sandbox_block.py`:

```python
def test_sandbox_policy_refs_injection_charset_refuses() -> None:
    # #437: a policy_ref carrying JSON-injection chars (a double-quote + comma
    # forging an `event` field) must raise the TYPED ManifestError before
    # SandboxBlock construction. Single-quoted TOML literal carries the quotes
    # verbatim. The launcher interpolates POLICY_REF raw into audit-JSON printf
    # rows; PLUGIN_ID is charset-validated for exactly this reason.
    raw = (
        _BASE
        + """
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = 'config/x","event":"forged'
"""
    )
    with pytest.raises(ManifestError):
        parse_manifest(raw)
```

- [ ] **Step 2: Run it — expect FAIL**

Run: `uv run pytest tests/unit/plugins/test_manifest_sandbox_block.py::test_sandbox_policy_refs_injection_charset_refuses -v`
Expected: FAIL — no exception raised (the value is a `str`, so the existing checks pass it through).

- [ ] **Step 3: Add the validator**

In `src/alfred/plugins/manifest.py`, add `import re` alongside the stdlib imports (near L34 `import tomllib`):

```python
import re
import tomllib
```

Add a module-level constant near the other manifest constants (e.g. beside `_VALID_OS_KEYS`):

```python
# #437: policy_ref values are interpolated raw into the launcher's audit-JSON
# printf rows (bin/alfred-plugin-launcher.sh L323/L397). Reject any char outside
# the path-safe set so a value cannot forge a JSON field / inject a row. Mirrors
# the launcher's own `*[!A-Za-z0-9._/-]*` guard (same negated class); empty is
# tolerated here (the kind:full-non-empty + launcher empty-checks own that case).
_POLICY_REF_BAD_CHAR = re.compile(r"[^A-Za-z0-9._/-]")
```

In the `policy_refs_raw.items()` loop, immediately after the `isinstance(os_value, str)` check (L313-314), add:

```python
        if _POLICY_REF_BAD_CHAR.search(os_value):
            raise ManifestError(
                t("plugin.manifest_sandbox_policy_refs_value_charset", os_key=os_key)
            )
```

- [ ] **Step 4: Add the i18n message**

In `locale/en/LC_MESSAGES/alfred.po`, after the `plugin.manifest_sandbox_policy_refs_value_type` entry (L2961-2963), add:

```
msgid "plugin.manifest_sandbox_policy_refs_value_charset"
msgstr "Plugin manifest [sandbox] policy_refs[{os_key}] contains characters outside the path-safe set [A-Za-z0-9._/-]."
```

(msgstr is brace-safe for `.format()` — `{os_key}` is the only brace pair, no literal braces.)

- [ ] **Step 5: Run — expect PASS**

Run: `uv run pytest tests/unit/plugins/test_manifest_sandbox_block.py::test_sandbox_policy_refs_injection_charset_refuses -v`
Expected: PASS.

- [ ] **Step 6: Add a property test + a valid-value guard test**

Append:

```python
from hypothesis import given
from hypothesis import strategies as st

# Chars guaranteed outside [A-Za-z0-9._/-] AND safe inside a single-quoted TOML
# literal (no single-quote, no newline/control). Every generated value has >=1.
_INJECTION_ALPHABET = "\",;:{}[]<>= \t()|&$#@!*?~`^%+"


@given(st.text(alphabet=_INJECTION_ALPHABET, min_size=1))
def test_sandbox_policy_refs_charset_property_refuses(bad: str) -> None:
    # Any value composed of out-of-set chars is refused. Single-quoted TOML
    # literal carries them verbatim (the alphabet excludes ' and newlines).
    raw = _BASE + f"""
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = '{bad}'
"""
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_sandbox_policy_refs_valid_path_still_parses() -> None:
    # A legitimate path-safe policy_ref must still parse (guards against an
    # over-strict allowlist). Mirrors the shape of every shipped policy_ref.
    raw = _BASE + """
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = "config/sandbox/example.linux.bwrap.policy"
"""
    manifest = parse_manifest(raw)
    assert manifest.sandbox.policy_refs["linux"] == "config/sandbox/example.linux.bwrap.policy"
```

- [ ] **Step 7: Run the manifest test module + lint/type**

Run: `uv run pytest tests/unit/plugins/test_manifest_sandbox_block.py -q`
Expected: all pass (existing + 3 new).
Run: `uv run ruff check src/alfred/plugins/manifest.py && uv run mypy src/alfred/plugins/manifest.py && uv run pyright src/alfred/plugins/manifest.py`
Expected: clean.

- [ ] **Step 8: pybabel catalog check**

Run: `uv run pybabel compile -d locale --statistics 2>&1 | tail -3` (or the repo's catalog-check target) and confirm no fuzzy/missing for the new key.
Expected: the new msgid compiles.

- [ ] **Step 9: Commit**

```bash
git add src/alfred/plugins/manifest.py locale/en/LC_MESSAGES/alfred.po tests/unit/plugins/test_manifest_sandbox_block.py
git commit -m "feat(plugins): #437 reject policy_ref values with injection chars

policy_ref is interpolated raw into the launcher's audit-JSON printf rows while
PLUGIN_ID is charset-validated for exactly that reason. Reject any policy_ref value
containing a char outside the path-safe set [A-Za-z0-9._/-] at the manifest parser
(the authoritative producer), before SandboxBlock construction."
```

---

### Task 2: launcher defense-in-depth guard + vocab + i18n

**Files:**

- Modify: `bin/alfred-plugin-launcher.sh` (guard after the empty-check `fi` ~L295)
- Modify: `src/alfred/audit/audit_row_schemas.py` (add the reason to `SANDBOX_REFUSED_REASONS`)
- Modify: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` (`== 25` → `== 26`)
- Modify: `src/alfred/plugins/_sandbox_i18n.py` + `locale/en/LC_MESSAGES/alfred.po`
- Test: `tests/unit/plugins/test_plugin_launcher_stub.py` (or the launcher subprocess test module) + an in-proc twin

**Interfaces:**

- Consumes: the launcher's `${POLICY_REF}` (assigned L290), `${PLUGIN_ID}` (validated L123), `SANDBOX_REFUSED_REASONS`.
- Produces: launcher exits 1 with `reason=policy_ref_charset_invalid` on a charset-invalid non-empty `POLICY_REF`, echoing no tainted value.

- [ ] **Step 1: Add the reason to the vocab + bump the count**

In `src/alfred/audit/audit_row_schemas.py`, add `"policy_ref_charset_invalid",` to the `SANDBOX_REFUSED_REASONS` frozenset in the "policy_ref resolution (launcher + manifest_reader)" group (beside `policy_ref_missing`).

In `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`, change the shape-test assertion (L56):

```python
    assert len(reasons) == 26, f"expected 26 reasons, got {len(reasons)}: {sorted(reasons)}"
```

(This is the intended count churn the #432 review documented — the closed-vocab binding forcing one deliberate, reviewed bump when a new launcher reason lands.)

- [ ] **Step 2: Run the vocab-sync test — expect FAIL (reason not yet emitted by the launcher)**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q`
Expected: FAIL — `test_frozenset_is_exactly_emittable_plus_reserved` (the frozenset now has `policy_ref_charset_invalid` but no launcher emit line produces it, so it's neither emittable nor in `_RESERVED_UNEMITTED` → orphan). This proves the #432 guard is live: the vocab entry MUST be matched by a launcher emit path.

- [ ] **Step 3: Add the launcher guard**

In `bin/alfred-plugin-launcher.sh`, after the empty-check block that ends around L295 (the `fi` closing `if [ -z "${POLICY_REF}" ]`), and BEFORE `case "${HOST_OS}" in`, insert:

```sh
        # #437: POLICY_REF is interpolated raw into the audit-JSON printf rows
        # below (and passed to the flags subprocess). PLUGIN_ID is charset-gated
        # at entry for exactly this reason; do the same for POLICY_REF here, at
        # its single chokepoint, BEFORE any use. Refuse WITHOUT echoing the
        # tainted value — emitting it into the JSON row would BE the injection.
        # Same negated path-safe class as the Python producer (manifest.py).
        case "${POLICY_REF}" in
            *[!A-Za-z0-9._/-]*)
                printf 'supervisor.sandbox.refused.policy_ref_charset_invalid plugin_id=%s\n' "${PLUGIN_ID}" >&2
                printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"policy_ref_charset_invalid","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
                exit 1
                ;;
        esac
```

- [ ] **Step 4: Run the vocab-sync test — expect PASS**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -q`
Expected: 7 passed. The launcher now emits `policy_ref_charset_invalid` (a literal in a printf carrying the event name), so `_launcher_emittable_reasons()` picks it up → emittable becomes 21, frozenset 26, equality holds.

- [ ] **Step 5: Add the operator i18n entry**

In `src/alfred/plugins/_sandbox_i18n.py`, add to the mapping (beside `policy_ref_unreadable`):

```python
    "supervisor.sandbox.refused.policy_ref_charset_invalid": t(
        "supervisor.sandbox.refused.policy_ref_charset_invalid"
    ),
```

In `locale/en/LC_MESSAGES/alfred.po`, add (beside the sibling `supervisor.sandbox.refused.*` entries):

```
msgid "supervisor.sandbox.refused.policy_ref_charset_invalid"
msgstr "The plugin's sandbox policy_ref contains characters outside the path-safe set and was refused."
```

- [ ] **Step 6: Write the launcher subprocess refusal test (with the anti-echo assertion)**

Add to the launcher subprocess test module (`tests/unit/plugins/test_plugin_launcher_stub.py` or the sibling that drives the real launcher script). Model it on the existing launcher-driving tests there. The load-bearing assertions:

```python
import sys
import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX launcher subprocess; winsock hermetic-PATH breaks the child (see #428)")
def test_launcher_refuses_policy_ref_with_injection_charset() -> None:
    # #437: drive the launcher with a manifest whose policy_ref carries a
    # JSON-injection payload. It must refuse with policy_ref_charset_invalid,
    # exit 1, and — the security crux — NOT echo the tainted value anywhere.
    tainted = 'config/x","event":"forged'
    result = _run_launcher_with_policy_ref(tainted)  # helper mirrors the module's existing launcher-drivers
    assert result.returncode == 1
    assert "policy_ref_charset_invalid" in result.stderr
    # ANTI-ECHO: neither the forged substring nor a bare quote from the payload
    # appears in the launcher's output — the refusal row omits the policy_ref field.
    assert "forged" not in result.stderr
    assert '","event":"' not in result.stderr
```

If the module lacks a reusable launcher-driver for a full-`kind` manifest, add a minimal helper that writes a temp manifest with `[sandbox] kind="full"` + `[sandbox.policy_refs] linux='<tainted>'`, sets `ALFRED_PLUGIN_MANIFEST_PATH`/`HOST_OS=linux`/env, and runs `bin/alfred-plugin-launcher.sh`. Reuse the existing hermetic-env pattern from the module (the `_run` helper that sets `PATH=/usr/bin:/bin` — the reason skipif(win32) is required).

- [ ] **Step 7: Write the in-proc twin (coverage the subprocess can't reach)**

The subprocess test is invisible to coverage. Add an in-process test that asserts the guard's LOGIC via the shared predicate — the negated path-safe class — so the branch is covered on all platforms. If the launcher guard's classification is not yet extracted to a Python-callable, assert the equivalent Python predicate that manifest.py uses (`_POLICY_REF_BAD_CHAR`) rejects the same payload, and cross-reference that the launcher's `*[!A-Za-z0-9._/-]*` is byte-identical to it (a sync assertion, the #432 pattern):

```python
def test_launcher_charset_class_matches_the_python_producer() -> None:
    # The launcher's negated class must equal manifest.py's, so both layers
    # refuse exactly the same values. Parse the class out of the launcher.
    from pathlib import Path

    from alfred.plugins.manifest import _POLICY_REF_BAD_CHAR

    launcher = (Path(__file__).resolve().parents[3] / "bin" / "alfred-plugin-launcher.sh").read_text()
    assert "*[!A-Za-z0-9._/-]*" in launcher, "launcher POLICY_REF guard class drifted from manifest.py"
    # And the Python producer rejects the injection payload the launcher guards.
    assert _POLICY_REF_BAD_CHAR.search('config/x","event":"forged')
    assert _POLICY_REF_BAD_CHAR.search("config/sandbox/x.linux.bwrap.policy") is None
```

- [ ] **Step 8: Run tests + shellcheck**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py tests/unit/plugins/test_plugin_launcher_stub.py -q`
Expected: all pass (subprocess test may skip on non-Linux hosts without runuser — acceptable; the in-proc twin + vocab-sync run everywhere).
Run: `shellcheck bin/alfred-plugin-launcher.sh` (if available) — expected clean.

- [ ] **Step 9: Commit**

```bash
git add bin/alfred-plugin-launcher.sh src/alfred/audit/audit_row_schemas.py tests/unit/plugins/test_sandbox_reason_vocab_sync.py src/alfred/plugins/_sandbox_i18n.py locale/en/LC_MESSAGES/alfred.po tests/unit/plugins/test_plugin_launcher_stub.py
git commit -m "feat(sandbox): #437 launcher POLICY_REF charset guard (defense-in-depth)

Guard POLICY_REF at its single chokepoint with the same negated path-safe class as
the manifest producer, refusing with policy_ref_charset_invalid WITHOUT echoing the
tainted value into the audit row (echoing it would be the injection). Add the reason
to SANDBOX_REFUSED_REASONS (the #432 vocab-sync test enforces it; count 25->26)."
```

---

### Task 3: sbx-2026-017 adversarial payload

**Files:**

- Create: `tests/adversarial/sandbox_escape/sbx_2026_017_policy_ref_charset_injection.yaml`
- Modify: the corpus load-list / node-id gate if payloads are enumerated (check `test_sbx_corpus_executable.py` + any `_load` list)
- Modify: `tests/adversarial/sandbox_escape/README.md` (payload count / entry)

**Interfaces:**

- Consumes: the corpus loader/schema in `test_sbx_corpus_executable.py`.
- Produces: `sbx-2026-017` asserting a charset-injection `policy_ref` is refused by both layers.

- [ ] **Step 1: Confirm the corpus schema + node-id gate**

Run: `uv run pytest tests/adversarial/sandbox_escape -q` (baseline green) and read `tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py` to find (a) the YAML schema keys it validates, (b) any hardcoded payload-id list or count assertion (the #245 "assert RAN" / required-node gate) that must include `sbx-2026-017`.
Expected: baseline passes; note the exact list/count to update.

- [ ] **Step 2: Create the payload**

Create `tests/adversarial/sandbox_escape/sbx_2026_017_policy_ref_charset_injection.yaml`, mirroring the `sbx_2026_016` shape (`id`, `category`, `threat`, `ingestion_path`, `payload.attack`, `payload.variants`, `expected_outcome`, `provenance`):

```yaml
id: sbx-2026-017
category: sandbox_escape
threat: >-
  A kind:full manifest sets a policy_ref containing JSON-injection characters —
  a double-quote + comma that forges the `event` field, or a newline that injects
  a whole fabricated row — that the launcher interpolates raw into its audit-JSON
  printf rows (the sandbox_refused and sandbox_stub_used emitters) and passes to
  the flags subprocess, latent today (manifests are human-gated and nothing yet
  parses the launcher's stderr JSON — #433) but live the instant a json.loads
  consumer of that row exists.
ingestion_path: sandbox_policy_load
payload:
  attack: policy_ref_charset_injection
  variants:
    - 'config/x","event":"forged'
    - "config/x\n{\"event\":\"forged\"}"
    - 'config/x";DROP'
    - 'config/x{{brace}}'
expected_outcome: refused
provenance: >-
  #437. Two layers refuse any policy_ref value containing a char outside the
  path-safe set [A-Za-z0-9._/-] (negated class, identical on both sides):
  manifest.py raises the typed ManifestError
  (plugin.manifest_sandbox_policy_refs_value_charset) BEFORE SandboxBlock
  construction; bin/alfred-plugin-launcher.sh refuses at the POLICY_REF chokepoint
  with reason=policy_ref_charset_invalid, emitting NO tainted value into the audit
  row (the anti-echo rule). PLUGIN_ID has been charset-gated since PR-S4-6 for the
  same reason; #437 closes the sibling POLICY_REF gap. Not kernel-observable — the
  containment is the parser/launcher refusing to emit a row carrying the payload.
references:
  - "spec §7.1 manifest sandbox policy_refs"
  - "src/alfred/plugins/manifest.py (_POLICY_REF_BAD_CHAR)"
  - "bin/alfred-plugin-launcher.sh (POLICY_REF charset guard)"
  - "docs/superpowers/specs/2026-07-15-issue-437-policy-ref-charset-guard-design.md"
```

`ingestion_path` must be `sandbox_policy_load` (a valid `IngestionPath` enum value) and
`references` is required (`Field(..., min_length=1)`) — confirm both against
`tests/adversarial/payload_schema.py` before writing.

- [ ] **Step 3: Wire it into the load-list / count gate (if present)**

If `test_sbx_corpus_executable.py` (or a sibling) hardcodes a payload-id set or a count (e.g. `assert len(payloads) == 16`), add `sbx-2026-017` / bump to `17`. Match the exact node-id string byte-for-byte across the YAML `id`, the load list, and any README table (the #428 lesson: node-id must be byte-identical across def / load-list / adversarial gate).

- [ ] **Step 4: Update the corpus README**

In `tests/adversarial/sandbox_escape/README.md`, add the `sbx-2026-017` row/entry mirroring `sbx-2026-016`'s.

- [ ] **Step 5: Run the adversarial corpus**

Run: `uv run pytest tests/adversarial/sandbox_escape -q`
Expected: all pass including the new payload; the load/schema/count gates green.

- [ ] **Step 6: markdownlint the README**

Run: `npx --yes markdownlint-cli2 "tests/adversarial/sandbox_escape/README.md"`
Expected: 0 errors.

- [ ] **Step 7: Commit**

```bash
git add tests/adversarial/sandbox_escape/sbx_2026_017_policy_ref_charset_injection.yaml tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py tests/adversarial/sandbox_escape/README.md
git commit -m "test(adversarial): #437 sbx-2026-017 policy_ref charset injection

A kind:full manifest whose policy_ref forges an event field / injects a row via
out-of-charset characters must be refused by both the manifest parser and the
launcher. Parse-refusal payload; both layers emit no tainted value."
```

---

### Task 4: full gates + coverage

**Files:** none (verification).

- [ ] **Step 1: Coverage on the new boundary code (must be 100% line+branch)**

Run: `uv run pytest tests/unit/plugins/test_manifest_sandbox_block.py tests/unit/plugins/test_sandbox_reason_vocab_sync.py tests/unit/plugins/test_plugin_launcher_stub.py --cov=src/alfred/plugins/manifest --cov=src/alfred/audit/audit_row_schemas --cov-branch --cov-report=term-missing 2>&1 | tail -20`
Expected: the new `manifest.py` charset branch and the vocab entry are covered; no missing lines/branches on the new code. If the launcher guard's Python-observable coverage is only via the in-proc twin, confirm the twin exercises both the reject and accept branches of `_POLICY_REF_BAD_CHAR`.

- [ ] **Step 2: i18n catalog drift**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/alfred437.pot src/alfred plugins && uv run pybabel update --no-fuzzy-matching -i /tmp/alfred437.pot -d locale && uv run pybabel compile -d locale 2>&1 | tail -3`
Expected: the two new keys present, compiled, no fuzzy. (NEVER `--omit-header`.) Confirm `git diff locale/` shows only the two new msgid/msgstr additions.

- [ ] **Step 3: Full quality gates**

Run:

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit -q
uv run pytest tests/adversarial -q
make check; echo "make check exit: $?"
```

Expected: all green; `make check` exit `0` (check `$?`; `| tail` masks it). The macOS integration lane may stall on this host's Docker — if so, verify the fast gates green and trust the Linux CI integration lane (the change has no DB/network surface).

- [ ] **Step 4: Confirm the anti-echo + both-layer refusal end-to-end**

Manually (or via the tests already written) confirm: (a) `parse_manifest` with the injection payload → `ManifestError`; (b) the launcher with the injection payload → exit 1, `reason=policy_ref_charset_invalid`, no tainted substring in output. Record the evidence for the PR.

---

## Definition of done

- [ ] `manifest.py` rejects any `policy_ref` value with a char outside `[A-Za-z0-9._/-]` via a typed `ManifestError`, before `SandboxBlock` construction; the valid-path and property tests pass.
- [ ] The launcher refuses a charset-invalid non-empty `POLICY_REF` with `policy_ref_charset_invalid`, emitting **no** tainted value (anti-echo test passes).
- [ ] `policy_ref_charset_invalid` is in `SANDBOX_REFUSED_REASONS`; `test_sandbox_reason_vocab_sync.py` green (count 26); the launcher class matches the Python producer (sync test).
- [ ] `sbx-2026-017` added, wired into the load/count gate, refused by both layers; the adversarial suite green.
- [ ] Two i18n keys added + catalog clean; 100% line+branch on the new boundary code; `make check` exit 0.

## Self-review

**Spec coverage.** Decision 1 (allowlist) → Task 1 const + Global Constraints (verified). Decision 2 (two layers) → Task 1 (manifest) + Task 2 (launcher). Decision 3 (placement) → Task 2 Step 3. Decision 4 (new reason) → Task 2 Steps 1-4. Decision 5 (anti-echo) → Task 2 Step 3 code + Step 6 assertion. Decision 6 (i18n) → Task 1 Step 4 + Task 2 Step 5. Decision 7 (adversarial) → Task 3. Testing section → Tasks 1-4. Out-of-scope items (#433, other fields) appear in no task.

**Placeholder scan.** No TBD/TODO; every code step carries literal code and commands. The one conditional ("if the module lacks a reusable launcher-driver" / "if the corpus hardcodes a count") is a genuine branch on existing-code shape the implementer confirms in Step 1 of each task, with the concrete action given for both arms.

**Type consistency.** `_POLICY_REF_BAD_CHAR` (manifest.py) — one definition, referenced by the in-proc twin (Task 2 Step 7). Reason string `policy_ref_charset_invalid` — byte-identical across the launcher printf, the frozenset, `_sandbox_i18n.py`, the `.po`, and the YAML provenance. The negated class `[A-Za-z0-9._/-]` / `*[!A-Za-z0-9._/-]*` — identical on both layers, pinned by the sync test.

**Design refinement noted.** The spec's Layer-1 sketch used `fullmatch(r"[A-Za-z0-9._/-]+")`; this plan uses the **negated-class search** `re.compile(r"[^A-Za-z0-9._/-]")` instead — it mirrors the launcher's `*[!…]*` semantics byte-for-byte (so the sync test is meaningful) and tolerates empty (no behavior change for the `kind:none`-with-policy_refs-tolerated case, which the missing/non-empty checks already own). Same security property: any non-empty value with an out-of-set char is refused.
