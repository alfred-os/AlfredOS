# #434 / #435 / #436 — Launcher Audit-Row Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `bin/alfred-plugin-launcher.sh`'s sandbox audit-row reason contract honest (every refusal recorded under its true reason), complete (every refusal path emits exactly one row), and bound (a closed vocabulary that a drift-guard enforces).

**Architecture:** Three commits on one branch. #434 fixes reason accuracy (a `2>/dev/null` that collapses five distinct refusals into one wrong reason; a `*)` alarm masquerading as a routine refusal). #435 adds rows to six row-less refusal paths. #436 declares the `sandbox_stub_used` row's `reason` field under its own closed vocabulary. The #432 AST drift-guard is extended once to cover both row families.

**Tech Stack:** Bash 3.2-compatible (`set -eu`, no pipefail), Python 3.14+, pytest, `ast` module for the drift-guard, pybabel for i18n catalogs.

**Spec:** `docs/superpowers/specs/2026-07-16-issues-434-435-436-launcher-audit-row-contract-design.md` (decisions D1-D9 referenced throughout).

**Branch:** `fix/434-435-436-launcher-audit-row-contract`, based on `4c015118`.

## Global Constraints

- **Every commit subject needs a literal `#NNN` AFTER the colon** — the `Conventional commit format` required check enforces this. Example: `fix(sandbox): #434 map the five manifest-reader refusal keys`.
- **Never `git add -A`** — untracked rulesync tool-outputs get swept in. Add named paths only.
- **Never `--no-verify`.** If a pre-commit hook fails, fix the issue.
- **`make check` before every `git push`.** `make ... | tail` masks the exit code — check `$?`.
- **The launcher is a security boundary** (`src/alfred/security/` contract). The full adversarial suite is mandatory: `uv run pytest tests/adversarial`.
- **Bash 3.2 compatibility** — macOS ships Bash 3.2. No `${arr[@]}` on a declared-but-empty array without the `${arr[@]+"${arr[@]}"}` guard. No associative arrays.
- **The parser (`src/alfred/audit/launcher_refusal.py`) is NOT modified by this PR.** D2 depends on it staying strict. Any task that touches it is wrong.
- **i18n:** exactly three new catalog keys (D9). Never `--omit-header` on pybabel. msgstrs must be brace-free. A line-shifting edit re-stales `#:` refs — re-run the i18n gate at the end.
- **structlog does not land in `caplog`** — assert via `structlog.testing.capture_logs()` filtering `e["event"]`.
- Comments explain **why**, never what. Match the launcher's existing comment density (it is heavily commented by design — it is a security boundary with non-obvious invariants).

---

## File Structure

| File | Responsibility | Tasks |
| --- | --- | --- |
| `bin/alfred-plugin-launcher.sh` | Sole producer of both row families. All emit sites. | 1, 2, 3, 4, 5 |
| `src/alfred/audit/audit_row_schemas.py` | The closed vocabularies + field sets + their prose. | 1, 2, 3, 4, 5 |
| `src/alfred/plugins/_sandbox_i18n.py` | Pybabel-visible `t()` anchors for launcher stderr keys. | 1, 4, 5 |
| `tests/unit/plugins/test_sandbox_reason_vocab_sync.py` | The #432 AST drift-guard. Extended to both families. | 1, 2, 3, 4, 5 |
| `tests/unit/launcher/test_launcher_sandbox_flow.py` | Behavioural launcher tests (fixture manifests + fake bwrap). | 1, 3, 4 |
| `tests/unit/plugins/test_plugin_launcher_stub.py` | Behavioural stub-path tests (real subprocess, JSON-parsed rows). | 5 |
| `tests/unit/audit/test_launcher_refusal.py` | Parser round-trip. New reasons must parse. | 3, 5 |
| `tests/unit/audit/test_slice_4_audit_row_fields.py` | Field-set constants. | 5 |
| `tests/adversarial/sandbox_escape/` | Forged-row + tainted-id adversarial corpus. | 6 |

**Do not create new source files.** Every change lands in an existing file.

---

## Task 1: #434A — map the five manifest-reader refusal keys

**Files:**

- Modify: `bin/alfred-plugin-launcher.sh:263-277`
- Modify: `src/alfred/audit/audit_row_schemas.py:1203-1252`
- Modify: `src/alfred/plugins/_sandbox_i18n.py:39-89`
- Modify: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`
- Test: `tests/unit/launcher/test_launcher_sandbox_flow.py`

**Interfaces:**

- Produces: launcher variable `_SANDBOX_REASON` (the mapped audit reason) and `_sandbox_err_key` (the case subject). Task 3's binding resolver keys on **both names**.
- Produces: vocab members `plugin_id_charset_invalid`, `manifest_reader_no_source`, `manifest_unreadable`, `manifest_invalid`, `reason_unclassified`.
- Produces: test helper `_parse_mapping_case(subject: str, var: str) -> dict[str, str]`.

**Naming constraint — load-bearing.** The variable MUST be `_SANDBOX_REASON`, never `_SANDBOX_AUDIT_REASON`. `_launcher_emittable_reasons` resolves a `%s` reason by substring-matching `"_AUDIT_REASON" in line` (test file L323). A name containing `_AUDIT_REASON` would silently bind the schema-case set to this printf and the guard would pass vacuously.

- [ ] **Step 1: Write the failing binding test**

Add to `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`, after `_parse_case` (~L238):

```python
def _parse_mapping_case(subject: str, var: str) -> dict[str, str]:
    """Parse a launcher ``case "<subject>" in`` whose arms each assign ``var="literal"``.

    ``_parse_case`` above understands exactly two arms (an allow-list + ``*)``) and hard-fails
    on a third. #434A's key->reason map is structurally different: N arms, each assigning a
    DISTINCT literal. Returns {arm-pattern: assigned literal}, with the ``*)`` arm keyed ``"*"``.

    Fails LOUD on an arm that does not assign ``var`` — an unassigned arm means the map has a
    hole the launcher would fall through, and a silently-skipped arm makes the binding
    UNDER-count (the #432 vacuity lesson).
    """
    text = _launcher_text()
    header = f'case "{subject}" in'
    idx = text.find(header)
    assert idx != -1, f"bash case header not found in the launcher: {header!r}"
    body = text[idx + len(header) :]
    esac = body.find("esac")
    assert esac != -1, f"no matching esac for case {subject!r}"
    body = body[:esac]

    mapping: dict[str, str] = {}
    unassigned: list[str] = []
    for arm in (a.strip() for a in body.split(";;") if a.strip()):
        pattern, _, arm_body = arm.partition(")")
        pattern = pattern.strip()
        if not pattern:
            continue
        match = re.search(rf'{re.escape(var)}="([^"]*)"', arm_body)
        if match is None:
            unassigned.append(pattern)
        else:
            mapping[pattern] = match.group(1)
    assert not unassigned, (
        f"case {subject!r} has arm(s) that never assign {var}: {unassigned}. "
        f"Each arm must assign a literal or the binding under-counts."
    )
    assert mapping, f"no arms parsed under case {subject!r}"
    return mapping


def _read_sandbox_keys() -> frozenset[str]:
    """The full ``plugin.*`` i18n keys ``manifest_reader --read-sandbox`` can print."""
    keys, passthrough = _fail_args_in("_cmd_read_sandbox")
    assert not passthrough, "_cmd_read_sandbox() unexpectedly re-emits exc.reason"
    return keys


def test_sandbox_case_maps_exactly_the_read_sandbox_keys() -> None:
    """The #434A key->reason map covers exactly the keys --read-sandbox can emit.

    Equality, not superset, so it bites BOTH ways: a new manifest_reader refusal key missing
    from bash (which would degrade to reason_unclassified — a real refusal reported as an
    alarm), AND a dead bash arm the helper can never print.
    """
    mapping = _parse_mapping_case("${_sandbox_err_key}", "_SANDBOX_REASON")
    arms = frozenset(mapping) - {"*"}
    expected = _read_sandbox_keys()
    assert len(expected) == 5, f"vacuity floor: derived {len(expected)} read-sandbox keys, want 5"
    assert arms == expected, (
        "the launcher's #434A sandbox `case` has drifted from the keys "
        "`manifest_reader --read-sandbox` can emit.\n"
        f"  missing from the bash case (would degrade to reason_unclassified): "
        f"{sorted(expected - arms)}\n"
        f"  dead entries in the bash case (unreachable): {sorted(arms - expected)}"
    )


def test_sandbox_case_maps_only_into_the_closed_vocab() -> None:
    """Every reason the #434A map can assign is a vocabulary member."""
    mapping = _parse_mapping_case("${_sandbox_err_key}", "_SANDBOX_REASON")
    unknown = frozenset(mapping.values()) - audit_row_schemas.SANDBOX_REFUSED_REASONS
    assert not unknown, (
        f"the #434A sandbox case maps to {sorted(unknown)}, absent from SANDBOX_REFUSED_REASONS."
    )


def test_sandbox_case_distinguishes_the_tamper_signals() -> None:
    """The named defect: manifest_unreadable / manifest_invalid are TAMPER signals and must NOT
    collapse into the benign sandbox_block_missing (#434A). Mutation-resistant: asserts the
    three map to three DISTINCT reasons, so re-pointing any one at another fails."""
    mapping = _parse_mapping_case("${_sandbox_err_key}", "_SANDBOX_REASON")
    tamper = {
        mapping["plugin.manifest_unreadable"],
        mapping["plugin.manifest_invalid"],
        mapping["plugin.manifest_sandbox_block_missing"],
    }
    assert len(tamper) == 3, (
        f"the tamper signals collapsed into {sorted(tamper)} — #434A's exact defect."
    )
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -k "sandbox_case" -v`
Expected: FAIL — `bash case header not found in the launcher: 'case "${_sandbox_err_key}" in'`

- [ ] **Step 3: Add the five vocabulary members**

In `src/alfred/audit/audit_row_schemas.py`, inside `SANDBOX_REFUSED_REASONS` (~L1225, after the `# Sandbox block / kind gating (launcher).` group), add:

```python
        # Manifest read refusals — the five distinct keys `manifest_reader
        # --read-sandbox` can emit (#434A). Before #434 a `2>/dev/null` discarded
        # all five and recorded every one as `sandbox_block_missing`, so a planted
        # or corrupt manifest read as "you forgot [sandbox]".
        "plugin_id_charset_invalid",
        "manifest_reader_no_source",
        "manifest_unreadable",
        "manifest_invalid",
        # The honest fallback for an UNCLASSIFIABLE helper stderr line (#434B).
        # Distinct from `policy_translate_failed`, which is a REAL malformed-TOML
        # refusal — conflating the drift/crash alarm with a routine policy-authoring
        # error hid the alarm.
        "reason_unclassified",
```

- [ ] **Step 4: Replace the `2>/dev/null` block in the launcher**

In `bin/alfred-plugin-launcher.sh`, replace lines 273-277 (the `if ! SANDBOX_JSON=...` block) with:

```bash
# #434A: capture the helper's stderr instead of discarding it. `_read_sandbox`
# can fail with FIVE distinct bare i18n keys; `2>/dev/null` collapsed all five
# into the benign `sandbox_block_missing`, so `manifest_unreadable` /
# `manifest_invalid` — a planted-manifest TAMPER signal — were recorded as "you
# forgot [sandbox]". Mirrors the environment path above (L155-171), which has
# implemented this capture-and-map correctly since PR #229.
_SANDBOX_ERR_FILE="$(mktemp "${TMPDIR:-/tmp}/alfred-launcher-sandbox-err.XXXXXX")"
if ! SANDBOX_JSON="$(_read_sandbox 2>"${_SANDBOX_ERR_FILE}")"; then
    _sandbox_err_key="$(tail -n 1 "${_SANDBOX_ERR_FILE}" 2>/dev/null || true)"
    rm -f "${_SANDBOX_ERR_FILE}"
    # Each arm assigns BOTH the audit reason and the operator key it re-prints.
    # The operator key is echoed VERBATIM (never synthesised from the reason) so
    # no new i18n key is needed — the `plugin.*` keys are already registered in
    # _sandbox_i18n.py, and a `t(message_key=var)` indirection would make them
    # pybabel-invisible. Closed vocab: audit_row_schemas.SANDBOX_REFUSED_REASONS;
    # bound by test_sandbox_reason_vocab_sync.py (#432).
    case "${_sandbox_err_key}" in
        plugin.launcher_plugin_id_invalid) _SANDBOX_REASON="plugin_id_charset_invalid" ;;
        plugin.manifest_reader_no_source) _SANDBOX_REASON="manifest_reader_no_source" ;;
        plugin.manifest_unreadable) _SANDBOX_REASON="manifest_unreadable" ;;
        plugin.manifest_sandbox_block_missing) _SANDBOX_REASON="sandbox_block_missing" ;;
        plugin.manifest_invalid) _SANDBOX_REASON="manifest_invalid" ;;
        *)
            # An empty or unrecognised capture is a drift/crash ALARM, not a
            # routine refusal — say so rather than guessing a specific reason
            # (fail-closed: we still refuse).
            _SANDBOX_REASON="reason_unclassified"
            _sandbox_err_key="supervisor.sandbox.refused.reason_unclassified"
            ;;
    esac
    printf '%s plugin_id=%s\n' "${_sandbox_err_key}" "${PLUGIN_ID}" >&2
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"%s","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${_SANDBOX_REASON}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
    exit 1
fi
rm -f "${_SANDBOX_ERR_FILE}"
```

Note the `rm -f` on **both** arms — the failure arm removes it before the `case`, the success arm after the `fi`. This mirrors L163/L172.

- [ ] **Step 5: Add the one new i18n key**

In `src/alfred/plugins/_sandbox_i18n.py`, inside `_SANDBOX_VISIBLE_KEYS` (after the `policy_translate_failed` entry ~L63):

```python
    # #434B: the honest fallback when the helper's stderr line is unclassifiable
    # (a traceback, an ImportError, a new unbound reason). Distinct from
    # policy_translate_failed so a drift/crash ALARM is forensically separable
    # from a routine malformed-TOML refusal.
    "supervisor.sandbox.refused.reason_unclassified": t(
        "supervisor.sandbox.refused.reason_unclassified"
    ),
```

- [ ] **Step 6: Update the vocab count pins**

In `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`:

- L52 docstring: `of 26` → `of 31`
- L56: `assert len(reasons) == 26, f"expected 26 reasons, got ...` → `== 31` / `expected 31 reasons`
- L402: `>= 25` → `>= 30`

In `src/alfred/audit/audit_row_schemas.py` L1204-1205, the prose count: `Twenty-one reasons are launcher-emittable. Five are RESERVED` → `Twenty-six reasons are launcher-emittable. Five are RESERVED`.

- [ ] **Step 7: Teach the emittable resolver about `_SANDBOX_REASON`**

In `_launcher_emittable_reasons` (~L291), add the sandbox mapping to the derived sets:

```python
    schema_first, schema_fallback = _parse_case("${_CAPTURED_REASON}")
    env_first, env_fallback = _parse_case("${_env_err_key}")
    sandbox_map = _parse_mapping_case("${_sandbox_err_key}", "_SANDBOX_REASON")
    sandbox_set = set(sandbox_map.values())
```

…and add the resolver branch, BEFORE the `else` (~L327). `_SANDBOX_REASON` does not contain `_AUDIT_REASON` as a substring, so branch order is safe, but keep it adjacent for readability:

```python
        elif "_SANDBOX_REASON" in line:
            emittable |= sandbox_set
```

- [ ] **Step 8: Run the binding tests to verify they pass**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -v`
Expected: PASS (all tests, including `test_frozenset_is_exactly_emittable_plus_reserved`)

If `test_frozenset_is_exactly_emittable_plus_reserved` fails with `orphan`, a new reason is in the vocab but no emit path produces it — re-check Step 4's case arms.

- [ ] **Step 9: Write the behavioural tests**

Add to `tests/unit/launcher/test_launcher_sandbox_flow.py`. Uses the existing `run_launcher` fixture and `_write_manifest` helper:

```python
_INVALID_TOML_MANIFEST = """[alfred]
manifest_version = 1
[plugin
id = "alfred.example"
"""


@_requires_jq
def test_unreadable_manifest_refused_as_manifest_unreadable(run_launcher, tmp_path) -> None:
    """#434A: an unreadable manifest is a TAMPER signal — it must NOT be recorded as the
    benign sandbox_block_missing."""
    missing = tmp_path / "definitely-absent.toml"
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "development",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(missing),
        },
    )
    assert result.returncode == 1
    row = _refusal_row(result.stderr)
    assert row["reason"] == "manifest_unreadable"
    assert row["plugin_id"] == "alfred.example"


@_requires_jq
def test_invalid_manifest_refused_as_manifest_invalid(run_launcher, tmp_path) -> None:
    """#434A: malformed TOML is a TAMPER signal, distinct from a missing [sandbox] block."""
    manifest = _write_manifest(tmp_path, _INVALID_TOML_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "development",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode == 1
    row = _refusal_row(result.stderr)
    assert row["reason"] == "manifest_invalid"


@_requires_jq
def test_missing_sandbox_block_still_refused_as_sandbox_block_missing(
    run_launcher, tmp_path
) -> None:
    """#434A must not REGRESS the one reason that was previously correct."""
    manifest = _write_manifest(tmp_path, _NO_SANDBOX_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "development",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode == 1
    row = _refusal_row(result.stderr)
    assert row["reason"] == "sandbox_block_missing"
```

Add this module-level helper near the top of the file (after the manifest constants), since Tasks 3 and 4 reuse it:

```python
def _refusal_row(stderr: str) -> dict[str, str]:
    """The single parsed supervisor.plugin.sandbox_refused JSON row on stderr.

    Asserts EXACTLY one — two rows for one refusal would double-count in the audit
    stream, and zero is the #435 defect.
    """
    import json

    lines = [
        line
        for line in stderr.splitlines()
        if '"event":"supervisor.plugin.sandbox_refused"' in line
    ]
    assert len(lines) == 1, f"expected exactly 1 sandbox_refused row, got {len(lines)}: {lines}"
    return json.loads(lines[0])
```

- [ ] **Step 10: Run the behavioural tests**

Run: `uv run pytest tests/unit/launcher/test_launcher_sandbox_flow.py -v`
Expected: PASS. If `_NO_SANDBOX_MANIFEST` or `_stub_binary` is not defined in the file, grep for the actual names (`grep -n '_NO_SANDBOX_MANIFEST\|def _stub_binary\|def _write_manifest' tests/unit/launcher/test_launcher_sandbox_flow.py`) and use those — do not invent new fixtures.

- [ ] **Step 11: Lint + type check**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/`
Expected: all clean.

- [ ] **Step 12: Shellcheck the launcher**

Run: `shellcheck bin/alfred-plugin-launcher.sh` (skip if not installed — the pre-commit hook runs it)
Expected: no new warnings versus `git stash && shellcheck ... && git stash pop`.

---

## Task 2: #434B — separate the drift alarm from the real refusal

**Files:**

- Modify: `bin/alfred-plugin-launcher.sh:328-337`
- Modify: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`

**Interfaces:**

- Consumes: `reason_unclassified` (added to the vocab in Task 1, Step 3).
- Consumes: `_parse_case("${_CAPTURED_REASON}")` (existing).

**Commits:** this task ends commit 1 (both #434 parts together).

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`:

```python
def test_schema_case_fallback_is_the_unclassified_alarm() -> None:
    """#434B: the schema `*)` arm is the drift/crash ALARM (a traceback, an ImportError, a
    new unbound reason). It must NOT reuse `policy_translate_failed`, which is ALSO a real
    malformed-TOML refusal — that conflation made the alarm read as a routine
    policy-authoring error and hid it.
    """
    _, schema_fallback = _parse_case("${_CAPTURED_REASON}")
    assert schema_fallback == "reason_unclassified", (
        f"the schema case `*)` fallback is {schema_fallback!r}; #434B requires the distinct "
        f"`reason_unclassified` so the alarm is forensically separable from the real refusal."
    )
    assert "policy_translate_failed" in _parse_case("${_CAPTURED_REASON}")[0], (
        "policy_translate_failed must REMAIN in the allow-list — it is a real "
        "SandboxPolicyInvalid reason for malformed TOML, not only the old fallback."
    )
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -k fallback_is_the_unclassified -v`
Expected: FAIL — `the schema case *) fallback is 'policy_translate_failed'`

- [ ] **Step 3: Change the `*)` arm**

In `bin/alfred-plugin-launcher.sh`, replace the `*)` arm at L331-336:

```bash
                        *)
                            # #434B: an unclassifiable last line is a drift/crash ALARM — a
                            # traceback, an ImportError, or a schema reason added to Python
                            # without touching this case. Record it as such. Reusing
                            # `policy_translate_failed` (which is ALSO the real reason for
                            # malformed TOML) made the alarm indistinguishable from a routine
                            # policy-authoring error, so nobody ever looked at it.
                            _AUDIT_REASON="reason_unclassified" ;;
```

- [ ] **Step 4: Make the operator stderr key reason-accurate**

The unconditional key at L317 says `policy_translate_failed` even when the reason is now something else. Replace L317:

```bash
                    printf 'supervisor.sandbox.refused.policy_translate_failed plugin_id=%s detail=%s\n' "${PLUGIN_ID}" "${BWRAP_FLAGS_RAW}" >&2
```

with a line emitted AFTER the `case` resolves `_AUDIT_REASON`, so the operator key matches the recorded reason. Move it to sit directly above the JSON printf at L338:

```bash
                    printf 'supervisor.sandbox.refused.%s plugin_id=%s detail=%s\n' "${_AUDIT_REASON}" "${PLUGIN_ID}" "${BWRAP_FLAGS_RAW}" >&2
```

**i18n note:** every value `_AUDIT_REASON` can take already has a registered `supervisor.sandbox.refused.*` key — the schema-case allow-list members are registered in `_sandbox_i18n.py`, and `reason_unclassified` was added in Task 1 Step 5. Verify with Step 6 below rather than assuming.

- [ ] **Step 5: Run the binding tests**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -v`
Expected: PASS

- [ ] **Step 6: Prove every schema-case reason has an i18n key**

Add to `tests/unit/plugins/test_sandbox_i18n_keys.py`:

```python
def test_every_schema_case_reason_has_a_registered_operator_key() -> None:
    """#434B made the operator stderr key interpolate ${_AUDIT_REASON}. Every value it can
    take must therefore have a registered `supervisor.sandbox.refused.*` catalog key, or the
    supervisor renders a raw msgid at the operator. This binding is what makes the
    interpolation safe.
    """
    from tests.unit.plugins.test_sandbox_reason_vocab_sync import _parse_case

    from alfred.plugins._sandbox_i18n import _SANDBOX_VISIBLE_KEYS

    first_arm, fallback = _parse_case("${_CAPTURED_REASON}")
    reasons = set(first_arm) | {fallback}
    missing = {
        reason
        for reason in reasons
        if f"supervisor.sandbox.refused.{reason}" not in _SANDBOX_VISIBLE_KEYS
    }
    assert not missing, (
        f"the launcher can print supervisor.sandbox.refused.{{{sorted(missing)}}} but those keys "
        f"are not registered in _sandbox_i18n.py — the supervisor would render a raw msgid."
    )
```

Run: `uv run pytest tests/unit/plugins/test_sandbox_i18n_keys.py -v`

If this FAILS, register the missing keys in `_sandbox_i18n.py` — do **not** weaken the test. This is the point of the task.

- [ ] **Step 7: Run the full i18n gate**

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update --no-fuzzy-matching -i /tmp/alfred.pot -d src/alfred/i18n/locale
uv run pybabel compile -d src/alfred/i18n/locale
```

Expected: no errors; `git diff --stat src/alfred/i18n/locale` shows only the new key(s).

- [ ] **Step 8: Full local gates**

Run: `make check; echo "EXIT=$?"`
Expected: `EXIT=0`. (Do not pipe to `tail` — it masks the exit code.)

If the macOS integration lane throws mass testcontainers setup errors, that is the known under-load flake — re-run the suspect file in isolation before believing a regression.

- [ ] **Step 9: Commit 1**

```bash
git add bin/alfred-plugin-launcher.sh \
        src/alfred/audit/audit_row_schemas.py \
        src/alfred/plugins/_sandbox_i18n.py \
        src/alfred/i18n/locale \
        tests/unit/plugins/test_sandbox_reason_vocab_sync.py \
        tests/unit/plugins/test_sandbox_i18n_keys.py \
        tests/unit/launcher/test_launcher_sandbox_flow.py
git commit -m "fix(sandbox): #434 record each launcher refusal under its true reason

Part A: the manifest read ran under 2>/dev/null and recorded all five
distinct manifest_reader refusal keys as sandbox_block_missing, so
manifest_unreadable and manifest_invalid — a planted-manifest tamper
signal — read as the benign 'you forgot [sandbox]'. Capture and map the
key instead, mirroring the environment path that has done this correctly
since PR #229. The operator key is re-printed verbatim, so no new i18n
key is needed for the five.

Part B: policy_translate_failed was simultaneously a real malformed-TOML
reason AND the schema case *) fallback — the drift/crash alarm that fires
on a traceback or a reason added to Python without touching bash. The
alarm read as a routine policy-authoring error, so nobody looked at it.
Give it a distinct reason_unclassified, and make the operator stderr key
track the resolved reason rather than hardcoding policy_translate_failed.

The #432 binding gains _parse_mapping_case (the two-arm _parse_case
cannot parse an N-arm key->reason map) and an i18n binding proving every
value the interpolated operator key can take is a registered catalog key.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: #435 — rows for the four row-less `exit 1` paths

**Files:**

- Modify: `bin/alfred-plugin-launcher.sh` (L123-128, L230-236, L281-284, L435-438)
- Modify: `src/alfred/audit/audit_row_schemas.py`
- Modify: `src/alfred/plugins/_sandbox_i18n.py`
- Modify: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`
- Test: `tests/unit/launcher/test_launcher_sandbox_flow.py`, `tests/unit/audit/test_launcher_refusal.py`

**Interfaces:**

- Consumes: `_refusal_row(stderr)` helper (Task 1, Step 9).
- Produces: vocab members `runuser_unavailable`, `jq_unavailable`, `macos_full_not_yet_shipped`, `sandbox_kind_unrecognised`.

**D2 — the tainted `plugin_id` (load-bearing).** The charset gate at L123-128 exists *precisely* so a malformed id never reaches a printf JSON template (audit-stream integrity, CR on PR #140). The row therefore carries the launcher-authored constant `<invalid>`, **never** the real id. `<` and `>` are outside the plugin-id charset, so it cannot collide with a real id. Do NOT interpolate `${PLUGIN_ID}` into this row — doing so IS the injection.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/launcher/test_launcher_sandbox_flow.py`:

```python
@_requires_jq
def test_invalid_plugin_id_emits_a_row_without_echoing_the_id(run_launcher, tmp_path) -> None:
    """#435 + D2: a malformed plugin_id must produce an audit row (today it produces NONE, so
    a probe leaves no trail) — but the row must carry the `<invalid>` sentinel, never the
    tainted bytes. Echoing them into the JSON template WOULD BE the injection (#437's lesson).
    """
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        'evil","event":"forged',
        str(stub),
        env={"ALFRED_ENVIRONMENT": "development"},
    )
    assert result.returncode == 1
    row = _refusal_row(result.stderr)
    assert row["reason"] == "plugin_id_charset_invalid"
    assert row["plugin_id"] == "<invalid>"
    assert row["environment"] == "unset"
    assert row["host_os"] == "unknown"
    assert "forged" not in result.stderr.replace("plugin.launcher_plugin_id_invalid", "")


```

**The unknown-kind `*)` arm has NO behavioural test, deliberately — do not try to write one.**
`manifest.py:98` declares `kind: Literal["full", "none", "stub"]`, so `parse_manifest` rejects any
other value and `_cmd_read_sandbox` fails with `plugin.manifest_invalid` — the launcher's
`*)` sandbox-kind arm is **unreachable from any valid manifest**. It fires only if the helper's
JSON ever lacks `.kind` (jq yields `null`) or carries a value outside the enum, i.e. on helper/jq
drift. It is a fail-closed default guarding a contract, not a live path.

Keep the arm and give it a row anyway: if it ever fires, an operator must get a record, and the
reason must not be the wrong one. Bind it via the AST guard instead — add to
`tests/unit/plugins/test_sandbox_reason_vocab_sync.py`:

```python
def _kind_case_fallback_arm() -> str:
    """The body of the launcher's sandbox-kind ``*)`` arm.

    NOT reusable via ``_parse_mapping_case``: that helper requires EVERY arm to assign the named
    variable, and this case's ``full)`` / ``none)`` / ``stub)`` arms do the real launcher work
    instead. Parse just the fallback arm.
    """
    text = _launcher_text()
    header = 'case "${SANDBOX_KIND}" in'
    idx = text.find(header)
    assert idx != -1, f"bash case header not found in the launcher: {header!r}"
    body = text[idx + len(header) :]
    # The kind case is the launcher's LAST case and its arms nest further cases, so anchor the
    # fallback on the `*)` arm marker rather than the first `esac`.
    marker = "\n    *)"
    arm_idx = body.find(marker)
    assert arm_idx != -1, "the sandbox-kind case has no `*)` fallback arm — it must fail closed"
    return body[arm_idx:]


def test_sandbox_kind_fallback_is_not_mislabelled_as_block_missing() -> None:
    """#435 / #434-class: the sandbox-kind `*)` arm recorded an unrecognised kind as
    `sandbox_block_missing` — a different condition ("no [sandbox] block") with a different fix.

    Text-bound rather than behavioural BY NECESSITY, and the limit is named here rather than left
    implicit: manifest.py declares `kind: Literal["full","none","stub"]`, so parse_manifest
    rejects anything else upstream and this arm is unreachable from a valid manifest. It is the
    fail-closed default against helper/jq drift. This guard proves WHICH reason the arm writes;
    it CANNOT prove the arm ever runs. No test can, short of stubbing the helper.
    """
    arm = _kind_case_fallback_arm()
    assert '"reason":"sandbox_kind_unrecognised"' in arm, (
        "the sandbox-kind `*)` fallback does not write sandbox_kind_unrecognised"
    )
    assert "sandbox_block_missing" not in arm, (
        "the sandbox-kind `*)` fallback still mislabels an unrecognised kind as "
        "sandbox_block_missing — #435's named defect."
    )
```

The `*)` arm's `reason` is a plain literal, so `_launcher_emittable_reasons` already resolves it
and `test_every_reason_the_launcher_can_emit_is_in_the_closed_vocab` already binds it to the
vocabulary — this test adds the *named* guard for the specific mislabel, belt-and-braces with
the ⊆ test. No launcher variable is needed; keep the literal inline.

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/launcher/test_launcher_sandbox_flow.py -k "invalid_plugin_id or unknown_sandbox_kind" -v`
Expected: FAIL — `expected exactly 1 sandbox_refused row, got 0`

- [ ] **Step 3: Add the four vocabulary members**

In `src/alfred/audit/audit_row_schemas.py`, `SANDBOX_REFUSED_REASONS`:

```python
        # Host tooling missing (launcher). Distinct from `uid_separation_unavailable`,
        # which means the HOST OS has no UID-drop mechanism at all: `runuser_unavailable`
        # is a Linux host that supports UID-drop but lacks util-linux. Different
        # remediation, so a different reason (#435 / D6).
        "runuser_unavailable",
        "jq_unavailable",
        # kind:full on macOS is not yet shipped (PR-S4-7 lands sandbox-exec).
        "macos_full_not_yet_shipped",
        # The sandbox-kind `*)` arm: a kind outside {full,none,stub}. Previously
        # mislabelled `sandbox_block_missing` — a #434-class conflation (#435).
        "sandbox_kind_unrecognised",
```

- [ ] **Step 4: Add the two new i18n keys**

In `src/alfred/plugins/_sandbox_i18n.py`, `_SANDBOX_VISIBLE_KEYS`:

```python
    # #435: previously refused with no audit row at all.
    "supervisor.sandbox.refused.sandbox_kind_unrecognised": t(
        "supervisor.sandbox.refused.sandbox_kind_unrecognised"
    ),
```

`jq_unavailable` and `macos_full_not_yet_shipped` are **already registered** (L57-60) — the operator keys existed, only the vocab members and rows were missing. `runuser_unavailable` reuses the existing `plugin.launcher_uid_drop_unavailable` operator key (`_launcher_i18n.py:42`), so it needs no new key. Do not add duplicates.

- [ ] **Step 5: Add the four rows in the launcher**

**L126** — the charset gate. Replace lines 123-128:

```bash
case "${PLUGIN_ID}" in
    *[!A-Za-z0-9._-]* | "")
        printf 'plugin.launcher_plugin_id_invalid\n' >&2
        # #435: emit a row so a malformed-id PROBE leaves an audit trail (it left
        # none before). D2: the row carries the launcher-authored `<invalid>`
        # sentinel, NEVER ${PLUGIN_ID} — interpolating the tainted bytes into this
        # template is exactly the injection the gate above exists to prevent (CR on
        # PR #140), and `<`/`>` are outside the id charset so it cannot collide with
        # a real id. environment/host_os are not resolved yet at this point, so they
        # carry the same unset/unknown markers as the environment-failure row below.
        printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"<invalid>","reason":"plugin_id_charset_invalid","environment":"unset","host_os":"unknown"}\n' >&2
        exit 1
        ;;
esac
```

**L234** — runuser missing. Inside `_do_exec`, replace lines 232-235:

```bash
        if ! command -v runuser >/dev/null 2>&1; then
            printf 'plugin.launcher_uid_drop_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
            # #435 / D6: a Linux host that SUPPORTS UID-drop but lacks util-linux —
            # distinct from uid_separation_unavailable (an OS with no mechanism at
            # all), because the remediation differs.
            printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"runuser_unavailable","environment":"%s","host_os":"linux"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
            exit 1
        fi
```

**L283** — jq missing. Replace lines 281-284:

```bash
if ! command -v jq >/dev/null 2>&1; then
    printf 'supervisor.sandbox.refused.jq_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"jq_unavailable","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
    exit 1
fi
```

**L402** — macOS kind:full. Replace lines 398-403:

```bash
            macos)
                # PR-S4-7 ships the sandbox-exec invocation; until then refuse so
                # the resolver path is well-defined on macOS.
                printf 'supervisor.sandbox.refused.macos_full_not_yet_shipped plugin_id=%s\n' "${PLUGIN_ID}" >&2
                printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","policy_ref":"%s","reason":"macos_full_not_yet_shipped","environment":"%s","host_os":"macos"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
                exit 1
                ;;
```

`POLICY_REF` is resolved and charset-validated (#437) by this point, so including it is safe and useful.

**L437** — the sandbox-kind `*)` arm. Replace lines 435-438:

```bash
    *)
        # #435: a kind outside {full,none,stub} — jq yielded null or an unknown
        # value. Previously recorded as sandbox_block_missing, which is a different
        # condition ("no [sandbox] block") with a different fix. Fail-closed default.
        printf 'supervisor.sandbox.refused.sandbox_kind_unrecognised plugin_id=%s\n' "${PLUGIN_ID}" >&2
        printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"sandbox_kind_unrecognised","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
        exit 1
        ;;
```

- [ ] **Step 6: Update the pins**

`tests/unit/plugins/test_sandbox_reason_vocab_sync.py`:

- L52 docstring `of 31` → `of 35`; L56 `== 31` → `== 35` (and the message)
- L400 `>= 20` → `>= 30`
- L402 `>= 30` → `>= 34`
- L334 `>= 11` → `>= 17` (five new emit lines: L126, L234, L283, L402, L437 — bwrap lands in Task 4)

`src/alfred/audit/audit_row_schemas.py` prose: `Twenty-six reasons are launcher-emittable` → `Thirty reasons are launcher-emittable`.

**These numbers are derived, not decreed.** If a pin fails, print the actual and reconcile — do not force the assertion to match without understanding why.

- [ ] **Step 7: Add parser round-trip coverage**

Add to `tests/unit/audit/test_launcher_refusal.py`:

```python
def test_every_vocab_reason_round_trips() -> None:
    """Every member of the closed vocab must survive the parser — a reason the launcher can
    write but the parser drops is a silently-lost audit row.
    """
    from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_REASONS

    for reason in sorted(SANDBOX_REFUSED_REASONS):
        line = json.dumps(
            {
                "event": "supervisor.plugin.sandbox_refused",
                "plugin_id": "alfred.example",
                "reason": reason,
                "environment": "production",
                "host_os": "linux",
            }
        )
        rows = parse_launcher_refusal_rows(line.encode() + b"\n")
        assert len(rows) == 1, f"the parser dropped the vocab reason {reason!r}"
        assert rows[0].reason == reason


def test_the_invalid_sentinel_row_parses() -> None:
    """D2: the charset-refusal row carries the `<invalid>` sentinel. It must parse — the
    parser charset-checks nothing, only Cc/Cf, so the sentinel is accepted as a plain str.
    """
    line = json.dumps(
        {
            "event": "supervisor.plugin.sandbox_refused",
            "plugin_id": "<invalid>",
            "reason": "plugin_id_charset_invalid",
            "environment": "unset",
            "host_os": "unknown",
        }
    )
    rows = parse_launcher_refusal_rows(line.encode() + b"\n")
    assert len(rows) == 1
    assert rows[0].plugin_id == "<invalid>"


def test_parser_optional_fields_not_widened() -> None:
    """D2 depends on the parser staying strict: plugin_id must NOT become optional. A row
    omitting it must still be dropped loudly, not canonicalized to "".
    """
    from alfred.audit.launcher_refusal import _OPTIONAL_FIELDS

    assert _OPTIONAL_FIELDS == frozenset({"policy_ref"}), (
        "widening _OPTIONAL_FIELDS weakens every row on the most adversary-facing surface "
        "in the system — D2 chose the <invalid> sentinel precisely to avoid this."
    )
```

- [ ] **Step 8: Run everything**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py tests/unit/launcher/ tests/unit/audit/test_launcher_refusal.py -v`
Expected: PASS

---

## Task 4: #435 — wire the reserved `bwrap_unavailable`

**Files:**

- Modify: `bin/alfred-plugin-launcher.sh` (before the `exec` at ~L393)
- Modify: `src/alfred/audit/audit_row_schemas.py`
- Modify: `src/alfred/plugins/_sandbox_i18n.py`
- Modify: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py:40-48` (`_RESERVED_UNEMITTED`)
- Test: `tests/unit/launcher/test_launcher_sandbox_flow.py`

**Interfaces:**

- Consumes: `_refusal_row(stderr)` (Task 1), `bwrap_unavailable` (already a vocab member — **do not re-add it**).

**Why this exists (D5):** the launcher checks `command -v jq` and refuses, but never checks bwrap — it just `exec`s it. A missing bwrap means exec fails, `set -e` aborts, bash prints its own 127 error, and no row is written. `bwrap_unavailable` already sits in the vocab as *reserved, no emitter*. This moves it reserved → emittable.

**Commits:** this task ends commit 2 (all of #435).

- [ ] **Step 1: Write the failing test**

```python
@_requires_jq
def test_missing_bwrap_refuses_with_a_row(run_launcher, tmp_path) -> None:
    """#435 / D5: a missing bwrap made exec fail at 127 with NO audit row. Refuse explicitly.

    Drives it via BWRAP= pointing at a path that does not exist, which is the same condition
    `command -v` reports for an uninstalled bwrap.
    """
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "development",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "BWRAP": str(tmp_path / "definitely-not-bwrap"),
            "FAKE_UNAME": "Linux",
        },
    )
    assert result.returncode == 1
    row = _refusal_row(result.stderr)
    assert row["reason"] == "bwrap_unavailable"
    assert row["host_os"] == "linux"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/launcher/test_launcher_sandbox_flow.py -k missing_bwrap -v`
Expected: FAIL — non-1 returncode (127 from the failed exec) and 0 rows.

- [ ] **Step 3: Move `bwrap_unavailable` out of the reserved set**

In `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`, delete this line from `_RESERVED_UNEMITTED` (L43):

```python
        "bwrap_unavailable",  # documented; no code path emits it
```

Update the docstring above it (L37-39): `The five vocabulary reasons` → `The four vocabulary reasons`.
Update L401: `assert len(_RESERVED_UNEMITTED) == 5` → `== 4`.

In `src/alfred/audit/audit_row_schemas.py`, move `"bwrap_unavailable"` out of the `# Reserved — no launcher emitter` group into the launcher-emittable groups, with a comment:

```python
        # Host tooling missing (launcher) — #435 wired this; it was reserved-with-no-emitter
        # while a missing bwrap merely made the exec fail at 127 with no audit row at all.
        "bwrap_unavailable",
```

Update the prose at L1204-1212: `Thirty reasons are launcher-emittable. Five are RESERVED` → `Thirty-one reasons are launcher-emittable. Four are RESERVED`, and delete `bwrap_unavailable` from the reserved bullet list.

- [ ] **Step 4: Add the i18n key**

```python
    # #435: a missing bwrap previously failed the exec at 127 with no row.
    "supervisor.sandbox.refused.bwrap_unavailable": t(
        "supervisor.sandbox.refused.bwrap_unavailable"
    ),
```

- [ ] **Step 5: Add the check in the launcher**

In `bin/alfred-plugin-launcher.sh`, immediately BEFORE the `exec "${BWRAP}"` at ~L393 (after `EXTRA_BINDS` / `EXEC_TARGET` resolution, so the refusal cannot mask a bind error):

```bash
                # #435 / D5: refuse explicitly rather than letting `exec` fail at 127
                # with no audit row. Mirrors the jq check above. `command -v` honours
                # both a bare `bwrap` on PATH and a BWRAP= absolute-path override.
                if ! command -v "${BWRAP}" >/dev/null 2>&1; then
                    printf 'supervisor.sandbox.refused.bwrap_unavailable plugin_id=%s\n' "${PLUGIN_ID}" >&2
                    printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","policy_ref":"%s","reason":"bwrap_unavailable","environment":"%s","host_os":"linux"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
                    exit 1
                fi
                exec "${BWRAP}" \
```

- [ ] **Step 6: Update the emit-line floor**

`tests/unit/plugins/test_sandbox_reason_vocab_sync.py` L334: `>= 17` → `>= 18`.
L400 `>= 30` → `>= 31`.

- [ ] **Step 7: Run the tests**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py tests/unit/launcher/ -v`
Expected: PASS. `test_frozenset_is_exactly_emittable_plus_reserved` now proves `bwrap_unavailable` is genuinely emittable — if it reports it as an overlap, the launcher check is not being seen by the resolver.

- [ ] **Step 8: Full gates**

Run: `make check; echo "EXIT=$?"`
Expected: `EXIT=0`

- [ ] **Step 9: Adversarial suite (the launcher is a security boundary)**

Run: `uv run pytest tests/adversarial -q`
Expected: all pass.

- [ ] **Step 10: Commit 2**

```bash
git add bin/alfred-plugin-launcher.sh \
        src/alfred/audit/audit_row_schemas.py \
        src/alfred/plugins/_sandbox_i18n.py \
        src/alfred/i18n/locale \
        tests/unit/plugins/test_sandbox_reason_vocab_sync.py \
        tests/unit/launcher/test_launcher_sandbox_flow.py \
        tests/unit/audit/test_launcher_refusal.py
git commit -m "fix(sandbox): #435 emit an audit row on every launcher refusal path

Six refusal paths exited without emitting any sandbox_refused row, so an
operator got a sandbox refusal with nothing in the audit stream. The issue
named four at stale line numbers; at HEAD there are six.

  charset gate      -> plugin_id_charset_invalid
  runuser missing   -> runuser_unavailable (new: a Linux host that supports
                       UID-drop but lacks util-linux is not the same condition
                       as an OS with no mechanism at all)
  jq missing        -> jq_unavailable
  bwrap missing     -> bwrap_unavailable (was reserved-with-no-emitter; a
                       missing bwrap merely failed the exec at 127)
  macOS kind:full   -> macos_full_not_yet_shipped
  unknown kind      -> sandbox_kind_unrecognised (was mislabelled
                       sandbox_block_missing — a #434-class conflation)

The charset row carries the launcher-authored '<invalid>' sentinel, never
the tainted id: the gate exists precisely so a malformed id never reaches a
printf JSON template (CR on PR #140), and echoing it would BE the injection
(#437's lesson). The parser stays strict — plugin_id is deliberately NOT
added to _OPTIONAL_FIELDS, and a test pins that.

jq_unavailable and macos_full_not_yet_shipped already had registered i18n
keys but no vocab member and no row — the drift in miniature.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: #436 — declare the stub row's reason under a closed vocabulary

**Files:**

- Modify: `bin/alfred-plugin-launcher.sh` (L412, L432)
- Modify: `src/alfred/audit/audit_row_schemas.py:1264-1274`
- Modify: `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`
- Test: `tests/unit/plugins/test_plugin_launcher_stub.py`, `tests/unit/audit/test_slice_4_audit_row_fields.py`

**Interfaces:**

- Consumes: `_parse_mapping_case` (Task 1).
- Produces: `SANDBOX_STUB_USED_REASONS: Final[frozenset[str]]`.

**D3/D4 — read before implementing.** `reason` at L248 is INTENDED (the launcher's own comment at L245-247 says the row is auditable *"under the same closed vocabulary as the other stub paths"* — the author believed L412/L432 already had one; they do not). **L248 is correct; L412 and L432 are the defect.**

**This task declares. It must NOT persist.** A `sandbox_stub_used` row asserts *"I am about to exec"*, so a live child shares that stderr with no delimiter — "launcher-authored" is not establishable in-band. The #446 gate (`refusal_candidate and not self._child_wrote_stdout`) is an *inverted oracle* for it: an honest child writes stdout and closes the gate (discarding the true row), while a forging child writes zero stdout and opens it. Do not touch `launcher_refusal.py`, `sandbox_refusal_audit.py`, or `quarantine_child_io.py` in this task.

**Commits:** this task ends commit 3.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/plugins/test_sandbox_reason_vocab_sync.py`:

```python
_SANDBOX_STUB_USED_EVENT = "supervisor.plugin.sandbox_stub_used"


def _stub_used_emit_lines() -> list[str]:
    """Every printf line carrying the stub_used event — keyed on the event NAME, not the
    compact JSON byte-string, so a future line that reformats its JSON cannot slip the count
    (#432's own silent-under-count lesson)."""
    return [
        line
        for line in _launcher_text().splitlines()
        if "printf" in line and _SANDBOX_STUB_USED_EVENT in line
    ]


def test_every_stub_used_reason_is_in_the_closed_vocab() -> None:
    """#436: the stub row's `reason` was undeclared — live field-vocabulary drift of exactly
    the class #432 closes for the sandbox_refused sibling. Bind it."""
    lines = _stub_used_emit_lines()
    assert len(lines) == 3, f"vacuity floor: expected 3 stub_used emit lines, got {len(lines)}"
    reasons: set[str] = set()
    missing_reason: list[str] = []
    for line in lines:
        match = re.search(r'"reason":\s*"([^"]*)"', line)
        if match is None:
            missing_reason.append(line.strip()[:90])
        else:
            reasons.add(match.group(1))
    assert not missing_reason, (
        "sandbox_stub_used printf line(s) with no `reason` field — #436 makes it MANDATORY on "
        "all three sites, because without it two structurally different launcher decisions "
        "collapse to a byte-identical row on macOS:\n" + "\n".join(missing_reason)
    )
    unknown = reasons - audit_row_schemas.SANDBOX_STUB_USED_REASONS
    assert not unknown, (
        f"the launcher writes {sorted(unknown)} into a {_SANDBOX_STUB_USED_EVENT} row, absent "
        f"from SANDBOX_STUB_USED_REASONS (a CLOSED vocabulary)."
    )


def test_stub_used_vocab_is_exactly_what_the_launcher_emits() -> None:
    """Equality, so an ORPHAN (declared, emitted by nothing) is caught too — #432's arch-001."""
    emitted = {
        match.group(1)
        for line in _stub_used_emit_lines()
        if (match := re.search(r'"reason":\s*"([^"]*)"', line))
    }
    assert emitted == audit_row_schemas.SANDBOX_STUB_USED_REASONS, (
        "SANDBOX_STUB_USED_REASONS is not exactly what the launcher emits.\n"
        f"  orphan (declared, never emitted): "
        f"{sorted(audit_row_schemas.SANDBOX_STUB_USED_REASONS - emitted)}\n"
        f"  missing (emitted, not declared): "
        f"{sorted(emitted - audit_row_schemas.SANDBOX_STUB_USED_REASONS)}"
    )


def test_stub_and_refused_vocabs_are_deliberately_not_disjoint() -> None:
    """D7: `uid_separation_unavailable` is a member of BOTH vocabularies, and that is correct
    — `reason` names the CAUSE, `event` names the disposition (refused vs proceeded anyway),
    `environment` names why they differ. This test exists so a future reviewer cannot
    'tidy' the overlap away without confronting the decision.
    """
    shared = (
        audit_row_schemas.SANDBOX_STUB_USED_REASONS & audit_row_schemas.SANDBOX_REFUSED_REASONS
    )
    assert shared == {"uid_separation_unavailable"}, (
        f"the vocab overlap changed to {sorted(shared)}. The two families share exactly one "
        f"cause; see D7 in the design spec before altering this."
    )
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -k stub_used -v`
Expected: FAIL — `AttributeError: module 'alfred.audit.audit_row_schemas' has no attribute 'SANDBOX_STUB_USED_REASONS'`

- [ ] **Step 3: Add the vocabulary + fix the false docstring**

In `src/alfred/audit/audit_row_schemas.py`, replace the `SANDBOX_STUB_USED_FIELDS` block (L1264-1274) entirely:

```python
# Emitted immediately BEFORE an exec that runs a plugin WITHOUT OS-level
# isolation. Three producers, all in bin/alfred-plugin-launcher.sh — the prior
# comment named only the third and was therefore false for two of them, which
# is how #436's field drift went unnoticed:
#   * kind:none on a non-Linux host (no UID-drop mechanism) -> uid_separation_unavailable
#   * kind:full on windows (resolves to a stub policy)      -> windows_stub
#   * a kind:stub manifest                                  -> stub_kind
# ``environment`` ∈ {"development", "test"} only — production refuses all three
# branches with a ``sandbox_refused`` row instead (PR-S4-6 sec-2 closure).
#
# ``policy_ref`` is OPTIONAL: only the windows kind:full producer resolves one.
# Absent -> canonicalize to "" at the parse boundary, exactly as the
# ``sandbox_refused`` sibling does (``launcher_refusal._OPTIONAL_FIELDS``).
#
# NOT PERSISTED, DELIBERATELY (#436 / ADR-0051). This row asserts "I am about to
# exec", so a live child shares the launcher's stderr with no delimiter — unlike
# ``sandbox_refused``, whose safety rests on the launcher exiting PRE-exec so no
# child exists. The #433/#446 drain gate (``refusal_candidate and not
# _child_wrote_stdout``) is an INVERTED oracle here: an honest child writes stdout
# and closes the gate (dropping the true row), while a forging child writes zero
# stdout and opens it — it would admit approximately only FORGERIES. Persisting
# this row needs a success-path stderr drain with an out-of-band provenance
# signal: a new interception point and its own ADR. Declaring the schema is NOT
# an invitation to wire it to the existing path.
SANDBOX_STUB_USED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "plugin_id",
        "policy_ref",
        "host_os",
        "environment",
        "reason",
    }
)

# Closed vocabulary for SANDBOX_STUB_USED_FIELDS['reason'] (#436). Each member is
# the dev-side twin of the ``sandbox_refused`` reason on the SAME launcher branch,
# stem-identical minus the ``_in_production`` suffix that no longer applies:
#
#   launcher branch            production -> sandbox_refused    dev/test -> stub_used
#   non-Linux, no UID-drop     uid_separation_unavailable       uid_separation_unavailable
#   windows kind:full          windows_stub_in_production       windows_stub
#   kind:stub manifest         stub_kind_in_production          stub_kind
#
# ``uid_separation_unavailable`` is deliberately SHARED with SANDBOX_REFUSED_REASONS:
# ``reason`` names the CAUSE, ``event`` names the disposition, ``environment`` names
# why the disposition differs. The two vocabularies are NOT disjoint by design.
SANDBOX_STUB_USED_REASONS: Final[frozenset[str]] = frozenset(
    {
        "uid_separation_unavailable",
        "windows_stub",
        "stub_kind",
    }
)
```

Add `"SANDBOX_STUB_USED_REASONS"` to `__all__` (near L1542, adjacent to `SANDBOX_STUB_USED_FIELDS`).

- [ ] **Step 4: Add `reason` to the two defective emit sites**

`bin/alfred-plugin-launcher.sh` L412 — the windows kind:full stub:

```bash
                printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","policy_ref":"%s","host_os":"windows","environment":"%s","reason":"windows_stub"}\n' "${PLUGIN_ID}" "${POLICY_REF}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
```

L432 — the kind:stub manifest:

```bash
        printf '{"event":"supervisor.plugin.sandbox_stub_used","plugin_id":"%s","host_os":"%s","environment":"%s","reason":"stub_kind"}\n' "${PLUGIN_ID}" "${HOST_OS}" "${ALFRED_RESOLVED_ENVIRONMENT}" >&2
```

L248 is already correct — **do not change it**.

- [ ] **Step 5: Run the binding tests**

Run: `uv run pytest tests/unit/plugins/test_sandbox_reason_vocab_sync.py -v`
Expected: PASS

- [ ] **Step 6: Add the field-set + behavioural tests**

`tests/unit/audit/test_slice_4_audit_row_fields.py`:

```python
def test_sandbox_stub_used_fields_declare_reason() -> None:
    """#436: the launcher wrote `reason` into this row but the constant never declared it."""
    assert "reason" in audit_row_schemas.SANDBOX_STUB_USED_FIELDS
    assert audit_row_schemas.SANDBOX_STUB_USED_FIELDS == frozenset(
        {"plugin_id", "policy_ref", "host_os", "environment", "reason"}
    )
```

`tests/unit/plugins/test_plugin_launcher_stub.py` — mirror the existing
`test_launcher_non_linux_dev_execs_with_stub_used_row` idiom (real subprocess, JSON-parsed row):

```python
def test_kind_stub_dev_row_carries_the_stub_kind_reason() -> None:
    """#436: without `reason` this row is byte-identical to the kind:none non-Linux row on
    macOS — two causes with OPPOSITE remediation ("you're on a Mac, ignore it" vs "this
    manifest declares kind:stub") collapsed into one indistinguishable record.
    """
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "development",
        "ALFRED_PLUGIN_MANIFEST_PATH": _write_stub_manifest(),
        "FAKE_UNAME": "Darwin",
    }
    env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "stub-kind-marker"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    json_line = next(
        line
        for line in result.stderr.splitlines()
        if b'"event":"supervisor.plugin.sandbox_stub_used"' in line
    )
    parsed = json.loads(json_line)
    assert parsed["reason"] == "stub_kind"
    assert parsed["host_os"] == "macos"


def test_kind_none_and_kind_stub_rows_are_distinguishable_on_macos() -> None:
    """The crux of #436, asserted end-to-end: the two macOS-reachable stub_used producers must
    differ in a POSITIVE field value, not merely by field presence (absence cannot survive the
    parse boundary — it canonicalizes to ""). Drive BOTH real launcher paths on one host and
    prove the emitted rows differ.
    """
    rows = {}
    for label, manifest_writer in (
        ("kind_none", _write_none_manifest),
        ("kind_stub", _write_stub_manifest),
    ):
        env = {
            **os.environ,
            "PYTHONPATH": str(_REPO_ROOT / "src"),
            "ALFRED_ENVIRONMENT": "development",
            "ALFRED_PLUGIN_MANIFEST_PATH": manifest_writer(),
            "FAKE_UNAME": "Darwin",
        }
        env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
        result = subprocess.run(  # noqa: S603 — literal repo-owned script path
            [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", label],
            capture_output=True,
            env=env,
            check=False,
        )
        assert result.returncode == 0, f"{label} did not exec: {result.stderr!r}"
        json_line = next(
            line
            for line in result.stderr.splitlines()
            if b'"event":"supervisor.plugin.sandbox_stub_used"' in line
        )
        rows[label] = json.loads(json_line)

    # Both are macOS dev rows; before #436 they were byte-identical.
    assert rows["kind_none"]["host_os"] == rows["kind_stub"]["host_os"] == "macos"
    assert rows["kind_none"]["reason"] == "uid_separation_unavailable"
    assert rows["kind_stub"]["reason"] == "stub_kind"
    assert rows["kind_none"] != rows["kind_stub"], (
        "the two macOS-reachable stub_used producers still emit identical rows — #436's defect."
    )
```

You will need a `_write_stub_manifest()` alongside the existing `_write_none_manifest()` — copy that helper and set `kind = "stub"`.

- [ ] **Step 7: Run everything**

Run: `uv run pytest tests/unit/plugins/ tests/unit/audit/ tests/unit/launcher/ -v`
Expected: PASS

- [ ] **Step 8: Full gates + adversarial**

Run: `make check; echo "EXIT=$?"` then `uv run pytest tests/adversarial -q`
Expected: `EXIT=0`, adversarial all pass.

- [ ] **Step 9: Commit 3**

```bash
git add bin/alfred-plugin-launcher.sh \
        src/alfred/audit/audit_row_schemas.py \
        tests/unit/plugins/test_sandbox_reason_vocab_sync.py \
        tests/unit/plugins/test_plugin_launcher_stub.py \
        tests/unit/audit/test_slice_4_audit_row_fields.py
git commit -m "fix(sandbox): #436 declare the sandbox_stub_used reason under a closed vocab

The launcher wrote a \`reason\` into the stub_used row that
SANDBOX_STUB_USED_FIELDS never declared. The field is INTENDED, not stray:
the constant landed 2026-06-07 (PR-S4-0a) describing only the kind:stub
path, \`reason\` landed two days later on the #152 security track, and
nothing bound them — parallel-PR drift. The launcher's own comment says the
row is auditable 'under the same closed vocabulary as the other stub paths',
so L248 is correct and L412/L432 are the defect.

Without it, the kind:none non-Linux row and the kind:stub row are
byte-identical on macOS — two causes with opposite remediation collapsed
into one record. Dropping \`reason\` would commit the exact conflation #434
fixes, in the same PR.

Adds SANDBOX_STUB_USED_REASONS, derivable by one rule: each member is the
dev-side twin of its refused counterpart minus the _in_production suffix.
uid_separation_unavailable is SHARED across both vocabs by design — reason
names the cause, event names the disposition — and a test pins that so it
cannot be 'tidied' away.

Also replaces the constant's docstring, which claimed the row is 'emitted
when a kind:stub plugin runs unsandboxed' — false for two of three
producers, and the reason the drift went unnoticed. It now names all three,
documents policy_ref optionality, and records why this row is deliberately
NOT persisted: it asserts 'I am about to exec', so a live child shares its
stderr with no delimiter, and the #446 gate is an inverted oracle for it.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Adversarial corpus, docs, and the PR

**Files:**

- Create: `tests/adversarial/sandbox_escape/sbx_2026_019_stub_used_forgery_not_persisted.yaml`
- Modify: `tests/adversarial/sandbox_escape/README.md`
- Modify: `docs/adr/0051-launcher-to-core-sandbox-refusal-audit-path.md` (Follow-ups only)

- [ ] **Step 1: Add the adversarial case for D4**

Model it on the existing `sbx_2026_018_launcher_refusal_row_injection.yaml` — read that file first and mirror its schema exactly. The assertion: a forged `sandbox_stub_used` row written by an exec'd child into inherited stderr is **not** persisted as an audit row. This asserts D4's guarantee rather than assuming it.

Use plain-ASCII `\uXXXX` escapes for any control/bidi characters — never literal control bytes in source YAML (a literal bidi override in source IS the Trojan-Source hazard).

- [ ] **Step 2: Add the tainted-id adversarial case**

Assert a malformed `plugin_id` never appears in any emitted row (D2). Assemble any token-shaped fixture from fragments at runtime — GitHub push-protection trips on synthetic secrets.

- [ ] **Step 3: Run the adversarial suite**

Run: `uv run pytest tests/adversarial -q`
Expected: all pass, including the two new cases.

- [ ] **Step 4: Record the follow-ups on ADR-0051**

Append to ADR-0051's **Follow-ups** section only — do **not** amend its Decision (this PR is conformance to it, not a change to it):

```markdown
* **#436 closed (2026-07-16)** — the `sandbox_stub_used` reason is now declared under
  `SANDBOX_STUB_USED_REASONS` and bound by the #432 guard. The row remains deliberately
  **unpersisted**: it asserts "I am about to exec", so a live child shares the launcher's
  stderr with no delimiter, and this ADR's EOF-on-refusal interception is structurally blind
  to it. Persisting it needs a success-path drain with an out-of-band provenance signal —
  filed as <NEW ISSUE>. Note this means #440/#441/#442 do NOT extend to `sandbox_stub_used`.
```

Replace `<NEW ISSUE>` with the real number from Step 5. Run `npx -y markdownlint-cli2@0.22.1 "docs/**/*.md"` afterwards (no `| tail`).

- [ ] **Step 5: File the follow-up issues**

```bash
gh issue create --title "sandbox: persist sandbox_stub_used needs a success-path stderr drain (ADR-0051 follow-up)" --body "..."
gh issue create --title "sandbox: collapse the two production-detection predicates in the launcher" --body "..."
gh issue create --title "sandbox: alfred audit log renders a blank REASON for sandbox rows (#381, third family)" --body "..."
gh issue create --title "sandbox: --reason cannot filter sandbox reasons (_ReasonChoice is comms-only)" --body "..."
gh issue create --title "docs: supervisor.md hookpoint table + config/sandbox README are stale for sandbox_stub_used" --body "..."
```

Each body: one paragraph of context, the exact file:line, and why it is out of #434/#435/#436's scope. Cross-link the spec.

- [ ] **Step 6: Push and open the PR**

```bash
make check; echo "EXIT=$?"   # MUST be 0 before pushing
git push -u origin fix/434-435-436-launcher-audit-row-contract
gh pr create --title "fix(sandbox): #434 #435 #436 make the launcher audit-row contract honest, complete, and bound" --body "..."
```

PR body must state: closes #434, #435, #436; the D4 non-persistence decision and why; that #435 had six paths not four; the vocab arithmetic (26→35, emittable 21→31, reserved 5→4); and the follow-ups filed.

- [ ] **Step 7: Review**

Run the **full** `/review-pr` fleet (security ALWAYS — it catches CRITICALs the others miss) **and** CodeRabbit CLI with `--base origin/main`. They catch disjoint bugs; neither is the last word. Parse both CR cloud inline threads and CR CLI findings.

**Do not arm `--auto` merge while anything Critical or CHANGES_REQUESTED is open.** Push any fix commit BEFORE claiming it in a comment — the reverse order merged #445 without its fix.

---

## Self-Review Notes

**Spec coverage:** D1→Tasks 1-5 (three commits). D2→Task 3 Step 5 + Step 7's `_OPTIONAL_FIELDS` pin. D3→Task 5. D4→Task 5 Step 3 docstring + Task 6 Step 1 adversarial + Task 6 Step 4 ADR. D5→Task 4. D6→Task 3 Step 3. D7→Task 5 Steps 3 + 1 (`test_stub_and_refused_vocabs_are_deliberately_not_disjoint`). D8→Task 5 Step 3 docstring. D9→Task 1 Steps 4-5 + Task 2 Step 6. #434A→Task 1. #434B→Task 2. #435→Tasks 3-4. #436→Task 5. Out-of-scope items→Task 6 Step 5.

**Two spec under-specifications this plan corrects:**

1. The spec said "extend the #432 binding" without noting `_parse_case` hard-fails on a third arm. #434A's map is 6 arms → Task 1 adds `_parse_mapping_case`.
2. The variable name is load-bearing: `_launcher_emittable_reasons` substring-matches `"_AUDIT_REASON" in line`, so `_SANDBOX_AUDIT_REASON` would silently bind the wrong set. Task 1 mandates `_SANDBOX_REASON`.

**Verified during planning, not assumed:** `manifest.py:98` declares `kind: Literal["full", "none", "stub"]`, so the launcher's `*)` sandbox-kind arm is **unreachable from any valid manifest** — `parse_manifest` rejects an unknown kind upstream and `_cmd_read_sandbox` fails with `plugin.manifest_invalid`. Task 3 therefore binds that arm by text, names in the test docstring exactly what the guard cannot prove (that the arm ever runs), and keeps the arm as the fail-closed default. This is the "name what a guard CANNOT do, IN the guard" discipline from #269/#431. An earlier draft of this plan had a behavioural `_UNKNOWN_KIND_MANIFEST` fixture; it would have been silently unreachable — a test that cannot fail.

**Helper names verified:** `run_launcher` is a fixture in `tests/unit/launcher/conftest.py:58`; `_write_manifest` (L75), `_stub_binary` (L81), and `_NO_SANDBOX_MANIFEST` (L62) are module-level in `test_launcher_sandbox_flow.py`. Do not invent new ones.

**Floor arithmetic:** vocab 26→31 (Task 1) →35 (Task 3). Emittable 21→26→30→31. Reserved 5→4 (Task 4). Emit lines 12→17 (Task 3) →18 (Task 4). Stub emit lines fixed at 3.
