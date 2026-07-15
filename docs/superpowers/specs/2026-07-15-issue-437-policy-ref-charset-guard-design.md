# #437 — validate the `policy_ref` charset to close the audit-JSON injection

**Status:** design, settled autonomously 2026-07-15 (operator asleep; delegated autonomous
execution — no genuine security fork arose, so decisions were made and documented rather than
asked; see "Decisions" below).
**Issue:** [#437](https://github.com/MrReasonable/AlfredOS/issues/437) — split out of the #432
plan review (security sec-002; cross-checked High→Low / latent).
**Predecessors:** #431 (over-broad bind guard), #432 (`SANDBOX_REFUSED_REASONS` closed vocab —
its drift-guard test now enforces any new launcher reason).

## Problem

`bin/alfred-plugin-launcher.sh` reads `POLICY_REF` once, raw from the manifest via jq
(`L290: POLICY_REF="$(… jq -r ".policy_refs.\"${HOST_OS}\"" …)"`), then interpolates it
**unescaped** into audit-JSON `printf` rows at **L323** (`supervisor.plugin.sandbox_refused`,
the `"policy_ref":"%s"` field) and **L397** (`supervisor.plugin.sandbox_stub_used`), and passes
it to a subprocess at L301. `PLUGIN_ID` is charset-validated at L123 (`*[!A-Za-z0-9._-]*`)
*precisely* so it is safe in these same templates — but `POLICY_REF` is not, and
`src/alfred/plugins/manifest.py` only type-checks `policy_refs` values as `str` (L313).

A `policy_ref` value containing `"`, a newline, or `","event":"…"` can therefore forge the
`event` field (last-duplicate-key-wins under `json.loads`) or inject a whole fabricated audit
row.

**Severity today: latent.** `kind:full` manifests are first-party and plugin install is
human-gated; nothing yet parses the launcher's stderr JSON into a structured row (#433). It
becomes a live Medium the instant #433 wires a `json.loads` consumer. This PR closes it now,
before that consumer exists.

## Decisions (settled autonomously, verified against the codebase)

1. **Charset allowlist = `[A-Za-z0-9._/-]`** (PLUGIN_ID's set plus `/`, since a policy_ref is a
   relative path). **Verified:** every shipped `policy_ref` across all three `kind:full`
   manifests (`alfred_discord`, `alfred_discord_probe`, `quarantine_child`) is exactly of the
   form `config/sandbox/<name>.<os>.<ext>` and contains only these characters. The set excludes
   `"`, newline, `,`, space, and every control character — the full JSON-injection vector set.
2. **Two layers, producer-side primary** (the issue mandates both):
   - **manifest.py** (the single authoritative producer) — reject a charset-invalid value in
     the `policy_refs_raw.items()` loop, right after the existing `isinstance(str)` check.
   - **launcher** (defense-in-depth, last fail-closed gate) — a `case` guard at the L290
     `POLICY_REF` chokepoint, before its three raw-interpolation sites (the flags subprocess
     argv, and the two JSON `printf` rows that embed `${POLICY_REF}`). **Correction (Task 2
     review):** this guard is *unreachable via any current manifest* — both branches of the
     launcher's `_read_sandbox()` (with and without `ALFRED_PLUGIN_MANIFEST_PATH`) route
     `SANDBOX_JSON` through `manifest_reader --read-sandbox` → `parse_manifest`, so the Layer-1
     validator refuses a charset-invalid value first. The launcher guard is therefore *not*
     covering an unvalidated path (the issue body's original framing was wrong); it is
     proximate-to-use belt-and-suspenders matching the launcher's own PLUGIN_ID pattern, and it
     is the only defense if a future change narrows `_parse_sandbox_block` to validate only the
     resolved host's key or introduces a `SANDBOX_JSON` source that bypasses Python. Its test
     necessarily bypasses the Python producer (a PATH-shadowed `python3` stub) to exercise it.
3. **Guard placement in the launcher: after the empty-check `fi` (L295), before the
   `case "${HOST_OS}"` (L296).** Empty `POLICY_REF` is already handled by the existing
   `policy_ref_missing` branch (L291-294); the charset guard runs only on a non-empty value and
   sits before *every* downstream use (the L301 subprocess and the L323/L397 JSON rows).
4. **New refusal reason: `policy_ref_charset_invalid`**, added to `SANDBOX_REFUSED_REASONS`.
   The #432 vocab-sync test will *require* this addition — a deliberate, welcome demonstration
   of that guard doing its job. Emitting a new launcher reason without adding it to the frozenset
   fails the build.
5. **The charset-refusal audit row MUST NOT echo the tainted `POLICY_REF`.** Unlike the L323
   row, the new refusal `printf` includes `reason`, `plugin_id`, `environment`, `host_os` but
   **omits the `policy_ref` field entirely** — echoing the value we just rejected would *be* the
   injection. This is the load-bearing security detail.
6. **i18n:** a new `ManifestError` message key `plugin.manifest_sandbox_policy_refs_value_charset`
   (operator-facing), and the launcher's operator-facing bare key
   `supervisor.sandbox.refused.policy_ref_charset_invalid` added to the launcher/sandbox i18n
   catalog alongside its sibling reasons (matching the existing pattern for launcher reasons).
   The *reason value* in the audit row is a bare machine key, not `t()` scope (per #432).
7. **Adversarial coverage:** a new `sandbox_escape` corpus payload (a `policy_ref` carrying
   `","event":"forged…` / a newline) that must be refused by *both* layers.

## Design

### Layer 1 — `manifest.py` (producer, primary)

In the `policy_refs_raw.items()` loop, after `if not isinstance(os_value, str): raise …`, add:

```python
if _POLICY_REF_BAD_CHAR.search(os_value):
    raise ManifestError(
        t("plugin.manifest_sandbox_policy_refs_value_charset", os_key=os_key)
    )
```

with a module-level `_POLICY_REF_BAD_CHAR: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._/-]")`.
**Refinement (during implementation):** a *negated-class search* (reject if any char is OUTSIDE
the set) is used rather than a `fullmatch` allowlist — it mirrors the launcher guard's
`*[!A-Za-z0-9._/-]*` byte-for-byte (so the two layers refuse exactly the same values, pinned by a
sync test) and *tolerates empty* (empty has no bad char), avoiding a behaviour change for the
`kind:none`-with-`policy_refs`-tolerated case; empty is owned by the launcher's `[ -z ]` check and
the `kind:full`-requires-non-empty check. This raises the typed `ManifestError` *before*
`SandboxBlock` construction (same contract as the existing type-check — a public `ManifestError`,
not a leaked Pydantic `ValidationError`).

### Layer 2 — `bin/alfred-plugin-launcher.sh` (defense-in-depth)

After the empty-check, before the host-OS `case`:

```sh
case "${POLICY_REF}" in
    *[!A-Za-z0-9._/-]*)
        printf 'supervisor.sandbox.refused.policy_ref_charset_invalid plugin_id=%s\n' "${PLUGIN_ID}" >&2
        printf '{"event":"supervisor.plugin.sandbox_refused","plugin_id":"%s","reason":"policy_ref_charset_invalid","environment":"%s","host_os":"%s"}\n' "${PLUGIN_ID}" "${ALFRED_RESOLVED_ENVIRONMENT}" "${HOST_OS}" >&2
        exit 1
        ;;
esac
```

`PLUGIN_ID` is already validated, so the row is safe; `POLICY_REF` is refused without appearing
in any output. The bare stderr key mirrors the `plugin.launcher_plugin_id_invalid` pattern.

### Layer 3 — vocab + audit schema

Add `policy_ref_charset_invalid` to `SANDBOX_REFUSED_REASONS` in `audit_row_schemas.py` (it is
launcher-emittable, so it joins the 20 emittable reasons → 26 total). The #432 vocab-sync test
binds it automatically once added; if it is *not* added, that test fails — which is the guard
working.

## Testing

Security boundary → **100% line + branch coverage** on the new manifest.py branch and the
launcher guard; the **adversarial suite is release-blocking** for this change.

- **manifest.py unit** — happy (a valid `config/sandbox/x.linux.bwrap.policy` parses); refusal
  (a value with `"`/newline/`,` → `ManifestError` carrying
  `plugin.manifest_sandbox_policy_refs_value_charset`); the existing type-check path still works;
  the `+` (non-empty) behaviour. Property test: any string containing a char outside the
  allowlist is rejected.
- **launcher** — a subprocess test (with `@pytest.mark.skipif(sys.platform=="win32")`, the #428
  lesson) driving the launcher with a charset-invalid `POLICY_REF` and asserting: exit 1, the
  bare key on stderr, a `sandbox_refused` JSON row with `reason=policy_ref_charset_invalid`, and
  **that the row does NOT contain the tainted substring** (the anti-echo assertion — the security
  crux). Plus an in-process twin for the coverage the subprocess test can't reach (the #428/#245
  pattern).
- **vocab-sync** — `test_sandbox_reason_vocab_sync.py` (from #432) must stay green with the new
  reason; confirm it *would* fail if the reason were emitted but not added to the frozenset
  (mutation check).
- **adversarial** — `sbx-2026-017` payload: a manifest whose `policy_ref` forges an `event`; both
  the manifest parser and the launcher must refuse it. CI required-node gate.
- i18n catalog: `pybabel` clean; the new `t()` key filled.

## Definition of done

- `manifest.py` rejects a charset-invalid `policy_ref` value with a typed `ManifestError`
  (new i18n key), before `SandboxBlock` construction.
- The launcher refuses a charset-invalid non-empty `POLICY_REF` with `policy_ref_charset_invalid`,
  emitting no tainted value.
- `policy_ref_charset_invalid` is in `SANDBOX_REFUSED_REASONS`; the #432 vocab-sync test is green.
- The anti-echo assertion (refusal row omits the tainted value) is tested.
- Adversarial payload added and refused by both layers; the suite is green.
- 100% line+branch on the new boundary code; `make check` green; i18n catalog clean.

## Out of scope

- #433 (persist the `sandbox_refused` row) — this hardens the value that row *would* carry;
  #433 is what gives the injection a reader, and lands separately.
- Retrofitting the same guard onto other manifest string fields (plugin id is already guarded;
  other fields do not reach a `printf` JSON template). YAGNI unless a future field does.
- The `//empty` jq semantics and the broader manifest-parse hardening — unchanged.
