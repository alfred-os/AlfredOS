# #339 PR4b-broker — Authenticated web.fetch via Broker Secret Substitution — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `web.fetch` send authenticated requests by resolving `{{secret:<name>}}` placeholders in header values through a new `SecretBroker.substitute()` — after core DLP, before the relay frame — gated by a closed, empty-by-default allowlist, so a raw secret never reaches the ledger, audit, or DLP-scanned frame.

**Architecture:** A caller places `{{secret:<name>}}` in a `web.fetch` header value. `dispatch_web_fetch` DLP-scans the placeholder frame first (ADR-0017), refuses any **raw** secret in the URL or a header, then calls `broker.substitute(value, allowed_secrets=WEB_FETCH_AUTH_SECRET_ALLOWLIST)` to fill placeholders **after** DLP and **before** building `_RawToolRequest`. The allowlist ships empty (live auth off in #339); the positive path is proven by fixture-binding tests. `SecretBroker.substitute()` is the shared primitive `stdio_transport`'s aspirational Protocol awaits (convergence deferred).

**Tech Stack:** Python 3.14+, Pydantic v2, pytest + testcontainers, `mypy --strict` + `pyright`, `ruff`, `pybabel` i18n, structlog.

## Global Constraints

- **Python floor `>=3.14.6`.** PEP 604/585/695 idioms; never `Optional[X]` / `typing.List`. Frozen/immutable by default; `Mapping` over `dict` for read-only inputs.
- **Strong typing.** No `Any` without justification. `mypy --strict` + `pyright` both clean on `src/`.
- **Security HARD rules.** #3 tag external input T3 at the boundary; #5 the privileged orchestrator never sees raw T3; #6 secrets live in the broker, substituted at the tool-call boundary — never a raw secret in headers; #7 no silent failures in security paths (loud audit + re-raise). This PR touches `src/alfred/security/` → **the adversarial suite (`tests/adversarial`) is release-blocking** and must be run before the PR is claimed green.
- **i18n HARD rules.** Every operator-facing string via `t()`. New keys: `pybabel extract` (pre-commit) + `pybabel compile --check` (CI). Add the English `msgstr` by hand in `locale/en/LC_MESSAGES/alfred.po`; NEVER `--omit-header`. A line-shifting edit re-stales `#:` refs → re-run extract.
- **Commit discipline.** Conventional-commit type is `[a-z]+` (no digits — `i18n` is rejected as a *type*; use it as a scope). Every commit SUBJECT needs a literal `#339` **after the colon** (a `(339)` scope does NOT satisfy `pr-validate-commits`). Never `git add -A` (untracked rulesync outputs); add named paths only. Never `--no-verify`. End every commit message with the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer.
- **Branch:** `339-pr4b-broker-secret-substitution` (already created off `main` @ `6a14c173`; the design spec commit `4b2f63e5` is already on it).
- **`make check`** (ruff + format + mypy + pyright + unit) before every push; run the full `tests/unit` (not a scoped subset) so the line-pinned audit AST guard runs.

---

## Plan-review fixes (FOLD THESE FIRST — they OVERRIDE the task bodies below)

A 5-lens `/review-plan` fleet (security, architect, test, reviewer, error) confirmed the **core security contract is sound** (substitute-after-DLP ordering preserved, closed allowlist genuinely enforced inside `substitute()`, empty default correct, `WEB_FETCH_FIELDS` header-free, audit domain-closed guard needs no change) — no Critical architecture flaw. The findings below are execution-fidelity defects; each implementer MUST apply the fixes relevant to their task. Corroboration count in brackets.

- **FIX-1 [×3 sec/err/test — High] Step-1b/1c placement (handle_cap slot leak).** In Task 3, do **NOT** place substitution "just before the `try:` at :557". Place BOTH Step 1b (header raw-secret defence) AND Step 1c (substitution → `auth_headers`) immediately after the URL `url_secret_refused` block (after `:386`), **before** Step 2 (allowlist, `:388`) and Step 3b (`handle_cap.try_reserve`, `:516`). This matches spec §5 and means a header/substitution refusal fires **before any concurrency slot is reserved** (the empty-allowlist default refuses every placeholder → the current plan would leak a slot per refusal = a planner-inducible self-DoS). The `_RawToolRequest` at `:558` then reads the already-computed `auth_headers`. **Add a test:** a Step-1c refusal reserves NO slot (spy `handle_cap.try_reserve` → `assert_not_awaited()`).
- **FIX-2 [×2 test(Crit)/rev — High] off-allowlist test needs a REAL broker.** The `_dispatch` helper's default `broker` must be a real `SecretBroker` (enforcement lives inside `substitute`; a passthrough never raises, so `test_off_allowlist_placeholder_refused` cannot pass). Default the helper to `SecretBroker(env={})`; positive tests pass a broker with the fixture secret; the passthrough fake is only for no-placeholder tests.
- **FIX-3 [×2 rev/test — High] i18n dependency order.** MOVE all i18n work (msgids + tests) from Task 2 into **Task 3**, in the SAME commit as the `t()` call sites. Task 2 keeps only the two `DlpScanResult` tokens + lockstep + the `auth_allowlist` module. Do NOT run `pybabel update` while the keys have no call site (it orphans them → the i18n test fails and pre-commit re-stales the `.po`).
- **FIX-4 [×2 test/sec — High] i18n msgstr braces + `_FINGERPRINTS`.** `t()` runs `raw.format(**vars)` (translator.py:184), so a msgstr MUST contain no `{...}`/`{{...}}`. Reword: `header_secret_refused` → `"The request was refused because a header contained a secret value. Reference the secret through the broker instead of sending its value."`; `secret_substitution_refused` → `"The request was refused because it referenced a secret that is not on the web.fetch allowlist. Ask an operator to allowlist it."` Test via the file's `_FINGERPRINTS` dict (add both keys with substring fingerprints + a remediation-lever hint for `test_error_message_names_remediation_lever` at `test_i18n_keys.py:214`) — NOT standalone `t(key) != key` functions.
- **FIX-5 [×1 sec — High, CI-breaking] third `dispatch_web_fetch` caller.** There are THREE direct callers: `builtin_tools.py:96`, `test_fetch_dispatcher.py:221` (the `_dispatch` helper), and **`tests/adversarial/dlp_egress/test_egress_no_orphan_and_inflight.py:578`** (release-blocking). Add `broker=` (+ default `auth_secret_allowlist`) to the third in Task 6's threading step — with `broker` required it otherwise `TypeError`s and breaks the adversarial suite.
- **FIX-6 [×4 sec/err/rev/test — High] missing imports.** In Task 3, ADD `from typing import NoReturn` and `from alfred.audit.audit_row_schemas import DlpScanResult` to `fetch_dispatcher.py` (the `_refuse` helper's annotations) — the "already imported" claim is FALSE (grep-verify). Task 1: confirm `re` + `Final` are imported in `secrets.py`; add if missing.
- **FIX-7 [×3 sec/rev/test — High] remove `merge_blocker`.** The de-2026-019 YAML must carry only fields `AdversarialPayload` declares (`extra="forbid"`): `id, category, threat, ingestion_path, payload, expected_outcome, provenance, references` (+ `note`/`out_of_scope*` if needed). DELETE `merge_blocker: true`.
- **FIX-8 [×2 err/sec — Med] `from None`.** The Step-1c `except (...)` → `_refuse(...)` must raise with `from None` (or `_refuse` raises `WebFetchError(...) from None`) — `UnknownSecretError` is a `KeyError` whose `str()` echoes the secret name; without `from None` it chains via `__context__` into the planner-facing exception (secret-name leak).
- **FIX-9 [err — Med] non-refusal fault totality.** Document (docstring + a plan note in Task 3): a broker BACKEND fault (anything not `SecretSubstitutionNotAllowed`/`UnknownSecretError`) propagates uncaught from `substitute` → caught by `dispatch_tool`'s outer `except Exception → unexpected_error/fault` arm (loud audit one layer up; the PR4a FIX-9/handle_cap-reserve precedent). Do NOT add a second dispatcher arm (double-audit).
- **FIX-10 [×4 all-Low/Med — Med] DRY `url_secret_refused` through `_refuse`.** Route the existing URL refusal (`:360-386`) through the new `_refuse` helper too (same subject shape). Define `_refuse` before the URL check; it closes over `clean_url`/`domain` (both bound by `:360`).
- **FIX-11 [×2 test/sec — Med] hard coverage gate.** State 100% line+branch on `fetch_dispatcher.py`'s new arms + `secrets.py::substitute` as a CI hard gate (both jobs), not just a local `--cov` check. Pin the dict-comprehension/ternary else-paths coverage.py cannot instrument with explicit tests.
- **FIX-12 [test — Med] empty-name test.** Task 1: add a unit test that `{{secret:}}` (empty name) → `SecretSubstitutionNotAllowed` (the `[^{}]*` match + `_VALID_SECRET_NAME` reject path).
- **FIX-13 [test — Med] non-vacuous absence guard.** The Task 6 secret-absence scan must include a same-test positive control (assert the fixture value WOULD be found if injected into a throwaway string), proving the scan is non-vacuous.
- **FIX-14 [×2 test/arch — Med] pin token + broker instance.** (a) The positive-path integration fixture token must be a value that provably does NOT match the gateway stage-2 regex (assertion + comment). (b) `build_tool_registry`'s `broker` must be the SAME boot `SecretBroker` instance backing `outbound_dlp` (one-broker invariant) — pin in ADR-0048/security.md for #338.
- **FIX-15 [test — Med] Task 5 DLP spec.** Task 5 builds a REAL `OutboundDlp` whose broker knows the planted raw secret — plant a genuine `SUPPORTED_SECRET` (e.g. set `deepseek_api_key` to the exfil value so DLP stage-1 redacts it → refusal fires). Do NOT reuse `identity_outbound_dlp`.
- **FIX-16 [arch — Med] ADR-0048 completeness.** Cross-ref ADR-0047 (deferred this to "PR4b") + PRD §7.1; note this closes the LAST #347 residual + extends ADR-0041's contract; include the sign-off-flag blockquote (ADR-0047 precedent). Sharpen the empty-allowlist rationale: every current `SUPPORTED_SECRET` is an infra credential → allowlisting any would be an exfil vector (that is WHY it ships empty).
- **FIX-17 [Low] misc.** (a) Drop the `#351 config-as-interface` citation in Task 3 Step 6 (`SecretBroker` is a service → plain DI). (b) The `build_tool_registry` call site is `test_tool_assembly.py:123` (the test def is `:74`); NO production caller exists yet. (c) Task 6 `git add` NAMED files, not a directory. (d) Add a breadcrumb to `stdio_transport.py`'s `_SecretBrokerSubstitute` Protocol comment: `SecretBroker.substitute()` now exists (#339 PR4b-broker); convergence deferred. (e) `_SecretSubstituter` is already in `auth_allowlist.__all__` — keep.

---

## File Structure

**Source:**
- `src/alfred/security/secrets.py` — add `SecretSubstitutionNotAllowed(AlfredError)`, the `_SECRET_PLACEHOLDER` / `_VALID_SECRET_NAME` regexes, and `SecretBroker.substitute()`.
- `src/alfred/plugins/web_fetch/auth_allowlist.py` — **new** — the closed `WEB_FETCH_AUTH_SECRET_ALLOWLIST` constant + a `_SecretSubstituter` Protocol for the dispatcher's broker seam.
- `src/alfred/audit/audit_row_schemas.py:50` — add `header_secret_refused` + `secret_substitution_refused` to the `DlpScanResult` Literal.
- `src/alfred/plugins/web_fetch/fetch_dispatcher.py` — header raw-secret defence (Step 1b) + substitution (Step 1c); new `broker` + `auth_secret_allowlist` params on `dispatch_web_fetch`.
- `src/alfred/orchestrator/builtin_tools.py:69` — thread `broker` + `auth_secret_allowlist` through `build_web_fetch_tool`.
- `src/alfred/orchestrator/tool_assembly.py:67` — derive the `SecretBroker` for `build_tool_registry` and pass it down.
- `locale/en/LC_MESSAGES/alfred.po` — two new `msgid`/`msgstr` pairs.
- `docs/adr/0048-web-fetch-authenticated-fetch-secret-substitution.md` — **new**.
- `docs/subsystems/security.md` — DLP-positioning correction (core DLP sole broker-secret defence; gateway `broker=None`).

**Tests:**
- `tests/unit/security/test_secrets.py` — `substitute()` unit tests.
- `tests/unit/audit/test_audit_row_schemas.py:355` — extend the `DlpScanResult` lockstep set.
- `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py` — header-secret-refused + substitution unit tests; **update** `test_real_url_sent_on_wire_with_redacted_headers` (:272).
- `tests/unit/plugins/web_fetch/test_i18n_keys.py` — assert the two new keys render.
- `tests/unit/orchestrator/test_builtin_tools.py` + callers — thread the new params.
- `tests/adversarial/dlp_egress/broker_secret_exfil.yaml` + `tests/adversarial/dlp_egress/test_de_2026_019_broker_secret_exfil.py` — **new**.
- `tests/integration/orchestrator/test_tool_assembly.py` / `test_act_loop_real_chain.py` / `test_tool_dispatch_timeout_audit_postgres.py` + `test_cap_2026_006_tool_arg_injection.py` — thread `broker` through the `build_web_fetch_tool` / `build_tool_registry` callers; add one positive-path integration assertion.

**Threading note (all tasks):** `build_web_fetch_tool` has these callers (each needs the new kwargs): `tool_assembly.py:125`; `tests/unit/orchestrator/test_builtin_tools.py` (:80,:107,:146); `tests/adversarial/capability_bypass/test_cap_2026_006_tool_arg_injection.py:182`; `tests/integration/orchestrator/test_tool_dispatch_timeout_audit_postgres.py:222`. `build_tool_registry` callers: `tests/integration/orchestrator/test_act_loop_real_chain.py:259`; `tests/integration/orchestrator/test_tool_assembly.py:74`. Keep the new params REQUIRED (no fail-open default) EXCEPT `auth_secret_allowlist`, which defaults to the empty module constant.

---

## Task 1: `SecretBroker.substitute()` + `SecretSubstitutionNotAllowed`

**Files:**
- Modify: `src/alfred/security/secrets.py` (add exception near `:123`; add regexes + method near `get` at `:626`)
- Test: `tests/unit/security/test_secrets.py`

**Interfaces:**
- Consumes: existing `SecretBroker.get(name) -> str` (raises `UnknownSecretError`), `SUPPORTED_SECRETS`, `alfred.errors.AlfredError`.
- Produces:
  - `SecretSubstitutionNotAllowed(AlfredError)` with attribute `.ref: str`.
  - `SecretBroker.substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/security/test_secrets.py` (reuse the module's existing broker-construction helper; the broker below is illustrative — match the file's fixture style):

```python
import pytest
from alfred.security.secrets import (
    SecretBroker,
    SecretSubstitutionNotAllowed,
    UnknownSecretError,
)


def _broker(**env: str) -> SecretBroker:
    # deepseek_api_key is a real SUPPORTED_SECRET; ALFRED_ prefix, upper-cased.
    return SecretBroker(env={f"ALFRED_{k.upper()}": v for k, v in env.items()})


def test_substitute_no_placeholder_returns_text_unchanged() -> None:
    broker = _broker(deepseek_api_key="sk-live")
    text = "Bearer static-token"
    assert broker.substitute(text, allowed_secrets=frozenset({"deepseek_api_key"})) == text


def test_substitute_fills_allowed_placeholder_preserving_surrounding_text() -> None:
    broker = _broker(deepseek_api_key="sk-live")
    out = broker.substitute(
        "Bearer {{secret:deepseek_api_key}}",
        allowed_secrets=frozenset({"deepseek_api_key"}),
    )
    assert out == "Bearer sk-live"


def test_substitute_multiple_placeholders() -> None:
    broker = _broker(deepseek_api_key="A", anthropic_api_key="B")
    out = broker.substitute(
        "{{secret:deepseek_api_key}}:{{secret:anthropic_api_key}}",
        allowed_secrets=frozenset({"deepseek_api_key", "anthropic_api_key"}),
    )
    assert out == "A:B"


def test_substitute_off_allowlist_ref_refuses() -> None:
    broker = _broker(deepseek_api_key="sk-live")
    with pytest.raises(SecretSubstitutionNotAllowed) as exc:
        broker.substitute(
            "{{secret:deepseek_api_key}}", allowed_secrets=frozenset()
        )
    assert exc.value.ref == "deepseek_api_key"


def test_substitute_allowed_but_unprovisioned_raises_unknown_secret() -> None:
    broker = _broker()  # deepseek_api_key not set
    with pytest.raises(UnknownSecretError):
        broker.substitute(
            "{{secret:deepseek_api_key}}",
            allowed_secrets=frozenset({"deepseek_api_key"}),
        )


def test_substitute_malformed_ref_refuses_without_echoing_attacker_text() -> None:
    broker = _broker(deepseek_api_key="sk-live")
    with pytest.raises(SecretSubstitutionNotAllowed):
        broker.substitute(
            "{{secret:Bad Name!}}", allowed_secrets=frozenset({"deepseek_api_key"})
        )
    # The fixed message must NOT interpolate the raw ref (log-injection guard).
    assert "Bad Name" not in str(SecretSubstitutionNotAllowed("Bad Name!"))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_secrets.py -k substitute -v`
Expected: FAIL — `ImportError: cannot import name 'SecretSubstitutionNotAllowed'` / `AttributeError: 'SecretBroker' object has no attribute 'substitute'`.

- [ ] **Step 3: Add the exception (near `secrets.py:123`, after `UnknownSecretError`)**

```python
class SecretSubstitutionNotAllowed(AlfredError):
    """A ``{{secret:<name>}}`` reference that is not permitted in this context.

    Confused-deputy defence (mirrors
    :class:`alfred.comms_mcp.adapter_credential_resolver.CoreAdapterCredentialResolver`'s
    closed ``_ADAPTER_SECRET_ALLOWLIST``): the referenced name is off the caller's
    closed ``allowed_secrets`` set, or is malformed. Carries the (possibly
    attacker-influenced) ``ref`` for internal correlation ONLY — the message is a
    FIXED string, and callers audit the closed ``secret_substitution_refused``
    token, never the raw ``ref`` (no unbounded attacker text into audit/logs).
    """

    __slots__ = ("ref",)

    def __init__(self, ref: str) -> None:
        super().__init__("web.fetch secret reference not permitted")
        self.ref = ref
```

- [ ] **Step 4: Add the regexes + `substitute` (near `get` at `secrets.py:626`)**

Add module-level (near the top, with the other module constants):

```python
# ``{{secret:<name>}}`` placeholder resolved by ``SecretBroker.substitute`` at the
# tool-call boundary (HARD rule #6). The inner group is deliberately permissive
# (any non-brace run) so a MALFORMED name is caught and refused rather than passed
# through literally; the strict name charset is validated separately.
_SECRET_PLACEHOLDER: Final = re.compile(r"\{\{secret:([^{}]*)\}\}")
_VALID_SECRET_NAME: Final = re.compile(r"^[a-z0-9_.]+$")
```

Add the method on `SecretBroker` (after `get`):

```python
def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str:
    """Replace every ``{{secret:<name>}}`` placeholder in ``text`` with the real
    secret value.

    ``<name>`` MUST match ``[a-z0-9_.]+``, be in ``allowed_secrets`` (the caller's
    closed, context-specific allowlist), AND resolve via :meth:`get` (i.e. be in
    ``SUPPORTED_SECRETS`` and provisioned). A ``text`` with no placeholder is
    returned byte-for-byte unchanged.

    This method resolves placeholders ONLY. It assumes ``text`` is already
    DLP-clean of RAW secret values (ADR-0017: DLP scans the placeholder frame
    BEFORE substitution) and does not itself detect raw secrets.

    Raises:
        SecretSubstitutionNotAllowed: ``<name>`` is malformed or off-allowlist
            (confused-deputy defence; never a broker passthrough of an
            attacker-named secret).
        UnknownSecretError: ``<name>`` is allowlisted but not a known/provisioned
            secret (delegated from :meth:`get`).
    """

    def _replace(match: re.Match[str]) -> str:
        ref = match.group(1)
        if not _VALID_SECRET_NAME.match(ref) or ref not in allowed_secrets:
            raise SecretSubstitutionNotAllowed(ref)
        return self.get(ref)

    return _SECRET_PLACEHOLDER.sub(_replace, text)
```

Ensure `import re` and `Final` are imported (they are used elsewhere in the module — confirm; add if missing). Add `SecretSubstitutionNotAllowed` to `__all__` if the module defines one.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/security/test_secrets.py -k substitute -v`
Expected: PASS (6 tests).

- [ ] **Step 6: Type-check**

Run: `uv run mypy src/alfred/security/secrets.py && uv run pyright src/alfred/security/secrets.py`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/security/secrets.py tests/unit/security/test_secrets.py
git commit -m "$(cat <<'EOF'
feat(339): SecretBroker.substitute() for {{secret:*}} placeholders (#347 blocker 4) (#339)

The shared secret-substitution primitive: resolves {{secret:<name>}} in a string
via a closed per-call allowed_secrets allowlist (confused-deputy defence,
mirrors adapter_credential_resolver) intersected with SUPPORTED_SECRETS. Raw
secret detection stays upstream in DLP (ADR-0017 ordering). New
SecretSubstitutionNotAllowed carries the ref internally but never echoes it.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 2: Allowlist constant + two `DlpScanResult` tokens + lockstep + i18n

**Files:**
- Create: `src/alfred/plugins/web_fetch/auth_allowlist.py`
- Modify: `src/alfred/audit/audit_row_schemas.py:50`
- Modify: `locale/en/LC_MESSAGES/alfred.po`
- Test: `tests/unit/audit/test_audit_row_schemas.py:355`, `tests/unit/plugins/web_fetch/test_i18n_keys.py`

**Interfaces:**
- Produces:
  - `WEB_FETCH_AUTH_SECRET_ALLOWLIST: Final[frozenset[str]]` (== `frozenset()`), plus a `_SecretSubstituter` Protocol (`substitute(text, *, allowed_secrets) -> str`).
  - `DlpScanResult` gains `"header_secret_refused"`, `"secret_substitution_refused"`.
  - i18n keys `web.fetch.error.header_secret_refused`, `web.fetch.error.secret_substitution_refused`.

- [ ] **Step 1: Write the failing lockstep + i18n tests**

Extend the assertion set in `tests/unit/audit/test_audit_row_schemas.py::test_dlp_scan_result_literal_includes_new_values` (`:379`):

```python
        "header_secret_refused",  # NEW #339 PR4b-broker — raw secret in a header
        "secret_substitution_refused",  # NEW #339 PR4b-broker — off-allowlist {{secret:*}}
```

Add to `tests/unit/plugins/web_fetch/test_i18n_keys.py` (follow the file's per-key-fingerprint pattern — assert `t(key)` is non-empty and distinct, not merely `!= key`):

```python
def test_header_secret_refused_key_renders() -> None:
    from alfred.i18n import t
    msg = t("web.fetch.error.header_secret_refused")
    assert msg and msg != "web.fetch.error.header_secret_refused"


def test_secret_substitution_refused_key_renders() -> None:
    from alfred.i18n import t
    msg = t("web.fetch.error.secret_substitution_refused")
    assert msg and msg != "web.fetch.error.secret_substitution_refused"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/audit/test_audit_row_schemas.py::test_dlp_scan_result_literal_includes_new_values tests/unit/plugins/web_fetch/test_i18n_keys.py -v`
Expected: FAIL — lockstep set mismatch; i18n `t(key) == key` (untranslated).

- [ ] **Step 3: Add the two `DlpScanResult` tokens (`audit_row_schemas.py:59`, after `handle_cap_exceeded`)**

```python
    "header_secret_refused",  # #339 PR4b-broker — raw secret detected in a request header
    "secret_substitution_refused",  # #339 PR4b-broker — off-allowlist {{secret:*}} reference
```

Update the docstring below the Literal (`:80`) to name the two new tokens as the PR4b-broker dispatcher emits (keep the grep-proven-removed list intact).

- [ ] **Step 4: Create `src/alfred/plugins/web_fetch/auth_allowlist.py`**

```python
"""The closed web.fetch auth-secret allowlist + the broker-substituter seam.

Confused-deputy defence for authenticated ``web.fetch`` (#347 blocker 4, ADR-0048):
a ``{{secret:<name>}}`` placeholder in a request header may reference ONLY a secret
name in :data:`WEB_FETCH_AUTH_SECRET_ALLOWLIST`. Mirrors
``adapter_credential_resolver._ADAPTER_SECRET_ALLOWLIST``.

Ships EMPTY: no ``SUPPORTED_SECRET`` is a third-party web-auth token, so there is
no live binding in #339. A future authenticated integration adds both a new
``SUPPORTED_SECRET`` and an entry here (behind operator config + its own review).
"""

from __future__ import annotations

from typing import Final, Protocol

WEB_FETCH_AUTH_SECRET_ALLOWLIST: Final[frozenset[str]] = frozenset()


class _SecretSubstituter(Protocol):
    """Structural shape of the broker surface ``dispatch_web_fetch`` consumes.

    Matches :meth:`alfred.security.secrets.SecretBroker.substitute`. A Protocol
    (not the concrete class) so unit tests can inject a fake without a real broker.
    """

    def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str: ...


__all__ = ["WEB_FETCH_AUTH_SECRET_ALLOWLIST", "_SecretSubstituter"]
```

- [ ] **Step 5: Add the i18n `msgstr` pairs to `locale/en/LC_MESSAGES/alfred.po`**

Append two entries (English body by hand — do NOT `--omit-header`). Place near the other `web.fetch.error.*` keys:

```po
msgid "web.fetch.error.header_secret_refused"
msgstr "The request was refused because a header contained a secret value. Reference it with a {{secret:<name>}} placeholder instead."

msgid "web.fetch.error.secret_substitution_refused"
msgstr "The request was refused because it referenced a secret that is not permitted for web.fetch."
```

- [ ] **Step 6: Run extract + compile, then the tests**

Run:
```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update --no-fuzzy-matching -i /tmp/alfred.pot -d locale
uv run pybabel compile -d locale
uv run pytest tests/unit/audit/test_audit_row_schemas.py::test_dlp_scan_result_literal_includes_new_values tests/unit/plugins/web_fetch/test_i18n_keys.py -v
```
Expected: PASS. (The `t()` call sites for these keys land in Task 3; `pybabel extract` will re-touch `#:` refs then — re-run `compile` if so.)

- [ ] **Step 7: Type-check + commit**

Run: `uv run mypy src/alfred/plugins/web_fetch/auth_allowlist.py src/alfred/audit/audit_row_schemas.py && uv run pyright src/alfred/plugins/web_fetch/auth_allowlist.py`

```bash
git add src/alfred/plugins/web_fetch/auth_allowlist.py src/alfred/audit/audit_row_schemas.py locale/en/LC_MESSAGES/alfred.po tests/unit/audit/test_audit_row_schemas.py tests/unit/plugins/web_fetch/test_i18n_keys.py
git commit -m "$(cat <<'EOF'
feat(339): web.fetch auth allowlist + header/substitution DLP tokens (#339)

Empty-by-default WEB_FETCH_AUTH_SECRET_ALLOWLIST (confused-deputy defence) + the
_SecretSubstituter seam Protocol; two new DlpScanResult tokens
(header_secret_refused, secret_substitution_refused) with lockstep + i18n keys.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 3: Wire the defence + substitution into `dispatch_web_fetch` (+ thread the broker)

**Files:**
- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py` (Step 1b + 1c; new params on `dispatch_web_fetch`)
- Modify: `src/alfred/orchestrator/builtin_tools.py:69` (`build_web_fetch_tool`)
- Modify: `src/alfred/orchestrator/tool_assembly.py:67` (`build_tool_registry`)
- Test: `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`, `tests/unit/orchestrator/test_builtin_tools.py`

**Interfaces:**
- Consumes: `SecretBroker.substitute` (Task 1); `WEB_FETCH_AUTH_SECRET_ALLOWLIST`, `_SecretSubstituter` (Task 2); the new `DlpScanResult` tokens (Task 2).
- Produces: `dispatch_web_fetch(..., broker: _SecretSubstituter, auth_secret_allowlist: frozenset[str] = WEB_FETCH_AUTH_SECRET_ALLOWLIST)`; `build_web_fetch_tool(..., broker: _SecretSubstituter, auth_secret_allowlist: frozenset[str] = WEB_FETCH_AUTH_SECRET_ALLOWLIST)`; `build_tool_registry(..., broker: SecretBroker)`.

- [ ] **Step 1: Write the failing unit tests**

Add to `tests/unit/plugins/web_fetch/test_fetch_dispatcher.py` (mirror `test_url_secret_refused_audits_and_skips_extractor` at `:372`). Use the module's `_dispatch` helper; pass a `broker` fake + `auth_secret_allowlist`:

```python
@pytest.mark.asyncio
async def test_header_raw_secret_refused_audits_and_skips_extractor() -> None:
    """A RAW secret in a header (DLP redacts it) is refused pre-network — not
    redact-and-sent — with a header_secret_refused row; the extractor never fires."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda s: "[REDACTED]" if s.startswith("Bearer ") else s)

    with pytest.raises(WebFetchError):
        await _dispatch(
            audit=audit,
            outbound_dlp=dlp,
            extractor=extractor,
            headers={"Authorization": "Bearer sk-raw"},
        )

    extractor.handle.assert_not_awaited()
    assert audit.append_schema.await_args.kwargs["subject"]["dlp_scan_result"] == "header_secret_refused"


@pytest.mark.asyncio
async def test_off_allowlist_placeholder_refused_audits_and_skips_extractor() -> None:
    """An off-allowlist {{secret:*}} reference is refused (empty allowlist) with a
    secret_substitution_refused row; the extractor never fires."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    with pytest.raises(WebFetchError):
        await _dispatch(
            audit=audit,
            extractor=extractor,
            headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
            auth_secret_allowlist=frozenset(),  # explicit empty (the #339 default)
        )

    extractor.handle.assert_not_awaited()
    assert audit.append_schema.await_args.kwargs["subject"]["dlp_scan_result"] == "secret_substitution_refused"


@pytest.mark.asyncio
async def test_allowlisted_placeholder_substituted_into_wire_headers() -> None:
    """A placeholder whose name is allowlisted + provisioned is substituted into
    the relay request AFTER DLP; the real value never appears in an audit subject."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    class _FakeBroker:
        def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str:
            return text.replace("{{secret:deepseek_api_key}}", "sk-REAL")

    await _dispatch(
        audit=audit,
        extractor=extractor,
        broker=_FakeBroker(),
        headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
        auth_secret_allowlist=frozenset({"deepseek_api_key"}),
    )

    raw_request = extractor.handle.await_args.kwargs["raw_request"]
    assert raw_request.headers["Authorization"] == "Bearer sk-REAL"
    # The real value is never in any audit subject (headers are not an audit field).
    for call in audit.append_schema.await_args_list:
        assert "sk-REAL" not in repr(call.kwargs["subject"])
```

Update the `_dispatch` helper in this test module to accept + forward `broker=` (default a passthrough fake) and `auth_secret_allowlist=` (default `frozenset()`).

- [ ] **Step 2: Update the now-wrong existing test**

Rewrite `test_real_url_sent_on_wire_with_redacted_headers` (`:272`) so it exercises only CLEAN (non-redacted) headers — the mixed secret+clean case now REFUSES (covered by the new test above):

```python
@pytest.mark.asyncio
async def test_real_url_sent_on_wire_with_clean_headers() -> None:
    """The REAL url crosses the wire (the gateway must fetch it); CLEAN header
    values (no DLP redaction) pass through to the relay unchanged. A redacted
    (secret-bearing) header now refuses (see test_header_raw_secret_refused_*)."""
    extractor = _build_extractor(outcome=_make_extracted_outcome())
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda s: s)  # nothing redacted

    await _dispatch(
        extractor=extractor,
        outbound_dlp=dlp,
        url="https://example.com/page",
        headers={"User-Agent": "alfred"},
    )

    raw_request = extractor.handle.await_args.kwargs["raw_request"]
    assert raw_request.url == "https://example.com/page"
    assert raw_request.headers["User-Agent"] == "alfred"
```

- [ ] **Step 3: Run to verify the new tests fail (and the rewritten one)**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_fetch_dispatcher.py -k "secret or clean_headers" -v`
Expected: FAIL — `dispatch_web_fetch` has no `broker`/`auth_secret_allowlist` kwargs; no header refusal.

- [ ] **Step 4: Add the params + Step 1b + Step 1c to `dispatch_web_fetch`**

Add to the signature (`fetch_dispatcher.py:250`), after `outbound_dlp`:

```python
    broker: _SecretSubstituter,
    auth_secret_allowlist: frozenset[str] = WEB_FETCH_AUTH_SECRET_ALLOWLIST,
```

Import at the top: `from alfred.plugins.web_fetch.auth_allowlist import WEB_FETCH_AUTH_SECRET_ALLOWLIST, _SecretSubstituter` and `from alfred.security.secrets import SecretSubstitutionNotAllowed`.

**Step 1b — header raw-secret defence.** Immediately AFTER the existing URL `url_secret_refused` block (after `:386`), before Step 2's allowlist check, add a per-header redaction check. Refactor the audit-emit into a small local helper to avoid copy-paste (DRY — the URL/header/substitution refusals share the subject shape):

```python
    async def _refuse(*, dlp_scan_result: DlpScanResult, message_key: str) -> NoReturn:
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": clean_url,
                "domain": domain,
                "status_code": None,
                "content_handle_id": None,
                "fetch_depth": _FETCH_DEPTH,
                "rate_limit_bucket": None,
                "manifest_commit_hash": config.manifest_commit_hash,
                "trust_tier_of_result": "T3",
                "dlp_scan_result": dlp_scan_result,
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="refused",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        raise WebFetchError(t(message_key))

    # Step 1b: a RAW secret in a header value (DLP redacted it) is refused, not
    # redact-and-sent — HARD rule #6. A {{secret:*}} placeholder is benign text to
    # DLP (no redaction), so it does NOT trip this arm; it is resolved in Step 1c.
    if any(clean_headers[name] != value for name, value in headers.items()):
        await _refuse(
            dlp_scan_result="header_secret_refused",
            message_key="web.fetch.error.header_secret_refused",
        )
```

**Step 1c — substitution (after DLP, before `_RawToolRequest`).** Replace the `_RawToolRequest(... headers=clean_headers ...)` build (`:558`) so it uses substituted headers. Put the substitution just before the `try:` at `:557`:

```python
    # Step 1c: resolve {{secret:<name>}} placeholders in header values via the
    # broker, AFTER DLP (ADR-0017) and BEFORE the relay frame. Off-allowlist /
    # malformed refs refuse loud (HARD rule #6/#7). The empty default allowlist
    # (#339) means every placeholder refuses here.
    try:
        auth_headers = {
            name: broker.substitute(value, allowed_secrets=auth_secret_allowlist)
            for name, value in clean_headers.items()
        }
    except (SecretSubstitutionNotAllowed, UnknownSecretError):
        await _refuse(
            dlp_scan_result="secret_substitution_refused",
            message_key="web.fetch.error.secret_substitution_refused",
        )
```

Then change the request build (`:558-560`) to `headers=auth_headers`:

```python
        raw_request = _RawToolRequest(
            method="GET", url=url, headers=auth_headers, body="", idempotent=True
        )
```

Import `UnknownSecretError` too. (`NoReturn`, `DlpScanResult`, `WEB_FETCH_FIELDS`, `t` are already imported — confirm.)

- [ ] **Step 5: Thread the params through `build_web_fetch_tool` (`builtin_tools.py:69`)**

Add `broker: _SecretSubstituter` and `auth_secret_allowlist: frozenset[str] = WEB_FETCH_AUTH_SECRET_ALLOWLIST` to the signature, and forward them into the `dispatch_web_fetch(...)` call (`:96`). Import the seam from `auth_allowlist`.

- [ ] **Step 6: Thread through `build_tool_registry` (`tool_assembly.py:67`)**

Add `broker: SecretBroker` to the signature and pass `broker=broker` into `build_web_fetch_tool(...)` (`:125`). Import `SecretBroker` from `alfred.security.secrets`. (Rationale: `build_tool_registry` is the composition root; it already receives `settings` — the daemon boot constructs the `SecretBroker` and passes it here explicitly per the #351 config-as-interface convention.)

- [ ] **Step 7: Fix the unit-test callers of `build_web_fetch_tool`**

Add `broker=<passthrough fake>` to `tests/unit/orchestrator/test_builtin_tools.py` (`:80,:107,:146`). A minimal passthrough fake:

```python
class _PassthroughBroker:
    def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str:
        return text
```

- [ ] **Step 8: Run the unit suites**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_fetch_dispatcher.py tests/unit/orchestrator/test_builtin_tools.py -v`
Expected: PASS (new + rewritten tests green).

- [ ] **Step 9: Coverage on the new arms**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_fetch_dispatcher.py --cov=alfred.plugins.web_fetch.fetch_dispatcher --cov-report=term-missing --cov-branch`
Expected: the Step-1b / Step-1c arms are covered (add a happy-path-no-placeholder assertion if a branch is missed — coverage.py does not instrument dict-comprehension conditionals, so pin the else-path explicitly).

- [ ] **Step 10: Type-check + commit**

Run: `uv run mypy src/alfred/plugins/web_fetch/fetch_dispatcher.py src/alfred/orchestrator/builtin_tools.py src/alfred/orchestrator/tool_assembly.py && uv run pyright src/`

```bash
git add src/alfred/plugins/web_fetch/fetch_dispatcher.py src/alfred/orchestrator/builtin_tools.py src/alfred/orchestrator/tool_assembly.py tests/unit/plugins/web_fetch/test_fetch_dispatcher.py tests/unit/orchestrator/test_builtin_tools.py
git commit -m "$(cat <<'EOF'
feat(339): wire header raw-secret defence + broker substitution into web.fetch (#339)

dispatch_web_fetch now refuses a raw secret in a header (header_secret_refused,
mirrors url_secret_refused) and resolves {{secret:*}} placeholders via
broker.substitute AFTER DLP / BEFORE _RawToolRequest, gated by the empty-default
WEB_FETCH_AUTH_SECRET_ALLOWLIST. broker threaded through build_web_fetch_tool +
build_tool_registry. Updates the redact-and-send test to the refuse posture.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 4: ADR-0048

**Files:**
- Create: `docs/adr/0048-web-fetch-authenticated-fetch-secret-substitution.md`

- [ ] **Step 1: Write the ADR** (mirror the format of `docs/adr/0047-web-fetch-handle-cap-reattach-and-inbound-canary.md`)

Sections and content (fill from spec §9):
- **Status:** Accepted (on #339 PR4b-broker merge) · **Date:** 2026-07-07 · **Slice:** #339 PR4b-broker · **Relates to:** ADR-0017 (DLP-before-substitute), ADR-0036 (gateway holds no vault), ADR-0040 (connectivity-free core), ADR-0041 (fused fetch+extract), #347 (blocker 4).
- **Context:** G7-2.5 shipped unauthenticated GET-only web.fetch; HARD rule #6 requires authenticated calls to inject secrets via the broker. #339 is the first live `dispatch_web_fetch` caller.
- **Decision:** `{{secret:<name>}}` in header values, resolved by `SecretBroker.substitute()` after core DLP and before `_RawToolRequest`, gated by a closed empty-by-default `WEB_FETCH_AUTH_SECRET_ALLOWLIST`; raw secrets in URL/headers refused at the core DLP boundary; substitution on header values only.
- **Invariants:** (1) DLP-before-substitute (ADR-0017 extension); (2) closed allowlist ∩ SUPPORTED_SECRETS confused-deputy defence; (3) raw secret in URL/header → refuse (never redact-and-send); (4) the secret is never persisted/audited/logged/ledgered nor in the DLP/planner representation (headers absent from `WEB_FETCH_FIELDS`; ledger hashes the empty body).
- **Positioning:** core-side DLP is the **sole** broker-secret defence; the gateway `broker=None` DLP is a detector for pattern/canary secrets only, NOT an independent DiD layer for broker secrets.
- **Accepted residuals:** the gateway re-scan positive-path residual (a substituted value matching a gateway stage-2 regex is denied `DLP_REDACTED` — moot in #339, empty allowlist; fixture test uses a non-pattern token; gateway auth-header allowance is future work); the empty live allowlist (no live binding in #339); `stdio_transport` async-Protocol convergence deferred; operator config surface for the allowlist deferred.
- Include the **sign-off flag** blockquote (as ADR-0047 does): new secret-substitution security contract → `alfred-security-engineer` sign-off at PR time; treat as provisional until it lands.

- [ ] **Step 2: Markdown-lint the ADR**

Run: `uv run pymarkdownlnt scan docs/adr/0048-web-fetch-authenticated-fetch-secret-substitution.md` (or the repo's markdownlint entrypoint). Fix MD031/MD032 (blank lines around fences/lists), MD004 (no `+`/`-` at wrapped line-start).
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0048-web-fetch-authenticated-fetch-secret-substitution.md
git commit -m "$(cat <<'EOF'
docs(339): ADR-0048 authenticated web.fetch secret-substitution invariant (#339)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Task 5: Adversarial `de-2026-019` (dlp_egress) + security sign-off

**Files:**
- Create: `tests/adversarial/dlp_egress/broker_secret_exfil.yaml`
- Create: `tests/adversarial/dlp_egress/test_de_2026_019_broker_secret_exfil.py`

**Interfaces:**
- Consumes: `build_web_fetch_tool` (Task 3); a fire-spy relay/extractor; the `AdversarialPayload` schema (`tests/adversarial/payload_schema.py`). Mirror `tests/adversarial/capability_bypass/test_cap_2026_006_tool_arg_injection.py` (fixture-filter + REAL dispatch + fire-spy).

- [ ] **Step 1: Write the payload YAML** (`de-2026-019`, next-free id; `de-`=dlp_egress)

```yaml
# broker_secret_exfil.yaml — dlp_egress adversarial payload (#339 PR4b-broker).
# Attack: an authenticated web.fetch is used to exfiltrate a broker secret to an
# allowlisted destination — either by planting a RAW secret in the URL/header, or
# by naming an off-allowlist secret via a {{secret:*}} placeholder. All three
# must be refused at the CORE DLP boundary BEFORE the relay is dialled.
id: de-2026-019
category: dlp_egress
ingestion_path: web.fetch
threat: >-
  A raw broker secret in a web.fetch URL or header, or an off-allowlist
  {{secret:<name>}} reference, must be refused at the core DLP boundary before
  any relay egress. url_secret_refused / header_secret_refused /
  secret_substitution_refused audit rows fire; the relay is never dialled.
payload:
  raw_secret_header: "Bearer sk-live-EXFIL"
  off_allowlist_ref: "Bearer {{secret:anthropic_api_key}}"
expected_outcome: caught_by_dlp
provenance: "#339 PR4b-broker (#347 blocker 4); ADR-0048"
references:
  - "docs/adr/0048-web-fetch-authenticated-fetch-secret-substitution.md"
  - "https://github.com/alfred-os/AlfredOS/issues/347"
merge_blocker: true
```

(Confirm the exact required field names against `payload_schema.py::AdversarialPayload` — `id`, `category`, `threat`, `payload`, `expected_outcome`, `provenance`, `references`, `ingestion_path`; add `note`/`merge_blocker` only if the schema declares them.)

- [ ] **Step 2: Write the harness test** (mirror `test_cap_2026_006_tool_arg_injection.py`)

Structure:
1. A `_FireSpy` extractor whose `handle` records that it was called (the "relay dialled" signal) and must NOT fire.
2. Build the real `web.fetch` tool via `build_web_fetch_tool` with a REAL `SecretBroker` (env has `anthropic_api_key` set to a benign value, to prove it's still refused off-allowlist) + the default empty `auth_secret_allowlist` + a real `OutboundDlp` whose broker knows a planted raw secret.
3. Three parametrised scenarios, each asserting `WebFetchError` (or the domain refusal), the expected `dlp_scan_result` audit token, and `fire_spy.called is False`:
   - raw secret in URL → `url_secret_refused`;
   - raw secret in header → `header_secret_refused`;
   - `{{secret:anthropic_api_key}}` (off empty allowlist) → `secret_substitution_refused`.
4. Load `broker_secret_exfil.yaml` via the corpus loader and assert its schema validates (the collection conftest already does this; add an explicit `AdversarialPayload.model_validate` smoke assert).

```python
import pytest
from alfred.plugins.web_fetch.errors import WebFetchError

@pytest.mark.parametrize(
    ("scenario", "url", "headers", "expected_token"),
    [
        ("raw_url", "https://example.com/?k=sk-live-EXFIL", {}, "url_secret_refused"),
        ("raw_header", "https://example.com/", {"Authorization": "Bearer sk-live-EXFIL"}, "header_secret_refused"),
        ("off_allowlist", "https://example.com/", {"Authorization": "Bearer {{secret:anthropic_api_key}}"}, "secret_substitution_refused"),
    ],
)
@pytest.mark.asyncio
async def test_broker_secret_exfil_refused_pre_relay(scenario, url, headers, expected_token, ...):
    # ... build the real tool with a fire-spy extractor + a broker that knows
    #     'sk-live-EXFIL' as a redactable secret and 'anthropic_api_key'=<benign> ...
    with pytest.raises(WebFetchError):
        await tool.dispatch(_invocation(url=url, headers=headers))
    assert fire_spy.called is False
    assert audit.last_subject["dlp_scan_result"] == expected_token
```

(Fill the harness body from the `cap-2026-006` scaffolding: `_invocation`, the audit spy, and the allowlist config so `example.com` is domain-allowed — the refusal must be the SECRET check, not `domain_not_allowed`.)

- [ ] **Step 3: Run the adversarial entry**

Run: `uv run pytest tests/adversarial/dlp_egress/test_de_2026_019_broker_secret_exfil.py -v`
Expected: PASS (3 scenarios) + schema-validation smoke.

- [ ] **Step 4: Corpus health/density gates**

Run: `uv run pytest tests/adversarial/test_payload_schema.py tests/adversarial/test_corpus_density.py tests/adversarial/test_corpus_health.py -v`
Expected: PASS (id/prefix/category coherence; density count for `dlp_egress` includes `de-2026-019`).

- [ ] **Step 5: Commit + request security sign-off**

```bash
git add tests/adversarial/dlp_egress/broker_secret_exfil.yaml tests/adversarial/dlp_egress/test_de_2026_019_broker_secret_exfil.py
git commit -m "$(cat <<'EOF'
test(339): adversarial de-2026-019 — broker-secret web.fetch exfil refused pre-relay (#339)

Raw secret in URL/header + off-allowlist {{secret:*}} all refused at the core DLP
boundary before any relay egress (fire-spy proves no dial). #347 blocker 4.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

Dispatch `alfred-security-engineer` for corpus sign-off (hard merge gate) — capture the sign-off note for the PR body.

---

## Task 6: security.md correction, positive-path integration test, docs, full verification

**Files:**
- Modify: `docs/subsystems/security.md`
- Modify: `tests/integration/orchestrator/test_tool_assembly.py` / `test_act_loop_real_chain.py` / `test_tool_dispatch_timeout_audit_postgres.py` + `tests/adversarial/capability_bypass/test_cap_2026_006_tool_arg_injection.py` (thread `broker` through the `build_web_fetch_tool` / `build_tool_registry` callers)

- [ ] **Step 1: Thread `broker` through the remaining integration/adversarial callers**

Add the `broker=` kwarg to every remaining `build_web_fetch_tool(...)` / `build_tool_registry(...)` call listed in the File Structure threading note. Integration callers that build a real `SecretBroker` may pass one; unit-ish callers pass the passthrough fake.

- [ ] **Step 2: Add ONE positive-path integration assertion**

In `tests/integration/orchestrator/test_tool_assembly.py` (loopback relay), add a case: a fixture allowlist `frozenset({"deepseek_api_key"})` + a broker whose `deepseek_api_key` is a **benign** token (NOT an API-key-pattern that a gateway stage-2 regex would deny), a header `Authorization: Bearer {{secret:deepseek_api_key}}` → assert the loopback echo server receives the substituted `Bearer <benign>` header AND the stored T2 + audit rows contain no secret. (Documents the gateway pass-through; the empty production allowlist keeps it off live.)

- [ ] **Step 3: Non-vacuous secret-absence guard**

Add a test that, after a positive-path fetch, scans the full audit-row set + the serialized ledger row for the fixture secret value and asserts absence (mirror PR3's non-vacuous HARD#5 marker guard).

- [ ] **Step 4: Correct `docs/subsystems/security.md`**

In the outbound-DLP / egress section, add/adjust the audit-vocabulary and DLP-positioning text: core-side DLP over URL + headers is the **sole** broker-secret defence; the gateway relay DLP runs `broker=None` (detector for pattern/canary only, denies on change); `{{secret:*}}` substitution happens after core DLP, before the relay frame; header raw-secret → `header_secret_refused`, off-allowlist ref → `secret_substitution_refused`. Note the gateway re-scan positive-path residual.

- [ ] **Step 5: Full verification (release-blocking — touches `src/alfred/security/`)**

Run:
```bash
make check
uv run pytest tests/unit -q
uv run pytest tests/adversarial -q
uv run pytest tests/integration/orchestrator -q
uv run pybabel compile --statistics -d locale
```
Expected: all green. (The macOS integration lane can flake under load — verify any suspect in isolation and trust Linux CI, per project norms. Docker Hub `postgres:18` pull flakes → re-run.)

- [ ] **Step 6: Markdown-lint the docs**

Run: `uv run pymarkdownlnt scan docs/subsystems/security.md docs/adr/0048-web-fetch-authenticated-fetch-secret-substitution.md docs/superpowers/plans/2026-07-07-issue-339-pr4b-broker-secret-substitution.md`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add docs/subsystems/security.md tests/integration/orchestrator tests/adversarial/capability_bypass/test_cap_2026_006_tool_arg_injection.py
git commit -m "$(cat <<'EOF'
test(339): positive-path integration + security.md DLP-positioning for broker substitution (#339)

Thread broker through the remaining build_web_fetch_tool/build_tool_registry
callers; loopback positive-path substitution assertion + non-vacuous
secret-absence guard; security.md core-DLP-is-sole-broker-defence correction.

MrReasonable <4990954+MrReasonable@users.noreply.github.com>
EOF
)"
```

---

## Post-implementation (outside this plan's tasks)

Per the standing cadence: autosquash any fixups → push → FULL `/review-pr` fleet (architect + security ALWAYS) + CodeRabbit CLI **and** cloud → resolve every thread → `alfred-security-engineer` M4 sign-off → poll `reviewDecision` + `mergeStateStatus` → non-admin `gh pr merge --rebase` on green (NEVER `--admin`). After merge: PR4c (cap-2026-006 corpus breadth + nightly real-LLM smoke) → **#339 epic CLOSES**.

---

## Self-Review

**Spec coverage** (against `docs/superpowers/specs/2026-07-07-issue-339-pr4b-broker-authenticated-fetch-design.md`):
- §3 substitute() primitive → Task 1. ✓
- §4 empty allowlist → Task 2. ✓
- §5 data-flow wiring (Steps 1b/1c, broker threading) → Task 3. ✓
- §6 secret-absence invariants → Task 3 (audit-subject assertion) + Task 6 (non-vacuous guard). ✓
- §7 gateway residual → Task 4 (ADR) + Task 6 (security.md). ✓
- §8 refusal vocab (2 tokens + i18n + lockstep) → Task 2; exception handling → Task 3. ✓
- §9 ADR-0048 → Task 4. ✓
- §10 adversarial de-2026-019 + security sign-off → Task 5. ✓
- §11 testing (unit/integration/adversarial/non-vacuous) → Tasks 1,3,5,6. ✓
- §12 one PR, 6 tasks → this plan. ✓

**Placeholder scan:** the only intentionally-open item is Task 5 Step 2's harness body (marked "fill from cap-2026-006 scaffolding") and the ADR prose (Task 4, section content enumerated) — both are structured with exact tokens/assertions, not vague "add tests." No `TODO`/`TBD` in source steps.

**Type consistency:** `substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str` is identical across Task 1 (definition), Task 2 (`_SecretSubstituter` Protocol), and Task 3 (call sites + fakes). `dispatch_web_fetch`/`build_web_fetch_tool` gain `broker: _SecretSubstituter` + `auth_secret_allowlist: frozenset[str] = WEB_FETCH_AUTH_SECRET_ALLOWLIST`; `build_tool_registry` gains `broker: SecretBroker`. Token names `header_secret_refused` / `secret_substitution_refused` are identical in Task 2 (Literal + lockstep + i18n) and Task 3 (emit sites). ✓
