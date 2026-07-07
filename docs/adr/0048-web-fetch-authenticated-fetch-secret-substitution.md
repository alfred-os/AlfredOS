# ADR-0048 — Authenticated `web.fetch` — broker secret-substitution invariant

- **Status**: Accepted (on #339 PR4b-broker merge)
- **Date**: 2026-07-07
- **Slice**: #339 (LLM tool-calling epic), PR4b-broker
- **Relates to**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)
  (DLP-before-substitute — this extends its ordering to a second consumer),
  [ADR-0036](0036-gateway-adapter-hosting-inversion.md) (gateway holds no vault —
  `broker=None` at the gateway), [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md)
  (connectivity-free core / Spec C egress control plane), [ADR-0041](0041-web-fetch-fused-fetch-extract-contract.md)
  (fused fetch+extract contract — this ADR extends its Decision with authenticated headers),
  [ADR-0047](0047-web-fetch-handle-cap-reattach-and-inbound-canary.md) (deferred the broker
  secret-injection residual to PR4b — closed here), issue #339 (LLM tool-calling epic), issue #347
  (the #339-first-live-caller merge-blocker obligation list — this closes blocker 4, the last of
  the five)

> **Sign-off flag.** This ADR records a new secret-substitution security contract — the first
> place a broker-held secret is deliberately placed on an outbound request. ADRs are
> agent-authored and are not human-gated the way `CLAUDE.md` / `PRD.md` are (self-improvement
> rule #4), so this record ships in the same PR as the code. A contract of this shape still wants
> `alfred-security-engineer` sign-off at PR time, not only a merged ADR — flagged here and on the
> #339 PR4b-broker pull request; treat the contract as provisional until that sign-off lands.

## Context

G7-2.5 shipped `web.fetch` as unauthenticated GET-only (ADR-0041): no code path could attach an
auth header, so there was no secret-exposure surface to defend. HARD rule #6 (`CLAUDE.md`) requires
that secrets reach a plugin call only via the broker substituting at the tool-call boundary — never
as an env var or a value a plugin (or the planner) can read directly. #339 is the first PR to give
`dispatch_web_fetch` a live caller (the agentic act-phase loop, ADR-0046), which is also the first
point a planner-authored request can carry a header the operator wants authenticated. ADR-0047
recorded this as an open #347 residual ("broker `SecretId`-based authenticated fetch") and deferred
it to PR4b. This ADR closes it — the last of the five #347 blockers.

The threat model is asymmetric: the planner (LLM) is
[T3](../glossary.md#t3-untrusted-ingestion-tier)-influenced and untrusted, yet #347 asks for a
contract where "the caller supplies a broker `SecretId` per auth header." #339 ships with no operator-bound authenticated integration, so the design closes the
positive surface by default (an empty allowlist) while still building and proving the full
mechanism — mirroring the closed-allowlist posture `adapter_credential_resolver` already uses for
comms adapter credentials.

## Decision

A planner-authored request header may contain a `{{secret:<name>}}` placeholder. `SecretBroker.substitute()`
(`src/alfred/security/secrets.py:668`) resolves it
(`src/alfred/plugins/web_fetch/fetch_dispatcher.py:461`) — **after** core DLP has scanned the header
value and **before** the wire `_RawToolRequest` is built
(`src/alfred/plugins/web_fetch/fetch_dispatcher.py:640`) — gated by a closed,
empty-by-default allowlist, `WEB_FETCH_AUTH_SECRET_ALLOWLIST`
(`src/alfred/plugins/web_fetch/auth_allowlist.py:17`). A raw (non-placeholder) secret value in a
URL or header is refused at the core DLP boundary, never redacted-and-sent. Substitution applies to
header values only — a `{{secret:...}}` token in the URL is left as literal text, since a raw
secret in the URL already refuses (`url_secret_refused`) and auth belongs in headers, not query
strings.

## Invariants

1. **DLP-before-substitute.** `substitute()` assumes its input is already DLP-clean text (ADR-0017's
   ordering, now shared by a second consumer): DLP scans the placeholder frame first, so a raw
   secret is caught by the existing redact-then-refuse arm (`header_secret_refused`) before
   substitution ever runs. `substitute()` does not itself detect raw secrets.
2. **Closed allowlist ∩ `SUPPORTED_SECRETS` — confused-deputy defence.** A placeholder resolves only
   if `<name>` is in *both* the caller's `allowed_secrets` and the broker's `SUPPORTED_SECRETS`
   registry (`secrets.py:668-695`). A **malformed or off-(caller's)-allowlist** name raises
   `SecretSubstitutionNotAllowed` — never a broker passthrough of an attacker-named secret. A
   well-formed, allowlisted name that is not itself a known/provisioned `SUPPORTED_SECRETS` entry
   raises `UnknownSecretError` instead (delegated from `SecretBroker.get`) — the two exceptions are
   distinct arms, not interchangeable (`fetch_dispatcher.py`'s Step 1c catches both and logs the
   discriminating `error_type`, never the ref, before refusing). This mirrors
   `adapter_credential_resolver`'s closed `_ADAPTER_SECRET_ALLOWLIST`.
3. **Raw secret in URL/header → refuse, never redact-and-send.** `url_secret_refused` (G7-2.5,
   unchanged) and the new `header_secret_refused` (`fetch_dispatcher.py:436-440`) both raise loud
   rather than forwarding a DLP-redacted value the destination could never authenticate with.
4. **The secret is never persisted in plaintext, audited, logged, nor in the DLP/planner
   representation.** `WEB_FETCH_FIELDS` carries no headers field, so audit rows never see a
   header value. The egress ledger's `commit_intent` folds the (already-substituted) request
   headers into `compute_egress_body_hash()`'s one-way sha256 integrity digest, alongside the
   request descriptor and the redacted body (`src/alfred/egress/relay_client.py:245-249`,
   `src/alfred/egress/egress_id.py:78`) — the digest is a fixed-width hash, never recoverable back
   to the header value, so a substituted secret contributes to it without being stored anywhere in
   plaintext. Refusal audit rows and log lines carry the secret *name* only
   (`SecretSubstitutionNotAllowed`'s payload, or the forensic `error_type` log the Step 1c `except`
   arm emits), never the value.

## Positioning: core DLP is the sole broker-secret defence

Core-side `OutboundDlp` (`broker` wired) is the **sole** defence against a broker secret reaching
the wire in the wrong place. The gateway relay builds its own re-scan `OutboundDlp` with
`broker=None` (ADR-0036: the gateway holds no vault) — it re-scans the body, URL, and forwarded
header values against pattern (stage-2) and canary (stage-3) rules only, and **denies** on any
redaction (`src/alfred/gateway/egress_relay.py:447-466`, `DLP_REDACTED`). It cannot recognize a
broker secret it has no knowledge of; it is a detector for pattern-shaped and canary secrets, not
an independent defence-in-depth layer for broker secrets. This corrects a positioning gap #347
blocker 4 named explicitly: the gateway's re-scan must not be read as a second line of defence
for secrets the core substituted.

## Consequences

### Positive

- The reusable `SecretBroker.substitute()` primitive exists and is proven (unit + fixture-binding
  integration tests), unblocking `stdio_transport.py`'s aspirational `_SecretBrokerSubstitute`
  Protocol from staying purely aspirational.
- All five #347 blockers on #339's first live `dispatch_web_fetch` caller are now closed (1 and 5
  by ADR-0047 / PR4a #401, 3 by PR3 #399, 2 by PR4b-audit #402; 4 here) — the epic's last
  cross-cutting security residual is resolved.
- Zero live confused-deputy exfiltration surface ships in #339: the empty allowlist means every
  planner-authored `{{secret:*}}` placeholder refuses in production, while the substitution path
  itself is exercised end-to-end by a fixture allowlist in tests.

### Negative

- **Gateway re-scan positive-path residual.** A future substituted secret whose value happens to
  match a gateway stage-2 pattern regex would be denied fail-closed at the gateway
  (`DLP_REDACTED`), breaking that authenticated fetch. Moot in #339 (empty allowlist ⇒ nothing is
  substituted in production; the fixture test's token is a non-pattern value that passes the
  loopback relay leg). A general fix — a gateway auth-header allowance — is future work, deferred
  until a real authenticated integration lands.
- **Exception-context name residual.** The raised `WebFetchError`'s containment is structural, not
  a product of traceback suppression: `.ref` (the possibly attacker-influenced secret name) never
  appears in `WebFetchError.__str__` / `__repr__` / `.args` — its message is the FIXED catalog
  string from `t(message_key)`. `_refuse`'s `raise ... from None` additionally sets
  `__suppress_context__ = True` (governing DEFAULT traceback rendering, e.g.
  `traceback.format_exception`), but does **not** clear `__context__` itself — the caught
  `UnknownSecretError` (whose `str()` embeds the secret *name*, never a value) remains attached
  there and reachable to any code that inspects `exc.__context__` directly rather than going
  through the suppressed default renderer. Two narrow windows follow: (a) a direct `__context__`
  read bypasses the suppression, and (b) an audit-write failure inside `_refuse` during a
  substitution refusal would raise a NEW exception that chains the un-suppressed
  `UnknownSecretError` (no `from None` on that separate raise) into a rendered traceback. Both leak
  only a secret *name* (HARD rule #6 — values — still holds), only under a direct `__context__`
  inspection or a simultaneous audit-infrastructure failure, and are unreachable in #339 (the empty
  allowlist means only the `SecretSubstitutionNotAllowed` arm fires in practice, whose `str()` does
  not echo the reference). Traceback and structlog rendering are verified clean of the suppressed
  context.
- **Forward gate: a per-secret↔destination binding is REQUIRED before any live allowlist entry.**
  `WEB_FETCH_AUTH_SECRET_ALLOWLIST` gates by SECRET NAME only — a planner that can name an
  allowlisted secret can pair it, via the `url` argument the same call also controls, with ANY
  domain the three-way `AllowlistIntersection` permits. Populating a real entry without ALSO adding
  a secret↔domain binding (Option B below — rejected as the *sole* mechanism for #339's
  empty-allowlist scope, but promoted here to a REQUIRED precondition for any future entry) reopens
  the exact confused-deputy shape this ADR closes: an infra secret meant for one destination could
  be sent, by planner choice, to a different allowlisted domain. This is not optional hardening — a
  future PR that populates a live allowlist entry without a domain binding does not satisfy this
  ADR's confused-deputy invariant (Invariant 2) and must not merge on the strength of this ADR
  alone.
- **One-broker pin (forward-looking, #338).** The Positioning section below treats core-side
  `OutboundDlp` (broker-bound) as the sole broker-secret defence for a *single* live secret set.
  When #338 wires the first live `dispatch_web_fetch` caller, `build_tool_registry`'s `broker=`
  kwarg MUST be the SAME `SecretBroker` instance backing that caller's `outbound_dlp=` — never a
  second, independently constructed broker. Two divergent instances would let a secrets hot-reload
  land on one but not the other, silently splitting the DLP-scan snapshot (Stage 1 redaction) from
  the `substitute()` snapshot and breaking the DLP-before-substitute ordering Invariant 1 depends
  on. See `docs/subsystems/security.md`'s matching pin.

### Neutral

- The live allowlist ships empty — no operator-bound authenticated integration exists in #339.
- `stdio_transport.py`'s async `_SecretBrokerSubstitute` Protocol is not converged onto this
  synchronous primitive; documented as a follow-up, out of scope here.
- The operator-facing config surface to populate `WEB_FETCH_AUTH_SECRET_ALLOWLIST` is deferred;
  the allowlist is code-defined only.

## Why the allowlist ships empty

Every current `SUPPORTED_SECRETS` entry (`deepseek_api_key`, `anthropic_api_key`,
`discord_bot_token`, `audit.hash_pepper`, `quarantine_provider_api_key`) is an AlfredOS
infrastructure credential, not a third-party web-auth token. Allowlisting any of them for outbound
`web.fetch` would hand a planner-influenced request a path to exfiltrate an infra secret to an
arbitrary destination domain — a confused-deputy attack, not a feature. A future authenticated
integration therefore requires two deliberate additions, not one: a new `SUPPORTED_SECRETS` entry
*and* a `WEB_FETCH_AUTH_SECRET_ALLOWLIST` entry, each behind operator configuration and its own
security review.

## Alternatives considered

### Option B — operator domain→secret binding, planner never names secrets

Bind a secret to a domain in operator config; the dispatcher looks up the binding by destination
domain, and the planner never writes a `{{secret:*}}` placeholder at all. Tighter (zero planner
secret-name surface) but diverges from blocker 4's literal wording ("the caller supplies a broker
`SecretId` per auth header") and does not produce the reusable `substitute()` primitive
`stdio_transport.py` is waiting on. **Rejected as the SOLE mechanism for #339's empty-allowlist
scope — but the domain-binding idea it proposes is not discarded.** The Consequences → Negative
"Forward gate" entry above promotes it to a REQUIRED precondition: no future PR may populate a live
`WEB_FETCH_AUTH_SECRET_ALLOWLIST` entry on the strength of the name-only allowlist alone; it must
also add a secret↔destination binding of this shape, or an equivalent, before that entry can be
considered safe.

### Option C — defence + ADR + primitive only, no positive wiring

Ship `substitute()`, the allowlist, the negative (raw-secret-refusal) defence, and this ADR, but
leave `dispatch_web_fetch` never calling `substitute()` at all. Smaller, but leaves blocker 4's
"the dispatcher performs broker substitution before building `_RawToolRequest`" only partially
satisfied, and the primitive would ship with zero consumers.

## References

- [PRD §7.1](../../PRD.md#71-security--prompt-injection-defense) — Security & Prompt-Injection
  Defense
- [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — DLP-before-substitute
  ordering (§ trust-tier / dual-LLM completion)
- [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — gateway holds no vault (`broker=None`)
- [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) — connectivity-free core
  / mandatory egress chokepoint (Spec C)
- [ADR-0041](0041-web-fetch-fused-fetch-extract-contract.md) — `web.fetch` fused fetch+extract
  contract (the ADR this one extends)
- [ADR-0047](0047-web-fetch-handle-cap-reattach-and-inbound-canary.md) — deferred this residual to
  PR4b
- Issue #339 (LLM tool-calling epic) — PR4b-broker
- Issue #347 — the #339-first-live-caller merge-blocker obligation list (blocker 4, the last of
  five, closed here)
