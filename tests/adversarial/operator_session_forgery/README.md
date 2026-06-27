# Operator-session forgery adversarial corpus

Attacks against the CLI operator-session boundary (`alfred login` / `whoami`
/ `logout`; #153). Covers planted session files, token-replay on different
machines, machine-id mismatch, host-rebind attacks, and session-file
log-injection.

**Attack vectors covered**

- Planted `~/.config/alfred/session` with an attacker-crafted token (token
  not in DB → `OPERATOR_SESSION_REFUSED_FIELDS(reason="planted_file")`).
- Token-reuse on a different machine (machine-id binding rejects;
  `reason="machine_mismatch"`).
- Host-rebind attempt after laptop dock change (`reason="host_mismatch"`).
- Token-user-id mismatch — planted file with a VALID token but a DIFFERENT
  user_id field (PR-S4-5 round-2 closure 11; `reason="token_user_mismatch"`).
- Expired session that the client tries to refresh (refused with
  `reason="expired"`).
- Revoked session attempted reuse (`reason="revoked"`).
- Planted file with malformed `attempted_user_id` (round-2 closure 4 sec-4:
  log-injection refused via Pydantic field validator; refusal emits
  `reason="planted_file_invalid_user_id"` with `attempted_user_id=None`).

**Prefix.** `osf-`

**Owning PR.** PR-S4-5 (CLI operator session).

**Ingestion paths.** `operator_session_file`.

**Expected outcomes.** `refused` or `audit_row_emitted` anchored to
`OPERATOR_SESSION_REFUSED_FIELDS` with a closed-vocab `reason` taken from
the discriminator list in `audit_row_schemas.py`.

**Status at graduation.** Minimum 3 entries.

## Coverage matrix

Maps each enumerated attack vector to the Slice-4 PR / task that lands its implementing
payload. Vectors labelled **TBD — Slice-4 follow-on (no current task)** have no
implementing payload in any current Slice-4 plan; they require a follow-on PR or
an explicit out-of-scope decision before Slice-4 closes. The matrix is the
contract between this category's threat model and the slice's task graph —
drift is a release-blocker.

| Attack vector | Owning PR / Task |
| --- | --- |
| Planted file with attacker-crafted token | PR-S4-5 (`osf-2026-001` — `planted_file` refusal) |
| Token-reuse on different machine | PR-S4-5 (`osf-2026-002` — `machine_mismatch` refusal) |
| Host-rebind after laptop dock change | PR-S4-5 (`osf-2026-003` — `host_mismatch` refusal) |
| Planted file: VALID token + DIFFERENT user_id | PR-S4-5 (`osf-2026-006` — `token_user_mismatch` refusal) |
| Expired session refresh attempt | PR-S4-5 (`osf-2026-004` — `expired` refusal) |
| Revoked session re-use | PR-S4-5 (`osf-2026-005` — `revoked` refusal) |
| Planted file: log-injection via malformed `attempted_user_id` | PR-S4-5 (`osf-2026-007` — Pydantic refusal pre-emit) |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
