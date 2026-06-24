## Summary

<!-- One paragraph describing what this change does and why. -->

## Related issue(s)

<!-- e.g. Closes #123, Refs #456 -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor
- [ ] Documentation
- [ ] Tests
- [ ] Build / CI / chore
- [ ] Touches a trust boundary (see Trust-boundary review below)

## Test plan

<!-- What did you add or run? Reviewer will look for this. -->

- [ ] Unit tests pass locally: `uv run pytest tests/unit -q`
- [ ] Integration tests pass (if applicable): `uv run pytest tests/integration`
- [ ] Adversarial corpus passes (release-blocking on **every** PR): `uv run pytest tests/adversarial`
- [ ] Lint and types clean: `uv run ruff check . && uv run mypy src/`

## Trust-boundary review

- [ ] This PR does NOT touch `src/alfred/security/`, the secret broker, the capability gate, the DLP layer, or the audit log writers.
- [ ] OR — this PR touches a trust boundary, and I have:
  - [ ] Extended the adversarial corpus to cover the new boundary behaviour (the corpus runs on every PR via the `Adversarial corpus` gate — a trust-boundary change should _add_ payloads, not just pass the existing ones)
  - [ ] Maintained 100% line and branch coverage on the changed boundary
  - [ ] Described the threat-model implications in the Summary above

## Documentation

- [ ] PRD updated if a structural invariant changed
- [ ] CLAUDE.md updated if conventions or commands changed
- [ ] ADR added under `docs/adr/` if architectural

## Notes for reviewers

<!-- Anything reviewers should focus on, or context they need. -->
