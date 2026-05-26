# 0013 — Defer T1 operator tier, T3 untrusted ingestion, and dual-LLM split to Slice 3

- **Status**: Accepted
- **Date**: 2026-05-26
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
- **Supersedes**: ADR-0008 (in part)
- **Superseded by**: —

## Decision (summary)

Slice 2 ships multi-user identity (T2 only), Discord adapter, file-backed secret broker. T1, T3, and the
dual-LLM split — committed by ADR-0008 to land in Slice 2 — are rescheduled to Slice 3.

## Rationale (one-line)

The Slice-2 surface area (identity + Discord + file broker) is already large enough for one slice; the
dual-LLM split without the upstream MCP plugin transport (Slice 3) is wasted scaffolding that Slice 3 rewrites.

## Author

`alfred-docs-author` writes the full body in PR E from the [Slice 2 design spec §0](../superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md#0-slice-2-prerequisites-land-before-anything-else).
The placeholder above is sufficient for PRs B-D to cite. Long-form rationale, alternatives, and consequences
land in PR E.
