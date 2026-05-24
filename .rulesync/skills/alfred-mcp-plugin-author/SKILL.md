---
name: alfred-mcp-plugin-author
description: >-
  Use when authoring or testing an MCP plugin for AlfredOS - comms adapter,
  memory backend, integration, or any capability plugin. Covers manifest format,
  capability declarations, hybrid-isolation rules, and the AlfredOS-specific
  extensions to standard MCP.
targets:
  - '*'
---
# Authoring an MCP plugin for AlfredOS

Every capability beyond the agent core is an MCP plugin. This skill captures the AlfredOS conventions on top of standard MCP.

## Layout

```
plugins/<name>/
├── manifest.json           # required
├── README.md               # what it does, when to invoke
├── src/                    # plugin implementation (any language)
├── tests/                  # happy-path + error-path + refusal tests
└── Dockerfile              # required for containerized (untrusted) plugins
```

## Manifest (required fields)

- `name` — kebab-case
- `version` — semver
- `description` — one line
- `trust_tier` — `official` (in-process) or `third_party` (containerized)
- `entrypoint` — command to run (stdio MCP server)
- `capabilities` — declared capabilities the plugin needs:
  - `network.allowlist` — array of domain patterns; empty means no network
  - `fs.read` / `fs.write` — array of path patterns
  - `secrets` — array of secret IDs to be substituted at the tool-call edge
- `provides` — array of MCP tools/resources/prompts the plugin exposes

## Hybrid isolation

- `trust_tier: official` plugins run as in-process subprocesses (stdio).
- `trust_tier: third_party` plugins run in their own container with capabilities enforced by Docker / OS-level controls.
- An agent-authored plugin always starts as `third_party`.

## Hooks AlfredOS adds on top of standard MCP

- Trust-tier tagging on tool outputs (`output_trust_tier`) — defaults to `T3` for any external data.
- Capability grant checks before each call — the plugin can be told "no, you cannot do that for this request" by the host.
- DLP scan on every output before it reaches the orchestrator.
- Audit-log emission on every call (with `trace_id`, `user_id`, capability grant snapshot).

## Tests required

1. **Happy path** — typical call returns expected output.
2. **Error path** — upstream failure → plugin reports the error correctly.
3. **Out-of-scope refusal** — plugin refuses gracefully when asked to do something outside its single responsibility.
4. **Capability denial** — when the host denies a capability, the plugin doesn't crash and reports it correctly.

## Common antipatterns

- Reading secrets from env vars instead of through the broker.
- Catching and swallowing errors in trust-boundary paths.
- Doing work that should be done in a separate plugin (single responsibility).
- Calling tools that aren't in the declared capabilities.
