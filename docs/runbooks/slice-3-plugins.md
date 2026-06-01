# Slice 3 — MCP plugin transport runbook

Operator-facing walkthrough for the Slice-3 plugin subsystem: the
fail-closed launcher, the sandbox policy directory, the quarantine UID, and
the audit-stream events the supervisor consumes. Companion to the unit
tests at
[`tests/unit/plugins/test_plugin_launcher_stub.py`](../../tests/unit/plugins/test_plugin_launcher_stub.py)
— the tests pin the contract; this runbook is the human-readable deployment
story.

If you have not read [`docs/runbooks/slice-2-discord-smoke.md`](./slice-2-discord-smoke.md)
yet, do that first. Slice 3 builds on the Slice-2 deployment shape (Postgres
+ Redis + the operator identity row), and the prerequisites carry over.

## Prerequisites

- Slice-2 deployment is healthy: `docker compose ps` shows
  `alfred-postgres`, `alfred-redis`, and the supervisor in a `running` state.
- The operator row exists (`docker compose run --rm alfred-core user list`
  shows at least one `authorization = operator` user).
- `~/.config/alfred/secrets.toml` exists at `chmod 600` (the Slice-2 setup
  script wrote it; the operator owns the backup-exclusion).
- The host has `runuser` available on PATH — on Debian / Ubuntu it ships in
  `util-linux`, which is a base package. macOS dev hosts may skip this; the
  launcher emits the macOS deviation audit row on those.

## Step 1 — Provision the quarantine UID

The launcher drops privilege via `runuser -u <UID>` before exec'ing the
plugin. The target UID must exist before the first plugin spawn.

Recommended approach: a `systemd-sysusers` fragment so the account is
re-created on first boot regardless of provisioning tool.

```ini
# /etc/sysusers.d/alfred-quarantine.conf
u alfred-quarantine - "AlfredOS plugin quarantine" /var/lib/alfred-quarantine /usr/sbin/nologin
```

Then:

```sh
sudo systemd-sysusers
id alfred-quarantine   # confirm the account exists
```

The UID does not own any persistent state directly — the supervisor passes
data over the JSON-RPC framing on stdio. The home directory is a parking
space for runuser's PAM session.

Override the default with `ALFRED_PLUGIN_UID` in `.env` if you must use a
different name. The launcher reads it at every spawn.

## Step 2 — Sandbox policy directory

The launcher reads `<DIR>/<plugin_id>.policy` and refuses to spawn if the
file is missing (production fail-closed). Default `DIR` is
`/etc/alfred/sandbox`; override with `ALFRED_SANDBOX_POLICY_DIR`.

```sh
sudo install -d -m 755 -o root -g root /etc/alfred/sandbox
```

Per-plugin policy files are free-form bytes — Slice 3 reads the file's
existence, not its contents (the Slice-4 sandbox engine will parse them).
A placeholder is fine for the supervisor smoke test:

```sh
sudo install -m 644 /dev/null /etc/alfred/sandbox/alfred.example.policy
```

When the supervisor tries to spawn a plugin whose policy file is missing,
the launcher emits `plugin.launcher_no_sandbox_policy` on stderr and exits
1. The audit row carries the plugin id; the supervisor renders the localised
message from the catalog.

## Step 3 — Verify the launcher contract

The launcher is invokable directly for verification. The `--help` flag
prints the contract; pass an obviously bad plugin id to confirm the
charset gate fires:

```sh
bin/alfred-plugin-launcher.sh --help
# Expect: usage + env vars + exit codes.

bin/alfred-plugin-launcher.sh 'alfred."evil' /bin/true
# Expect: stderr "plugin.launcher_plugin_id_invalid", exit 1.
```

The supervisor never invokes the launcher with an unsafe id — manifest
parsing rejects them earlier — but the launcher's charset gate is the
last fail-closed boundary. If it ever fires in production, an upstream
validation regression has happened; treat the audit row as a P1.

### Bare i18n keys on stderr — what to expect

The launcher does not emit hardcoded English. Instead it prints one of four
bare i18n keys on stderr, plus optional `key=value` context fields:

| Key | Meaning |
| --- | --- |
| `plugin.launcher_plugin_id_invalid` | plugin_id failed the safe-charset regex |
| `plugin.launcher_unsandboxed_rejected` | dev-only escape hatch refused in production |
| `plugin.launcher_no_sandbox_policy` | sandbox policy file missing |
| `plugin.launcher_uid_drop_unavailable` | Linux host without `runuser` — refused to exec un-dropped |

The supervisor parses stderr, persists the audit row, and renders the
localised message for any operator surface (CLI, TUI, log dashboard).

The supervisor also captures the two JSON event lines emitted on the
documented-deviation paths:

```json
{"event":"supervisor.config_insecure","insecure_config_key":"ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED","plugin_id":"alfred.example"}
{"event":"supervisor.config_insecure","insecure_config_key":"launcher_uid_separation_unavailable_macos","plugin_id":"alfred.example"}
```

The first appears only in `ALFRED_ENV=development` with the unsandboxed
escape hatch active. The second appears on macOS dev hosts (no `runuser`)
when a sandbox policy file is present. Both are operator-visible config
deviations; neither should appear in production.

## Step 4 — Capability-gate selection

The gate factory at `src/alfred/bootstrap/gate_factory.py` reads
`ALFRED_ENV` and constructs `RealGate` (production default) or `DevGate`
(fail-open stubs). The selection is **opt-out of production**:

| `ALFRED_ENV` value | Gate constructed |
| --- | --- |
| `development` | `DevGate` |
| Unset, empty, or whitespace-only | `DevGate` |
| Anything else | `RealGate` |

A typo (`prdouction`, `prod`, `staging-eu`) safely maps to `RealGate`.
The bootstrap emits an INFO-level `bootstrap.gate_selected` structlog event
on every selection — grep your log stream for it after deploy to confirm
you got the gate you intended:

```text
INFO  bootstrap.gate_selected gate=RealGate alfred_env=production
```

`DevGate` adds a `warning` field so the line is visible in dashboards even
without filtering:

```text
INFO  bootstrap.gate_selected gate=DevGate alfred_env=(unset)
       warning="fail-open capability stubs; do not use in production"
```

## Step 5 — First-plugin smoke test

Once policy + UID + gate are in place, spawn a placeholder plugin via the
supervisor's spawn API. The audit log should show:

1. `supervisor.spawn_requested` (the supervisor accepted the request).
2. `supervisor.spawn_succeeded` (the launcher exec'd cleanly).
3. `transport.handshake_ok` (the JSON-RPC handshake completed).

If you see `supervisor.spawn_failed` with `plugin.launcher_no_sandbox_policy`
as the reason, return to Step 2 — the per-plugin policy file is missing.

If you see `supervisor.spawn_failed` with
`plugin.launcher_uid_drop_unavailable`, return to Step 1 — `runuser` is not
installed.

## Troubleshooting common audit rows

### `plugin.launcher_unsandboxed_rejected`

An operator set `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` in a non-development
deployment. This is refused unconditionally outside development. Either
unset the flag, or set `ALFRED_ENV=development` (NEVER in production).

### `plugin.launcher_uid_drop_unavailable`

Linux host, but `runuser` is missing from PATH. Install `util-linux`:

```sh
sudo apt-get install -y util-linux           # Debian / Ubuntu
sudo dnf install -y util-linux               # Fedora / RHEL
```

Restart the supervisor. The next spawn should succeed.

### `launcher_uid_separation_unavailable_macos`

macOS dev host. Expected — the deviation is documented; it MUST NOT appear
in production. If you see it in a production log stream, the host is
mis-tagged or someone deployed macOS code into Linux containers.

### `supervisor.config_insecure` with `insecure_config_key=ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED`

The dev-only escape hatch fired. Confirm `ALFRED_ENV=development` (not
production), and that the absence of a sandbox policy file is intentional.

## Further reading

- PRD §4.8 — supervisor + launcher contract
- PRD §5.2 — sandbox policy directory + UID drop
- [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — manifest
  shape, error hierarchy, QuarantinedUnavailable location.
- [`tests/unit/plugins/test_plugin_launcher_stub.py`](../../tests/unit/plugins/test_plugin_launcher_stub.py)
  — every invariant pinned by a test; read alongside the script.
