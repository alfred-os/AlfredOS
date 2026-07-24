# AlfredOS PowerShell entry — redirects to WSL2.
#
# Native Windows hosts cannot satisfy the PRD §6.7 quarantined-LLM
# containerisation invariant (ADR-0015 — bwrap on Linux, sandbox-exec on
# macOS, no Windows kernel-level equivalent ships in Slice 4). The
# quarantined-LLM subprocess that reads raw T3 content MUST run under a
# kernel-level sandbox primitive; bare Windows has none, so the AlfredOS
# security model only holds under WSL2/Linux (ops-003). Running AlfredOS in
# WSL2 is therefore the supported configuration on Windows; bare Windows is
# out of scope through Slice 4+.
#
# See: ADR-0015, docs/superpowers/specs/2026-06-06-slice-4-design.md.

$ErrorActionPreference = "Stop"

if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Error @"
WSL2 is required for AlfredOS on Windows.

Install with: wsl --install

Native Windows is not a supported AlfredOS deployment target. The
quarantined-LLM containerisation invariant (PRD §6.7, ADR-0015) requires a
kernel-level sandbox primitive (bwrap on Linux, sandbox-exec on macOS); no
equivalent ships through Slice 4 on bare Windows, so the security model only
holds under WSL2/Linux. After installing WSL2, re-run this script from a
Windows shell (it forwards to bin/alfred-setup.sh inside your WSL2 distro) or
run bin/alfred-setup.sh directly from a WSL2 terminal.
"@
    exit 1
}

# #309 preflight (Windows/WSL2 parity): warn before forwarding if the Discord
# bot token is missing, so the operator sees the guidance in their native shell
# rather than inside the WSL2 transcript. Identical wording to bin/alfred-setup.sh.
if (docker compose ps --services 2>$null | Select-String -Quiet "^alfred-discord$") {
    Write-Warning "A stale alfred-discord container is running — 'docker compose down' then 'up -d'."
}
$_envFile = Join-Path $PSScriptRoot "..\.env"
$_tokenInEnvFile = Test-Path $_envFile -PathType Leaf -ErrorAction SilentlyContinue
if ($_tokenInEnvFile) {
    $_tokenInEnvFile = (Get-Content $_envFile | Select-String -Quiet '^\s*ALFRED_DISCORD_BOT_TOKEN\s*=')
}
if (-not $env:ALFRED_DISCORD_BOT_TOKEN -and -not $_tokenInEnvFile) {
    # #469 Blocker 2 Task 5: this script only forwards to WSL2 (see `wsl bash
    # bin/alfred-setup.sh` below) — it does not seed .env itself. The real seed
    # (`seed_hosted_adapters`, which sets ALFRED_GATEWAY_HOSTED_ADAPTERS when a token is
    # present) runs inside that forwarded bin/alfred-setup.sh run. This is a heads-up
    # printed in the operator's native shell before forwarding; message kept in the same
    # substance as bin/alfred-setup.sh's own advisory (simplified here to avoid embedding
    # a quoted JSON literal in a PowerShell double-quoted string).
    Write-Warning "ALFRED_DISCORD_BOT_TOKEN is unset. Discord is opt-in: set ALFRED_DISCORD_BOT_TOKEN in .env then re-run setup, or set ALFRED_GATEWAY_HOSTED_ADAPTERS manually (a JSON array containing alfred_discord, in .env — NOT secrets.toml, which would shadow env) — then 'docker compose up -d alfred-gateway'."
}

Write-Host "AlfredOS: forwarding setup to WSL2 (bin/alfred-setup.sh) — the supported Windows configuration."
# ALFRED_DISCORD_BOT_TOKEN is forwarded into WSL2 via the environment; the
# gateway adapters --wait-ready discord probe inside bin/alfred-setup.sh will
# pick it up there. No duplicate probe here — the WSL2 run is authoritative.
wsl bash bin/alfred-setup.sh @args
