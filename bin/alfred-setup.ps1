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

Write-Host "AlfredOS: forwarding setup to WSL2 (bin/alfred-setup.sh) — the supported Windows configuration."
wsl bash bin/alfred-setup.sh @args
