# Slice-1 PowerShell stub. Delegates to WSL until native Windows support lands.
$ErrorActionPreference = "Stop"

if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Error "WSL is required for AlfredOS on Windows in Slice 1. Install with 'wsl --install'."
    exit 1
}

wsl bash bin/alfred-setup.sh @args
