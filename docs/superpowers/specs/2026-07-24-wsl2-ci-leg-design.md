# WSL2 CI leg — catch Windows-via-WSL idiosyncrasies (#496)

**Status:** design v1, approved in brainstorming (realistic-interop model). Tracked as
**#496**. Own PR off `main`, to merge **before** #469 Blocker 2 (PR #495) so B2's
setup-script / `.ps1` path is validated under real WSL first (B2 rebases onto this once
it lands).

## Problem

AlfredOS's supported Windows path is **WSL2** — `bin/alfred-setup.ps1` is a shim that
requires WSL and forwards to `wsl bash bin/alfred-setup.sh` (native Windows is out of
scope per ADR-0015 / PRD §6.7; native-Windows sandbox support is tracked separately as
**#471**). But **no CI leg exercises that path**: the matrix is
`[macos-latest, windows-latest]` (both native, no WSL) plus the ubuntu jobs. So the
Windows-operator reality — repo on the Windows filesystem, run from WSL over `/mnt/d` —
is unverified: CRLF-in-`.sh`, `/mnt/d` path/permission interop, and the
`.ps1`→`wsl bash` handoff can all break for a real operator with green CI.

## Approach — realistic Windows-operator interop

A new **advisory-first** job that provisions WSL2 on a `windows-latest` runner and
exercises the setup-script surface **from WSL, over the Windows-side checkout** — the
shape a real operator hits. Scoped tight (the setup-script + `.ps1` surface only); the
bulk portable Python suite is *not* re-run (WSL ≈ Ubuntu for pure Python — already
covered by the ubuntu leg).

### Job: `python-wsl` (ci.yml)

- `runs-on: windows-latest`, `timeout-minutes: 30`, `permissions: contents: read`.
- **Required from day one (maintainer decision):** a hard merge gate, so WSL issues get
  fixed rather than accumulating as advisory noise. Mechanical caveat: GitHub cannot mark
  a check *required* on the same PR that introduces it (the check context must first exist
  on `main`). So the sequence is — merge the leg PR (the job runs on it, non-required, and
  must be green to merge), then **immediately promote `python-wsl` to a required status
  check** via the `author-gating-workflow` skill (branch-protection `gh api` + update the
  tracked required-checks manifest), *before* B2 rebases onto `main`. From that point every
  PR (B2 included) must pass it.
- `actions/checkout` stays on the **Windows filesystem** (default); WSL reaches the repo
  via `/mnt/d/…`. This is the interop that catches the real quirks. (The `windows-latest`
  runner's `GITHUB_WORKSPACE` lands on `D:`, hence `/mnt/d`; the drive letter is incidental
  — every `/mnt/<drive>` is a `drvfs` mount of an NTFS drive with identical Windows↔WSL
  interop, and a real operator clones wherever their dev drive is. The job intentionally
  uses the runner's natural workspace rather than forcing a copy to `C:`.)

### Provisioning

- `Vampire/setup-wsl@<sha>` (SHA-pinned per repo convention) → **Ubuntu-24.04** (matches
  the Linux base).
- Inside WSL: install `uv` (`astral-sh/setup-uv` runs on the Windows side; inside WSL use
  the official `uv` installer or `pipx`), `uv python install 3.14`, `uv sync --frozen --dev`.
  Confirm `uv sync` over `/mnt/d` is workable; if the `/mnt/d` I/O is prohibitively slow,
  fall back to syncing into a WSL-native venv while keeping the **repo/tests** on `/mnt/d`
  (the interop we care about is the repo path, not the venv location).

### What it runs (from WSL, over `/mnt/d`)

1. **Setup-script `.sh` tests under WSL** — `uv run pytest tests/unit/test_setup_script_*.py`.
   Under WSL `sys.platform == "linux"`, so the `win32` skips do **not** fire — these run
   for real, executing `bin/alfred-setup.sh`'s sliced functions via WSL `bash` over the
   Windows-side checkout. Catches CRLF / path / interop in the `.sh` path.
2. **`.ps1`→WSL forwarding smoke** — from PowerShell: `bin/alfred-setup.ps1 --dry-run`.
   Confirmed feasible: `setup.ps1:52` forwards `@args` to `wsl bash bin/alfred-setup.sh`,
   and `setup.sh` honours `--dry-run` (`:20-22`, exits 0 after prereq checks). Assert exit
   0 and that the `.sh` dry-run banner appears — i.e. the real Windows entry point forwards
   into WSL and the script runs there end-to-end.
3. **Line-ending guard** — assert the repo's `.sh` files are LF as seen from WSL (a CRLF
   `.sh` fails `bash` with a `\r` / bad-interpreter error under WSL). Belt-and-suspenders
   with `.gitattributes` (verify in the plan whether `.gitattributes` forces `eol=lf` for
   `*.sh`; if not, either add it or rely on this guard to catch a regression).

## Discovered risk (flag, likely follow-up)

The `.ps1`'s WSL guard is `if (-not (Get-Command wsl))` — but `wsl.exe` ships on Win10/11
**even with no distro installed**, so `Get-Command wsl` succeeds on a bare machine. The
friendly "WSL2 is required — `wsl --install`" refusal therefore only fires when `wsl.exe`
itself is absent (rare); the **common** "`wsl.exe` present, no distro" case skips the
guard, forwards to `wsl bash …`, and fails with a raw WSL error instead of the actionable
message. This is a real robustness gap in the shim (arguably the guard should probe a
working distro, e.g. `wsl -l -q` / `wsl --status`). **Out of this leg's core scope** —
recorded as a finding; fix as a small `.ps1` hardening in a follow-up (a "no-distro"
assertion is also awkward to stage on a runner where `wsl.exe` is always present, so it is
NOT a leg test).

## Cost discipline

`fail-fast: false` (a WSL failure must not be masked by / mask anything). Scoped to the
setup-script + `.ps1` surface only — no full-suite-under-WSL (redundant with ubuntu).
Heavy Docker/integration stays Linux-only.

## Sequencing with #469 Blocker 2

1. This leg merges to `main` on its own PR (green on its own PR = it works against `main`'s
   current setup scripts).
2. **Immediately promote `python-wsl` to a required status check** (author-gating-workflow:
   branch-protection `gh api` + required-checks manifest) so it hard-gates every subsequent PR.
3. Rebase Blocker 2 (PR #495) onto the new `main`; B2's CI now includes the required
   `python-wsl`, so B2's `seed_hosted_adapters` / advisory / `.ps1` changes are exercised
   under real WSL and must pass.
4. Merge B2 once that leg (and the rest) is green.

## Testing the leg itself (no paper gate — #245 discipline)

The job green on its own PR proves it runs. During implementation, verify it can actually
**fail**: inject a CRLF into a `.sh` (or a broken `wsl bash` forward) locally / in a
throwaway push and confirm the leg goes red. A leg that can only pass is worthless.

## Out of scope

- **Full portable suite under WSL** — redundant with the ubuntu leg (WSL ≈ Ubuntu for pure
  Python); this leg is the interop/`.sh`/`.ps1` surface only.
- **Native-Windows (non-WSL) support** — a #471-scale sandbox-backend effort with its own
  brainstorm + human-gated ADR-0015 / PRD §6.7 revision. Cycled back later.
- The `.ps1` no-distro guard hardening — a noted follow-up, not this leg.
