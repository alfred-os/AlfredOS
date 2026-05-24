# Security Policy

AlfredOS is a security-sensitive project. We take reports seriously and respond promptly.

## Reporting an issue

**Do not open a public issue for a suspected security weakness.**

Report via [GitHub Security Advisories](https://github.com/alfred-os/AlfredOS/security/advisories/new). This is private to the maintainers.

If you cannot use the advisory form, email **4990954+MrReasonable@users.noreply.github.com** with the subject prefix `[AlfredOS Security]`.

## What to include

- A clear description of the issue.
- Steps to reproduce or proof-of-concept.
- Affected version or commit.
- Impact assessment (what an attacker could achieve).
- A suggested fix, if you have one.

## What to expect

- Acknowledgement within **72 hours**.
- Initial assessment within **7 days**.
- Status updates at least every **14 days** until resolution.
- Credit in the published advisory unless you prefer to remain anonymous.
- Coordinated disclosure: default 90-day window, negotiable based on severity and complexity.

## Scope

**In scope**

- AlfredOS core (`src/alfred/`)
- Bundled first-party plugins (`plugins/`)
- Default configurations and policies (`config/`)
- Setup scripts (`bin/`)
- Docker Compose deployment

**Out of scope**

- Third-party plugins (report to the plugin author)
- User-deployed configurations that override our defaults
- Issues requiring physical access to the host
- Social engineering of individual operators
- Issues in pre-release / unmerged branches

## Severity guidelines

We score using CVSS v4. Indicative priorities:

- **Critical** — Remote code execution, secret-broker bypass, T3-to-tool-call bypass, DLP bypass, audit log tampering.
- **High** — Trust-tier escape (T3 reaching the privileged orchestrator), reviewer-gate bypass, capability-gate bypass.
- **Medium** — Information disclosure within authorized scope, capability-gate race conditions, denial of service on the agent loop.
- **Low** — Best-practice deviations without exploitable impact.

## Out-of-band confirmation

For high-impact reports, maintainers may request an out-of-band confirmation (signed message from your GitHub account, or a brief video call) to protect both parties from impersonation.

## Acknowledgements

Valid reports are credited in `SECURITY-HALL-OF-FAME.md` (created on the first report) unless the reporter prefers anonymity.
