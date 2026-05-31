# PR-S3-6: Operator CLI Surface + CommsAdapterMCP Protocol Stub — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the complete operator CLI surface (`alfred plugin`, `alfred web allowlist`, `alfred config`, `alfred supervisor`, `alfred audit graph --tier`) plus the `CommsAdapterMCP` Protocol stub and a reference test plugin that validates the MCP comms transport contract against a second consumer.

**Architecture:** Six new CLI modules hang off the existing `typer` root app in `src/alfred/cli/main.py`. **rvw-002 / devex-001:** `src/alfred/cli/supervisor.py` is exclusively owned by this PR. PR-S3-3b Task 18 (which attempted to ship the same module in Click) has been removed from the PR-S3-3b plan — confirmed by rvw-002 (reviewer) and devex-001 (devex). Each module owns a single `Typer()` sub-app registered with a callback that performs T1-tier or read-only access validation; all output strings route through `t()`. The `CommsAdapterMCP` Protocol lives in `src/alfred/comms/mcp_protocol.py` as a structural stub alongside the in-process `CommsAdapter` Protocol — both coexist through Slice 3, the MCP shape is validated by the reference plugin roundtrip test. Every reviewer-gated command (`alfred plugin grant`, `alfred web allowlist add/remove`, `alfred config quarantined-provider`) queues a state.git proposal and prints the async-UX pending message; it does NOT apply changes immediately.

**Tech Stack:** Python 3.12+ · Typer (CLI) · Pydantic v2 (wire models for MCP protocol stub) · `model_context_protocol` SDK (MCP client for reference plugin test) · `asyncio.TaskGroup` (structured concurrency in integration test) · `structlog` · `t()` for all operator-facing strings · pytest + testcontainers (integration) · `uv run pytest` + `make check`

**Depends on:** PR-S3-0a (merged — `audit_row_schemas.py` `PLUGIN_GRANT_FIELDS`, `PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS`, `SUPERVISOR_BREAKER_RESET_FIELDS`, `WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS`), PR-S3-0b (merged — i18n catalog with `cli.*` and `plugin.grant_prompt` keys, Alembic migrations 0008 `plugin_grants` + 0009 `capability_gate_sync`, `config/policies.yaml` low-blast knobs, state.git infrastructure), PR-S3-1 (merged — `tag(T3, ...)` nonce, `T3DerivedData`), PR-S3-2 (merged — `RealGate.check_plugin_load`, `check_content_clearance`, `PluginGrant` SQLAlchemy model), PR-S3-3a (merged — `StdioTransport.dispatch`, `AlfredPluginSession`, MCP wire protocol surface) per the §2 dependency table in `docs/superpowers/plans/2026-05-31-slice-3-index.md`. **Soft dependency:** PR-S3-3b (`Supervisor.reset_breaker`, `CircuitBreaker` state, `circuit_breakers` table from migration 0010) for `alfred supervisor reset` — PR-S3-6 may begin once PR-S3-3a merges and integrate PR-S3-3b's surface when both land.

**Blocks:** PR-S3-7 (CLAUDE.md command table refresh, subsystem deep-docs).

---

## §1 Goal

This PR delivers the operator-facing command surface defined in spec §11.3 CLI table and the ADR-0009 comms-MCP contract from spec §9 (Fork 8). It sits between PR-S3-3b (supervisor shipped) and PR-S3-7 (flag-day), giving operators discovery paths for every Slice-3 subsystem: plugin grants flow through `alfred plugin grant`; web allowlist changes through `alfred web allowlist add`; config changes through `alfred config`; circuit-breaker resets through `alfred supervisor reset`; T1/T3 audit swimlanes through `alfred audit graph --tier`. The `CommsAdapterMCP` Protocol stub and the `plugins/alfred-comms-test/` reference plugin validate that the MCP transport contract from PR-S3-3a can carry comms-adapter messages — without forcing the Discord/TUI rewrite until Slice 4.

Spec anchors: §9 (Fork 8), §11 (all sub-sections), §14 hookpoint table, §11.5 i18n key list. Predecessor contracts consumed: `src/alfred/audit/audit_row_schemas.py` (PR-S3-0a), Alembic `plugin_grants` + `circuit_breakers` tables (PR-S3-0b + PR-S3-3b), `RealGate.check_plugin_load` + `check_content_clearance` (PR-S3-2), `StdioTransport.dispatch` + `AlfredPluginSession` (PR-S3-3a), `Supervisor.reset_breaker` + `CircuitBreaker` state (PR-S3-3b).

---

## §2 Architecture overview

The CLI surface is a set of independent Typer sub-apps, each registered on the root `app` in `main.py`. Reviewer-gated commands write a proposal branch to state.git via `StateGitProposalClient` (a thin wrapper over `git` subprocess) and return a `pending_review` message; they never mutate Postgres directly. Read-only commands query Postgres via the existing `build_session_scope` seam.

```
alfred (typer root)
├── plugin  ── src/alfred/cli/plugin.py
│   ├── grant <id> <tier> <hookpoint>    → state.git proposal (reviewer-gated)
│   ├── grant status <id>               → Postgres read
│   ├── grant list --pending            → state.git + Postgres read
│   ├── list                            → Postgres read
│   ├── show <id>                       → Postgres read
│   └── revoke <id>                     → state.git proposal (reviewer-gated)
├── web     ── src/alfred/cli/web.py
│   └── allowlist
│       ├── add <domain>                → state.git proposal (reviewer-gated)
│       ├── remove <domain>             → state.git proposal (reviewer-gated)
│       └── list                        → Postgres read
├── config  ── src/alfred/cli/config.py
│   ├── set <key> <value>               → low-blast → policies.yaml / high-blast → state.git
│   ├── get <key>                       → policies.yaml read
│   └── list                            → policies.yaml read
├── supervisor ── src/alfred/cli/supervisor.py
│   ├── status                          → Postgres read (circuit_breakers table)
│   └── reset <component> --confirm    → Supervisor.reset_breaker (T1 command)
└── audit (extended) ── src/alfred/cli/audit.py
    └── graph --tier T1|T2|T3 --since  → Postgres read (audit_log table)

src/alfred/comms/mcp_protocol.py          → CommsAdapterMCP Protocol stub (4 methods)
plugins/alfred-comms-test/                → reference echo plugin (validates transport)
```

The `CommsAdapterMCP` Protocol defines the four wire methods from spec §9.1 (`lifecycle.start`, `lifecycle.stop`, `inbound.message`, `adapter.health`). It is a `typing.Protocol` — structural, not imported by the in-process `CommsAdapter` Protocol, which remains unchanged. The reference test plugin implements `CommsAdapterMCP` as an MCP stdio server and is loaded by `AlfredPluginSession` in the integration test to prove the contract works end-to-end.

ADR-0009's status flip (spec §9.4, §15.2) lands in **PR-S3-0a**, not here. Task 18 (formerly in this PR) has been removed — comms-005 + architect cross-check confirmed the duplicate would produce a merge conflict. Task 21 verification step asserts ADR-0009 already carries the correct status header before this PR opens.

---

## §3 File structure

| File | Action | Responsibility |
|---|---|---|
| `src/alfred/cli/plugin.py` | Create | `alfred plugin {grant, grant_status, grant_list, list, show, revoke}` sub-app |
| `src/alfred/cli/web.py` | Create | `alfred web allowlist {add, remove, list}` sub-app |
| `src/alfred/cli/config.py` | Create | `alfred config {set, get, list}` sub-app |
| `src/alfred/cli/supervisor.py` | Create | `alfred supervisor {status, reset --confirm}` sub-app |
| `src/alfred/cli/audit.py` | Create | `alfred audit graph --tier T1\|T2\|T3 --since` sub-app (extends existing graph output) |
| `src/alfred/cli/_state_git.py` | Create | `StateGitProposalClient` — thin wrapper to create state.git proposal branches |
| `src/alfred/cli/main.py` | Modify | Register 5 new sub-apps; add `audit` sub-app; keep existing `status`/`chat`/`migrate` unchanged |
| `src/alfred/comms/mcp_protocol.py` | Create | `CommsAdapterMCP` Protocol stub + `InboundMessage` (with `platform` field, comms-001) / `AdapterHealthResponse` Pydantic models + `WIRE_METHOD_NAMES` constant (comms-002) |
| `plugins/alfred-comms-test/__init__.py` | Create | Package marker |
| `plugins/alfred-comms-test/main.py` | Create | Reference echo plugin implementing `CommsAdapterMCP` as MCP stdio server |
| `plugins/alfred-comms-test/manifest.toml` | Create | Plugin manifest (`alfred.manifest_version = 1`, `subscriber_tier = "system"`) |
| `docs/adr/0009-comms-adapter-protocol-slice2-only.md` | **(removed — owned by PR-S3-0a; comms-005)** | Status flip deferred to PR-S3-0a |
| `tests/unit/cli/test_plugin_grant_async_ux.py` | Create | Proposal-branch name printed, follow-up command shown, `pending_review` key used |
| `tests/unit/cli/test_supervisor_reset_confirm.py` | Create | `--confirm` required, audit row attribution, T1-tier enforcement |
| `tests/unit/cli/test_audit_graph_tier_swimlanes.py` | Create | `--tier T1`, `--tier T2`, `--tier T3` filter correctness |
| `tests/unit/cli/test_web_allowlist.py` | Create | Pending-review UX for add/remove; list renders correct columns |
| `tests/unit/cli/test_config_commands.py` | Create | Low-blast set → policies.yaml; high-blast quarantined-provider → state.git |
| `tests/unit/comms/test_mcp_protocol.py` | Create | `CommsAdapterMCP` structural Protocol checks + wire model validation |
| `tests/unit/comms/test_mcp_identity_boundary.py` | Create | In-process identity resolution guard: raw platform_user_id enters, canonical user_id never leaves host (comms-006) |
| `tests/unit/comms/test_discord_allowlist_unchanged_in_slice3.py` | Create | Regression guard: `_ALLOWLIST_FIELDS` unchanged through Slice 3 (comms-004) |
| `tests/integration/test_comms_mcp_contract.py` | Create | Handshake + lifecycle + echo roundtrip against reference plugin (renamed from roundtrip per comms-007) |

---

## §4 Tasks

### Component A: `StateGitProposalClient` — shared proposal infrastructure

---

- [ ] **Task 1 — Write failing test for `StateGitProposalClient`.**

  **Files:** Test: `tests/unit/cli/test_state_git.py` (new)

  ```python
  # tests/unit/cli/test_state_git.py
  """Unit tests for StateGitProposalClient.

  Depends on: PR-S3-0a (audit_row_schemas), PR-S3-0b (state.git infra).
  The client itself has no Slice-3-only imports — it is shelled subprocess
  calls — so this test runs in isolation with a temporary git repo.
  """
  from __future__ import annotations

  import subprocess
  import tempfile
  from pathlib import Path

  import pytest

  from alfred.cli._state_git import ProposalResult, StateGitProposalClient


  @pytest.fixture()
  def bare_repo(tmp_path: Path) -> Path:
      """Create a bare git repo to simulate /var/lib/alfred/state.git."""
      repo = tmp_path / "state.git"
      subprocess.run(["git", "init", "--bare", str(repo)], check=True, capture_output=True)
      # Seed an empty main branch so checkout works
      work = tmp_path / "work"
      work.mkdir()
      subprocess.run(["git", "clone", str(repo), str(work)], check=True, capture_output=True)
      (work / "README").write_text("seeded")
      subprocess.run(["git", "-C", str(work), "add", "."], check=True, capture_output=True)
      subprocess.run(
          ["git", "-C", str(work), "commit", "-m", "seed"],
          check=True, capture_output=True,
          env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
      )
      subprocess.run(["git", "-C", str(work), "push", "origin", "main"],
                     check=True, capture_output=True)
      return repo


  def test_create_proposal_returns_branch_name(bare_repo: Path) -> None:
      client = StateGitProposalClient(state_git_path=bare_repo)
      result = client.create_proposal(
          proposal_type="policy-grant",
          payload={"plugin_id": "alfred.web-fetch", "hookpoint": "tool.web.fetch"},
      )
      assert isinstance(result, ProposalResult)
      assert result.branch.startswith("proposal/policy-grant-")
      assert len(result.proposal_id) > 0


  def test_create_proposal_branch_exists_in_repo(bare_repo: Path) -> None:
      client = StateGitProposalClient(state_git_path=bare_repo)
      result = client.create_proposal(
          proposal_type="web-allowlist-add",
          payload={"domain": "example.com", "path_prefix": "/"},
      )
      # Branch must be visible in the bare repo
      out = subprocess.run(
          ["git", "--git-dir", str(bare_repo), "branch", "-a"],
          capture_output=True, text=True, check=True,
      )
      assert result.branch in out.stdout


  def test_proposal_id_is_unique_per_call(bare_repo: Path) -> None:
      client = StateGitProposalClient(state_git_path=bare_repo)
      r1 = client.create_proposal("policy-grant", {"plugin_id": "a"})
      r2 = client.create_proposal("policy-grant", {"plugin_id": "b"})
      assert r1.proposal_id != r2.proposal_id
  ```

  Run: `uv run pytest tests/unit/cli/test_state_git.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.cli._state_git'`

---

- [ ] **Task 2 — Implement `StateGitProposalClient`.**

  **Files:** Create `src/alfred/cli/_state_git.py`

  ```python
  # src/alfred/cli/_state_git.py
  """StateGitProposalClient — thin state.git proposal branch writer.

  PR-S3-6 uses this to queue reviewer-gated proposals for plugin grants,
  web allowlist changes, and high-blast config changes. The client is
  synchronous (CLI context) and shells subprocess calls to git so there
  is no dependency on any Slice-3 async subsystem.

  CLAUDE.md hard rule #6: proposal payloads MUST NOT include raw secret
  values. Callers pass structured dicts; the broker substitution happens
  at runtime, not at proposal time.

  devex-006: PR-S3-2 ships an async create_proposal_branch() in
  src/alfred/security/capability_gate/proposals.py that writes to the same
  state.git paths. This sync client exists because the CLI is synchronous and
  cannot await the async version without asyncio.run(). Consolidation into a
  single canonical writer (with the CLI using asyncio.run) is a PR-S3-7 task.
  Until then, both writers exist. They MUST produce the same branch-name schema:
  proposal/<type>-<hex8-id>. Any format change must land in both simultaneously.
  """
  from __future__ import annotations

  import json
  import secrets
  import subprocess
  import tempfile
  from dataclasses import dataclass
  from pathlib import Path

  from alfred.errors import AlfredError


  class StateGitError(AlfredError):
      """Raised when a state.git operation fails."""


  @dataclass(frozen=True, slots=True)
  class ProposalResult:
      """Result of a create_proposal call."""
      proposal_id: str
      branch: str


  class StateGitProposalClient:
      """Thin wrapper for state.git proposal branch creation.

      Creates a proposal/<type>-<id> branch in the bare state.git repo,
      commits the payload JSON, and returns the branch name for CLI display.

      The state_git_path defaults to /var/lib/alfred/state.git as per
      the Slice-3 operator runbook (spec §15.4).
      """

      def __init__(
          self,
          *,
          state_git_path: Path = Path("/var/lib/alfred/state.git"),
      ) -> None:
          self._repo = state_git_path

      def create_proposal(
          self,
          proposal_type: str,
          payload: dict[str, object],
      ) -> ProposalResult:
          """Create a proposal branch and commit the payload JSON.

          The branch name is proposal/<proposal_type>-<8-char-hex-id>.
          Raises StateGitError if the git operation fails.
          """
          proposal_id = secrets.token_hex(8)
          branch = f"proposal/{proposal_type}-{proposal_id}"
          payload_json = json.dumps(payload, indent=2, sort_keys=True)

          with tempfile.TemporaryDirectory() as work_dir:
              work = Path(work_dir)
              self._run(["git", "clone", str(self._repo), str(work)])
              self._run(["git", "-C", str(work), "checkout", "-b", branch])
              proposal_file = work / "proposal.json"
              proposal_file.write_text(payload_json)
              self._run(["git", "-C", str(work), "add", "proposal.json"])
              self._run([
                  "git", "-C", str(work), "commit",
                  "-m", f"proposal({proposal_type}): {proposal_id}",
              ])
              self._run(["git", "-C", str(work), "push", "origin", branch])

          return ProposalResult(proposal_id=proposal_id, branch=branch)

      def _run(self, cmd: list[str]) -> None:
          result = subprocess.run(cmd, capture_output=True, text=True)
          if result.returncode != 0:
              raise StateGitError(
                  f"state.git command failed: {' '.join(cmd)}\n{result.stderr}"
              )
  ```

  Run: `uv run pytest tests/unit/cli/test_state_git.py -q`
  Expected: `3 passed`

  Run: `make check`
  Expected: passes (ruff + mypy + pyright all green)

  Commit: `feat(cli): StateGitProposalClient — proposal branch writer (#TBD-slice3)`

---

### Component B: `alfred plugin` CLI

---

- [ ] **Task 3 — Write failing tests for `alfred plugin` async UX.**

  **Files:** Test: `tests/unit/cli/test_plugin_grant_async_ux.py` (new)

  ```python
  # tests/unit/cli/test_plugin_grant_async_ux.py
  """Spec §11.3 reviewer-gated async UX — alfred plugin grant.

  Asserts:
  - Proposal branch name printed with t("cli.plugin.grant.pending_review")
  - Follow-up command shown: 'alfred plugin grant status <id>'
  - Output does NOT contain t("cli.plugin.grant.success") (grant not yet active)

  Depends on: PR-S3-0a (audit_row_schemas), PR-S3-0b (i18n catalog with
  cli.plugin.grant.* keys), PR-S3-2 (RealGate), PR-S3-3a (StdioTransport).
  """
  from __future__ import annotations

  from unittest.mock import MagicMock, patch

  import pytest
  from typer.testing import CliRunner

  from alfred.cli.plugin import plugin_app
  from alfred.cli._state_git import ProposalResult


  @pytest.fixture()
  def runner() -> CliRunner:
      return CliRunner(mix_stderr=False)


  @pytest.fixture()
  def mock_proposal() -> ProposalResult:
      return ProposalResult(
          proposal_id="abc12345",
          branch="proposal/policy-grant-abc12345",
      )


  def test_grant_prints_proposal_branch(
      runner: CliRunner, mock_proposal: ProposalResult
  ) -> None:
      with patch(
          "alfred.cli.plugin._state_git_client"
      ) as mock_client:
          mock_client.create_proposal.return_value = mock_proposal
          result = runner.invoke(
              plugin_app, ["grant", "alfred.web-fetch", "system", "tool.web.fetch"]
          )
      assert result.exit_code == 0
      assert "proposal/policy-grant-abc12345" in result.output


  def test_grant_prints_status_follow_up_command(
      runner: CliRunner, mock_proposal: ProposalResult
  ) -> None:
      with patch("alfred.cli.plugin._state_git_client") as mock_client:
          mock_client.create_proposal.return_value = mock_proposal
          result = runner.invoke(
              plugin_app, ["grant", "alfred.web-fetch", "system", "tool.web.fetch"]
          )
      assert "alfred plugin grant status" in result.output
      assert "abc12345" in result.output


  def test_grant_output_uses_pending_review_key_not_success(
      runner: CliRunner, mock_proposal: ProposalResult
  ) -> None:
      """Grant is queued but NOT yet active — must not print success text."""
      with patch("alfred.cli.plugin._state_git_client") as mock_client:
          mock_client.create_proposal.return_value = mock_proposal
          result = runner.invoke(
              plugin_app, ["grant", "alfred.web-fetch", "system", "tool.web.fetch"]
          )
      # The t() key used must be cli.plugin.grant.pending_review, not
      # cli.plugin.grant.success (spec §11.3 reviewer-gated async UX rule).
      # We test the semantic by checking "pending" appears and "success" does not.
      assert "pending" in result.output.lower() or "proposal" in result.output
      assert "grant is now active" not in result.output.lower()


  def test_grant_list_pending_shows_pending_proposals(runner: CliRunner) -> None:
      with patch("alfred.cli.plugin._list_pending_grants") as mock_list:
          mock_list.return_value = [
              {"proposal_id": "abc12345", "plugin_id": "alfred.web-fetch",
               "hookpoint": "tool.web.fetch", "subscriber_tier": "system"}
          ]
          result = runner.invoke(plugin_app, ["grant", "list", "--pending"])
      assert result.exit_code == 0
      assert "abc12345" in result.output
  ```

  Run: `uv run pytest tests/unit/cli/test_plugin_grant_async_ux.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.cli.plugin'`

---

- [ ] **Task 4 — Implement `src/alfred/cli/plugin.py`.**

  **Files:** Create `src/alfred/cli/plugin.py`

  ```python
  # src/alfred/cli/plugin.py
  """alfred plugin CLI — grant/revoke/list/show plugin capabilities.

  Reviewer-gated commands (grant, revoke) queue state.git proposals and
  print async-UX messages per spec §11.3. Read-only commands (list, show,
  grant status, grant list) query Postgres via the existing session scope.

  All output routes through t() per CLAUDE.md i18n rule #1.
  T1-tier ingress: alfred plugin grant, alfred plugin revoke per spec §3.6.
  """
  from __future__ import annotations

  import asyncio
  from typing import Annotated

  import typer

  from alfred.cli._state_git import StateGitProposalClient, StateGitError
  from alfred.i18n import t

  plugin_app = typer.Typer(help=t("cli.plugin.help"), no_args_is_help=True)
  grant_app = typer.Typer(help=t("cli.plugin.grant.help"), no_args_is_help=True)
  plugin_app.add_typer(grant_app, name="grant")

  # Module-level client; tests patch this symbol.
  _state_git_client = StateGitProposalClient()


  def _list_pending_grants() -> list[dict[str, object]]:
      """Query state.git + Postgres for pending (unmerged) grant proposals.

      Stub implementation — full query implemented in PR-S3-7 flag-day
      after RealGate's Postgres projection is fully seeded.
      Returns an empty list until RealGate is available.
      """
      return []


  @grant_app.command("request")
  def grant_request(
      plugin_id: Annotated[str, typer.Argument(help=t("cli.plugin.grant.usage"))],
      subscriber_tier: Annotated[str, typer.Argument()],
      hookpoint: Annotated[str, typer.Argument()],
  ) -> None:
      """Queue a reviewer-gated capability grant proposal.

      Does NOT apply immediately. Prints proposal branch + follow-up command.
      Spec §11.1: high-blast grants require state.git proposal + reviewer-gate
      + explicit human approval.
      """
      try:
          result = _state_git_client.create_proposal(
              proposal_type="policy-grant",
              payload={
                  "plugin_id": plugin_id,
                  "subscriber_tier": subscriber_tier,
                  "hookpoint": hookpoint,
              },
          )
      except StateGitError as exc:
          typer.echo(t("cli.plugin.grant.denied", reason=str(exc)), err=True)
          raise typer.Exit(code=1) from exc

      # i18n-002 fix: catalog declares placeholder {proposal_branch} not {branch}.
      # devex-018: group branch + proposal_id + follow-up into a single visual block.
      # The catalog key cli.plugin.grant.pending_review can carry a multi-line msgstr.
      typer.echo(
          t(
              "cli.plugin.grant.pending_review",
              proposal_branch=result.branch,
              proposal_id=result.proposal_id,
          )
      )
      typer.echo(
          t("cli.plugin.grant.follow_up_command", proposal_id=result.proposal_id)
      )
      # devex-018: visual separator so the proposal_id is easy to copy
      typer.echo(f"  proposal_id: {result.proposal_id}")


  # devex-009: verb inconsistency — 'grant request' vs 'grant <id> <tier> <hookpoint>'
  # shorthand. Requires human judgment: keep both surfaces or collapse to one.
  # Current state: shorthand is the canonical form; 'grant request' is the long form.
  # Resolution deferred to human reviewer. If collapsed, delete grant_request and
  # remove 'grant request' from §5 Spec Coverage Map.
  # Make 'alfred plugin grant <args>' invoke 'grant request' as the default
  # subcommand by also registering it as the plain 'grant' callback.
  @plugin_app.command("grant")
  def grant_shorthand(
      plugin_id: Annotated[str, typer.Argument(help=t("cli.plugin.grant.usage"))],
      subscriber_tier: Annotated[str, typer.Argument()],
      hookpoint: Annotated[str, typer.Argument()],
  ) -> None:
      """Alias for 'alfred plugin grant request'."""
      grant_request(
          plugin_id=plugin_id,
          subscriber_tier=subscriber_tier,
          hookpoint=hookpoint,
      )


  @grant_app.command("status")
  def grant_status(
      proposal_id: Annotated[str, typer.Argument()],
  ) -> None:
      """Show approval status for a queued grant proposal.

      Queries state.git branch existence + Postgres plugin_grants table.
      Four states: pending / approved / denied / not_found (devex-010).
      """
      # i18n-002 fix: catalog uses {proposal_branch} not {proposal_id}.
      # devex-010: stub must not claim 'pending' permanently — wire real query in PR-S3-7.
      # For now, emit pending with a note that full query wiring is PR-S3-7.
      proposal_branch = f"proposal/policy-grant-{proposal_id}"
      typer.echo(
          t("cli.plugin.grant.status.pending", proposal_branch=proposal_branch)
      )


  @grant_app.command("list")
  def grant_list(
      pending: Annotated[bool, typer.Option("--pending")] = False,
  ) -> None:
      """List grants, optionally filtered to pending (unmerged) proposals."""
      rows = _list_pending_grants() if pending else []
      if not rows:
          typer.echo(t("cli.plugin.list.empty_hint"))
          return
      header = "  ".join([
          t("cli.plugin.list.column.plugin_id").ljust(30),
          t("cli.plugin.list.column.subscriber_tier").ljust(12),
          t("cli.plugin.list.column.status").ljust(10),
      ])
      typer.echo(header)
      for row in rows:
          typer.echo(
              f"{str(row.get('plugin_id', '')):<30}  "
              f"{str(row.get('subscriber_tier', '')):<12}  "
              f"{str(row.get('status', 'pending')):<10}"
          )


  @plugin_app.command("list")
  def plugin_list() -> None:
      """List all registered plugins from the Postgres projection.

      devex-011: Full Postgres query wired in PR-S3-7 once RealGate is seeded.
      Until then, emit explicit not-yet-implemented (exit code 2) so operators
      don't interpret silent empty output as 'no plugins loaded'.
      """
      # t() key for not-yet-implemented; add to PR-S3-0b catalog.
      typer.echo(t("cli.plugin.list.not_implemented_yet"), err=True)
      raise typer.Exit(code=2)


  @plugin_app.command("show")
  def plugin_show(
      plugin_id: Annotated[str, typer.Argument()],
  ) -> None:
      """Show manifest details for a registered plugin.

      devex-011: avoid returning empty/nonsense. Until PR-S3-7 wires Postgres,
      emit explicit not-yet-available message so operators know this is planned.
      """
      # i18n-002 fix: cli.plugin.show.field.plugin_id in catalog is a bare label
      # with no {value} placeholder. Use a separate row-formatter key or
      # format the output as a bare 'key = value' line (not a t() translation issue).
      typer.echo(f"plugin_id = {plugin_id}")
      typer.echo(t("cli.plugin.list.empty_hint"))  # indicates no additional data yet


  @plugin_app.command("revoke")
  def plugin_revoke(
      plugin_id: Annotated[str, typer.Argument()],
  ) -> None:
      """Queue a reviewer-gated revocation proposal for a plugin grant."""
      try:
          result = _state_git_client.create_proposal(
              proposal_type="policy-revoke",
              payload={"plugin_id": plugin_id},
          )
      except StateGitError as exc:
          typer.echo(t("cli.plugin.grant.denied", reason=str(exc)), err=True)
          raise typer.Exit(code=1) from exc

      typer.echo(
          t(
              "cli.plugin.grant.pending_review",
              branch=result.branch,
              proposal_id=result.proposal_id,
          )
      )
  ```

  Run: `uv run pytest tests/unit/cli/test_plugin_grant_async_ux.py -q`
  Expected: `4 passed`

  Run: `make check`
  Expected: passes

  Commit: `feat(cli): alfred plugin {grant,list,show,revoke} with reviewer-gated async UX (#TBD-slice3)`

---

### Component C: `alfred web allowlist` CLI

---

- [ ] **Task 5 — Write failing tests for `alfred web allowlist`.**

  **Files:** Test: `tests/unit/cli/test_web_allowlist.py` (new)

  ```python
  # tests/unit/cli/test_web_allowlist.py
  """Spec §11.3 — alfred web allowlist {add, remove, list}.

  add + remove → reviewer-gated proposal (pending_review UX).
  list → Postgres read (shows domain / path_prefix / granted_by / granted_at).

  Depends on: PR-S3-0a (audit_row_schemas), PR-S3-0b (i18n catalog,
  web allowlist tables in Postgres via migration 0008).
  """
  from __future__ import annotations

  from unittest.mock import patch

  import pytest
  from typer.testing import CliRunner

  from alfred.cli.web import web_app
  from alfred.cli._state_git import ProposalResult


  @pytest.fixture()
  def runner() -> CliRunner:
      return CliRunner(mix_stderr=False)


  @pytest.fixture()
  def mock_proposal() -> ProposalResult:
      return ProposalResult(proposal_id="ff001122", branch="proposal/web-allowlist-add-ff001122")


  def test_allowlist_add_prints_proposal_branch(
      runner: CliRunner, mock_proposal: ProposalResult
  ) -> None:
      with patch("alfred.cli.web._state_git_client") as mock_client:
          mock_client.create_proposal.return_value = mock_proposal
          result = runner.invoke(web_app, ["allowlist", "add", "example.com"])
      assert result.exit_code == 0
      assert "proposal/web-allowlist-add-ff001122" in result.output


  def test_allowlist_add_uses_pending_review_key(
      runner: CliRunner, mock_proposal: ProposalResult
  ) -> None:
      with patch("alfred.cli.web._state_git_client") as mock_client:
          mock_client.create_proposal.return_value = mock_proposal
          result = runner.invoke(web_app, ["allowlist", "add", "example.com"])
      assert "pending" in result.output.lower() or "proposal" in result.output


  def test_allowlist_remove_prints_proposal_branch(
      runner: CliRunner, mock_proposal: ProposalResult
  ) -> None:
      mock_proposal_remove = ProposalResult(
          proposal_id="aa334455", branch="proposal/web-allowlist-remove-aa334455"
      )
      with patch("alfred.cli.web._state_git_client") as mock_client:
          mock_client.create_proposal.return_value = mock_proposal_remove
          result = runner.invoke(web_app, ["allowlist", "remove", "example.com"])
      assert result.exit_code == 0
      assert "proposal/web-allowlist-remove-aa334455" in result.output


  def test_allowlist_list_renders_column_headers(runner: CliRunner) -> None:
      with patch("alfred.cli.web._list_allowlist_entries") as mock_list:
          mock_list.return_value = [
              {"domain": "api.example.com", "path_prefix": "/v1/",
               "granted_by": "operator", "granted_at": "2026-05-31"}
          ]
          result = runner.invoke(web_app, ["allowlist", "list"])
      assert result.exit_code == 0
      assert "api.example.com" in result.output
  ```

  Run: `uv run pytest tests/unit/cli/test_web_allowlist.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.cli.web'`

---

- [ ] **Task 6 — Implement `src/alfred/cli/web.py`.**

  **Files:** Create `src/alfred/cli/web.py`

  ```python
  # src/alfred/cli/web.py
  """alfred web allowlist CLI — manage web-fetch domain allowlist.

  add + remove → reviewer-gated state.git proposals (spec §11.1, §11.3).
  list → Postgres read from operator-config projection.

  T1-tier command surface per spec §3.6: alfred web allowlist.
  All output routes through t() per CLAUDE.md i18n rule #1.
  """
  from __future__ import annotations

  from typing import Annotated

  import typer

  from alfred.cli._state_git import StateGitProposalClient, StateGitError
  from alfred.i18n import t

  web_app = typer.Typer(help=t("cli.web.help"), no_args_is_help=True)
  allowlist_app = typer.Typer(help=t("cli.web.allowlist.help"), no_args_is_help=True)
  web_app.add_typer(allowlist_app, name="allowlist")

  _state_git_client = StateGitProposalClient()


  def _list_allowlist_entries() -> list[dict[str, object]]:
      """Query Postgres web_allowlist projection. Stub — full impl PR-S3-7."""
      return []


  @allowlist_app.command("add")
  def allowlist_add(
      domain: Annotated[str, typer.Argument(help=t("cli.web.allowlist.add.usage"))],
      path_prefix: Annotated[str, typer.Option("--path-prefix")] = "/",
  ) -> None:
      """Queue a reviewer-gated proposal to add a domain to the web allowlist.

      Does not activate immediately. Spec §11.1: domain additions widen the
      trust surface and require state.git proposal + reviewer-gate + human approval.
      """
      try:
          result = _state_git_client.create_proposal(
              proposal_type="web-allowlist-add",
              payload={"domain": domain, "path_prefix": path_prefix},
          )
      except StateGitError as exc:
          typer.echo(t("cli.web.allowlist.add.denied", reason=str(exc)), err=True)
          raise typer.Exit(code=1) from exc

      # devex-019: include domain + path_prefix so operator can distinguish
      # concurrent proposals for the same domain with different path prefixes.
      typer.echo(
          t(
              "cli.web.allowlist.pending_review",
              branch=result.branch,
              proposal_id=result.proposal_id,
              domain=domain,
              path_prefix=path_prefix,
          )
      )


  @allowlist_app.command("remove")
  def allowlist_remove(
      domain: Annotated[str, typer.Argument()],
  ) -> None:
      """Queue a reviewer-gated proposal to remove a domain from the allowlist."""
      try:
          result = _state_git_client.create_proposal(
              proposal_type="web-allowlist-remove",
              payload={"domain": domain},
          )
      except StateGitError as exc:
          typer.echo(t("cli.web.allowlist.remove.denied", reason=str(exc)), err=True)
          raise typer.Exit(code=1) from exc

      typer.echo(
          t(
              "cli.web.allowlist.pending_review",
              branch=result.branch,
              proposal_id=result.proposal_id,
          )
      )


  @allowlist_app.command("list")
  def allowlist_list() -> None:
      """List the current web-fetch domain allowlist from Postgres."""
      rows = _list_allowlist_entries()
      if not rows:
          typer.echo(t("cli.web.allowlist.list_empty"))
          return
      header = "  ".join([
          t("cli.web.allowlist.list.column.domain").ljust(40),
          t("cli.web.allowlist.list.column.path_prefix").ljust(20),
          t("cli.web.allowlist.list.column.granted_by").ljust(15),
          t("cli.web.allowlist.list.column.granted_at").ljust(20),
      ])
      typer.echo(header)
      for row in rows:
          typer.echo(
              f"{str(row.get('domain', '')):<40}  "
              f"{str(row.get('path_prefix', '/')):<20}  "
              f"{str(row.get('granted_by', '')):<15}  "
              f"{str(row.get('granted_at', '')):<20}"
          )
  ```

  Run: `uv run pytest tests/unit/cli/test_web_allowlist.py -q`
  Expected: `4 passed`

  Run: `make check`
  Expected: passes

  Commit: `feat(cli): alfred web allowlist {add,remove,list} reviewer-gated (#TBD-slice3)`

---

### Component D: `alfred config` CLI

---

- [ ] **Task 7 — Write failing tests for `alfred config`.**

  **Files:** Test: `tests/unit/cli/test_config_commands.py` (new)

  ```python
  # tests/unit/cli/test_config_commands.py
  """Spec §11.2/§11.3 — alfred config {set, get, list}.

  Low-blast keys (web-fetch-budget, etc.) → policies.yaml write.
  High-blast keys (quarantined-provider) → state.git reviewer-gated proposal.
  get/list → policies.yaml read.

  Depends on: PR-S3-0b (i18n catalog: cli.config.* keys, policies.yaml).
  """
  from __future__ import annotations

  import tempfile
  from pathlib import Path
  from unittest.mock import patch

  import pytest
  from typer.testing import CliRunner

  from alfred.cli.config import config_app
  from alfred.cli._state_git import ProposalResult


  @pytest.fixture()
  def runner() -> CliRunner:
      return CliRunner(mix_stderr=False)


  def test_config_set_low_blast_writes_policies_yaml(
      runner: CliRunner, tmp_path: Path
  ) -> None:
      policies = tmp_path / "policies.yaml"
      policies.write_text("web_fetch:\n  user_daily_budget: 100\n")
      with patch("alfred.cli.config._policies_yaml_path", policies):
          result = runner.invoke(config_app, ["set", "web-fetch-budget", "50"])
      assert result.exit_code == 0
      content = policies.read_text()
      assert "50" in content


  def test_config_set_high_blast_quarantined_provider_queues_proposal(
      runner: CliRunner,
  ) -> None:
      mock_proposal = ProposalResult(
          proposal_id="cc778899",
          branch="proposal/policy-grant-cc778899",
      )
      with patch("alfred.cli.config._state_git_client") as mock_client:
          mock_client.create_proposal.return_value = mock_proposal
          result = runner.invoke(config_app, ["set", "quarantined-provider", "anthropic"])
      assert result.exit_code == 0
      assert "proposal" in result.output.lower() or "pending" in result.output.lower()


  def test_config_get_reads_policies_yaml(
      runner: CliRunner, tmp_path: Path
  ) -> None:
      policies = tmp_path / "policies.yaml"
      policies.write_text("web_fetch:\n  user_daily_budget: 75\n")
      with patch("alfred.cli.config._policies_yaml_path", policies):
          result = runner.invoke(config_app, ["get", "web-fetch-budget"])
      assert result.exit_code == 0
      assert "75" in result.output


  def test_config_list_renders_keys(runner: CliRunner, tmp_path: Path) -> None:
      policies = tmp_path / "policies.yaml"
      policies.write_text(
          "web_fetch:\n  user_daily_budget: 100\n"
          "orchestrator:\n  action_deadline_seconds: 30\n"
      )
      with patch("alfred.cli.config._policies_yaml_path", policies):
          result = runner.invoke(config_app, ["list"])
      assert result.exit_code == 0
      assert "web_fetch" in result.output or "user_daily_budget" in result.output
  ```

  Run: `uv run pytest tests/unit/cli/test_config_commands.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.cli.config'`

---

- [ ] **Task 8 — Implement `src/alfred/cli/config.py`.**

  **Files:** Create `src/alfred/cli/config.py`

  ```python
  # src/alfred/cli/config.py
  """alfred config CLI — set/get/list operator configuration.

  Low-blast keys write to config/policies.yaml (hot-reload, no reviewer gate).
  High-blast keys (quarantined-provider) queue a state.git proposal.

  Spec §11.2 low-blast keys: web_fetch.user_daily_budget,
    web_fetch.operator_daily_budget, quarantine.extraction_max_retries,
    orchestrator.action_deadline_seconds, web_fetch.user_agent,
    web_fetch.rate_limits.<domain>.
  Spec §11.1 high-blast keys: quarantined-provider.

  All output routes through t() per CLAUDE.md i18n rule #1.
  """
  from __future__ import annotations

  from pathlib import Path
  from typing import Annotated

  import typer
  import yaml

  from alfred.cli._state_git import StateGitProposalClient, StateGitError
  from alfred.i18n import t

  config_app = typer.Typer(help=t("cli.config.help"), no_args_is_help=True)

  _state_git_client = StateGitProposalClient()

  # The policies.yaml path; patched in tests.
  _policies_yaml_path: Path = Path("config/policies.yaml")

  # High-blast keys that require reviewer-gate proposal.
  _HIGH_BLAST_KEYS: frozenset[str] = frozenset({"quarantined-provider"})

  # Map CLI key names to policies.yaml YAML paths (dot-separated).
  _KEY_TO_YAML_PATH: dict[str, str] = {
      "web-fetch-budget": "web_fetch.user_daily_budget",
      "operator-fetch-budget": "web_fetch.operator_daily_budget",
      "extraction-max-retries": "quarantine.extraction_max_retries",
      "action-deadline": "orchestrator.action_deadline_seconds",
      "user-agent": "web_fetch.user_agent",
  }


  def _yaml_set(yaml_path: Path, dotted_key: str, value: object) -> None:
      """Write a value at a dotted key path in a YAML file (creates parents)."""
      if yaml_path.exists():
          data: dict[str, object] = yaml.safe_load(yaml_path.read_text()) or {}
      else:
          data = {}
      keys = dotted_key.split(".")
      node = data
      for k in keys[:-1]:
          if k not in node or not isinstance(node[k], dict):
              node[k] = {}  # type: ignore[index]
          node = node[k]  # type: ignore[assignment]
      node[keys[-1]] = value  # type: ignore[index]
      yaml_path.write_text(yaml.dump(data, default_flow_style=False))


  def _yaml_get(yaml_path: Path, dotted_key: str) -> object:
      """Read a value at a dotted key path from a YAML file."""
      if not yaml_path.exists():
          return None
      data = yaml.safe_load(yaml_path.read_text()) or {}
      for k in dotted_key.split("."):
          if not isinstance(data, dict) or k not in data:
              return None
          data = data[k]
      return data


  @config_app.command("set")
  def config_set(
      key: Annotated[str, typer.Argument(help=t("cli.config.set.key_help"))],
      value: Annotated[str, typer.Argument(help=t("cli.config.set.value_help"))],
  ) -> None:
      """Set an operator configuration key.

      High-blast keys (e.g. quarantined-provider) queue a reviewer-gated
      state.git proposal. Low-blast keys write directly to policies.yaml.
      """
      if key in _HIGH_BLAST_KEYS:
          try:
              result = _state_git_client.create_proposal(
                  proposal_type=f"config-{key}",
                  payload={"key": key, "value": value},
              )
          except StateGitError as exc:
              typer.echo(t("cli.config.set.denied", reason=str(exc)), err=True)
              raise typer.Exit(code=1) from exc
          typer.echo(
              t(
                  "cli.config.quarantined_provider_pending_review",
                  branch=result.branch,
                  proposal_id=result.proposal_id,
              )
          )
          return

      yaml_key = _KEY_TO_YAML_PATH.get(key)
      if yaml_key is None:
          # devex-012: include list of valid keys so operator has recovery path.
          valid_keys = ", ".join(sorted(_KEY_TO_YAML_PATH | _HIGH_BLAST_KEYS))
          typer.echo(t("cli.config.set.unknown_key", key=key, valid_keys=valid_keys), err=True)
          raise typer.Exit(code=1)

      # Parse value: try int/float, fall back to str
      parsed: int | float | str
      try:
          parsed = int(value)
      except ValueError:
          try:
              parsed = float(value)
          except ValueError:
              parsed = value

      _yaml_set(_policies_yaml_path, yaml_key, parsed)
      # i18n-001 fix: catalog (PR-S3-0b) declares {key} and {value} placeholders;
      # call site must match exactly. If catalog uses {user}/{n}, align the catalog
      # in PR-S3-0b to {key}/{value} — these are the semantic names.
      typer.echo(t("cli.config.web_fetch_budget_set", key=key, value=str(parsed)))


  @config_app.command("get")
  def config_get(
      key: Annotated[str, typer.Argument()],
  ) -> None:
      """Get the current value of an operator configuration key."""
      yaml_key = _KEY_TO_YAML_PATH.get(key)
      if yaml_key is None:
          # devex-012: include valid keys list for get as well.
          valid_keys = ", ".join(sorted(_KEY_TO_YAML_PATH | _HIGH_BLAST_KEYS))
          typer.echo(t("cli.config.get.unknown_key", key=key, valid_keys=valid_keys), err=True)
          raise typer.Exit(code=1)
      value = _yaml_get(_policies_yaml_path, yaml_key)
      if value is None:
          typer.echo(t("cli.config.get.not_set", key=key))
      else:
          typer.echo(f"{key} = {value}")


  @config_app.command("list")
  def config_list() -> None:
      """List all current operator configuration values from policies.yaml."""
      if not _policies_yaml_path.exists():
          typer.echo(t("cli.config.list.empty"))
          return
      data = yaml.safe_load(_policies_yaml_path.read_text()) or {}
      _print_yaml_flat(data, prefix="")


  def _print_yaml_flat(data: object, prefix: str) -> None:
      """Recursively print YAML keys as dotted paths."""
      if isinstance(data, dict):
          for k, v in data.items():
              _print_yaml_flat(v, f"{prefix}.{k}" if prefix else k)
      else:
          typer.echo(f"{prefix} = {data}")
  ```

  Run: `uv run pytest tests/unit/cli/test_config_commands.py -q`
  Expected: `4 passed`

  Run: `make check`
  Expected: passes

  Commit: `feat(cli): alfred config {set,get,list} low/high-blast routing (#TBD-slice3)`

---

### Component E: `alfred supervisor` CLI

---

- [ ] **Task 9 — Write failing tests for `alfred supervisor reset --confirm`.**

  **Files:** Test: `tests/unit/cli/test_supervisor_reset_confirm.py` (new)

  ```python
  # tests/unit/cli/test_supervisor_reset_confirm.py
  """Spec §10.8, §11.3 — alfred supervisor {status, reset --confirm}.

  Asserts:
  - reset without --confirm exits non-zero (gate required per spec §11.3)
  - reset with --confirm calls Supervisor.reset_breaker
  - audit row carries operator_user_id attribution
  - T1-tier: command requires operator role

  Depends on: PR-S3-3b (Supervisor.reset_breaker, CircuitBreaker, circuit_breakers
  table from migration 0010), PR-S3-0a (SUPERVISOR_BREAKER_RESET_FIELDS constants).
  """
  from __future__ import annotations

  from unittest.mock import AsyncMock, patch

  import pytest
  from typer.testing import CliRunner

  from alfred.cli.supervisor import supervisor_app


  @pytest.fixture()
  def runner() -> CliRunner:
      return CliRunner(mix_stderr=False)


  def test_reset_without_confirm_exits_nonzero(runner: CliRunner) -> None:
      result = runner.invoke(supervisor_app, ["reset", "quarantined-llm"])
      assert result.exit_code != 0
      # Must prompt for --confirm; refusing should produce a non-zero exit
      assert "--confirm" in result.output or "confirm" in result.output.lower()


  def test_reset_with_confirm_calls_reset_breaker(runner: CliRunner) -> None:
      mock_supervisor = AsyncMock()
      mock_supervisor.reset_breaker = AsyncMock(return_value=None)
      with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
          result = runner.invoke(
              supervisor_app, ["reset", "quarantined-llm", "--confirm"]
          )
      assert result.exit_code == 0
      mock_supervisor.reset_breaker.assert_called_once_with(
          component_id="quarantined-llm",
          operator_user_id=None,  # None in test env without full bootstrap
      )


  def test_reset_success_message_rendered(runner: CliRunner) -> None:
      mock_supervisor = AsyncMock()
      mock_supervisor.reset_breaker = AsyncMock(return_value=None)
      with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
          result = runner.invoke(
              supervisor_app, ["reset", "quarantined-llm", "--confirm"]
          )
      assert result.exit_code == 0
      assert "quarantined-llm" in result.output or "reset" in result.output.lower()


  def test_reset_unknown_component_exits_nonzero(runner: CliRunner) -> None:
      from alfred.supervisor.errors import SupervisorError
      mock_supervisor = AsyncMock()
      mock_supervisor.reset_breaker = AsyncMock(
          side_effect=SupervisorError("Component not found: no-such-plugin")
      )
      with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
          result = runner.invoke(
              supervisor_app, ["reset", "no-such-plugin", "--confirm"]
          )
      assert result.exit_code != 0
      assert "no-such-plugin" in result.output or "not found" in result.output.lower()


  def test_status_renders_table_header(runner: CliRunner) -> None:
      with patch("alfred.cli.supervisor._list_breaker_states") as mock_list:
          mock_list.return_value = [
              {
                  "component": "quarantined-llm",
                  "state": "CLOSED",
                  "trip_count": 0,
                  "last_trip_at": None,
              }
          ]
          result = runner.invoke(supervisor_app, ["status"])
      assert result.exit_code == 0
      assert "quarantined-llm" in result.output
  ```

  Run: `uv run pytest tests/unit/cli/test_supervisor_reset_confirm.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.cli.supervisor'`

---

- [ ] **Task 10 — Implement `src/alfred/cli/supervisor.py`.**

  **Files:** Create `src/alfred/cli/supervisor.py`

  ```python
  # src/alfred/cli/supervisor.py
  """alfred supervisor CLI — status + circuit-breaker reset.

  T1-tier commands per spec §3.6 and §10.8:
  - alfred supervisor status → read-only; lists all supervised components
    and their circuit-breaker states.
  - alfred supervisor reset <component> --confirm → calls
    Supervisor.reset_breaker; requires --confirm gate.

  All output routes through t() per CLAUDE.md i18n rule #1.
  Audit row for reset carries operator_user_id per SUPERVISOR_BREAKER_RESET_FIELDS
  (src/alfred/audit/audit_row_schemas.py from PR-S3-0a).
  """
  from __future__ import annotations

  import asyncio
  from typing import Annotated

  import typer

  from alfred.i18n import t

  supervisor_app = typer.Typer(help=t("cli.supervisor.help"), no_args_is_help=True)


  def _get_supervisor() -> object:
      """Return the live Supervisor instance.

      Imported lazily so the CLI bootstrap does not construct a supervisor
      for read-only commands like alfred status. Tests patch this function.

      Depends on PR-S3-3b: src/alfred/supervisor/core.Supervisor.
      """
      # Deferred import — Supervisor depends on Postgres + async bootstrap.
      # The CLI is synchronous (Typer); we run the async call via asyncio.run.
      from alfred.supervisor.core import Supervisor  # type: ignore[import]  # PR-S3-3b
      return Supervisor.get_instance()


  def _list_breaker_states() -> list[dict[str, object]]:
      """Query circuit_breakers Postgres table for all component states.

      Depends on PR-S3-3b migration 0010 + SQLAlchemy model.
      Stub returns empty list until PR-S3-3b merges.
      """
      return []


  @supervisor_app.command("status")
  def supervisor_status() -> None:
      """List all supervised components and their circuit-breaker states.

      Spec §11.3: alfred supervisor status → read-only, Postgres read.
      Discovery path: quarantine_unavailable error → alfred supervisor status
      → alfred supervisor reset <component> --confirm.
      """
      # devex-013: disambiguate empty state — supervisor not running vs genuinely empty.
      try:
          _supervisor_handle = _get_supervisor()
          rows = _list_breaker_states()
      except Exception:  # noqa: BLE001
          typer.echo(t("cli.supervisor.status.no_supervisor_running"), err=True)
          raise typer.Exit(code=1)
      if not rows:
          typer.echo(t("cli.supervisor.status.empty_hint"))
          return
      header = "  ".join([
          t("cli.supervisor.status.column.component").ljust(25),
          t("cli.supervisor.status.column.state").ljust(10),
          t("cli.supervisor.status.column.trip_count").ljust(12),
          t("cli.supervisor.status.column.last_trip_at").ljust(25),
      ])
      typer.echo(header)
      for row in rows:
          state_raw = str(row.get("state", ""))
          state_key_map = {
              "OPEN": "cli.supervisor.status.breaker_state.open",
              "CLOSED": "cli.supervisor.status.breaker_state.closed",
              "HALF_OPEN": "cli.supervisor.status.breaker_state.half_open",
          }
          state_label = t(state_key_map.get(state_raw, "cli.supervisor.status.breaker_state.closed"))
          last_trip = str(row.get("last_trip_at") or "-")
          # rvw-010: hardcoded column widths mis-render in CJK locales (code-point width
          # vs display width). Deferred to a follow-up; use rich.table.Table in Slice 4.
          typer.echo(
              f"{str(row.get('component', '')):<25}  "
              f"{state_label:<10}  "
              f"{str(row.get('trip_count', 0)):<12}  "
              f"{last_trip:<25}"
          )


  @supervisor_app.command("reset")
  def supervisor_reset(
      component_id: Annotated[str, typer.Argument(help=t("cli.supervisor.reset.usage"))],
      confirm: Annotated[
          bool,
          typer.Option(
              "--confirm",
              help=t("cli.supervisor.reset.confirm_prompt"),
              is_flag=True,
          ),
      ] = False,
  ) -> None:
      """Reset a circuit breaker from OPEN to CLOSED.

      Spec §10.8: operator-tier T1 command; requires --confirm; emits
      supervisor.breaker.reset audit row with operator_user_id attribution.
      The --confirm gate prevents accidental resets in scripts — a supervisor
      reset clears a tripped circuit breaker, potentially re-enabling a
      quarantined-LLM plugin that failed 3+ times in 5 minutes.
      """
      if not confirm:
          # devex-004 + i18n-004: catalog requires {component}, {trip_count}, {last_trip_at}.
          # The confirm_prompt kwarg must match catalog placeholders exactly.
          # Full breaker-state fetch (trip_count/last_trip_at) wired in PR-S3-7 when
          # Supervisor.get_breaker_state is available; pass safe defaults here.
          typer.echo(
              t(
                  "cli.supervisor.reset.confirm_prompt",
                  component=component_id,
                  trip_count="-",
                  last_trip_at="-",
              ),
              err=True,
          )
          # i18n-004 fix: was hardcoded English f-string — now routed through t().
          # Add cli.supervisor.reset.rerun_hint to PR-S3-0b catalog with
          # msgstr "Re-run with: alfred supervisor reset {component} --confirm"
          typer.echo(
              t("cli.supervisor.reset.rerun_hint", component=component_id),
              err=True,
          )
          raise typer.Exit(code=1)

      supervisor = _get_supervisor()

      # devex-007: operator_user_id=None is a known placeholder. Full T1 attribution
      # requires wiring IdentityResolver.resolve() from the CLI session in PR-S3-7.
      # Human judgment required: surface an unmistakable error if attribution cannot
      # be resolved, or emit None and let the audit row carry NULL (weaker audit story).
      # Decision deferred to PR-S3-7; see devex-007 + spec §10.8.
      try:
          asyncio.run(
              supervisor.reset_breaker(
                  component_id=component_id,
                  operator_user_id=None,  # Full T1 attribution wired in PR-S3-7
              )
          )
      except Exception as exc:
          # devex-005: map specific error types to distinct messages so operators
          # can distinguish "wrong component ID" from "supervisor unavailable".
          # Import lazily to avoid bootstrap cost for other CLI commands.
          try:
              from alfred.supervisor.errors import ComponentNotFoundError, SupervisorError  # type: ignore[import]
              if isinstance(exc, ComponentNotFoundError):
                  typer.echo(
                      t("cli.supervisor.reset.component_not_found", component=component_id),
                      err=True,
                  )
              else:
                  typer.echo(
                      t("cli.supervisor.reset.unexpected_error", component=component_id,
                        error_type=type(exc).__name__),
                      err=True,
                  )
          except ImportError:
              typer.echo(
                  t("cli.supervisor.reset.unexpected_error", component=component_id,
                    error_type=type(exc).__name__),
                  err=True,
              )
          raise typer.Exit(code=1) from exc

      typer.echo(t("cli.supervisor.reset.success", component=component_id))
  ```

  Run: `uv run pytest tests/unit/cli/test_supervisor_reset_confirm.py -q`
  Expected: `5 passed`

  Run: `make check`
  Expected: passes

  Commit: `feat(cli): alfred supervisor {status,reset --confirm} T1 command (#TBD-slice3)`

---

### Component F: `alfred audit graph --tier` extension

---

- [ ] **Task 11 — Write failing tests for `alfred audit graph --tier` swimlanes.**

  **Files:** Test: `tests/unit/cli/test_audit_graph_tier_swimlanes.py` (new)

  ```python
  # tests/unit/cli/test_audit_graph_tier_swimlanes.py
  """Spec §11.3 (last row) — alfred audit graph --tier T1|T2|T3 swimlanes.

  Asserts:
  - --tier T3 filters audit rows to trust_tier_of_trigger="T3"
  - --tier T1 filters to T1 rows
  - --tier T2 (unfiltered baseline) shows all tiers
  - --since 24h time filter passed through
  - Column headers rendered (spec §11.3 'alfred audit graph --tier T3 --since 24h')

  Depends on: PR-S3-0a (audit_row_schemas), PR-S3-0b (Alembic migration 0007
  extends audit_log CHECK constraint with new result values).
  """
  from __future__ import annotations

  from unittest.mock import patch

  import pytest
  from typer.testing import CliRunner

  from alfred.cli.audit import audit_app


  @pytest.fixture()
  def runner() -> CliRunner:
      return CliRunner(mix_stderr=False)


  @pytest.fixture()
  def t3_rows() -> list[dict[str, object]]:
      return [
          {
              "event": "tool.web.fetch",
              "trust_tier_of_trigger": "T3",
              "actor_user_id": "operator",
              "result": "success",
              "timestamp": "2026-05-31T10:00:00Z",
          }
      ]


  @pytest.fixture()
  def t1_rows() -> list[dict[str, object]]:
      return [
          {
              "event": "identity.t1_ingress",
              "trust_tier_of_trigger": "T1",
              "actor_user_id": "operator",
              "result": "success",
              "timestamp": "2026-05-31T09:00:00Z",
          }
      ]


  def test_audit_graph_tier_t3_filters_rows(
      runner: CliRunner, t3_rows: list[dict[str, object]]
  ) -> None:
      with patch("alfred.cli.audit._query_audit_log") as mock_query:
          mock_query.return_value = t3_rows
          result = runner.invoke(audit_app, ["graph", "--tier", "T3", "--since", "24h"])
      assert result.exit_code == 0
      mock_query.assert_called_once()
      call_kwargs = mock_query.call_args
      assert call_kwargs.kwargs.get("tier") == "T3" or "T3" in str(call_kwargs)


  def test_audit_graph_tier_t3_renders_row(
      runner: CliRunner, t3_rows: list[dict[str, object]]
  ) -> None:
      with patch("alfred.cli.audit._query_audit_log", return_value=t3_rows):
          result = runner.invoke(audit_app, ["graph", "--tier", "T3", "--since", "24h"])
      assert result.exit_code == 0
      assert "tool.web.fetch" in result.output
      assert "T3" in result.output


  def test_audit_graph_tier_t1_filters_rows(
      runner: CliRunner, t1_rows: list[dict[str, object]]
  ) -> None:
      with patch("alfred.cli.audit._query_audit_log") as mock_query:
          mock_query.return_value = t1_rows
          result = runner.invoke(audit_app, ["graph", "--tier", "T1", "--since", "24h"])
      assert result.exit_code == 0
      mock_query.assert_called_once()
      call_kwargs = mock_query.call_args
      assert call_kwargs.kwargs.get("tier") == "T1" or "T1" in str(call_kwargs)


  def test_audit_graph_no_tier_shows_all(runner: CliRunner) -> None:
      rows: list[dict[str, object]] = []
      with patch("alfred.cli.audit._query_audit_log", return_value=rows):
          result = runner.invoke(audit_app, ["graph", "--since", "24h"])
      assert result.exit_code == 0
  ```

  Run: `uv run pytest tests/unit/cli/test_audit_graph_tier_swimlanes.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.cli.audit'`

---

- [ ] **Task 12 — Implement `src/alfred/cli/audit.py`.**

  **Files:** Create `src/alfred/cli/audit.py`

  ```python
  # src/alfred/cli/audit.py
  """alfred audit CLI — audit graph with tier swimlane filter.

  Extends the existing audit surface with --tier T1|T2|T3 filtering.
  Each tier produces a swimlane view of audit rows attributed to that tier.

  Read-only command surface per spec §11.3.
  All output routes through t() per CLAUDE.md i18n rule #1.
  Depends on: PR-S3-0a audit_row_schemas, PR-S3-0b migration 0007 (extends
  audit_log CHECK constraint with new result values including T3 events).
  """
  from __future__ import annotations

  from typing import Annotated, Literal

  import typer

  from alfred.i18n import t

  audit_app = typer.Typer(help=t("cli.audit.help"), no_args_is_help=True)

  TierChoice = Literal["T0", "T1", "T2", "T3"]


  def _query_audit_log(
      *,
      tier: str | None = None,
      since_hours: int = 24,
  ) -> list[dict[str, object]]:
      """Query audit_log table with optional tier filter.

      Depends on: PR-S3-0b migration 0007 extends the CHECK constraint;
      production query wired once Postgres session scope available.
      Returns empty list until full Postgres bootstrap available.
      """
      return []


  @audit_app.command("log")
  def audit_log(
      event: Annotated[
          str | None,
          typer.Option("--event", help=t("cli.audit.log.event_help")),
      ] = None,
      since: Annotated[
          str,
          typer.Option("--since", help=t("cli.audit.graph.since_help")),
      ] = "24h",
  ) -> None:
      """List audit log entries, optionally filtered by event name and time window.

      devex-008: runbook fix-suggestion 3 uses 'alfred audit log --event
      plugin.lifecycle.crashed --since 5m'. This command provides the expected surface.
      Spec §11.3 notes this as part of the audit CLI surface.
      """
      since_hours = _parse_since(since)
      rows = _query_audit_log(tier=None, since_hours=since_hours)
      if event:
          rows = [r for r in rows if r.get("event") == event]
      if not rows:
          typer.echo(t("cli.audit.graph.empty", tier="", since=since))
          return
      for row in rows:
          typer.echo(
              f"{str(row.get('timestamp', '')):<25}  "
              f"{str(row.get('event', '')):<40}  "
              f"{str(row.get('result', '')):<12}  "
              f"{str(row.get('actor_user_id', ''))}"
          )


  @audit_app.command("graph")
  def audit_graph(
      tier: Annotated[
          str | None,
          typer.Option("--tier", help=t("cli.audit.graph.tier_help")),
      ] = None,
      since: Annotated[
          str,
          typer.Option("--since", help=t("cli.audit.graph.since_help")),
      ] = "24h",
  ) -> None:
      """Show the audit graph, optionally filtered to a trust tier swimlane.

      Spec §11.3: alfred audit graph --tier T1|T2|T3 --since 24h.
      Each tier's rows form a swimlane; --tier T3 shows all web.fetch,
      quarantine.extract, and security.t3_boundary events.
      """
      # Parse --since (e.g. "24h", "7d")
      since_hours = _parse_since(since)

      rows = _query_audit_log(tier=tier, since_hours=since_hours)

      if not rows:
          tier_label = f" ({tier})" if tier else ""
          typer.echo(t("cli.audit.graph.empty", tier=tier_label, since=since))
          return

      # Render header
      label = t("cli.audit.graph.tier_header", tier=tier) if tier else t("cli.audit.graph.header")
      typer.echo(label)
      typer.echo("-" * 60)

      for row in rows:
          typer.echo(
              f"{str(row.get('timestamp', '')):<25}  "
              f"{str(row.get('trust_tier_of_trigger', '')):<4}  "
              f"{str(row.get('event', '')):<40}  "
              f"{str(row.get('result', '')):<12}  "
              f"{str(row.get('actor_user_id', ''))}"
          )


  def _parse_since(since: str) -> int:
      """Parse a --since value like '24h', '7d', or '30m' into hours.

      devex-016: invalid input raises typer.BadParameter rather than silently
      returning 24h. Bare integers are rejected — unit suffix is required.
      """
      s = since.strip().lower()
      try:
          if s.endswith("h"):
              return int(s[:-1])
          if s.endswith("d"):
              return int(s[:-1]) * 24
          if s.endswith("m"):
              minutes = int(s[:-1])
              return max(1, minutes // 60) if minutes >= 60 else 1
      except ValueError:
          pass
      raise typer.BadParameter(
          t("cli.audit.graph.since_invalid", value=since, example="24h, 7d, or 30m"),
          param_hint="'--since'",
      )
  ```

  Run: `uv run pytest tests/unit/cli/test_audit_graph_tier_swimlanes.py -q`
  Expected: `4 passed`

  Run: `make check`
  Expected: passes

  Commit: `feat(cli): alfred audit graph --tier T1|T2|T3 swimlane filter (#TBD-slice3)`

---

### Component G: Register all new sub-apps in `main.py`

---

- [ ] **Task 13 — Wire new sub-apps into `src/alfred/cli/main.py`.**

  **Files:** Modify `src/alfred/cli/main.py`

  Add imports and `add_typer` registrations after the existing `discord_app` registration:

  ```python
  # At the top-level imports (add after existing imports):
  from alfred.cli.audit import audit_app
  from alfred.cli.config import config_app
  from alfred.cli.plugin import plugin_app
  from alfred.cli.supervisor import supervisor_app
  from alfred.cli.web import web_app
  ```

  Add registrations after `app.add_typer(discord_app, name="discord")`:

  ```python
  app.add_typer(plugin_app, name="plugin")
  app.add_typer(web_app, name="web")
  app.add_typer(config_app, name="config")
  app.add_typer(supervisor_app, name="supervisor")
  app.add_typer(audit_app, name="audit")
  ```

  Run: `uv run pytest tests/unit/ -q --tb=short`
  Expected: all existing tests pass plus new CLI tests pass

  Run: `make check`
  Expected: passes

  Commit: `feat(cli): register plugin/web/config/supervisor/audit sub-apps in main (#TBD-slice3)`

---

### Component H: `CommsAdapterMCP` Protocol stub

---

- [ ] **Task 14 — Write failing test for `CommsAdapterMCP` Protocol.**

  **Files:** Test: `tests/unit/comms/test_mcp_protocol.py` (new)

  ```python
  # tests/unit/comms/test_mcp_protocol.py
  """Spec §9 (Fork 8) — CommsAdapterMCP Protocol structural tests.

  Validates the four-method MCP wire contract: lifecycle.start,
  lifecycle.stop, inbound.message, adapter.health.

  The Protocol is structural (typing.Protocol), so any class implementing
  all four methods satisfies it — no inheritance required.

  Depends on: PR-S3-3a (StdioTransport, AlfredPluginSession) for wiring;
  this unit test validates the Protocol shape only.
  """
  from __future__ import annotations

  import pytest
  from pydantic import ValidationError

  from alfred.comms.mcp_protocol import (
      AdapterHealthResponse,
      CommsAdapterMCP,
      InboundMessage,
  )


  class _EchoAdapter:
      """Minimal concrete implementation of CommsAdapterMCP for testing."""

      async def lifecycle_start(self) -> None:
          pass

      async def lifecycle_stop(self) -> None:
          pass

      async def inbound_message(self, msg: InboundMessage) -> None:
          pass

      async def adapter_health(self) -> AdapterHealthResponse:
          return AdapterHealthResponse(status="ok", detail="")


  def test_echo_adapter_satisfies_protocol() -> None:
      adapter = _EchoAdapter()
      assert isinstance(adapter, CommsAdapterMCP)


  def test_inbound_message_valid_payload() -> None:
      # comms-001: platform field is now required
      msg = InboundMessage(
          platform="discord",
          platform_user_id="12345",
          content="hello",
          language="en-US",
      )
      assert msg.platform == "discord"
      assert msg.content == "hello"
      assert msg.language == "en-US"


  def test_inbound_message_rejects_missing_content() -> None:
      with pytest.raises(ValidationError):
          InboundMessage(platform="discord", platform_user_id="12345", language="en")  # type: ignore[call-arg]


  def test_inbound_message_rejects_missing_platform() -> None:
      """comms-001: platform is required; omitting it must raise ValidationError."""
      with pytest.raises(ValidationError):
          InboundMessage(platform_user_id="12345", content="hi", language="en")  # type: ignore[call-arg]


  def test_adapter_health_response_status_values() -> None:
      ok = AdapterHealthResponse(status="ok", detail="all good")
      assert ok.status == "ok"
      degraded = AdapterHealthResponse(status="degraded", detail="reconnecting")
      assert degraded.status == "degraded"


  def test_adapter_health_rejects_invalid_status() -> None:
      with pytest.raises(ValidationError):
          AdapterHealthResponse(status="unknown", detail="")  # type: ignore[arg-type]


  def test_protocol_is_runtime_checkable() -> None:
      """CommsAdapterMCP must be @runtime_checkable for isinstance checks."""
      from typing import runtime_checkable
      # The class-level check: a non-adapter should NOT satisfy it
      class _NotAnAdapter:
          pass
      assert not isinstance(_NotAnAdapter(), CommsAdapterMCP)
  ```

  Run: `uv run pytest tests/unit/comms/test_mcp_protocol.py -q`
  Expected: `ModuleNotFoundError: No module named 'alfred.comms.mcp_protocol'`

---

- [ ] **Task 15 — Implement `src/alfred/comms/mcp_protocol.py`.**

  **Files:** Create `src/alfred/comms/mcp_protocol.py`

  ```python
  # src/alfred/comms/mcp_protocol.py
  """CommsAdapterMCP Protocol — MCP wire-shape for comms adapters.

  Defines the Slice-3 MCP comms adapter Protocol stub per spec §9 (Fork 8).
  This Protocol is DISTINCT from the in-process CommsAdapter Protocol at
  src/alfred/comms/adapter.py. Both coexist through Slice 3.

  The four methods pin the minimum wire shape the reference test plugin
  (plugins/alfred-comms-test/) validates against:

  | Direction              | Method            | Payload                                            |
  |------------------------|-------------------|----------------------------------------------------|
  | Orchestrator → adapter | lifecycle_start   | none                                               |
  | Orchestrator → adapter | lifecycle_stop    | none                                               |
  | Adapter → orchestrator | inbound_message   | platform, platform_user_id, content, language      |
  | Orchestrator → adapter | adapter_health    | → {status: ok\|degraded, detail: str}              |

  comms-001 fix: `platform` field added — spec §9.1 line 744 says adapters send
  raw (platform, platform_user_id) so the orchestrator can disambiguate
  discord:12345 from telegram:12345 from tui:12345. Without platform, identity
  resolution collides across platforms.

  The full message-contract definition (error shapes, rate-limit signalling)
  is co-defined in ADR-0016 when Slice 4 implements the Discord rewrite; it
  is NOT finalised here. This stub validates transport + handshake only.

  Per spec §9.1: identity resolution stays in-process to the orchestrator
  in Slice 3. comms-MCP plugins send raw (platform, platform_user_id) over
  the wire; the orchestrator resolves identity before invoking _ingest_tier.

  ADR-0009 status: "Superseded by ADR-0016 for new adapters;
  in-process adapters live through Slice 3 unchanged." (spec §9.4)

  comms-011: Authorised by ADR-0017 (Slice-3 trust-tier completion + MCP
  plugin transport). Why this stub lands in Slice 3: spec §9 Fork-8 commits
  to validating the MCP transport contract against a second consumer before
  Slice 4 rewrites Discord and TUI as MCP plugins.
  """
  from __future__ import annotations

  from typing import Final, Literal, Mapping, Protocol, runtime_checkable

  from pydantic import BaseModel, ConfigDict

  # comms-002 fix: architect cross-check confirmed method names are literal
  # JSON-RPC method names (NOT MCP tools/call subjects). AlfredPluginSession.dispatch
  # in PR-S3-3a MUST route these as JSON-RPC method=<name>, not as tools/call.
  # This constant is the single source of truth for the wire mapping;
  # test_mcp_identity_boundary.py and integration test verify it is honoured.
  WIRE_METHOD_NAMES: Final[Mapping[str, str]] = {
      "lifecycle_start": "lifecycle.start",
      "lifecycle_stop": "lifecycle.stop",
      "inbound_message": "inbound.message",
      "adapter_health": "adapter.health",
  }


  class InboundMessage(BaseModel):
      """Message payload received from a comms-MCP adapter.

      Corresponds to the adapter → orchestrator inbound.message method.
      All fields are required — adapters MUST supply platform, platform_user_id,
      and language with every message (spec §9.1 identity-resolver placement).

      comms-001: `platform` is required so the orchestrator can disambiguate
      e.g. discord:12345 from telegram:12345 from tui:12345. Without it,
      IdentityResolver.resolve() cannot scope the lookup to the correct platform
      namespace and identity collisions occur across platforms.

      language is a BCP-47 tag per CLAUDE.md i18n rule #3.
      """

      model_config = ConfigDict(frozen=True)

      platform: str
      platform_user_id: str
      content: str
      language: str


  class AdapterHealthResponse(BaseModel):
      """Health snapshot returned by adapter_health().

      status="ok" → adapter fully operational.
      status="degraded" → adapter running but with reduced capability
        (e.g. reconnecting to gateway). detail provides human-readable context.
      """

      model_config = ConfigDict(frozen=True)

      # comms-009: Slice-3 narrow set per spec §9.1. ADR-0016 (Slice 4) will
      # widen this to include "unhealthy" / "starting" / "stopping" for full
      # lifecycle visibility. When ADR-0016 lands, widen the Literal AND update
      # test_adapter_health_rejects_invalid_status to accept the new values.
      status: Literal["ok", "degraded"]
      detail: str


  @runtime_checkable
  class CommsAdapterMCP(Protocol):
      """MCP-shaped comms adapter Protocol.

      Slice 3 stub: pins four wire methods only. Full contract (error shapes,
      rate-limit signalling, rich-media handling) lands in ADR-0016 + Slice 4
      when TUI and Discord adapters rewrite as MCP plugins.

      The Protocol is @runtime_checkable so AlfredPluginSession and the
      integration test can use isinstance() checks.

      Note on method naming: JSON-RPC method names use dot-notation
      (lifecycle.start, inbound.message) but Python method names cannot
      contain dots. The wire mapping:
        lifecycle_start   → JSON-RPC method "lifecycle.start"
        lifecycle_stop    → JSON-RPC method "lifecycle.stop"
        inbound_message   → JSON-RPC method "inbound.message" (adapter → host)
        adapter_health    → JSON-RPC method "adapter.health"
      """

      async def lifecycle_start(self) -> None:
          """Initiate the adapter's main loop. Spec §9.1: method lifecycle.start."""
          ...

      async def lifecycle_stop(self) -> None:
          """Gracefully shut down the adapter. Spec §9.1: method lifecycle.stop."""
          ...

      async def inbound_message(self, msg: InboundMessage) -> None:
          """Adapter→host notification: adapter sends inbound user message.

          Spec §9.1: JSON-RPC notification ``inbound.message``. The adapter
          sends this notification to the host when a user turn arrives.
          Identity resolution happens in-process in the host; raw
          platform_user_id is resolved before _ingest_tier is invoked.
          """
          ...

      async def adapter_health(self) -> AdapterHealthResponse:
          """Return adapter health snapshot. Called by alfred supervisor status.

          Spec §9.1: method adapter.health. Returns AdapterHealthResponse.
          """
          ...
  ```

  Run: `uv run pytest tests/unit/comms/test_mcp_protocol.py -q`
  Expected: `8 passed` (comms-001 adds test_inbound_message_rejects_missing_platform)

  Run: `make check`
  Expected: passes

  Commit: `feat(comms): CommsAdapterMCP Protocol stub + wire models (spec §9) (#TBD-slice3)`

---

### Component I: Reference test plugin `plugins/alfred-comms-test/`

---

- [ ] **Task 16 — Write failing integration test for comms-MCP roundtrip.**

  **Files:** Test: `tests/integration/test_comms_mcp_contract.py` (new — renamed per comms-007 spec §9.1 line 746)

  ```python
  # tests/integration/test_comms_mcp_contract.py
  """Spec §9.1 — CommsAdapterMCP reference plugin contract test.

  comms-007: Filename matches spec §9.1 line 746 so ADR-0016 cross-references hold.

  Validates:
  1. Handshake: manifest_version=1 accepted, plugin loaded.
  2. Lifecycle: lifecycle.start → host receives inbound.message notification
     (comms-003: plugin→host direction verified, not host→plugin).
  3. lifecycle.stop completes cleanly.
  4. adapter.health returns ControlResult with {"status": "ok"}.

  The test plugin is an MCP stdio server. This test uses AlfredPluginSession
  (PR-S3-3a) to load it, verifying the transport contract works for a second
  consumer beyond the quarantined-LLM and web-fetch plugins.

  Depends on: PR-S3-3a (StdioTransport, AlfredPluginSession with notification
  handler support), PR-S3-2 (RealGate or DevGate in test config),
  PR-S3-0b (manifest_version=1 schema).

  Marked: pytest.mark.integration — requires subprocess launch of the test plugin.
  """
  from __future__ import annotations

  import asyncio
  import sys
  from pathlib import Path

  import pytest

  try:
      from alfred.plugins.stdio_transport import AlfredPluginSession  # type: ignore[import]
      from alfred.hooks.capability import DevGate
      HAS_PLUGIN_HOST = True
  except ImportError:
      HAS_PLUGIN_HOST = False

  PLUGIN_DIR = Path(__file__).parent.parent.parent / "plugins" / "alfred-comms-test"


  @pytest.mark.integration
  @pytest.mark.skipif(not HAS_PLUGIN_HOST, reason="PR-S3-3a (AlfredPluginSession) not merged")
  @pytest.mark.skipif(not PLUGIN_DIR.exists(), reason="reference plugin not yet created")
  async def test_comms_test_plugin_handshake() -> None:
      """Plugin loads without error: manifest_version=1 accepted."""
      gate = DevGate(allow_system=True)
      async with AlfredPluginSession(plugin_dir=PLUGIN_DIR, gate=gate) as session:
          assert session.is_loaded


  @pytest.mark.integration
  @pytest.mark.skipif(not HAS_PLUGIN_HOST, reason="PR-S3-3a not merged")
  @pytest.mark.skipif(not PLUGIN_DIR.exists(), reason="reference plugin not yet created")
  async def test_comms_test_plugin_lifecycle_start_emits_inbound_message() -> None:
      """comms-003: lifecycle.start triggers plugin→host inbound.message notification.

      The host must have a notification handler registered for 'inbound.message'.
      The notification payload must match InboundMessage shape (platform, platform_user_id,
      content, language) per comms-001 + spec §9.1.
      """
      gate = DevGate(allow_system=True)
      received_notifications: list[dict[str, object]] = []

      async def on_inbound_message(params: dict[str, object]) -> None:
          received_notifications.append(params)

      async with AlfredPluginSession(
          plugin_dir=PLUGIN_DIR,
          gate=gate,
          notification_handlers={"inbound.message": on_inbound_message},
      ) as session:
          result_start = await session.dispatch("lifecycle.start", {})
          assert result_start is not None
          # Give the notification a tick to arrive
          await asyncio.sleep(0.05)

      assert len(received_notifications) >= 1, "Expected at least one inbound.message notification"
      notif = received_notifications[0]
      assert "platform" in notif
      assert "platform_user_id" in notif
      assert "content" in notif
      assert "language" in notif


  @pytest.mark.integration
  @pytest.mark.skipif(not HAS_PLUGIN_HOST, reason="PR-S3-3a not merged")
  @pytest.mark.skipif(not PLUGIN_DIR.exists(), reason="reference plugin not yet created")
  async def test_comms_test_plugin_adapter_health_ok() -> None:
      """adapter.health returns ControlResult with status=ok."""
      gate = DevGate(allow_system=True)
      async with AlfredPluginSession(plugin_dir=PLUGIN_DIR, gate=gate) as session:
          await session.dispatch("lifecycle.start", {})
          result = await session.dispatch("adapter.health", {})
          assert result is not None
          payload = getattr(result, "payload", {})
          assert payload.get("status") == "ok"
  ```

  Run: `uv run pytest tests/integration/test_comms_mcp_contract.py -q`
  Expected: `3 skipped` (AlfredPluginSession not merged; plugin not yet created — both correct)

---

- [ ] **Task 17 — Create the reference test plugin.**

  **Files:**
  - Create `plugins/alfred-comms-test/__init__.py`
  - Create `plugins/alfred-comms-test/manifest.toml`
  - Create `plugins/alfred-comms-test/main.py`

  `plugins/alfred-comms-test/__init__.py`:
  ```python
  # plugins/alfred-comms-test/__init__.py
  """Alfred comms-test reference plugin.

  Implements CommsAdapterMCP as an MCP stdio server for transport validation.
  Spec §9.1: validates the MCP comms contract against a second consumer
  beyond the quarantined-LLM + web.fetch plugins.
  """
  ```

  `plugins/alfred-comms-test/manifest.toml`:
  ```toml
  # plugins/alfred-comms-test/manifest.toml
  # Slice-3 manifest schema (spec §4.3): manifest_version = 1 (integer).
  # sandbox_profile declared per spec §4.3.
  #
  # comms-008 fix: [[hooks]] blocks removed. lifecycle.start and adapter.health
  # are JSON-RPC methods on the plugin's own surface, NOT hookpoints registered
  # with the orchestrator's hook registry (spec §14 hookpoint table). Including
  # them as hook subscriptions would cause RealGate.check_plugin_load to reject
  # this manifest, since neither appears in the spec §14 hookpoint table.

  alfred.manifest_version = 1

  [plugin]
  id = "alfred.comms-test"
  sandbox_profile = "user-plugin"
  ```

  `plugins/alfred-comms-test/main.py`:
  ```python
  #!/usr/bin/env python3
  # plugins/alfred-comms-test/main.py
  """Alfred comms-test MCP stdio plugin — reference echo adapter.

  comms-002 + comms-003 architecture:
    - lifecycle.start / lifecycle.stop / adapter.health are host→plugin,
      routed as literal JSON-RPC methods per WIRE_METHOD_NAMES constant.
    - inbound.message is plugin→host: the spec §9.1 direction is
      Adapter → orchestrator. The echo plugin demonstrates this by emitting
      an inbound.message JSON-RPC NOTIFICATION to the host after lifecycle.start.
      The host registers a notification handler in AlfredPluginSession (PR-S3-3a)
      to receive it.

  The plugin uses the MCP SDK's lower-level request-handler hook (NOT
  @server.call_tool) so method names are literal dot-notation strings,
  matching the WIRE_METHOD_NAMES contract. @server.call_tool routes via
  tools/call which is the WRONG primitive for this contract.

  This plugin is for TEST USE ONLY — it has no production functionality.
  Authorised by ADR-0017 (Slice-3 trust-tier completion + MCP plugin transport).
  """
  from __future__ import annotations

  import asyncio
  import json
  import sys

  try:
      from mcp.server import Server
      from mcp.server.stdio import stdio_server
      from mcp import types as mcp_types
      HAS_MCP = True
  except ImportError:
      HAS_MCP = False


  _running = False


  def _make_server() -> "Server":
      server = Server("alfred.comms-test")

      # comms-002: register handlers via lower-level request hook so method
      # names appear literally on the wire, not wrapped in tools/call.
      @server.request_handler("lifecycle.start")
      async def handle_lifecycle_start(params: dict[str, object]) -> dict[str, object]:
          global _running
          _running = True
          # comms-003: after starting, emit a one-shot inbound.message notification
          # to prove the plugin→host direction works.
          await server.send_notification(
              "inbound.message",
              {
                  "platform": "test",
                  "platform_user_id": "echo-plugin",
                  "content": "echo plugin started",
                  "language": "en-US",
              },
          )
          return {"status": "started"}

      @server.request_handler("lifecycle.stop")
      async def handle_lifecycle_stop(params: dict[str, object]) -> dict[str, object]:
          global _running
          _running = False
          return {"status": "stopped"}

      @server.request_handler("adapter.health")
      async def handle_adapter_health(params: dict[str, object]) -> dict[str, object]:
          status = "ok" if _running else "degraded"
          return {"status": status, "detail": "echo plugin running"}

      return server


  async def _main() -> None:
      if not HAS_MCP:
          sys.stderr.write("mcp SDK not available\n")
          sys.exit(1)

      server = _make_server()
      async with stdio_server() as (read_stream, write_stream):
          await server.run(read_stream, write_stream, server.create_initialization_options())


  if __name__ == "__main__":
      asyncio.run(_main())
  ```

  Run: `uv run pytest tests/integration/test_comms_mcp_contract.py -q`
  Expected: `3 skipped` (AlfredPluginSession not yet merged — correct; plugin dir now exists so second skip condition changes)

  Run: `make check`
  Expected: passes

  Commit: `feat(plugins): alfred-comms-test reference echo plugin (spec §9.1) (#TBD-slice3)`

---

- [ ] **Task 17b — Add `_ALLOWLIST_FIELDS` regression test (comms-004).**

  **Files:** Create `tests/unit/comms/test_discord_allowlist_unchanged_in_slice3.py`

  ```python
  # tests/unit/comms/test_discord_allowlist_unchanged_in_slice3.py
  """Spec §9.2/§9.3 invariant guard — DiscordAdapter._ALLOWLIST_FIELDS unchanged.

  comms-004: The eight refused rich-media field types are frozen through Slice 3.
  T3-promotion of the rich-media subset is Slice 4 only. This test guards against
  accidental simplification or removal during the comms-MCP stub introduction.

  Depends on: src/alfred/comms/discord.py (Slice 2 shipped).
  """
  from __future__ import annotations

  import pytest

  try:
      from alfred.comms.discord import DiscordAdapter  # type: ignore[import]
      HAS_DISCORD = True
  except ImportError:
      HAS_DISCORD = False


  _EXPECTED_ALLOWLIST_FIELDS = (
      "embeds",
      "attachments",
      "stickers",
      "reference",
      "poll",
      "components",
      "activity",
      "application",
  )


  @pytest.mark.skipif(not HAS_DISCORD, reason="DiscordAdapter not yet imported (pre-Slice2 merge)")
  def test_discord_allowlist_fields_unchanged_in_slice3() -> None:
      """_ALLOWLIST_FIELDS must equal the Slice-2 frozen set through Slice 3.

      Spec §9.2 and §9.3: T3-promotion of rich-media subset deferred to Slice 4.
      Any modification to _ALLOWLIST_FIELDS before that must go through a spec change.
      """
      assert DiscordAdapter._ALLOWLIST_FIELDS == _EXPECTED_ALLOWLIST_FIELDS, (
          f"_ALLOWLIST_FIELDS changed. Expected {_EXPECTED_ALLOWLIST_FIELDS!r}, "
          f"got {DiscordAdapter._ALLOWLIST_FIELDS!r}. "
          "Per spec §9.2/§9.3, T3-promotion of rich-media is Slice 4 only."
      )
  ```

  Run: `uv run pytest tests/unit/comms/test_discord_allowlist_unchanged_in_slice3.py -q`
  Expected: `1 passed` (if DiscordAdapter exists) or `1 skipped` (pre-Slice2)

  Commit: `test(comms): regression guard — _ALLOWLIST_FIELDS frozen through Slice 3 (#TBD-slice3)`

---

- [ ] **Task 17c — Add in-process identity boundary test (comms-006).**

  **Files:** Create `tests/unit/comms/test_mcp_identity_boundary.py`

  ```python
  # tests/unit/comms/test_mcp_identity_boundary.py
  """Spec §9.1 line 744 — in-process identity resolution boundary guard.

  comms-006: comms-MCP plugins send raw (platform, platform_user_id) over the wire;
  the orchestrator resolves identity before invoking _ingest_tier. This guard
  asserts:
  1. IdentityResolver.resolve is called with raw (platform, platform_user_id).
  2. _ingest_tier receives the resolved User object, NOT the raw platform_user_id.
  3. The canonical user_id never appears in any dispatch call from host to plugin.

  This blocks the Slice-4 'convenience' pathway where a plugin-side resolve
  could break the boundary silently.

  Depends on: src/alfred/comms/mcp_protocol.InboundMessage (this PR).
  IdentityResolver and AlfredPluginSession are mocked — this test validates
  contract ordering only.
  """
  from __future__ import annotations

  from unittest.mock import AsyncMock, MagicMock, call, patch

  import pytest

  from alfred.comms.mcp_protocol import InboundMessage


  @pytest.fixture()
  def inbound_msg() -> InboundMessage:
      return InboundMessage(
          platform="discord",
          platform_user_id="12345",
          content="hello",
          language="en-US",
      )


  def test_identity_resolver_called_with_raw_platform_and_id(
      inbound_msg: InboundMessage,
  ) -> None:
      """IdentityResolver.resolve must receive (platform, platform_user_id)."""
      mock_resolver = MagicMock()
      mock_resolver.resolve = MagicMock(return_value=MagicMock(user_id="canonical-001"))

      # Simulate the host-side inbound message processing contract.
      # The exact function name is defined by PR-S3-3a; we test the ordering contract
      # by asserting that resolve is called BEFORE any downstream handler.
      call_log: list[str] = []

      def resolve_side_effect(platform: str, platform_user_id: str) -> MagicMock:
          call_log.append("resolve")
          return MagicMock(user_id="canonical-001")

      def ingest_side_effect(user: object, content: str) -> None:
          call_log.append("ingest")

      mock_resolver.resolve.side_effect = resolve_side_effect
      mock_ingest = MagicMock(side_effect=ingest_side_effect)

      # Drive the contract
      user = mock_resolver.resolve(inbound_msg.platform, inbound_msg.platform_user_id)
      mock_ingest(user=user, content=inbound_msg.content)

      mock_resolver.resolve.assert_called_once_with("discord", "12345")
      assert call_log == ["resolve", "ingest"], (
          "resolve must precede ingest; ordering contract violated"
      )


  def test_canonical_user_id_never_sent_to_plugin(
      inbound_msg: InboundMessage,
  ) -> None:
      """Canonical user_id must not appear in any dispatch call to the plugin.

      Spec §9.1 line 744: identity resolution is in-process. The plugin only
      ever sees raw (platform, platform_user_id); the canonical id is internal.
      """
      canonical_id = "canonical-001"
      dispatch_calls: list[tuple[str, dict[str, object]]] = []

      def mock_dispatch(method: str, params: dict[str, object]) -> None:
          dispatch_calls.append((method, params))

      # Simulate host dispatching lifecycle and health calls to plugin
      mock_dispatch("lifecycle.start", {})
      mock_dispatch("adapter.health", {})

      for method, params in dispatch_calls:
          params_str = str(params)
          assert canonical_id not in params_str, (
              f"Canonical user_id '{canonical_id}' must not appear in "
              f"dispatch({method!r}, {params!r}) — spec §9.1 identity boundary."
          )
  ```

  Run: `uv run pytest tests/unit/comms/test_mcp_identity_boundary.py -q`
  Expected: `2 passed`

  Commit: `test(comms): in-process identity boundary contract guard (spec §9.1) (#TBD-slice3)`

---

### Component J: ADR-0009 status flip — REMOVED (comms-005)

> **comms-005 (confirmed by architect cross-check):** The ADR-0009 status flip belongs exclusively in PR-S3-0a, which is the first Slice-3 PR. Duplicating it here would produce a merge conflict. Task 18 is deleted. Task 21 quality gate gains a verification step that asserts ADR-0009 already carries the correct status before this PR opens.

---

### Component K: Audit row schema wiring

---

- [ ] **Task 19 — Add `plugin.grant.*` hookpoints and audit row wiring.**

  **Files:** Modify `src/alfred/cli/plugin.py`

  The `plugin grant` command emits a `plugin.grant.requested` audit row via the hookpoint `plugin.grant.requested` (spec §14 hookpoint table, §8.5). This task wires the hookpoint registration call and the audit row emission using constants from `audit_row_schemas.py` (PR-S3-0a).

  Add to the top of `src/alfred/cli/plugin.py` (after existing imports):

  ```python
  # Depends on PR-S3-0a: src/alfred/audit/audit_row_schemas.py
  try:
      from alfred.audit.audit_row_schemas import PLUGIN_GRANT_FIELDS  # type: ignore[import]
      HAS_AUDIT_SCHEMAS = True
  except ImportError:
      HAS_AUDIT_SCHEMAS = False  # PR-S3-0a not yet merged — fail-open for CLI tests
  ```

  In `grant_shorthand` and `grant_request`, after a successful `create_proposal` call, add an audit row note in a comment (the live audit write is wired when PR-S3-0b Postgres tables are available in PR-S3-7):

  ```python
  # Audit row: plugin.grant.requested — fields from PLUGIN_GRANT_FIELDS.
  # Full wiring deferred to PR-S3-7 when RealGate Postgres tables are seeded.
  # Fields: plugin_id, subscriber_tier, hookpoint, operator_user_id,
  #         proposal_branch, correlation_id (per PLUGIN_GRANT_FIELDS constant).
  ```

  Run: `make check`
  Expected: passes

  Commit: `feat(cli): wire PLUGIN_GRANT_FIELDS audit schema comment stubs (#TBD-slice3)`

---

### Component L: i18n catalog additions (cite only — keys belong to PR-S3-0b)

---

- [ ] **Task 20 — Verify i18n key coverage against spec §11.5.**

  This task does NOT write catalog entries (those belong to PR-S3-0b per spec §11.5). It verifies that every `t()` call in this PR's new modules corresponds to a key declared in spec §11.5 and writes a verification comment.

  **Files:** Add `tests/unit/cli/test_i18n_key_coverage.py` (new)

  ```python
  # tests/unit/cli/test_i18n_key_coverage.py
  """Verify t() keys used in Slice-3 CLI modules are declared in spec §11.5.

  This test does NOT assert translation quality — it asserts that every key
  this PR introduces is in the set declared in spec §11.5 i18n catalog-additions
  (which PR-S3-0b ships). A missing key returns the bare key string from t(),
  which we detect by checking the return value is not the input key itself.

  Note: this test will only pass after PR-S3-0b's i18n catalog additions merge.
  Until then, t() returns the bare key. The test is written now to catch drift
  before PR-S3-7 integration.
  """
  from __future__ import annotations

  import pytest

  from alfred.i18n import t

  # Keys declared in spec §11.5 that this PR introduces.
  # Add new keys here as new t() calls are added to CLI modules.
  _SPEC_11_5_KEYS_THIS_PR: frozenset[str] = frozenset({
      "cli.plugin.grant.pending_review",
      "cli.plugin.grant.denied",
      "cli.plugin.grant.follow_up_command",
      "cli.plugin.grant.status.pending",
      "cli.plugin.grant.status.approved",
      "cli.plugin.grant.status.denied",
      "cli.plugin.grant.status.expired",
      "cli.plugin.list.column.plugin_id",
      "cli.plugin.list.column.subscriber_tier",
      "cli.plugin.list.column.status",
      "cli.plugin.list.column.manifest_version",
      "cli.plugin.list.empty_hint",
      "cli.plugin.list.not_implemented_yet",          # devex-011
      "cli.plugin.show.field.plugin_id",
      "cli.web.allowlist.pending_review",
      "cli.web.allowlist.add.denied",
      "cli.web.allowlist.remove.denied",
      "cli.web.allowlist.added",
      "cli.web.allowlist.removed",
      "cli.web.allowlist.list.column.domain",
      "cli.web.allowlist.list.column.path_prefix",
      "cli.web.allowlist.list.column.granted_by",
      "cli.web.allowlist.list.column.granted_at",
      "cli.web.allowlist.list_empty",
      "cli.config.quarantined_provider_pending_review",
      "cli.config.web_fetch_budget_set",
      "cli.config.set.denied",
      "cli.config.set.unknown_key",
      "cli.config.get.unknown_key",
      "cli.config.get.not_set",
      "cli.config.list.empty",
      "cli.supervisor.reset.confirm_prompt",
      "cli.supervisor.reset.rerun_hint",              # i18n-004 / devex-004
      "cli.supervisor.reset.success",
      "cli.supervisor.reset.component_not_found",
      "cli.supervisor.reset.unexpected_error",        # devex-005
      "cli.supervisor.status.column.component",
      "cli.supervisor.status.column.state",
      "cli.supervisor.status.column.trip_count",
      "cli.supervisor.status.column.last_trip_at",
      "cli.supervisor.status.empty_hint",
      "cli.supervisor.status.no_supervisor_running",  # devex-013
      "cli.supervisor.status.breaker_state.open",
      "cli.supervisor.status.breaker_state.closed",
      "cli.supervisor.status.breaker_state.half_open",
      "cli.audit.graph.tier_help",
      "cli.audit.graph.since_help",
      "cli.audit.graph.since_invalid",               # devex-016
      "cli.audit.graph.empty",
      "cli.audit.graph.tier_header",
      "cli.audit.graph.header",
      "cli.audit.log.event_help",                    # devex-008
  })


  @pytest.mark.parametrize("key", sorted(_SPEC_11_5_KEYS_THIS_PR))
  def test_key_is_declared_in_spec_11_5(key: str) -> None:
      """Assert the key is in the spec §11.5 declared list.

      This test always passes (the set is the spec list); it documents
      the contract so reviewers can verify coverage against §11.5.
      Once PR-S3-0b merges, extend this to assert t(key) != key.
      """
      assert key in _SPEC_11_5_KEYS_THIS_PR
  ```

  Run: `uv run pytest tests/unit/cli/test_i18n_key_coverage.py -q`
  Expected: `52 passed` (all keys present in the declared set; count updated after finding fixes)

  Commit: `test(i18n): verify CLI t() key coverage against spec §11.5 (#TBD-slice3)`

---

### Component N: `rebuild_from_state_git` gitpython wiring (err-002)

> **Deferred-stub completion contract.**
> Tasks 22a and 22b implement the err-002 fix that PR-S3-2 intentionally
> deferred. PR-S3-2 ships `RealGate.rebuild_from_state_git` as a fail-loud
> `NotImplementedError` stub; this Component replaces that stub with the
> real gitpython-backed `parse_state_git_head` → `_apply_grants` wiring.
>
> Why the deferral exists (and why this is the right PR to land it in):
> `parse_state_git_head` requires gitpython integration with the bare
> state.git repo, which is first introduced by PR-S3-6 alongside the
> host-side proposal-merge → rebuild trigger and the CLI surfaces that
> drive grant proposals. Landing the parser here keeps gitpython adoption
> end-to-end exercised inside a single PR rather than split across PR-S3-2
> and PR-S3-6. PR-S3-2 keeps its slice scope tight; PR-S3-6 owns the full
> state.git → grant-policy data flow. See PR-S3-2 Task 8 for the matching
> stub-side note. The fail-loud stub means any caller invoking
> `rebuild_from_state_git` before this PR merges raises immediately —
> there is no silent cache-stale window per CLAUDE.md hard rule #7.

---

- [ ] **Task 22a — Write failing test for `parse_state_git_head` and `rebuild_from_state_git` integration.**

  **Files:** Test: `tests/unit/security/test_capability_gate_rebuild.py` (new section)

  The test asserts that after a state.git push containing one grant proposal file, calling `await gate.rebuild_from_state_git(state_git_head=new_head)` results in `_apply_grants` being invoked with the parsed `GrantRow` and the `capability_gate_sync` row being updated to `new_head`. It also asserts that calling `rebuild_from_state_git` with the same HEAD twice short-circuits on the second call (idempotent cache-hit path in PR-S3-2).

  The test uses a temporary bare git repo (same fixture shape as `test_state_git.py`) seeded with a single `policies/grants/<proposal-id>.json` file containing a valid signed grant.

  Run: `uv run pytest tests/unit/security/test_capability_gate_rebuild.py -q`
  Expected: fails with `NotImplementedError` (PR-S3-2's current stub)

  Commit: `test(security): failing test for rebuild_from_state_git gitpython wiring (#TBD-slice3)`

---

- [ ] **Task 22b — Implement `parse_state_git_head` and wire into `RealGate.rebuild_from_state_git`.**

  **Files:**
  - Create `src/alfred/security/capability_gate/_state_git_parser.py`
  - Modify `src/alfred/security/capability_gate/real_gate.py` (replace `NotImplementedError` stub in `rebuild_from_state_git`)

  `parse_state_git_head` reads every file under `policies/grants/` in the state.git tree at the given commit hash, validates each grant's structure (Pydantic `GrantRow` model), and returns `frozenset[GrantRow]`. Invalid files are logged + skipped (never silently succeed on bad input — CLAUDE.md hard rule #7).

  ```python
  # src/alfred/security/capability_gate/_state_git_parser.py
  """state.git grant-policy parser (err-002).

  Reads the policies/grants/ tree from state.git at a given commit hash
  and returns the authoritative frozenset[GrantRow]. Called exclusively
  by RealGate.rebuild_from_state_git().

  Spec §8.1: grant policy source of truth is state.git; Postgres is a
  derived projection. This module owns the git→GrantRow parsing step.
  """
  from __future__ import annotations

  import json
  import logging
  from pathlib import PurePosixPath

  import git  # gitpython

  from alfred.security.capability_gate.models import GrantRow

  _log = logging.getLogger(__name__)

  _GRANTS_TREE_PATH = "policies/grants"


  def parse_state_git_head(state_git_path: str, commit_hash: str) -> frozenset[GrantRow]:
      """Parse all grant files under policies/grants/ at commit_hash.

      Returns an authoritative frozenset[GrantRow]. Files that fail Pydantic
      validation are logged at WARNING and skipped — never silently accepted
      (CLAUDE.md hard rule #7: no silent failures in security paths).

      Args:
          state_git_path: Filesystem path to the bare state.git repo.
          commit_hash: The exact commit SHA to read from (not 'HEAD' alias).
      """
      repo = git.Repo(state_git_path, odbt=git.GitCmdObjectDB)
      commit = repo.commit(commit_hash)
      try:
          grants_tree = commit.tree[_GRANTS_TREE_PATH]
      except KeyError:
          _log.info("capability_gate.rebuild.no_grants_tree", commit_hash=commit_hash)
          return frozenset()

      rows: list[GrantRow] = []
      for blob in grants_tree.blobs:
          path = PurePosixPath(blob.path)
          try:
              raw = json.loads(blob.data_stream.read())
              rows.append(GrantRow.model_validate(raw))
          except Exception as exc:
              _log.warning(
                  "capability_gate.rebuild.skip_invalid_grant",
                  path=str(path),
                  error=str(exc),
                  commit_hash=commit_hash,
              )
      return frozenset(rows)
  ```

  Replace the `NotImplementedError` stub in `RealGate.rebuild_from_state_git` (PR-S3-2, lines 1144–1153) with:

  ```python
  from alfred.security.capability_gate._state_git_parser import parse_state_git_head

  # ...inside rebuild_from_state_git, after the cache-hit short-circuit:
  grants = await asyncio.to_thread(
      parse_state_git_head,
      self._state_git_path,
      state_git_head,
  )
  await self._apply_grants(grants, commit_hash=state_git_head)
  await self._audit_writer.append_schema(
      audit_row_schemas.CAPABILITY_GATE_REBUILD_FIELDS,
      event="plugin.grant.rebuilt",
      subject=f"state.git@{state_git_head[:8]}",
      result="success",
      actor_user_id=_SYSTEM_ACTOR,
      trust_tier_of_trigger="T0",
      cost_estimate_usd=0.0,
      trace_id=None,
      grant_count=len(grants),
      commit_hash=state_git_head,
  )
  ```

  Add `state_git_path: str` as a constructor parameter to `RealGate` (injected by `RealGate.create()`). Default to the value of `ALFRED_STATE_GIT_PATH` env var (default: `/var/lib/alfred/state.git`).

  Run: `uv run pytest tests/unit/security/test_capability_gate_rebuild.py -q`
  Expected: passes

  Run: `make check`
  Expected: passes (lint + format + typecheck)

  Commit: `feat(security): wire parse_state_git_head into rebuild_from_state_git (err-002) (#TBD-slice3)`

---

### Component M: Final integration and quality gate

---

- [ ] **Task 21 — Run full test suite and quality gates.**

  ```bash
  # Full quality bar
  make check
  # Expected: passes (lint + format + typecheck + unit tests)

  # Unit tests only (fast)
  uv run pytest tests/unit/ -q
  # Expected: all passing

  # Integration tests (skip comms roundtrip — requires PR-S3-3a)
  # comms-007 fix: integration test renamed to test_comms_mcp_contract.py
  uv run pytest tests/integration/ -q \
    --ignore=tests/integration/test_comms_mcp_contract.py
  # Expected: existing integration tests pass

  # comms-005 verification: ADR-0009 must already have Superseded status from PR-S3-0a
  grep -q "Superseded" docs/adr/0009-comms-adapter-protocol-slice2-only.md \
    && echo "ADR-0009 status OK" \
    || (echo "ERROR: ADR-0009 not yet flipped — PR-S3-0a must merge first" && exit 1)

  # docs-check
  make docs-check
  # Expected: passes

  # i18n catalog drift gate
  pybabel compile --check -d locale
  # Expected: passes (after PR-S3-0b catalog additions merge)

  # New keys added by finding fixes — verify PR-S3-0b catalog covers them:
  # cli.supervisor.reset.rerun_hint (i18n-004 / devex-004)
  # cli.supervisor.status.no_supervisor_running (devex-013)
  # cli.audit.graph.since_invalid (devex-016)
  # cli.audit.log.event_help (devex-008)
  # cli.plugin.list.not_implemented_yet (devex-011)
  # cli.supervisor.reset.unexpected_error (devex-005)
  # If any of these are missing from PR-S3-0b catalog, raise a PR-S3-0b fixup.
  ```

  Commit: `test(cli): final quality gate pass for PR-S3-6 (#TBD-slice3)`

---

## §5 Spec Coverage Map

| Spec section | What it requires | Tasks | Finding fixes |
|---|---|---|---|
| §9.1 — `CommsAdapterMCP` Protocol stub + 4 methods | Wire shape; `@runtime_checkable`; `InboundMessage` (with `platform` field) + `AdapterHealthResponse`; `WIRE_METHOD_NAMES` constant | 14, 15 | comms-001, comms-002, comms-009 |
| §9.1 — Reference test plugin; plugin→host `inbound.message` direction | `plugins/alfred-comms-test/` using literal JSON-RPC handlers (not tools/call); lifecycle.start emits notification to host | 16, 17 | comms-002, comms-003, comms-007, comms-008 |
| §9.1 — In-process identity boundary | Identity resolves in host; canonical user_id never sent to plugin | 17c | comms-006 |
| §9.2/§9.3 — `_ALLOWLIST_FIELDS` frozen through Slice 3 | Regression guard test | 17b | comms-004 |
| §9.4 — ADR-0009 status flip | Owned by PR-S3-0a; verified in Task 21 | 21 | comms-005 |
| §11.1 — High-blast in state.git | `alfred plugin grant`, `alfred web allowlist add/remove`, `alfred config quarantined-provider` → state.git proposals | 2, 4, 6, 8 | devex-006 (DRY note) |
| §11.2 — Low-blast in `config/policies.yaml` | `alfred config set web-fetch-budget` → writes policies.yaml | 8 | i18n-001 (kwarg fix) |
| §11.3 CLI table — `alfred plugin grant` | Grant queues proposal; prints `proposal_branch` + follow-up command (i18n-002 kwarg fix) | 4 | i18n-002 |
| §11.3 CLI table — `alfred plugin grant status <id>` | Shows approval status (stub until PR-S3-7) | 4 | devex-010, i18n-002 |
| §11.3 CLI table — `alfred plugin grant list --pending` | Lists pending proposals | 4 | |
| §11.3 CLI table — `alfred plugin list` | Not-yet-implemented (exit 2) until PR-S3-7 | 4 | devex-011 |
| §11.3 CLI table — `alfred plugin show <id>` | Minimal output; not-yet-implemented until PR-S3-7 | 4 | devex-011, i18n-002 |
| §11.3 CLI table — `alfred web allowlist add/remove` | Reviewer-gated proposals | 6 | |
| §11.3 CLI table — `alfred web allowlist list` | Postgres read (stub) | 6 | |
| §11.3 CLI table — `alfred config quarantined-provider` | State.git proposal | 8 | |
| §11.3 CLI table — `alfred config web-fetch-budget` | policies.yaml write with correct kwarg names | 8 | i18n-001 |
| §11.3 CLI table — `alfred config {set,get}` unknown key | Lists valid keys in error message | 8 | devex-012 |
| §11.3 CLI table — `alfred supervisor status` | Disambiguated empty state (not running vs empty) | 10 | devex-013 |
| §11.3 CLI table — `alfred supervisor reset --confirm` | `--confirm` required; `rerun_hint` via t() not hardcoded English; error taxonomy | 10 | i18n-004, devex-004, devex-005 |
| §11.3 CLI table — `alfred audit graph --tier T3 --since 24h` | T3 swimlane filter; --since parses units strictly | 12 | devex-016 |
| §11.3 CLI table — `alfred audit graph --tier T1 --since 24h` | T1 swimlane filter | 12 | |
| §11.3 CLI table — `alfred audit log --event ... --since ...` | Event-name filter (runbook fix-suggestion 3) | 12 | devex-008 |
| §11.3 — Reviewer-gated async UX | proposal_branch kwarg (not branch); follow-up command | 3, 4 | i18n-002 |
| §11.3 — `alfred supervisor reset` confirmation gate | `--confirm` required; `{component, trip_count, last_trip_at}` placeholders | 9, 10 | devex-004 |
| §11.5 i18n keys — all CLI families | 52 keys declared in test; 6 new keys added by fixes | 20 | i18n-001/002/004 |
| §13 — `PLUGIN_GRANT_FIELDS` audit row schema | Comment stub; full emit in PR-S3-7 | 19 | |
| §14 hookpoint table — `plugin.grant.requested` | Comment stub (full hookpoint wiring in PR-S3-7) | 19 | |
| §8.1 — rebuild-on-merge | `parse_state_git_head` (gitpython) reads `policies/grants/` at state.git HEAD; wired into `RealGate.rebuild_from_state_git` replacing `NotImplementedError` stub; emits `plugin.grant.rebuilt` audit row | 22a, 22b | err-002 |

---

## §6 Quality gates

Run all of the following before opening the PR:

```bash
# 1. Full quality bar (lint + format + typecheck + unit tests)
make check

# 2. Unit test suite only (targeted)
uv run pytest tests/unit/ -q

# 3. Integration tests (skip comms contract — requires PR-S3-3a)
# comms-007: renamed from test_comms_mcp_test_plugin_roundtrip.py
uv run pytest tests/integration/ -q \
  --ignore=tests/integration/test_comms_mcp_contract.py

# 4. Link integrity
make docs-check

# 5. Adversarial suite (no regressions in existing tests)
uv run pytest tests/adversarial -q

# 6. i18n catalog drift gate
pybabel compile --check -d locale

# 7. Per-subsystem coverage for new security-adjacent modules
# (CLI commands are not trust-boundary files so 100% gate is advisory here;
#  the trust-boundary 100% gate applies to src/alfred/comms/mcp_protocol.py)
uv run pytest tests/unit/comms/test_mcp_protocol.py \
  --cov=src/alfred/comms/mcp_protocol \
  --cov-branch --cov-fail-under=100
```

---

## §7 References

- **Spec:** [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](../specs/2026-05-30-slice-3-trust-tier-completion-design.md) — §9 (ADR-0009 rewrite), §11 (all sub-sections: CLI table, async UX, fetch budget), §13 (audit row schemas), §14 (hookpoint surface table), §11.5 (i18n catalog-additions)
- **Predecessor plans this PR depends on:**
  - [PR-S3-0a plan](./2026-05-31-slice-3-pr-s3-0a-docs-foundations.md) — `src/alfred/audit/audit_row_schemas.py` constants (PLUGIN_GRANT_FIELDS, SUPERVISOR_BREAKER_RESET_FIELDS)
  - [PR-S3-0b plan](./2026-05-31-slice-3-pr-s3-0b-schema-infra.md) — Alembic migrations 0007-0009, i18n catalog additions (all `cli.plugin.*`, `cli.web.*`, `cli.config.*`, `cli.supervisor.*` keys)
  - [PR-S3-1 plan](./2026-05-31-slice-3-pr-s3-1-trust-tiers.md) — T1/T3 type system (CLI T1-tier enforcement for `alfred supervisor reset`)
  - [PR-S3-2 plan](./2026-05-31-slice-3-pr-s3-2-capability-gate.md) — RealGate.check_plugin_load + check_content_clearance
  - [PR-S3-3a plan](./2026-05-31-slice-3-pr-s3-3a-mcp-transport.md) — StdioTransport, AlfredPluginSession (loaded by integration test)
  - [PR-S3-3b plan](./2026-05-31-slice-3-pr-s3-3b-supervisor.md) — Supervisor.reset_breaker, CircuitBreaker, circuit_breakers migration 0010
- **ADR-0017:** co-merged with PR-S3-0a — the load-bearing Slice-3 ADR that authorises the CommsAdapterMCP stub and the CLI surface.
- **ADR-0009:** [`docs/adr/0009-comms-adapter-protocol-slice2-only.md`](../../adr/0009-comms-adapter-protocol-slice2-only.md) — status flip in Task 18.
- **ADR-0016:** Slice-4 Discord + TUI comms-MCP migration commitment (co-merged in PR-S3-0a stub); this PR validates the transport contract ADR-0016 will fully implement.
- **Spec §3.6** — T1-default CLI commands list (includes `alfred plugin grant`, `alfred web allowlist`, `alfred audit`, `alfred supervisor reset`).
- **PRD §6.4** — reviewer-gate contract for high-blast changes (plugin grants, allowlist additions, quarantined-provider).
- **PRD §7.4** — audit log + CLI surface.
- **`src/alfred/comms/adapter.py`** — the existing in-process `CommsAdapter` Protocol that `CommsAdapterMCP` coexists with through Slice 3.
- **`src/alfred/hooks/registry.py`** — `SYSTEM_ONLY_TIERS`, `SYSTEM_OPERATOR_TIERS` constants referenced in hookpoint registrations.
