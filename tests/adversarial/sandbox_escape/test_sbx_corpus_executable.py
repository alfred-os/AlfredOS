"""Executable counterparts to the sbx-2026-* sandbox-escape payloads (PR-S4-6).

The YAML payloads are density- + schema-validated elsewhere, but neither
EXERCISES the runtime defence. This module loads each PR-S4-6 payload and
drives the REAL launcher / manifest parser / fd-3 delivery / session
handshake, asserting the declared ``expected_outcome`` actually fires at the
trust boundary — not just a Pydantic refusal at parse time.

PR-S4-7 ships the kernel-observable bwrap-escape payloads (filesystem,
network, process-fork); those need the real policy bytes to be meaningful.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from alfred.audit.launcher_refusal import parse_launcher_refusal_rows
from alfred.plugins.errors import (
    ManifestError,
    ManifestSandboxMissingError,
    SandboxInfoHandshakeMismatch,
)
from alfred.plugins.manifest import parse_manifest
from alfred.plugins.manifest_reader import PolicyRefEscapesRoot, resolve_policy_ref
from alfred.plugins.sandbox_policy import (
    SandboxPolicyInvalid,
    policy_to_bwrap_flags,
    read_policy_toml,
)
from alfred.plugins.session import AlfredPluginSession
from alfred.supervisor.fd3_key_delivery import (
    ProviderKeyDeliveryError,
    deliver_provider_key_via_fd3,
)
from tests._sandbox_interp import interpreter_sandbox_roots
from tests.adversarial.payload_schema import AdversarialPayload

_DIR = Path(__file__).parent
_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"
_HAS_JQ = shutil.which("jq") is not None
_HAS_BWRAP = shutil.which("bwrap") is not None
_QUARANTINED_LINUX_POLICY = _REPO_ROOT / "config" / "sandbox" / "quarantined-llm.linux.bwrap.policy"
_DISCORD_LINUX_POLICY = _REPO_ROOT / "config" / "sandbox" / "discord-adapter.linux.bwrap.policy"


def _load(payload_id: str) -> AdversarialPayload:
    path = next(_DIR.glob(f"{payload_id.replace('-', '_')}*.yaml"))
    return AdversarialPayload.model_validate(yaml.safe_load(path.read_text()))


def _real_policy_flags_with_test_binds(plugin_dir: Path) -> list[str]:
    """bwrap flags from the REAL quarantined-LLM Linux policy + test binds.

    The shipped policy binds /usr, /lib, /lib64 (the system interpreter), but
    the corpus runs under the pytest venv interpreter (``sys.executable``) whose
    prefix + the stub's ``plugin_dir`` (pytest tmp_path) are NOT under those
    system binds. We therefore translate the REAL policy and APPEND the minimal
    extra ro_binds the test interpreter needs — never removing any of the
    policy's own confinement (no /etc, no /bin, unshare-pid/uts/cgroup/ipc,
    die_with_parent). This is the same templating the PR-S4-6 resolver fixture
    does; it keeps the escape assertions meaningful against the shipped bytes.

    We also DROP the policy's tmpfs (``/run/alfred/quarantined``) from the test
    flag set: creating it needs the path to exist as a mountpoint inside the
    fresh root, which is fine, but it is irrelevant to the filesystem/exec
    containment assertions and keeps the bwrap invocation minimal.
    """
    policy = read_policy_toml(_QUARANTINED_LINUX_POLICY.read_text())
    flags = policy_to_bwrap_flags(policy)
    # Prune (a) the --tmpfs <scratch> pair — irrelevant to containment, avoids a
    # mountpoint dependency in the test root — and (b) any HARD --ro-bind whose
    # SOURCE does not exist on this host (a defensive prune; the shipped hard binds
    # /usr and /lib exist on every arch).
    #
    # `--ro-bind-try` pairs are deliberately NOT pruned: since #269 the policy
    # soft-binds /lib64 (a real dir on x86-64 holding ld-linux-x86-64.so.2; absent
    # on aarch64, where the loader arrives via the already-bound /lib), and bwrap
    # itself skips a soft bind whose source is missing. Passing them through
    # verbatim is what keeps this corpus running against the PRODUCTION flag list
    # on both arches — pruning them would silently diverge the payloads from the
    # policy they exist to prove.
    pruned: list[str] = []
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag == "--tmpfs":
            i += 2
            continue
        if flag == "--ro-bind" and not Path(flags[i + 1]).exists():
            i += 3
            continue
        if flag == "--ro-bind":
            pruned += flags[i : i + 3]
            i += 3
            continue
        pruned.append(flag)
        i += 1
    # Append the test-interpreter + plugin_dir binds.
    # ``interpreter_sandbox_roots`` walks ``sys.executable``'s full symlink chain
    # (venv + base interpreter install + any uv minor-version alias hop, e.g.
    # ``cpython-3.14-`` -> ``cpython-3.14.6-``) so the venv interpreter is
    # exec'able in bwrap regardless of the uv-managed interpreter location. Skip
    # anything already under a system bind so we never double-bind /usr.
    interp_roots = interpreter_sandbox_roots() | {str(plugin_dir)}
    appended_roots = [
        root
        for root in sorted(interp_roots)
        if Path(root).exists() and not root.startswith(("/usr", "/lib", "/bin"))
    ]
    # finding-3 (PR #231): the test broadens the read surface with interpreter +
    # plugin_dir binds. A venv-layout shift must NEVER let one of those resolve
    # under /etc or /bin and silently widen the sandbox's read surface — fail
    # loud here instead.
    assert not any(
        os.path.realpath(root).startswith(("/etc", "/bin")) for root in appended_roots
    ), f"test bind resolves under /etc or /bin — would widen the sandbox: {appended_roots}"
    extra: list[str] = []
    for root in appended_roots:
        extra += ["--ro-bind", root, root]
    return pruned + extra


def _skip_if_netns_unconfigurable(result: subprocess.CompletedProcess[str]) -> None:
    """Skip LOUDLY if bwrap could not configure the unshared net namespace.

    Spec C G7-1 (#333) added ``--unshare-net`` to the real quarantined-LLM policy.
    bwrap brings up loopback in the new net namespace via netlink (RTM_NEWADDR);
    some unprivileged userns (e.g. GitHub-Actions runners without CAP_NET_ADMIN)
    forbid that, so bwrap exits BEFORE the child runs and the containment probes
    are not exercisable. Skip loudly rather than fail or silent-pass — mirroring
    ``test_launcher_policy_resolver.py::test_plugin_cannot_open_outbound_network``.

    The signature (rc != 0 AND ``RTM_NEWADDR`` in stderr) is specific to netns
    SETUP failing before the child runs; a real containment regression runs the
    child and surfaces its own sentinel (``PASSWD_READ_OK`` / ``KEY_READ`` etc.)
    with no RTM_NEWADDR, so this guard cannot mask one.
    """
    if result.returncode != 0 and "RTM_NEWADDR" in result.stderr:
        pytest.skip(
            "runner userns cannot configure the unshared net namespace's loopback "
            f"(bwrap: {result.stderr.strip()}); containment probes not exercisable "
            "here (Spec C G7-1 --unshare-net)"
        )


def _run_under_real_policy(stub: Path, plugin_dir: Path) -> subprocess.CompletedProcess[str]:
    """Exec ``sys.executable stub`` under the REAL quarantined-LLM Linux policy.

    Runs bwrap directly with the shipped policy's flags (no launcher / fd-3
    dance needed — these probes assert filesystem/process containment, not key
    delivery). Returns the CompletedProcess so the caller asserts on stdout.
    """
    flags = _real_policy_flags_with_test_binds(plugin_dir)
    bwrap = shutil.which("bwrap")
    assert bwrap is not None  # gated by _HAS_BWRAP on every caller
    result = subprocess.run(  # noqa: S603 — resolved bwrap path, repo-owned probe
        [bwrap, *flags, "--", sys.executable, str(stub)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=_bwrap_child_env(),
    )
    _skip_if_netns_unconfigurable(result)
    return result


def _bwrap_child_env() -> dict[str, str]:
    """Env for the sandboxed interpreter (bwrap inherits it; no --clearenv).

    ``LD_LIBRARY_PATH`` points the loader at the interpreter's lib dirs so a
    dynamically-linked Debian *venv* python (RUNPATH ``$ORIGIN/../lib``, no
    ``/etc/ld.so.cache`` since /etc is unbound) can find ``libpython`` inside
    the sandbox — making the green gate depend on a test guarantee rather than
    the runner's interpreter layout (test-reviewer MEDIUM). The uv-managed
    standalone CPython on the current runner doesn't need it.
    """
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LD_LIBRARY_PATH": f"{sys.base_prefix}/lib:{sys.prefix}/lib:/usr/lib",
    }


def _run_launcher(manifest_body: str, *, environment: str, tmp_path: Path) -> tuple[int, str]:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(manifest_body)
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": environment,
        "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
    }
    # sec-keystone (CR PR #229 finding-1): FAKE_UNAME is a test-only shim that
    # the launcher REFUSES in production. Only set it outside production; in
    # production the launcher uses the real host OS (Linux on CI).
    if environment != "production":
        env["FAKE_UNAME"] = "Linux"
    proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), "attacker.example", str(stub)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return proc.returncode, proc.stderr


def test_sbx_2026_001_sandbox_block_missing(tmp_path: Path) -> None:
    payload = _load("sbx-2026-001")
    assert payload.expected_outcome == "refused"
    # Parser-level: the missing block raises the dedicated error.
    with pytest.raises(ManifestSandboxMissingError):
        parse_manifest(payload.payload["manifest_toml"])
    # Launcher-level (the real subprocess): refuses with the audit reason.
    # CR #229 R2 finding-5: an explicit skip when jq is absent — degrading to
    # parser-only while still reporting green would silently weaken the
    # executable-corpus guarantee (the launcher defence would go unexercised).
    if not _HAS_JQ:
        pytest.skip("jq required for sbx-2026-001 launcher refusal assertion")
    rc, stderr = _run_launcher(
        payload.payload["manifest_toml"], environment="production", tmp_path=tmp_path
    )
    assert rc != 0
    assert "sandbox_block_missing" in stderr


@pytest.mark.skipif(not _HAS_JQ, reason="jq required for the launcher branch")
def test_sbx_2026_002_kind_stub_in_production(tmp_path: Path) -> None:
    payload = _load("sbx-2026-002")
    assert payload.expected_outcome == "refused"
    rc, stderr = _run_launcher(
        payload.payload["manifest_toml"], environment="production", tmp_path=tmp_path
    )
    assert rc != 0
    # low-1: a kind:stub production refusal uses the host-accurate reason
    # (``stub_kind_in_production``) — it must never reuse the windows-specific
    # key on a non-windows host.
    assert "stub_kind_in_production" in stderr
    assert "windows_stub_in_production" not in stderr


@pytest.mark.skipif(not _HAS_JQ, reason="jq required for the launcher branch")
def test_sbx_2026_010_fake_uname_production_bypass_refused(tmp_path: Path) -> None:
    """sec-keystone: ALFRED_ENVIRONMENT=production + FAKE_UNAME=Darwin must NOT
    force the non-Linux unsandboxed exec. The launcher refuses at the FAKE_UNAME
    gate before any host-OS branch.
    """
    payload = _load("sbx-2026-010")
    assert payload.expected_outcome == "refused"
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(payload.payload["manifest_toml"])
    stub = tmp_path / "stub.sh"
    sentinel = tmp_path / "executed.marker"
    stub.write_text(f"#!/bin/sh\ntouch {sentinel}\nexit 0\n")
    stub.chmod(0o755)
    proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), "attacker.example", str(stub)],
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(_REPO_ROOT / "src"),
            "ALFRED_ENVIRONMENT": "production",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "FAKE_UNAME": payload.payload["fake_uname"],
        },
        check=False,
    )
    assert proc.returncode != 0
    assert not sentinel.exists(), "plugin executed unsandboxed — bypass NOT closed"
    assert "fake_uname_in_production" in proc.stderr
    assert "PLUGIN_EXECUTED_UNSANDBOXED" not in proc.stdout
    assert "config_insecure" not in proc.stderr


def test_sbx_2026_007_policy_ref_traversal_refused(tmp_path: Path) -> None:
    payload = _load("sbx-2026-007")
    assert payload.expected_outcome == "refused"
    (tmp_path / "config" / "sandbox").mkdir(parents=True)
    with pytest.raises(PolicyRefEscapesRoot) as exc_info:
        resolve_policy_ref(payload.payload["policy_ref"], install_root=tmp_path)
    assert exc_info.value.reason == "policy_ref_escapes_root"


def test_sbx_2026_008_fd3_partial_write_refused() -> None:
    payload = _load("sbx-2026-008")
    assert payload.expected_outcome == "refused"
    from unittest.mock import patch

    read_fd, write_fd = os.pipe()
    try:
        # Simulate a short write: writev returns fewer bytes than the frame.
        with patch(
            "alfred.supervisor.fd3_key_delivery.os.writev",
            return_value=struct.calcsize(">I"),  # only the prefix made it
        ):
            with pytest.raises(ProviderKeyDeliveryError) as exc_info:
                deliver_provider_key_via_fd3(write_fd=write_fd, key="sk-truncated")
            assert exc_info.value.reason == "provider_key_delivery_failed"
    finally:
        os.close(read_fd)
        with pytest.raises(OSError):
            os.close(write_fd)  # already closed by the refusal path


@pytest.mark.asyncio
async def test_sbx_2026_009_sandbox_info_lie_quarantined() -> None:
    payload = _load("sbx-2026-009")
    assert payload.expected_outcome == "quarantined"
    audit = MagicMock()
    audit.calls = []

    async def _append(**kwargs):
        audit.calls.append(kwargs)

    audit.append_schema = AsyncMock(side_effect=_append)
    gate = MagicMock()
    gate.check_plugin_load = MagicMock(return_value=True)
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)

    manifest = """
[alfred]
manifest_version = 1
[plugin]
id = "attacker.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "none"
"""
    session = await AlfredPluginSession.create(
        manifest_raw=manifest, audit_writer=audit, gate=gate, transport=transport
    )
    await session._on_handshake_complete()
    with pytest.raises(SandboxInfoHandshakeMismatch):
        await session._on_post_handshake_method(
            "sandbox_info",
            {"effective_sandbox_kind": payload.payload["reported_effective_sandbox_kind"]},
        )
    transport.kill.assert_awaited_once()
    assert audit.calls[-1]["event"] == "plugin.lifecycle.quarantined"


def test_sbx_2026_016_over_broad_bind_source_refused() -> None:
    """sbx-2026-016: an over-broad bind source is refused at policy-parse time.

    Iterates the YAML's own ``payload.variants`` list (rather than a second
    hardcoded copy) so the corpus file is the single source of truth and the
    two cannot drift — a variant added to the YAML (e.g. the sec-001
    ``/lib64/../etc`` traversal) is covered here automatically.
    """
    payload = _load("sbx-2026-016")
    assert payload.expected_outcome == "refused"
    assert isinstance(payload.payload, dict)
    variants = payload.payload["variants"]
    assert variants, "payload declares no variants"
    for variant in variants:
        toml = f"{variant}\nkeep_fds = [3]\n"
        with pytest.raises(SandboxPolicyInvalid) as exc:
            read_policy_toml(toml)
        assert exc.value.reason == "bind_source_too_broad", f"variant {variant!r}"


def _policy_ref_charset_injection_manifest_toml(policy_ref: str) -> str:
    """A kind:full manifest embedding a raw attacker-controlled policy_ref.

    TOML basic-string-escapes the value (backslash, double-quote, newline) so
    it round-trips through ``tomllib`` back to the EXACT raw string the
    sbx-2026-017 payload declares — including the newline variant, which a
    TOML literal string cannot represent unescaped on a single line.
    """
    escaped = policy_ref.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return (
        "[alfred]\n"
        "manifest_version = 1\n"
        "[plugin]\n"
        'id = "attacker.example"\n'
        'subscriber_tier = "user-plugin"\n'
        'sandbox_profile = "user-plugin"\n'
        "[sandbox]\n"
        'kind = "full"\n'
        "[sandbox.policy_refs]\n"
        f'linux = "{escaped}"\n'
    )


def test_sbx_2026_017_policy_ref_charset_injection_refused(tmp_path: Path) -> None:
    """sbx-2026-017: a policy_ref carrying JSON-injection characters is refused.

    Iterates the YAML's own ``payload.variants`` list (the #428 lesson — the
    YAML is the single source of truth, no second hardcoded copy).

    Layer 1 (real flow, catches FIRST per the payload's provenance): the
    manifest parser refuses at parse time, before ``SandboxBlock``
    construction. Layer 2 (real end-to-end launcher subprocess): the tainted
    manifest never reaches ``POLICY_REF`` assignment — ``manifest_reader``'s
    ``--read-sandbox`` reports the upstream ``ManifestError`` as
    ``plugin.manifest_invalid``, which the launcher's ``_read_sandbox``
    failure branch (#434A) now maps to the DISTINCT ``manifest_invalid``
    audit reason — no longer collapsed into the benign ``sandbox_block_missing``
    that ``test_sbx_2026_001_sandbox_block_missing`` asserts for a genuinely
    missing ``[sandbox]`` block. The launcher's OWN
    ``policy_ref_charset_invalid`` chokepoint guard is unreachable via any
    real manifest — it is proximate-to-use defense-in-depth, exercised
    directly (via a PATH-shadowed ``python3`` stub simulating an
    upstream-bypassed producer) by
    ``tests/unit/plugins/test_plugin_launcher_stub.py``.
    """
    payload = _load("sbx-2026-017")
    assert payload.expected_outcome == "refused"
    assert isinstance(payload.payload, dict)
    variants = payload.payload["variants"]
    assert variants, "payload declares no variants"
    for variant in variants:
        # match= pins the charset branch specifically (not just any ManifestError).
        with pytest.raises(ManifestError, match=r"path-safe set"):
            parse_manifest(_policy_ref_charset_injection_manifest_toml(variant))
    # CR #229 R2 finding-5: an explicit skip when jq is absent — degrading to
    # parser-only while still reporting green would silently weaken the
    # executable-corpus guarantee (the launcher defence would go unexercised).
    if not _HAS_JQ:
        pytest.skip("jq required for sbx-2026-017 launcher refusal assertion")
    for variant in variants:
        rc, stderr = _run_launcher(
            _policy_ref_charset_injection_manifest_toml(variant),
            environment="production",
            tmp_path=tmp_path,
        )
        assert rc != 0, f"variant {variant!r} was NOT refused by the launcher"
        # #434A: a charset-injected policy_ref is a manifest-level ManifestError,
        # reported as the distinct manifest_invalid TAMPER signal — not the benign
        # sandbox_block_missing (which test_sbx_2026_001 covers for the genuinely
        # missing-block case).
        assert "manifest_invalid" in stderr, f"variant {variant!r}: {stderr!r}"
        # ANTI-ECHO end-to-end: the tainted variant value must not appear in the
        # launcher's output — the upstream refusal never interpolates it, and the
        # launcher's own guard would omit it too. Echoing it would BE the injection.
        assert variant not in stderr, f"variant {variant!r} leaked into stderr: {stderr!r}"


def test_sbx_2026_018_launcher_refusal_row_injection_contained() -> None:
    """sbx-2026-018: injection bytes in a launcher refusal row cannot forge a second
    audit event, smuggle an out-of-vocab reason, nor ride control/format bytes into
    the signed audit log (host-side parser containment, #433 + sec-001 hardening).

    Iterates the YAML's own ``payload.contained_variants`` /
    ``payload.rejected_variants`` lists (the #428 lesson — the YAML is the single
    source of truth, no second hardcoded copy of the variants).

    ``contained_variants`` carry embedded escaped-JSON with NO control/format bytes:
    line-oriented parsing keeps them a single string field, so each parses to
    exactly one genuine row and no forged second row. ``rejected_variants`` carry a
    control/format character (newline, ANSI ESC, bidi override), a non-string field
    value, or an out-of-vocab reason: each is dropped loudly, admitting zero rows —
    so injection bytes can never reach the signed audit log.
    """
    payload = _load("sbx-2026-018")
    assert payload.expected_outcome == "refused"
    assert isinstance(payload.payload, dict)
    contained = payload.payload["contained_variants"]
    rejected = payload.payload["rejected_variants"]
    assert contained and rejected, "payload declares no variants"
    for variant in contained:
        rows = parse_launcher_refusal_rows(variant.encode("utf-8"))
        assert len(rows) == 1, f"contained variant produced {len(rows)} rows: {variant!r}"
        assert rows[0].reason == "sandbox_block_missing", f"{variant!r}"
    for variant in rejected:
        assert parse_launcher_refusal_rows(variant.encode("utf-8")) == (), (
            f"rejected variant not dropped: {variant!r}"
        )


def test_sbx_2026_019_stub_used_forgery_not_persisted() -> None:
    """sbx-2026-019: a forged sandbox_stub_used row on inherited stderr is NEVER
    persisted (ADR-0051 D4).

    This is the design's most subtle decision, and the INVERSE of sbx-2026-018:
    a sandbox_refused row is safe to persist because a refusing launcher exits
    PRE-exec (no child exists, so drained stderr is provably launcher-authored).
    A sandbox_stub_used row asserts "I am about to exec" -- a live child then
    shares that SAME stderr fd with no delimiter, so "launcher-authored" is not
    establishable in-band for this row at all. The #433/#446 drain gate
    (``quarantine_child_io._SubprocessChildIO`` -- ``refusal_candidate and not
    self._child_wrote_stdout``) is an INVERTED oracle for it: an honest child
    writes stdout and closes the gate (discarding the true row it might have
    emitted), while a FORGING child that writes zero stdout OPENS the gate --
    it would admit approximately only forgeries. So the design declares the
    stub schema (``SANDBOX_STUB_USED_FIELDS``) but wires NO persistence path at
    all; this test pins that the parser itself -- the only thing standing
    between a forged line and a persisted row today -- drops every
    sandbox_stub_used line unconditionally, because it recognizes ONLY
    ``event == "supervisor.plugin.sandbox_refused"``. Iterates the YAML's own
    ``payload.forged_stub_variants`` list (the #428 lesson -- no second
    hardcoded copy) and additionally exercises a mixed stream
    (``payload.mixed_with_genuine_refusal``) carrying both a genuine
    sandbox_refused line and a forged stub_used line, proving the forgery
    does not disturb correct parsing of the real row riding the same stream.

    Only ONE of the three ``forged_stub_variants`` actually exercises the
    event gate this test is named for: the ``uid_separation_unavailable``
    variant, because that reason is the single member shared between
    ``SANDBOX_REFUSED_REASONS`` and ``SANDBOX_STUB_USED_REASONS`` (D7), so it
    is the only one that survives the earlier reason-vocab check in
    ``_validated_row`` and reaches the event check at all. The other two
    variants (``stub_kind``, ``windows_stub``) are already rejected by the
    reason-vocab check regardless of the event gate -- they are
    defense-in-depth against that check, not additional coverage of the event
    gate. The mixed-stream variant is likewise built on the shared reason so
    it, too, is load-bearing rather than redundant. See the YAML's own
    comments next to ``forged_stub_variants`` for the full explanation.
    """
    payload = _load("sbx-2026-019")
    assert payload.expected_outcome == "neutralized"
    assert isinstance(payload.payload, dict)
    forged = payload.payload["forged_stub_variants"]
    assert forged, "payload declares no forged_stub_variants"
    for variant in forged:
        rows = parse_launcher_refusal_rows(variant.encode("utf-8"))
        assert rows == (), f"forged stub_used variant was NOT dropped: {variant!r}"
    mixed = payload.payload["mixed_with_genuine_refusal"]
    rows = parse_launcher_refusal_rows(mixed.encode("utf-8"))
    assert len(rows) == 1, f"mixed stream produced {len(rows)} rows, expected exactly 1: {mixed!r}"
    assert rows[0].reason == "sandbox_block_missing", f"unexpected surviving row: {rows[0]!r}"


def _run_launcher_with_raw_plugin_id(plugin_id: str, *, tmp_path: Path) -> tuple[int, str, str]:
    """Run the real launcher with a caller-supplied (possibly malformed) plugin_id.

    The charset gate (``bin/alfred-plugin-launcher.sh``, top of script) fires on
    ``argv[1]`` BEFORE any manifest read, jq invocation, or environment
    resolution, so this needs no manifest file, no ``ALFRED_ENVIRONMENT``, and
    no jq -- exactly the ordering guarantee sbx-2026-020 exercises. The second
    positional arg (the executable) is a real, harmless stub so a
    (hypothetical) charset-gate regression that let the tainted id through
    would still exec something inert rather than fail for an unrelated reason.
    """
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), plugin_id, str(stub)],
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_sbx_2026_020_plugin_id_charset_injection_refused(tmp_path: Path) -> None:
    """sbx-2026-020: an injection-shaped plugin_id never appears in any emitted row (D2).

    Iterates the YAML's own ``payload.variants`` list (the #428 lesson -- the
    YAML is the single source of truth, no second hardcoded copy). Drives the
    REAL launcher subprocess (not just the parser) so this proves the
    end-to-end guarantee: the charset gate at ``argv[1]`` refuses BEFORE any
    JSON-emitting branch, so the tainted bytes never reach a printf template
    in the first place -- the row the launcher DOES emit carries only the
    constant ``<invalid>`` sentinel (#435's comment: "interpolating the
    tainted bytes into this template is exactly the injection the gate above
    exists to prevent"). Three checks per variant close the loop from raw
    argv to the validated row the core would persist: the launcher refuses;
    the tainted string never appears on stdout OR stderr (ANTI-ECHO,
    generalizing #437's "echoing it would BE the injection" lesson); and
    ``parse_launcher_refusal_rows`` on the real captured stderr yields
    exactly one row whose ``plugin_id`` is the literal ``"<invalid>"``.
    """
    payload = _load("sbx-2026-020")
    assert payload.expected_outcome == "refused"
    assert isinstance(payload.payload, dict)
    variants = payload.payload["variants"]
    assert variants, "payload declares no variants"
    for variant in variants:
        rc, stdout, stderr = _run_launcher_with_raw_plugin_id(variant, tmp_path=tmp_path)
        assert rc != 0, f"variant {variant!r} was NOT refused by the launcher"
        assert "plugin_id_charset_invalid" in stderr, f"variant {variant!r}: {stderr!r}"
        # ANTI-ECHO end-to-end: the tainted variant must not appear on ANY
        # output stream — echoing it would BE the injection (#437's lesson).
        # Skipped for the `<invalid>` variant itself: that string IS the
        # launcher-authored sentinel, so it trivially (and correctly) appears
        # in the sentinel row — the collision-safety property it proves is
        # asserted below instead (the row's plugin_id is the sentinel, not a
        # copy of the tainted argv smuggled through some special case).
        if variant != "<invalid>":
            assert variant not in stderr, f"variant {variant!r} leaked into stderr: {stderr!r}"
            assert variant not in stdout, f"variant {variant!r} leaked into stdout: {stdout!r}"
        rows = parse_launcher_refusal_rows(stderr.encode("utf-8"))
        assert len(rows) == 1, f"variant {variant!r} produced {len(rows)} rows: {stderr!r}"
        assert rows[0].plugin_id == "<invalid>", f"variant {variant!r}: {rows[0]!r}"
        assert rows[0].reason == "plugin_id_charset_invalid", f"variant {variant!r}: {rows[0]!r}"


def test_all_pr_s4_6_payloads_load() -> None:
    # Every PR-S4-6 sbx payload schema-validates + carries the sbx prefix.
    ids = [
        "sbx-2026-001",
        "sbx-2026-002",
        "sbx-2026-007",
        "sbx-2026-008",
        "sbx-2026-009",
        "sbx-2026-010",
        "sbx-2026-016",
        "sbx-2026-017",
        "sbx-2026-018",
        "sbx-2026-019",
        "sbx-2026-020",
    ]
    for pid in ids:
        payload = _load(pid)
        assert payload.id == pid
        assert payload.category == "sandbox_escape"


# ---------------------------------------------------------------------------
# PR-S4-7 kernel-observable payloads — driven against the REAL shipped
# quarantined-LLM Linux policy bytes via bwrap. Skipped where bwrap is absent
# (macOS dev); run in CI (alfred-core image ships bubblewrap 0.8.0).
# ---------------------------------------------------------------------------

_bwrap_required = pytest.mark.skipif(
    not _HAS_BWRAP,
    reason="bwrap required for the kernel-observable PR-S4-7 sandbox-escape payloads",
)


@_bwrap_required
def test_sbx_2026_003_host_etc_passwd_read_contained(tmp_path: Path) -> None:
    payload = _load("sbx-2026-003")
    assert payload.expected_outcome == "refused"
    stub = tmp_path / "probe.py"
    stub.write_text(
        "import sys\n"
        "try:\n"
        "    open('/etc/passwd').read()\n"
        "    print('READ_OK', flush=True)\n"
        "    sys.exit(1)\n"
        "except OSError:\n"
        "    print('BLOCKED', flush=True)\n"
        "    sys.exit(0)\n"
    )
    result = _run_under_real_policy(stub, tmp_path)
    # finding-1: rc==0 proves the sandbox started; BLOCKED proves the probe ran
    # and the read was refused — neither a vacuous empty-stdout pass nor a crash.
    assert result.returncode == 0, result.stderr
    assert "READ_OK" not in result.stdout, "host /etc/passwd was readable — containment failed"
    assert "BLOCKED" in result.stdout, "stub did not run / read was not refused"


@_bwrap_required
def test_sbx_2026_004_host_bin_sh_exec_contained(tmp_path: Path) -> None:
    payload = _load("sbx-2026-004")
    assert payload.expected_outcome == "refused"
    stub = tmp_path / "probe.py"
    stub.write_text(
        "import subprocess, sys\n"
        "try:\n"
        "    subprocess.run(['/bin/sh', '-c', 'echo escape'], check=True)\n"
        "    print('EXEC_OK', flush=True)\n"
        "    sys.exit(1)\n"
        "except (FileNotFoundError, OSError):\n"
        "    print('BLOCKED', flush=True)\n"
        "    sys.exit(0)\n"
    )
    result = _run_under_real_policy(stub, tmp_path)
    # MEDIUM (PR #231 finding-1): a negative-only assertion (`EXEC_OK not in`)
    # passes VACUOUSLY if the bwrap sandbox never STARTS (empty stdout). Assert
    # the probe actually ran (rc==0, surfacing stderr on failure) AND the
    # affirmative containment sentinel so the test PROVES the exec was refused,
    # not merely that nothing happened.
    assert result.returncode == 0, result.stderr
    assert "EXEC_OK" not in result.stdout, "/bin/sh exec was NOT contained"
    assert "BLOCKED" in result.stdout, "stub did not run / exec was not refused"


@_bwrap_required
def test_usr_bin_exec_reachable_known_permissive_pending_230(tmp_path: Path) -> None:
    """finding-4 (PR #231): document the KNOWN-PERMISSIVE /usr/bin exec surface.

    The /bin/sh containment passes only because /bin is not bound. The broad
    ``/usr`` ro_bind, however, leaves ``/usr/bin/*`` exec-reachable inside the
    sandbox. We assert that reachability as a TRACKED FACT (not a surprise): a
    compromised quarantined process CAN exec ``/usr/bin/true`` today. The
    load-bearing exec containment is --unshare-pid + --die-with-parent, NOT the
    absence of exec targets. #230 tightens the interpreter bind to the exact
    CPython prefix; when it lands this test flips (the exec should then fail) —
    forcing the corpus to track the posture change rather than silently widen.
    """
    stub = tmp_path / "probe.py"
    stub.write_text(
        "import subprocess, sys\n"
        "r = subprocess.run(['/usr/bin/true'])\n"
        "print('USRBIN_EXEC_RC', r.returncode, flush=True)\n"
        "sys.exit(0)\n"
    )
    result = _run_under_real_policy(stub, tmp_path)
    assert result.returncode == 0, result.stderr
    # Known-permissive: /usr/bin/true is exec-reachable (rc 0) under the broad
    # /usr bind. If this stops being true, #230 likely landed — update the doc.
    assert "USRBIN_EXEC_RC 0" in result.stdout, (
        "/usr/bin/* is no longer exec-reachable — #230 may have tightened the "
        "/usr bind; update config/sandbox/README.md + this tracked-fact test"
    )


@_bwrap_required
def test_sbx_2026_006_host_proc_environ_read_contained(tmp_path: Path) -> None:
    # finding-2 (PR #231): the prior assertion (rc==0 + BLOCKED||READ_LEN) was
    # self-fulfilling — under --unshare-pid the probe can ONLY ever see its own
    # pid namespace, so it could never construct a host-env leak and "passed"
    # regardless of containment. We make it HONEST with the option-(a) marker
    # probe: seed a recognizable host-env secret in the PARENT env, then assert
    # that whatever /proc/1/environ the sandboxed process can read NEVER contains
    # that marker.
    #
    # The containment that makes this true under the SHIPPED policy is the MOUNT
    # namespace: the policy binds no /proc, so /proc/1/environ does not even
    # exist inside the sandbox and the read raises (verified in Debian Bookworm +
    # bwrap 0.8.0 — the probe gets ENOENT, MARKER_PRESENT False). The host init's
    # secret env is therefore unreachable. A regression that exposed host /proc
    # (or a host-side pid-1 read) would surface the marker and fail this test.
    payload = _load("sbx-2026-006")
    assert payload.expected_outcome == "refused"
    marker = "ALFRED_HOST_SECRET_MARKER=sbx2026006_leak_canary"
    stub = tmp_path / "probe.py"
    # Always print PROBE_RAN (proves the stub executed, not a vacuous empty pass)
    # and a MARKER_PRESENT verdict. The marker is seeded into the host-side
    # parent env; the assertion is that it never appears in the /proc/1/environ
    # the sandboxed process can read.
    stub.write_text(
        "import sys\n"
        "marker = b'sbx2026006_leak_canary'\n"
        "print('PROBE_RAN', flush=True)\n"
        "try:\n"
        "    data = open('/proc/1/environ', 'rb').read()\n"
        "    print('MARKER_PRESENT', marker in data, flush=True)\n"
        "except OSError:\n"
        "    print('MARKER_PRESENT', False, flush=True)\n"
        "sys.exit(0)\n"
    )
    env = {
        **_bwrap_child_env(),
        "ALFRED_HOST_SECRET_MARKER": "sbx2026006_leak_canary",
    }
    flags = _real_policy_flags_with_test_binds(tmp_path)
    bwrap = shutil.which("bwrap")
    assert bwrap is not None  # gated by _bwrap_required
    result = subprocess.run(  # noqa: S603 — resolved bwrap path, repo-owned probe
        [bwrap, *flags, "--", sys.executable, str(stub)],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "PROBE_RAN" in result.stdout, "stub did not run — sandbox never started"
    assert "MARKER_PRESENT True" not in result.stdout, (
        f"host pid-1 env marker {marker!r} leaked into the sandbox — pid-namespace isolation failed"
    )
    assert "MARKER_PRESENT False" in result.stdout


def test_sbx_2026_011_policy_ref_symlink_follow_contained(tmp_path: Path) -> None:
    """A symlink whose realpath escapes the policy root is refused (no bwrap)."""
    payload = _load("sbx-2026-011")
    assert payload.expected_outcome == "refused"
    policy_root = tmp_path / "config" / "sandbox"
    policy_root.mkdir(parents=True)
    # Plant a symlink under the policy root pointing OUTSIDE it (the payload's
    # symlink_target). Use a real outside file so resolve(strict=True) succeeds
    # and the confinement check — not a broken-link OSError — is what refuses.
    outside = tmp_path / "outside_secret"
    outside.write_text("SHADOW\n")
    link = policy_root / "quarantined-llm.linux.bwrap.policy"
    link.symlink_to(outside)
    with pytest.raises(PolicyRefEscapesRoot) as exc_info:
        resolve_policy_ref(payload.payload["policy_ref"], install_root=tmp_path)
    assert exc_info.value.reason == "policy_ref_escapes_root"


def test_sbx_2026_005_outbound_network_egress_contained() -> None:
    """sbx-2026-005 is now an ENFORCED-containment vector (Spec C G7-1, #333).

    The real Linux policy --unshare-net's the child into an empty network
    namespace: an outbound connection is refused at the kernel. The payload
    flipped from ``out_of_scope=True`` to a defended vector; we assert the SHIPPED
    policy genuinely unshares ``net`` so the containment claim stays honest.

    #340 PR2b-golive raised the stakes rather than lowering them. The child is no
    longer the egress-free echo stub — it is the real-LLM child, holding a live
    provider key and T3 content, and it reaches its provider ONLY through a
    gateway socket the core pre-connects and passes in over SCM_RIGHTS (fd 4).
    The empty netns is what makes that brokered fd the child's SOLE reachability;
    dropping ``net`` would hand a T3-holding child a direct route past the
    gateway chokepoint.
    """
    payload = _load("sbx-2026-005")
    assert payload.out_of_scope is False
    assert payload.expected_outcome == "refused"
    policy = read_policy_toml(_QUARANTINED_LINUX_POLICY.read_text())
    assert "net" in policy.unshare, (
        "policy no longer unshares net — sbx-2026-005 asserts the quarantine "
        "child's egress is kernel-closed (--unshare-net) so the SCM_RIGHTS-brokered "
        "gateway socket is its only reachability; a dropped 'net' lets the real-LLM "
        "child bypass the chokepoint (Spec C G7-1 / #340)"
    )


def test_sbx_2026_014_discord_outbound_contained() -> None:
    """sbx-2026-014 is an ENFORCED-containment vector (Spec C G7-4, #333).

    The Discord adapter is ``--unshare-net``'d into an empty network namespace
    (G7-4 / ADR-0043): outbound TCP connections are refused at the kernel and
    egress routes ONLY through the bind-mounted gateway L7 CONNECT proxy socket.
    The corpus entry marks the containment as enforced; we assert the SHIPPED
    Discord policy genuinely unshares ``net`` so the claim stays honest.
    The kernel-observable proof (direct connect blocked + getaddrinfo fails) is
    in ``tests/integration/egress/test_discord_policy_kernel_enforced.py``.
    """
    payload = _load("sbx-2026-014")
    assert payload.out_of_scope is False
    assert payload.expected_outcome == "refused"
    policy = read_policy_toml(_DISCORD_LINUX_POLICY.read_text())
    assert "net" in policy.unshare, (
        "Discord policy no longer unshares net — sbx-2026-014 asserts the "
        "adapter's egress is kernel-closed (--unshare-net); a dropped 'net' "
        "silently re-opens the adapter's egress (Spec C G7-4 / ADR-0043)"
    )


def test_all_pr_s4_7_payloads_load() -> None:
    # Every PR-S4-7 sbx payload schema-validates + carries the sbx prefix.
    # sbx-2026-014 (G7-4 Discord egress containment) is structurally equivalent
    # to the PR-S4-7 bwrap-containment payloads and is validated here.
    ids = [
        "sbx-2026-003",
        "sbx-2026-004",
        "sbx-2026-005",
        "sbx-2026-006",
        "sbx-2026-011",
        "sbx-2026-014",
    ]
    for pid in ids:
        payload = _load(pid)
        assert payload.id == pid
        assert payload.category == "sandbox_escape"


# ---------------------------------------------------------------------------
# PR-S4-11c-2b0 — the LIVE-spawned, wheel-co-located quarantined child.
# sbx-2026-012 (fd-3 key / raw-T3 leak containment) + sbx-2026-013 ("policy was
# inert, now enforced live" via the kind=full launcher spawn). The live-spawn
# assertions are docker-only (bwrap + Linux + root).
# ---------------------------------------------------------------------------


def test_all_pr_s4_11c_2b0_payloads_load() -> None:
    # Every PR-S4-11c-2b0 sbx payload schema-validates + carries the sbx prefix.
    for pid in ("sbx-2026-012", "sbx-2026-013"):
        payload = _load(pid)
        assert payload.id == pid
        assert payload.category == "sandbox_escape"


@_bwrap_required
def test_sbx_2026_012_quarantine_child_does_not_leak_fd3_key(tmp_path: Path) -> None:
    """sbx-2026-012: a child seeded with an fd-3 key must not echo it to stdout.

    Drives the REAL quarantined-LLM child wire contract via a stub run under the
    shipped policy: the host delivers a recognizable key over fd 3; the contract
    is that the host's reply channel (the child's stdout, which the host frames
    as ONE length-prefixed result) never carries the raw key back. We seed a
    marker key on fd 3, run a child stub that reads it the way the real plugin
    does, and assert the marker never appears on a host-visible surface unless the
    (untrusted) child code explicitly echoes it — proving the leak is a
    child-authored act, not a structural one. The production host transport
    (read_frame -> _decode_result_payload) lifts only the JSON-RPC ``result`` to a
    ControlResult, so even a leaking child cannot push raw bytes to the
    orchestrator.
    """
    payload = _load("sbx-2026-012")
    assert payload.expected_outcome == "neutralized"
    marker = "sbx2026012_fd3_key_canary"
    # A faithful child stub: reads the fd-3 framed key (4-byte len + key) the way
    # the real plugin does, scrubs it, and emits ONLY a structured result frame —
    # never the key. Asserts the key is readable on fd 3 but is NOT echoed.
    stub = tmp_path / "probe.py"
    stub.write_text(
        "import os, struct, sys\n"
        "hdr = os.read(3, 4)\n"
        "n = struct.unpack('>I', hdr)[0]\n"
        "key = os.read(3, n).decode()\n"
        "# Structured output discipline: emit a verdict, NEVER the key.\n"
        "print('KEY_READ', len(key) > 0, flush=True)\n"
        "print('KEY_IN_OUTPUT', False, flush=True)\n"
        "sys.exit(0)\n"
    )
    flags = _real_policy_flags_with_test_binds(tmp_path)
    bwrap = shutil.which("bwrap")
    assert bwrap is not None  # gated by _bwrap_required
    # Place the framed key on a pipe read-end at fd 3 (bwrap inherits fd 3).
    r_fd, w_fd = os.pipe()
    os.set_inheritable(r_fd, True)  # noqa: FBT003
    key_bytes = marker.encode()
    os.write(w_fd, struct.pack(">I", len(key_bytes)) + key_bytes)
    os.close(w_fd)
    saved: int | None = None
    try:
        saved = os.dup(3)
    except OSError:
        saved = None
    try:
        os.dup2(r_fd, 3)
        result = subprocess.run(  # noqa: S603 — resolved bwrap path, repo-owned probe
            [bwrap, *flags, "--", sys.executable, str(stub)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            pass_fds=(3,),
            env=_bwrap_child_env(),
        )
    finally:
        if saved is not None:
            os.dup2(saved, 3)
            os.close(saved)
        with contextlib.suppress(OSError):
            os.close(r_fd)
    _skip_if_netns_unconfigurable(result)
    assert result.returncode == 0, result.stderr
    assert "KEY_READ True" in result.stdout, "child could not read the fd-3 key"
    # The marker key never appears on a host-visible surface.
    assert marker not in result.stdout, "fd-3 provider key leaked to child stdout"
    assert marker not in result.stderr, "fd-3 provider key leaked to child stderr"


@_bwrap_required
def test_sbx_2026_013_live_spawned_child_host_escape_contained(tmp_path: Path) -> None:
    """sbx-2026-013: the live bwrap child cannot read /etc/passwd, exec /bin/sh,
    or read /proc/1/environ — the "policy was inert, now enforced live" graduation.

    Reuses the SHIPPED-policy bwrap harness (the same bytes the kind=full launcher
    resolves) to drive all three host-escape probes in one stub. Peer to
    sbx-2026-003/004/006, consolidated to assert the live-spawn posture: a
    compromised child has no host fs / no host shell / no host env.
    """
    payload = _load("sbx-2026-013")
    assert payload.expected_outcome == "refused"
    stub = tmp_path / "probe.py"
    stub.write_text(
        "import subprocess, sys\n"
        "print('PROBE_RAN', flush=True)\n"
        "try:\n"
        "    open('/etc/passwd').read()\n"
        "    print('PASSWD_READ_OK', flush=True)\n"
        "except OSError:\n"
        "    print('PASSWD_BLOCKED', flush=True)\n"
        "try:\n"
        "    subprocess.run(['/bin/sh', '-c', 'echo escape'], check=True)\n"
        "    print('SH_EXEC_OK', flush=True)\n"
        "except (FileNotFoundError, OSError):\n"
        "    print('SH_BLOCKED', flush=True)\n"
        "try:\n"
        "    open('/proc/1/environ', 'rb').read()\n"
        "    print('PROC_ENVIRON_READ_OK', flush=True)\n"
        "except OSError:\n"
        "    print('PROC_ENVIRON_BLOCKED', flush=True)\n"
        "sys.exit(0)\n"
    )
    result = _run_under_real_policy(stub, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "PROBE_RAN" in result.stdout, "stub did not run (vacuous pass guard)"
    assert "PASSWD_READ_OK" not in result.stdout, "host /etc/passwd was readable"
    assert "PASSWD_BLOCKED" in result.stdout
    assert "SH_EXEC_OK" not in result.stdout, "host /bin/sh exec was not contained"
    assert "SH_BLOCKED" in result.stdout
    assert "PROC_ENVIRON_READ_OK" not in result.stdout, "host /proc/1/environ was readable"
    assert "PROC_ENVIRON_BLOCKED" in result.stdout
