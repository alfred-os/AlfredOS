"""Thin subprocess+stdio smoke test for the comms-test reference plugin.

Spec §9.1 + comms-002: the reference echo plugin
(``plugins.alfred_comms_test.main``) is a hand-rolled MCP stdio server
speaking line-delimited JSON-RPC. The richer round-trip tests live in
``tests/integration/test_comms_mcp_contract.py``; this file is the
single thinnest smoke test the reviewer asked for — spawn the plugin
via :func:`subprocess.Popen`, write ONE JSON-RPC line, read ONE response
line, assert the echo round-trips. Used to catch packaging / wiring
breakage where the plugin fails to start at all (missing ``__main__``
guard, ImportError in the module body, broken ``sys.path`` under
``python -m plugins.alfred_comms_test.main``).

Why subprocess.Popen rather than the asyncio variant in the integration
tests:

* The reviewer recommendation explicitly called for the synchronous
  Popen pattern so this smoke test can run as a unit-level test with
  no integration marker. Asyncio subprocess work requires an event
  loop and pytest-asyncio's auto-mode; spawning via ``subprocess.Popen``
  + ``communicate(input=...)`` is loop-free and fast (~50 ms wall on
  a healthy box).
* The integration tests assert the multi-frame ordering (response then
  notification) which needs incremental reads. A single round-trip
  fits ``communicate`` cleanly.

The test is decorated with no marker — it runs in the default unit
suite. ``MAIN_PATH.exists()`` skip guards against the plugin dir being
removed from a future packaging refactor without breaking the smoke
collection.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Resolve to the repo's plugin dir relative to this test file so the
# smoke test runs regardless of cwd (unit suite, IDE, makefile, etc.).
_PLUGIN_DIR: Path = Path(__file__).parent.parent.parent.parent / "plugins" / "alfred_comms_test"
_MAIN_PATH: Path = _PLUGIN_DIR / "main.py"

# Generous so a slow CI worker still completes within the budget; tight
# enough that a wedged plugin fails loud rather than hangs the suite.
# Single-frame echo on a healthy box returns within ~10 ms, so 5 s is
# a 500x cushion.
_SMOKE_TIMEOUT_S: float = 5.0


@pytest.mark.skipif(
    not _MAIN_PATH.exists(),
    reason=f"reference plugin missing at {_MAIN_PATH} (packaging change?)",
)
def test_comms_test_plugin_handles_non_object_json_with_invalid_request() -> None:
    """CR-149: a non-object JSON frame returns a structured Invalid Request.

    ``json.loads`` legally returns lists / strings / numbers / null
    for valid JSON that does NOT conform to the JSON-RPC request
    shape. The previous code called ``.get(...)`` unconditionally
    and crashed the subprocess on the first such frame, leaving the
    host hanging waiting for a response that would never arrive.
    The plugin now emits a JSON-RPC ``-32600`` Invalid Request
    envelope and stays in its receive loop.
    """
    # A bare JSON array — valid JSON, invalid JSON-RPC request.
    bad_frame = json.dumps([1, 2, 3])
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_MAIN_PATH)],
        input=bad_frame + "\n",
        capture_output=True,
        text=True,
        timeout=_SMOKE_TIMEOUT_S,
        check=False,
    )
    assert result.returncode == 0, (
        f"plugin exited with code {result.returncode}; stderr={result.stderr!r}"
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, (
        f"expected exactly one Invalid Request frame, got {len(lines)}: {result.stdout!r}"
    )
    response = json.loads(lines[0])
    # JSON-RPC 2.0 Invalid Request envelope shape.
    assert response.get("jsonrpc") == "2.0", response
    assert response.get("id") is None, response
    err = response.get("error", {})
    assert err.get("code") == -32600, response
    assert err.get("message") == "Invalid Request", response


@pytest.mark.skipif(
    not _MAIN_PATH.exists(),
    reason=f"reference plugin missing at {_MAIN_PATH} (packaging change?)",
)
def test_comms_test_plugin_missing_method_returns_invalid_request() -> None:
    """CR-149 round-6.5: object frame with no ``method`` returns -32600.

    JSON-RPC 2.0 §4.1 / §5.1: ``method`` is a required member and MUST
    be a string. The prior implementation called
    ``request.get("method", "")`` and let the empty-string fallback
    flow into ``_build_method_not_found`` (-32601), which is the wrong
    code per spec — the request object itself is malformed, not the
    method name. This test pins the corrected -32600 (Invalid Request)
    envelope so a future refactor cannot regress the spec compliance.

    The frame carries an ``id`` so the plugin is required to reply
    (per §4.2 the reply is suppressed only for notifications, which
    omit ``id``); the spec-mandated reply shape is the Invalid Request
    envelope with the request's ``id`` echoed back.
    """
    bad_frame = json.dumps({"jsonrpc": "2.0", "id": 7})
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_MAIN_PATH)],
        input=bad_frame + "\n",
        capture_output=True,
        text=True,
        timeout=_SMOKE_TIMEOUT_S,
        check=False,
    )
    assert result.returncode == 0, (
        f"plugin exited with code {result.returncode}; stderr={result.stderr!r}"
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, (
        f"expected exactly one Invalid Request frame, got {len(lines)}: {result.stdout!r}"
    )
    response = json.loads(lines[0])
    assert response.get("jsonrpc") == "2.0", response
    # ``id`` is echoed back per spec §5.1 when the request supplied one.
    assert response.get("id") == 7, response
    err = response.get("error", {})
    assert err.get("code") == -32600, response
    assert err.get("message") == "Invalid Request", response


@pytest.mark.skipif(
    not _MAIN_PATH.exists(),
    reason=f"reference plugin missing at {_MAIN_PATH} (packaging change?)",
)
def test_comms_test_plugin_non_string_method_returns_invalid_request() -> None:
    """CR-149 round-6.5: object frame with non-string ``method`` returns -32600.

    Same spec contract as the missing-method case — ``method`` MUST be
    a string per JSON-RPC 2.0 §4.1. ``{"method": 1}`` previously
    flowed through ``_build_method_not_found(1)`` and emitted a -32601
    envelope with a non-string method name interpolated into the
    message — both protocol-incorrect.
    """
    bad_frame = json.dumps({"jsonrpc": "2.0", "id": 8, "method": 1})
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_MAIN_PATH)],
        input=bad_frame + "\n",
        capture_output=True,
        text=True,
        timeout=_SMOKE_TIMEOUT_S,
        check=False,
    )
    assert result.returncode == 0, (
        f"plugin exited with code {result.returncode}; stderr={result.stderr!r}"
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, (
        f"expected exactly one Invalid Request frame, got {len(lines)}: {result.stdout!r}"
    )
    response = json.loads(lines[0])
    assert response.get("jsonrpc") == "2.0", response
    assert response.get("id") == 8, response
    err = response.get("error", {})
    assert err.get("code") == -32600, response
    assert err.get("message") == "Invalid Request", response


@pytest.mark.skipif(
    not _MAIN_PATH.exists(),
    reason=f"reference plugin missing at {_MAIN_PATH} (packaging change?)",
)
def test_comms_test_plugin_missing_method_emits_invalid_request_with_null_id() -> None:
    """CR-149 round-10 (3339423468): malformed object frames ALWAYS reply.

    JSON-RPC 2.0 §5.1 (Error object): "If there was an error in
    detecting the id in the Request object (e.g. Parse error / Invalid
    Request), it MUST be Null." The notification-suppression contract
    (§4.1.2) applies only to *valid* Request objects that omit ``id``.
    When the request is fundamentally invalid (no ``method``, wrong
    type for ``method``), the host cannot disambiguate
    "intended notification" from "malformed request" — the server MUST
    treat the frame as malformed and emit ``-32600`` with ``id: null``
    so strict hosts are not left waiting for a reply that never
    arrives (PRD §9).

    The prior shape gated the reply on ``has_response_id`` and dropped
    the frame entirely, regressing the spec compliance the broader
    request-object refusal pins.
    """
    bad_frame = json.dumps({"jsonrpc": "2.0"})
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_MAIN_PATH)],
        input=bad_frame + "\n",
        capture_output=True,
        text=True,
        timeout=_SMOKE_TIMEOUT_S,
        check=False,
    )
    assert result.returncode == 0, (
        f"plugin exited with code {result.returncode}; stderr={result.stderr!r}"
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, (
        f"expected exactly one Invalid Request frame, got {len(lines)}: {result.stdout!r}"
    )
    response = json.loads(lines[0])
    assert response.get("jsonrpc") == "2.0", response
    # ``id`` is null per §5.1 because the request did not detect one.
    assert response.get("id") is None, response
    err = response.get("error", {})
    assert err.get("code") == -32600, response
    assert err.get("message") == "Invalid Request", response


def test_comms_test_plugin_non_string_method_no_id_emits_invalid_request_with_null_id() -> None:
    """CR-149 round-10 (3339423468): non-string ``method`` with no id replies.

    Sister case of the missing-method test above: ``{"method": 1}`` is
    fundamentally invalid per §4.1, so even without ``id`` the plugin
    MUST emit ``-32600`` with ``id: null``. The prior ``has_response_id``
    gating dropped this frame silently.
    """
    bad_frame = json.dumps({"jsonrpc": "2.0", "method": 1})
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_MAIN_PATH)],
        input=bad_frame + "\n",
        capture_output=True,
        text=True,
        timeout=_SMOKE_TIMEOUT_S,
        check=False,
    )
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    response = json.loads(lines[0])
    assert response.get("jsonrpc") == "2.0"
    assert response.get("id") is None, response
    err = response.get("error", {})
    assert err.get("code") == -32600
    assert err.get("message") == "Invalid Request"


@pytest.mark.skipif(
    not _MAIN_PATH.exists(),
    reason=f"reference plugin missing at {_MAIN_PATH} (packaging change?)",
)
def test_comms_test_plugin_subprocess_health_round_trip() -> None:
    """One ``adapter.health`` JSON-RPC frame in, one response frame out.

    Smoke-test contract:

    * The plugin starts cleanly under the test runner's interpreter via
      ``python -m plugins.alfred_comms_test.main``.
    * It reads ONE line-delimited JSON-RPC request on stdin.
    * It writes ONE line-delimited JSON-RPC response on stdout matching
      the request ``id``.
    * stdin EOF after the single frame causes the plugin to drain its
      loop (``reader.readline()`` returns ``b""``) and exit 0.

    ``adapter.health`` rather than ``lifecycle.start`` because the
    health probe is a single-response method — ``lifecycle.start`` emits
    BOTH a response AND a notification, which ``communicate(input=...)``
    captures as concatenated lines and complicates the single-frame
    assertion this smoke test pins. The integration test in
    ``tests/integration/test_comms_mcp_contract.py`` covers the multi-
    frame ordering.

    Without :func:`lifecycle.start` first the plugin reports ``ok=false``
    (the ``_running`` state stays False) — that's the expected pre-start
    ``HealthReport`` payload. PR-S4-8 upgraded the reference plugin to the
    full-lifecycle ADR-0024 contract, so ``adapter.health`` returns the
    ``HealthReport`` shape (``ok`` / ``queue_depth`` / ``error_count``) rather
    than the Slice-3 ``{"ok", "degraded"}`` status Literal. The smoke test
    asserts on the response *shape*.
    """
    request = json.dumps({"jsonrpc": "2.0", "id": 42, "method": "adapter.health", "params": {}})

    # ``subprocess.run`` is a thin wrapper over Popen + communicate; we
    # use it here because it gives us the timeout, capture, and EOF
    # semantics in one call without managing the pipes manually.
    # ``check=False`` because non-zero exit codes are surfaced via the
    # ``returncode`` assertion below — communicating the failure mode
    # explicitly beats letting CalledProcessError mask the captured
    # stderr.
    # CR-149: invoke the resolved script path (``_MAIN_PATH``) rather
    # than ``-m plugins.alfred_comms_test.main``. The ``-m`` form
    # depends on the subprocess' cwd being the repo root so the
    # ``plugins`` package is importable; running this smoke test from
    # an IDE / a subdirectory / a future workflow that changes cwd
    # would otherwise fail with ``ModuleNotFoundError: plugins`` even
    # though the script exists. Direct script invocation is
    # cwd-independent and matches how the integration test in
    # ``tests/integration/test_comms_mcp_contract.py`` already spawns
    # the plugin.
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_MAIN_PATH)],
        input=request + "\n",
        capture_output=True,
        text=True,
        timeout=_SMOKE_TIMEOUT_S,
        check=False,
    )

    # Plugin should exit cleanly after stdin EOF.
    assert result.returncode == 0, (
        f"plugin exited with code {result.returncode}; stderr={result.stderr!r}"
    )

    # Exactly one response line on stdout; trailing newline trimmed.
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, (
        f"expected exactly one response frame, got {len(lines)}: {result.stdout!r}"
    )

    response = json.loads(lines[0])
    assert response.get("id") == 42, (
        f"response id must echo request id=42, got {response.get('id')!r}"
    )
    # ``result`` envelope (not ``error``) — health is always answerable.
    assert "result" in response, f"expected result envelope, got {response!r}"
    # CR-149: every wire frame carries the mandatory ``jsonrpc: "2.0"``
    # member so a strict host parser accepts the reply. The previous
    # shape omitted the version on success / method-not-found / parse-
    # error envelopes, which is a JSON-RPC 2.0 protocol violation.
    assert response.get("jsonrpc") == "2.0", (
        f"every response frame must carry jsonrpc=2.0 per spec §9, got {response!r}"
    )
    payload = response["result"]
    # PR-S4-8 HealthReport shape: ok (bool) + queue_depth + error_count.
    assert isinstance(payload.get("ok"), bool), (
        f"adapter.health must report a boolean ok, got {payload!r}"
    )
    # CR #232: pin the pre-start lifecycle STATE, not just the shape -- this probe
    # runs WITHOUT lifecycle.start, so ``ok`` must be ``False``. Type-checking
    # alone would let a regression that flips pre-start ``ok`` to ``True`` slip by.
    assert payload.get("ok") is False, (
        f"pre-start adapter.health must report ok=False, got {payload!r}"
    )
    assert payload.get("queue_depth") == 0
    assert payload.get("error_count") == 0
