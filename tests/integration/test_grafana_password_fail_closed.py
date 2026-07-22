"""Real-execution proof that the Grafana entrypoint credential guard fails closed.

#470 PR2 Task 3 (rev.3, PR #480 CR Major/security): the compose-level lexical test
``test_grafana_entrypoint_guards_the_admin_password`` in
``tests/unit/test_compose_invariants.py`` asserts the entrypoint STRING mentions
``GF_SECURITY_ADMIN_PASSWORD`` and ``exit 78`` — it cannot decide what Grafana
actually DOES. That distinction is not academic: the original plan claimed an
*empty* ``GF_SECURITY_ADMIN_PASSWORD`` alone made Grafana refuse to start. Verified
against ``grafana/grafana:11.6.0`` on 2026-07-21 (see the compose service's inline
comment): that claim was FALSE. Grafana's own env-override loop only applies a
non-empty value, so an empty ``GF_SECURITY_ADMIN_PASSWORD`` is silently ignored and
``conf/defaults.ini``'s ``admin_password = admin`` wins — the container boots,
``/api/health`` answers 200, and ``admin:admin`` authenticates. The fix is the
``entrypoint:`` preflight guard in ``docker-compose.yaml`` (layer 3 of the three-layer
credential design, spec §6.2a); THIS file proves that guard actually holds, against
the real image, for real.

**The `$$` extraction — read this before touching the fixture below.** The shipped
guard uses Compose's ``$$`` escape (``$${GF_SECURITY_ADMIN_PASSWORD}``) so Compose
itself does not try to interpolate it — the guard must run INSIDE the container, at
container start, against the container's own environment. The original plan
proposed reading the resolved entrypoint via
``yaml.safe_load(subprocess.check_output(["docker", "compose", "config"]))``, on the
theory that ``docker compose config`` performs Compose's ``$$`` -> ``$``
interpolation before re-serializing. Measured empirically against docker compose
v5.1.2 on 2026-07-22: it does **not**. ``docker compose config``'s own YAML output is
designed to be round-trippable back through ``docker compose`` — a literal ``$``
(which is the entire *point* of the ``$$`` escape) has to stay ``$$`` in that output
too, or feeding the ``config`` output back through Compose a second time would try to
interpolate it again. ``yaml.safe_load`` of ``docker compose config``'s stdout
therefore still shows ``$${GF_SECURITY_ADMIN_PASSWORD}`` verbatim. Executing that raw
string through a bare ``sh -ec`` OUTSIDE Compose would expand ``$$`` to the shell's
own PID (never empty) — the empty-password refusal arm below could then never
legitimately fire, and this whole suite would report green while proving nothing
(the exact non-vacuity failure mode this file exists to prevent). Do NOT "fix" this
by hand-de-escaping the string either — that drifts the tested guard from the
shipped one.

The container Docker Engine actually CREATES does carry the fully-resolved,
single-``$`` entrypoint (``docker inspect`` on a real container proves it — Compose
resolves ``$$`` -> ``$`` when it builds the container's ``Entrypoint`` field, it just
doesn't re-emit that resolution in its own re-serialized YAML). So
``grafana_entrypoint_from_compose`` below lets ``docker compose create`` build (never
start) one throwaway container under a private, uuid-suffixed project name, reads
its resolved ``Config.Entrypoint`` back via ``docker inspect`` — Compose's own
interpolation engine, not a hand-rolled parse — and tears the scaffold container
down immediately. Every arm below then executes that extracted list byte-for-byte
via the Docker SDK.

**Fixture mechanics (rev.4):**

* The two refusal arms (empty / literal ``admin``) exit immediately (``exit 78``).
  Testcontainers' ``DockerContainer`` is service-oriented — its helpers assume a
  long-lived container and are the wrong tool for an immediately-exiting one — so
  those two arms use the Docker SDK directly (``docker_client.containers.run(...,
  detach=True)`` + ``.wait()`` + ``.logs(stderr=True)``).
* The real-password arm (the non-vacuity control) is long-lived and HTTP-polled, so
  it uses ``testcontainers.core.container.DockerContainer``.
* The pinned image is pulled ONCE (module-scoped fixture) and shared across all
  three arms (test-008: the mac integration lane already runs >20 min and is flaky
  under load).
* This file is plain ``pytest.mark.integration`` — no ``docker`` marker, no
  ``skipif``. It must ERROR (not silently skip) when Docker is unreachable, so a
  daemon-less run of the required lane fails loud rather than reporting a false
  green (mirrors the #245 "assert RAN" pattern this repo already uses elsewhere).

**Expected values, measured 2026-07-21 on grafana/grafana:11.6.0 (real containers,
all three arms; re-measure before trusting these on ANY other tag — the guard's
``exec /run.sh`` couples to this tag's canonical entrypoint):** empty or literal
``admin`` password -> exit 78, refusal on stderr, names ``bin/alfred-setup.sh``; real
seeded password -> boots, ``/api/health`` 200, ``admin:admin`` -> 401, the seeded
credential -> 200.
"""

from __future__ import annotations

# ruff: noqa: S603, S607
# Test-controlled invocations of `docker` / `docker compose` from the integration
# suite. Every argv is a literal (plus a uuid-suffixed project name this module
# generates) authored in this module; nothing crosses an untrusted boundary.
import json
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from testcontainers.core.container import DockerContainer

import docker

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[2]
# Resolved from docker-compose.yaml's `alfred-grafana.image` rather than hardcoded here —
# a hand-copied literal would silently drift from the pinned tag docker-compose.yaml
# actually ships, and this suite's whole point is proving what the SHIPPED image does.
_GRAFANA_IMAGE = yaml.safe_load((_REPO_ROOT / "docker-compose.yaml").read_text())["services"][
    "alfred-grafana"
]["image"]
_REFUSAL_EXIT_CODE = 78
_HEALTH_TIMEOUT_S = 90.0


def _extract_grafana_entrypoint() -> list[str]:
    """Return the entrypoint argv Docker will ACTUALLY run for ``alfred-grafana``.

    See the module docstring for why this does not parse ``docker compose
    config``'s YAML (it keeps the `$$` escape intact, by design, for
    round-trippability) and instead reads the resolved value off a real
    (never-started) container that Compose itself created.
    """
    project = f"alfred-entrypoint-probe-{uuid.uuid4().hex[:8]}"
    try:
        subprocess.run(
            ["docker", "compose", "-p", project, "create", "alfred-grafana"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        inspected = subprocess.run(
            [
                "docker",
                "inspect",
                f"{project}-alfred-grafana-1",
                "--format",
                "{{json .Config.Entrypoint}}",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    finally:
        # Best-effort teardown of the scaffold container + the network/volumes
        # `create` provisions alongside it — never masks a real failure above with
        # `check=False`.
        subprocess.run(
            ["docker", "compose", "-p", project, "down", "-v", "--remove-orphans"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    entrypoint: Any = json.loads(inspected.stdout)
    assert isinstance(entrypoint, list) and entrypoint, (
        f"unexpected entrypoint shape from docker inspect: {entrypoint!r}"
    )
    joined = " ".join(entrypoint)
    # The whole point of this extraction: the resolved entrypoint must carry a REAL
    # single-`$` variable reference, not the compose-source `$$` escape. If this
    # ever trips, `docker compose create`'s interpolation behaviour changed and the
    # arms below would silently stop proving anything.
    assert "$$" not in joined, (
        f"extracted entrypoint still carries the `$$` escape — Compose did not "
        f"resolve it as expected: {entrypoint!r}"
    )
    assert "GF_SECURITY_ADMIN_PASSWORD" in joined
    assert "exit 78" in joined
    return entrypoint


@pytest.fixture(scope="module")
def grafana_entrypoint_from_compose() -> list[str]:
    return _extract_grafana_entrypoint()


@pytest.fixture(scope="module")
def docker_client() -> Iterator[docker.DockerClient]:
    client = docker.from_env()
    try:
        yield client
    finally:
        client.close()


@pytest.fixture(scope="module")
def grafana_image(docker_client: docker.DockerClient) -> str:
    """Pull the pinned image once; every arm in this module reuses it (test-008)."""
    docker_client.images.pull(_GRAFANA_IMAGE)
    return _GRAFANA_IMAGE


def _run_refusal_arm(
    docker_client: docker.DockerClient,
    image: str,
    entrypoint: list[str],
    password: str,
) -> tuple[int, str]:
    """Run the real guard with ``password`` and return ``(exit_code, stderr_text)``."""
    container = docker_client.containers.run(
        image,
        entrypoint=entrypoint,
        environment={"GF_SECURITY_ADMIN_PASSWORD": password},
        detach=True,
    )
    try:
        result = container.wait(timeout=60)
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
        return result["StatusCode"], stderr
    finally:
        container.remove(force=True)


def test_empty_admin_password_refuses_to_start(
    docker_client: docker.DockerClient,
    grafana_image: str,
    grafana_entrypoint_from_compose: list[str],
) -> None:
    """No password (the skipped-setup operator) => the container exits non-zero, loudly."""
    status_code, stderr = _run_refusal_arm(
        docker_client, grafana_image, grafana_entrypoint_from_compose, ""
    )
    assert status_code == _REFUSAL_EXIT_CODE, (
        f"expected exit {_REFUSAL_EXIT_CODE} (EX_CONFIG), got {status_code}; stderr={stderr!r}"
    )
    assert "GF_SECURITY_ADMIN_PASSWORD" in stderr
    assert "alfred-setup.sh" in stderr, "the refusal must be actionable — name the fix"


def test_literal_admin_password_refuses_to_start(
    docker_client: docker.DockerClient,
    grafana_image: str,
    grafana_entrypoint_from_compose: list[str],
) -> None:
    """The well-known default is refused explicitly, not just the empty string."""
    status_code, stderr = _run_refusal_arm(
        docker_client, grafana_image, grafana_entrypoint_from_compose, "admin"
    )
    assert status_code == _REFUSAL_EXIT_CODE, (
        f"expected exit {_REFUSAL_EXIT_CODE} (EX_CONFIG), got {status_code}; stderr={stderr!r}"
    )
    assert "admin" in stderr


def _wait_for_health(base_url: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{base_url}/api/health", timeout=5)
        except httpx.HTTPError as exc:
            last_error = exc
        else:
            if response.status_code == 200:
                return
            last_error = AssertionError(f"/api/health returned {response.status_code}")
        time.sleep(1)
    raise TimeoutError(
        f"grafana did not become healthy within {timeout_s:.0f}s (last: {last_error!r})"
    )


def test_real_password_boots_and_rejects_admin_admin(
    grafana_image: str,
    grafana_entrypoint_from_compose: list[str],
) -> None:
    """NON-VACUITY CONTROL — the arm that proves this suite is about Grafana's real auth state.

    With a seeded password the container boots (``/api/health`` 200), ``admin:admin``
    is REJECTED (401), and the seeded credential is accepted (200). Without this arm
    the two refusal tests above would still pass against a guard that refuses
    EVERYTHING, and against a Grafana build that authenticates NOTHING.
    """
    real_password = f"fail-closed-probe-{uuid.uuid4().hex}"
    container = DockerContainer(grafana_image, entrypoint=grafana_entrypoint_from_compose)
    container.with_env("GF_SECURITY_ADMIN_PASSWORD", real_password)
    container.with_exposed_ports(3000)
    with container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(3000)
        base_url = f"http://{host}:{port}"
        _wait_for_health(base_url, _HEALTH_TIMEOUT_S)

        health = httpx.get(f"{base_url}/api/health", timeout=10)
        assert health.status_code == 200

        rejected = httpx.get(f"{base_url}/api/org", auth=("admin", "admin"), timeout=10)
        assert rejected.status_code == 401, (
            "admin:admin must be REJECTED with a real password seeded — this is the "
            f"exact hazard the guard closes; got {rejected.status_code}"
        )

        accepted = httpx.get(f"{base_url}/api/org", auth=("admin", real_password), timeout=10)
        assert accepted.status_code == 200, (
            f"the seeded credential must be ACCEPTED; got {accepted.status_code}"
        )
