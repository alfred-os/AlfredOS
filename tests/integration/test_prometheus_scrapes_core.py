import time
from pathlib import Path

import httpx
import pytest
import yaml  # rev.4 (devops-002): resolve the Prometheus image from compose, don't hardcode it
from testcontainers.core.container import DockerContainer
from testcontainers.core.network import Network

pytestmark = pytest.mark.integration
_REPO = Path(__file__).resolve().parents[2]

# rev.3 (PR #480 CR): every probe carries an explicit timeout. Precision on the CR wording — httpx
# 0.28.1 already defaults to Timeout(5.0), so these calls could NOT "hang indefinitely" (that is the
# `requests` failure mode, not httpx's). Explicit is still right: the value is now visible next to
# the readiness deadline it interacts with, and a library-default change or a Client(timeout=None)
# can no longer alter this test's behaviour silently.
_PROBE_TIMEOUT_S = 5.0
_READY_DEADLINE_S = 60.0
_POLL_INTERVAL_S = 0.25


def _wait_for_first_scrape(base: str) -> None:
    """Block until Prometheus has COMPLETED one scrape attempt of the alfred-core target.

    rev.3 (PR #480 CR): replaces a fixed `time.sleep(3)`, which is flaky under CI load (image pull,
    cold container start) and wasteful when the stack is fast.

    The gate is `health != "unknown"` — i.e. a scrape ATTEMPT finished — deliberately NOT `up == 1`.
    Waiting on `up == 1` would move the test's own oracle into the fixture: a genuinely dead stub
    would time out here with a fixture error instead of failing the assertion that exists to catch
    it. With this gate, a dead stub yields health="down"/up=0 and the TEST fails, loudly and
    specifically.
    """
    deadline = time.monotonic() + _READY_DEADLINE_S
    last = "no probe completed"
    while time.monotonic() < deadline:
        try:
            data = httpx.get(f"{base}/api/v1/targets", timeout=_PROBE_TIMEOUT_S).json()
            active = data["data"]["activeTargets"]
            core = [t for t in active if t["labels"].get("job") == "alfred-core"]
            if core and core[0]["health"] != "unknown":
                return
            last = repr([(t["labels"].get("job"), t["health"]) for t in active])
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            last = repr(exc)
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"Prometheus did not complete a scrape of job=alfred-core within {_READY_DEADLINE_S}s; "
        f"last observation: {last}"
    )


@pytest.fixture
def prometheus_with_stub_core():
    with Network() as net:
        # (1) stub core /metrics, aliased EXACTLY as the scrape target expects
        stub_body = (
            "# TYPE alfred_quarantine_capability_revoked_total counter\n"
            "alfred_quarantine_capability_revoked_total 0\n"
        )
        # rev.2: the stub MUST RUN A PERSISTENT SERVER. The earlier draft's command only
        # *imported* http.server and exited, so the alias resolved to a dead container and
        # `up{job="alfred-core"}` was 0 — the test would have proven nothing. Bind 0.0.0.0
        # (not 127.0.0.1) or Prometheus cannot reach it across the container network, and
        # keep serve_forever() alive for the whole fixture.
        stub_script = (
            "import http.server\n"
            f"BODY = {stub_body!r}.encode()\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        if self.path != '/metrics':\n"
            "            self.send_error(404); return\n"
            "        self.send_response(200)\n"
            "        self.send_header('Content-Type', 'text/plain; version=0.0.4')\n"
            "        self.send_header('Content-Length', str(len(BODY)))\n"
            "        self.end_headers()\n"
            "        self.wfile.write(BODY)\n"
            "    def log_message(self, *a): pass\n"
            "http.server.HTTPServer(('0.0.0.0', 9465), H).serve_forever()\n"
        )
        # NOTE (deviation from brief): the installed testcontainers version exposes
        # `with_network_aliases(*aliases)` as a first-class builder (it sets
        # `self._network_aliases`, which `start()` folds into `networking_config`
        # itself). The brief's `.with_kwargs(network_aliases=[...])` instead forwards
        # `network_aliases` raw to docker-py's `containers.run()`, which rejects it
        # with `TypeError: run() got an unexpected keyword argument 'network_aliases'`.
        stub = (
            DockerContainer("python:3.14-slim")
            .with_network(net)
            .with_network_aliases("alfred-core")
            .with_command(["python", "-c", stub_script])
        )
        _prom_image = yaml.safe_load((_REPO / "docker-compose.yaml").read_text())["services"][
            "alfred-prometheus"
        ]["image"]  # rev.4 devops-002
        prom = (
            DockerContainer(_prom_image)
            .with_network(net)
            .with_exposed_ports(9090)
            .with_volume_mapping(
                str(_REPO / "ops/prometheus/prometheus.yml"), "/etc/prometheus/prometheus.yml", "ro"
            )
            .with_volume_mapping(str(_REPO / "ops/alerts"), "/etc/prometheus/alerts", "ro")
        )
        with stub, prom:
            base = f"http://{prom.get_container_host_ip()}:{prom.get_exposed_port(9090)}"
            _wait_for_first_scrape(base)  # rev.3: bounded readiness poll, not a fixed sleep
            yield base


def test_prometheus_loads_config_and_rule_is_live(prometheus_with_stub_core):
    base = prometheus_with_stub_core
    rules = httpx.get(f"{base}/api/v1/rules", timeout=_PROBE_TIMEOUT_S).json()
    names = {r["name"] for g in rules["data"]["groups"] for r in g["rules"]}
    # rev.2: assert THIS PR's new core rules, not only the pre-existing quarantine rule —
    # `core.yml` is the file this task adds to `rule_files`, so a typo'd rule_files entry
    # must fail here. QuarantineCapabilityRevoked is kept as the #470 raison d'etre (and as
    # proof `quarantine.yml` reached the mount too).
    assert {"AlfredCoreMetricsDown", "AlfredQuarantineCounterAbsent"} <= names
    assert "QuarantineCapabilityRevoked" in names
    up = httpx.get(
        f"{base}/api/v1/query",
        params={"query": 'up{job="alfred-core"}'},
        timeout=_PROBE_TIMEOUT_S,
    ).json()
    assert up["data"]["result"][0]["value"][1] == "1"  # the alfred-core alias was scraped
