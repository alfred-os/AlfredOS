from prometheus_client import generate_latest
from prometheus_client.parser import text_string_to_metric_families

from alfred.observability.core_metrics import CORE_OWNED_COLLECTORS, build_core_registry


def test_build_core_registry_serves_the_capability_counter():
    reg = build_core_registry()
    families = {f.name for f in text_string_to_metric_families(generate_latest(reg).decode())}
    assert "alfred_quarantine_capability_revoked" in families  # parser strips the Counter's _total


def test_ten_core_collectors():
    assert len(CORE_OWNED_COLLECTORS) == 10
