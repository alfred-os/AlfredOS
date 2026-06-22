from alfred.memory.models import AuditEntry, ForwardedDispatchAttempt


def test_forwarded_dispatch_attempt_columns() -> None:
    cols = {c.name for c in ForwardedDispatchAttempt.__table__.columns}
    assert cols == {
        "adapter_id",
        "inbound_id",
        "attempt_count",
        "first_failed_at",
        "last_failed_at",
    }
    pk = {c.name for c in ForwardedDispatchAttempt.__table__.primary_key.columns}
    assert pk == {"adapter_id", "inbound_id"}


def test_poisoned_is_in_audit_result_check() -> None:
    check = next(
        c
        for c in AuditEntry.__table__.constraints
        if getattr(c, "name", "") == "ck_audit_log_result"
    )
    assert "'poisoned'" in str(check.sqltext)
