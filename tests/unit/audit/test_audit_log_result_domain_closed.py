"""Static guard: every ``result=`` literal written to ``audit_log`` is in-domain.

Issue #320 (+ #252, + C1/H1 from the adversarial review). The
``audit_log.result`` column is a CLOSED CHECK domain (``ck_audit_log_result``
on :class:`alfred.memory.models.AuditEntry`). A writer that passes a
``result=`` value the migration never added crashes with an asyncpg
``CheckViolation`` against real Postgres — but the unit and adversarial suites
use append-only audit doubles that never enforce the constraint, so the gap
stays invisible until a row carrying the out-of-domain value is written against
a real DB. Issue #252 (the ``transport_failed`` row in
:meth:`alfred.security.quarantine.QuarantinedExtractor._emit_transport_failed_audit`)
is one instance of that bug class.

What this guard catches — and what it does NOT
----------------------------------------------
The guard catches every LITERAL ``result=`` value at BOTH ``audit_log`` write
paths (see below), STATICALLY, with no DB, at unit tier. It does NOT — and
cannot — prove that a DYNAMIC (non-literal) ``result=`` value is in-domain: a
static walk over literals has no way to enumerate what a runtime expression
evaluates to. Dynamic sites are therefore location-pinned in
:func:`test_dynamic_result_sites_are_documented`, and the reachable values of
each were MANUALLY AUDITED this round (the quarantine ``post_stage_refused``
value reached through the ``_emit_extract_audit`` helper param is now closed in
migration 0022; the ``web_fetch/fetch_dispatcher.py:914`` plugin-payload value
is tracked as issue #326 — an emit-site clamp, not a domain-widen). The guard
documents those sites rather than false-positiving on them.

The two ``audit_log`` write paths
----------------------------------
A row reaches the ``audit_log`` table by exactly one of:

1. an ``AuditWriter.append`` / ``.append_schema`` CALL
   (:class:`alfred.audit.log.AuditWriter`), or
2. a direct ``AuditEntry(...)`` CONSTRUCTION handed to ``session.add()``
   (the writer itself does this internally; one other production site —
   ``state/dispatch_loop.py`` — constructs the row directly).

The adversarial review confirmed (by sweep) that these are the ONLY two write
paths: no raw ``INSERT INTO audit_log``, no ``insert(AuditEntry)`` /
``sa.insert``, no ``executemany``, no ``functools.partial`` over the writer.

How the guard scopes to the ``audit_log.result`` column ONLY
----------------------------------------------------------------
The grep ``result=`` over ``src/alfred`` is HEAVILY conflated: the token
appears as a key inside ``subject={...}`` dicts, as a kwarg of unrelated
handlers, and as look-alike columns on OTHER CHECK domains
(``dlp_scan_result=``, ``trust_tier_of_result=``, ``hook_result=``,
``dispatch_result=`` …). NONE of those are the ``audit_log.result``
column and they must not be collected here.

The guard scopes precisely by FINGERPRINTING the write: both
``AuditWriter.append`` / ``.append_schema`` and the ``AuditEntry`` constructor
carry BOTH the ``trust_tier_of_trigger=`` and ``cost_estimate_usd=`` keyword
arguments (no other method or constructor in the tree shares that pair). A node
is counted iff it is an ``ast.Call`` whose callee is EITHER

* an attribute access named ``append`` / ``append_schema``, OR
* a bare name ``AuditEntry`` (direct construction),

AND whose keyword set is a superset of ``{trust_tier_of_trigger,
cost_estimate_usd}`` (the audit-writer fingerprint).

This excludes ``list.append`` (no kwargs), ``subject``-dict ``result``
keys (not a call kwarg), and every look-alike ``*_result=`` kwarg on a
different column (none of those callees match with the fingerprint). The
receiver of a method call may be the concrete ``AuditWriter`` or a narrow
``Protocol`` the production ``AuditWriter`` satisfies (``_AuditWriterLike`` /
``_AuditSink``) — both persist to ``audit_log``.

Determinism: pure ``ast`` parse of the source tree + a regex over the
constructed ORM CHECK constraint. No imports of ``src/alfred`` runtime
modules with side effects, no DB, no network. Fast (single AST pass).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from alfred.memory.models import AuditEntry

# ---------------------------------------------------------------------------
# Source tree + audit-writer fingerprint
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SRC_ROOT = _REPO_ROOT / "src" / "alfred"

# The two AuditWriter methods that persist an AuditEntry row.
_AUDIT_WRITER_METHODS = frozenset({"append", "append_schema"})

# The ORM model whose direct ``AuditEntry(...)`` construction (handed to
# ``session.add()``) is the SECOND ``audit_log`` write path.
_AUDIT_ENTRY_CTOR = "AuditEntry"

# The kwarg pair that uniquely fingerprints an audit_log write — no other
# method or constructor in src/alfred takes BOTH of these. Used to exclude
# list.append and every look-alike ``*_result=`` kwarg on a different column.
_AUDIT_WRITER_FINGERPRINT = frozenset({"trust_tier_of_trigger", "cost_estimate_usd"})


class _ResultEmit:
    """A single ``result=`` argument at an audit-writer call site."""

    __slots__ = ("file", "lineno", "value")

    def __init__(self, *, file: str, lineno: int, value: str) -> None:
        self.file = file
        self.lineno = lineno
        self.value = value

    def location(self) -> str:
        return f"{self.file}:{self.lineno}"


def _is_audit_writer_call(node: ast.Call) -> bool:
    """True iff ``node`` writes an ``audit_log`` row (either write path).

    Matches BOTH ``audit_log`` write paths (see module docstring):

    * an ``AuditWriter.append`` / ``.append_schema`` method call (callee is an
      attribute access named ``append`` / ``append_schema``), OR
    * a direct ``AuditEntry(...)`` construction (callee is the bare name
      ``AuditEntry``),

    AND carrying the ``trust_tier_of_trigger`` + ``cost_estimate_usd`` kwarg
    fingerprint (see module docstring for why this excludes look-alikes).
    """
    func = node.func
    is_writer_method = isinstance(func, ast.Attribute) and func.attr in _AUDIT_WRITER_METHODS
    # Match both bare ``AuditEntry(...)`` (ast.Name) and qualified
    # ``models.AuditEntry(...)`` (ast.Attribute). The fingerprint guard below
    # keeps a same-named look-alike from false-positiving.
    is_entry_ctor = (isinstance(func, ast.Name) and func.id == _AUDIT_ENTRY_CTOR) or (
        isinstance(func, ast.Attribute) and func.attr == _AUDIT_ENTRY_CTOR
    )
    if not (is_writer_method or is_entry_ctor):
        return False
    present_kwargs = {kw.arg for kw in node.keywords if kw.arg is not None}
    return _AUDIT_WRITER_FINGERPRINT.issubset(present_kwargs)


def _collect_result_emits() -> tuple[list[_ResultEmit], list[_ResultEmit]]:
    """Walk ``src/alfred`` and split audit-writer ``result=`` args.

    Returns ``(literal_emits, dynamic_emits)`` where ``literal_emits`` carry
    the string-constant value and ``dynamic_emits`` carry a placeholder value
    (the unparsed expression) for documentation.
    """
    literal: list[_ResultEmit] = []
    dynamic: list[_ResultEmit] = []
    for path in sorted(_SRC_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _is_audit_writer_call(node)):
                continue
            for kw in node.keywords:
                if kw.arg != "result":
                    continue
                value_node = kw.value
                lineno = value_node.lineno
                if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                    literal.append(_ResultEmit(file=rel, lineno=lineno, value=value_node.value))
                else:
                    dynamic.append(
                        _ResultEmit(file=rel, lineno=lineno, value=ast.unparse(value_node))
                    )
    return literal, dynamic


def _allowed_result_domain() -> frozenset[str]:
    """Parse the allowed ``result`` set out of the constructed ORM CHECK.

    Reads ``ck_audit_log_result`` off ``AuditEntry.__table_args__`` and
    extracts every quoted literal from ``result IN ('a', 'b', ...)``. Reading
    the CONSTRUCTED constraint (not the source string) means the guard tracks
    exactly what ``metadata.create_all()`` would emit, so an ORM/migration
    drift cannot hide from it.
    """
    constraints = [
        c
        for c in AuditEntry.__table_args__
        if hasattr(c, "name") and c.name == "ck_audit_log_result"
    ]
    assert len(constraints) == 1, "expected exactly one ck_audit_log_result CheckConstraint"
    sqltext = str(constraints[0].sqltext)
    # ``[^']+`` (not ``[a-z_]+``) so a future domain value containing a digit or
    # other safe char isn't silently under-collected. Only the result literals
    # are single-quoted in ``result IN ('a', 'b', ...)`` — the column/keywords
    # are unquoted and the constraint name uses double quotes — so this can't
    # over-collect.
    return frozenset(re.findall(r"'([^']+)'", sqltext))


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


def test_every_audit_log_result_literal_is_in_check_domain() -> None:
    """Every literal ``result=`` written to ``audit_log`` is a CHECK member.

    Fails LOUDLY with the offending value + ``file:line`` so an engineer can
    fix the emit site or add the value to ``ck_audit_log_result`` via a new
    migration. This is the systematic guard for the #252 bug class.
    """
    literal_emits, _dynamic = _collect_result_emits()
    allowed = _allowed_result_domain()

    offenders = [emit for emit in literal_emits if emit.value not in allowed]
    if offenders:
        lines = "\n".join(
            f"  - result={emit.value!r} at {emit.location()}"
            for emit in sorted(offenders, key=lambda e: (e.value, e.file, e.lineno))
        )
        missing_values = sorted({emit.value for emit in offenders})
        raise AssertionError(
            "audit_log.result literal(s) NOT in ck_audit_log_result CHECK domain "
            "— a real row carrying one of these crashes with a Postgres "
            f"CheckViolation.\nMissing values: {missing_values}\n{lines}\n"
            "Fix: add the value to ck_audit_log_result via a new migration "
            "(mirror migration 0022) AND the AuditEntry CHECK string in "
            "src/alfred/memory/models.py, OR correct the emit site."
        )


def test_guard_collects_the_transport_failed_emit() -> None:
    """Sanity: the #252 ``transport_failed`` emit IS in the collected set.

    Proves the fingerprint actually reaches the quarantine transport-failed
    site (not just that the subset check is vacuously true). If this row stops
    being collected, the guard would silently stop covering #252.
    """
    literal_emits, _dynamic = _collect_result_emits()
    transport = [e for e in literal_emits if e.value == "transport_failed"]
    assert transport, "guard failed to collect the #252 transport_failed audit emit"
    assert any(e.file == "src/alfred/security/quarantine.py" for e in transport), (
        "transport_failed emit not found at the expected quarantine.py site"
    )


def test_guard_bites_on_a_bogus_result_literal() -> None:
    """Bite-proof: a synthetic out-of-domain ``result=`` literal is caught.

    Constructs a snippet that emits an audit-writer call with an
    ``__definitely_not_in_domain__`` result and asserts the SAME subset
    logic flags it. Proves the guard is not vacuous.
    """
    bogus_src = (
        "await self._audit_writer.append_schema(\n"
        "    fields=FIELDS,\n"
        "    schema_name='X',\n"
        "    event='synthetic.bite',\n"
        "    actor_user_id=None,\n"
        "    subject={},\n"
        "    trust_tier_of_trigger='T0',\n"
        "    result='__definitely_not_in_domain__',\n"
        "    cost_estimate_usd=0.0,\n"
        "    trace_id='t',\n"
        ")"
    )
    tree = ast.parse(bogus_src)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert _is_audit_writer_call(call), "fingerprint must match the synthetic audit call"

    collected = [
        kw.value.value
        for kw in call.keywords
        if kw.arg == "result"
        and isinstance(kw.value, ast.Constant)
        and isinstance(kw.value.value, str)
    ]
    allowed = _allowed_result_domain()
    offenders = [v for v in collected if v not in allowed]
    assert offenders == ["__definitely_not_in_domain__"], (
        "guard must flag a synthetic out-of-domain result literal"
    )


def test_dynamic_result_sites_are_documented() -> None:
    """Non-literal ``result=`` sites are skipped — but enumerated here.

    A static literal guard cannot prove a runtime value is in-domain, so
    dynamic ``result=`` arguments (across BOTH write paths — ``append`` /
    ``append_schema`` calls AND direct ``AuditEntry(...)`` construction) are
    excluded from the subset check. This test pins the set of dynamic sites so
    a NEW dynamic site can't be added silently: a reviewer must confirm each
    routes through an enumerated / typed value (a ``Literal``, a lookup table,
    or an ``IfExp`` over in-domain constants) rather than an arbitrary string,
    then update this expectation.

    The reachable values of every site below were MANUALLY AUDITED this round
    (the adversarial C1/H1 pass). This test does NOT attempt to auto-validate
    the reachable values — it pins the SITES so a reviewer re-audits on change.
    Outcomes of the manual audit:

    * ``security/quarantine.py`` — the ``_emit_extract_audit`` ``audit_result``
      param carries closed-vocab literals; its ``post_stage_refused`` value
      (C1) is now in ``ck_audit_log_result`` (migration 0022).
    * ``plugins/web_fetch/fetch_dispatcher.py:914`` — ``result=dlp_result`` is
      sourced from a plugin-supplied error payload
      (``error_data["dlp_scan_result"]``), falling back to ``"fetch_error"`` —
      neither is in the domain. Tracked as issue #326 (H2): the fix is an
      emit-site CLAMP to an enumerated value, NOT a domain-widen, so the value
      is deliberately NOT added to the CHECK here.
    * ``egress/relay_client.py:376`` — ``result=result`` in ``_audit_refused``;
      the three reachable values are ``"in_doubt"``, ``"io_plane_unavailable"``,
      and ``"denied"`` — all in-domain (the first two added by migration 0024;
      ``"denied"`` was already in-domain since migration 0007). Manually audited
      in the G7-2c-1 C1 pass (#333).
    * all others route through enumerated lookups / ``IfExp`` over in-domain
      constants / forwarded typed params.

    The guard documents these rather than false-positiving on them.
    """
    _literal, dynamic = _collect_result_emits()
    locations = sorted(e.location() for e in dynamic)
    expected = sorted(
        [
            # --- AuditWriter.append / .append_schema call path ---
            "src/alfred/audit/log.py:180",  # append_schema forwards result -> append
            "src/alfred/cli/daemon/_commands.py:1804",
            "src/alfred/comms_mcp/adapter_credential_resolver.py:288",
            "src/alfred/comms_mcp/adapter_status_observer.py:255",
            "src/alfred/comms_mcp/forwarded_inbound_receiver.py:366",
            # G7-2c-1 (#333) — _audit_refused result param; reachable values:
            # "in_doubt" | "io_plane_unavailable" | "denied" (all in-domain,
            # migration 0024 added the first two; "denied" was already in-domain).
            "src/alfred/egress/relay_client.py:376",
            "src/alfred/identity/cli.py:219",
            "src/alfred/memory/hooks_audit_sink.py:398",  # _RESULT_BY_EVENT lookup
            "src/alfred/orchestrator/burst_limiter.py:368",  # IfExp dropped/capped
            "src/alfred/orchestrator/core.py:842",  # IfExp over charge_result
            # web_fetch:914 — dynamic plugin-payload value tracked as #326 (H2);
            # clamp at the emit site, do NOT widen the domain (see docstring).
            "src/alfred/plugins/web_fetch/fetch_dispatcher.py:914",
            # audit_result param; post_stage_refused (C1) now in-domain.
            "src/alfred/security/quarantine.py:1261",
            "src/alfred/supervisor/core.py:692",  # result_label local
            # --- direct AuditEntry(...) construction path (H1) ---
            "src/alfred/audit/log.py:96",  # AuditWriter.append forwards result -> AuditEntry(...)
            "src/alfred/state/dispatch_loop.py:1061",  # IfExp over dispatched_with_redactions/clean
        ]
    )
    assert locations == expected, (
        "dynamic audit-writer result= sites changed.\n"
        f"got:      {locations}\n"
        f"expected: {expected}\n"
        "If you ADDED a site: confirm its result value routes through an "
        "enumerated/typed value that is in ck_audit_log_result, then update "
        "the expected list. If you made a site LITERAL: it is now covered by "
        "the subset guard — remove it here."
    )


def test_guard_bites_on_a_bogus_audit_entry_construction() -> None:
    """Bite-proof for the SECOND write path (H1): direct ``AuditEntry(...)``.

    The H1 finding: the guard was blind to a row written by constructing
    ``AuditEntry(..., result=<literal>)`` directly (``session.add(...)``)
    rather than via ``append`` / ``append_schema``. This proves the extended
    matcher now fingerprints that construction and the SAME subset logic flags
    an out-of-domain literal — mirroring the append_schema bite test.
    """
    bogus_src = (
        "session.add(\n"
        "    AuditEntry(\n"
        "        trace_id='t',\n"
        "        event='synthetic.bite',\n"
        "        actor_user_id=None,\n"
        "        subject={},\n"
        "        trust_tier_of_trigger='T0',\n"
        "        result='__definitely_not_in_domain__',\n"
        "        cost_estimate_usd=0.0,\n"
        "    )\n"
        ")"
    )
    tree = ast.parse(bogus_src)
    ctor = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "AuditEntry"
    )
    assert _is_audit_writer_call(ctor), (
        "extended fingerprint must match a direct AuditEntry(...) construction"
    )

    collected = [
        kw.value.value
        for kw in ctor.keywords
        if kw.arg == "result"
        and isinstance(kw.value, ast.Constant)
        and isinstance(kw.value.value, str)
    ]
    allowed = _allowed_result_domain()
    offenders = [v for v in collected if v not in allowed]
    assert offenders == ["__definitely_not_in_domain__"], (
        "guard must flag a synthetic out-of-domain AuditEntry result literal"
    )
