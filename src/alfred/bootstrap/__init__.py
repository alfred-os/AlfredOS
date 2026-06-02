"""AlfredOS process-bootstrap factories.

Modules under this package construct per-process objects that need to
exist before any caller runs — most notably the T3 capability-gate
nonce. They are called exactly once at process start and are NOT a
runtime API; production callers never re-enter them.

:mod:`alfred.bootstrap.gate_factory` is the ONE module in ``src/alfred/``
that may read the production-environment env key for the purpose of
selecting which :class:`alfred.security.capability_gate._gate.RealGate`
construction the supervisor wires — the development branch (no
grants, in-memory stub backend, no heartbeat) or the production
branch (Postgres backend, full grant table, heartbeat running). PR-S3-7
removed the Slice-2.5 :class:`DevGate` from ``src/`` entirely (spec
§15.1 flag-day); both bootstrap branches now construct
:class:`RealGate`. The capability-gate modules themselves
(``hooks/capability.py``,
``security/capability_gate/{policy,_gate,backend,proposals}.py``) are
import-os-forbidden and contain no literal references to the env key;
the AST scans in :mod:`tests.unit.security` pin the invariant.
"""
