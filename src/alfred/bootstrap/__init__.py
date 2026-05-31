"""AlfredOS process-bootstrap factories.

Modules under this package construct per-process objects that need to
exist before any caller runs — most notably the T3 capability-gate
nonce. They are called exactly once at process start and are NOT a
runtime API; production callers never re-enter them.
"""
