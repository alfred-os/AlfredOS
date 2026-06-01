"""web.fetch host-side package (spec §7).

This package owns the host-side primitives the ``alfred-web-fetch`` plugin
relies on: the operational error tree (:mod:`errors`), the Redis-backed
``ContentStore`` (:mod:`content_store`), the three-way allowlist
intersection (:mod:`allowlist`), the Lua-atomic rate limiter
(:mod:`rate_limit`), the system-tier ``InboundCanaryScanner``
(:mod:`canary_scanner`), and the ``tool.web.fetch`` hookpoint
registration entrypoint (this module).

Tasks 1-6 of PR-S3-5 land the symbols incrementally; this docstring
documents the final public surface so reviewers can confirm each task
adds the spec'd primitive without expanding the contract.
"""

from __future__ import annotations
