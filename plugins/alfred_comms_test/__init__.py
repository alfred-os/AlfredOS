"""Alfred comms-test reference plugin.

Implements :class:`alfred.comms.mcp_protocol.CommsAdapterMCP` as an MCP
stdio server for transport validation. Spec §9.1 validates the MCP
comms contract against a second consumer beyond the quarantined-LLM
and ``web.fetch`` plugins.

The on-disk directory uses an underscore (``alfred_comms_test``) so the
package is importable by mypy / pyright — a hyphenated dir containing
``__init__.py`` confuses the type-checker (mypy: "alfred-comms-test
contains __init__.py but is not a valid Python package name"). The
underscore form follows the established ``alfred_quarantined_llm`` /
``alfred_web_fetch`` precedent from PR-S3-3a / PR-S3-5. The manifest's
publicly-visible ``id = "alfred.comms-test"`` keeps the hyphen; the
supervisor resolves the on-disk path via ``Path``, never by ``import``.
"""
