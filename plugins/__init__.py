"""Top-level ``plugins`` namespace for supervisor-launched MCP plugins.

Plugins under this package are NOT part of the ``alfred`` wheel — the
supervisor launches each one as its own subprocess. The package exists
solely so the test/IDE/type-checker import surface is a normal Python
package import (``plugins.alfred_quarantined_llm.*``), not a sys.path
fixup at every call site.

PR-S3-4 adds the first plugin under this namespace: the quarantined-LLM
extractor (spec §5.1).
"""
