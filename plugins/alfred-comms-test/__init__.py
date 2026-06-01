"""Alfred comms-test reference plugin.

Implements :class:`alfred.comms.mcp_protocol.CommsAdapterMCP` as an MCP
stdio server for transport validation. Spec §9.1 validates the MCP
comms contract against a second consumer beyond the quarantined-LLM
and ``web.fetch`` plugins.

The directory uses a hyphen (``alfred-comms-test``), not an underscore,
because this plugin is launched as a subprocess by the supervisor and
is NOT imported as a Python package from host code — keeping the
hyphen makes the manifest ``id = "alfred.comms-test"`` align with the
on-disk name without an underscore-to-hyphen translation step at
launch time. Test code resolves the directory by ``Path(...)``, never
by ``import``.
"""
