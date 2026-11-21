"""QueryVault MCP: read-only SQLite MCP server with SQL guardrails and PII redaction."""

from queryvault_mcp.server import create_server

__all__ = ["__version__", "create_server"]
__version__ = "0.1.0"
