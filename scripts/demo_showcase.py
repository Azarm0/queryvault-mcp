"""Live in-memory FastMCP client showcase for QueryVault MCP."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path

from fastmcp import Client
from fastmcp.exceptions import ToolError

from queryvault_mcp.seed import seed_demo_database
from queryvault_mcp.server import create_server

# Suppress FastMCP server-side traceback logging for the intentional security block demo.
logging.getLogger("fastmcp").setLevel(logging.CRITICAL)


def _section(title: str) -> None:
    bar = "=" * 72
    print(f"\n{bar}\n{title}\n{bar}")


async def run_showcase() -> None:
    with tempfile.TemporaryDirectory(prefix="queryvault_demo_") as tmpdir:
        db_path = seed_demo_database(Path(tmpdir) / "demo.db", force=True)
        server = create_server(db_path)

        async with Client(server) as client:
            # 1. list_tables structured output
            _section("[1/4] TOOL: list_tables (schema inventory + PII column detection)")
            tables_res = await client.call_tool("list_tables", {})
            print(json.dumps(tables_res.structured_content, indent=2))

            # 2. run_readonly_query with live PII redaction
            _section("[2/4] TOOL: run_readonly_query (live PII redaction active)")
            pii_query = (
                "SELECT c.id, c.company_name, c.contact_email, c.phone, c.api_key "
                "FROM customers c ORDER BY c.id"
            )
            query_res = await client.call_tool(
                "run_readonly_query",
                {"sql": pii_query, "limit": 3, "redact_pii": True},
            )
            print(json.dumps(query_res.structured_content, indent=2))

            # 3. Security guard blocking DROP TABLE customers; --
            _section("[3/4] SECURITY GUARD: blocking 'DROP TABLE customers; --'")
            malicious_sql = "DROP TABLE customers; --"
            try:
                await client.call_tool("run_readonly_query", {"sql": malicious_sql})
                print("[FAIL] Malicious query was not blocked!")
            except ToolError as exc:
                print(f"[BLOCKED] {exc}")

            # 4. detect_anomalies flagging the seeded revenue outlier
            _section("[4/4] TOOL: detect_anomalies (z-score scan on orders.amount_usd)")
            anomaly_res = await client.call_tool(
                "detect_anomalies",
                {"table_name": "orders", "column_name": "amount_usd", "z_threshold": 2.0},
            )
            print(json.dumps(anomaly_res.structured_content, indent=2))


def main() -> None:
    asyncio.run(run_showcase())


if __name__ == "__main__":
    main()
