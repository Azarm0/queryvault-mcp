"""FastMCP server factory and CLI entrypoint for QueryVault MCP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastmcp import FastMCP

from queryvault_mcp.db import DEFAULT_ROW_LIMIT, MAX_ROW_LIMIT, ReadOnlyDatabase
from queryvault_mcp.models import (
    AnomalyReport,
    QueryPlanAnalysis,
    QueryResult,
    TableDescription,
    TableInfo,
)
from queryvault_mcp.seed import seed_demo_database


def create_server(db_path: Path | str) -> FastMCP:
    """Build a FastMCP server bound to a read-only SQLite database."""
    db = ReadOnlyDatabase(db_path)

    mcp = FastMCP(
        name="QueryVault MCP",
        instructions=(
            "Read-only SQLite analytics server with multi-layer SQL guardrails, "
            "automatic PII redaction, query plan inspection, and z-score anomaly detection. "
            f"Hard caps: max {MAX_ROW_LIMIT} rows per query, 5.0s DB timeout, 100-entry audit log."
        ),
    )

    # ------------------------------------------------------------------
    # Tools (5)
    # ------------------------------------------------------------------

    @mcp.tool
    def list_tables() -> list[TableInfo]:
        """List all user tables with row counts, indexes, and detected PII columns."""
        return db.list_tables()

    @mcp.tool
    def describe_table(table_name: str) -> TableDescription:
        """Return column types, PK/FK constraints, distinct counts, and PII flags for a table."""
        return db.describe_table(table_name)

    @mcp.tool
    def run_readonly_query(
        sql: str,
        limit: int = DEFAULT_ROW_LIMIT,
        redact_pii: bool = True,
    ) -> QueryResult:
        """Execute a single guarded SELECT/WITH query with hard 100-row cap and PII redaction."""
        return db.execute_readonly_query(sql=sql, limit=limit, redact_pii=redact_pii)

    @mcp.tool
    def explain_query_plan(sql: str) -> QueryPlanAnalysis:
        """Run EXPLAIN QUERY PLAN, flag full table SCANs, and return index recommendations."""
        return db.explain_query_plan(sql=sql)

    @mcp.tool
    def detect_anomalies(
        table_name: str,
        column_name: str,
        z_threshold: float = 2.0,
    ) -> AnomalyReport:
        """Compute mean, stdev, and z-score outliers on a validated table and numeric column."""
        return db.detect_anomalies(
            table_name=table_name,
            column_name=column_name,
            z_threshold=z_threshold,
        )

    # ------------------------------------------------------------------
    # Resources (3)
    # ------------------------------------------------------------------

    @mcp.resource("db://schema", mime_type="application/json")
    def resource_schema() -> str:
        """Full JSON schema, index map, PII column list, and hard server limits."""
        return json.dumps(db.get_schema_map(), indent=2)

    @mcp.resource("db://tables/{table_name}/sample", mime_type="application/json")
    def resource_table_sample(table_name: str) -> str:
        """PII-redacted 5-row preview of a validated table."""
        return json.dumps(db.get_table_sample(table_name, limit=5), indent=2)

    @mcp.resource("db://audit/recent", mime_type="application/json")
    def resource_audit_recent() -> str:
        """Recent bounded in-memory audit log (max 100 entries, newest first)."""
        entries = [entry.model_dump() for entry in db.get_recent_audit()]
        return json.dumps({"count": len(entries), "entries": entries}, indent=2)

    # ------------------------------------------------------------------
    # Prompts (2)
    # ------------------------------------------------------------------

    @mcp.prompt
    def investigate_revenue_drop(
        table_name: str = "orders",
        metric_column: str = "amount_usd",
        z_threshold: float = 2.0,
    ) -> str:
        """Guided workflow: inspect schema, run anomaly scan, and isolate revenue root causes."""
        return (
            f"Investigate revenue anomalies in '{table_name}.{metric_column}' using QueryVault MCP:\n"
            f"1. Read resource `db://schema` or call `list_tables` and `describe_table('{table_name}')` "
            "to confirm table relationships and indexes.\n"
            f"2. Call `detect_anomalies(table_name='{table_name}', column_name='{metric_column}', "
            f"z_threshold={z_threshold})` to flag statistical outliers.\n"
            "3. Call `run_readonly_query` with a grouped breakdown by status, region, and plan_tier "
            "(keep redact_pii=True) to separate duplicate charges from failed payment storms.\n"
            "4. Summarize affected order IDs, customer segments, total dollar impact, and remediation steps."
        )

    @mcp.prompt
    def audit_query_performance(sql: str) -> str:
        """Guided workflow: analyze EXPLAIN QUERY PLAN and propose minimal safe indexes."""
        return (
            "Audit the following read-only SQL query for performance bottlenecks:\n"
            f"```sql\n{sql}\n```\n"
            "1. Call `explain_query_plan` with the SQL statement above.\n"
            "2. Check `has_full_table_scan` and `scanned_tables` in the structured output.\n"
            "3. Inspect current table indexes via `describe_table` for every scanned table.\n"
            "4. Return exact `CREATE INDEX` statements, explain selectivity tradeoffs, "
            "and note any write-overhead risks."
        )

    return mcp


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for QueryVault MCP."""
    parser = argparse.ArgumentParser(
        prog="queryvault-mcp",
        description="Read-only SQLite MCP server with SQL guardrails and PII redaction.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("demo.db"),
        help="Path to the SQLite database file (default: ./demo.db).",
    )
    parser.add_argument(
        "--seed-demo",
        action="store_true",
        help="Generate the deterministic SaaS demo database at --db if it does not exist.",
    )
    parser.add_argument(
        "--force-seed",
        action="store_true",
        help="Overwrite --db with a fresh seeded demo database.",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport mode: stdio (default) or http (Streamable HTTP).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host for --transport http (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Bind port for --transport http (default: 8000).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Run QueryVault MCP from the command line."""
    args = parse_args(argv)
    if args.seed_demo or args.force_seed:
        seed_demo_database(args.db, force=args.force_seed)

    server = create_server(args.db)
    if args.transport == "http":
        server.run(transport="http", host=args.host, port=args.port)
    else:
        server.run()


if __name__ == "__main__":
    main()
