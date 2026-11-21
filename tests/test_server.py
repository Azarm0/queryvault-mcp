"""End-to-end async tests for QueryVault MCP using FastMCP's in-memory Client."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from queryvault_mcp.seed import seed_demo_database
from queryvault_mcp.server import create_server


@pytest.fixture()
def demo_server(tmp_path: Path):
    db_path = seed_demo_database(tmp_path / "test_demo.db", force=True)
    return create_server(db_path)


async def test_list_tables_tool(demo_server) -> None:
    async with Client(demo_server) as client:
        res = await client.call_tool("list_tables", {})
        tables = res.structured_content["result"]
        names = [t["name"] for t in tables]
        assert names == ["customers", "orders", "subscriptions", "webhook_events"]

        customers = next(t for t in tables if t["name"] == "customers")
        assert customers["row_count"] == 15
        assert set(customers["pii_columns"]) == {"contact_email", "phone", "api_key"}

        orders = next(t for t in tables if t["name"] == "orders")
        assert orders["row_count"] == 120


async def test_describe_table_tool(demo_server) -> None:
    async with Client(demo_server) as client:
        res = await client.call_tool("describe_table", {"table_name": "orders"})
        desc = res.structured_content
        assert desc["table_name"] == "orders"
        assert desc["row_count"] == 120
        col_map = {c["name"]: c for c in desc["columns"]}
        assert col_map["id"]["primary_key"] is True
        assert col_map["customer_id"]["foreign_key"] == "customers.id"

        with pytest.raises(ToolError):
            await client.call_tool("describe_table", {"table_name": "orders; DROP TABLE orders"})


async def test_run_readonly_query_redacts_pii(demo_server) -> None:
    async with Client(demo_server) as client:
        res = await client.call_tool(
            "run_readonly_query",
            {
                "sql": "SELECT id, contact_email, phone, api_key FROM customers ORDER BY id",
                "limit": 5,
                "redact_pii": True,
            },
        )
        data = res.structured_content
        assert data["row_count"] == 5
        assert data["truncated"] is True
        assert data["applied_limit"] == 5
        assert data["redacted_fields_count"] == 15
        assert data["elapsed_ms"] >= 0.0

        serialized = json.dumps(data["rows"])
        assert "alice.chen@northstar.io" not in serialized
        assert "415-555-0142" not in serialized
        assert "qv_live_" not in serialized
        assert "a***@northstar.io" in serialized
        assert "***-***-0142" in serialized
        assert "[REDACTED]" in serialized


async def test_run_readonly_query_hard_row_cap(demo_server) -> None:
    async with Client(demo_server) as client:
        res = await client.call_tool(
            "run_readonly_query",
            {"sql": "SELECT id, amount_usd FROM orders", "limit": 500},
        )
        data = res.structured_content
        assert data["applied_limit"] == 100
        assert data["row_count"] == 100
        assert data["truncated"] is True

        with pytest.raises(ToolError):
            await client.call_tool(
                "run_readonly_query",
                {"sql": "SELECT id FROM orders", "limit": 0},
            )


@pytest.mark.parametrize(
    "bad_sql",
    [
        "DROP TABLE customers; --",
        "DELETE FROM orders WHERE id = 1",
        "SELECT 1; DROP TABLE orders",
        "ATTACH DATABASE ':memory:' AS extra",
        "PRAGMA table_info(customers)",
        "UPDATE customers SET plan_tier = 'free'",
    ],
)
async def test_run_readonly_query_blocks_injection_and_writes(demo_server, bad_sql: str) -> None:
    async with Client(demo_server) as client:
        with pytest.raises(ToolError):
            await client.call_tool("run_readonly_query", {"sql": bad_sql})


async def test_explain_query_plan_detects_full_scan_and_indexed_lookup(demo_server) -> None:
    async with Client(demo_server) as client:
        # Unindexed filter on orders.status -> full table SCAN
        scan_res = await client.call_tool(
            "explain_query_plan",
            {"sql": "SELECT id, amount_usd FROM orders WHERE status = 'failed'"},
        )
        scan_data = scan_res.structured_content
        assert scan_data["has_full_table_scan"] is True
        assert "orders" in scan_data["scanned_tables"]
        assert any("CREATE INDEX" in rec and "status" in rec for rec in scan_data["recommendations"])

        # Indexed filter on orders.customer_id -> no full table SCAN
        idx_res = await client.call_tool(
            "explain_query_plan",
            {"sql": "SELECT id, amount_usd FROM orders WHERE customer_id = 1"},
        )
        idx_data = idx_res.structured_content
        assert idx_data["has_full_table_scan"] is False
        assert idx_data["scanned_tables"] == []


async def test_detect_anomalies_flags_seeded_revenue_outliers(demo_server) -> None:
    async with Client(demo_server) as client:
        res = await client.call_tool(
            "detect_anomalies",
            {"table_name": "orders", "column_name": "amount_usd", "z_threshold": 2.0},
        )
        report = res.structured_content
        assert report["table_name"] == "orders"
        assert report["column_name"] == "amount_usd"
        assert report["sample_size"] == 120
        assert len(report["anomalies"]) >= 2

        top_ids = {pt["row_id"] for pt in report["anomalies"][:2]}
        assert top_ids == {47, 93}
        assert report["anomalies"][0]["value"] == 14950.0
        assert report["anomalies"][0]["z_score"] > 5.0
        # Ensure inline PII inside notes context was redacted
        ctx_text = json.dumps(report["anomalies"])
        assert "billing@northstar.io" not in ctx_text
        assert "415-555-0199" not in ctx_text


async def test_all_three_resources(demo_server) -> None:
    async with Client(demo_server) as client:
        # 1. db://schema
        schema_contents = await client.read_resource("db://schema")
        schema = json.loads(schema_contents[0].text)
        assert schema["limits"]["max_row_limit"] == 100
        assert "customers" in schema["tables"]
        assert "orders" in schema["tables"]

        # 2. db://tables/{table_name}/sample
        sample_contents = await client.read_resource("db://tables/customers/sample")
        sample = json.loads(sample_contents[0].text)
        assert sample["table_name"] == "customers"
        assert sample["sample_size"] == 5
        assert sample["redacted_fields_count"] > 0
        assert "alice.chen@northstar.io" not in json.dumps(sample["rows"])

        # Trigger one blocked query so audit log records both ok and blocked entries
        with pytest.raises(ToolError):
            await client.call_tool("run_readonly_query", {"sql": "DROP TABLE customers"})

        # 3. db://audit/recent
        audit_contents = await client.read_resource("db://audit/recent")
        audit = json.loads(audit_contents[0].text)
        assert audit["count"] >= 2
        statuses = {entry["status"] for entry in audit["entries"]}
        assert "ok" in statuses
        assert "blocked" in statuses


async def test_both_prompts(demo_server) -> None:
    async with Client(demo_server) as client:
        prompts = await client.list_prompts()
        prompt_names = {p.name for p in prompts}
        assert prompt_names == {"investigate_revenue_drop", "audit_query_performance"}

        rev_prompt = await client.get_prompt(
            "investigate_revenue_drop",
            {"table_name": "orders", "metric_column": "amount_usd", "z_threshold": 2.5},
        )
        rev_text = rev_prompt.messages[0].content.text
        assert "detect_anomalies" in rev_text
        assert "orders" in rev_text

        perf_prompt = await client.get_prompt(
            "audit_query_performance",
            {"sql": "SELECT * FROM orders WHERE region = 'eu-west'"},
        )
        perf_text = perf_prompt.messages[0].content.text
        assert "explain_query_plan" in perf_text
        assert "CREATE INDEX" in perf_text
