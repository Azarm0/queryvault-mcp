"""Unit tests for SQL guardrails and PII redaction."""

from __future__ import annotations

import pytest

from queryvault_mcp.security import (
    SecurityError,
    is_pii_column,
    redact_rows,
    strip_sql_comments,
    validate_readonly_sql,
)


def test_strip_comments_preserves_string_literals() -> None:
    sql = "SELECT '-- not a comment' AS tag, /* block */ '/* also literal */' AS tag2 -- trailing"
    cleaned = strip_sql_comments(sql)
    assert "'-- not a comment'" in cleaned
    assert "'/* also literal */'" in cleaned
    assert "block" not in cleaned
    assert "trailing" not in cleaned


def test_unterminated_block_comment_rejected() -> None:
    with pytest.raises(SecurityError, match="Unterminated block comment"):
        validate_readonly_sql("SELECT 1 /* unclosed")


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id, company_name FROM customers;",
        "WITH top_orders AS (SELECT * FROM orders WHERE amount_usd > 100) SELECT * FROM top_orders",
        "EXPLAIN QUERY PLAN SELECT * FROM orders WHERE status = 'failed'",
        "SELECT 'DELETE' AS action_label FROM orders LIMIT 1",
    ],
)
def test_valid_readonly_sql_passes(sql: str) -> None:
    cleaned = validate_readonly_sql(sql)
    assert not cleaned.endswith(";")


@pytest.mark.parametrize(
    "sql",
    [
        "",
        "   -- just a comment",
        "DROP TABLE customers; --",
        "SELECT 1; SELECT 2",
        "SELECT 1; DROP TABLE orders;",
        "DELETE FROM orders WHERE id = 1",
        "INSERT INTO customers (id) VALUES (999)",
        "UPDATE orders SET amount_usd = 0",
        "ALTER TABLE orders ADD COLUMN hacked TEXT",
        "CREATE TABLE evil (id INT)",
        "REPLACE INTO customers (id) VALUES (1)",
        "TRUNCATE TABLE orders",
        "ATTACH DATABASE '/tmp/pwn.db' AS pwn",
        "DETACH DATABASE main",
        "VACUUM",
        "REINDEX orders",
        "PRAGMA writable_schema = ON",
        "/* sneaky */ DROP TABLE customers",
        "WITH cte AS (SELECT 1) DELETE FROM orders",
    ],
)
def test_malicious_or_non_readonly_sql_blocked(sql: str) -> None:
    with pytest.raises(SecurityError):
        validate_readonly_sql(sql)


def test_pii_column_detection() -> None:
    assert is_pii_column("contact_email")
    assert is_pii_column("PHONE")
    assert is_pii_column("api_key")
    assert is_pii_column("user_password_hash")
    assert not is_pii_column("company_name")
    assert not is_pii_column("amount_usd")


def test_redact_rows_masks_columns_and_inline_pii() -> None:
    rows = [
        {
            "company_name": "Northstar Analytics",
            "contact_email": "alice.chen@northstar.io",
            "phone": "+1-415-555-0142",
            "api_key": "qv_live_01_123456789012",
            "notes": "Escalate to billing@northstar.io or call +1-415-555-0199",
            "amount_usd": 149.50,
        }
    ]
    redacted, count = redact_rows(rows)
    row = redacted[0]

    assert count == 4
    assert row["company_name"] == "Northstar Analytics"
    assert row["amount_usd"] == 149.50
    assert row["contact_email"] == "a***@northstar.io"
    assert row["phone"] == "***-***-0142"
    assert row["api_key"] == "[REDACTED]"
    assert "billing@northstar.io" not in row["notes"]
    assert "b***@northstar.io" in row["notes"]
    assert "***-***-0199" in row["notes"]
    assert "415-555-0199" not in row["notes"]
