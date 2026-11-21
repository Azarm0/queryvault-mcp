"""Multi-layer read-only SQL guard and automatic PII redaction engine."""

from __future__ import annotations

import re
from typing import Any


class SecurityError(ValueError):
    """Raised when a SQL statement or identifier violates read-only guardrails."""


BLOCKED_KEYWORDS: tuple[str, ...] = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "CREATE",
    "REPLACE",
    "TRUNCATE",
    "ATTACH",
    "DETACH",
    "VACUUM",
    "REINDEX",
    "PRAGMA",
    "SAVEPOINT",
    "RELEASE",
    "ROLLBACK",
    "BEGIN",
    "COMMIT",
    "LOAD_EXTENSION",
)

_BLOCKED_PATTERN = re.compile(
    r"\b(?:" + "|".join(BLOCKED_KEYWORDS) + r")\b",
    flags=re.IGNORECASE,
)

PII_COLUMN_TOKENS: tuple[str, ...] = (
    "email",
    "phone",
    "mobile",
    "ssn",
    "api_key",
    "token",
    "password",
    "secret",
)

EMAIL_REGEX = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
PHONE_REGEX = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?(\d{4})(?!\w)"
)


def strip_sql_comments(sql: str) -> str:
    """Remove -- line comments and /* */ block comments while preserving string literals."""
    out: list[str] = []
    i = 0
    n = len(sql)
    in_single = False
    in_double = False

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if in_single:
            out.append(ch)
            if ch == "'" and nxt == "'":
                out.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue

        if in_double:
            out.append(ch)
            if ch == '"' and nxt == '"':
                out.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue

        if ch == "'":
            in_single = True
            out.append(ch)
            i += 1
            continue

        if ch == '"':
            in_double = True
            out.append(ch)
            i += 1
            continue

        if ch == "-" and nxt == "-":
            i += 2
            while i < n and sql[i] not in ("\n", "\r"):
                i += 1
            out.append(" ")
            continue

        if ch == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            if end == -1:
                raise SecurityError("Unterminated block comment in SQL statement.")
            i = end + 2
            out.append(" ")
            continue

        out.append(ch)
        i += 1

    if in_single or in_double:
        raise SecurityError("Unterminated string or identifier literal in SQL statement.")

    return "".join(out)


def _strip_string_literals(sql: str) -> str:
    """Replace single-quoted string literals with empty literals for safe keyword inspection."""
    out: list[str] = []
    i = 0
    n = len(sql)
    in_single = False

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if in_single:
            if ch == "'" and nxt == "'":
                i += 2
                continue
            if ch == "'":
                in_single = False
                out.append("'")
            i += 1
            continue
        if ch == "'":
            in_single = True
            out.append("'")
            i += 1
            continue
        out.append(ch)
        i += 1

    return "".join(out)


def _check_stacked_statements(sql_no_strings: str) -> None:
    """Reject any semicolon followed by non-whitespace characters."""
    first_semi = sql_no_strings.find(";")
    if first_semi == -1:
        return
    trailing = sql_no_strings[first_semi + 1 :].strip()
    if trailing:
        raise SecurityError("Stacked SQL statements are not allowed.")


def validate_readonly_sql(sql: str) -> str:
    """Validate that SQL is a single read-only SELECT, WITH...SELECT, or EXPLAIN QUERY PLAN."""
    if not sql or not sql.strip():
        raise SecurityError("SQL statement cannot be empty.")

    stripped = strip_sql_comments(sql).strip()
    if not stripped:
        raise SecurityError("SQL statement contains only comments or whitespace.")

    inspectable = _strip_string_literals(stripped)
    _check_stacked_statements(inspectable)

    # Strip a single benign trailing semicolon
    cleaned = stripped[:-1].strip() if stripped.endswith(";") else stripped
    inspectable_cleaned = inspectable[:-1].strip() if inspectable.endswith(";") else inspectable

    blocked_match = _BLOCKED_PATTERN.search(inspectable_cleaned)
    if blocked_match:
        keyword = blocked_match.group(0).upper()
        raise SecurityError(f"Blocked SQL keyword detected: {keyword}")

    normalized_prefix = re.sub(r"\s+", " ", inspectable_cleaned).strip().upper()

    is_select = normalized_prefix.startswith("SELECT ") or normalized_prefix == "SELECT"
    is_cte_select = normalized_prefix.startswith("WITH ") and bool(
        re.search(r"\bSELECT\b", inspectable_cleaned, flags=re.IGNORECASE)
    )
    is_explain_select = normalized_prefix.startswith("EXPLAIN QUERY PLAN SELECT ") or (
        normalized_prefix.startswith("EXPLAIN QUERY PLAN WITH ")
        and bool(re.search(r"\bSELECT\b", inspectable_cleaned, flags=re.IGNORECASE))
    )

    if not (is_select or is_cte_select or is_explain_select):
        raise SecurityError(
            "Only single SELECT, WITH ... SELECT, or EXPLAIN QUERY PLAN SELECT statements are allowed."
        )

    return cleaned


def validate_identifier(name: str, allowed: set[str], kind: str = "identifier") -> str:
    """Validate a table or column identifier against an exact schema allowlist."""
    if name not in allowed:
        raise SecurityError(f"Unknown or disallowed {kind}: {name!r}")
    return name


def is_pii_column(column_name: str) -> bool:
    """Return True if a column name matches any sensitive PII token."""
    lowered = column_name.lower()
    return any(token in lowered for token in PII_COLUMN_TOKENS)


def mask_email(value: str) -> str:
    """Mask email addresses into a***@domain format."""
    return EMAIL_REGEX.sub(lambda m: f"{m.group(1)[0]}***@{m.group(2)}", value)


def mask_phone(value: str) -> str:
    """Mask phone numbers into ***-***-1234 format preserving the last 4 digits."""
    return PHONE_REGEX.sub(lambda m: f"***-***-{m.group(1)}", value)


def redact_value(column_name: str, value: Any) -> tuple[Any, bool]:
    """Redact a single cell value based on column name and inline PII regexes."""
    if value is None:
        return None, False

    if is_pii_column(column_name):
        if isinstance(value, str):
            if EMAIL_REGEX.search(value):
                return mask_email(value), True
            if PHONE_REGEX.search(value):
                return mask_phone(value), True
        return "[REDACTED]", True

    if isinstance(value, str):
        redacted = mask_email(value)
        redacted = mask_phone(redacted)
        if redacted != value:
            return redacted, True

    return value, False


def redact_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Redact PII across a list of row dicts and return (redacted_rows, redacted_fields_count)."""
    redacted_count = 0
    redacted_rows: list[dict[str, Any]] = []

    for row in rows:
        new_row: dict[str, Any] = {}
        for col, val in row.items():
            new_val, was_redacted = redact_value(col, val)
            if was_redacted:
                redacted_count += 1
            new_row[col] = new_val
        redacted_rows.append(new_row)

    return redacted_rows, redacted_count
