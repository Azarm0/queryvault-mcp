"""Read-only SQLite access layer, query plan analyzer, anomaly detector, and bounded audit log."""

from __future__ import annotations

import re
import sqlite3
import statistics
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from queryvault_mcp.models import (
    AnomalyPoint,
    AnomalyReport,
    AuditEntry,
    ColumnInfo,
    PlanStep,
    QueryPlanAnalysis,
    QueryResult,
    TableDescription,
    TableInfo,
)
from queryvault_mcp.security import (
    SecurityError,
    is_pii_column,
    redact_rows,
    validate_identifier,
    validate_readonly_sql,
)

DEFAULT_ROW_LIMIT = 50
MAX_ROW_LIMIT = 100
DB_TIMEOUT_SECONDS = 5.0
AUDIT_LOG_MAXLEN = 100

_SCAN_TABLE_RE = re.compile(r"\bSCAN\s+(?:TABLE\s+)?([A-Za-z_][A-Za-z0-9_]*)", flags=re.IGNORECASE)
_FILTER_COLUMN_RE = re.compile(
    r"\b(?:WHERE|AND|OR|ON)\s+(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|!=|<>|<|>|<=|>=|IN\b|LIKE\b|BETWEEN\b)",
    flags=re.IGNORECASE,
)
_ORDER_GROUP_RE = re.compile(
    r"\b(?:ORDER|GROUP)\s+BY\s+(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)",
    flags=re.IGNORECASE,
)


def _quote_ident(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


class ReadOnlyDatabase:
    """Thread-safe read-only SQLite wrapper with hard caps and bounded audit logging."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path).resolve()
        if not self.db_path.exists():
            raise FileNotFoundError(f"SQLite database not found: {self.db_path}")
        self._audit_log: deque[AuditEntry] = deque(maxlen=AUDIT_LOG_MAXLEN)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a strict read-only SQLite URI connection with PRAGMA query_only = ON."""
        uri = f"{self.db_path.as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=DB_TIMEOUT_SECONDS)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA query_only = ON")
            yield conn
        finally:
            conn.close()

    def _record_audit(
        self,
        *,
        tool: str,
        sql: str,
        status: str,
        row_count: int = 0,
        elapsed_ms: float = 0.0,
        redacted_fields_count: int = 0,
        error: str | None = None,
    ) -> None:
        self._audit_log.append(
            AuditEntry(
                timestamp=datetime.now(UTC).isoformat(),
                tool=tool,
                sql=sql,
                status=status,
                row_count=row_count,
                elapsed_ms=round(elapsed_ms, 3),
                redacted_fields_count=redacted_fields_count,
                error=error,
            )
        )

    def get_recent_audit(self) -> list[AuditEntry]:
        """Return bounded recent audit entries (newest first)."""
        return list(reversed(self._audit_log))

    def _get_table_names(self, conn: sqlite3.Connection) -> list[str]:
        rows = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        ).fetchall()
        return [str(r["name"]) for r in rows]

    def _get_table_indexes(self, conn: sqlite3.Connection, table_name: str) -> list[str]:
        rows = conn.execute(f"PRAGMA index_list({_quote_ident(table_name)})").fetchall()
        indexes: list[str] = []
        for row in rows:
            idx_name = str(row["name"])
            cols = conn.execute(f"PRAGMA index_info({_quote_ident(idx_name)})").fetchall()
            col_names = [str(c["name"]) for c in cols if c["name"] is not None]
            if col_names:
                indexes.append(f"{idx_name}({', '.join(col_names)})")
            else:
                indexes.append(idx_name)
        return indexes

    def _get_indexed_columns(self, conn: sqlite3.Connection, table_name: str) -> set[str]:
        indexed: set[str] = set()
        for row in conn.execute(f"PRAGMA index_list({_quote_ident(table_name)})").fetchall():
            idx_name = str(row["name"])
            for col in conn.execute(f"PRAGMA index_info({_quote_ident(idx_name)})").fetchall():
                if col["name"] is not None:
                    indexed.add(str(col["name"]))
        for col in conn.execute(f"PRAGMA table_info({_quote_ident(table_name)})").fetchall():
            if col["pk"]:
                indexed.add(str(col["name"]))
        return indexed

    def list_tables(self) -> list[TableInfo]:
        """Return table names, row counts, indexes, and detected PII columns."""
        start = time.perf_counter()
        with self.connect() as conn:
            tables: list[TableInfo] = []
            for table in self._get_table_names(conn):
                qt = _quote_ident(table)
                count = int(conn.execute(f"SELECT COUNT(*) FROM {qt}").fetchone()[0])
                cols = conn.execute(f"PRAGMA table_info({qt})").fetchall()
                pii_cols = [str(c["name"]) for c in cols if is_pii_column(str(c["name"]))]
                indexes = self._get_table_indexes(conn, table)
                tables.append(
                    TableInfo(
                        name=table,
                        row_count=count,
                        indexes=indexes,
                        pii_columns=pii_cols,
                    )
                )
        elapsed_ms = (time.perf_counter() - start) * 1000
        self._record_audit(
            tool="list_tables",
            sql="SELECT name FROM sqlite_master WHERE type = 'table'",
            status="ok",
            row_count=len(tables),
            elapsed_ms=elapsed_ms,
        )
        return tables

    def describe_table(self, table_name: str) -> TableDescription:
        """Return column metadata, PK/FK info, distinct counts, and indexes for a table."""
        start = time.perf_counter()
        with self.connect() as conn:
            allowed_tables = set(self._get_table_names(conn))
            validated_table = validate_identifier(table_name, allowed_tables, kind="table")
            qt = _quote_ident(validated_table)

            row_count = int(conn.execute(f"SELECT COUNT(*) FROM {qt}").fetchone()[0])
            indexes = self._get_table_indexes(conn, validated_table)

            fk_map: dict[str, str] = {}
            for fk in conn.execute(f"PRAGMA foreign_key_list({qt})").fetchall():
                fk_map[str(fk["from"])] = f"{fk['table']}.{fk['to']}"

            columns: list[ColumnInfo] = []
            for col in conn.execute(f"PRAGMA table_info({qt})").fetchall():
                col_name = str(col["name"])
                qc = _quote_ident(col_name)
                distinct_count = int(
                    conn.execute(f"SELECT COUNT(DISTINCT {qc}) FROM {qt}").fetchone()[0]
                )
                columns.append(
                    ColumnInfo(
                        name=col_name,
                        data_type=str(col["type"] or "ANY"),
                        nullable=not bool(col["notnull"]),
                        primary_key=bool(col["pk"]),
                        default_value=str(col["dflt_value"])
                        if col["dflt_value"] is not None
                        else None,
                        foreign_key=fk_map.get(col_name),
                        distinct_count=distinct_count,
                        is_pii=is_pii_column(col_name),
                    )
                )

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._record_audit(
            tool="describe_table",
            sql=f"PRAGMA table_info({validated_table})",
            status="ok",
            row_count=len(columns),
            elapsed_ms=elapsed_ms,
        )
        return TableDescription(
            table_name=validated_table,
            row_count=row_count,
            indexes=indexes,
            columns=columns,
        )

    def get_schema_map(self) -> dict[str, Any]:
        """Return complete schema and index map for the db://schema resource."""
        tables = self.list_tables()
        schema: dict[str, Any] = {
            "database": self.db_path.name,
            "limits": {
                "default_row_limit": DEFAULT_ROW_LIMIT,
                "max_row_limit": MAX_ROW_LIMIT,
                "db_timeout_seconds": DB_TIMEOUT_SECONDS,
                "audit_log_maxlen": AUDIT_LOG_MAXLEN,
            },
            "tables": {},
        }
        for t in tables:
            desc = self.describe_table(t.name)
            schema["tables"][t.name] = {
                "row_count": desc.row_count,
                "indexes": desc.indexes,
                "pii_columns": t.pii_columns,
                "columns": [c.model_dump() for c in desc.columns],
            }
        return schema

    def get_table_sample(self, table_name: str, limit: int = 5) -> dict[str, Any]:
        """Return a PII-redacted sample of rows for the db://tables/{table_name}/sample resource."""
        with self.connect() as conn:
            allowed_tables = set(self._get_table_names(conn))
            validated_table = validate_identifier(table_name, allowed_tables, kind="table")
        safe_limit = max(1, min(limit, 10))
        result = self.execute_readonly_query(
            f"SELECT * FROM {_quote_ident(validated_table)}",
            limit=safe_limit,
            redact_pii=True,
            tool_name="resource:table_sample",
        )
        return {
            "table_name": validated_table,
            "sample_size": result.row_count,
            "redacted_fields_count": result.redacted_fields_count,
            "rows": result.rows,
        }

    def execute_readonly_query(
        self,
        sql: str,
        limit: int = DEFAULT_ROW_LIMIT,
        redact_pii: bool = True,
        tool_name: str = "run_readonly_query",
    ) -> QueryResult:
        """Validate and run a read-only SQL query with hard row cap and optional PII redaction."""
        start = time.perf_counter()
        if limit < 1:
            raise ValueError("limit must be at least 1.")
        applied_limit = min(limit, MAX_ROW_LIMIT)

        try:
            cleaned_sql = validate_readonly_sql(sql)
        except SecurityError as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._record_audit(
                tool=tool_name,
                sql=sql,
                status="blocked",
                elapsed_ms=elapsed_ms,
                error=str(exc),
            )
            raise

        try:
            with self.connect() as conn:
                cursor = conn.execute(cleaned_sql)
                columns = [desc[0] for desc in (cursor.description or [])]
                fetched = cursor.fetchmany(applied_limit + 1)
                truncated = len(fetched) > applied_limit
                rows_raw = [dict(r) for r in fetched[:applied_limit]]
        except sqlite3.Error as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._record_audit(
                tool=tool_name,
                sql=cleaned_sql,
                status="error",
                elapsed_ms=elapsed_ms,
                error=str(exc),
            )
            raise ValueError(f"SQLite query error: {exc}") from exc

        redacted_count = 0
        if redact_pii and rows_raw:
            rows_final, redacted_count = redact_rows(rows_raw)
        else:
            rows_final = rows_raw

        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
        self._record_audit(
            tool=tool_name,
            sql=cleaned_sql,
            status="ok",
            row_count=len(rows_final),
            elapsed_ms=elapsed_ms,
            redacted_fields_count=redacted_count,
        )
        return QueryResult(
            sql=cleaned_sql,
            columns=columns,
            rows=rows_final,
            row_count=len(rows_final),
            truncated=truncated,
            applied_limit=applied_limit,
            elapsed_ms=elapsed_ms,
            redacted_fields_count=redacted_count,
        )

    def explain_query_plan(self, sql: str) -> QueryPlanAnalysis:
        """Run EXPLAIN QUERY PLAN, detect full table scans, and suggest indexes."""
        start = time.perf_counter()
        try:
            cleaned_sql = validate_readonly_sql(sql)
        except SecurityError as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._record_audit(
                tool="explain_query_plan",
                sql=sql,
                status="blocked",
                elapsed_ms=elapsed_ms,
                error=str(exc),
            )
            raise

        upper = re.sub(r"\s+", " ", cleaned_sql).upper()
        explain_sql = (
            cleaned_sql
            if upper.startswith("EXPLAIN QUERY PLAN ")
            else f"EXPLAIN QUERY PLAN {cleaned_sql}"
        )

        steps: list[PlanStep] = []
        scanned_tables: list[str] = []
        recommendations: list[str] = []

        with self.connect() as conn:
            allowed_tables = set(self._get_table_names(conn))
            rows = conn.execute(explain_sql).fetchall()

            for row in rows:
                detail = str(row["detail"])
                scan_match = _SCAN_TABLE_RE.search(detail)
                uses_index = "USING INDEX" in detail.upper() or "COVERING INDEX" in detail.upper()
                is_full_scan = bool(scan_match) and not uses_index
                if is_full_scan and scan_match:
                    tbl = scan_match.group(1)
                    if tbl in allowed_tables and tbl not in scanned_tables:
                        scanned_tables.append(tbl)
                steps.append(
                    PlanStep(
                        id=int(row["id"]),
                        parent=int(row["parent"]),
                        detail=detail,
                        is_full_scan=is_full_scan,
                    )
                )

            candidate_cols = set(_FILTER_COLUMN_RE.findall(cleaned_sql)) | set(
                _ORDER_GROUP_RE.findall(cleaned_sql)
            )

            for tbl in scanned_tables:
                qt = _quote_ident(tbl)
                table_cols = {
                    str(c["name"]) for c in conn.execute(f"PRAGMA table_info({qt})").fetchall()
                }
                indexed_cols = self._get_indexed_columns(conn, tbl)
                unindexed_used = sorted((candidate_cols & table_cols) - indexed_cols)
                if unindexed_used:
                    cols_sql = ", ".join(unindexed_used)
                    idx_name = f"idx_{tbl}_{'_'.join(unindexed_used)}"
                    recommendations.append(
                        f"Full table scan on '{tbl}'. Add index: "
                        f"CREATE INDEX {idx_name} ON {tbl}({cols_sql});"
                    )
                else:
                    recommendations.append(
                        f"Full table scan on '{tbl}'. Narrow the query with an indexed WHERE predicate or add a covering index."
                    )

        if not scanned_tables:
            recommendations.append("Query plan uses indexed lookups; no full table scan detected.")

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._record_audit(
            tool="explain_query_plan",
            sql=explain_sql,
            status="ok",
            row_count=len(steps),
            elapsed_ms=elapsed_ms,
        )
        return QueryPlanAnalysis(
            sql=cleaned_sql,
            steps=steps,
            has_full_table_scan=bool(scanned_tables),
            scanned_tables=scanned_tables,
            recommendations=recommendations,
        )

    def detect_anomalies(
        self,
        table_name: str,
        column_name: str,
        z_threshold: float = 2.0,
    ) -> AnomalyReport:
        """Compute mean, stdev, and z-score outliers on a validated table and numeric column."""
        start = time.perf_counter()
        if z_threshold <= 0:
            raise ValueError("z_threshold must be greater than 0.")

        with self.connect() as conn:
            allowed_tables = set(self._get_table_names(conn))
            validated_table = validate_identifier(table_name, allowed_tables, kind="table")
            qt = _quote_ident(validated_table)

            col_rows = conn.execute(f"PRAGMA table_info({qt})").fetchall()
            allowed_cols = {str(c["name"]) for c in col_rows}
            validated_col = validate_identifier(column_name, allowed_cols, kind="column")
            qc = _quote_ident(validated_col)

            pk_col = next((str(c["name"]) for c in col_rows if c["pk"]), "rowid")
            qpk = _quote_ident(pk_col) if pk_col != "rowid" else "rowid"

            context_cols = [
                str(c["name"])
                for c in col_rows
                if str(c["name"]) not in (validated_col, pk_col)
            ][:4]
            select_cols = [f"{qpk} AS __row_id__", f"{qc} AS __val__"] + [
                _quote_ident(c) for c in context_cols
            ]
            query = f"SELECT {', '.join(select_cols)} FROM {qt} WHERE {qc} IS NOT NULL"
            raw_rows = [dict(r) for r in conn.execute(query).fetchall()]

        numeric_records: list[tuple[int | str, float, dict[str, Any]]] = []
        for row in raw_rows:
            val = row["__val__"]
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                raise TypeError(
                    f"Column '{validated_table}.{validated_col}' contains non-numeric values."
                )
            ctx_raw = {k: v for k, v in row.items() if k not in ("__row_id__", "__val__")}
            ctx_redacted, _ = redact_rows([ctx_raw])
            numeric_records.append((row["__row_id__"], float(val), ctx_redacted[0]))

        if len(numeric_records) < 2:
            mean_val = numeric_records[0][1] if numeric_records else 0.0
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._record_audit(
                tool="detect_anomalies",
                sql=query,
                status="ok",
                row_count=0,
                elapsed_ms=elapsed_ms,
            )
            return AnomalyReport(
                table_name=validated_table,
                column_name=validated_col,
                sample_size=len(numeric_records),
                mean=round(mean_val, 4),
                stdev=0.0,
                z_threshold=z_threshold,
                anomalies=[],
            )

        values = [rec[1] for rec in numeric_records]
        mean_val = statistics.mean(values)
        stdev_val = statistics.stdev(values)

        anomalies: list[AnomalyPoint] = []
        if stdev_val > 0:
            for row_id, val, ctx in numeric_records:
                z = (val - mean_val) / stdev_val
                if abs(z) >= z_threshold:
                    anomalies.append(
                        AnomalyPoint(
                            row_id=row_id,
                            value=round(val, 4),
                            z_score=round(z, 3),
                            context=ctx,
                        )
                    )
            anomalies.sort(key=lambda p: abs(p.z_score), reverse=True)

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._record_audit(
            tool="detect_anomalies",
            sql=query,
            status="ok",
            row_count=len(anomalies),
            elapsed_ms=elapsed_ms,
        )
        return AnomalyReport(
            table_name=validated_table,
            column_name=validated_col,
            sample_size=len(numeric_records),
            mean=round(mean_val, 4),
            stdev=round(stdev_val, 4),
            z_threshold=z_threshold,
            anomalies=anomalies,
        )
