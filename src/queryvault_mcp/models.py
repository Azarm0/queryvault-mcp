"""Pydantic v2 structured output models for QueryVault MCP."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ColumnInfo(BaseModel):
    name: str
    data_type: str
    nullable: bool
    primary_key: bool
    default_value: str | None = None
    foreign_key: str | None = None
    distinct_count: int = Field(ge=0)
    is_pii: bool = False


class TableInfo(BaseModel):
    name: str
    row_count: int = Field(ge=0)
    indexes: list[str] = Field(default_factory=list)
    pii_columns: list[str] = Field(default_factory=list)


class TableDescription(BaseModel):
    table_name: str
    row_count: int = Field(ge=0)
    indexes: list[str] = Field(default_factory=list)
    columns: list[ColumnInfo] = Field(default_factory=list)


class QueryResult(BaseModel):
    sql: str
    columns: list[str] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = Field(ge=0)
    truncated: bool = False
    applied_limit: int = Field(ge=1)
    elapsed_ms: float = Field(ge=0.0)
    redacted_fields_count: int = Field(ge=0, default=0)


class PlanStep(BaseModel):
    id: int
    parent: int
    detail: str
    is_full_scan: bool = False


class QueryPlanAnalysis(BaseModel):
    sql: str
    steps: list[PlanStep] = Field(default_factory=list)
    has_full_table_scan: bool = False
    scanned_tables: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class AnomalyPoint(BaseModel):
    row_id: int | str
    value: float
    z_score: float
    context: dict[str, Any] = Field(default_factory=dict)


class AnomalyReport(BaseModel):
    table_name: str
    column_name: str
    sample_size: int = Field(ge=0)
    mean: float
    stdev: float = Field(ge=0.0)
    z_threshold: float = Field(gt=0.0)
    anomalies: list[AnomalyPoint] = Field(default_factory=list)


class AuditEntry(BaseModel):
    timestamp: str
    tool: str
    sql: str
    status: str
    row_count: int = Field(ge=0, default=0)
    elapsed_ms: float = Field(ge=0.0, default=0.0)
    redacted_fields_count: int = Field(ge=0, default=0)
    error: str | None = None
