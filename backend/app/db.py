from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import settings

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - PostgreSQL backend needs optional dependency.
    psycopg = None
    dict_row = None


_db_lock = threading.RLock()
POSTGRES_BACKENDS = {"postgres", "postgresql", "pg"}
ALERT_EXCLUDED_SOURCES = {"doonsec_wechat", "github_advisories"}
POSTGRES_ID_TABLES = {
    "analysis_events",
    "analysis_feedback",
    "deepseek_balance_checks",
    "github_evidence",
    "messages",
    "model_usage_events",
    "product_aliases",
    "rag_notes",
    "runs",
    "sbom_components",
    "sbom_projects",
    "source_archives",
    "vendor_aliases",
    "vulnerabilities",
}
VULNERABILITY_COLUMNS = [
    "id",
    "source",
    "source_uid",
    "title",
    "severity",
    "cve_id",
    "aliases",
    "published_at",
    "updated_at",
    "description",
    "url",
    "product",
    "raw",
    "first_seen_at",
    "last_seen_at",
    "cvss_score",
    "cvss_version",
    "cvss_vector",
    "poc_available",
    "poc_url",
    "poc_content",
    "exp_available",
    "exp_url",
    "exp_content",
    "dedupe_key",
    "analysis_status",
    "analysis_requested_at",
    "analysis_started_at",
    "analysis_finished_at",
    "analysis_error",
    "analysis_source_found",
    "analysis_source_url",
    "analysis_source_local_path",
    "analysis_source_title",
    "analysis_source_archive_path",
    "analysis_source_retained_until",
    "analysis_source_cleaned_at",
    "analysis_summary",
    "analysis_sources",
    "analysis_raw",
    "analysis_run_id",
    "analysis_model",
    "analysis_trigger",
    "analysis_priority",
    "analysis_cancel_requested",
    "analysis_failure_reason",
    "quality_score",
    "quality_level",
    "quality_reason",
    "quality_raw",
    "quality_updated_at",
    "product_match_method",
    "product_match_confidence",
    "product_match_evidence",
    "product_resolved_at",
    "github_evidence_checked_at",
    "github_evidence_count",
    "github_evidence_max_score",
    "github_evidence_summary",
]


def _compat_row(row: Any) -> CompatRow | None:
    if row is None:
        return None
    if isinstance(row, CompatRow):
        return row
    return CompatRow(dict(row))


def _normalize_params(params: Any) -> Any:
    if params is None:
        return ()
    if isinstance(params, dict):
        return params
    if isinstance(params, (list, tuple)):
        return tuple(params)
    return (params,)


def _postgres_pragma_table_info(statement: str) -> str:
    match = re.fullmatch(
        r"\s*PRAGMA\s+table_info\s*\(\s*\"?([A-Za-z_][A-Za-z0-9_]*)\"?\s*\)\s*;?\s*",
        statement or "",
        flags=re.I,
    )
    return match.group(1) if match else ""


def _postgres_sql(statement: str) -> str:
    sql = (statement or "").strip()
    sql = re.sub(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", sql, flags=re.I)
    sql = re.sub(r"\s+COLLATE\s+NOCASE\b", "", sql, flags=re.I)
    return _sqlite_placeholders_to_psycopg(sql)


def _sqlite_placeholders_to_psycopg(sql: str) -> str:
    out: list[str] = []
    in_single = False
    in_double = False
    index = 0
    while index < len(sql):
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""
        if char == "'" and not in_double:
            out.append(char)
            if in_single and next_char == "'":
                out.append(next_char)
                index += 2
                continue
            in_single = not in_single
        elif char == '"' and not in_single:
            out.append(char)
            if in_double and next_char == '"':
                out.append(next_char)
                index += 2
                continue
            in_double = not in_double
        elif char == "?" and not in_single and not in_double:
            out.append("%s")
        elif char == "%":
            out.append("%%")
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _postgres_lastrowid_sql(sql: str) -> tuple[str, bool]:
    stripped = sql.strip().rstrip(";")
    match = re.match(r"INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)\s", stripped, flags=re.I)
    if not match or re.search(r"\bRETURNING\b", stripped, flags=re.I):
        return sql, False
    table = match.group(1).lower()
    if table == "alerts" and "ON CONFLICT" not in stripped.upper():
        return f"{stripped} ON CONFLICT DO NOTHING RETURNING id", True
    if table in POSTGRES_ID_TABLES and "ON CONFLICT" not in stripped.upper():
        return f"{stripped} RETURNING id", True
    return sql, False


def _postgres_schema_sql(sql: str) -> str:
    rewritten = re.sub(
        r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b",
        "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
        sql,
        flags=re.I,
    )
    rewritten = re.sub(r"\bAUTOINCREMENT\b", "", rewritten, flags=re.I)
    return rewritten


def _split_sql_script(script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    for char in script or "":
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if char == ";" and not in_single and not in_double:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def _ensure_postgres_indexes(conn: PostgresConnection) -> None:
    statements = [
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_vulnerabilities_source_uid ON vulnerabilities(source, source_uid)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_dedupe_key ON alerts(dedupe_key)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_product_aliases_product_alias ON product_aliases(product_key, normalized_alias)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_vendor_aliases_vendor_alias ON vendor_aliases(vendor_key, normalized_alias)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_analysis_feedback_vulnerability ON analysis_feedback(vulnerability_id)",
    ]
    for statement in statements:
        conn._conn.execute(statement)


class CompatRow(dict):
    def __init__(self, values: dict[str, Any]) -> None:
        super().__init__(values)
        self._keys = list(values.keys())

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return super().__getitem__(self._keys[key])
        return super().__getitem__(key)


class PostgresCursor:
    def __init__(self, cursor: Any, *, lastrowid: int = 0, buffered_rows: list[CompatRow] | None = None) -> None:
        self._cursor = cursor
        self.lastrowid = lastrowid
        self._buffered_rows = buffered_rows or []
        self.rowcount = cursor.rowcount
        self.description = cursor.description

    def fetchone(self) -> CompatRow | None:
        if self._buffered_rows:
            return self._buffered_rows.pop(0)
        row = self._cursor.fetchone()
        return _compat_row(row)

    def fetchall(self) -> list[CompatRow]:
        rows = self._buffered_rows
        self._buffered_rows = []
        return rows + [_compat_row(row) for row in self._cursor.fetchall()]

    def fetchmany(self, size: int) -> list[CompatRow]:
        rows: list[CompatRow] = []
        while self._buffered_rows and len(rows) < size:
            rows.append(self._buffered_rows.pop(0))
        if len(rows) < size:
            rows.extend(_compat_row(row) for row in self._cursor.fetchmany(size - len(rows)))
        return rows


class PostgresConnection:
    def __init__(self) -> None:
        if psycopg is None or dict_row is None:
            raise RuntimeError("psycopg is required when DATABASE_BACKEND=postgresql")
        if not settings.database_url:
            raise RuntimeError("DATABASE_URL is required when DATABASE_BACKEND=postgresql")
        self._conn = psycopg.connect(settings.database_url, row_factory=dict_row, connect_timeout=5)

    def execute(self, statement: str, params: Any = ()) -> PostgresCursor:
        pragma = _postgres_pragma_table_info(statement)
        if pragma:
            rows = self._table_info(pragma)
            return PostgresCursor(_EmptyCursor(), buffered_rows=rows)
        sql = _postgres_sql(statement)
        sql, wants_lastrowid = _postgres_lastrowid_sql(sql)
        cursor = self._conn.cursor()
        cursor.execute(sql, _normalize_params(params))
        lastrowid = 0
        buffered_rows: list[CompatRow] = []
        if wants_lastrowid:
            row = cursor.fetchone()
            if row is not None:
                compat = _compat_row(row)
                buffered_rows.append(compat)
                try:
                    lastrowid = int(compat[0] or 0)
                except (TypeError, ValueError):
                    lastrowid = 0
        return PostgresCursor(cursor, lastrowid=lastrowid, buffered_rows=buffered_rows if not wants_lastrowid else [])

    def executescript(self, script: str) -> None:
        for statement in _split_sql_script(script):
            sql = _postgres_sql(statement)
            sql = _postgres_schema_sql(sql)
            if sql.strip():
                self._conn.execute(sql)
        _ensure_postgres_indexes(self)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _table_info(self, table: str) -> list[CompatRow]:
        rows = self._conn.execute(
            """
            SELECT
                c.column_name AS name,
                c.data_type AS type,
                CASE WHEN c.is_nullable = 'NO' THEN 1 ELSE 0 END AS notnull,
                c.column_default AS dflt_value,
                CASE WHEN tc.constraint_type = 'PRIMARY KEY' THEN kcu.ordinal_position ELSE 0 END AS pk
            FROM information_schema.columns c
            LEFT JOIN information_schema.key_column_usage kcu
              ON c.table_schema = kcu.table_schema
             AND c.table_name = kcu.table_name
             AND c.column_name = kcu.column_name
            LEFT JOIN information_schema.table_constraints tc
              ON kcu.constraint_schema = tc.constraint_schema
             AND kcu.constraint_name = tc.constraint_name
             AND tc.constraint_type = 'PRIMARY KEY'
            WHERE c.table_schema = 'public'
              AND c.table_name = %s
            ORDER BY c.ordinal_position
            """,
            (table,),
        ).fetchall()
        return [_compat_row(row) for row in rows]


class _EmptyCursor:
    rowcount = 0
    description = None

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> list[Any]:
        return []

    def fetchmany(self, size: int) -> list[Any]:
        return []


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        match = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", text)
        if not match:
            return None
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
        except ValueError:
            return None


def _using_postgres() -> bool:
    return settings.database_backend in POSTGRES_BACKENDS


def _connect() -> sqlite3.Connection | PostgresConnection:
    if _using_postgres():
        return PostgresConnection()
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.database_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def connection() -> Iterable[sqlite3.Connection | PostgresConnection]:
    lock = _db_lock if not _using_postgres() else nullcontext()
    with lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db() -> None:
    with connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sources (
                name TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                schedule TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_run_at TEXT,
                last_status TEXT,
                last_error TEXT,
                last_item_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                source_uid TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                cve_id TEXT,
                aliases TEXT NOT NULL DEFAULT '[]',
                published_at TEXT,
                updated_at TEXT,
                description TEXT,
                url TEXT,
                product TEXT,
                raw TEXT NOT NULL DEFAULT '{}',
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(source, source_uid)
            );

            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published
                ON vulnerabilities(published_at DESC);
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source
                ON vulnerabilities(source);
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve
                ON vulnerabilities(cve_id);

            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                item_count INTEGER NOT NULL DEFAULT 0,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS deepseek_balance_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checked_at TEXT NOT NULL,
                status TEXT NOT NULL,
                is_available INTEGER,
                currency TEXT,
                total_balance TEXT,
                granted_balance TEXT,
                topped_up_balance TEXT,
                raw TEXT NOT NULL DEFAULT '{}',
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'new',
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                acknowledged_at TEXT,
                FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_status
                ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_created
                ON alerts(created_at DESC);

            CREATE TABLE IF NOT EXISTS followed_products (
                product_key TEXT PRIMARY KEY,
                product TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_matched_at TEXT,
                last_analysis_vulnerability_id INTEGER
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL DEFAULT 'info',
                category TEXT NOT NULL DEFAULT 'system',
                title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                entity_type TEXT NOT NULL DEFAULT '',
                entity_id TEXT NOT NULL DEFAULT '',
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                read_at TEXT,
                raw TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_messages_read_created
                ON messages(is_read, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_messages_category
                ON messages(category);

            CREATE TABLE IF NOT EXISTS analysis_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                run_id TEXT NOT NULL DEFAULT '',
                stream TEXT NOT NULL DEFAULT 'stage',
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                raw TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
            );

            CREATE INDEX IF NOT EXISTS idx_analysis_events_vulnerability
                ON analysis_events(vulnerability_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_analysis_events_run
                ON analysis_events(run_id, id DESC);

            CREATE TABLE IF NOT EXISTS products (
                product_key TEXT PRIMARY KEY,
                source TEXT NOT NULL DEFAULT '',
                source_uid TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL,
                normalized_name TEXT NOT NULL,
                url TEXT NOT NULL DEFAULT '',
                vulnerability_count INTEGER NOT NULL DEFAULT 0,
                poc_count INTEGER NOT NULL DEFAULT 0,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                last_crawled_at TEXT,
                raw TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_products_source
                ON products(source);
            CREATE INDEX IF NOT EXISTS idx_products_name
                ON products(name);
            CREATE INDEX IF NOT EXISTS idx_products_vuln_count
                ON products(vulnerability_count DESC);

            CREATE TABLE IF NOT EXISTS product_vulnerabilities (
                product_key TEXT NOT NULL,
                vulnerability_id INTEGER NOT NULL,
                product_name TEXT NOT NULL,
                match_method TEXT NOT NULL DEFAULT '',
                confidence REAL NOT NULL DEFAULT 0,
                evidence TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                raw TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(product_key, vulnerability_id),
                FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
            );

            CREATE INDEX IF NOT EXISTS idx_product_vulns_product
                ON product_vulnerabilities(product_key, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_product_vulns_vulnerability
                ON product_vulnerabilities(vulnerability_id);

            CREATE TABLE IF NOT EXISTS product_aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_key TEXT NOT NULL,
                alias TEXT NOT NULL,
                normalized_alias TEXT NOT NULL,
                vendor TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(product_key, normalized_alias)
            );

            CREATE INDEX IF NOT EXISTS idx_product_aliases_product
                ON product_aliases(product_key);
            CREATE INDEX IF NOT EXISTS idx_product_aliases_normalized
                ON product_aliases(normalized_alias);

            CREATE TABLE IF NOT EXISTS vendor_aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_key TEXT NOT NULL,
                vendor TEXT NOT NULL,
                alias TEXT NOT NULL,
                normalized_alias TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(vendor_key, normalized_alias)
            );

            CREATE INDEX IF NOT EXISTS idx_vendor_aliases_normalized
                ON vendor_aliases(normalized_alias);

            CREATE TABLE IF NOT EXISTS analysis_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                rating TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(vulnerability_id),
                FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
            );

            CREATE TABLE IF NOT EXISTS sbom_projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '',
                supplier TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                raw TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS sbom_components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '',
                supplier TEXT NOT NULL DEFAULT '',
                purl TEXT NOT NULL DEFAULT '',
                product_key TEXT NOT NULL DEFAULT '',
                match_method TEXT NOT NULL DEFAULT '',
                confidence REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                raw TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(project_id) REFERENCES sbom_projects(id)
            );

            CREATE INDEX IF NOT EXISTS idx_sbom_components_project
                ON sbom_components(project_id);
            CREATE INDEX IF NOT EXISTS idx_sbom_components_product
                ON sbom_components(product_key);

            CREATE TABLE IF NOT EXISTS sbom_component_vulnerabilities (
                project_id INTEGER NOT NULL,
                component_id INTEGER NOT NULL,
                vulnerability_id INTEGER NOT NULL,
                product_key TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(project_id, component_id, vulnerability_id),
                FOREIGN KEY(project_id) REFERENCES sbom_projects(id),
                FOREIGN KEY(component_id) REFERENCES sbom_components(id),
                FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
            );

            CREATE INDEX IF NOT EXISTS idx_sbom_component_vulns_project
                ON sbom_component_vulnerabilities(project_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sbom_component_vulns_vuln
                ON sbom_component_vulnerabilities(vulnerability_id);

            CREATE TABLE IF NOT EXISTS rag_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL DEFAULT 'analysis',
                title TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                tags TEXT NOT NULL DEFAULT '[]',
                related_key TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_rag_notes_scope
                ON rag_notes(scope, updated_at DESC);

            CREATE TABLE IF NOT EXISTS model_usage_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type TEXT NOT NULL,
                model TEXT NOT NULL,
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                estimated_cost REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'success',
                created_at TEXT NOT NULL,
                raw TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_model_usage_events_created
                ON model_usage_events(created_at DESC);

            CREATE TABLE IF NOT EXISTS source_archives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                origin TEXT NOT NULL DEFAULT 'user_upload',
                filename TEXT NOT NULL DEFAULT '',
                content_type TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                sha256 TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'queued',
                minio_status TEXT NOT NULL DEFAULT 'pending',
                minio_bucket TEXT NOT NULL DEFAULT '',
                minio_object_key TEXT NOT NULL DEFAULT '',
                minio_url TEXT NOT NULL DEFAULT '',
                minio_error TEXT NOT NULL DEFAULT '',
                local_path TEXT NOT NULL DEFAULT '',
                extracted_path TEXT NOT NULL DEFAULT '',
                product_hint TEXT NOT NULL DEFAULT '',
                suggested_product_name TEXT NOT NULL DEFAULT '',
                suggested_vendor TEXT NOT NULL DEFAULT '',
                suggested_aliases TEXT NOT NULL DEFAULT '[]',
                product_name TEXT NOT NULL DEFAULT '',
                product_key TEXT NOT NULL DEFAULT '',
                product_confirmed INTEGER NOT NULL DEFAULT 0,
                architecture_summary TEXT NOT NULL DEFAULT '',
                function_summary TEXT NOT NULL DEFAULT '',
                product_evidence TEXT NOT NULL DEFAULT '',
                analysis_model TEXT NOT NULL DEFAULT '',
                analysis_raw TEXT NOT NULL DEFAULT '{}',
                error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                analyzed_at TEXT,
                confirmed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_source_archives_status
                ON source_archives(status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_source_archives_product
                ON source_archives(product_key, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_source_archives_sha256
                ON source_archives(sha256);
            CREATE INDEX IF NOT EXISTS idx_source_archives_created
                ON source_archives(created_at DESC);

            CREATE TABLE IF NOT EXISTS github_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL DEFAULT '',
                query TEXT NOT NULL DEFAULT '',
                evidence_type TEXT NOT NULL DEFAULT '',
                artifact_kind TEXT NOT NULL DEFAULT 'unknown',
                title TEXT NOT NULL DEFAULT '',
                evidence_url TEXT NOT NULL DEFAULT '',
                repository TEXT NOT NULL DEFAULT '',
                evidence_path TEXT NOT NULL DEFAULT '',
                snippet TEXT NOT NULL DEFAULT '',
                score REAL NOT NULL DEFAULT 0,
                confidence TEXT NOT NULL DEFAULT 'low',
                source_api TEXT NOT NULL DEFAULT 'github',
                raw TEXT NOT NULL DEFAULT '{}',
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(vulnerability_id, evidence_url, evidence_path),
                FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
            );

            CREATE INDEX IF NOT EXISTS idx_github_evidence_vulnerability
                ON github_evidence(vulnerability_id, score DESC, last_seen_at DESC);
            CREATE INDEX IF NOT EXISTS idx_github_evidence_kind
                ON github_evidence(artifact_kind, score DESC);
            CREATE INDEX IF NOT EXISTS idx_github_evidence_cve
                ON github_evidence(cve_id);

            """
        )
        _ensure_columns(
            conn,
            "vulnerabilities",
            {
                "cvss_score": "REAL",
                "cvss_version": "TEXT NOT NULL DEFAULT ''",
                "cvss_vector": "TEXT NOT NULL DEFAULT ''",
                "poc_available": "INTEGER NOT NULL DEFAULT 0",
                "poc_url": "TEXT NOT NULL DEFAULT ''",
                "poc_content": "TEXT NOT NULL DEFAULT ''",
                "exp_available": "INTEGER NOT NULL DEFAULT 0",
                "exp_url": "TEXT NOT NULL DEFAULT ''",
                "exp_content": "TEXT NOT NULL DEFAULT ''",
                "dedupe_key": "TEXT NOT NULL DEFAULT ''",
                "analysis_status": "TEXT NOT NULL DEFAULT 'idle'",
                "analysis_requested_at": "TEXT",
                "analysis_started_at": "TEXT",
                "analysis_finished_at": "TEXT",
                "analysis_error": "TEXT NOT NULL DEFAULT ''",
                "analysis_source_found": "INTEGER NOT NULL DEFAULT 0",
                "analysis_source_url": "TEXT NOT NULL DEFAULT ''",
                "analysis_source_local_path": "TEXT NOT NULL DEFAULT ''",
                "analysis_source_title": "TEXT NOT NULL DEFAULT ''",
                "analysis_source_archive_path": "TEXT NOT NULL DEFAULT ''",
                "analysis_source_retained_until": "TEXT NOT NULL DEFAULT ''",
                "analysis_source_cleaned_at": "TEXT NOT NULL DEFAULT ''",
                "analysis_summary": "TEXT NOT NULL DEFAULT ''",
                "analysis_sources": "TEXT NOT NULL DEFAULT '[]'",
                "analysis_raw": "TEXT NOT NULL DEFAULT '{}'",
                "analysis_run_id": "TEXT NOT NULL DEFAULT ''",
                "analysis_model": "TEXT NOT NULL DEFAULT ''",
                "analysis_trigger": "TEXT NOT NULL DEFAULT ''",
                "analysis_priority": "INTEGER NOT NULL DEFAULT 50",
                "analysis_cancel_requested": "INTEGER NOT NULL DEFAULT 0",
                "analysis_failure_reason": "TEXT NOT NULL DEFAULT ''",
                "quality_score": "REAL",
                "quality_level": "TEXT NOT NULL DEFAULT ''",
                "quality_reason": "TEXT NOT NULL DEFAULT ''",
                "quality_raw": "TEXT NOT NULL DEFAULT '{}'",
                "quality_updated_at": "TEXT",
                "product_match_method": "TEXT NOT NULL DEFAULT ''",
                "product_match_confidence": "REAL",
                "product_match_evidence": "TEXT NOT NULL DEFAULT ''",
                "product_resolved_at": "TEXT",
                "github_evidence_checked_at": "TEXT NOT NULL DEFAULT ''",
                "github_evidence_count": "INTEGER NOT NULL DEFAULT 0",
                "github_evidence_max_score": "REAL",
                "github_evidence_summary": "TEXT NOT NULL DEFAULT '{}'",
            },
        )
        _ensure_columns(
            conn,
            "products",
            {
                "vendor": "TEXT NOT NULL DEFAULT ''",
                "merged_into_product_key": "TEXT NOT NULL DEFAULT ''",
                "merge_note": "TEXT NOT NULL DEFAULT ''",
            },
        )
        _ensure_columns(
            conn,
            "product_vulnerabilities",
            {
                "evidence_type": "TEXT NOT NULL DEFAULT 'direct'",
                "source_count": "INTEGER NOT NULL DEFAULT 1",
            },
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_dedupe ON vulnerabilities(dedupe_key)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_analysis_status ON vulnerabilities(analysis_status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_quality ON vulnerabilities(quality_score DESC)"
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_analysis_queue
            ON vulnerabilities(analysis_status, analysis_priority DESC, analysis_requested_at ASC)
            """
        )
        _seed_common_product_aliases(conn)
        _backfill_vulnerability_intel(conn)
        _cleanup_placeholder_artifacts(conn)
        _cleanup_noisy_product_matches(conn)


def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing_rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row["name"]: dict(row) for row in existing_rows}
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
            continue
        default = _column_default_from_ddl(ddl)
        not_null = "NOT NULL" in ddl.upper()
        if default is not None:
            conn.execute(f"UPDATE {table} SET {name}={default} WHERE {name} IS NULL")
        if _using_postgres():
            if default is not None:
                conn.execute(
                    f"ALTER TABLE {_quote_ident(table)} ALTER COLUMN {_quote_ident(name)} SET DEFAULT {default}"
                )
            if not_null and not bool(existing[name].get("notnull")):
                conn.execute(
                    f"ALTER TABLE {_quote_ident(table)} ALTER COLUMN {_quote_ident(name)} SET NOT NULL"
                )


def _quote_ident(value: str) -> str:
    return '"' + str(value).replace('"', '""') + '"'


def _column_default_from_ddl(ddl: str) -> str | None:
    match = re.search(r"\bDEFAULT\s+(.+)$", ddl.strip(), flags=re.I)
    if not match:
        return None
    return match.group(1).strip()


def _cleanup_noisy_product_matches(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT id, product, product_match_method, product_match_evidence
        FROM vulnerabilities
        WHERE COALESCE(product, '') <> ''
           OR COALESCE(product_match_evidence, '') <> ''
        """
    ).fetchall()
    noisy_ids: list[int] = []
    noisy_products: set[str] = set()
    for row in rows:
        product = str(row["product"] or "")
        evidence = str(row["product_match_evidence"] or "")
        evidence_label = evidence.rsplit("：", 1)[-1] if "：" in evidence else ""
        if _is_noisy_product_label(product) or _is_noisy_product_label(evidence_label):
            noisy_ids.append(int(row["id"]))
            if product:
                noisy_products.add(product_key(product))
            if evidence_label:
                noisy_products.add(product_key(evidence_label))
    if noisy_ids:
        placeholders = ",".join("?" for _ in noisy_ids)
        conn.execute(
            f"""
            UPDATE vulnerabilities
            SET product='',
                product_match_method='',
                product_match_confidence=NULL,
                product_match_evidence='',
                product_resolved_at=NULL
            WHERE id IN ({placeholders})
            """,
            noisy_ids,
        )
        conn.execute(
            f"DELETE FROM product_vulnerabilities WHERE vulnerability_id IN ({placeholders})",
            noisy_ids,
        )
    clean_keys = [key for key in noisy_products if key]
    if clean_keys:
        placeholders = ",".join("?" for _ in clean_keys)
        conn.execute(
            f"""
            DELETE FROM products
            WHERE product_key IN ({placeholders})
              AND source='vulnerability_match'
            """,
            clean_keys,
        )


def _seed_common_product_aliases(conn: sqlite3.Connection) -> None:
    now = utc_now()
    aliases = [
        ("用友NC", "Yonyou NC", "用友"),
        ("用友NC", "Yongyou NC", "用友"),
        ("用友NC", "YonyouNC", "用友"),
        ("用友NC", "YongyouNC", "用友"),
        ("用友NC", "UFIDA NC", "用友"),
        ("用友NC", "Yonyou UFIDA ERP NC", "用友"),
        ("用友NC", "Yonyou UFIDA ERP-NC", "用友"),
        ("用友 NC", "Yonyou NC", "用友"),
        ("用友NC Cloud", "Yonyou NC Cloud", "用友"),
        ("用友NC Cloud", "Yonyou NC-Cloud", "用友"),
        ("用友NC Cloud", "Yonyou NCCloud", "用友"),
        ("用友NC Cloud", "Yonyou NC Cloud", "用友"),
        ("用友U8", "Yonyou U8", "用友"),
        ("用友U8", "Yongyou U8", "用友"),
        ("用友U8", "UFIDA U8", "用友"),
        ("用友U8", "Yonyou U8", "用友"),
        ("用友U8 Cloud", "Yonyou U8 Cloud", "用友"),
        ("用友CRM", "Yonyou CRM", "用友"),
        ("用友YonBIP", "Yonyou YonBIP", "用友"),
        ("泛微OA", "Weaver OA", "泛微"),
        ("金蝶云", "Kingdee Cloud", "金蝶"),
        ("畅捷通T+", "Chanjet T+", "畅捷通"),
    ]
    for canonical_name, alias, vendor in aliases:
        normalized = _normalize_product_text(canonical_name)
        row = conn.execute(
            """
            SELECT product_key
            FROM products
            WHERE normalized_name=?
              AND COALESCE(merged_into_product_key, '') = ''
            LIMIT 1
            """,
            (normalized,),
        ).fetchone()
        if row is None:
            continue
        alias_norm = _normalize_product_text(alias)
        if not alias_norm:
            continue
        conn.execute(
            """
            INSERT INTO product_aliases (
                product_key, alias, normalized_alias, vendor, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(product_key, normalized_alias) DO UPDATE SET
                alias=excluded.alias,
                vendor=excluded.vendor,
                updated_at=excluded.updated_at
            """,
            (row["product_key"], alias, alias_norm, vendor, now, now),
        )


def _backfill_vulnerability_intel(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT *
        FROM vulnerabilities
        WHERE dedupe_key=''
           OR cvss_score IS NULL
           OR poc_content=''
           OR exp_content=''
        LIMIT 10000
        """
    ).fetchall()
    for row in rows:
        data = dict(row)
        data["aliases"] = json.loads(data.get("aliases") or "[]")
        data["raw"] = json.loads(data.get("raw") or "{}")
        intel = extract_item_intel(data)
        conn.execute(
            """
            UPDATE vulnerabilities
            SET
                cvss_score=COALESCE(cvss_score, ?),
                cvss_version=CASE WHEN cvss_version='' THEN ? ELSE cvss_version END,
                cvss_vector=CASE WHEN cvss_vector='' THEN ? ELSE cvss_vector END,
                poc_available=CASE WHEN poc_available=0 THEN ? ELSE poc_available END,
                poc_url=CASE WHEN poc_url='' THEN ? ELSE poc_url END,
                poc_content=CASE WHEN poc_content='' THEN ? ELSE poc_content END,
                exp_available=CASE WHEN exp_available=0 THEN ? ELSE exp_available END,
                exp_url=CASE WHEN exp_url='' THEN ? ELSE exp_url END,
                exp_content=CASE WHEN exp_content='' THEN ? ELSE exp_content END,
                dedupe_key=CASE WHEN dedupe_key='' THEN ? ELSE dedupe_key END
            WHERE id=?
            """,
            (
                intel.get("cvss_score"),
                intel.get("cvss_version") or "",
                intel.get("cvss_vector") or "",
                1 if intel.get("poc_available") else 0,
                intel.get("poc_url") or "",
                intel.get("poc_content") or "",
                1 if intel.get("exp_available") else 0,
                intel.get("exp_url") or "",
                intel.get("exp_content") or "",
                intel.get("dedupe_key") or "",
                data["id"],
            ),
        )


def _cleanup_placeholder_artifacts(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT id, poc_available, poc_url, poc_content, exp_available, exp_url, exp_content
        FROM vulnerabilities
        WHERE (poc_available=1 AND COALESCE(poc_url, '')='')
           OR (exp_available=1 AND COALESCE(exp_url, '')='')
           OR poc_content LIKE '源数据包含 POC 标记:%'
           OR exp_content LIKE '源数据包含 EXP 标记:%'
           OR poc_content LIKE '源字段 % 标记存在 POC。'
           OR exp_content LIKE '源字段 % 标记存在 EXP。'
        """
    ).fetchall()
    for row in rows:
        poc_available, poc_url, poc_content = _normalize_artifact_fields(
            "poc",
            bool(row["poc_available"]),
            row["poc_url"] or "",
            row["poc_content"] or "",
        )
        exp_available, exp_url, exp_content = _normalize_artifact_fields(
            "exp",
            bool(row["exp_available"]),
            row["exp_url"] or "",
            row["exp_content"] or "",
        )
        if (
            int(poc_available) == int(row["poc_available"] or 0)
            and poc_url == (row["poc_url"] or "")
            and poc_content == (row["poc_content"] or "")
            and int(exp_available) == int(row["exp_available"] or 0)
            and exp_url == (row["exp_url"] or "")
            and exp_content == (row["exp_content"] or "")
        ):
            continue
        conn.execute(
            """
            UPDATE vulnerabilities
            SET poc_available=?,
                poc_url=?,
                poc_content=?,
                exp_available=?,
                exp_url=?,
                exp_content=?
            WHERE id=?
            """,
            (
                1 if poc_available else 0,
                poc_url,
                poc_content,
                1 if exp_available else 0,
                exp_url,
                exp_content,
                row["id"],
            ),
        )
        _refresh_vulnerability_quality_conn(conn, int(row["id"]))


def compute_quality_score(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw") or {}
    if isinstance(raw, str):
        raw = _json_value(raw, {})
    aliases = row.get("aliases") or []
    if isinstance(aliases, str):
        aliases = _json_value(aliases, [])

    reasons: list[str] = []
    score = 0.0
    severity = str(row.get("severity") or "unknown").lower()
    severity_score = {"critical": 34, "high": 26, "medium": 12, "low": 5}.get(severity, 3)
    score += severity_score
    reasons.append(f"等级 {severity}: +{severity_score}")

    cvss = _score_value(row.get("cvss_score"))
    if cvss is not None:
        add = 12 if cvss >= 9 else 8 if cvss >= 7 else 4 if cvss >= 4 else 1
        score += add
        reasons.append(f"CVSS {cvss:g}: +{add}")

    if row.get("poc_available"):
        score += 14
        reasons.append("POC: +14")
    if row.get("exp_available"):
        score += 16
        reasons.append("EXP: +16")

    raw_text = json.dumps(raw, ensure_ascii=False).lower() if raw else ""
    in_wild_markers = [
        "known exploited",
        "kev",
        "exploited in the wild",
        "wild",
        "在野",
        "已利用",
        "ransomware",
        "proof_of_concept",
        "exploit maturity",
    ]
    if any(marker in raw_text for marker in in_wild_markers):
        score += 12
        reasons.append("利用活跃/公开利用信号: +12")

    source_reports = raw.get("_source_reports") if isinstance(raw, dict) else None
    source_count = 1
    if isinstance(source_reports, list):
        source_count = max(1, len(source_reports) + 1)
    source_add = min(10, (source_count - 1) * 3)
    if source_add:
        score += source_add
        reasons.append(f"多源交叉 {source_count} 个源: +{source_add}")

    published = _parse_datetime(row.get("published_at") or row.get("updated_at"))
    if published:
        now = datetime.now(timezone.utc)
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        age_days = max(0, (now - published).days)
        freshness = 10 if age_days <= 3 else 8 if age_days <= 7 else 5 if age_days <= 30 else 1
        score += freshness
        reasons.append(f"新鲜度 {age_days} 天: +{freshness}")

    product = row.get("product") or _asset_from_title(row.get("title") or "")
    followed = bool(row.get("is_followed")) or is_product_followed(product)
    if followed:
        score += 12
        reasons.append("命中关注产品: +12")

    if row.get("cve_id") or aliases:
        score += 3
        reasons.append("有标准编号/别名: +3")

    final = max(0.0, min(100.0, round(score, 1)))
    level = "critical" if final >= 85 else "high" if final >= 70 else "medium" if final >= 45 else "low"
    return {
        "score": final,
        "level": level,
        "reason": "；".join(reasons),
        "raw": {
            "engine": "local",
            "severity": severity,
            "cvss_score": cvss,
            "source_count": source_count,
            "followed": followed,
        },
    }


def _refresh_vulnerability_quality_conn(conn: sqlite3.Connection, vulnerability_id: int) -> None:
    row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone()
    if row is None:
        return
    data = dict(row)
    data["raw"] = _json_value(data.get("raw"), {})
    data["aliases"] = _json_value(data.get("aliases"), [])
    data["poc_available"] = bool(data.get("poc_available"))
    data["exp_available"] = bool(data.get("exp_available"))
    quality = compute_quality_score(data)
    conn.execute(
        """
        UPDATE vulnerabilities
        SET quality_score=?, quality_level=?, quality_reason=?, quality_raw=?, quality_updated_at=?
        WHERE id=?
        """,
        (
            quality["score"],
            quality["level"],
            quality["reason"][:4000],
            json.dumps(quality["raw"], ensure_ascii=False),
            utc_now(),
            vulnerability_id,
        ),
    )


def refresh_quality_scores(limit: int = 500) -> dict[str, Any]:
    limit = max(1, min(limit, 5000))
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id
            FROM vulnerabilities
            ORDER BY COALESCE(quality_updated_at, '') ASC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        for row in rows:
            _refresh_vulnerability_quality_conn(conn, int(row["id"]))
    return {"status": "ok", "count": len(rows)}


def upsert_github_evidence(
    vulnerability_id: int,
    evidence_items: list[dict[str, Any]],
    *,
    mark_checked: bool = True,
) -> dict[str, Any]:
    now = utc_now()
    changed = 0
    with connection() as conn:
        if not conn.execute("SELECT id FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone():
            return {"status": "missing", "changed": 0, "summary": {}}
        for item in evidence_items:
            evidence_url = _clip_text(item.get("url") or item.get("evidence_url"), 2000)
            evidence_path = _clip_text(item.get("path") or item.get("evidence_path"), 1000)
            if not evidence_url and not evidence_path:
                continue
            score = _bounded_float(item.get("score"), 0.0, 100.0)
            confidence = str(item.get("confidence") or _github_confidence_label(score)).strip() or "low"
            raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
            conn.execute(
                """
                INSERT INTO github_evidence (
                    vulnerability_id, cve_id, query, evidence_type, artifact_kind,
                    title, evidence_url, repository, evidence_path, snippet,
                    score, confidence, source_api, raw, first_seen_at, last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vulnerability_id, evidence_url, evidence_path) DO UPDATE SET
                    cve_id=excluded.cve_id,
                    query=excluded.query,
                    evidence_type=excluded.evidence_type,
                    artifact_kind=excluded.artifact_kind,
                    title=excluded.title,
                    repository=excluded.repository,
                    snippet=excluded.snippet,
                    score=excluded.score,
                    confidence=excluded.confidence,
                    source_api=excluded.source_api,
                    raw=excluded.raw,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    vulnerability_id,
                    _clip_text(item.get("cve_id"), 64),
                    _clip_text(item.get("query"), 1000),
                    _clip_text(item.get("evidence_type") or item.get("type"), 64),
                    _clip_text(item.get("artifact_kind") or "unknown", 32),
                    _clip_text(item.get("title"), 500),
                    evidence_url,
                    _clip_text(item.get("repository"), 255),
                    evidence_path,
                    _clip_text(item.get("snippet"), 4000),
                    score,
                    confidence[:32],
                    _clip_text(item.get("source_api") or "github", 64),
                    json.dumps(raw, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            changed += 1
        summary = _refresh_github_evidence_summary_conn(conn, vulnerability_id, checked_at=now if mark_checked else "")
    return {"status": "ok", "changed": changed, "summary": summary}


def list_github_evidence(vulnerability_id: int, limit: int = 20) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 100))
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM github_evidence
            WHERE vulnerability_id=?
            ORDER BY score DESC, last_seen_at DESC, id DESC
            LIMIT ?
            """,
            (vulnerability_id, limit),
        ).fetchall()
    return [_deserialize_github_evidence(dict(row)) for row in rows]


def github_evidence_needs_refresh(vulnerability_id: int, max_age_hours: int = 24) -> bool:
    with connection() as conn:
        row = conn.execute(
            "SELECT github_evidence_checked_at FROM vulnerabilities WHERE id=?",
            (vulnerability_id,),
        ).fetchone()
    if row is None:
        return False
    checked_at = _parse_datetime(row["github_evidence_checked_at"])
    if checked_at is None:
        return True
    return datetime.now(timezone.utc) - checked_at >= timedelta(hours=max(1, max_age_hours))


def mark_github_evidence_checked(vulnerability_id: int, note: str = "") -> dict[str, Any]:
    with connection() as conn:
        summary = _refresh_github_evidence_summary_conn(
            conn,
            vulnerability_id,
            checked_at=utc_now(),
            note=note,
        )
    return {"status": "ok", "summary": summary}


def recent_vulnerabilities_for_github_evidence(limit: int = 20) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 200))
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM vulnerabilities
            WHERE COALESCE(cve_id, '') <> ''
              AND (
                COALESCE(github_evidence_checked_at, '') = ''
                OR github_evidence_checked_at < ?
              )
            ORDER BY COALESCE(published_at, updated_at, first_seen_at) DESC, id DESC
            LIMIT ?
            """,
            ((datetime.now(timezone.utc) - timedelta(hours=settings.github_evidence_refresh_hours)).isoformat(timespec="seconds"), limit),
        ).fetchall()
    return [_deserialize_vuln(dict(row)) for row in rows]


def _refresh_github_evidence_summary_conn(
    conn: sqlite3.Connection,
    vulnerability_id: int,
    *,
    checked_at: str = "",
    note: str = "",
) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            COALESCE(MAX(score), 0) AS max_score,
            SUM(CASE WHEN artifact_kind='poc' THEN 1 ELSE 0 END) AS poc_count,
            SUM(CASE WHEN artifact_kind='exp' THEN 1 ELSE 0 END) AS exp_count,
            SUM(CASE WHEN evidence_type='advisory' THEN 1 ELSE 0 END) AS advisory_count,
            SUM(CASE WHEN evidence_type='code' THEN 1 ELSE 0 END) AS code_count,
            SUM(CASE WHEN evidence_type='repository' THEN 1 ELSE 0 END) AS repository_count
        FROM github_evidence
        WHERE vulnerability_id=?
        """,
        (vulnerability_id,),
    ).fetchone()
    total = int(row["total"] or 0) if row else 0
    max_score = float(row["max_score"] or 0) if row else 0.0
    summary = {
        "total": total,
        "max_score": round(max_score, 1),
        "confidence": _github_confidence_label(max_score),
        "poc_count": int(row["poc_count"] or 0) if row else 0,
        "exp_count": int(row["exp_count"] or 0) if row else 0,
        "advisory_count": int(row["advisory_count"] or 0) if row else 0,
        "code_count": int(row["code_count"] or 0) if row else 0,
        "repository_count": int(row["repository_count"] or 0) if row else 0,
        "note": note,
    }
    assignments = [
        "github_evidence_count=?",
        "github_evidence_max_score=?",
        "github_evidence_summary=?",
    ]
    args: list[Any] = [
        total,
        max_score if total else None,
        json.dumps(summary, ensure_ascii=False),
    ]
    if checked_at:
        assignments.append("github_evidence_checked_at=?")
        args.append(checked_at)
    args.append(vulnerability_id)
    conn.execute(
        f"UPDATE vulnerabilities SET {', '.join(assignments)} WHERE id=?",
        args,
    )
    return summary


def _deserialize_github_evidence(row: dict[str, Any]) -> dict[str, Any]:
    row["raw"] = _json_value(row.get("raw"), {})
    row["score"] = round(float(row.get("score") or 0), 1)
    row["confidence"] = row.get("confidence") or _github_confidence_label(row["score"])
    return row


def _github_confidence_label(score: float | int | None) -> str:
    value = float(score or 0)
    if value >= 78:
        return "high"
    if value >= 55:
        return "medium"
    return "low"


def _bounded_float(value: Any, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = minimum
    return max(minimum, min(maximum, round(number, 2)))


def _clip_text(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return None if row is None else dict(row)


def register_source(
    name: str,
    title: str,
    category: str,
    schedule: str,
    *,
    enabled_by_default: bool = True,
) -> None:
    now = utc_now()
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO sources (
                name, title, category, schedule, enabled,
                last_item_count, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                title=excluded.title,
                category=excluded.category,
                schedule=excluded.schedule,
                updated_at=excluded.updated_at
            """,
            (name, title, category, schedule, 1 if enabled_by_default else 0, now, now),
        )


def list_sources() -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            "SELECT * FROM sources ORDER BY category, name"
        ).fetchall()
        sources = []
        for row in rows:
            source = dict(row)
            if not source.get("enabled"):
                source["display_status"] = "disabled"
                source["display_error"] = ""
            else:
                source["display_status"] = source.get("last_status") or "pending"
                source["display_error"] = source.get("last_error") or ""
            sources.append(source)
        return sources


def set_source_enabled(name: str, enabled: bool) -> None:
    with connection() as conn:
        conn.execute(
            "UPDATE sources SET enabled=?, updated_at=? WHERE name=?",
            (1 if enabled else 0, utc_now(), name),
        )


def source_is_enabled(name: str) -> bool:
    with connection() as conn:
        row = conn.execute(
            "SELECT enabled FROM sources WHERE name=?", (name,)
        ).fetchone()
        return bool(row and row["enabled"])


def create_run(source: str) -> int:
    with connection() as conn:
        cursor = conn.execute(
            "INSERT INTO runs (source, started_at, status, item_count) VALUES (?, ?, ?, ?)",
            (source, utc_now(), "running", 0),
        )
        return int(cursor.lastrowid)


def finish_run(run_id: int, source: str, status: str, item_count: int, error: str = "") -> None:
    now = utc_now()
    with connection() as conn:
        conn.execute(
            """
            UPDATE runs
            SET finished_at=?, status=?, item_count=?, error=?
            WHERE id=?
            """,
            (now, status, item_count, error, run_id),
        )
        conn.execute(
            """
            UPDATE sources
            SET last_run_at=?, last_status=?, last_error=?, last_item_count=?, updated_at=?
            WHERE name=?
            """,
            (now, status, error, item_count, now, source),
        )


def recover_interrupted_runs() -> int:
    now = utc_now()
    error = "run interrupted before completion"
    with connection() as conn:
        rows = conn.execute(
            "SELECT id, source FROM runs WHERE status='running'"
        ).fetchall()
        for row in rows:
            conn.execute(
                """
                UPDATE runs
                SET finished_at=?, status='orphaned', error=?
                WHERE id=?
                """,
                (now, error, row["id"]),
            )
            conn.execute(
                """
                UPDATE sources
                SET last_run_at=?, last_status='orphaned', last_error=?, updated_at=?
                WHERE name=?
                """,
                (now, error, now, row["source"]),
            )
        return len(rows)


def upsert_vulnerabilities(items: list[dict[str, Any]]) -> int:
    now = utc_now()
    changed = 0
    with connection() as conn:
        for item in items:
            item.update(extract_item_intel(item))
            dedupe_key = item.get("dedupe_key") or dedupe_key_for_item(item)
            item["dedupe_key"] = dedupe_key
            duplicate = _find_duplicate_row(conn, item)
            if duplicate is not None:
                _merge_duplicate_row(conn, duplicate, item, now)
                changed += 1
                continue
            cursor = conn.execute(
                """
                INSERT INTO vulnerabilities (
                    source, source_uid, title, severity, cve_id, aliases,
                    published_at, updated_at, description, url, product, raw,
                    cvss_score, cvss_version, cvss_vector,
                    poc_available, poc_url, poc_content,
                    exp_available, exp_url, exp_content,
                    dedupe_key, first_seen_at, last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, source_uid) DO UPDATE SET
                    title=excluded.title,
                    severity=excluded.severity,
                    cve_id=excluded.cve_id,
                    aliases=excluded.aliases,
                    published_at=excluded.published_at,
                    updated_at=excluded.updated_at,
                    description=excluded.description,
                    url=excluded.url,
                    product=excluded.product,
                    raw=excluded.raw,
                    cvss_score=excluded.cvss_score,
                    cvss_version=excluded.cvss_version,
                    cvss_vector=excluded.cvss_vector,
                    poc_available=excluded.poc_available,
                    poc_url=excluded.poc_url,
                    poc_content=excluded.poc_content,
                    exp_available=excluded.exp_available,
                    exp_url=excluded.exp_url,
                    exp_content=excluded.exp_content,
                    dedupe_key=excluded.dedupe_key,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    item["source"],
                    item["source_uid"],
                    item["title"],
                    item.get("severity"),
                    item.get("cve_id"),
                    json.dumps(item.get("aliases", []), ensure_ascii=False),
                    item.get("published_at"),
                    item.get("updated_at"),
                    item.get("description"),
                    item.get("url"),
                    item.get("product"),
                    json.dumps(item.get("raw", {}), ensure_ascii=False),
                    item.get("cvss_score"),
                    item.get("cvss_version") or "",
                    item.get("cvss_vector") or "",
                    1 if item.get("poc_available") else 0,
                    item.get("poc_url") or "",
                    item.get("poc_content") or "",
                    1 if item.get("exp_available") else 0,
                    item.get("exp_url") or "",
                    item.get("exp_content") or "",
                    dedupe_key,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT id FROM vulnerabilities WHERE source=? AND source_uid=?",
                (item["source"], item["source_uid"]),
            ).fetchone()
            if row is not None:
                _refresh_vulnerability_quality_conn(conn, int(row["id"]))
            changed += 1
    return changed


def upsert_products(items: list[dict[str, Any]]) -> int:
    now = utc_now()
    changed = 0
    with connection() as conn:
        for item in items:
            name = str(item.get("name") or item.get("product") or "").strip()
            if not name:
                continue
            key = product_key(name) or item.get("product_key")
            normalized = _normalize_product_text(name)
            conn.execute(
                """
                INSERT INTO products (
                    product_key, source, source_uid, name, normalized_name, url,
                    vulnerability_count, poc_count, first_seen_at, last_seen_at,
                    last_crawled_at, raw, vendor, merged_into_product_key, merge_note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(product_key) DO UPDATE SET
                    source=excluded.source,
                    source_uid=excluded.source_uid,
                    name=excluded.name,
                    normalized_name=excluded.normalized_name,
                    url=excluded.url,
                    vulnerability_count=excluded.vulnerability_count,
                    poc_count=CASE
                        WHEN excluded.poc_count > 0 THEN excluded.poc_count
                        ELSE products.poc_count
                    END,
                    last_seen_at=excluded.last_seen_at,
                    last_crawled_at=excluded.last_crawled_at,
                    raw=excluded.raw,
                    vendor=CASE
                        WHEN excluded.vendor <> '' THEN excluded.vendor
                        ELSE products.vendor
                    END,
                    merged_into_product_key=CASE
                        WHEN excluded.merged_into_product_key <> '' THEN excluded.merged_into_product_key
                        ELSE products.merged_into_product_key
                    END,
                    merge_note=CASE
                        WHEN excluded.merge_note <> '' THEN excluded.merge_note
                        ELSE products.merge_note
                    END
                """,
                (
                    key,
                    item.get("source") or "",
                    item.get("source_uid") or key,
                    name,
                    normalized,
                    item.get("url") or "",
                    int(item.get("vulnerability_count") or 0),
                    int(item.get("poc_count") or 0),
                    now,
                    now,
                    now,
                    json.dumps(item.get("raw") or {}, ensure_ascii=False),
                    item.get("vendor") or "",
                    item.get("merged_into_product_key") or "",
                    item.get("merge_note") or "",
                ),
            )
            changed += 1
    return changed


def list_products(
    *,
    source: str = "",
    query: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    clauses: list[str] = ["COALESCE(merged_into_product_key, '') = ''"]
    args: list[Any] = []
    if source:
        clauses.append("source = ?")
        args.append(source)
    if query:
        like = f"%{query}%"
        normalized_like = f"%{_normalize_product_text(query)}%"
        clauses.append(
            """
            (
                name LIKE ?
                OR normalized_name LIKE ?
                OR EXISTS (
                    SELECT 1 FROM product_aliases pa
                    WHERE pa.product_key = products.product_key
                      AND (pa.alias LIKE ? OR pa.normalized_alias LIKE ?)
                )
            )
            """
        )
        args.extend([like, normalized_like, like, normalized_like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS total FROM products {where}",
            args,
        ).fetchone()["total"]
        rows = conn.execute(
            f"""
            SELECT *
            FROM products
            {where}
            ORDER BY vulnerability_count DESC, name COLLATE NOCASE ASC
            LIMIT ? OFFSET ?
            """,
            [*args, limit, offset],
        ).fetchall()
        products = []
        for row in rows:
            product = _deserialize_product(dict(row))
            product["local_vulnerability_count"] = _product_link_count_conn(
                conn,
                str(product.get("product_key") or ""),
            )
            product["latest_vulnerabilities"] = _latest_product_vulnerabilities_conn(
                conn,
                str(product.get("product_key") or ""),
                str(product.get("name") or ""),
                limit=3,
            )
            product["aliases"] = _product_aliases_conn(
                conn,
                str(product.get("product_key") or ""),
            )[:6]
            product["merged_count"] = int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM products WHERE merged_into_product_key=?",
                    (str(product.get("product_key") or ""),),
                ).fetchone()["n"]
            )
            products.append(product)
    return {"total": total, "data": products}


def _deserialize_product(row: dict[str, Any]) -> dict[str, Any]:
    row["raw"] = _json_value(row.get("raw"), {})
    row["is_followed"] = is_product_followed(row.get("name") or "")
    row["vendor"] = row.get("vendor") or ""
    row["merged_into_product_key"] = row.get("merged_into_product_key") or ""
    row["merge_note"] = row.get("merge_note") or ""
    return row


def _latest_product_vulnerabilities_conn(
    conn: sqlite3.Connection,
    product_key_value: str,
    product: str,
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    name = str(product or "").strip()
    compact = _normalize_product_text(name)
    if not name or not compact:
        return []
    linked_rows = conn.execute(
        """
        SELECT v.id, v.title, v.severity, v.cve_id, v.url, v.source,
               v.published_at, v.updated_at, v.first_seen_at
        FROM product_vulnerabilities pv
        JOIN vulnerabilities v ON v.id = pv.vulnerability_id
        WHERE pv.product_key=?
        ORDER BY COALESCE(v.published_at, v.updated_at, v.first_seen_at) DESC, v.id DESC
        LIMIT ?
        """,
        (product_key_value, limit),
    ).fetchall()
    if linked_rows:
        return [_vulnerability_summary_from_row(row) for row in linked_rows]
    like = f"%{name}%"
    compact_like = f"%{compact}%"
    rows = conn.execute(
        """
        SELECT id, title, severity, cve_id, url, source, published_at, updated_at, first_seen_at
        FROM vulnerabilities
        WHERE product = ?
           OR title LIKE ?
           OR description LIKE ?
           OR REPLACE(REPLACE(LOWER(COALESCE(title, '')), ' ', ''), '　', '') LIKE ?
           OR REPLACE(REPLACE(LOWER(COALESCE(description, '')), ' ', ''), '　', '') LIKE ?
        ORDER BY COALESCE(published_at, updated_at, first_seen_at) DESC, id DESC
        LIMIT ?
        """,
        (name, like, like, compact_like, compact_like, limit),
    ).fetchall()
    return [_vulnerability_summary_from_row(row) for row in rows]


def _vulnerability_summary_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"] or "",
        "severity": row["severity"] or "unknown",
        "cve_id": row["cve_id"] or "",
        "url": row["url"] or "",
        "source": row["source"] or "",
        "published_at": row["published_at"] or row["updated_at"] or row["first_seen_at"] or "",
    }


def _product_link_count_conn(conn: sqlite3.Connection, product_key_value: str) -> int:
    if not product_key_value:
        return 0
    return int(
        conn.execute(
            "SELECT COUNT(*) AS n FROM product_vulnerabilities WHERE product_key=?",
            (product_key_value,),
        ).fetchone()["n"]
    )


def _canonical_product_key_conn(conn: sqlite3.Connection, product_key_value: str) -> str:
    key = str(product_key_value or "").strip()
    seen: set[str] = set()
    for _ in range(12):
        if not key or key in seen:
            return key
        seen.add(key)
        row = conn.execute(
            "SELECT merged_into_product_key FROM products WHERE product_key=?",
            (key,),
        ).fetchone()
        if row is None:
            return key
        target = str(row["merged_into_product_key"] or "").strip()
        if not target:
            return key
        key = target
    return key


def _product_row_by_key_conn(conn: sqlite3.Connection, product_key_value: str) -> sqlite3.Row | None:
    key = _canonical_product_key_conn(conn, product_key_value)
    if not key:
        return None
    return conn.execute("SELECT * FROM products WHERE product_key=?", (key,)).fetchone()


def _resolve_product_key_conn(conn: sqlite3.Connection, value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("product:"):
        return _canonical_product_key_conn(conn, text)
    normalized = _normalize_product_text(text)
    if not normalized:
        return ""
    alias = conn.execute(
        "SELECT product_key FROM product_aliases WHERE normalized_alias=? ORDER BY updated_at DESC LIMIT 1",
        (normalized,),
    ).fetchone()
    if alias is not None:
        return _canonical_product_key_conn(conn, str(alias["product_key"] or ""))
    row = conn.execute(
        """
        SELECT product_key
        FROM products
        WHERE normalized_name=?
          AND COALESCE(merged_into_product_key, '') = ''
        ORDER BY vulnerability_count DESC, name COLLATE NOCASE ASC
        LIMIT 1
        """,
        (normalized,),
    ).fetchone()
    if row is not None:
        return str(row["product_key"] or "")
    return product_key(text)


def _product_aliases_conn(conn: sqlite3.Connection, product_key_value: str) -> list[dict[str, Any]]:
    key = _canonical_product_key_conn(conn, product_key_value)
    rows = conn.execute(
        """
        SELECT *
        FROM product_aliases
        WHERE product_key=?
        ORDER BY vendor COLLATE NOCASE ASC, alias COLLATE NOCASE ASC
        """,
        (key,),
    ).fetchall()
    return [dict(row) for row in rows]


def add_product_alias(product_key_value: str, alias: str, vendor: str = "") -> dict[str, Any]:
    normalized = _normalize_product_text(alias)
    if not normalized:
        raise ValueError("alias is required")
    now = utc_now()
    with connection() as conn:
        key = _canonical_product_key_conn(conn, product_key_value)
        product = _product_row_by_key_conn(conn, key)
        if product is None:
            raise KeyError("product not found")
        conn.execute(
            """
            INSERT INTO product_aliases (
                product_key, alias, normalized_alias, vendor, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(product_key, normalized_alias) DO UPDATE SET
                alias=excluded.alias,
                vendor=excluded.vendor,
                updated_at=excluded.updated_at
            """,
            (
                key,
                str(alias or "").strip()[:160],
                normalized,
                str(vendor or "").strip()[:120],
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT *
            FROM product_aliases
            WHERE product_key=? AND normalized_alias=?
            """,
            (key, normalized),
        ).fetchone()
        return dict(row)


def delete_product_alias(alias_id: int) -> bool:
    with connection() as conn:
        cursor = conn.execute("DELETE FROM product_aliases WHERE id=?", (alias_id,))
        return cursor.rowcount > 0


def merge_products(target_product_key: str, source_values: list[str], note: str = "") -> dict[str, Any]:
    now = utc_now()
    merged: list[dict[str, Any]] = []
    with connection() as conn:
        target_key = _canonical_product_key_conn(conn, target_product_key)
        target_row = _product_row_by_key_conn(conn, target_key)
        if target_row is None:
            raise KeyError("target product not found")
        target_key = str(target_row["product_key"] or target_key)
        target_name = str(target_row["name"] or "")
        for source_value in source_values:
            source_key = _resolve_product_key_conn(conn, source_value)
            source_key = _canonical_product_key_conn(conn, source_key)
            if not source_key or source_key == target_key:
                continue
            source_row = conn.execute("SELECT * FROM products WHERE product_key=?", (source_key,)).fetchone()
            if source_row is None:
                continue
            source_name = str(source_row["name"] or "")
            if source_name:
                normalized = _normalize_product_text(source_name)
                if normalized:
                    conn.execute(
                        """
                        INSERT INTO product_aliases (
                            product_key, alias, normalized_alias, vendor, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(product_key, normalized_alias) DO UPDATE SET
                            alias=excluded.alias,
                            vendor=excluded.vendor,
                            updated_at=excluded.updated_at
                        """,
                        (
                            target_key,
                            source_name[:160],
                            normalized,
                            str(source_row["vendor"] or "")[:120],
                            now,
                            now,
                        ),
                    )
            for alias_row in conn.execute(
                "SELECT alias, normalized_alias, vendor FROM product_aliases WHERE product_key=?",
                (source_key,),
            ).fetchall():
                conn.execute(
                    """
                    INSERT INTO product_aliases (
                        product_key, alias, normalized_alias, vendor, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(product_key, normalized_alias) DO UPDATE SET
                        alias=excluded.alias,
                        vendor=excluded.vendor,
                        updated_at=excluded.updated_at
                    """,
                    (
                        target_key,
                        str(alias_row["alias"] or "")[:160],
                        str(alias_row["normalized_alias"] or ""),
                        str(alias_row["vendor"] or "")[:120],
                        now,
                        now,
                    ),
                )
            for relation in conn.execute(
                "SELECT * FROM product_vulnerabilities WHERE product_key=?",
                (source_key,),
            ).fetchall():
                vuln_id = int(relation["vulnerability_id"])
                existing = conn.execute(
                    """
                    SELECT confidence, source_count
                    FROM product_vulnerabilities
                    WHERE product_key=? AND vulnerability_id=?
                    """,
                    (target_key, vuln_id),
                ).fetchone()
                if existing is not None:
                    confidence = max(float(existing["confidence"] or 0), float(relation["confidence"] or 0))
                    source_count = max(int(existing["source_count"] or 1), int(relation["source_count"] or 1) + 1)
                    conn.execute(
                        """
                        UPDATE product_vulnerabilities
                        SET confidence=?,
                            evidence=?,
                            source_count=?,
                            updated_at=?
                        WHERE product_key=? AND vulnerability_id=?
                        """,
                        (
                            confidence,
                            f"{relation['evidence'] or ''}\n合并自：{source_name}".strip()[:1000],
                            source_count,
                            now,
                            target_key,
                            vuln_id,
                        ),
                    )
                    conn.execute(
                        "DELETE FROM product_vulnerabilities WHERE product_key=? AND vulnerability_id=?",
                        (source_key, vuln_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE product_vulnerabilities
                        SET product_key=?,
                            product_name=?,
                            match_method=CASE
                                WHEN match_method='' THEN 'merged_product'
                                ELSE match_method
                            END,
                            evidence=?,
                            evidence_type='merged',
                            source_count=source_count + 1,
                            updated_at=?
                        WHERE product_key=? AND vulnerability_id=?
                        """,
                        (
                            target_key,
                            target_name,
                            f"{relation['evidence'] or ''}\n合并自：{source_name}".strip()[:1000],
                            now,
                            source_key,
                            vuln_id,
                        ),
                    )
            conn.execute(
                """
                UPDATE vulnerabilities
                SET product=CASE WHEN product=? THEN ? ELSE product END,
                    product_match_method=CASE
                        WHEN product_match_method='' THEN 'merged_product'
                        ELSE product_match_method
                    END,
                    product_resolved_at=?
                WHERE product=?
                """,
                (source_name, target_name, now, source_name),
            )
            followed = conn.execute(
                "SELECT * FROM followed_products WHERE product_key=?",
                (source_key,),
            ).fetchone()
            if followed is not None:
                conn.execute(
                    """
                    INSERT INTO followed_products (
                        product_key, product, created_at, updated_at,
                        last_matched_at, last_analysis_vulnerability_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(product_key) DO UPDATE SET
                        updated_at=excluded.updated_at,
                        last_matched_at=COALESCE(excluded.last_matched_at, followed_products.last_matched_at),
                        last_analysis_vulnerability_id=COALESCE(
                            excluded.last_analysis_vulnerability_id,
                            followed_products.last_analysis_vulnerability_id
                        )
                    """,
                    (
                        target_key,
                        target_name,
                        followed["created_at"],
                        now,
                        followed["last_matched_at"],
                        followed["last_analysis_vulnerability_id"],
                    ),
                )
            conn.execute("DELETE FROM followed_products WHERE product_key=?", (source_key,))
            conn.execute(
                """
                UPDATE products
                SET merged_into_product_key=?,
                    merge_note=?,
                    last_seen_at=?,
                    last_crawled_at=?
                WHERE product_key=?
                """,
                (target_key, str(note or "")[:500], now, now, source_key),
            )
            merged.append(
                {
                    "product_key": source_key,
                    "name": source_name,
                    "merged_into_product_key": target_key,
                }
            )
        _refresh_product_counts_conn(conn, target_key)
        detail = _product_detail_conn(conn, target_key)
        return {"target": detail, "merged": merged}


def product_duplicate_candidates(limit: int = 30) -> list[dict[str, Any]]:
    with connection() as conn:
        return _product_duplicate_candidates_conn(conn, limit=limit)


def normalize_product_catalog(*, auto_merge: bool = True, merge_limit: int = 200) -> dict[str, Any]:
    now = utc_now()
    normalized_products = 0
    normalized_aliases = 0
    deleted_aliases = 0
    with connection() as conn:
        product_rows = conn.execute(
            """
            SELECT product_key, name, normalized_name
            FROM products
            """
        ).fetchall()
        for row in product_rows:
            normalized = _normalize_product_text(str(row["name"] or ""))
            if normalized and normalized != str(row["normalized_name"] or ""):
                conn.execute(
                    "UPDATE products SET normalized_name=? WHERE product_key=?",
                    (normalized, row["product_key"]),
                )
                normalized_products += 1

        alias_rows = conn.execute(
            """
            SELECT id, product_key, alias, normalized_alias
            FROM product_aliases
            ORDER BY id ASC
            """
        ).fetchall()
        for row in alias_rows:
            alias_id = int(row["id"])
            product_key_value = str(row["product_key"] or "")
            normalized = _normalize_product_text(str(row["alias"] or ""))
            if not normalized:
                conn.execute("DELETE FROM product_aliases WHERE id=?", (alias_id,))
                deleted_aliases += 1
                continue
            duplicate = conn.execute(
                """
                SELECT id
                FROM product_aliases
                WHERE product_key=?
                  AND normalized_alias=?
                  AND id<>?
                LIMIT 1
                """,
                (product_key_value, normalized, alias_id),
            ).fetchone()
            if duplicate is not None:
                conn.execute("DELETE FROM product_aliases WHERE id=?", (alias_id,))
                deleted_aliases += 1
                continue
            if normalized != str(row["normalized_alias"] or ""):
                conn.execute(
                    "UPDATE product_aliases SET normalized_alias=?, updated_at=? WHERE id=?",
                    (normalized, now, alias_id),
                )
                normalized_aliases += 1

        _seed_common_product_aliases(conn)
        candidates = _product_duplicate_candidates_conn(conn, limit=merge_limit)

    merged_groups = 0
    merged_products = 0
    merge_results: list[dict[str, Any]] = []
    if auto_merge:
        for group in candidates[: max(0, min(int(merge_limit), 1000))]:
            source_keys = [str(item.get("product_key") or "") for item in group.get("sources", [])]
            source_keys = [key for key in source_keys if key]
            if not source_keys:
                continue
            result = merge_products(
                str(group["target"]["product_key"]),
                source_keys,
                "产品库规范化：同义别名或精确归一化重复",
            )
            merged_count = len(result.get("merged") or [])
            if merged_count:
                merged_groups += 1
                merged_products += merged_count
                merge_results.append(
                    {
                        "normalized_name": group["normalized_name"],
                        "target": result.get("target", {}),
                        "merged": result.get("merged", []),
                    }
                )
        with connection() as conn:
            alias_candidates = _product_alias_duplicate_candidates_conn(
                conn,
                limit=merge_limit,
            )
        for group in alias_candidates[: max(0, min(int(merge_limit), 1000))]:
            source_keys = [str(item.get("product_key") or "") for item in group.get("sources", [])]
            source_keys = [key for key in source_keys if key]
            if not source_keys:
                continue
            result = merge_products(
                str(group["target"]["product_key"]),
                source_keys,
                "产品库规范化：别名命中已有产品",
            )
            merged_count = len(result.get("merged") or [])
            if merged_count:
                merged_groups += 1
                merged_products += merged_count
                merge_results.append(
                    {
                        "normalized_name": group["normalized_name"],
                        "target": result.get("target", {}),
                        "merged": result.get("merged", []),
                        "reason": group["reason"],
                    }
                )

    return {
        "status": "ok",
        "normalized_products": normalized_products,
        "normalized_aliases": normalized_aliases,
        "deleted_aliases": deleted_aliases,
        "merged_groups": merged_groups,
        "merged_products": merged_products,
        "merged": merge_results[:50],
        "remaining_duplicates": product_duplicate_candidates(limit=20),
    }


def _product_duplicate_candidates_conn(conn: sqlite3.Connection, *, limit: int = 30) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT product_key, name, normalized_name, source, vulnerability_count, poc_count,
               vendor, merged_into_product_key
        FROM products
        WHERE COALESCE(merged_into_product_key, '') = ''
          AND normalized_name <> ''
        """
    ).fetchall()
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        item = dict(row)
        normalized = str(item.get("normalized_name") or "").strip()
        if len(normalized) < 3 and not re.search(r"[\u4e00-\u9fff]", normalized):
            continue
        groups.setdefault(normalized, []).append(item)

    candidates: list[dict[str, Any]] = []
    for normalized, items in groups.items():
        if len(items) < 2:
            continue
        ranked = sorted(items, key=_product_merge_rank, reverse=True)
        target = ranked[0]
        sources = ranked[1:]
        candidates.append(
            {
                "normalized_name": normalized,
                "count": len(items),
                "total_vulnerability_count": sum(int(item.get("vulnerability_count") or 0) for item in items),
                "target": target,
                "sources": sources,
                "names": [str(item.get("name") or "") for item in ranked],
                "reason": "exact_normalized_name",
            }
        )
    candidates.sort(
        key=lambda item: (
            int(item.get("count") or 0),
            int(item.get("total_vulnerability_count") or 0),
        ),
        reverse=True,
    )
    return candidates[: max(1, min(int(limit), 200))]


def _product_alias_duplicate_candidates_conn(conn: sqlite3.Connection, *, limit: int = 30) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
            a.product_key AS target_key,
            target.name AS target_name,
            target.normalized_name AS target_normalized_name,
            target.source AS target_source,
            target.vulnerability_count AS target_vulnerability_count,
            target.poc_count AS target_poc_count,
            target.vendor AS target_vendor,
            a.alias,
            a.normalized_alias,
            source.product_key AS source_key,
            source.name AS source_name,
            source.normalized_name AS source_normalized_name,
            source.source AS source_source,
            source.vulnerability_count AS source_vulnerability_count,
            source.poc_count AS source_poc_count,
            source.vendor AS source_vendor
        FROM product_aliases a
        JOIN products target ON target.product_key=a.product_key
        JOIN products source
          ON source.normalized_name=a.normalized_alias
         AND source.product_key<>a.product_key
        WHERE COALESCE(target.merged_into_product_key, '') = ''
          AND COALESCE(source.merged_into_product_key, '') = ''
          AND a.normalized_alias <> ''
        ORDER BY target.name COLLATE NOCASE ASC, source.vulnerability_count DESC
        """
    ).fetchall()
    grouped: dict[str, dict[str, Any]] = {}
    seen_sources: set[tuple[str, str]] = set()
    for row in rows:
        target_key = str(row["target_key"] or "")
        source_key = str(row["source_key"] or "")
        if not target_key or not source_key or target_key == source_key:
            continue
        source_pair = (target_key, source_key)
        if source_pair in seen_sources:
            continue
        seen_sources.add(source_pair)
        group = grouped.setdefault(
            target_key,
            {
                "normalized_name": str(row["normalized_alias"] or ""),
                "target": {
                    "product_key": target_key,
                    "name": str(row["target_name"] or ""),
                    "normalized_name": str(row["target_normalized_name"] or ""),
                    "source": str(row["target_source"] or ""),
                    "vulnerability_count": int(row["target_vulnerability_count"] or 0),
                    "poc_count": int(row["target_poc_count"] or 0),
                    "vendor": str(row["target_vendor"] or ""),
                },
                "sources": [],
                "names": [str(row["target_name"] or "")],
                "reason": "alias_matches_existing_product",
            },
        )
        source_item = {
            "product_key": source_key,
            "name": str(row["source_name"] or ""),
            "normalized_name": str(row["source_normalized_name"] or ""),
            "source": str(row["source_source"] or ""),
            "vulnerability_count": int(row["source_vulnerability_count"] or 0),
            "poc_count": int(row["source_poc_count"] or 0),
            "vendor": str(row["source_vendor"] or ""),
            "matched_alias": str(row["alias"] or ""),
        }
        group["sources"].append(source_item)
        group["names"].append(source_item["name"])

    candidates = list(grouped.values())
    candidates.sort(
        key=lambda item: (
            len(item.get("sources") or []),
            sum(int(source.get("vulnerability_count") or 0) for source in item.get("sources", [])),
        ),
        reverse=True,
    )
    return candidates[: max(1, min(int(limit), 200))]


def _product_merge_rank(item: dict[str, Any]) -> tuple[int, int, int, int, int]:
    source = str(item.get("source") or "")
    name = str(item.get("name") or "")
    source_score = 3 if source == "biu_products" else 2 if source else 1
    if source == "vulnerability_match":
        source_score = 0
    chinese_score = 1 if re.search(r"[\u4e00-\u9fff]", name) else 0
    return (
        source_score,
        int(item.get("vulnerability_count") or 0),
        int(item.get("poc_count") or 0),
        chinese_score,
        -len(name),
    )


def _refresh_product_counts_conn(conn: sqlite3.Connection, product_key_value: str) -> None:
    key = _canonical_product_key_conn(conn, product_key_value)
    if not key:
        return
    stats = conn.execute(
        """
        SELECT
            COUNT(*) AS vulnerability_count,
            SUM(CASE WHEN v.poc_available=1 OR v.poc_content <> '' THEN 1 ELSE 0 END) AS poc_count
        FROM product_vulnerabilities pv
        JOIN vulnerabilities v ON v.id = pv.vulnerability_id
        WHERE pv.product_key=?
        """,
        (key,),
    ).fetchone()
    local_count = int(stats["vulnerability_count"] or 0)
    poc_count = int(stats["poc_count"] or 0)
    now = utc_now()
    conn.execute(
        """
        UPDATE products
        SET vulnerability_count=CASE
                WHEN vulnerability_count < ? OR source='vulnerability_match' THEN ?
                ELSE vulnerability_count
            END,
            poc_count=CASE WHEN poc_count < ? THEN ? ELSE poc_count END,
            last_seen_at=?,
            last_crawled_at=?
        WHERE product_key=?
        """,
        (local_count, local_count, poc_count, poc_count, now, now, key),
    )


def get_product_detail(product_key_value: str) -> dict[str, Any] | None:
    with connection() as conn:
        return _product_detail_conn(conn, product_key_value)


def _product_detail_conn(conn: sqlite3.Connection, product_key_value: str) -> dict[str, Any] | None:
    row = _product_row_by_key_conn(conn, product_key_value)
    if row is None:
        return None
    product = _deserialize_product(dict(row))
    key = str(product["product_key"])
    aliases = _product_aliases_conn(conn, key)
    merged_rows = conn.execute(
        """
        SELECT product_key, name, source, vulnerability_count, poc_count, merged_into_product_key, merge_note
        FROM products
        WHERE merged_into_product_key=?
        ORDER BY name COLLATE NOCASE ASC
        """,
        (key,),
    ).fetchall()
    severity_rows = conn.execute(
        """
        SELECT COALESCE(NULLIF(LOWER(v.severity), ''), 'unknown') AS severity, COUNT(*) AS count
        FROM product_vulnerabilities pv
        JOIN vulnerabilities v ON v.id = pv.vulnerability_id
        WHERE pv.product_key=?
        GROUP BY COALESCE(NULLIF(LOWER(v.severity), ''), 'unknown')
        ORDER BY count DESC
        """,
        (key,),
    ).fetchall()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
    date_expr = "substr(COALESCE(v.published_at, v.updated_at, v.first_seen_at), 1, 10)"
    trend_rows = conn.execute(
        f"""
        SELECT {date_expr} AS day, COUNT(*) AS count
        FROM product_vulnerabilities pv
        JOIN vulnerabilities v ON v.id = pv.vulnerability_id
        WHERE pv.product_key=?
          AND {date_expr} >= ?
        GROUP BY {date_expr}
        ORDER BY day ASC
        """,
        (key, cutoff),
    ).fetchall()
    latest_rows = conn.execute(
        """
        SELECT v.id, v.title, v.severity, v.cve_id, v.url, v.source,
               v.published_at, v.updated_at, v.first_seen_at
        FROM product_vulnerabilities pv
        JOIN vulnerabilities v ON v.id = pv.vulnerability_id
        WHERE pv.product_key=?
        ORDER BY COALESCE(v.published_at, v.updated_at, v.first_seen_at) DESC, v.id DESC
        LIMIT 20
        """,
        (key,),
    ).fetchall()
    poc_exp_rows = conn.execute(
        """
        SELECT v.id, v.title, v.severity, v.cve_id, v.url, v.source,
               v.published_at, v.updated_at, v.first_seen_at,
               v.poc_available, v.poc_url, v.exp_available, v.exp_url
        FROM product_vulnerabilities pv
        JOIN vulnerabilities v ON v.id = pv.vulnerability_id
        WHERE pv.product_key=?
          AND (
            v.poc_available=1 OR v.exp_available=1
            OR v.poc_content <> '' OR v.exp_content <> ''
          )
        ORDER BY COALESCE(v.published_at, v.updated_at, v.first_seen_at) DESC, v.id DESC
        LIMIT 10
        """,
        (key,),
    ).fetchall()
    evidence_rows = conn.execute(
        """
        SELECT match_method, evidence_type, COUNT(*) AS count, AVG(confidence) AS avg_confidence
        FROM product_vulnerabilities
        WHERE product_key=?
        GROUP BY match_method, evidence_type
        ORDER BY count DESC
        LIMIT 12
        """,
        (key,),
    ).fetchall()
    product["aliases"] = aliases
    product["merged_products"] = [dict(item) for item in merged_rows]
    product["local_vulnerability_count"] = _product_link_count_conn(conn, key)
    product["severity_distribution"] = [dict(item) for item in severity_rows]
    product["trend"] = [dict(item) for item in trend_rows]
    product["latest_vulnerabilities"] = [_vulnerability_summary_from_row(row) for row in latest_rows]
    product["latest_poc_exp"] = [_product_poc_exp_summary(row) for row in poc_exp_rows]
    product["evidence_summary"] = [
        {
            **dict(row),
            "avg_confidence": round(float(row["avg_confidence"] or 0), 3),
        }
        for row in evidence_rows
    ]
    product["canonical_product_key"] = key
    product["is_followed"] = is_product_followed(product.get("name") or "")
    return product


def _product_poc_exp_summary(row: sqlite3.Row) -> dict[str, Any]:
    payload = _vulnerability_summary_from_row(row)
    payload["poc_available"] = bool(row["poc_available"])
    payload["poc_url"] = row["poc_url"] or ""
    payload["exp_available"] = bool(row["exp_available"])
    payload["exp_url"] = row["exp_url"] or ""
    return payload


def align_products_for_items(items: list[dict[str, Any]], *, max_matches: int = 3) -> dict[str, int]:
    """Directly link freshly ingested vulnerabilities to product catalog rows."""
    if not items:
        return {"checked": 0, "linked": 0, "created_products": 0}
    with connection() as conn:
        candidates = _product_candidates_conn(conn)
        checked = linked = created_products = 0
        for item in items:
            vuln = _vulnerability_row_for_item_conn(conn, item)
            if vuln is None:
                continue
            checked += 1
            matches = _direct_product_matches(dict(vuln), candidates, max_matches=max_matches)
            if not matches:
                continue
            if not item.get("product"):
                item["product"] = matches[0]["name"]
            for match in matches:
                result = _link_vulnerability_to_product_conn(
                    conn,
                    int(vuln["id"]),
                    match["name"],
                    match["method"],
                    match["confidence"],
                    match["evidence"],
                    raw={"resolver": "direct", "match": match},
                )
                linked += int(result["linked"])
                created_products += int(result["created_product"])
        return {"checked": checked, "linked": linked, "created_products": created_products}


def align_vulnerability_products(*, limit: int = 0, only_unlinked: bool = True) -> dict[str, int]:
    """Backfill product links for existing vulnerability rows."""
    with connection() as conn:
        candidates = _product_candidates_conn(conn)
        where = ""
        if only_unlinked:
            where = """
            WHERE NOT EXISTS (
                SELECT 1 FROM product_vulnerabilities pv
                WHERE pv.vulnerability_id = vulnerabilities.id
            )
            """
        limit_sql = "LIMIT ?" if limit and limit > 0 else ""
        args: list[Any] = [limit] if limit and limit > 0 else []
        rows = conn.execute(
            f"""
            SELECT *
            FROM vulnerabilities
            {where}
            ORDER BY COALESCE(published_at, updated_at, first_seen_at) DESC, id DESC
            {limit_sql}
            """,
            args,
        ).fetchall()
        checked = linked = created_products = 0
        for row in rows:
            checked += 1
            for match in _direct_product_matches(dict(row), candidates, max_matches=3):
                result = _link_vulnerability_to_product_conn(
                    conn,
                    int(row["id"]),
                    match["name"],
                    match["method"],
                    match["confidence"],
                    match["evidence"],
                    raw={"resolver": "direct_backfill", "match": match},
                )
                linked += int(result["linked"])
                created_products += int(result["created_product"])
        return {"checked": checked, "linked": linked, "created_products": created_products}


def ai_product_resolution_candidates(*, limit: int = 5) -> list[dict[str, Any]]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="seconds")
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT v.*
            FROM vulnerabilities v
            WHERE (
                EXISTS (
                    SELECT 1
                    FROM alerts a
                    WHERE a.vulnerability_id = v.id
                      AND a.status='new'
                )
                OR v.first_seen_at >= ?
                OR COALESCE(v.product_match_method, '') = ''
              )
              AND NOT EXISTS (
                SELECT 1 FROM product_vulnerabilities pv
                WHERE pv.vulnerability_id = v.id
              )
              AND COALESCE(v.product_match_method, '') NOT IN (
                'deepseek_flash',
                'deepseek_flash_empty',
                'deepseek_product_pro',
                'deepseek_product_empty'
              )
            ORDER BY COALESCE(
                (
                    SELECT MAX(a.created_at)
                    FROM alerts a
                    WHERE a.vulnerability_id = v.id
                ),
                v.first_seen_at
            ) DESC, v.id DESC
            LIMIT ?
            """,
            (cutoff, max(1, min(limit, 50))),
        ).fetchall()
        return [_deserialize_vuln(dict(row)) for row in rows]


def product_catalog_candidates_for_terms(terms: list[str], *, limit: int = 30) -> list[dict[str, Any]]:
    normalized_terms = [
        normalized
        for value in terms
        for normalized in [_normalize_product_text(value)]
        if normalized
    ]
    if not normalized_terms:
        return []
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT product_key, name, normalized_name, source, vulnerability_count, poc_count, vendor
            FROM products
            WHERE COALESCE(merged_into_product_key, '') = ''
            """
        ).fetchall()
        alias_rows = conn.execute(
            """
            SELECT product_key, alias, normalized_alias, vendor
            FROM product_aliases
            WHERE normalized_alias <> ''
            """
        ).fetchall()
    aliases_by_product: dict[str, list[dict[str, Any]]] = {}
    for alias in alias_rows:
        aliases_by_product.setdefault(str(alias["product_key"] or ""), []).append(dict(alias))

    scored: list[tuple[float, dict[str, Any]]] = []
    for row in rows:
        item = dict(row)
        product_norm = str(item.get("normalized_name") or "")
        alias_items = aliases_by_product.get(str(item.get("product_key") or ""), [])
        candidate_norms = [product_norm, *[str(alias.get("normalized_alias") or "") for alias in alias_items]]
        score = 0.0
        for term in normalized_terms:
            for candidate in candidate_norms:
                if not candidate:
                    continue
                if term == candidate:
                    score = max(score, 1.0)
                elif term in candidate or candidate in term:
                    ratio = min(len(term), len(candidate)) / max(len(term), len(candidate))
                    score = max(score, 0.62 + ratio * 0.25)
        if score <= 0:
            continue
        item["aliases"] = alias_items[:8]
        item["match_score"] = round(score, 3)
        scored.append((score, item))
    scored.sort(
        key=lambda pair: (
            pair[0],
            int(pair[1].get("vulnerability_count") or 0),
            int(pair[1].get("poc_count") or 0),
        ),
        reverse=True,
    )
    return [item for _score, item in scored[: max(1, min(int(limit), 100))]]


def link_vulnerability_to_product(
    vulnerability_id: int,
    product_name: str,
    match_method: str,
    confidence: float,
    evidence: str,
    raw: dict[str, Any] | None = None,
) -> dict[str, int]:
    with connection() as conn:
        return _link_vulnerability_to_product_conn(
            conn,
            vulnerability_id,
            product_name,
            match_method,
            confidence,
            evidence,
            raw=raw,
        )


def mark_product_resolution_attempt(
    vulnerability_id: int,
    method: str,
    evidence: str,
    raw: dict[str, Any] | None = None,
) -> None:
    now = utc_now()
    raw_json = json.dumps(raw or {}, ensure_ascii=False)
    with connection() as conn:
        row = conn.execute("SELECT raw FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone()
        if row is None:
            return
        vuln_raw = _json_value(row["raw"], {})
        if isinstance(vuln_raw, dict):
            attempts = list(vuln_raw.get("_product_resolution_attempts") or [])
            attempts.append({"method": method, "evidence": evidence[:1000], "raw": raw or {}, "at": now})
            vuln_raw["_product_resolution_attempts"] = attempts[-10:]
            raw_json = json.dumps(vuln_raw, ensure_ascii=False)
        conn.execute(
            """
            UPDATE vulnerabilities
            SET product_match_method=?,
                product_match_evidence=?,
                product_resolved_at=?,
                raw=?
            WHERE id=?
            """,
            (method, evidence[:1000], now, raw_json, vulnerability_id),
        )


def _vulnerability_row_for_item_conn(conn: sqlite3.Connection, item: dict[str, Any]) -> sqlite3.Row | None:
    source = str(item.get("source") or "")
    source_uid = str(item.get("source_uid") or "")
    dedupe_key = str(item.get("dedupe_key") or dedupe_key_for_item(item) or "")
    row = None
    if source and source_uid:
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE source=? AND source_uid=?",
            (source, source_uid),
        ).fetchone()
    if row is None and dedupe_key:
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE dedupe_key=? ORDER BY id ASC LIMIT 1",
            (dedupe_key,),
        ).fetchone()
    return row


def _product_candidates_conn(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    product_rows = conn.execute(
        """
        SELECT product_key, name, normalized_name, vulnerability_count, '' AS alias_name
        FROM products
        WHERE normalized_name <> ''
          AND COALESCE(merged_into_product_key, '') = ''
        ORDER BY LENGTH(normalized_name) DESC, vulnerability_count DESC
        """
    ).fetchall()
    alias_rows = conn.execute(
        """
        SELECT p.product_key,
               p.name,
               pa.normalized_alias AS normalized_name,
               p.vulnerability_count,
               pa.alias AS alias_name
        FROM product_aliases pa
        JOIN products p ON p.product_key = pa.product_key
        WHERE pa.normalized_alias <> ''
          AND COALESCE(p.merged_into_product_key, '') = ''
        ORDER BY LENGTH(pa.normalized_alias) DESC, p.vulnerability_count DESC
        """
    ).fetchall()
    seen: set[tuple[str, str]] = set()
    candidates: list[dict[str, Any]] = []
    for row in [*product_rows, *alias_rows]:
        item = dict(row)
        marker = (str(item.get("product_key") or ""), str(item.get("normalized_name") or ""))
        if marker in seen:
            continue
        seen.add(marker)
        candidates.append(item)
    return candidates


def _direct_product_matches(
    row: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    max_matches: int = 3,
) -> list[dict[str, Any]]:
    title = str(row.get("title") or "")
    description = str(row.get("description") or "")
    product = str(row.get("product") or "")
    text = " ".join([title, description, product])
    compact_text = _normalize_product_text(text)
    lower_text = text.lower()
    labels = _product_labels_from_vulnerability(row)
    by_norm = {str(item.get("normalized_name") or ""): item for item in candidates}
    matches: dict[str, dict[str, Any]] = {}

    def add(name: str, method: str, confidence: float, evidence: str, key: str = "") -> None:
        cleaned = _clean_product_label(name)
        if not cleaned:
            return
        product_key_value = key or product_key(cleaned)
        if not product_key_value:
            return
        current = matches.get(product_key_value)
        payload = {
            "product_key": product_key_value,
            "name": cleaned,
            "method": method,
            "confidence": round(float(confidence), 3),
            "evidence": evidence[:1000],
        }
        if current is None or (payload["confidence"], len(payload["name"])) > (
            current["confidence"],
            len(current["name"]),
        ):
            matches[product_key_value] = payload

    if product:
        add(product, "source_product_field", 0.9, f"源产品字段：{product}")

    for label in labels:
        normalized = _normalize_product_text(label)
        if not normalized:
            continue
        exact = by_norm.get(normalized)
        if exact:
            add(exact["name"], "direct_product_field", 0.98, f"源产品字段/标题直接命中产品库：{label}", exact["product_key"])
            continue
        add(label, "inferred_product_label", 0.74, f"从漏洞标题或源产品字段提取：{label}")

    for candidate in candidates:
        normalized = str(candidate.get("normalized_name") or "")
        name = str(candidate.get("name") or "")
        if not _candidate_can_match(normalized, name):
            continue
        if _candidate_appears(normalized, name, compact_text, lower_text):
            score = 0.86 + min(len(normalized), 60) / 600
            if lower_text.strip().startswith(name.lower()):
                score = max(score, 0.94)
            add(name, "title_catalog_match", min(score, 0.96), f"标题/描述包含产品库名称：{name}", candidate["product_key"])

    ranked = sorted(
        matches.values(),
        key=lambda item: (item["confidence"], len(_normalize_product_text(item["name"]))),
        reverse=True,
    )
    return ranked[:max(1, max_matches)]


def _link_vulnerability_to_product_conn(
    conn: sqlite3.Connection,
    vulnerability_id: int,
    product_name: str,
    match_method: str,
    confidence: float,
    evidence: str,
    *,
    raw: dict[str, Any] | None = None,
) -> dict[str, int]:
    name = _clean_product_label(product_name)
    key = product_key(name)
    if not key:
        return {"linked": 0, "created_product": 0}
    normalized_name = _normalize_product_text(name)
    alias_row = conn.execute(
        "SELECT product_key FROM product_aliases WHERE normalized_alias=? ORDER BY updated_at DESC LIMIT 1",
        (normalized_name,),
    ).fetchone()
    if alias_row is not None:
        canonical_key = _canonical_product_key_conn(conn, str(alias_row["product_key"] or ""))
        canonical_row = conn.execute("SELECT name FROM products WHERE product_key=?", (canonical_key,)).fetchone()
        if canonical_row is not None:
            key = canonical_key
            name = str(canonical_row["name"] or name)
    now = utc_now()
    existing_product = conn.execute("SELECT product_key FROM products WHERE product_key=?", (key,)).fetchone()
    vuln = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone()
    if vuln is None:
        return {"linked": 0, "created_product": 0}
    conn.execute(
        """
        INSERT INTO products (
            product_key, source, source_uid, name, normalized_name, url,
            vulnerability_count, poc_count, first_seen_at, last_seen_at,
            last_crawled_at, raw, vendor, merged_into_product_key, merge_note
        )
        VALUES (?, 'vulnerability_match', ?, ?, ?, '', 1, ?, ?, ?, ?, ?, '', '', '')
        ON CONFLICT(product_key) DO UPDATE SET
            name=CASE
                WHEN products.source='vulnerability_match' THEN excluded.name
                ELSE products.name
            END,
            normalized_name=CASE
                WHEN products.source='vulnerability_match' THEN excluded.normalized_name
                ELSE products.normalized_name
            END,
            last_seen_at=excluded.last_seen_at,
            last_crawled_at=excluded.last_crawled_at
        """,
        (
            key,
            key,
            name,
            _normalize_product_text(name),
            1 if vuln["poc_available"] else 0,
            now,
            now,
            now,
            json.dumps({"source": "vulnerability_match"}, ensure_ascii=False),
        ),
    )
    cursor = conn.execute(
        """
        INSERT INTO product_vulnerabilities (
            product_key, vulnerability_id, product_name, match_method,
            confidence, evidence, created_at, updated_at, raw, evidence_type, source_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'direct', 1)
        ON CONFLICT(product_key, vulnerability_id) DO UPDATE SET
            product_name=excluded.product_name,
            match_method=excluded.match_method,
            confidence=CASE
                WHEN excluded.confidence >= product_vulnerabilities.confidence
                THEN excluded.confidence
                ELSE product_vulnerabilities.confidence
            END,
            evidence=excluded.evidence,
            updated_at=excluded.updated_at,
            raw=excluded.raw
        """,
        (
            key,
            vulnerability_id,
            name,
            match_method,
            max(0.0, min(float(confidence or 0), 1.0)),
            evidence[:1000],
            now,
            now,
            json.dumps(raw or {}, ensure_ascii=False),
        ),
    )
    local_count = _product_link_count_conn(conn, key)
    poc_count = int(
        conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM product_vulnerabilities pv
            JOIN vulnerabilities v ON v.id = pv.vulnerability_id
            WHERE pv.product_key=? AND v.poc_available=1
            """,
            (key,),
        ).fetchone()["n"]
    )
    conn.execute(
        """
        UPDATE products
        SET vulnerability_count=CASE
                WHEN source='vulnerability_match' THEN ?
                WHEN vulnerability_count < ? THEN ?
                ELSE vulnerability_count
            END,
            poc_count=CASE WHEN poc_count < ? THEN ? ELSE poc_count END,
            last_seen_at=?,
            last_crawled_at=?
        WHERE product_key=?
        """,
        (local_count, local_count, local_count, poc_count, poc_count, now, now, key),
    )
    existing_confidence = vuln["product_match_confidence"]
    should_update_product = (
        not str(vuln["product"] or "").strip()
        or len(str(vuln["product"] or "")) > 120
        or existing_confidence is None
        or float(existing_confidence or 0) <= float(confidence or 0)
    )
    conn.execute(
        f"""
        UPDATE vulnerabilities
        SET product=CASE WHEN ?=1 THEN ? ELSE product END,
            product_match_method=?,
            product_match_confidence=?,
            product_match_evidence=?,
            product_resolved_at=?
        WHERE id=?
        """,
        (
            1 if should_update_product else 0,
            name,
            match_method,
            max(0.0, min(float(confidence or 0), 1.0)),
            evidence[:1000],
            now,
            vulnerability_id,
        ),
    )
    _refresh_vulnerability_quality_conn(conn, vulnerability_id)
    return {"linked": 1 if cursor.rowcount else 0, "created_product": 0 if existing_product else 1}


def _product_labels_from_vulnerability(row: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    labels.extend(_structured_product_labels(row))
    product = str(row.get("product") or "")
    if product:
        labels.extend(_split_product_labels(product))
    title = str(row.get("title") or "")
    description = str(row.get("description") or "")
    for text in [title, description]:
        labels.extend(_product_labels_from_text(text))
    asset = _asset_from_title(title)
    if asset:
        labels.append(asset)
    return _unique_list([_clean_product_label(label) for label in labels])[:8]


NOISY_PRODUCT_NORMALIZED = {
    "asecurityvulnerabilityhas",
    "asecurityflawhas",
    "avulnerabilitywas",
    "avulnerabilityhas",
    "avulnerabilityin",
    "avulnerabilityinthethe",
    "avulnerabilitybypassof",
    "avulnerabilitywasdetermined",
    "avulnerabilitywasfound",
    "avulnerabilityinthethe",
    "auseafterfreevulnerabilitywas",
    "aclientsideauthorizationflaw",
    "animproper",
    "anissuewas",
    "thisissue",
    "affectedbythisissue",
    "affectedelement",
    "affectedfunction",
    "component",
    "handler",
    "file",
    "function",
    "argument",
    "parameter",
    "security",
    "vulnerability",
    "vulnerabilityinthethe",
    "vulnerabilityinoracle",
    "vulnerabilityinoraclefusion",
    "securityvulnerability",
    "securityflaw",
    "issue",
    "thefile",
    "ofthefile",
    "cgihandler",
    "missingauthorizationvulnerabilityin",
    "impropercontroloffilename",
    "multipleproducts",
    "author",
    "by",
    "director",
    "versions",
    "authorizationbypass",
    "crosssiterequestforgerycsrf",
    "deserializationofuntrusteddata",
    "incorrectprivilegeassignmentvulnerability",
    "pathtraversalvulnerability",
    "bythisvulnerability",
    "bythisvulnerabilityisan",
    "bythisvulnerabilityisthe",
    "systemsThisvulnerabilitycouldaffect",
    "functionr7webssecurityhandlerfunction",
    "functionupdatestoryboardurl",
    "arbitrarycodeexecution",
}


NOISY_PRODUCT_PREFIXES = [
    "a security vulnerability has",
    "a security flaw has",
    "a vulnerability was",
    "a vulnerability has",
    "an improper ",
    "an issue was",
    "a vulnerability in ",
    "a vulnerability bypass ",
    "a use-after-free vulnerability ",
    "a client-side authorization flaw",
    "vulnerability in the ",
    "vulnerability in oracle ",
    "missing authorization vulnerability",
    "improper control of ",
    "incorrect privilege assignment vulnerability",
    "cross-site request forgery",
    "deserialization of untrusted data",
    "path traversal",
    "authorization bypass",
    "this issue ",
    "affected by this issue",
    "by this vulnerability",
    "the affected element",
    "the affected function",
    "function ",
    "ghsl-",
    "systems. this vulnerability",
]


def _structured_product_labels(row: dict[str, Any]) -> list[str]:
    raw = _json_value(row.get("raw"), {})
    if not isinstance(raw, dict):
        return []
    labels: list[str] = []

    for key in ["product", "product_name", "packageName", "package_name", "module", "component"]:
        value = raw.get(key)
        if isinstance(value, str):
            labels.extend(_split_product_labels(value))
    vendor = str(raw.get("vendorProject") or raw.get("vendor") or raw.get("manufacturer") or "").strip()
    product = str(raw.get("product") or raw.get("productName") or raw.get("packageName") or "").strip()
    if vendor and product:
        labels.append(f"{vendor} {product}")
        labels.append(product)

    affected = raw.get("affected") or raw.get("affected_products") or []
    if isinstance(affected, dict):
        affected = [affected]
    if isinstance(affected, list):
        for item in affected[:12]:
            if not isinstance(item, dict):
                continue
            vendor = str(item.get("vendor") or item.get("vendor_name") or "").strip()
            product = str(
                item.get("product")
                or item.get("packageName")
                or item.get("package")
                or item.get("name")
                or ""
            ).strip()
            if vendor and product:
                labels.append(f"{vendor} {product}")
            if product:
                labels.append(product)

    project = raw.get("project")
    if isinstance(project, str):
        labels.append(project)
    elif isinstance(project, list):
        for item in project[:12]:
            if isinstance(item, str):
                labels.append(item)
            elif isinstance(item, dict):
                labels.extend(
                    str(item.get(key) or "").strip()
                    for key in ["name", "full_name", "packageName", "purl"]
                    if item.get(key)
                )

    for criteria in _walk_raw_strings(raw):
        if "cpe:2.3:" not in criteria:
            continue
        parsed = _product_label_from_cpe(criteria)
        if parsed:
            labels.extend(parsed)
    return labels


def _walk_raw_strings(value: Any, *, limit: int = 300) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, str):
            found.append(node)
        elif isinstance(node, dict):
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return found


def _product_label_from_cpe(value: str) -> list[str]:
    # cpe:2.3:a:vendor:product:version:...
    match = re.search(r"cpe:2\.3:[aho]:([^:]+):([^:]+):", value)
    if not match:
        return []
    vendor = _clean_cpe_token(match.group(1))
    product = _clean_cpe_token(match.group(2))
    labels = []
    if vendor and product and vendor.lower() not in {"*", "-", "n/a"}:
        labels.append(f"{vendor} {product}")
    if product:
        labels.append(product)
    return labels


def _clean_cpe_token(value: str) -> str:
    text = str(value or "").replace("\\:", ":").replace("_", " ").strip()
    if text in {"*", "-", "ANY"}:
        return ""
    return re.sub(r"\s+", " ", text)


def _split_product_labels(value: str) -> list[str]:
    labels: list[str] = []
    for part in re.split(r"[,，、;\n]+", value or "")[:12]:
        text = part.strip()
        if not text:
            continue
        if ">" in text:
            left, right = text.rsplit(">", 1)
            labels.append(right)
            if len(left) <= 40:
                labels.append(left)
        else:
            labels.append(text)
    return labels


def _product_labels_from_text(value: str) -> list[str]:
    text = re.sub(r"^CVE-\d{4}-\d{4,}[:：\\s-]*", "", value or "", flags=re.I).strip()
    labels: list[str] = []
    for pattern in [
        r"\bin\s+([A-Za-z0-9][A-Za-z0-9_.:/-]+(?:\s+[A-Za-z0-9][A-Za-z0-9_.:/()-]+){0,5})\s+(?:up to|before|through|prior to|versions?|version|\d)",
        r"\bin\s+([A-Za-z0-9][A-Za-z0-9_.:/-]+(?:\s+[A-Za-z0-9][A-Za-z0-9_.:/()-]+){0,5})[,.]\s+(?:this|the|affected|executing)",
        r"\bin\s+([A-Z][A-Za-z0-9_.-]+(?:\s+[A-Z0-9][A-Za-z0-9_.-]+){0,4})(?:\s+(?:up to|before|through|prior to|versions?|version|\d))",
        r"\b(?:detected|identified|discovered|found)\s+in\s+([A-Z][A-Za-z0-9_.-]+(?:\s+[A-Z0-9][A-Za-z0-9_.-]+){0,4})",
        r"\baffects\s+(?:the\s+)?([A-Z][A-Za-z0-9_.-]+(?:\s+[A-Z0-9][A-Za-z0-9_.-]+){0,4})",
    ]:
        match = re.search(pattern, text, flags=re.I)
        if match:
            labels.append(match.group(1))
    return labels


def _clean_product_label(value: str) -> str:
    text = str(value or "").strip(" \t\r\n-:：,，.;；()（）[]【】")
    text = re.sub(r"CVE-\d{4}-\d{4,}", "", text, flags=re.I).strip()
    text = _strip_product_versions(text)
    text = re.split(
        r"\s+(?:up to|before|through|prior to|versions?|version|exists|contains|存在|漏洞|安全漏洞|高危漏洞|严重漏洞)\b",
        text,
        maxsplit=1,
        flags=re.I,
    )[0].strip(" \t\r\n-:：,，.;；()（）[]【】")
    text = re.sub(r"\s+(?:of|in|from)\s+the\s+(?:file|function|component|argument)\b.*$", "", text, flags=re.I).strip()
    if _is_noisy_product_label(text) or len(text) > 120:
        return ""
    compact = _normalize_product_text(text)
    if len(compact) < 2:
        return ""
    noisy = {"cve", "vulnerability", "security", "漏洞", "安全漏洞", "unknown", "none"}
    if compact in noisy or compact in NOISY_PRODUCT_NORMALIZED:
        return ""
    return text


def _strip_product_versions(value: str) -> str:
    parts = str(value or "").split()
    kept: list[str] = []
    for part in parts:
        token = part.strip(" ,;:()[]")
        if re.fullmatch(r"v?\d+(?:[._-]\d+){1,}[A-Za-z0-9._-]*", token, flags=re.I):
            break
        if re.fullmatch(r"\d{4,}", token):
            break
        kept.append(part)
    return " ".join(kept).strip()


def _is_noisy_product_label(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    compact = _normalize_product_text(text)
    if compact in NOISY_PRODUCT_NORMALIZED:
        return True
    if any(text.startswith(prefix) for prefix in NOISY_PRODUCT_PREFIXES):
        return True
    if re.match(r"^(?:the\s+)?(?:file|function|component|argument|parameter|handler)\s+", text):
        return True
    words = re.findall(r"[a-z0-9]+", text)
    if words and all(word in {"a", "an", "the", "this", "issue", "security", "vulnerability", "flaw", "has", "was", "been", "found", "detected", "discovered", "file", "function", "component", "argument"} for word in words):
        return True
    return False


def _candidate_can_match(normalized: str, name: str) -> bool:
    if not normalized or not name:
        return False
    if normalized in NOISY_PRODUCT_NORMALIZED or _is_noisy_product_label(name):
        return False
    if len(normalized) >= 4:
        return True
    return bool(re.search(r"[\u4e00-\u9fff]", name)) and len(normalized) >= 2


def _candidate_appears(normalized: str, name: str, compact_text: str, lower_text: str) -> bool:
    if not normalized or normalized not in compact_text:
        return False
    ascii_name = re.fullmatch(r"[A-Za-z0-9_.-]+", name or "") is not None
    if ascii_name and len(normalized) <= 3:
        return re.search(rf"(?<![a-z0-9_.-]){re.escape(name.lower())}(?![a-z0-9_.-])", lower_text) is not None
    return True


def _find_duplicate_row(conn: sqlite3.Connection, item: dict[str, Any]) -> dict[str, Any] | None:
    same = conn.execute(
        "SELECT * FROM vulnerabilities WHERE source=? AND source_uid=?",
        (item["source"], item["source_uid"]),
    ).fetchone()
    if same is not None:
        return None
    dedupe_key = item.get("dedupe_key") or ""
    if not dedupe_key:
        return None
    duplicate = conn.execute(
        """
        SELECT *
        FROM vulnerabilities
        WHERE dedupe_key=?
        ORDER BY id ASC
        LIMIT 1
        """,
        (dedupe_key,),
    ).fetchone()
    return None if duplicate is None else dict(duplicate)


def _merge_duplicate_row(
    conn: sqlite3.Connection,
    duplicate: dict[str, Any],
    item: dict[str, Any],
    now: str,
) -> None:
    existing_raw = json.loads(duplicate.get("raw") or "{}")
    merged_raw = _merge_raw_reports(existing_raw, item)
    existing_aliases = json.loads(duplicate.get("aliases") or "[]")
    aliases = _unique_list([*existing_aliases, *(item.get("aliases") or []), item.get("cve_id")])
    existing_intel = _row_intel(duplicate)
    incoming_intel = extract_item_intel(item)
    cvss = _choose_cvss(existing_intel, incoming_intel)
    poc = _choose_artifact(existing_intel, incoming_intel, "poc")
    exp = _choose_artifact(existing_intel, incoming_intel, "exp")
    conn.execute(
        """
        UPDATE vulnerabilities
        SET
            severity=?,
            cve_id=?,
            aliases=?,
            updated_at=COALESCE(?, updated_at),
            description=COALESCE(description, ?),
            url=COALESCE(url, ?),
            product=COALESCE(product, ?),
            raw=?,
            cvss_score=?,
            cvss_version=?,
            cvss_vector=?,
            poc_available=?,
            poc_url=?,
            poc_content=?,
            exp_available=?,
            exp_url=?,
            exp_content=?,
            last_seen_at=?
        WHERE id=?
        """,
        (
            _max_severity(duplicate.get("severity"), item.get("severity")),
            duplicate.get("cve_id") or item.get("cve_id") or "",
            json.dumps(aliases, ensure_ascii=False),
            item.get("updated_at"),
            item.get("description"),
            item.get("url"),
            item.get("product"),
            json.dumps(merged_raw, ensure_ascii=False),
            cvss.get("cvss_score"),
            cvss.get("cvss_version") or "",
            cvss.get("cvss_vector") or "",
            1 if poc.get("available") else 0,
            poc.get("url") or "",
            poc.get("content") or "",
            1 if exp.get("available") else 0,
            exp.get("url") or "",
            exp.get("content") or "",
            now,
            duplicate["id"],
        ),
    )
    _refresh_vulnerability_quality_conn(conn, int(duplicate["id"]))


def _merge_raw_reports(existing_raw: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    reports = list(existing_raw.get("_source_reports") or [])
    report_key = f"{item.get('source')}:{item.get('source_uid')}"
    if not any(report.get("key") == report_key for report in reports):
        reports.append(
            {
                "key": report_key,
                "source": item.get("source"),
                "source_uid": item.get("source_uid"),
                "title": item.get("title"),
                "url": item.get("url"),
                "product": item.get("product"),
                "cve_id": item.get("cve_id"),
                "severity": item.get("severity"),
                "raw": item.get("raw") or {},
            }
        )
    existing_raw["_source_reports"] = reports[-20:]
    return existing_raw


def _unique_list(values: list[Any]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
    return result


def _row_intel(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "cvss_score": row.get("cvss_score"),
        "cvss_version": row.get("cvss_version") or "",
        "cvss_vector": row.get("cvss_vector") or "",
        "poc_available": bool(row.get("poc_available")),
        "poc_url": row.get("poc_url") or "",
        "poc_content": row.get("poc_content") or "",
        "exp_available": bool(row.get("exp_available")),
        "exp_url": row.get("exp_url") or "",
        "exp_content": row.get("exp_content") or "",
    }


def _choose_cvss(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_score = _score_value(left.get("cvss_score"))
    right_score = _score_value(right.get("cvss_score"))
    if right_score is None:
        return left
    if left_score is None:
        return right
    left_priority = _cvss_priority(str(left.get("cvss_version") or ""))
    right_priority = _cvss_priority(str(right.get("cvss_version") or ""))
    return right if (right_priority, right_score) > (left_priority, left_score) else left


def _choose_artifact(left: dict[str, Any], right: dict[str, Any], kind: str) -> dict[str, Any]:
    available = bool(left.get(f"{kind}_available") or right.get(f"{kind}_available"))
    return {
        "available": available,
        "url": left.get(f"{kind}_url") or right.get(f"{kind}_url") or "",
        "content": left.get(f"{kind}_content") or right.get(f"{kind}_content") or "",
    }


def _max_severity(left: str | None, right: str | None) -> str:
    order = {"none": 0, "unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    left_text = str(left or "unknown").lower()
    right_text = str(right or "unknown").lower()
    return right_text if order.get(right_text, 0) > order.get(left_text, 0) else left_text


def list_vulnerabilities(
    *,
    source: str = "",
    severity: str = "",
    query: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    clauses: list[str] = []
    args: list[Any] = []
    if source:
        clauses.append("source = ?")
        args.append(source)
    if severity:
        clauses.append("severity = ?")
        args.append(severity)
    if query:
        like = f"%{query}%"
        clauses.append("(title LIKE ? OR cve_id LIKE ? OR aliases LIKE ? OR product LIKE ?)")
        args.extend([like, like, like, like])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    partition = "CASE WHEN dedupe_key <> '' THEN dedupe_key ELSE 'row:' || id END"
    with connection() as conn:
        total = conn.execute(
            f"""
            WITH ranked AS (
                SELECT id, ROW_NUMBER() OVER (
                    PARTITION BY {partition}
                    ORDER BY COALESCE(published_at, updated_at, first_seen_at) DESC, id DESC
                ) AS rn
                FROM vulnerabilities
                {where}
            )
            SELECT COUNT(*) AS total FROM ranked WHERE rn=1
            """,
            args,
        ).fetchone()["total"]
        rows = conn.execute(
            f"""
            WITH ranked AS (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY {partition}
                    ORDER BY COALESCE(published_at, updated_at, first_seen_at) DESC, id DESC
                ) AS rn
                FROM vulnerabilities
                {where}
            )
            SELECT * FROM ranked
            WHERE rn=1
            ORDER BY COALESCE(published_at, updated_at, first_seen_at) DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*args, limit, offset],
        ).fetchall()
    return {
        "total": total,
        "data": [_deserialize_vuln(dict(row)) for row in rows],
    }


def _deserialize_vuln(row: dict[str, Any]) -> dict[str, Any]:
    row.pop("rn", None)
    row["aliases"] = json.loads(row.get("aliases") or "[]")
    row["raw"] = json.loads(row.get("raw") or "{}")
    row["analysis_sources"] = _json_value(row.get("analysis_sources"), [])
    row["analysis_raw"] = _json_value(row.get("analysis_raw"), {})
    extracted = _extract_vulnerability_intel(row["raw"])
    row["cvss_score"] = row.get("cvss_score") if row.get("cvss_score") is not None else extracted["cvss_score"]
    row["cvss_version"] = row.get("cvss_version") or extracted["cvss_version"]
    row["cvss_vector"] = row.get("cvss_vector") or extracted["cvss_vector"]
    row["poc_available"], row["poc_url"], row["poc_content"] = _normalize_artifact_fields(
        "poc",
        bool(row.get("poc_available") or extracted["poc_available"]),
        row.get("poc_url") or extracted["poc_url"],
        row.get("poc_content") or extracted["poc_content"],
    )
    row["exp_available"], row["exp_url"], row["exp_content"] = _normalize_artifact_fields(
        "exp",
        bool(row.get("exp_available") or extracted["exp_available"]),
        row.get("exp_url") or extracted["exp_url"],
        row.get("exp_content") or extracted["exp_content"],
    )
    row["dedupe_key"] = row.get("dedupe_key") or dedupe_key_for_item(row)
    row["analysis_status"] = row.get("analysis_status") or "idle"
    row["analysis_error"] = row.get("analysis_error") or ""
    row["analysis_source_url"] = row.get("analysis_source_url") or ""
    row["analysis_source_local_path"] = row.get("analysis_source_local_path") or ""
    row["analysis_source_title"] = row.get("analysis_source_title") or ""
    row["analysis_source_archive_path"] = row.get("analysis_source_archive_path") or ""
    row["analysis_source_retained_until"] = row.get("analysis_source_retained_until") or ""
    row["analysis_source_cleaned_at"] = row.get("analysis_source_cleaned_at") or ""
    row["analysis_summary"] = row.get("analysis_summary") or ""
    row["analysis_run_id"] = row.get("analysis_run_id") or ""
    row["analysis_model"] = row.get("analysis_model") or ""
    row["analysis_trigger"] = row.get("analysis_trigger") or ""
    row["analysis_confidence"] = _analysis_confidence(row["analysis_raw"])
    row["source_credibility"] = _source_credibility(row["analysis_sources"])
    row["analysis_feedback"] = get_analysis_feedback(int(row["id"])) if row.get("id") else None
    row["analysis_priority"] = int(row.get("analysis_priority") or 50)
    row["analysis_cancel_requested"] = bool(row.get("analysis_cancel_requested"))
    row["analysis_failure_reason"] = row.get("analysis_failure_reason") or ""
    row["product_key"] = product_key_for_item(row)
    row["is_followed"] = is_product_followed(row.get("product") or _asset_from_title(row.get("title") or ""))
    row["product_match_method"] = row.get("product_match_method") or ""
    row["product_match_confidence"] = (
        None if row.get("product_match_confidence") is None else float(row.get("product_match_confidence") or 0)
    )
    row["product_match_evidence"] = row.get("product_match_evidence") or ""
    row["product_resolved_at"] = row.get("product_resolved_at") or ""
    row["github_evidence_checked_at"] = row.get("github_evidence_checked_at") or ""
    row["github_evidence_count"] = int(row.get("github_evidence_count") or 0)
    row["github_evidence_max_score"] = (
        None if row.get("github_evidence_max_score") is None else float(row.get("github_evidence_max_score") or 0)
    )
    row["github_evidence_summary"] = _json_value(row.get("github_evidence_summary"), {})
    row["github_evidence"] = (
        list_github_evidence(int(row["id"]), limit=8)
        if row.get("id") and row["github_evidence_count"]
        else []
    )
    row["quality_raw"] = _json_value(row.get("quality_raw"), {})
    if row.get("quality_score") is None:
        quality = compute_quality_score(row)
        row["quality_score"] = quality["score"]
        row["quality_level"] = quality["level"]
        row["quality_reason"] = quality["reason"]
        row["quality_raw"] = quality["raw"]
    else:
        row["quality_score"] = float(row.get("quality_score") or 0)
        row["quality_level"] = row.get("quality_level") or "low"
        row["quality_reason"] = row.get("quality_reason") or ""
    return row


def _analysis_confidence(raw: Any) -> float | None:
    payload = raw if isinstance(raw, dict) else _json_value(raw, {})
    candidates: list[Any] = []
    if isinstance(payload, dict):
        candidates.append(payload.get("confidence"))
        claude_output = payload.get("claude_output")
        if isinstance(claude_output, dict):
            candidates.append(claude_output.get("confidence"))
            candidates.append(claude_output.get("analysis_confidence"))
        parsed = payload.get("parsed")
        if isinstance(parsed, dict):
            candidates.append(parsed.get("confidence"))
    for value in candidates:
        if value is None or isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            score = float(value)
        else:
            match = re.search(r"\d+(?:\.\d+)?", str(value))
            if not match:
                continue
            score = float(match.group(0))
        if score > 1:
            score = score / 100
        return round(max(0.0, min(score, 1.0)), 3)
    return None


def _source_credibility(sources: Any) -> dict[str, Any]:
    items = sources if isinstance(sources, list) else _json_value(sources, [])
    if not isinstance(items, list):
        items = []
    high_trust = 0
    medium_trust = 0
    domains: set[str] = set()
    for source in items:
        if not isinstance(source, dict):
            continue
        url = str(source.get("url") or source.get("local_path") or source.get("title") or "").lower()
        domain = _domain_from_url(url)
        if domain:
            domains.add(domain)
        if any(token in url for token in ["nvd.nist.gov", "cisa.gov", "github.com", "gitlab.com", "sourceware.org"]):
            high_trust += 1
        elif any(token in url for token in [".gov", ".edu", "vendor", "advisory", "security"]):
            medium_trust += 1
    count = len(items)
    score = min(1.0, (count * 0.12) + (high_trust * 0.22) + (medium_trust * 0.12))
    label = "高" if score >= 0.75 else "中" if score >= 0.45 else "低"
    return {
        "score": round(score, 3),
        "label": label,
        "source_count": count,
        "trusted_source_count": high_trust,
        "domains": sorted(domains)[:8],
    }


def _domain_from_url(value: str) -> str:
    match = re.search(r"https?://([^/\s]+)", value or "", flags=re.I)
    if not match:
        return ""
    return match.group(1).lower().removeprefix("www.")


def _json_value(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not value:
        return fallback
    try:
        return json.loads(str(value))
    except (TypeError, json.JSONDecodeError):
        return fallback


def extract_item_intel(item: dict[str, Any]) -> dict[str, Any]:
    extracted = _extract_vulnerability_intel(item.get("raw") or {})
    poc_available, poc_url, poc_content = _normalize_artifact_fields(
        "poc",
        bool(item.get("poc_available") or extracted["poc_available"]),
        item.get("poc_url") or extracted["poc_url"],
        item.get("poc_content") or extracted["poc_content"],
    )
    exp_available, exp_url, exp_content = _normalize_artifact_fields(
        "exp",
        bool(item.get("exp_available") or extracted["exp_available"]),
        item.get("exp_url") or extracted["exp_url"],
        item.get("exp_content") or extracted["exp_content"],
    )
    return {
        "cvss_score": item.get("cvss_score") if item.get("cvss_score") is not None else extracted["cvss_score"],
        "cvss_version": item.get("cvss_version") or extracted["cvss_version"],
        "cvss_vector": item.get("cvss_vector") or extracted["cvss_vector"],
        "poc_available": poc_available,
        "poc_url": poc_url,
        "poc_content": poc_content,
        "exp_available": exp_available,
        "exp_url": exp_url,
        "exp_content": exp_content,
        "dedupe_key": item.get("dedupe_key") or dedupe_key_for_item(item),
    }


def _extract_vulnerability_intel(raw: dict[str, Any]) -> dict[str, Any]:
    cvss = _best_cvss(raw)
    poc = _artifact_info(raw, "poc")
    exp = _artifact_info(raw, "exp")
    return {
        "cvss_score": cvss.get("score"),
        "cvss_version": cvss.get("version", ""),
        "cvss_vector": cvss.get("vector", ""),
        "poc_available": poc["available"],
        "poc_url": poc["url"],
        "poc_content": poc["content"],
        "exp_available": exp["available"],
        "exp_url": exp["url"],
        "exp_content": exp["content"],
    }


def _normalize_artifact_fields(
    kind: str,
    available: bool,
    url: Any,
    content: Any,
) -> tuple[bool, str, str]:
    kind = str(kind or "").lower()
    url_text = str(url or "").strip()
    content_text = str(content or "").strip()
    has_url = bool(url_text)
    has_content = _artifact_content_is_substantive(kind, content_text)
    normalized_available = bool((available and (has_url or has_content)) or has_url or has_content)
    if not normalized_available and _artifact_placeholder_note(kind, content_text):
        content_text = ""
    return normalized_available, url_text, content_text


def _artifact_content_is_substantive(kind: str, content: Any) -> bool:
    text = str(content or "").strip()
    if not text:
        return False
    if text.startswith("http://") or text.startswith("https://"):
        return _looks_like_artifact_url(text, kind)
    compact = _compact_text(text)
    marker_values = {
        "poc",
        "proof",
        "proofofconcept",
        "proof_of_concept",
        "functional",
        "unproven",
        "exploit",
        "exploitavailable",
        "exp",
        "true",
        "1",
    }
    if compact in marker_values:
        return False
    if _artifact_placeholder_note(kind, text):
        return False
    lower = text.lower()
    substantive_markers = [
        "```",
        "curl ",
        "wget ",
        "python ",
        "import requests",
        "requests.",
        "http/1.",
        "get /",
        "post /",
        "put /",
        "delete /",
        "nuclei",
        "template",
        "payload",
        "request",
        "response",
        "检测逻辑",
        "验证步骤",
        "复现步骤",
        "利用条件",
        "缓解建议",
        "修复建议",
    ]
    if any(marker in lower for marker in substantive_markers):
        return True
    return len(text) >= 120


def _artifact_placeholder_note(kind: str, content: Any) -> bool:
    text = str(content or "").strip()
    if not text:
        return False
    label = "POC" if str(kind or "").lower() == "poc" else "EXP"
    compact = _compact_text(text)
    placeholder_tokens = [
        f"源数据包含{label.lower()}标记",
        f"源数据标记存在{label.lower()}但未提供公开内容",
        f"源字段poc_available标记存在{label.lower()}",
        f"源字段exp_available标记存在{label.lower()}",
        f"源字段is_poc标记存在{label.lower()}",
        f"源字段is_exp标记存在{label.lower()}",
        f"源字段has_poc标记存在{label.lower()}",
        f"源字段has_exp标记存在{label.lower()}",
        "biu.life页面标记poc已公开",
    ]
    if any(token in compact for token in placeholder_tokens):
        return True
    return compact in {"proofofconcept", "proof_of_concept", "functional", "unproven", "exploitavailable"}


def _best_cvss(raw: Any) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []

    def walk(value: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            cvss_data = value.get("cvssData")
            if isinstance(cvss_data, dict):
                score = _score_value(cvss_data.get("baseScore"))
                if score is not None:
                    version = str(cvss_data.get("version") or _version_from_path(path))
                    candidates.append(
                        {
                            "score": score,
                            "version": version,
                            "vector": str(cvss_data.get("vectorString") or ""),
                            "priority": _cvss_priority(version),
                        }
                    )

            for key in ["cvss_score", "cvssScore", "cvss3", "cvss2"]:
                score = _score_value(value.get(key))
                if score is not None:
                    vector = str(value.get("cvss_vector") or value.get("vectorString") or "")
                    version = _version_from_vector(vector)
                    if not version:
                        version = "3.x" if key.lower() == "cvss3" else "2.0" if key.lower() == "cvss2" else _version_from_path(path)
                    candidates.append(
                        {
                            "score": score,
                            "version": version,
                            "vector": vector,
                            "priority": _cvss_priority(version),
                        }
                    )

            base_score = _score_value(value.get("baseScore"))
            if base_score is not None and any("cvss" in part.lower() for part in path):
                version = str(value.get("version") or _version_from_path(path))
                candidates.append(
                    {
                        "score": base_score,
                        "version": version,
                        "vector": str(value.get("vectorString") or ""),
                        "priority": _cvss_priority(version),
                    }
                )

            for key, child in value.items():
                walk(child, (*path, str(key)))
        elif isinstance(value, list):
            for child in value:
                walk(child, path)

    walk(raw)
    if not candidates:
        return {}
    candidates.sort(key=lambda item: (item["priority"], item["score"]), reverse=True)
    winner = candidates[0]
    return {
        "score": winner["score"],
        "version": winner["version"],
        "vector": winner["vector"],
    }


def _score_value(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        match = re.search(r"\d+(?:\.\d+)?", value)
        if not match:
            return None
        score = float(match.group(0))
    else:
        return None
    return score if 0 <= score <= 10 else None


def _version_from_path(path: tuple[str, ...]) -> str:
    text = ".".join(path).lower()
    if "v40" in text or "4.0" in text:
        return "4.0"
    if "v31" in text or "3.1" in text:
        return "3.1"
    if "v30" in text or "3.0" in text:
        return "3.0"
    if "v2" in text or "2.0" in text:
        return "2.0"
    return ""


def _version_from_vector(vector: str) -> str:
    match = re.match(r"CVSS:(\d+(?:\.\d+)?)", vector or "", flags=re.I)
    return match.group(1) if match else ""


def _cvss_priority(version: str) -> int:
    text = (version or "").lower()
    if text.startswith("4"):
        return 40
    if text.startswith("3.1"):
        return 31
    if text.startswith("3"):
        return 30
    if text.startswith("2"):
        return 20
    return 10


def _artifact_info(raw: Any, kind: str) -> dict[str, Any]:
    found = False
    urls: list[str] = []
    evidence: list[str] = []
    marker_notes: list[str] = []
    kind = kind.lower()
    key_names = (
        {"poc", "poc_exp", "poc_exploit", "is_poc", "ispoc", "poc_exist", "pocexist", "has_poc", "poc_available"}
        if kind == "poc"
        else {"exp", "poc_exp", "poc_exploit", "is_exp", "has_exp", "exp_exist", "expexist", "exploit_available"}
    )
    value_keys = (
        {"poc_id", "poc_disclosure_date", "poc_url", "poc_link"}
        if kind == "poc"
        else {"exp_id", "exp_disclosure_date", "exp_url", "exp_link", "exploit_url", "exploit_link"}
    )
    negative_tokens = (
        {"无poc", "nopoc", "nopoc", "nopoc", "nopoc", "nopoc", "nopoc", "no poc", "nopoc"}
        if kind == "poc"
        else {"无exp", "noexp", "no exp", "无exploit"}
    )
    positive_tokens = (
        {"有poc", "pocavailable", "proof_of_concept", "proofofconcept", "cvepoc"}
        if kind == "poc"
        else {"有exp", "expavailable", "exploitavailable", "exploit-db", "exploitdb"}
    )

    def mark(value: bool = True, note: str = "") -> None:
        nonlocal found
        if value:
            found = True
            if note:
                evidence.append(note)

    def remember_marker(note: str = "") -> None:
        if note:
            marker_notes.append(note)

    def walk(value: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
                if key_text in key_names:
                    if isinstance(child, str) and child.startswith("http"):
                        urls.append(child)
                        mark(True, _artifact_note(kind, key, child))
                    elif _artifact_content_is_substantive(kind, child):
                        mark(True, _artifact_note(kind, key, child))
                    elif _truthy(child):
                        remember_marker(_artifact_note(kind, key, child))
                elif key_text in value_keys:
                    if isinstance(child, str) and child.startswith("http"):
                        urls.append(child)
                        mark(True, _artifact_note(kind, key, child))
                    elif _artifact_content_is_substantive(kind, child):
                        mark(True, _artifact_note(kind, key, child))
                    elif child:
                        remember_marker(_artifact_note(kind, key, child))
                elif key_text in {"url", "link"} and isinstance(child, str) and _looks_like_artifact_url(child, kind):
                    urls.append(child)
                    mark(True, f"{kind.upper()} 相关链接：{child}")
                walk(child, (*path, str(key)))
        elif isinstance(value, list):
            for child in value:
                walk(child, path)
        elif isinstance(value, str):
            text = _compact_text(value)
            if any(_compact_text(token) in text for token in negative_tokens):
                return
            if value.startswith("http") and _looks_like_artifact_url(value, kind):
                urls.append(value)
                mark(True, f"{kind.upper()} 相关链接：{value}")

    walk(raw)
    if found and not evidence:
        evidence.extend(marker_notes[:3])
    return {
        "available": found,
        "url": urls[0] if urls else "",
        "content": "\n".join(_unique_list(evidence))[:4000],
    }


def _artifact_note(kind: str, key: Any, value: Any) -> str:
    if isinstance(value, bool):
        return f"源字段 {key} 标记存在 {kind.upper()}。"
    if isinstance(value, (int, float)):
        return f"源字段 {key}={value} 标记存在 {kind.upper()}。"
    text = str(value).strip()
    if not text:
        return ""
    return f"源字段 {key}: {text[:800]}"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, str):
        text = _compact_text(value)
        return bool(text) and text not in {"0", "false", "否", "无", "none", "null", "nopoc", "无poc"}
    return bool(value)


def _compact_text(value: str) -> str:
    return re.sub(r"\s+", "", value).lower()


def _looks_like_artifact_url(value: str, kind: str) -> bool:
    text = value.lower()
    common = ["packetstormsecurity", "0day.today"]
    poc_tokens = ["poc", "proof-of-concept", "proof_of_concept"]
    exp_tokens = ["exploit", "exploit-db.com", "exploitdb"]
    tokens = common + (poc_tokens if kind == "poc" else exp_tokens)
    return any(token in text for token in tokens)


def dedupe_key_for_item(item: dict[str, Any]) -> str:
    cve = _first_cve(item)
    if cve:
        return f"cve:{cve}"
    asset = _normalize_dedupe_text(item.get("product") or _asset_from_title(item.get("title") or ""))
    content = _normalize_dedupe_text(
        " ".join(
            str(item.get(key) or "")
            for key in ["title", "description"]
        )
    )
    if asset and content:
        return f"asset-content:{_short_hash(asset + '|' + content)}"
    if content:
        return f"content:{_short_hash(content)}"
    return f"source:{item.get('source')}:{item.get('source_uid')}"


def product_label_for_item(item: dict[str, Any]) -> str:
    return str(item.get("product") or _asset_from_title(item.get("title") or "")).strip()


def product_key_for_item(item: dict[str, Any]) -> str:
    return product_key(product_label_for_item(item))


def product_key(product: str) -> str:
    normalized = _normalize_product_text(product)
    if not normalized:
        return ""
    return f"product:{_short_hash(normalized)}"


SOURCE_ARCHIVE_UPDATE_COLUMNS = {
    "origin",
    "filename",
    "content_type",
    "size_bytes",
    "sha256",
    "status",
    "minio_status",
    "minio_bucket",
    "minio_object_key",
    "minio_url",
    "minio_error",
    "local_path",
    "extracted_path",
    "product_hint",
    "suggested_product_name",
    "suggested_vendor",
    "suggested_aliases",
    "product_name",
    "product_key",
    "product_confirmed",
    "architecture_summary",
    "function_summary",
    "product_evidence",
    "analysis_model",
    "analysis_raw",
    "error",
    "analyzed_at",
    "confirmed_at",
}


def create_source_archive(payload: dict[str, Any]) -> dict[str, Any]:
    now = utc_now()
    suggested_aliases = payload.get("suggested_aliases") or []
    analysis_raw = payload.get("analysis_raw") or {}
    with connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO source_archives (
                origin, filename, content_type, size_bytes, sha256, status,
                minio_status, minio_bucket, minio_object_key, minio_url, minio_error,
                local_path, extracted_path, product_hint, suggested_product_name,
                suggested_vendor, suggested_aliases, product_name, product_key,
                product_confirmed, architecture_summary, function_summary,
                product_evidence, analysis_model, analysis_raw, error,
                created_at, updated_at, analyzed_at, confirmed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("origin") or "user_upload",
                payload.get("filename") or "",
                payload.get("content_type") or "",
                int(payload.get("size_bytes") or 0),
                payload.get("sha256") or "",
                payload.get("status") or "queued",
                payload.get("minio_status") or "pending",
                payload.get("minio_bucket") or "",
                payload.get("minio_object_key") or "",
                payload.get("minio_url") or "",
                payload.get("minio_error") or "",
                payload.get("local_path") or "",
                payload.get("extracted_path") or "",
                payload.get("product_hint") or "",
                payload.get("suggested_product_name") or "",
                payload.get("suggested_vendor") or "",
                json.dumps(suggested_aliases, ensure_ascii=False),
                payload.get("product_name") or "",
                payload.get("product_key") or "",
                1 if payload.get("product_confirmed") else 0,
                payload.get("architecture_summary") or "",
                payload.get("function_summary") or "",
                payload.get("product_evidence") or "",
                payload.get("analysis_model") or "",
                json.dumps(analysis_raw, ensure_ascii=False),
                payload.get("error") or "",
                payload.get("created_at") or now,
                payload.get("updated_at") or now,
                payload.get("analyzed_at") or None,
                payload.get("confirmed_at") or None,
            ),
        )
        row = conn.execute(
            "SELECT * FROM source_archives WHERE id=?",
            (cursor.lastrowid,),
        ).fetchone()
        return _deserialize_source_archive(dict(row))


def update_source_archive(archive_id: int, **fields: Any) -> dict[str, Any] | None:
    values: list[Any] = []
    assignments: list[str] = []
    for key, value in fields.items():
        if key not in SOURCE_ARCHIVE_UPDATE_COLUMNS:
            continue
        if key in {"suggested_aliases"} and not isinstance(value, str):
            value = json.dumps(value or [], ensure_ascii=False)
        elif key in {"analysis_raw"} and not isinstance(value, str):
            value = json.dumps(value or {}, ensure_ascii=False)
        elif key == "product_confirmed":
            value = 1 if value else 0
        assignments.append(f"{key}=?")
        values.append(value)
    if not assignments:
        return get_source_archive(archive_id)
    assignments.append("updated_at=?")
    values.append(utc_now())
    values.append(archive_id)
    with connection() as conn:
        conn.execute(
            f"UPDATE source_archives SET {', '.join(assignments)} WHERE id=?",
            values,
        )
        row = conn.execute("SELECT * FROM source_archives WHERE id=?", (archive_id,)).fetchone()
        return None if row is None else _deserialize_source_archive(dict(row))


def get_source_archive(archive_id: int) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute("SELECT * FROM source_archives WHERE id=?", (archive_id,)).fetchone()
        return None if row is None else _deserialize_source_archive(dict(row))


def delete_source_archive_record(archive_id: int) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute("SELECT * FROM source_archives WHERE id=?", (archive_id,)).fetchone()
        if row is None:
            return None
        conn.execute("DELETE FROM source_archives WHERE id=?", (archive_id,))
        return _deserialize_source_archive(dict(row))


def list_source_archives(
    *,
    status: str = "",
    query: str = "",
    limit: int = 30,
    offset: int = 0,
) -> dict[str, Any]:
    clauses: list[str] = []
    args: list[Any] = []
    if status:
        clauses.append("status=?")
        args.append(status)
    if query:
        like = f"%{query}%"
        clauses.append(
            """
            (
                filename LIKE ?
                OR product_hint LIKE ?
                OR suggested_product_name LIKE ?
                OR product_name LIKE ?
                OR sha256 LIKE ?
            )
            """
        )
        args.extend([like, like, like, like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) AS total FROM source_archives {where}",
                args,
            ).fetchone()["total"]
        )
        rows = conn.execute(
            f"""
            SELECT *
            FROM source_archives
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*args, limit, offset],
        ).fetchall()
        count_rows = conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM source_archives
            GROUP BY status
            """
        ).fetchall()
    return {
        "total": total,
        "counts": {str(row["status"] or "unknown"): int(row["count"] or 0) for row in count_rows},
        "data": [_deserialize_source_archive(dict(row)) for row in rows],
    }


def confirm_source_archive_product(
    archive_id: int,
    *,
    product_name: str = "",
    product_key_value: str = "",
    vendor: str = "",
    aliases: list[str] | None = None,
) -> dict[str, Any] | None:
    archive = get_source_archive(archive_id)
    if not archive:
        return None
    name = str(product_name or "").strip()
    key = str(product_key_value or "").strip()
    if key:
        detail = get_product_detail(key)
        if not detail:
            raise KeyError("product not found")
        name = str(detail.get("name") or name).strip()
        key = str(detail.get("canonical_product_key") or detail.get("product_key") or key)
    if not name:
        raise ValueError("product_name is required")
    if not key:
        upsert_products(
            [
                {
                    "name": name,
                    "source": "source_archives",
                    "source_uid": f"source_archive:{archive_id}",
                    "vendor": vendor,
                    "raw": {
                        "origin": archive.get("origin"),
                        "source_archive_id": archive_id,
                        "vendor": vendor,
                    },
                }
            ]
        )
        detail = get_product_detail(name) or get_product_detail(product_key(name))
        key = str((detail or {}).get("canonical_product_key") or (detail or {}).get("product_key") or product_key(name))
    alias_values = [str(item or "").strip() for item in (aliases or []) if str(item or "").strip()]
    for alias in alias_values[:20]:
        try:
            add_product_alias(key, alias, vendor=vendor)
        except (KeyError, ValueError):
            continue
    return update_source_archive(
        archive_id,
        status="ready",
        product_name=name,
        product_key=key,
        product_confirmed=True,
        confirmed_at=utc_now(),
    )


def cancel_source_archive_ingest(archive_id: int, reason: str = "") -> dict[str, Any] | None:
    archive = get_source_archive(archive_id)
    if not archive:
        return None
    if archive.get("product_confirmed"):
        raise ValueError("source archive has already been confirmed")
    return update_source_archive(
        archive_id,
        status="canceled",
        error=(reason or "用户取消入库。")[:1000],
        product_name="",
        product_key="",
        product_confirmed=False,
    )


def _deserialize_source_archive(row: dict[str, Any]) -> dict[str, Any]:
    row["suggested_aliases"] = _json_value(row.get("suggested_aliases"), [])
    row["analysis_raw"] = _json_value(row.get("analysis_raw"), {})
    row["product_confirmed"] = bool(row.get("product_confirmed"))
    row["size_bytes"] = int(row.get("size_bytes") or 0)
    row["minio_ready"] = row.get("minio_status") == "uploaded" and bool(row.get("minio_url"))
    return row


def add_followed_product(product: str) -> dict[str, Any]:
    label = str(product or "").strip()
    key = product_key(label)
    if not key:
        raise ValueError("product is required")
    now = utc_now()
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO followed_products (product_key, product, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(product_key) DO UPDATE SET
                product=excluded.product,
                updated_at=excluded.updated_at
            """,
            (key, label, now, now),
        )
        row = conn.execute(
            "SELECT * FROM followed_products WHERE product_key=?", (key,)
        ).fetchone()
        return dict(row)


def list_followed_products() -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM followed_products
            ORDER BY updated_at DESC, created_at DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]


def delete_followed_product(product_key_value: str) -> bool:
    with connection() as conn:
        cursor = conn.execute(
            "DELETE FROM followed_products WHERE product_key=?", (product_key_value,)
        )
        return cursor.rowcount > 0


def get_followed_product(product: str) -> dict[str, Any] | None:
    key = product_key(product)
    if not key:
        return None
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM followed_products WHERE product_key=?", (key,)
        ).fetchone()
        return None if row is None else dict(row)


def is_product_followed(product: str) -> bool:
    return get_followed_product(product) is not None


def mark_followed_product_match(product_key_value: str, vulnerability_id: int) -> None:
    if not product_key_value:
        return
    now = utc_now()
    with connection() as conn:
        conn.execute(
            """
            UPDATE followed_products
            SET last_matched_at=?, last_analysis_vulnerability_id=?, updated_at=?
            WHERE product_key=?
            """,
            (now, vulnerability_id, now, product_key_value),
        )


def _normalize_product_text(value: str) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"cve-\d{4}-\d{4,}", " ", text, flags=re.I)
    text = _canonicalize_product_synonyms(text)
    text = re.sub(r"\b(?:critical|high|medium|low)\b", " ", text, flags=re.I)
    for token in ["漏洞", "安全", "存在", "高危", "严重"]:
        text = text.replace(token, "")
    text = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", text)
    text = _canonicalize_product_synonyms(text)
    return text[:180]


def _canonicalize_product_synonyms(value: str) -> str:
    text = str(value or "")
    replacements = [
        ("yongyou", "用友"),
        ("yonyou", "用友"),
        ("ufida", "用友"),
        ("用友网络", "用友"),
        ("kingdee", "金蝶"),
        ("weaver", "泛微"),
        ("fanwei", "泛微"),
        ("ecology", "e-cology"),
        ("chanjet", "畅捷通"),
    ]
    for source, target in replacements:
        text = text.replace(source, target)
    text = re.sub(r"(用友){2,}", "用友", text)
    text = re.sub(r"(金蝶){2,}", "金蝶", text)
    text = re.sub(r"(泛微){2,}", "泛微", text)
    return text


def _first_cve(item: dict[str, Any]) -> str:
    texts = [
        str(item.get("cve_id") or ""),
        str(item.get("title") or ""),
        str(item.get("description") or ""),
        " ".join(str(alias) for alias in item.get("aliases") or []),
    ]
    for text in texts:
        match = re.search(r"CVE-\d{4}-\d{4,}", text, flags=re.I)
        if match:
            return match.group(0).upper()
    return ""


def _asset_from_title(title: str) -> str:
    text = re.sub(r"（?CVE-\d{4}-\d{4,}）?", "", title or "", flags=re.I).strip()
    for marker in ["存在", "安全漏洞", "漏洞", "远程代码执行", "命令执行", "SQL注入", "任意文件"]:
        if marker in text:
            return text.split(marker, 1)[0]
    return " ".join(text.split()[:4])


def _normalize_dedupe_text(value: str) -> str:
    text = str(value or "").lower()
    text = re.sub(r"cve-\d{4}-\d{4,}", " ", text, flags=re.I)
    text = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", text)
    for token in ["漏洞", "安全", "存在", "高危", "严重", "critical", "high", "medium", "low"]:
        text = text.replace(token, "")
    return text[:160]


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


ALERT_SEVERITY_ORDER = {
    "none": 0,
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _alert_window(conn: sqlite3.Connection) -> tuple[list[str], str]:
    raw_row = conn.execute(
        "SELECT value FROM app_settings WHERE key='monitor_rules'"
    ).fetchone()
    payload: dict[str, Any] = {}
    if raw_row is not None:
        try:
            payload = json.loads(raw_row["value"] or "{}")
        except json.JSONDecodeError:
            payload = {}
    min_severity = str(payload.get("min_severity") or "high").lower()
    if ALERT_SEVERITY_ORDER.get(min_severity, 0) < ALERT_SEVERITY_ORDER["high"]:
        min_severity = "high"
    try:
        max_age_days = int(payload.get("max_age_days") or 30)
    except (TypeError, ValueError):
        max_age_days = 30
    return _severity_values_at_or_above(min_severity), _alert_cutoff_date(max_age_days)


def _severity_values_at_or_above(min_severity: str) -> list[str]:
    rank = ALERT_SEVERITY_ORDER.get(str(min_severity or "high").lower(), ALERT_SEVERITY_ORDER["high"])
    return [
        severity
        for severity, value in ALERT_SEVERITY_ORDER.items()
        if value >= rank and value > 0
    ]


def _alert_cutoff_date(max_age_days: int) -> str:
    try:
        today = datetime.now(ZoneInfo(settings.scheduler_timezone)).date()
    except ZoneInfoNotFoundError:
        today = datetime.now(timezone.utc).date()
    clamped = max(1, min(int(max_age_days or 30), 3650))
    return (today - timedelta(days=clamped)).isoformat()


def _alert_date_expr(alias: str = "v") -> str:
    return f"substr(COALESCE({alias}.published_at, {alias}.updated_at, {alias}.first_seen_at), 1, 10)"


def summary() -> dict[str, Any]:
    try:
        local_today = datetime.now(ZoneInfo(settings.scheduler_timezone)).date().isoformat()
    except ZoneInfoNotFoundError:
        local_today = datetime.now(timezone.utc).date().isoformat()

    with connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS n FROM vulnerabilities").fetchone()["n"]
        products = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM products
            WHERE COALESCE(merged_into_product_key, '') = ''
            """
        ).fetchone()["n"]
        active_products = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM products p
            WHERE COALESCE(p.merged_into_product_key, '') = ''
              AND (
                p.source='source_archives'
                OR EXISTS (
                    SELECT 1
                    FROM product_vulnerabilities pv
                    WHERE pv.product_key=p.product_key
                )
                OR EXISTS (
                    SELECT 1
                    FROM followed_products fp
                    WHERE fp.product_key=p.product_key
                )
              )
            """
        ).fetchone()["n"]
        hidden_products = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM products
            WHERE COALESCE(merged_into_product_key, '') <> ''
            """
        ).fetchone()["n"]
        source_archives = conn.execute("SELECT COUNT(*) AS n FROM source_archives").fetchone()["n"]
        source_archives_pending = conn.execute(
            "SELECT COUNT(*) AS n FROM source_archives WHERE status IN ('queued', 'analyzing', 'needs_confirmation')"
        ).fetchone()["n"]
        today = conn.execute(
            "SELECT COUNT(*) AS n FROM vulnerabilities WHERE published_at >= ?",
            (local_today,),
        ).fetchone()["n"]
        sources = conn.execute("SELECT COUNT(*) AS n FROM sources WHERE enabled=1").fetchone()["n"]
        runs = conn.execute("SELECT COUNT(*) AS n FROM runs WHERE status='running'").fetchone()["n"]
        alert_severities, alert_cutoff = _alert_window(conn)
        alert_placeholders = ", ".join("?" for _ in alert_severities)
        alert_date_expr = _alert_date_expr("v")
        alerts = conn.execute(
            f"""
            SELECT COUNT(*) AS n
            FROM alerts a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            WHERE a.status='new'
              AND v.source NOT IN ('doonsec_wechat')
              AND LOWER(COALESCE(v.severity, 'unknown')) IN ({alert_placeholders})
              AND {alert_date_expr} >= ?
            """,
            [*alert_severities, alert_cutoff],
        ).fetchone()["n"]
        acknowledged_alerts = conn.execute(
            f"""
            SELECT COUNT(*) AS n
            FROM alerts a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            WHERE a.status='acknowledged'
              AND v.source NOT IN ('doonsec_wechat')
              AND LOWER(COALESCE(v.severity, 'unknown')) IN ({alert_placeholders})
              AND {alert_date_expr} >= ?
            """,
            [*alert_severities, alert_cutoff],
        ).fetchone()["n"]
        analysis_counts = {
            row["analysis_status"]: row["count"]
            for row in conn.execute(
                """
                SELECT COALESCE(analysis_status, 'idle') AS analysis_status, COUNT(*) AS count
                FROM vulnerabilities
                GROUP BY COALESCE(analysis_status, 'idle')
                """
            ).fetchall()
        }
        poc_available = conn.execute(
            "SELECT COUNT(*) AS n FROM vulnerabilities WHERE poc_available=1"
        ).fetchone()["n"]
        exp_available = conn.execute(
            "SELECT COUNT(*) AS n FROM vulnerabilities WHERE exp_available=1"
        ).fetchone()["n"]
        by_severity = conn.execute(
            """
            SELECT COALESCE(severity, 'unknown') AS severity, COUNT(*) AS count
            FROM vulnerabilities
            GROUP BY COALESCE(severity, 'unknown')
            ORDER BY count DESC
            """
        ).fetchall()
    return {
        "vulnerabilities": total,
        "products": active_products,
        "catalog_products": products,
        "hidden_products": hidden_products,
        "source_archives": source_archives,
        "source_archives_pending": source_archives_pending,
        "graph_nodes": 0,
        "graph_relationships": 0,
        "published_today": today,
        "enabled_sources": sources,
        "running_jobs": runs,
        "open_alerts": alerts,
        "acknowledged_alerts": acknowledged_alerts,
        "analysis_queued": analysis_counts.get("queued", 0),
        "analysis_running": analysis_counts.get("running", 0),
        "analysis_finished": analysis_counts.get("finished", 0),
        "analysis_failed": analysis_counts.get("failed", 0),
        "poc_available": poc_available,
        "exp_available": exp_available,
        "by_analysis_status": [
            {"status": status, "count": count}
            for status, count in sorted(analysis_counts.items(), key=lambda item: item[0])
        ],
        "by_severity": [dict(row) for row in by_severity],
    }


def latest_runs(limit: int = 20) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_setting(key: str) -> str:
    with connection() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        return "" if row is None else str(row["value"])


def get_setting_meta(key: str) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT key, created_at, updated_at FROM app_settings WHERE key=?", (key,)
        ).fetchone()
        return row_to_dict(row)


def set_setting(key: str, value: str) -> None:
    now = utc_now()
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO app_settings (key, value, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value,
                updated_at=excluded.updated_at
            """,
            (key, value, now, now),
        )


def delete_setting(key: str) -> None:
    with connection() as conn:
        conn.execute("DELETE FROM app_settings WHERE key=?", (key,))


def create_message(
    *,
    title: str,
    body: str = "",
    level: str = "info",
    category: str = "system",
    entity_type: str = "",
    entity_id: str | int = "",
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = utc_now()
    normalized_level = str(level or "info").lower()
    if normalized_level not in {"info", "success", "warning", "error"}:
        normalized_level = "info"
    normalized_category = str(category or "system").lower()
    with connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO messages (
                level, category, title, body, entity_type, entity_id,
                is_read, created_at, raw
            )
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                normalized_level,
                normalized_category,
                str(title or "消息")[:240],
                str(body or "")[:8000],
                str(entity_type or "")[:80],
                str(entity_id or "")[:120],
                now,
                json.dumps(raw or {}, ensure_ascii=False),
            ),
        )
        row = conn.execute(
            "SELECT * FROM messages WHERE id=?", (cursor.lastrowid,)
        ).fetchone()
        return _deserialize_message(dict(row))


def list_messages(
    *,
    status: str = "",
    category: str = "",
    limit: int = 30,
    offset: int = 0,
) -> dict[str, Any]:
    clauses: list[str] = []
    args: list[Any] = []
    if status == "unread":
        clauses.append("is_read=0")
    elif status == "read":
        clauses.append("is_read=1")
    if category:
        clauses.append("category=?")
        args.append(category)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        unread = conn.execute(
            "SELECT COUNT(*) AS n FROM messages WHERE is_read=0"
        ).fetchone()["n"]
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM messages {where}",
            args,
        ).fetchone()["n"]
        rows = conn.execute(
            f"""
            SELECT *
            FROM messages
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*args, limit, offset],
        ).fetchall()
    return {
        "total": total,
        "unread": unread,
        "data": [_deserialize_message(dict(row)) for row in rows],
    }


def mark_message_read(message_id: int, read: bool = True) -> bool:
    now = utc_now()
    with connection() as conn:
        cursor = conn.execute(
            """
            UPDATE messages
            SET is_read=?, read_at=?
            WHERE id=?
            """,
            (1 if read else 0, now if read else None, message_id),
        )
        return cursor.rowcount > 0


def mark_all_messages_read() -> int:
    now = utc_now()
    with connection() as conn:
        cursor = conn.execute(
            """
            UPDATE messages
            SET is_read=1, read_at=?
            WHERE is_read=0
            """,
            (now,),
        )
        return cursor.rowcount


def _deserialize_message(row: dict[str, Any]) -> dict[str, Any]:
    row["is_read"] = bool(row.get("is_read"))
    row["raw"] = _json_value(row.get("raw"), {})
    return row


def insert_deepseek_balance_check(
    *,
    status: str,
    is_available: bool | None = None,
    currency: str = "",
    total_balance: str = "",
    granted_balance: str = "",
    topped_up_balance: str = "",
    raw: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    checked_at = utc_now()
    with connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO deepseek_balance_checks (
                checked_at, status, is_available, currency, total_balance,
                granted_balance, topped_up_balance, raw, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checked_at,
                status,
                None if is_available is None else 1 if is_available else 0,
                currency,
                total_balance,
                granted_balance,
                topped_up_balance,
                json.dumps(raw or {}, ensure_ascii=False),
                error,
            ),
        )
        row = conn.execute(
            "SELECT * FROM deepseek_balance_checks WHERE id=?", (cursor.lastrowid,)
        ).fetchone()
        return _deserialize_balance(dict(row))


def latest_deepseek_balance_check() -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM deepseek_balance_checks ORDER BY checked_at DESC, id DESC LIMIT 1"
        ).fetchone()
        return None if row is None else _deserialize_balance(dict(row))


def _deserialize_balance(row: dict[str, Any]) -> dict[str, Any]:
    row["is_available"] = None if row.get("is_available") is None else bool(row["is_available"])
    row["raw"] = json.loads(row.get("raw") or "{}")
    return row


def get_vulnerability_by_source_uid(source: str, source_uid: str) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE source=? AND source_uid=?",
            (source, source_uid),
        ).fetchone()
        return None if row is None else _deserialize_vuln(dict(row))


def get_vulnerability_for_item(item: dict[str, Any]) -> dict[str, Any] | None:
    source = str(item.get("source") or "")
    source_uid = str(item.get("source_uid") or "")
    dedupe_key = str(item.get("dedupe_key") or dedupe_key_for_item(item) or "")
    with connection() as conn:
        row = None
        if source and source_uid:
            row = conn.execute(
                "SELECT * FROM vulnerabilities WHERE source=? AND source_uid=?",
                (source, source_uid),
            ).fetchone()
        if row is None and dedupe_key:
            row = conn.execute(
                """
                SELECT *
                FROM vulnerabilities
                WHERE dedupe_key=?
                ORDER BY id ASC
                LIMIT 1
                """,
                (dedupe_key,),
            ).fetchone()
        return None if row is None else _deserialize_vuln(dict(row))


def get_vulnerability(vulnerability_id: int) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
        ).fetchone()
        return None if row is None else _deserialize_vuln(dict(row))


def delete_vulnerability_analysis(vulnerability_id: int) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
        ).fetchone()
        if row is None:
            return None
        conn.execute("DELETE FROM analysis_events WHERE vulnerability_id=?", (vulnerability_id,))
        conn.execute(
            """
            UPDATE vulnerabilities
            SET
                analysis_status='idle',
                analysis_requested_at=NULL,
                analysis_started_at=NULL,
                analysis_finished_at=NULL,
                analysis_error='',
                analysis_summary='',
                analysis_source_found=0,
                analysis_source_url='',
                analysis_source_local_path='',
                analysis_source_title='',
                analysis_source_archive_path='',
                analysis_source_retained_until='',
                analysis_source_cleaned_at='',
                analysis_sources='[]',
                analysis_raw='{}',
                analysis_run_id='',
                analysis_model='',
                analysis_trigger='',
                analysis_priority=50,
                analysis_cancel_requested=0,
                analysis_failure_reason='',
                poc_available=0,
                poc_url='',
                poc_content='',
                exp_available=0,
                exp_url='',
                exp_content=''
            WHERE id=?
            """,
            (vulnerability_id,),
        )
        refreshed = conn.execute(
            "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
        ).fetchone()
        return None if refreshed is None else _deserialize_vuln(dict(refreshed))


def get_analysis_feedback(vulnerability_id: int) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM analysis_feedback WHERE vulnerability_id=?",
            (vulnerability_id,),
        ).fetchone()
        return None if row is None else dict(row)


def upsert_analysis_feedback(
    vulnerability_id: int,
    rating: str,
    note: str = "",
) -> dict[str, Any] | None:
    rating_value = str(rating or "").strip().lower()
    if rating_value not in {"useful", "not_useful"}:
        raise ValueError("rating must be useful or not_useful")
    now = utc_now()
    with connection() as conn:
        vuln = conn.execute(
            "SELECT id FROM vulnerabilities WHERE id=?",
            (vulnerability_id,),
        ).fetchone()
        if vuln is None:
            return None
        conn.execute(
            """
            INSERT INTO analysis_feedback (
                vulnerability_id, rating, note, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(vulnerability_id) DO UPDATE SET
                rating=excluded.rating,
                note=excluded.note,
                updated_at=excluded.updated_at
            """,
            (
                vulnerability_id,
                rating_value,
                str(note or "").strip()[:1000],
                now,
                now,
            ),
        )
        _create_analysis_event_conn(
            conn,
            vulnerability_id,
            "",
            "feedback",
            "用户反馈：有用" if rating_value == "useful" else "用户反馈：无用",
            {"rating": rating_value, "note": str(note or "").strip()[:1000]},
        )
        row = conn.execute(
            "SELECT * FROM analysis_feedback WHERE vulnerability_id=?",
            (vulnerability_id,),
        ).fetchone()
        return None if row is None else dict(row)


def request_vulnerability_analysis(
    vulnerability_id: int,
    *,
    trigger: str = "manual",
    force: bool = False,
    priority: int = 50,
    analysis_model: str = "",
) -> dict[str, Any] | None:
    now = utc_now()
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
        ).fetchone()
        if row is None:
            return None
        status = str(row["analysis_status"] or "idle")
        if status in {"queued", "running"} and not force:
            return _deserialize_vuln(dict(row))
        cursor = conn.execute(
            """
            UPDATE vulnerabilities
            SET
                analysis_status='queued',
                analysis_requested_at=?,
                analysis_started_at=NULL,
                analysis_finished_at=NULL,
                analysis_error='',
                analysis_failure_reason='',
                analysis_trigger=?,
                analysis_run_id='',
                analysis_model=?,
                analysis_priority=?,
                analysis_cancel_requested=0
            WHERE id=?
            """,
            (
                now,
                trigger,
                str(analysis_model or "").strip()[:120],
                max(0, min(int(priority), 100)),
                vulnerability_id,
            ),
        )
        if cursor.rowcount <= 0:
            return None
        _create_analysis_event_conn(
            conn,
            vulnerability_id,
            "",
            "queue",
            f"已进入分析队列，触发方式：{trigger}",
            {"trigger": trigger, "force": force, "analysis_model": str(analysis_model or "").strip()[:120]},
        )
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
        ).fetchone()
        return None if row is None else _deserialize_vuln(dict(row))


def start_vulnerability_analysis(vulnerability_id: int, run_id: str, model: str) -> bool:
    now = utc_now()
    with connection() as conn:
        cursor = conn.execute(
            """
            UPDATE vulnerabilities
            SET
                analysis_status='running',
                analysis_started_at=?,
                analysis_error='',
                analysis_failure_reason='',
                analysis_run_id=?,
                analysis_model=?,
                analysis_cancel_requested=0
            WHERE id=?
              AND analysis_status='queued'
              AND analysis_cancel_requested=0
            """,
            (now, run_id, model, vulnerability_id),
        )
        if cursor.rowcount <= 0:
            return False
        _create_analysis_event_conn(
            conn,
            vulnerability_id,
            run_id,
            "stage",
            f"分析任务启动，模型：{model}",
            {"model": model},
        )
        return True


def finish_vulnerability_analysis(
    vulnerability_id: int,
    *,
    summary: str,
    sources: list[dict[str, Any]],
    raw: dict[str, Any],
    analysis_error: str = "",
    source_found: bool = False,
    source_url: str = "",
    source_local_path: str = "",
    source_title: str = "",
    source_archive_path: str = "",
    source_retained_until: str = "",
    poc_available: bool = False,
    poc_url: str = "",
    poc_content: str = "",
    exp_available: bool = False,
    exp_url: str = "",
    exp_content: str = "",
) -> dict[str, Any] | None:
    now = utc_now()
    poc_available, poc_url, poc_content = _normalize_artifact_fields(
        "poc",
        poc_available,
        poc_url,
        poc_content,
    )
    exp_available, exp_url, exp_content = _normalize_artifact_fields(
        "exp",
        exp_available,
        exp_url,
        exp_content,
    )
    with connection() as conn:
        current = conn.execute(
            """
            SELECT analysis_run_id, analysis_source_found, analysis_source_url,
                   analysis_source_local_path, analysis_source_title,
                   analysis_source_archive_path, analysis_source_retained_until,
                   analysis_source_cleaned_at, analysis_sources
            FROM vulnerabilities WHERE id=?
            """,
            (vulnerability_id,),
        ).fetchone()
        run_id = "" if current is None else str(current["analysis_run_id"] or "")
        preserve_existing_source = (
            not source_found
            and current is not None
            and bool(current["analysis_source_found"])
        )
        if preserve_existing_source:
            source_found = True
            source_url = str(current["analysis_source_url"] or "")
            source_local_path = str(current["analysis_source_local_path"] or "")
            source_title = str(current["analysis_source_title"] or "")
            source_archive_path = str(current["analysis_source_archive_path"] or "")
            source_retained_until = str(current["analysis_source_retained_until"] or "")
            if _analysis_failure_reason(analysis_error) == "源码未搜索到":
                analysis_error = ""
            existing_sources = _json_value(current["analysis_sources"], [])
            if isinstance(existing_sources, list):
                source_keys = {
                    (
                        str(item.get("url") or ""),
                        str(item.get("local_path") or ""),
                    )
                    for item in sources
                    if isinstance(item, dict)
                }
                for item in existing_sources:
                    if not isinstance(item, dict):
                        continue
                    marker = (str(item.get("url") or ""), str(item.get("local_path") or ""))
                    if marker not in source_keys:
                        sources.append(item)
                        source_keys.add(marker)
        raw = dict(raw or {})
        if preserve_existing_source:
            raw["preserved_existing_source"] = True
        cursor = conn.execute(
            """
            UPDATE vulnerabilities
            SET
                analysis_status='finished',
                analysis_finished_at=?,
                analysis_error=?,
                analysis_failure_reason=?,
                analysis_source_found=?,
                analysis_source_url=?,
                analysis_source_local_path=?,
                analysis_source_title=?,
                analysis_source_archive_path=?,
                analysis_source_retained_until=?,
                analysis_source_cleaned_at=CASE
                    WHEN ? <> '' THEN ''
                    ELSE analysis_source_cleaned_at
                END,
                analysis_summary=?,
                analysis_sources=?,
                analysis_raw=?,
                analysis_cancel_requested=0,
                poc_available=?,
                poc_url=?,
                poc_content=?,
                exp_available=?,
                exp_url=?,
                exp_content=?
            WHERE id=?
              AND analysis_status != 'canceled'
              AND analysis_cancel_requested=0
            """,
            (
                now,
                analysis_error[:4000],
                _analysis_failure_reason(analysis_error) if analysis_error else "",
                1 if source_found else 0,
                source_url[:1000],
                source_local_path[:1000],
                source_title[:300],
                source_archive_path[:1000],
                source_retained_until[:40],
                source_archive_path[:1000],
                summary[:12000],
                json.dumps(sources[:30], ensure_ascii=False),
                json.dumps(raw, ensure_ascii=False)[:60000],
                1 if poc_available else 0,
                poc_url,
                poc_content[:20000],
                1 if exp_available else 0,
                exp_url,
                exp_content[:20000],
                vulnerability_id,
            ),
        )
        if cursor.rowcount <= 0:
            row = conn.execute(
                "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
            ).fetchone()
            return None if row is None else _deserialize_vuln(dict(row))
        _create_analysis_event_conn(
            conn,
            vulnerability_id,
            run_id,
            "poc",
            "POC 已生成" if poc_available or poc_content else "POC 未生成",
            {"available": bool(poc_available), "content_length": len(poc_content or "")},
        )
        _create_analysis_event_conn(
            conn,
            vulnerability_id,
            run_id,
            "exp",
            "EXP 已生成" if exp_available or exp_content else "EXP 未生成",
            {"available": bool(exp_available), "content_length": len(exp_content or "")},
        )
        _create_analysis_event_conn(
            conn,
            vulnerability_id,
            run_id,
            "finish",
            "漏洞分析完成" if not analysis_error else f"漏洞分析完成，但存在异常：{analysis_error[:500]}",
            {"warning": analysis_error[:4000], "source_count": len(sources)},
        )
        _refresh_vulnerability_quality_conn(conn, vulnerability_id)
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
        ).fetchone()
        return None if row is None else _deserialize_vuln(dict(row))


def fail_vulnerability_analysis(vulnerability_id: int, error: str) -> dict[str, Any] | None:
    now = utc_now()
    reason = _analysis_failure_reason(error)
    with connection() as conn:
        current = conn.execute(
            "SELECT analysis_run_id FROM vulnerabilities WHERE id=?", (vulnerability_id,)
        ).fetchone()
        run_id = "" if current is None else str(current["analysis_run_id"] or "")
        conn.execute(
            """
            UPDATE vulnerabilities
            SET
                analysis_status='failed',
                analysis_finished_at=?,
                analysis_error=?,
                analysis_failure_reason=?
            WHERE id=?
            """,
            (now, error[:4000], reason, vulnerability_id),
        )
        _create_analysis_event_conn(
            conn,
            vulnerability_id,
            run_id,
            "error",
            error[:2000],
            {"error": error[:4000]},
        )
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
        ).fetchone()
        return None if row is None else _deserialize_vuln(dict(row))


def _analysis_failure_reason(error: str) -> str:
    text = str(error or "").strip()
    if "：" in text:
        return text.split("：", 1)[0][:80]
    lower = text.lower()
    if any(marker in lower for marker in ["deepseek", "api key", "quota", "rate limit", "model", "401", "403", "429"]):
        return "模型源异常"
    if any(marker in lower for marker in ["source", "repository", "源码"]):
        return "源码未搜索到"
    if "timeout" in lower or "超时" in text:
        return "分析超时"
    return "分析失败"


def set_vulnerability_analysis_priority(vulnerability_id: int, priority: int) -> dict[str, Any] | None:
    clamped = max(0, min(int(priority), 100))
    with connection() as conn:
        cursor = conn.execute(
            """
            UPDATE vulnerabilities
            SET analysis_priority=?
            WHERE id=?
            """,
            (clamped, vulnerability_id),
        )
        if cursor.rowcount <= 0:
            return None
        row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone()
        return None if row is None else _deserialize_vuln(dict(row))


ANALYSIS_CONCURRENCY_SETTING = "analysis_concurrency"


def next_queued_analysis(limit: int, exclude_ids: set[int] | None = None) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 20))
    exclude_ids = exclude_ids or set()
    clauses = ["analysis_status='queued'", "analysis_cancel_requested=0"]
    args: list[Any] = []
    if exclude_ids:
        placeholders = ", ".join("?" for _ in exclude_ids)
        clauses.append(f"id NOT IN ({placeholders})")
        args.extend(sorted(exclude_ids))
    where = " AND ".join(clauses)
    with connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM vulnerabilities
            WHERE {where}
            ORDER BY analysis_priority DESC, COALESCE(analysis_requested_at, first_seen_at) ASC, id ASC
            LIMIT ?
            """,
            [*args, limit],
        ).fetchall()
    return [_deserialize_vuln(dict(row)) for row in rows]


def list_queued_analysis(limit: int = 10000) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 50000))
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM vulnerabilities
            WHERE analysis_status='queued'
              AND analysis_cancel_requested=0
            ORDER BY analysis_priority DESC, COALESCE(analysis_requested_at, first_seen_at) ASC, id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [_deserialize_vuln(dict(row)) for row in rows]


def create_analysis_event(
    vulnerability_id: int,
    run_id: str,
    stream: str,
    message: str,
    raw: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    with connection() as conn:
        return _create_analysis_event_conn(
            conn,
            vulnerability_id,
            run_id,
            stream,
            message,
            raw or {},
        )


def _create_analysis_event_conn(
    conn: sqlite3.Connection,
    vulnerability_id: int,
    run_id: str,
    stream: str,
    message: str,
    raw: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    text = str(message or "").strip()
    if not text:
        return None
    now = utc_now()
    cursor = conn.execute(
        """
        INSERT INTO analysis_events (
            vulnerability_id, run_id, stream, message, created_at, raw
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            vulnerability_id,
            run_id or "",
            (stream or "stage")[:40],
            text[:4000],
            now,
            json.dumps(raw or {}, ensure_ascii=False)[:12000],
        ),
    )
    row = conn.execute(
        "SELECT * FROM analysis_events WHERE id=?", (cursor.lastrowid,)
    ).fetchone()
    return None if row is None else _deserialize_analysis_event(dict(row))


def list_analysis_events(
    vulnerability_id: int,
    *,
    run_id: str = "",
    limit: int = 80,
    offset: int = 0,
) -> dict[str, Any]:
    clauses = ["vulnerability_id = ?"]
    args: list[Any] = [vulnerability_id]
    if run_id:
        clauses.append("run_id = ?")
        args.append(run_id)
    where = f"WHERE {' AND '.join(clauses)}"
    with connection() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS total FROM analysis_events {where}",
            args,
        ).fetchone()["total"]
        rows = conn.execute(
            f"""
            SELECT *
            FROM analysis_events
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*args, limit, offset],
        ).fetchall()
    events = [_deserialize_analysis_event(dict(row)) for row in rows]
    return {"total": total, "data": events}


def list_expired_analysis_source_artifacts(now_iso: str, *, limit: int = 100) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, analysis_source_local_path, analysis_source_archive_path,
                   analysis_source_retained_until, analysis_raw
            FROM vulnerabilities
            WHERE analysis_source_retained_until <> ''
              AND analysis_source_retained_until <= ?
              AND analysis_source_cleaned_at = ''
            ORDER BY analysis_source_retained_until ASC, id ASC
            LIMIT ?
            """,
            (now_iso, max(1, min(int(limit), 500))),
        ).fetchall()
        return [dict(row) for row in rows]


def mark_analysis_source_cleaned(vulnerability_id: int, cleaned_at: str) -> None:
    with connection() as conn:
        conn.execute(
            """
            UPDATE vulnerabilities
            SET analysis_source_cleaned_at=?,
                analysis_source_local_path=''
            WHERE id=?
            """,
            (cleaned_at, vulnerability_id),
        )


def list_analysis_workbench(query: str = "", limit: int = 8) -> dict[str, Any]:
    limit = max(1, min(limit, 30))
    with connection() as conn:
        counts = {
            row["analysis_status"]: row["count"]
            for row in conn.execute(
                """
                SELECT COALESCE(analysis_status, 'idle') AS analysis_status, COUNT(*) AS count
                FROM vulnerabilities
                WHERE analysis_status IN ('queued', 'running', 'finished', 'failed', 'canceled')
                GROUP BY COALESCE(analysis_status, 'idle')
                """
            ).fetchall()
        }
        queued = _analysis_rows(
            conn,
            ["queued"],
            query,
            limit,
            "analysis_priority DESC, COALESCE(analysis_requested_at, first_seen_at) ASC, id ASC",
        )
        running = _analysis_rows(
            conn,
            ["running"],
            query,
            limit,
            "COALESCE(analysis_started_at, analysis_requested_at, first_seen_at) DESC, id DESC",
        )
        finished = _analysis_rows(
            conn,
            ["finished", "failed", "canceled"],
            query,
            limit,
            "COALESCE(analysis_finished_at, analysis_started_at, first_seen_at) DESC, id DESC",
        )
    for item in running:
        item["analysis_events"] = list_analysis_events(int(item["id"]), limit=60)["data"]
    return {
        "counts": {
            "queued": counts.get("queued", 0),
            "running": counts.get("running", 0),
            "finished": counts.get("finished", 0),
            "failed": counts.get("failed", 0),
            "canceled": counts.get("canceled", 0),
        },
        "settings": get_analysis_settings(),
        "failure_stats": analysis_failure_stats(),
        "queued": queued,
        "running": running,
        "finished": finished,
    }


def _analysis_rows(
    conn: sqlite3.Connection,
    statuses: list[str],
    query: str,
    limit: int,
    order_by: str,
) -> list[dict[str, Any]]:
    placeholders = ", ".join("?" for _ in statuses)
    clauses = [f"analysis_status IN ({placeholders})"]
    args: list[Any] = [*statuses]
    if query:
        like = f"%{query}%"
        clauses.append("(title LIKE ? OR cve_id LIKE ? OR aliases LIKE ? OR product LIKE ?)")
        args.extend([like, like, like, like])
    where = f"WHERE {' AND '.join(clauses)}"
    rows = conn.execute(
        f"""
        SELECT *
        FROM vulnerabilities
        {where}
        ORDER BY {order_by}
        LIMIT ?
        """,
        [*args, limit],
    ).fetchall()
    return [_deserialize_vuln(dict(row)) for row in rows]


def _deserialize_analysis_event(row: dict[str, Any]) -> dict[str, Any]:
    row["raw"] = _json_value(row.get("raw"), {})
    return row


def create_alert_if_absent(vulnerability_id: int, dedupe_key: str, reason: str) -> int:
    now = utc_now()
    with connection() as conn:
        source_row = conn.execute(
            "SELECT source FROM vulnerabilities WHERE id=?",
            (vulnerability_id,),
        ).fetchone()
        if source_row and str(source_row["source"] or "") in ALERT_EXCLUDED_SOURCES:
            return 0
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO alerts (
                vulnerability_id, dedupe_key, status, reason, created_at, updated_at
            )
            VALUES (?, ?, 'new', ?, ?, ?)
            """,
            (vulnerability_id, dedupe_key, reason, now, now),
        )
        if cursor.rowcount <= 0:
            return 0
        return int(cursor.lastrowid)


def list_alerts(
    status: str = "new",
    source: str = "",
    query: str = "",
    limit: int = 50,
    offset: int = 0,
    min_severity: str = "",
    published_after: str = "",
) -> dict[str, Any]:
    clauses: list[str] = []
    args: list[Any] = []
    if ALERT_EXCLUDED_SOURCES:
        clauses.append(
            f"v.source NOT IN ({', '.join('?' for _ in ALERT_EXCLUDED_SOURCES)})"
        )
        args.extend(sorted(ALERT_EXCLUDED_SOURCES))
    if status:
        clauses.append("a.status = ?")
        args.append(status)
    if source:
        clauses.append("v.source = ?")
        args.append(source)
    if min_severity:
        severities = _severity_values_at_or_above(min_severity)
        if severities:
            clauses.append(
                f"LOWER(COALESCE(v.severity, 'unknown')) IN ({', '.join('?' for _ in severities)})"
            )
            args.extend(severities)
    if published_after:
        clauses.append(f"{_alert_date_expr('v')} >= ?")
        args.append(published_after)
    if query:
        like = f"%{query}%"
        clauses.append(
            """
            (
                v.cve_id LIKE ?
                OR v.product LIKE ?
                OR v.title LIKE ?
                OR v.aliases LIKE ?
                OR a.dedupe_key LIKE ?
            )
            """
        )
        args.extend([like, like, like, like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        total = conn.execute(
            f"""
            SELECT COUNT(*) AS total
            FROM alerts a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            {where}
            """,
            args,
        ).fetchone()["total"]
        rows = conn.execute(
            f"""
            SELECT
                a.id AS alert_id,
                a.dedupe_key,
                a.status AS alert_status,
                a.reason,
                a.created_at AS alert_created_at,
                a.updated_at AS alert_updated_at,
                a.acknowledged_at,
                v.*
            FROM alerts a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            {where}
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT ? OFFSET ?
            """,
            [*args, limit, offset],
        ).fetchall()
    return {
        "total": total,
        "data": [_deserialize_alert(dict(row)) for row in rows],
    }


def acknowledge_alert(alert_id: int) -> bool:
    now = utc_now()
    with connection() as conn:
        cursor = conn.execute(
            """
            UPDATE alerts
            SET status='acknowledged', acknowledged_at=?, updated_at=?
            WHERE id=? AND status != 'acknowledged'
            """,
            (now, now, alert_id),
        )
        return cursor.rowcount > 0


def get_alert(alert_id: int) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT
                a.id AS alert_id,
                a.dedupe_key,
                a.status AS alert_status,
                a.reason,
                a.created_at AS alert_created_at,
                a.updated_at AS alert_updated_at,
                a.acknowledged_at,
                v.*
            FROM alerts a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            WHERE a.id=?
            """,
            (alert_id,),
        ).fetchone()
        return None if row is None else _deserialize_alert(dict(row))


def _deserialize_alert(row: dict[str, Any]) -> dict[str, Any]:
    vuln = {key: row.pop(key, None) for key in VULNERABILITY_COLUMNS if key in row}
    row["vulnerability"] = _deserialize_vuln(vuln)
    return row


# ─── 数据源健康中心 ─────────────────────────────────────────────

def source_health() -> list[dict[str, Any]]:
    failure_statuses = {"failed", "partial", "orphaned"}
    with connection() as conn:
        sources_raw = conn.execute("SELECT * FROM sources ORDER BY category, name").fetchall()
    results = []
    for src in sources_raw:
        info = dict(src)
        name = info["name"]
        with connection() as conn:
            recent = conn.execute("""
                SELECT started_at, finished_at, status, item_count, error
                FROM runs WHERE source=? AND finished_at IS NOT NULL
                ORDER BY started_at DESC LIMIT 10
            """, (name,)).fetchall()
            run_times = []
            error_types = {}
            item_counts = []
            for run in recent:
                r = dict(run)
                if r["finished_at"] and r["started_at"]:
                    try:
                        elapsed = (datetime.fromisoformat(r["finished_at"]) - datetime.fromisoformat(r["started_at"])).total_seconds()
                        run_times.append(elapsed)
                    except (TypeError, ValueError):
                        pass
                item_counts.append({"started_at": r["started_at"], "item_count": r["item_count"]})
                err = (r.get("error") or "").strip()
                if err:
                    key = _classify_source_error(err)
                    error_types[key] = error_types.get(key, 0) + 1
            last_ok = conn.execute(
                "SELECT * FROM runs WHERE source=? AND status='success' AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1",
                (name,)).fetchone()
            last_fail = conn.execute(
                "SELECT * FROM runs WHERE source=? AND status IN ('failed','partial','orphaned') AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1",
                (name,)).fetchone()
        consecutive_failures = 0
        for run in recent:
            if dict(run)["status"] in failure_statuses:
                consecutive_failures += 1
                continue
            break
        avg_time = round(sum(run_times) / len(run_times), 2) if run_times else None
        info.pop("raw", None)
        display_status = "disabled" if not info.get("enabled") else (info.get("last_status") or "pending")
        latest_error = ""
        if display_status in failure_statuses:
            latest_error = dict(last_fail).get("error", "") if last_fail else (info.get("last_error") or "")
        results.append({
            **info,
            "display_status": display_status,
            "display_error": latest_error,
            "last_successful_run_at": dict(last_ok)["finished_at"] if last_ok else None,
            "last_failure_at": dict(last_fail)["finished_at"] if last_fail else None,
            "last_error": latest_error,
            "avg_run_seconds": avg_time,
            "consecutive_failures": consecutive_failures,
            "recent_item_counts": item_counts[:5],
            "error_type_counts": error_types,
            "total_runs": len(recent),
        })
    return results


def _classify_source_error(error: str) -> str:
    text = error.lower()
    if "429" in text or "too many requests" in text:
        return "rate_limit"
    if "captcha" in text or "验证码" in text:
        return "captcha"
    if "401" in text or "403" in text or "unauthorized" in text or "forbidden" in text:
        return "auth_error"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "connection" in text or "resolve" in text or "econnrefused" in text:
        return "network"
    if "not configured" in text or "is not configured" in text:
        return "misconfiguration"
    if "500" in text or "502" in text or "503" in text:
        return "server_error"
    return "other"


# ─── 日报/周报 ──────────────────────────────────────────────────

def daily_report(hour_offset: int = 24) -> dict[str, Any]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hour_offset)).isoformat()
    with connection() as conn:
        new_severity = conn.execute(f"""
            SELECT COALESCE(severity, 'unknown') AS severity, COUNT(*) AS count
            FROM vulnerabilities
            WHERE first_seen_at >= ?
            GROUP BY COALESCE(severity, 'unknown')
        """, (cutoff,)).fetchall()
        new_poc = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM vulnerabilities
            WHERE poc_available=1
              AND (first_seen_at >= ? OR analysis_finished_at >= ? OR updated_at >= ?)
            """,
            (cutoff, cutoff, cutoff)).fetchone()["n"]
        new_exp = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM vulnerabilities
            WHERE exp_available=1
              AND (first_seen_at >= ? OR analysis_finished_at >= ? OR updated_at >= ?)
            """,
            (cutoff, cutoff, cutoff)).fetchone()["n"]
        followed_matches = conn.execute("""
            SELECT fp.product, fp.last_matched_at, fp.last_analysis_vulnerability_id,
                   v.title, v.cve_id, v.severity
            FROM followed_products fp
            LEFT JOIN vulnerabilities v ON v.id = fp.last_analysis_vulnerability_id
            WHERE fp.last_matched_at >= ?
            ORDER BY fp.last_matched_at DESC
        """, (cutoff,)).fetchall()
        new_alerts = conn.execute("""
            SELECT COUNT(*) AS n
            FROM alerts a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            WHERE a.created_at >= ? AND v.source NOT IN ('doonsec_wechat')
        """, (cutoff,)).fetchone()["n"]
        pending_alerts = conn.execute("""
            SELECT COUNT(*) AS n
            FROM alerts a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            WHERE a.status='new' AND v.source NOT IN ('doonsec_wechat')
        """).fetchone()["n"]
        analysis_done = conn.execute("""
            SELECT COUNT(*) AS n FROM vulnerabilities
            WHERE analysis_status='finished' AND analysis_finished_at >= ?
        """, (cutoff,)).fetchone()["n"]
        analysis_failed = conn.execute("""
            SELECT COUNT(*) AS n FROM vulnerabilities
            WHERE analysis_status='failed' AND analysis_finished_at >= ?
        """, (cutoff,)).fetchone()["n"]
        new_products = conn.execute("SELECT COUNT(*) AS n FROM products WHERE first_seen_at >= ?", (cutoff,)).fetchone()["n"]
    return {
        "period_hours": hour_offset,
        "period_label": "日报" if hour_offset <= 24 else "周报",
        "cutoff_at": cutoff,
        "new_vulnerabilities_by_severity": [dict(row) for row in new_severity],
        "new_total": sum(row["count"] for row in new_severity),
        "new_poc": new_poc,
        "new_exp": new_exp,
        "followed_product_matches": [dict(row) for row in followed_matches],
        "new_alerts": new_alerts,
        "pending_alerts": pending_alerts,
        "analysis_completed": analysis_done,
        "analysis_failed": analysis_failed,
        "new_products": new_products,
    }


# ─── 情报质量评分 ──────────────────────────────────────────────

def _score_freshness(days_old: float) -> float:
    if days_old <= 1: return 10.0
    if days_old <= 7: return 8.0
    if days_old <= 30: return 6.0
    if days_old <= 90: return 4.0
    if days_old <= 365: return 2.0
    return 0.0


def _score_severity(severity: str | None) -> float:
    rank = {"critical": 25.0, "high": 20.0, "medium": 10.0, "low": 5.0, "none": 0.0, "unknown": 0.0}
    return rank.get((severity or "unknown").lower(), 0.0)


def compute_threat_score(vuln: dict[str, Any]) -> dict[str, Any]:
    score = 0.0
    breakdown = {}
    score += (sev := _score_severity(vuln.get("severity"))); breakdown["severity"] = sev
    poc = bool(vuln.get("poc_available")); breakdown["poc"] = 20.0 if poc else 0.0; score += breakdown["poc"]
    exp = bool(vuln.get("exp_available")); breakdown["exp"] = 10.0 if exp else 0.0; score += breakdown["exp"]
    raw = vuln.get("raw") or {}
    raw_text = json.dumps(raw, ensure_ascii=False).lower()
    wild_indicators = ["in the wild", "在野", "已公开利用", "active exploit", "exploited", "ransomware"]
    wild = any(i in raw_text for i in wild_indicators)
    if not wild:
        td = f"{vuln.get('title', '')} {vuln.get('description', '')}".lower()
        wild = any(i in td for i in wild_indicators)
    breakdown["in_wild"] = 15.0 if wild else 0.0; score += breakdown["in_wild"]
    product = vuln.get("product") or ""
    breakdown["followed_product"] = 15.0 if (product and is_product_followed(product)) else 0.0; score += breakdown["followed_product"]
    src_count = 1 + len(raw.get("_source_reports") or [])
    breakdown["source_count"] = min(5.0, src_count); score += breakdown["source_count"]
    published = _parse_datetime(vuln.get("published_at") or vuln.get("updated_at") or vuln.get("first_seen_at"))
    if published:
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - published).total_seconds() / 86400
        breakdown["freshness"] = _score_freshness(max(0.0, days))
    else:
        breakdown["freshness"] = 5.0
    score += breakdown["freshness"]
    total = round(score, 1)
    risk = "critical" if total >= 70 else "high" if total >= 50 else "medium" if total >= 30 else "low"
    return {"total_score": total, "breakdown": breakdown, "risk_level": risk}


def list_scored_alerts(
    status: str = "new", source: str = "", query: str = "",
    limit: int = 50, offset: int = 0,
    min_severity: str = "",
    published_after: str = "",
) -> dict[str, Any]:
    base = list_alerts(
        status=status,
        source=source,
        query=query,
        limit=100000,
        offset=0,
        min_severity=min_severity,
        published_after=published_after,
    )
    data = base.get("data", [])
    for alert in data:
        vuln = alert.get("vulnerability") or alert
        alert["threat_score"] = compute_threat_score(vuln)
    data.sort(key=lambda a: a.get("threat_score", {}).get("total_score", 0), reverse=True)
    total = len(data)
    base["total"] = total
    base["data"] = data[offset:offset + limit]
    return base


# ─── 分析任务控制 ──────────────────────────────────────────────

def cancel_vulnerability_analysis(vulnerability_id: int) -> dict[str, Any] | None:
    now = utc_now()
    with connection() as conn:
        row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone()
        if row is None:
            return None
        current_status = str(row["analysis_status"] or "idle")
        if current_status not in {"queued", "running"}:
            return None
        conn.execute("""
            UPDATE vulnerabilities
            SET analysis_status='canceled',
                analysis_cancel_requested=1,
                analysis_finished_at=?,
                analysis_error='canceled by user',
                analysis_failure_reason='用户取消'
            WHERE id=? AND analysis_status IN ('queued', 'running')
        """, (now, vulnerability_id))
        _create_analysis_event_conn(
            conn,
            vulnerability_id,
            str(row["analysis_run_id"] or ""),
            "cancel",
            "用户取消分析任务。",
            {"previous_status": current_status},
        )
        row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone()
        return None if row is None else _deserialize_vuln(dict(row))


def get_analysis_settings() -> dict[str, Any]:
    raw = get_setting("analysis_settings")
    fallback_concurrency = get_setting(ANALYSIS_CONCURRENCY_SETTING)
    default = {"max_concurrency": 2, "concurrency": 2, "default_priority": 50}
    if not raw:
        if fallback_concurrency:
            try:
                concurrency = max(1, min(int(fallback_concurrency), 10))
                return {**default, "max_concurrency": concurrency, "concurrency": concurrency}
            except ValueError:
                pass
        return default
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default
    try:
        concurrency = int(payload.get("max_concurrency", payload.get("concurrency", default["max_concurrency"])))
    except (TypeError, ValueError):
        concurrency = default["max_concurrency"]
    try:
        priority = int(payload.get("default_priority", default["default_priority"]))
    except (TypeError, ValueError):
        priority = default["default_priority"]
    concurrency = max(1, min(concurrency, 10))
    priority = max(0, min(priority, 100))
    return {"max_concurrency": concurrency, "concurrency": concurrency, "default_priority": priority}


def set_analysis_settings(payload: dict[str, Any]) -> dict[str, Any]:
    current = get_analysis_settings()
    merged = {**current, **payload}
    concurrency_value = merged.get("max_concurrency", merged.get("concurrency", current["max_concurrency"]))
    priority_value = merged.get("default_priority", current["default_priority"])
    try:
        concurrency = int(concurrency_value)
    except (TypeError, ValueError):
        concurrency = current["max_concurrency"]
    try:
        priority = int(priority_value)
    except (TypeError, ValueError):
        priority = current["default_priority"]
    merged["max_concurrency"] = max(1, min(10, concurrency))
    merged["concurrency"] = merged["max_concurrency"]
    merged["default_priority"] = max(0, min(100, priority))
    set_setting("analysis_settings", json.dumps(merged, ensure_ascii=False))
    return merged


def analysis_failure_stats() -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute("""
            SELECT COALESCE(NULLIF(analysis_failure_reason, ''), '分析失败') AS reason,
                   COUNT(*) AS count,
                   MAX(analysis_finished_at) AS last_failure_at
            FROM vulnerabilities
            WHERE analysis_status='failed' AND analysis_error != ''
            GROUP BY COALESCE(NULLIF(analysis_failure_reason, ''), '分析失败')
            ORDER BY count DESC, reason ASC LIMIT 30
        """).fetchall()
        return [dict(row) for row in rows]


def recover_interrupted_analysis() -> int:
    now = utc_now()
    with connection() as conn:
        cursor = conn.execute("""
            UPDATE vulnerabilities
            SET analysis_status='queued',
                analysis_requested_at=COALESCE(analysis_requested_at, ?),
                analysis_started_at=NULL,
                analysis_finished_at=NULL,
                analysis_error='',
                analysis_failure_reason='',
                analysis_run_id='',
                analysis_cancel_requested=0
            WHERE analysis_status='running'
        """, (now,))
        return cursor.rowcount


def requeue_failed_analysis_ids() -> list[int]:
    now = utc_now()
    ids: list[int] = []
    default_priority = get_analysis_settings().get("default_priority", 50)
    with connection() as conn:
        rows = conn.execute("SELECT id FROM vulnerabilities WHERE analysis_status='failed'").fetchall()
        for row in rows:
            conn.execute("""
                UPDATE vulnerabilities SET analysis_status='queued', analysis_requested_at=?,
                    analysis_started_at=NULL, analysis_finished_at=NULL,
                    analysis_error='', analysis_failure_reason='', analysis_run_id='',
                    analysis_cancel_requested=0, analysis_priority=?
                WHERE id=?
            """, (now, int(default_priority), row["id"]))
            _create_analysis_event_conn(
                conn,
                int(row["id"]),
                "",
                "queue",
                "失败分析已重新排队。",
                {"trigger": "requeue_failed"},
            )
            ids.append(int(row["id"]))
    return ids


def requeue_all_failed_analysis() -> int:
    return len(requeue_failed_analysis_ids())


def create_sbom_project(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    components = payload.get("components") or []
    if not isinstance(components, list):
        raise ValueError("components must be a list")
    now = utc_now()
    with connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO sbom_projects (name, version, supplier, created_at, updated_at, raw)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                name[:200],
                str(payload.get("version") or "").strip()[:120],
                str(payload.get("supplier") or "").strip()[:160],
                now,
                now,
                json.dumps({k: v for k, v in payload.items() if k != "components"}, ensure_ascii=False)[:12000],
            ),
        )
        project_id = int(cursor.lastrowid)
        for component in components[:5000]:
            if not isinstance(component, dict):
                continue
            component_name = str(component.get("name") or component.get("component") or "").strip()
            if not component_name:
                continue
            conn.execute(
                """
                INSERT INTO sbom_components (
                    project_id, name, version, supplier, purl, created_at, updated_at, raw
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id,
                    component_name[:220],
                    str(component.get("version") or "").strip()[:120],
                    str(component.get("supplier") or component.get("vendor") or "").strip()[:160],
                    str(component.get("purl") or component.get("package_url") or "").strip()[:500],
                    now,
                    now,
                    json.dumps(component, ensure_ascii=False)[:12000],
                ),
            )
        _match_sbom_project_conn(conn, project_id)
        return _sbom_project_detail_conn(conn, project_id) or {"id": project_id}


def list_sbom_projects(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    with connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS total FROM sbom_projects").fetchone()["total"]
        rows = conn.execute(
            """
            SELECT p.*,
                   COUNT(DISTINCT c.id) AS component_count,
                   COUNT(DISTINCT cv.vulnerability_id) AS vulnerability_count
            FROM sbom_projects p
            LEFT JOIN sbom_components c ON c.project_id = p.id
            LEFT JOIN sbom_component_vulnerabilities cv ON cv.project_id = p.id
            GROUP BY p.id
            ORDER BY p.updated_at DESC, p.id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        return {"total": total, "data": [_deserialize_sbom_project(row) for row in rows]}


def get_sbom_project(project_id: int) -> dict[str, Any] | None:
    with connection() as conn:
        return _sbom_project_detail_conn(conn, project_id)


def match_sbom_project(project_id: int) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute("SELECT id FROM sbom_projects WHERE id=?", (project_id,)).fetchone()
        if row is None:
            return None
        result = _match_sbom_project_conn(conn, project_id)
        detail = _sbom_project_detail_conn(conn, project_id) or {"id": project_id}
        detail["match_result"] = result
        return detail


def _deserialize_sbom_project(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["raw"] = _json_value(data.get("raw"), {})
    data["component_count"] = int(data.get("component_count") or 0)
    data["vulnerability_count"] = int(data.get("vulnerability_count") or 0)
    return data


def _sbom_project_detail_conn(conn: sqlite3.Connection, project_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT p.*,
               COUNT(DISTINCT c.id) AS component_count,
               COUNT(DISTINCT cv.vulnerability_id) AS vulnerability_count
        FROM sbom_projects p
        LEFT JOIN sbom_components c ON c.project_id = p.id
        LEFT JOIN sbom_component_vulnerabilities cv ON cv.project_id = p.id
        WHERE p.id=?
        GROUP BY p.id
        """,
        (project_id,),
    ).fetchone()
    if row is None:
        return None
    project = _deserialize_sbom_project(row)
    component_rows = conn.execute(
        """
        SELECT c.*,
               p.name AS product_name,
               COUNT(DISTINCT cv.vulnerability_id) AS vulnerability_count
        FROM sbom_components c
        LEFT JOIN products p ON p.product_key = c.product_key
        LEFT JOIN sbom_component_vulnerabilities cv ON cv.component_id = c.id
        WHERE c.project_id=?
        GROUP BY c.id
        ORDER BY vulnerability_count DESC, c.name COLLATE NOCASE ASC
        LIMIT 200
        """,
        (project_id,),
    ).fetchall()
    vuln_rows = conn.execute(
        """
        SELECT DISTINCT v.id, v.title, v.severity, v.cve_id, v.url, v.source,
               v.published_at, v.updated_at, v.first_seen_at
        FROM sbom_component_vulnerabilities cv
        JOIN vulnerabilities v ON v.id = cv.vulnerability_id
        WHERE cv.project_id=?
        ORDER BY COALESCE(v.published_at, v.updated_at, v.first_seen_at) DESC, v.id DESC
        LIMIT 50
        """,
        (project_id,),
    ).fetchall()
    project["components"] = [_deserialize_sbom_component(row) for row in component_rows]
    project["latest_vulnerabilities"] = [_vulnerability_summary_from_row(row) for row in vuln_rows]
    return project


def _deserialize_sbom_component(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["raw"] = _json_value(data.get("raw"), {})
    data["confidence"] = float(data.get("confidence") or 0)
    data["vulnerability_count"] = int(data.get("vulnerability_count") or 0)
    return data


def _match_sbom_project_conn(conn: sqlite3.Connection, project_id: int) -> dict[str, int]:
    now = utc_now()
    checked = matched_components = linked_vulnerabilities = 0
    components = conn.execute(
        "SELECT * FROM sbom_components WHERE project_id=?",
        (project_id,),
    ).fetchall()
    for component in components:
        checked += 1
        match = _resolve_component_product_conn(conn, dict(component))
        if not match:
            continue
        matched_components += 1
        conn.execute(
            """
            UPDATE sbom_components
            SET product_key=?, match_method=?, confidence=?, updated_at=?
            WHERE id=?
            """,
            (
                match["product_key"],
                match["match_method"],
                match["confidence"],
                now,
                component["id"],
            ),
        )
        vuln_rows = conn.execute(
            "SELECT vulnerability_id, evidence FROM product_vulnerabilities WHERE product_key=?",
            (match["product_key"],),
        ).fetchall()
        for vuln in vuln_rows:
            cursor = conn.execute(
                """
                INSERT INTO sbom_component_vulnerabilities (
                    project_id, component_id, vulnerability_id, product_key,
                    evidence, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, component_id, vulnerability_id) DO UPDATE SET
                    product_key=excluded.product_key,
                    evidence=excluded.evidence,
                    updated_at=excluded.updated_at
                """,
                (
                    project_id,
                    component["id"],
                    vuln["vulnerability_id"],
                    match["product_key"],
                    str(vuln["evidence"] or "")[:1000],
                    now,
                    now,
                ),
            )
            linked_vulnerabilities += 1 if cursor.rowcount else 0
    conn.execute(
        "UPDATE sbom_projects SET updated_at=? WHERE id=?",
        (now, project_id),
    )
    return {
        "checked_components": checked,
        "matched_components": matched_components,
        "linked_vulnerabilities": linked_vulnerabilities,
    }


def _resolve_component_product_conn(conn: sqlite3.Connection, component: dict[str, Any]) -> dict[str, Any] | None:
    names = [
        str(component.get("name") or ""),
        _name_from_purl(str(component.get("purl") or "")),
    ]
    for name in _unique_list([item for item in names if item]):
        normalized = _normalize_product_text(name)
        if not normalized:
            continue
        row = conn.execute(
            """
            SELECT product_key, name
            FROM products
            WHERE normalized_name=?
              AND COALESCE(merged_into_product_key, '') = ''
            ORDER BY vulnerability_count DESC
            LIMIT 1
            """,
            (normalized,),
        ).fetchone()
        if row is not None:
            return {
                "product_key": str(row["product_key"]),
                "match_method": "component_exact_product",
                "confidence": 0.95,
            }
        alias = conn.execute(
            """
            SELECT pa.product_key
            FROM product_aliases pa
            JOIN products p ON p.product_key = pa.product_key
            WHERE pa.normalized_alias=?
              AND COALESCE(p.merged_into_product_key, '') = ''
            ORDER BY p.vulnerability_count DESC
            LIMIT 1
            """,
            (normalized,),
        ).fetchone()
        if alias is not None:
            return {
                "product_key": _canonical_product_key_conn(conn, str(alias["product_key"])),
                "match_method": "component_alias_product",
                "confidence": 0.9,
            }
    return None


def _name_from_purl(purl: str) -> str:
    text = str(purl or "").strip()
    if not text:
        return ""
    tail = text.rsplit("/", 1)[-1]
    tail = tail.split("@", 1)[0]
    return tail.strip()


def get_model_settings() -> dict[str, Any]:
    flash_model = settings.anthropic_default_haiku_model
    pro_model = settings.anthropic_model or settings.anthropic_default_opus_model
    default = {
        "flash_model": flash_model,
        "pro_model": pro_model,
        "default_analysis_model": "pro",
        "product_attribution_model": flash_model,
        "source_triage_model": flash_model,
        "root_cause_model": pro_model,
        "poc_generation_model": pro_model,
        "fix_advice_model": pro_model,
        "daily_token_budget": 200000,
        "daily_cost_budget": 0,
        "structured_validation": True,
        "rag_enabled": True,
        "red_team_mode": False,
        "enhanced_exp_enabled": True,
    }
    raw = get_setting("model_settings")
    if not raw:
        return default
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default
    merged = {**default, **payload}
    for key in [
        "flash_model",
        "pro_model",
        "product_attribution_model",
        "source_triage_model",
        "root_cause_model",
        "poc_generation_model",
        "fix_advice_model",
    ]:
        merged[key] = str(merged.get(key) or default[key]).strip()[:120]
    if str(merged.get("default_analysis_model") or "").strip().lower() not in {"flash", "pro"}:
        merged["default_analysis_model"] = default["default_analysis_model"]
    else:
        merged["default_analysis_model"] = str(merged["default_analysis_model"]).strip().lower()
    for key in ["daily_token_budget"]:
        try:
            merged[key] = max(0, int(merged.get(key) or 0))
        except (TypeError, ValueError):
            merged[key] = default[key]
    try:
        merged["daily_cost_budget"] = max(0.0, float(merged.get("daily_cost_budget") or 0))
    except (TypeError, ValueError):
        merged["daily_cost_budget"] = default["daily_cost_budget"]
    merged["structured_validation"] = bool(merged.get("structured_validation"))
    merged["rag_enabled"] = bool(merged.get("rag_enabled"))
    merged["red_team_mode"] = bool(merged.get("red_team_mode"))
    merged["enhanced_exp_enabled"] = bool(merged.get("enhanced_exp_enabled"))
    return merged


def set_model_settings(payload: dict[str, Any]) -> dict[str, Any]:
    current = get_model_settings()
    allowed = set(current)
    merged = {**current, **{key: value for key, value in payload.items() if key in allowed}}
    for key in [
        "flash_model",
        "pro_model",
        "product_attribution_model",
        "source_triage_model",
        "root_cause_model",
        "poc_generation_model",
        "fix_advice_model",
    ]:
        merged[key] = str(merged.get(key) or current[key]).strip()[:120]
    default_choice = str(merged.get("default_analysis_model") or current.get("default_analysis_model") or "pro").strip().lower()
    merged["default_analysis_model"] = default_choice if default_choice in {"flash", "pro"} else "pro"
    try:
        merged["daily_token_budget"] = max(0, int(merged.get("daily_token_budget") or 0))
    except (TypeError, ValueError):
        merged["daily_token_budget"] = current["daily_token_budget"]
    try:
        merged["daily_cost_budget"] = max(0.0, float(merged.get("daily_cost_budget") or 0))
    except (TypeError, ValueError):
        merged["daily_cost_budget"] = current["daily_cost_budget"]
    merged["structured_validation"] = bool(merged.get("structured_validation"))
    merged["rag_enabled"] = bool(merged.get("rag_enabled"))
    merged["red_team_mode"] = bool(merged.get("red_team_mode"))
    merged["enhanced_exp_enabled"] = bool(merged.get("enhanced_exp_enabled"))
    set_setting("model_settings", json.dumps(merged, ensure_ascii=False))
    return merged


def record_model_usage(
    *,
    task_type: str,
    model: str,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    estimated_cost: float = 0.0,
    status: str = "success",
    raw: dict[str, Any] | None = None,
) -> None:
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO model_usage_events (
                task_type, model, prompt_tokens, completion_tokens,
                estimated_cost, status, created_at, raw
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(task_type or "analysis")[:80],
                str(model or "")[:120],
                max(0, int(prompt_tokens or 0)),
                max(0, int(completion_tokens or 0)),
                max(0.0, float(estimated_cost or 0)),
                str(status or "success")[:40],
                utc_now(),
                json.dumps(raw or {}, ensure_ascii=False)[:12000],
            ),
        )


def record_claude_model_usage(
    *,
    task_type: str,
    default_model: str,
    stdout_text: str,
    status: str = "success",
    raw: dict[str, Any] | None = None,
) -> int:
    payload = _json_from_text_for_usage(stdout_text)
    if not isinstance(payload, dict):
        return 0
    recorded = 0
    model_usage = payload.get("modelUsage")
    if isinstance(model_usage, dict) and model_usage:
        for model_name, usage in model_usage.items():
            if not isinstance(usage, dict):
                continue
            prompt_tokens = _usage_int(usage, "inputTokens") + _usage_int(usage, "cacheCreationInputTokens") + _usage_int(usage, "cacheReadInputTokens")
            completion_tokens = _usage_int(usage, "outputTokens")
            cost = _usage_float(usage, "costUSD")
            record_model_usage(
                task_type=task_type,
                model=str(model_name or default_model),
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                estimated_cost=cost,
                status=status,
                raw={
                    **(raw or {}),
                    "usage_source": "modelUsage",
                    "model_usage": usage,
                },
            )
            recorded += 1
        return recorded

    usage = payload.get("usage")
    if isinstance(usage, dict):
        cache_creation = usage.get("cache_creation")
        cache_creation_tokens = 0
        if isinstance(cache_creation, dict):
            cache_creation_tokens = _usage_int(cache_creation, "ephemeral_1h_input_tokens") + _usage_int(cache_creation, "ephemeral_5m_input_tokens")
        prompt_tokens = (
            _usage_int(usage, "input_tokens")
            + _usage_int(usage, "cache_creation_input_tokens")
            + _usage_int(usage, "cache_read_input_tokens")
            + cache_creation_tokens
        )
        completion_tokens = _usage_int(usage, "output_tokens") + _usage_int(usage, "completion_tokens")
        cost = _usage_float(payload, "total_cost_usd") or _usage_float(usage, "total_cost_usd") or _usage_float(usage, "estimated_cost")
        record_model_usage(
            task_type=task_type,
            model=default_model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            estimated_cost=cost,
            status=status,
            raw={
                **(raw or {}),
                "usage_source": "usage",
                "usage": usage,
            },
        )
        return 1
    return 0


def _json_from_text_for_usage(text: str) -> Any:
    cleaned = (text or "").strip()
    if not cleaned:
        return {}
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", cleaned, flags=re.S)
    if not match:
        return {}
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}


def _usage_int(payload: dict[str, Any], key: str) -> int:
    try:
        return max(0, int(payload.get(key) or 0))
    except (TypeError, ValueError):
        return 0


def _usage_float(payload: dict[str, Any], key: str) -> float:
    try:
        return max(0.0, float(payload.get(key) or 0))
    except (TypeError, ValueError):
        return 0.0


def _model_usage_recorded(run_id: str) -> bool:
    marker = str(run_id or "").strip()
    if not marker:
        return False
    with connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM model_usage_events WHERE raw LIKE ?",
            (f"%{marker}%",),
        ).fetchone()
        return bool(row and int(row["n"] or 0) > 0)


def model_usage_recorded_for_run(run_id: str) -> bool:
    return _model_usage_recorded(run_id)


def backfill_model_usage_from_analysis_raw(limit: int = 200) -> dict[str, int]:
    checked = recorded = skipped = 0
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, analysis_run_id, analysis_model, analysis_raw
            FROM vulnerabilities
            WHERE analysis_status='finished'
              AND COALESCE(analysis_run_id, '') <> ''
              AND COALESCE(analysis_raw, '') <> ''
            ORDER BY COALESCE(analysis_finished_at, last_seen_at) DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(int(limit or 200), 1000)),),
        ).fetchall()
    for row in rows:
        checked += 1
        run_id = str(row["analysis_run_id"] or "")
        if _model_usage_recorded(run_id):
            skipped += 1
            continue
        raw = _json_value(row["analysis_raw"], {})
        if not isinstance(raw, dict):
            continue
        count = record_claude_model_usage(
            task_type="deep_analysis",
            default_model=str(row["analysis_model"] or ""),
            stdout_text=str(raw.get("stdout") or ""),
            status="success",
            raw={"run_id": run_id, "vulnerability_id": row["id"], "backfilled": True},
        )
        recorded += count
    return {"checked": checked, "recorded": recorded, "skipped": skipped}


def model_usage_summary(hours: int = 24) -> dict[str, Any]:
    backfill_model_usage_from_analysis_raw(limit=200)
    hours = max(1, min(int(hours or 24), 24 * 30))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT task_type,
                   model,
                   COUNT(*) AS calls,
                   SUM(prompt_tokens) AS prompt_tokens,
                   SUM(completion_tokens) AS completion_tokens,
                   SUM(estimated_cost) AS estimated_cost
            FROM model_usage_events
            WHERE created_at >= ?
            GROUP BY task_type, model
            ORDER BY calls DESC
            """,
            (cutoff,),
        ).fetchall()
    settings_payload = get_model_settings()
    total_tokens = sum(int(row["prompt_tokens"] or 0) + int(row["completion_tokens"] or 0) for row in rows)
    total_cost = sum(float(row["estimated_cost"] or 0) for row in rows)
    return {
        "hours": hours,
        "settings": settings_payload,
        "total_tokens": total_tokens,
        "total_cost": round(total_cost, 6),
        "token_budget_remaining": max(0, int(settings_payload["daily_token_budget"]) - total_tokens),
        "cost_budget_remaining": (
            None
            if float(settings_payload["daily_cost_budget"] or 0) <= 0
            else max(0.0, float(settings_payload["daily_cost_budget"]) - total_cost)
        ),
        "data": [dict(row) for row in rows],
    }


def add_rag_note(payload: dict[str, Any]) -> dict[str, Any]:
    title = str(payload.get("title") or "").strip()
    content = str(payload.get("content") or "").strip()
    if not title and content:
        title = content[:80]
    if not title:
        raise ValueError("title is required")
    tags = payload.get("tags") or []
    if isinstance(tags, str):
        tags = [item.strip() for item in tags.replace("\n", ",").split(",") if item.strip()]
    if not isinstance(tags, list):
        tags = []
    now = utc_now()
    with connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO rag_notes (scope, title, content, tags, related_key, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(payload.get("scope") or "analysis").strip()[:80],
                title[:200],
                content[:20000],
                json.dumps(tags[:20], ensure_ascii=False),
                str(payload.get("related_key") or "").strip()[:240],
                now,
                now,
            ),
        )
        row = conn.execute("SELECT * FROM rag_notes WHERE id=?", (cursor.lastrowid,)).fetchone()
        return _deserialize_rag_note(row)


def list_rag_notes(scope: str = "", query: str = "", limit: int = 50, offset: int = 0) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    clauses: list[str] = []
    args: list[Any] = []
    if scope:
        clauses.append("scope=?")
        args.append(scope)
    if query:
        like = f"%{query}%"
        clauses.append("(title LIKE ? OR content LIKE ? OR tags LIKE ? OR related_key LIKE ?)")
        args.extend([like, like, like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS total FROM rag_notes {where}", args).fetchone()["total"]
        rows = conn.execute(
            f"""
            SELECT *
            FROM rag_notes
            {where}
            ORDER BY updated_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*args, limit, offset],
        ).fetchall()
        return {"total": total, "data": [_deserialize_rag_note(row) for row in rows]}


def _deserialize_rag_note(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    data["tags"] = _json_value(data.get("tags"), [])
    return data
