#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import tempfile
from typing import Any
import zipfile
from datetime import datetime, timezone


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app import db


DIST_DIR = ROOT_DIR / "dist"
LOCAL_HOSTNAME = socket.gethostname()
LOCAL_MARKERS = sorted(
    {
        str(ROOT_DIR),
        str(ROOT_DIR.parent),
        str(Path.home()),
        os.environ.get("USER", ""),
        os.environ.get("LOGNAME", ""),
        LOCAL_HOSTNAME,
    }
    - {""},
    key=len,
    reverse=True,
)

COPY_ROOTS = [
    "backend/app",
    "frontend",
    "docs",
    "scripts",
    "deploy",
]

COPY_FILES = [
    ".dockerignore",
    ".env.example",
    ".env.docker.example",
    ".gitignore",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.infra.yml",
    "README.md",
    "requirements.txt",
    "start.sh",
    "start.command",
]

EXCLUDED_DIR_NAMES = {
    "__pycache__",
    ".git",
    ".venv",
    "dist",
    "backend/data",
    "node_modules",
}

EXCLUDED_FILE_NAMES = {
    ".DS_Store",
    ".env",
    ".env.docker",
    "capture.pcap",
}

TABLE_EXPORTS: dict[str, dict[str, Any]] = {
    "sources": {
        "columns": [
            "name",
            "title",
            "category",
            "schedule",
            "enabled",
            "last_run_at",
            "last_status",
            "last_item_count",
            "created_at",
            "updated_at",
        ],
        "where": "",
        "order": "name ASC",
    },
    "products": {
        "columns": [
            "product_key",
            "source",
            "source_uid",
            "name",
            "normalized_name",
            "url",
            "vulnerability_count",
            "poc_count",
            "first_seen_at",
            "last_seen_at",
            "last_crawled_at",
            "vendor",
            "merged_into_product_key",
            "merge_note",
        ],
        "where": "COALESCE(merged_into_product_key, '') = ''",
        "order": "vulnerability_count DESC, name ASC",
    },
    "product_aliases": {
        "columns": [
            "id",
            "product_key",
            "alias",
            "normalized_alias",
            "vendor",
            "created_at",
            "updated_at",
        ],
        "where": "product_key IN (SELECT product_key FROM products WHERE COALESCE(merged_into_product_key, '') = '')",
        "order": "product_key ASC, alias ASC",
    },
    "vendor_aliases": {
        "columns": [
            "id",
            "vendor_key",
            "vendor",
            "alias",
            "normalized_alias",
            "created_at",
            "updated_at",
        ],
        "where": "",
        "order": "vendor_key ASC, alias ASC",
    },
    "vulnerabilities": {
        "columns": [
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
            "first_seen_at",
            "last_seen_at",
            "cvss_score",
            "cvss_version",
            "cvss_vector",
            "poc_available",
            "poc_url",
            "exp_available",
            "exp_url",
            "dedupe_key",
            "analysis_source_found",
            "analysis_source_url",
            "analysis_source_title",
            "quality_score",
            "quality_level",
            "quality_reason",
            "quality_updated_at",
            "product_match_method",
            "product_match_confidence",
            "product_match_evidence",
            "product_resolved_at",
        ],
        "where": "",
        "order": "id ASC",
    },
    "alerts": {
        "columns": [
            "id",
            "vulnerability_id",
            "dedupe_key",
            "status",
            "reason",
            "created_at",
            "updated_at",
            "acknowledged_at",
        ],
        "where": "",
        "order": "id ASC",
    },
    "product_vulnerabilities": {
        "columns": [
            "product_key",
            "vulnerability_id",
            "product_name",
            "match_method",
            "confidence",
            "evidence",
            "created_at",
            "updated_at",
            "evidence_type",
            "source_count",
        ],
        "where": "product_key IN (SELECT product_key FROM products WHERE COALESCE(merged_into_product_key, '') = '')",
        "order": "product_key ASC, vulnerability_id ASC",
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a sanitized ZhuWei release package with current seed data.")
    parser.add_argument("--name", default="", help="Optional package directory name.")
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
    package_name = args.name.strip() or f"zhuwei-release-data-sanitized-{stamp}"
    out_dir = DIST_DIR / package_name
    zip_path = DIST_DIR / f"{package_name}.zip"
    filelist_path = DIST_DIR / f"{package_name}.filelist"
    sha_path = DIST_DIR / f"{package_name}.zip.sha256"

    if out_dir.exists():
        shutil.rmtree(out_dir)
    for path in [zip_path, filelist_path, sha_path]:
        if path.exists():
            path.unlink()
    out_dir.mkdir(parents=True)

    _copy_project_files(out_dir)
    manifest = _export_seed_data(out_dir / "seed-data")
    _write_current_stats(out_dir / "CURRENT_STATS.md", manifest)

    leaks = _scan_sensitive_text(out_dir)
    if leaks:
        sample = "\n".join(leaks[:20])
        raise SystemExit(f"Sensitive local markers detected in package output:\n{sample}")

    files = _zip_dir(out_dir, zip_path)
    filelist_path.write_text("\n".join(files) + "\n", encoding="utf-8")
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    sha_path.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")

    print(json.dumps({
        "package": _rel(zip_path),
        "directory": _rel(out_dir),
        "sha256": digest,
        "manifest": manifest,
    }, ensure_ascii=False, indent=2))


def _copy_project_files(out_dir: Path) -> None:
    for rel in COPY_ROOTS:
        src = ROOT_DIR / rel
        if src.is_dir():
            shutil.copytree(src, out_dir / rel, ignore=_copy_ignore)
    for rel in COPY_FILES:
        src = ROOT_DIR / rel
        if src.is_file():
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)


def _copy_ignore(directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        if name in EXCLUDED_FILE_NAMES or name in EXCLUDED_DIR_NAMES:
            ignored.add(name)
            continue
        candidate = Path(directory) / name
        rel = _rel(candidate)
        if rel.startswith("backend/data") or "/__pycache__/" in f"/{rel}/":
            ignored.add(name)
    return ignored


def _export_seed_data(seed_dir: Path) -> dict[str, Any]:
    postgres_dir = seed_dir / "postgres"
    neo4j_dir = seed_dir / "neo4j"
    postgres_dir.mkdir(parents=True, exist_ok=True)
    neo4j_dir.mkdir(parents=True, exist_ok=True)

    exported_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest: dict[str, Any] = {
        "package": "zhuwei sanitized release seed data",
        "exported_at": exported_at,
        "business_counts": {},
        "postgres_tables": {},
        "excluded": {
            "files": [
                ".env",
                ".env.docker",
                "backend/data",
                ".venv",
                "dist",
                "runtime logs",
                "analysis workspaces",
                "source upload contents",
                "update job workspaces",
            ],
            "tables": [
                "app_settings",
                "messages",
                "analysis_events",
                "analysis_feedback",
                "deepseek_balance_checks",
                "model_usage_events",
                "runs",
                "source_archives",
                "rag_notes",
                "sbom_projects",
                "sbom_components",
                "sbom_component_vulnerabilities",
            ],
            "columns": [
                "raw",
                "poc_content",
                "exp_content",
                "analysis_raw",
                "analysis_summary",
                "analysis_sources",
                "analysis_error",
                "analysis_source_local_path",
                "analysis_source_archive_path",
                "minio_*",
                "local_path",
                "extracted_path",
            ],
        },
        "redaction": {
            "local_paths": "replaced or excluded",
            "computer_name": "not recorded",
            "api_keys": "not exported",
            "cookies_sessions": "not exported",
        },
        "notes": [
            "The SQL dump is data-only; initialize the app schema before import.",
            "Neo4j graph data can be rebuilt from PostgreSQL with /api/graph/sync; graph.json is a sanitized portable snapshot.",
            "Generated POC/EXP bodies, model conversations, source code uploads and local filesystem paths are intentionally excluded.",
        ],
    }

    with db.connection() as conn:
        manifest["business_counts"] = _business_counts(conn)
        sql_lines = [
            "-- Sanitized seed data for ZhuWei",
            f"-- Exported at: {exported_at}",
            "-- Import after the application has initialized the PostgreSQL schema.",
            "BEGIN;",
        ]
        exported_rows: dict[str, list[dict[str, Any]]] = {}
        for table, spec in TABLE_EXPORTS.items():
            rows, columns = _export_table(conn, table, spec, postgres_dir)
            exported_rows[table] = rows
            manifest["postgres_tables"][table] = {
                "rows": len(rows),
                "columns": columns,
                "jsonl": f"postgres/{table}.jsonl",
            }
            sql_lines.append(f"-- {table}: {len(rows)} rows")
            sql_lines.extend(_insert_lines(table, columns, rows))
            if "id" in columns:
                sql_lines.append(
                    "SELECT setval(pg_get_serial_sequence('%s','id'), "
                    "GREATEST(COALESCE((SELECT MAX(id) FROM \"%s\"), 1), 1), true) "
                    "WHERE pg_get_serial_sequence('%s','id') IS NOT NULL;"
                    % (table, table, table)
                )
        sql_lines.append("COMMIT;")
        (postgres_dir / "open-data.sql").write_text("\n".join(sql_lines) + "\n", encoding="utf-8")
        manifest["postgres_sql"] = "postgres/open-data.sql"
        graph = _build_graph_snapshot(exported_rows)
        (neo4j_dir / "graph.json").write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest["neo4j"] = {
            "nodes": len(graph["nodes"]),
            "relationships": len(graph["relationships"]),
            "json": "neo4j/graph.json",
        }

    (seed_dir / "README.md").write_text(_seed_readme(manifest), encoding="utf-8")
    (seed_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def _business_counts(conn: Any) -> dict[str, Any]:
    counts = {
        "vulnerabilities": _count(conn, "SELECT COUNT(*) AS n FROM vulnerabilities"),
        "alerts": _count(conn, "SELECT COUNT(*) AS n FROM alerts"),
        "alerts_new": _count(conn, "SELECT COUNT(*) AS n FROM alerts WHERE status='new'"),
        "alerts_acknowledged": _count(conn, "SELECT COUNT(*) AS n FROM alerts WHERE status='acknowledged'"),
        "products_effective": _count(
            conn,
            """
            SELECT COUNT(*) AS n
            FROM products p
            WHERE COALESCE(p.merged_into_product_key, '') = ''
              AND (
                p.source='source_archives'
                OR EXISTS (SELECT 1 FROM product_vulnerabilities pv WHERE pv.product_key=p.product_key)
                OR EXISTS (SELECT 1 FROM followed_products fp WHERE fp.product_key=p.product_key)
              )
            """,
        ),
        "products_catalog_visible": _count(
            conn,
            "SELECT COUNT(*) AS n FROM products WHERE COALESCE(merged_into_product_key, '') = ''",
        ),
        "products_hidden_or_merged": _count(
            conn,
            "SELECT COUNT(*) AS n FROM products WHERE COALESCE(merged_into_product_key, '') <> ''",
        ),
        "product_vulnerability_links": _count(
            conn,
            """
            SELECT COUNT(*) AS n
            FROM product_vulnerabilities pv
            JOIN products p ON p.product_key=pv.product_key
            WHERE COALESCE(p.merged_into_product_key, '') = ''
            """,
        ),
        "products_with_links": _count(
            conn,
            """
            SELECT COUNT(DISTINCT pv.product_key) AS n
            FROM product_vulnerabilities pv
            JOIN products p ON p.product_key=pv.product_key
            WHERE COALESCE(p.merged_into_product_key, '') = ''
            """,
        ),
        "sources_enabled": _count(conn, "SELECT COUNT(*) AS n FROM sources WHERE enabled=1"),
    }
    counts["by_alert_status"] = [
        dict(row)
        for row in conn.execute(
            "SELECT status, COUNT(*) AS count FROM alerts GROUP BY status ORDER BY status ASC"
        ).fetchall()
    ]
    counts["by_severity"] = [
        dict(row)
        for row in conn.execute(
            """
            SELECT COALESCE(severity, 'unknown') AS severity, COUNT(*) AS count
            FROM vulnerabilities
            GROUP BY COALESCE(severity, 'unknown')
            ORDER BY count DESC
            """
        ).fetchall()
    ]
    return counts


def _count(conn: Any, sql: str) -> int:
    return int(conn.execute(sql).fetchone()["n"] or 0)


def _export_table(conn: Any, table: str, spec: dict[str, Any], out_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    existing = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    columns = [column for column in spec["columns"] if column in existing]
    if not columns:
        return [], []
    where = f"WHERE {spec['where']}" if spec.get("where") else ""
    order = f"ORDER BY {spec['order']}" if spec.get("order") else ""
    rows = [
        {column: _sanitize_value(row[column]) for column in columns}
        for row in conn.execute(
            f"SELECT {', '.join(_quote_ident(column) for column in columns)} FROM {_quote_ident(table)} {where} {order}"
        ).fetchall()
    ]
    with (out_dir / f"{table}.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return rows, columns


def _insert_lines(table: str, columns: list[str], rows: list[dict[str, Any]]) -> list[str]:
    if not columns:
        return []
    column_sql = ", ".join(_quote_ident(column) for column in columns)
    lines = []
    for row in rows:
        values = ", ".join(_sql_literal(row.get(column)) for column in columns)
        lines.append(f"INSERT INTO {_quote_ident(table)} ({column_sql}) VALUES ({values}) ON CONFLICT DO NOTHING;")
    return lines


def _build_graph_snapshot(exported_rows: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    products = {
        row["product_key"]: row
        for row in exported_rows.get("products", [])
        if row.get("product_key") and not row.get("merged_into_product_key")
    }
    vulnerabilities = {
        int(row["id"]): row
        for row in exported_rows.get("vulnerabilities", [])
        if row.get("id") is not None
    }
    nodes: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    for key, row in products.items():
        nodes.append({
            "id": f"product:{key}",
            "labels": ["Product"],
            "properties": {k: row.get(k) for k in ["product_key", "name", "source", "vendor", "url", "vulnerability_count", "poc_count"]},
        })
    for vuln_id, row in vulnerabilities.items():
        nodes.append({
            "id": f"vulnerability:{vuln_id}",
            "labels": ["Vulnerability"],
            "properties": {k: row.get(k) for k in ["id", "title", "severity", "cve_id", "source", "url", "published_at", "poc_available", "exp_available"]},
        })
    for row in exported_rows.get("alerts", []):
        alert_id = row.get("id")
        vuln_id = row.get("vulnerability_id")
        if alert_id is None or vuln_id not in vulnerabilities:
            continue
        nodes.append({
            "id": f"alert:{alert_id}",
            "labels": ["Alert"],
            "properties": {k: row.get(k) for k in ["id", "status", "reason", "created_at", "updated_at"]},
        })
        relationships.append({
            "id": f"alert:{alert_id}->vulnerability:{vuln_id}",
            "type": "FOR",
            "source": f"alert:{alert_id}",
            "target": f"vulnerability:{vuln_id}",
            "properties": {},
        })
    for row in exported_rows.get("product_vulnerabilities", []):
        key = row.get("product_key")
        vuln_id = row.get("vulnerability_id")
        if key not in products or vuln_id not in vulnerabilities:
            continue
        relationships.append({
            "id": f"vulnerability:{vuln_id}->product:{key}",
            "type": "AFFECTS",
            "source": f"vulnerability:{vuln_id}",
            "target": f"product:{key}",
            "properties": {k: row.get(k) for k in ["confidence", "match_method", "evidence_type", "source_count", "updated_at"]},
        })
    return {
        "format": "zhuwei.graph.snapshot.v1",
        "nodes": nodes,
        "relationships": relationships,
    }


def _write_current_stats(path: Path, manifest: dict[str, Any]) -> None:
    counts = manifest["business_counts"]
    path.write_text(
        "\n".join([
            "# ZhuWei Current Release Stats",
            "",
            f"- Exported at: `{manifest['exported_at']}`",
            f"- Vulnerabilities: `{counts.get('vulnerabilities', 0)}`",
            f"- Alerts: `{counts.get('alerts', 0)}`",
            f"- New alerts: `{counts.get('alerts_new', 0)}`",
            f"- Effective products: `{counts.get('products_effective', 0)}`",
            f"- Visible product catalog: `{counts.get('products_catalog_visible', 0)}`",
            f"- Hidden or merged products: `{counts.get('products_hidden_or_merged', 0)}`",
            f"- Product-vulnerability links: `{counts.get('product_vulnerability_links', 0)}`",
            "",
            "This package intentionally excludes local machine names, local filesystem paths, `.env`, API keys, cookies, sessions, logs, model conversations, source upload contents, and generated POC/EXP bodies.",
            "",
        ]),
        encoding="utf-8",
    )


def _seed_readme(manifest: dict[str, Any]) -> str:
    counts = manifest["business_counts"]
    return "\n".join([
        "# Seed Data Bundle",
        "",
        "This directory contains sanitized release seed data exported from ZhuWei.",
        "",
        "## Current Counts",
        "",
        f"- Vulnerabilities: `{counts.get('vulnerabilities', 0)}`",
        f"- Alerts: `{counts.get('alerts', 0)}`",
        f"- New alerts: `{counts.get('alerts_new', 0)}`",
        f"- Effective products: `{counts.get('products_effective', 0)}`",
        f"- Visible product catalog: `{counts.get('products_catalog_visible', 0)}`",
        f"- Hidden or merged products: `{counts.get('products_hidden_or_merged', 0)}`",
        "",
        "## Contents",
        "",
        "- `postgres/open-data.sql`: PostgreSQL data-only seed dump.",
        "- `postgres/*.jsonl`: JSONL exports for the same public seed tables.",
        "- `neo4j/graph.json`: Sanitized portable graph snapshot.",
        "- `manifest.json`: Export counts, included columns, excluded data and redaction notes.",
        "",
        "## Excluded",
        "",
        "No `.env`, local database files, API keys, cookies, sessions, runtime logs, model conversations, source upload contents, local paths, machine names, or generated POC/EXP bodies are included.",
        "",
    ])


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_text(value)
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _sanitize_value(child) for key, child in value.items() if not _sensitive_key(str(key))}
    return value


def _sanitize_text(text: str) -> str:
    if not text:
        return ""
    result = text
    for marker in LOCAL_MARKERS:
        result = result.replace(marker, "<redacted>")
    result = re.sub(r"/Users/[^\\s'\"<>]+", "<redacted-path>", result)
    result = re.sub(r"/home/[^\\s'\"<>]+", "<redacted-path>", result)
    result = re.sub(r"[A-Za-z]:\\\\Users\\\\[^\\s'\"<>]+", "<redacted-path>", result)
    result = re.sub(r"(?i)(api[_-]?key|auth[_-]?token|secret|password|cookie|session)\\s*[:=]\\s*[^\\s,;]+", r"\1=<redacted>", result)
    result = re.sub(r"(?i)bearer\\s+[A-Za-z0-9._~+/=-]{12,}", "Bearer <redacted>", result)
    result = re.sub(r"\bsk-[A-Za-z0-9._-]{12,}", "sk-<redacted>", result)
    return result


def _sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in ["api_key", "token", "secret", "password", "cookie", "session"])


def _scan_sensitive_text(root: Path) -> list[str]:
    patterns = [
        re.escape(str(ROOT_DIR)),
        re.escape(str(Path.home())),
        re.escape(os.environ.get("USER", "")) if os.environ.get("USER") else r"$^",
        re.escape(LOCAL_HOSTNAME) if LOCAL_HOSTNAME else r"$^",
        r"^\s*(?:export\s+)?DEEPSEEK_API_KEY\s*=\s*(?!\.\.\.)(?!<)[^\s#]{16,}",
        r"^\s*(?:export\s+)?ANTHROPIC_AUTH_TOKEN\s*=\s*(?!\.\.\.)(?!<)[^\s#]{16,}",
        r"\bsk-[A-Za-z0-9._-]{12,}",
    ]
    combined = re.compile("|".join(f"(?:{pattern})" for pattern in patterns))
    leaks: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".zip"}:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for index, line in enumerate(handle, 1):
                    if combined.search(line):
                        leaks.append(f"{_rel(path)}:{index}")
                        break
        except OSError:
            continue
    return leaks


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = str(value).replace("'", "''")
    return f"'{text}'"


def _quote_ident(value: str) -> str:
    return '"' + str(value).replace('"', '""') + '"'


def _zip_dir(source: Path, output: Path) -> list[str]:
    files: list[str] = []
    base = source.parent
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source.rglob("*")):
            if path.is_dir():
                continue
            arcname = path.relative_to(base).as_posix()
            zf.write(path, arcname)
            files.append(arcname)
    return files


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return path.name


if __name__ == "__main__":
    main()
