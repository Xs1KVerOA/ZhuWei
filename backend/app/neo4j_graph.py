from __future__ import annotations

import json
from typing import Any

from . import db
from .config import settings


def neo4j_configured() -> bool:
    return bool(settings.neo4j_enabled and settings.neo4j_uri and settings.neo4j_user and settings.neo4j_password)


def graph_status() -> dict[str, Any]:
    if not neo4j_configured():
        return {
            "configured": False,
            "available": False,
            "uri": settings.neo4j_uri,
            "database": settings.neo4j_database,
            "nodes": 0,
            "relationships": 0,
            "error": "",
        }
    try:
        with _driver() as driver:
            with _session(driver) as session:
                row = session.run(
                    """
                    CALL () {
                      MATCH (n)
                      RETURN count(n) AS nodes
                    }
                    CALL () {
                      MATCH ()-[r]->()
                      RETURN count(r) AS relationships
                    }
                    RETURN nodes, relationships
                    """
                ).single()
        return {
            "configured": True,
            "available": True,
            "uri": settings.neo4j_uri,
            "database": settings.neo4j_database,
            "nodes": int(row["nodes"] or 0) if row else 0,
            "relationships": int(row["relationships"] or 0) if row else 0,
            "error": "",
        }
    except Exception as exc:
        return {
            "configured": True,
            "available": False,
            "uri": settings.neo4j_uri,
            "database": settings.neo4j_database,
            "nodes": 0,
            "relationships": 0,
            "error": str(exc)[:500],
        }


def sync_graph(*, limit: int = 800) -> dict[str, Any]:
    if not neo4j_configured():
        raise RuntimeError("Neo4j is not configured")
    payload = _graph_sync_payload(limit=max(50, min(int(limit or 800), 5000)))
    with _driver() as driver:
        with _session(driver) as session:
            session.execute_write(_ensure_graph_schema)
            session.execute_write(_sync_products, payload["products"])
            session.execute_write(_sync_vulnerabilities, payload["vulnerabilities"])
            session.execute_write(_sync_product_vulnerabilities, payload["product_vulnerabilities"])
            session.execute_write(_sync_alerts, payload["alerts"])
            session.execute_write(_sync_source_archives, payload["source_archives"])
    status = graph_status()
    return {
        "status": "ok",
        "synced": {key: len(value) for key, value in payload.items()},
        "graph": status,
    }


def vulnerability_neighborhood(vulnerability_id: int, *, depth: int = 2) -> dict[str, Any]:
    return _neighborhood("Vulnerability", "id", int(vulnerability_id), depth=depth)


def product_neighborhood(product_key: str, *, depth: int = 2) -> dict[str, Any]:
    return _neighborhood("Product", "key", product_key, depth=depth)


def _neighborhood(label: str, key: str, value: Any, *, depth: int = 2) -> dict[str, Any]:
    if not neo4j_configured():
        raise RuntimeError("Neo4j is not configured")
    depth = max(1, min(int(depth or 2), 4))
    query = f"""
    MATCH (center:{label} {{{key}: $value}})
    OPTIONAL MATCH path=(center)-[*1..{depth}]-(n)
    WITH center, collect(path) AS paths
    WITH center, [p IN paths WHERE p IS NOT NULL] AS realPaths
    WITH CASE WHEN size(realPaths) = 0 THEN [center] ELSE
         reduce(nodesAcc = [center], p IN realPaths | nodesAcc + nodes(p)) END AS rawNodes,
         realPaths
    UNWIND rawNodes AS node
    WITH collect(DISTINCT node) AS nodes, realPaths
    CALL {{
      WITH realPaths
      UNWIND realPaths AS path
      UNWIND relationships(path) AS rel
      RETURN collect(DISTINCT rel) AS relationships
    }}
    RETURN
      [node IN nodes | {{
        id: elementId(node),
        labels: labels(node),
        properties: properties(node)
      }}] AS nodes,
      [rel IN relationships | {{
        id: elementId(rel),
        type: type(rel),
        source: elementId(startNode(rel)),
        target: elementId(endNode(rel)),
        properties: properties(rel)
      }}] AS relationships
    """
    with _driver() as driver:
        with _session(driver) as session:
            row = session.run(query, value=value).single()
    return {
        "nodes": row["nodes"] if row else [],
        "relationships": row["relationships"] if row else [],
    }


def _driver():
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise RuntimeError("neo4j Python driver is not installed") from exc
    return GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))


def _session(driver: Any):
    if settings.neo4j_database:
        return driver.session(database=settings.neo4j_database)
    return driver.session()


def _ensure_graph_schema(tx: Any) -> None:
    constraints = [
        "CREATE CONSTRAINT zhuwei_vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
        "CREATE CONSTRAINT zhuwei_product_key IF NOT EXISTS FOR (p:Product) REQUIRE p.key IS UNIQUE",
        "CREATE CONSTRAINT zhuwei_alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
        "CREATE CONSTRAINT zhuwei_source_archive_id IF NOT EXISTS FOR (s:SourceArchive) REQUIRE s.id IS UNIQUE",
        "CREATE CONSTRAINT zhuwei_data_source_name IF NOT EXISTS FOR (s:DataSource) REQUIRE s.name IS UNIQUE",
        "CREATE CONSTRAINT zhuwei_vendor_name IF NOT EXISTS FOR (v:Vendor) REQUIRE v.name IS UNIQUE",
    ]
    for statement in constraints:
        tx.run(statement)


def _sync_products(tx: Any, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (p:Product {key: row.product_key})
        SET p.name = row.name,
            p.normalized_name = row.normalized_name,
            p.vendor = row.vendor,
            p.source = row.source,
            p.url = row.url,
            p.vulnerability_count = row.vulnerability_count,
            p.poc_count = row.poc_count,
            p.last_seen_at = row.last_seen_at,
            p.last_crawled_at = row.last_crawled_at
        """,
        rows=rows,
    )
    tx.run(
        """
        UNWIND $rows AS row
        WITH row WHERE row.vendor <> ''
        MATCH (p:Product {key: row.product_key})
        MERGE (v:Vendor {name: row.vendor})
        MERGE (v)-[:OWNS]->(p)
        """,
        rows=rows,
    )


def _sync_vulnerabilities(tx: Any, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (v:Vulnerability {id: row.id})
        SET v.title = row.title,
            v.severity = row.severity,
            v.cve_id = row.cve_id,
            v.source = row.source,
            v.product = row.product,
            v.url = row.url,
            v.published_at = row.published_at,
            v.updated_at = row.updated_at,
            v.poc_available = row.poc_available,
            v.exp_available = row.exp_available,
            v.analysis_status = row.analysis_status,
            v.quality_score = row.quality_score
        WITH row, v
        WHERE row.source <> ''
        MERGE (s:DataSource {name: row.source})
        MERGE (s)-[:REPORTED]->(v)
        """,
        rows=rows,
    )


def _sync_product_vulnerabilities(tx: Any, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    tx.run(
        """
        UNWIND $rows AS row
        MATCH (p:Product {key: row.product_key})
        MATCH (v:Vulnerability {id: row.vulnerability_id})
        MERGE (v)-[r:AFFECTS]->(p)
        SET r.confidence = row.confidence,
            r.match_method = row.match_method,
            r.evidence_type = row.evidence_type,
            r.source_count = row.source_count,
            r.updated_at = row.updated_at
        """,
        rows=rows,
    )


def _sync_alerts(tx: Any, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (a:Alert {id: row.id})
        SET a.status = row.status,
            a.reason = row.reason,
            a.created_at = row.created_at,
            a.updated_at = row.updated_at
        WITH row, a
        MATCH (v:Vulnerability {id: row.vulnerability_id})
        MERGE (a)-[:FOR]->(v)
        """,
        rows=rows,
    )


def _sync_source_archives(tx: Any, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    tx.run(
        """
        UNWIND $rows AS row
        MERGE (s:SourceArchive {id: row.id})
        SET s.filename = row.filename,
            s.origin = row.origin,
            s.status = row.status,
            s.minio_status = row.minio_status,
            s.product_name = row.product_name,
            s.suggested_product_name = row.suggested_product_name,
            s.created_at = row.created_at,
            s.updated_at = row.updated_at
        """,
        rows=rows,
    )
    tx.run(
        """
        UNWIND $rows AS row
        WITH row WHERE row.product_key <> ''
        MATCH (s:SourceArchive {id: row.id})
        MATCH (p:Product {key: row.product_key})
        MERGE (s)-[:EVIDENCES]->(p)
        """,
        rows=rows,
    )
    tx.run(
        """
        UNWIND $rows AS row
        WITH row WHERE row.vulnerability_id IS NOT NULL
        MATCH (s:SourceArchive {id: row.id})
        MATCH (v:Vulnerability {id: row.vulnerability_id})
        MERGE (s)-[:SOURCE_FOR]->(v)
        """,
        rows=rows,
    )


def _graph_sync_payload(limit: int) -> dict[str, list[dict[str, Any]]]:
    with db.connection() as conn:
        vulnerabilities = [
            _clean_vulnerability_row(dict(row))
            for row in conn.execute(
                """
                SELECT id, title, severity, cve_id, source, product, url,
                       published_at, updated_at, poc_available, exp_available,
                       analysis_status, quality_score
                FROM vulnerabilities
                ORDER BY COALESCE(published_at, updated_at, first_seen_at) DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
        recent_product_vulnerabilities = [
            dict(row)
            for row in conn.execute(
                """
                SELECT product_key, vulnerability_id, confidence, match_method,
                       evidence_type, source_count, updated_at
                FROM product_vulnerabilities
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit * 3,),
            ).fetchall()
        ]
        linked_product_vulnerabilities = _product_vulnerability_rows_for_vulnerabilities(
            conn,
            [int(row["id"]) for row in vulnerabilities if row.get("id") is not None],
        )
        product_vulnerabilities_by_key = {
            (row["product_key"], int(row["vulnerability_id"])): row for row in recent_product_vulnerabilities
        }
        product_vulnerabilities_by_key.update(
            {(row["product_key"], int(row["vulnerability_id"])): row for row in linked_product_vulnerabilities}
        )
        product_vulnerabilities = list(product_vulnerabilities_by_key.values())
        top_products = [
            dict(row)
            for row in conn.execute(
                """
                SELECT product_key, name, normalized_name, vendor, source, url,
                       vulnerability_count, poc_count, last_seen_at, last_crawled_at
                FROM products
                WHERE COALESCE(merged_into_product_key, '') = ''
                ORDER BY vulnerability_count DESC, last_seen_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
        linked_product_keys = [str(row["product_key"]) for row in product_vulnerabilities if row.get("product_key")]
        linked_products = _product_rows_for_keys(conn, linked_product_keys)
        products_by_key = {row["product_key"]: row for row in top_products}
        products_by_key.update({row["product_key"]: row for row in linked_products})
        products = list(products_by_key.values())
        alerts = [
            dict(row)
            for row in conn.execute(
                """
                SELECT id, vulnerability_id, status, reason, created_at, updated_at
                FROM alerts
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
        source_archives = [
            _clean_source_archive_row(dict(row))
            for row in conn.execute(
                """
                SELECT id, origin, filename, status, minio_status, product_name,
                       suggested_product_name, product_key, created_at, updated_at,
                       analysis_raw
                FROM source_archives
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
    return {
        "products": products,
        "vulnerabilities": vulnerabilities,
        "product_vulnerabilities": product_vulnerabilities,
        "alerts": alerts,
        "source_archives": source_archives,
    }


def _product_vulnerability_rows_for_vulnerabilities(conn: Any, vulnerability_ids: list[int]) -> list[dict[str, Any]]:
    ids = sorted({int(value) for value in vulnerability_ids if value is not None})
    if not ids:
        return []
    rows: list[dict[str, Any]] = []
    for start in range(0, len(ids), 500):
        chunk = ids[start : start + 500]
        placeholders = ",".join("?" for _ in chunk)
        rows.extend(
            dict(row)
            for row in conn.execute(
                f"""
                SELECT product_key, vulnerability_id, confidence, match_method,
                       evidence_type, source_count, updated_at
                FROM product_vulnerabilities
                WHERE vulnerability_id IN ({placeholders})
                """,
                tuple(chunk),
            ).fetchall()
        )
    return rows


def _product_rows_for_keys(conn: Any, product_keys: list[str]) -> list[dict[str, Any]]:
    keys = sorted({key for key in product_keys if key})
    if not keys:
        return []
    rows: list[dict[str, Any]] = []
    for start in range(0, len(keys), 500):
        chunk = keys[start : start + 500]
        placeholders = ",".join("?" for _ in chunk)
        rows.extend(
            dict(row)
            for row in conn.execute(
                f"""
                SELECT product_key, name, normalized_name, vendor, source, url,
                       vulnerability_count, poc_count, last_seen_at, last_crawled_at
                FROM products
                WHERE COALESCE(merged_into_product_key, '') = ''
                  AND product_key IN ({placeholders})
                """,
                tuple(chunk),
            ).fetchall()
        )
    return rows


def _clean_vulnerability_row(row: dict[str, Any]) -> dict[str, Any]:
    row["poc_available"] = bool(row.get("poc_available"))
    row["exp_available"] = bool(row.get("exp_available"))
    row["quality_score"] = None if row.get("quality_score") is None else float(row.get("quality_score") or 0)
    return row


def _clean_source_archive_row(row: dict[str, Any]) -> dict[str, Any]:
    vulnerability_id = None
    try:
        raw = json.loads(row.get("analysis_raw") or "{}")
        value = raw.get("vulnerability_id") if isinstance(raw, dict) else None
        vulnerability_id = int(value) if value is not None and str(value).isdigit() else None
    except (TypeError, ValueError, json.JSONDecodeError):
        vulnerability_id = None
    row["vulnerability_id"] = vulnerability_id
    row.pop("analysis_raw", None)
    return row
