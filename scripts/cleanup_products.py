#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT_DIR / "backend" / "data"
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app import db

GENERIC_CATALOG_NAMES = {
    "file",
    "config",
    "configuration",
    "vulnerability",
    "security",
    "unknown",
}

NOISY_SUBSTRINGS = {
    " vulnerability",
    "authorization bypass",
    "missing authorization",
    "improper control of filename",
    "cross-site request forgery",
    "deserialization of untrusted data",
    "incorrect privilege assignment",
    "path traversal",
    "by this vulnerability",
}

MANUAL_MERGE_NAMES = {
    "kernel": ["linux_kernel", "Linux Kernel"],
}


def _row_dict(row: Any) -> dict[str, Any]:
    return dict(row)


def _is_noisy_product(row: dict[str, Any]) -> bool:
    name = str(row.get("name") or "").strip()
    source = str(row.get("source") or "")
    lower = name.lower()
    normalized = db._normalize_product_text(name)
    if not name:
        return True
    if source == "biu_products":
        return lower in GENERIC_CATALOG_NAMES
    if source != "vulnerability_match":
        return False
    if db._is_noisy_product_label(name):
        return True
    if normalized in db.NOISY_PRODUCT_NORMALIZED:
        return True
    if lower in {"author", "director", "versions", "core", "multiple products"}:
        return True
    return any(token in lower for token in NOISY_SUBSTRINGS)


def _product_by_names(conn: Any, names: list[str]) -> dict[str, Any] | None:
    for name in names:
        normalized = db._normalize_product_text(name)
        if not normalized:
            continue
        row = conn.execute(
            """
            SELECT *
            FROM products
            WHERE normalized_name=?
              AND COALESCE(merged_into_product_key, '') = ''
            ORDER BY
              CASE WHEN source='biu_products' THEN 1 ELSE 0 END DESC,
              vulnerability_count DESC,
              poc_count DESC
            LIMIT 1
            """,
            (normalized,),
        ).fetchone()
        if row is not None:
            return _row_dict(row)
    return None


def _normalize_product_names(conn: Any, *, apply: bool) -> int:
    changed = 0
    rows = conn.execute("SELECT product_key, name, normalized_name FROM products").fetchall()
    for row in rows:
        normalized = db._normalize_product_text(str(row["name"] or ""))
        if normalized and normalized != str(row["normalized_name"] or ""):
            changed += 1
            if apply:
                conn.execute(
                    "UPDATE products SET normalized_name=? WHERE product_key=?",
                    (normalized, row["product_key"]),
                )
    return changed


def _hide_product(conn: Any, row: dict[str, Any], note: str, *, apply: bool) -> None:
    if not apply:
        return
    now = db.utc_now()
    conn.execute(
        """
        UPDATE products
        SET merged_into_product_key='__noise__',
            merge_note=?,
            last_seen_at=?,
            last_crawled_at=?
        WHERE product_key=?
        """,
        (note[:500], now, now, row["product_key"]),
    )
    conn.execute(
        """
        UPDATE vulnerabilities
        SET product='',
            product_match_method='noise_product_removed',
            product_match_confidence=NULL,
            product_match_evidence=?,
            product_resolved_at=?
        WHERE product=?
        """,
        (note[:1000], now, row["name"]),
    )
    conn.execute(
        "DELETE FROM product_vulnerabilities WHERE product_key=?",
        (row["product_key"],),
    )


def _merge_product_marker(
    conn: Any,
    target: dict[str, Any],
    source: dict[str, Any],
    note: str,
    *,
    apply: bool,
) -> None:
    if not apply:
        return
    now = db.utc_now()
    target_key = str(target["product_key"])
    target_name = str(target["name"] or "")
    source_key = str(source["product_key"])
    source_name = str(source["name"] or "")
    if not target_key or not source_key or target_key == source_key:
        return
    if source_name:
        try:
            db.add_product_alias(target_key, source_name, str(source.get("vendor") or ""))
        except Exception:
            pass
    conn.execute(
        """
        UPDATE products
        SET merged_into_product_key=?,
            merge_note=?,
            last_seen_at=?,
            last_crawled_at=?
        WHERE product_key=?
        """,
        (target_key, note[:500], now, now, source_key),
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
    _move_relations_to_target(conn, source, target, note, apply=apply)


def _move_relations_to_target(
    conn: Any,
    source: dict[str, Any],
    target: dict[str, Any],
    note: str,
    *,
    apply: bool,
) -> int:
    if not apply:
        return 0
    source_key = str(source.get("product_key") or "")
    target_key = str(target.get("product_key") or "")
    target_name = str(target.get("name") or "")
    source_name = str(source.get("name") or "")
    if not source_key or not target_key or source_key == target_key:
        return 0
    now = db.utc_now()
    moved = 0
    rows = conn.execute(
        "SELECT * FROM product_vulnerabilities WHERE product_key=?",
        (source_key,),
    ).fetchall()
    for relation in rows:
        vulnerability_id = int(relation["vulnerability_id"])
        existing = conn.execute(
            """
            SELECT confidence, source_count
            FROM product_vulnerabilities
            WHERE product_key=? AND vulnerability_id=?
            """,
            (target_key, vulnerability_id),
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
                    vulnerability_id,
                ),
            )
            conn.execute(
                "DELETE FROM product_vulnerabilities WHERE product_key=? AND vulnerability_id=?",
                (source_key, vulnerability_id),
            )
        else:
            conn.execute(
                """
                UPDATE product_vulnerabilities
                SET product_key=?,
                    product_name=?,
                    match_method=CASE WHEN match_method='' THEN 'merged_product' ELSE match_method END,
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
                    vulnerability_id,
                ),
            )
        moved += 1
    if moved:
        conn.execute(
            """
            UPDATE vulnerabilities
            SET product=CASE WHEN product=? THEN ? ELSE product END,
                product_match_method=CASE WHEN product_match_method='' THEN 'merged_product' ELSE product_match_method END,
                product_resolved_at=?
            WHERE product=?
            """,
            (source_name, target_name, now, source_name),
        )
        db._refresh_product_counts_conn(conn, target_key)
    return moved


def _reconcile_existing_markers(conn: Any, *, apply: bool) -> dict[str, int]:
    merged_relations = 0
    deleted_noise_relations = 0
    rows = conn.execute(
        """
        SELECT *
        FROM products
        WHERE COALESCE(merged_into_product_key, '') <> ''
        """
    ).fetchall()
    for source_row in rows:
        source = _row_dict(source_row)
        source_key = str(source.get("product_key") or "")
        target_key = str(source.get("merged_into_product_key") or "")
        if target_key == "__noise__":
            relation_count = int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM product_vulnerabilities WHERE product_key=?",
                    (source_key,),
                ).fetchone()["n"]
            )
            if apply and relation_count:
                conn.execute("DELETE FROM product_vulnerabilities WHERE product_key=?", (source_key,))
                conn.execute(
                    """
                    UPDATE vulnerabilities
                    SET product='',
                        product_match_method='noise_product_removed',
                        product_match_confidence=NULL,
                        product_match_evidence='产品清理：非产品词/漏洞类型词，已移除关联。',
                        product_resolved_at=?
                    WHERE product=?
                    """,
                    (db.utc_now(), source.get("name") or ""),
                )
            deleted_noise_relations += relation_count
            continue
        target = conn.execute("SELECT * FROM products WHERE product_key=?", (target_key,)).fetchone()
        if target is None:
            continue
        merged_relations += _move_relations_to_target(
            conn,
            source,
            _row_dict(target),
            "产品清理：迁移已合并产品的历史关联。",
            apply=apply,
        )
    return {
        "reconciled_merged_relations": merged_relations,
        "deleted_noise_relations": deleted_noise_relations,
    }


def build_plan(*, duplicate_limit: int) -> dict[str, Any]:
    with db.connection() as conn:
        all_visible = [
            _row_dict(row)
            for row in conn.execute(
                """
                SELECT *
                FROM products
                WHERE COALESCE(merged_into_product_key, '') = ''
                ORDER BY vulnerability_count DESC, name ASC
                """
            ).fetchall()
        ]
        noisy = [row for row in all_visible if _is_noisy_product(row)]

        manual_merges: list[dict[str, Any]] = []
        for source_name, target_names in MANUAL_MERGE_NAMES.items():
            source = _product_by_names(conn, [source_name])
            target = _product_by_names(conn, target_names)
            if source and target and source["product_key"] != target["product_key"]:
                manual_merges.append({"target": target, "source": source, "reason": "manual_alias"})

        duplicate_groups = db.product_duplicate_candidates(limit=duplicate_limit)
        duplicate_merges: list[dict[str, Any]] = []
        for group in duplicate_groups:
            target = group.get("target") or {}
            for source in group.get("sources") or []:
                if target.get("product_key") and source.get("product_key"):
                    duplicate_merges.append(
                        {
                            "target": target,
                            "source": source,
                            "reason": group.get("reason") or "duplicate",
                            "normalized_name": group.get("normalized_name") or "",
                        }
                    )

        noisy_keys = {str(item["product_key"]) for item in noisy}
        duplicate_merges = [
            item
            for item in [*manual_merges, *duplicate_merges]
            if str(item["source"].get("product_key") or "") not in noisy_keys
        ]
        return {
            "noisy_products": noisy,
            "duplicate_merges": duplicate_merges,
        }


def apply_plan(plan: dict[str, Any], *, apply: bool) -> dict[str, Any]:
    with db.connection() as conn:
        normalized_products = _normalize_product_names(conn, apply=apply)
        for row in plan["noisy_products"]:
            _hide_product(conn, row, "产品清理：非产品词/漏洞类型词，已从产品库前台隐藏。", apply=apply)
        for item in plan["duplicate_merges"]:
            _merge_product_marker(
                conn,
                item["target"],
                item["source"],
                f"产品清理：{item.get('reason') or 'duplicate'}，非破坏性合并到规范产品。",
                apply=apply,
            )
        reconciled = _reconcile_existing_markers(conn, apply=apply)
    return {
        "normalized_products": normalized_products,
        "hidden_noisy_products": len(plan["noisy_products"]),
        "marked_duplicate_products": len(plan["duplicate_merges"]),
        **reconciled,
        "sample_noisy_products": [
            {
                "product_key": item["product_key"],
                "name": item["name"],
                "source": item["source"],
                "vulnerability_count": item["vulnerability_count"],
            }
            for item in plan["noisy_products"][:50]
        ],
        "sample_duplicate_merges": [
            {
                "source": item["source"].get("name"),
                "target": item["target"].get("name"),
                "reason": item.get("reason"),
            }
            for item in plan["duplicate_merges"][:50]
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Clean ZhuWei product catalog noise and duplicates.")
    parser.add_argument("--apply", action="store_true", help="Apply the cleanup. Without this flag it only previews.")
    parser.add_argument("--duplicate-limit", type=int, default=500)
    args = parser.parse_args()

    plan = build_plan(duplicate_limit=max(1, args.duplicate_limit))
    result = apply_plan(plan, apply=args.apply)
    result["mode"] = "apply" if args.apply else "dry-run"

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / ("product_cleanup_apply.json" if args.apply else "product_cleanup_dry_run.json")
    report_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"report: {report_path.relative_to(ROOT_DIR)}")


if __name__ == "__main__":
    main()
