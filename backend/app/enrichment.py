from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from . import db
from .async_utils import run_blocking


NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_PREFIX = "nvd_cve_enrichment:"
NVD_ENRICH_LIMIT = 40


async def enrich_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    await run_blocking(_apply_local_intel, items)

    missing_cvss = []
    seen = set()
    for item in items:
        cve = str(item.get("cve_id") or "").upper()
        if cve and not item.get("cvss_score") and cve not in seen:
            seen.add(cve)
            missing_cvss.append(cve)

    if missing_cvss:
        nvd_cache = await _load_nvd_cves(missing_cvss[:NVD_ENRICH_LIMIT])
        await run_blocking(_apply_nvd_intel, items, nvd_cache)

    await run_blocking(_apply_dedupe_keys, items)
    return items


def backfill_missing_cvss_sync(limit: int = 40) -> dict[str, int]:
    return asyncio.run(backfill_missing_cvss(limit=limit))


async def backfill_missing_cvss(limit: int = 40) -> dict[str, int]:
    rows = await run_blocking(_missing_cvss_rows, limit)
    if not rows:
        return {"checked": 0, "updated": 0}
    cves = []
    for row in rows:
        cve = str(row.get("cve_id") or "").upper()
        if cve and cve not in cves:
            cves.append(cve)
    nvd_cache = await _load_nvd_cves(cves)
    updated = await run_blocking(_apply_cvss_backfill, rows, nvd_cache)
    return {"checked": len(rows), "updated": updated}


def _apply_local_intel(items: list[dict[str, Any]]) -> None:
    for item in items:
        item.update(db.extract_item_intel(item))


def _apply_nvd_intel(items: list[dict[str, Any]], nvd_cache: dict[str, dict[str, Any]]) -> None:
    for item in items:
        cve = str(item.get("cve_id") or "").upper()
        nvd_raw = nvd_cache.get(cve)
        if not nvd_raw or item.get("cvss_score"):
            continue
        raw = dict(item.get("raw") or {})
        raw["nvd_enrichment"] = nvd_raw
        item["raw"] = raw
        item.update(db.extract_item_intel(item))


def _apply_dedupe_keys(items: list[dict[str, Any]]) -> None:
    for item in items:
        item["dedupe_key"] = db.dedupe_key_for_item(item)


def _apply_cvss_backfill(rows: list[dict[str, Any]], nvd_cache: dict[str, dict[str, Any]]) -> int:
    updated = 0
    with db.connection() as conn:
        for row in rows:
            cve = str(row.get("cve_id") or "").upper()
            nvd_raw = nvd_cache.get(cve)
            if not nvd_raw:
                continue
            raw = json.loads(row.get("raw") or "{}")
            raw["nvd_enrichment"] = nvd_raw
            item = dict(row)
            item["aliases"] = json.loads(row.get("aliases") or "[]")
            item["raw"] = raw
            intel = db.extract_item_intel(item)
            if intel.get("cvss_score") is None:
                continue
            conn.execute(
                """
                UPDATE vulnerabilities
                SET raw=?,
                    cvss_score=?,
                    cvss_version=?,
                    cvss_vector=?,
                    poc_available=CASE WHEN poc_available=0 THEN ? ELSE poc_available END,
                    poc_url=CASE WHEN poc_url='' THEN ? ELSE poc_url END,
                    poc_content=CASE WHEN poc_content='' THEN ? ELSE poc_content END,
                    exp_available=CASE WHEN exp_available=0 THEN ? ELSE exp_available END,
                    exp_url=CASE WHEN exp_url='' THEN ? ELSE exp_url END,
                    exp_content=CASE WHEN exp_content='' THEN ? ELSE exp_content END
                WHERE id=?
                """,
                (
                    json.dumps(raw, ensure_ascii=False),
                    intel.get("cvss_score"),
                    intel.get("cvss_version") or "",
                    intel.get("cvss_vector") or "",
                    1 if intel.get("poc_available") else 0,
                    intel.get("poc_url") or "",
                    intel.get("poc_content") or "",
                    1 if intel.get("exp_available") else 0,
                    intel.get("exp_url") or "",
                    intel.get("exp_content") or "",
                    row["id"],
                ),
            )
            updated += 1
    return updated


def _missing_cvss_rows(limit: int) -> list[dict[str, Any]]:
    with db.connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM vulnerabilities
            WHERE cve_id LIKE 'CVE-%'
              AND cvss_score IS NULL
            ORDER BY last_seen_at DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(limit, NVD_ENRICH_LIMIT)),),
        ).fetchall()
        return [dict(row) for row in rows]


async def _load_nvd_cves(cves: list[str]) -> dict[str, dict[str, Any]]:
    results = {}
    async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
        for cve in cves:
            cached = await run_blocking(db.get_setting, f"{NVD_CACHE_PREFIX}{cve}")
            if cached:
                try:
                    results[cve] = json.loads(cached)
                    continue
                except json.JSONDecodeError:
                    pass
            data = await _fetch_nvd_cve(client, cve)
            if data:
                results[cve] = data
                await run_blocking(db.set_setting, f"{NVD_CACHE_PREFIX}{cve}", json.dumps(data, ensure_ascii=False))
    return results


async def _fetch_nvd_cve(client: httpx.AsyncClient, cve: str) -> dict[str, Any]:
    try:
        response = await client.get(NVD_CVE_URL, params={"cveId": cve})
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return {}
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return {}
    return vulnerabilities[0].get("cve") or {}
