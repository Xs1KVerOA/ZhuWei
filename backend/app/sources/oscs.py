from __future__ import annotations

from datetime import datetime, timezone

import httpx

from .base import SourceAdapter, normalize_severity


class OscsIntelAdapter(SourceAdapter):
    name = "oscs_intel"
    title = "OSCS Open Source Intel"
    category = "regular"
    schedule = "every 30 minutes"

    list_url = "https://www.oscs1024.com/oscs/v1/intelligence/list"
    detail_url = "https://www.oscs1024.com/oscs/v1/vdb/info"

    async def fetch(self) -> list[dict]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://www.oscs1024.com",
            "Referer": "https://www.oscs1024.com/cm",
            "User-Agent": _chrome_ua(),
        }
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.post(self.list_url, json={"page": 1, "per_page": 10})
            response.raise_for_status()
            payload = response.json()
            entries = payload.get("data", {}).get("data", [])
            items = []
            for entry in entries:
                detail = await _detail(client, self.detail_url, entry.get("mps") or "")
                items.append(_item_from_entry(self, entry, detail))
            return items


async def _detail(client: httpx.AsyncClient, url: str, vuln_no: str) -> dict:
    if not vuln_no:
        return {}
    try:
        response = await client.post(url, json={"vuln_no": vuln_no})
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return {}
    data = payload.get("data") or []
    return data[0] if data else {}


def _item_from_entry(adapter: OscsIntelAdapter, entry: dict, detail: dict) -> dict:
    vuln_no = detail.get("vuln_no") or entry.get("mps") or entry.get("id")
    cve = detail.get("cve_id") or detail.get("vuln_cve_id") or ""
    title = detail.get("vuln_title") or entry.get("title") or vuln_no
    publish_time = detail.get("publish_time")
    refs = [ref.get("url") for ref in detail.get("references", []) if ref.get("url")]
    tags = []
    if entry.get("is_push") == 1:
        tags.append("发布预警")
    if entry.get("is_poc") == 1 or detail.get("poc"):
        tags.append("POC")
    if entry.get("is_exp") == 1 or detail.get("exp"):
        tags.append("EXP")
    return adapter.item(
        source_uid=vuln_no,
        title=title,
        severity=normalize_severity(detail.get("level") or entry.get("level")),
        cve_id=cve,
        aliases=[value for value in [vuln_no, cve, detail.get("cnvd_id")] if value],
        published_at=_date_from_ms(publish_time) or _date_part(entry.get("public_time")),
        updated_at=_date_part(entry.get("updated_at")),
        description=detail.get("description") or entry.get("title"),
        url=f"https://www.oscs1024.com/hd/{vuln_no}",
        product=", ".join(
            sorted({effect.get("name", "") for effect in detail.get("effect", []) if effect.get("name")})
        ),
        raw={**entry, "detail": detail, "tags": tags, "references": refs},
    )


def _date_from_ms(value: int | None) -> str:
    if not value:
        return ""
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).date().isoformat()


def _date_part(value: str | None) -> str:
    return (value or "").split("T", 1)[0]


def _chrome_ua() -> str:
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )
