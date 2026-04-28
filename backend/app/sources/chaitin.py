from __future__ import annotations

import httpx

from .base import SourceAdapter, normalize_severity


class ChaitinVuldbAdapter(SourceAdapter):
    name = "chaitin_vuldb"
    title = "Chaitin VulDB"
    category = "regular"
    schedule = "every 30 minutes"

    url = "https://stack.chaitin.com/api/v2/vuln/list/"

    async def fetch(self) -> list[dict]:
        params = {"limit": 15, "offset": 0, "search": "CT-"}
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Origin": "https://stack.chaitin.com",
            "Referer": "https://stack.chaitin.com/vuldb/index",
            "User-Agent": _chrome_ua(),
        }
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.get(self.url, params=params)
            response.raise_for_status()
            payload = response.json()

        items = []
        for entry in payload.get("data", {}).get("list", []):
            cve = entry.get("cve_id") or ""
            ct_id = entry.get("ct_id") or entry.get("id")
            references = entry.get("references") or ""
            items.append(
                self.item(
                    source_uid=ct_id,
                    title=entry.get("title") or ct_id,
                    severity=normalize_severity(entry.get("severity")),
                    cve_id=cve,
                    aliases=[value for value in [ct_id, cve] if value],
                    published_at=_date_part(entry.get("disclosure_date") or entry.get("created_at")),
                    updated_at=_date_part(entry.get("updated_at")),
                    description=entry.get("summary"),
                    url=f"https://stack.chaitin.com/vuldb/detail/{entry.get('id')}",
                    raw={**entry, "references": _split_refs(references)},
                )
            )
        return items


def _date_part(value: str | None) -> str:
    return (value or "").split("T", 1)[0]


def _split_refs(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _chrome_ua() -> str:
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )
