from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from .base import SourceAdapter


class NvdRecentAdapter(SourceAdapter):
    name = "nvd_recent"
    title = "NVD Recent CVE"
    category = "regular"
    schedule = "every 30 minutes"

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def fetch(self) -> list[dict]:
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=2)
        params = {
            "lastModStartDate": _nvd_time(since),
            "lastModEndDate": _nvd_time(now),
            "resultsPerPage": 100,
        }
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as client:
            response = await client.get(self.url, params=params)
            response.raise_for_status()
            payload = response.json()

        items = []
        for wrapper in payload.get("vulnerabilities", []):
            cve = wrapper.get("cve", {})
            cve_id = cve.get("id", "")
            description = _description(cve)
            severity = _severity(cve)
            items.append(
                self.item(
                    source_uid=cve_id,
                    title=f"{cve_id} {description[:120]}".strip(),
                    severity=severity,
                    cve_id=cve_id,
                    aliases=[cve_id] if cve_id else [],
                    published_at=_date(cve.get("published")),
                    updated_at=_date(cve.get("lastModified")),
                    description=description,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
                    raw=cve,
                )
            )
        return items


def _nvd_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000")


def _date(value: str | None) -> str:
    return (value or "")[:10]


def _description(cve: dict) -> str:
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value", "")
    descriptions = cve.get("descriptions") or []
    return descriptions[0].get("value", "") if descriptions else ""


def _severity(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            severity = values[0].get("cvssData", {}).get("baseSeverity") or values[0].get("baseSeverity")
            if severity:
                return severity
    return "unknown"
