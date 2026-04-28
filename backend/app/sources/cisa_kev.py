from __future__ import annotations

import httpx

from .base import SourceAdapter


class CisaKevAdapter(SourceAdapter):
    name = "cisa_kev"
    title = "CISA KEV"
    category = "regular"
    schedule = "every 30 minutes"

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def fetch(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            payload = response.json()

        items = []
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cveID", "")
            title = f"{entry.get('vendorProject', '')} {entry.get('product', '')} {entry.get('vulnerabilityName', '')}".strip()
            items.append(
                self.item(
                    source_uid=cve,
                    title=title or cve,
                    severity="critical",
                    cve_id=cve,
                    aliases=[cve] if cve else [],
                    published_at=entry.get("dateAdded"),
                    description=entry.get("shortDescription"),
                    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    product=entry.get("product"),
                    raw=entry,
                )
            )
        return items
