from __future__ import annotations

import re

import httpx
from bs4 import BeautifulSoup

from .base import SourceAdapter, extract_cve, normalize_severity


class SeebugVuldbAdapter(SourceAdapter):
    name = "seebug_vuldb"
    title = "Seebug VulDB"
    category = "regular"
    schedule = "every 30 minutes"

    url = "https://www.seebug.org/vuldb/vulnerabilities"

    async def fetch(self) -> list[dict]:
        headers = {
            "Referer": "https://www.seebug.org/",
            "User-Agent": _chrome_ua(),
        }
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.get(self.url)
            response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        rows = soup.select(".sebug-table tbody tr")
        if not rows:
            raise RuntimeError("Seebug list returned no rows; source may require WAF cookie")

        items = []
        for row in rows[:20]:
            cells = row.select("td")
            if len(cells) < 5:
                continue
            link = cells[0].select_one("a") or cells[3].select_one("a")
            source_uid = link.get_text(strip=True) if link else ""
            title = cells[3].get_text(" ", strip=True)
            href = link.get("href", "") if link else ""
            url = href if href.startswith("http") else f"https://www.seebug.org{href}"
            cve_text = cells[4].select_one("i.fa-id-card")
            cve_blob = cve_text.get("data-original-title", "") if cve_text else ""
            aliases = [source_uid, *_extract_cves(cve_blob)]
            items.append(
                self.item(
                    source_uid=source_uid,
                    title=title,
                    severity=normalize_severity(_severity(cells[2])),
                    cve_id=extract_cve(cve_blob),
                    aliases=[value for value in aliases if value],
                    published_at=cells[1].get_text(" ", strip=True),
                    url=url,
                    raw={"cve_text": cve_blob, "flags": _flags(cells[4])},
                )
            )
        return items


def _severity(cell) -> str:
    node = cell.select_one("[data-original-title]")
    return node.get("data-original-title", "") if node else cell.get_text(" ", strip=True)


def _flags(cell) -> list[str]:
    values = []
    for icon in cell.select("[data-original-title]"):
        value = icon.get("data-original-title", "").strip()
        if value:
            values.append(value)
    return values


def _extract_cves(value: str) -> list[str]:
    return [match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,}", value or "", flags=re.I)]


def _chrome_ua() -> str:
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )
