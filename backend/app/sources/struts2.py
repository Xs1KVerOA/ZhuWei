from __future__ import annotations

import re

import httpx
from bs4 import BeautifulSoup

from .base import SourceAdapter, extract_cve, normalize_severity


class Struts2BulletinAdapter(SourceAdapter):
    name = "struts2_bulletin"
    title = "Apache Struts2 Bulletins"
    category = "slow"
    schedule = "daily at 10:00 and 18:00"

    url = "https://cwiki.apache.org/confluence/display/WW/Security+Bulletins"

    async def fetch(self) -> list[dict]:
        headers = {
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://cwiki.apache.org/",
            "User-Agent": _chrome_ua(),
        }
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.select("#main-content ul li a[href*='S2-']")
            items = []
            for link in links[-10:]:
                href = link.get("href", "")
                detail_url = href if href.startswith("http") else f"https://cwiki.apache.org{href}"
                detail = await _detail(client, detail_url)
                title = link.parent.get_text(" ", strip=True) if link.parent else link.get_text(" ", strip=True)
                items.append(_item_from_detail(self, detail_url, title, detail))
            return items


async def _detail(client: httpx.AsyncClient, url: str) -> dict:
    try:
        response = await client.get(url)
        response.raise_for_status()
    except httpx.HTTPError:
        return {}
    soup = BeautifulSoup(response.text, "html.parser")
    return {
        "severity": _table_value(soup, "Maximum security rating"),
        "cve": _table_value(soup, "CVE Identifier"),
        "impact": _table_value(soup, "Impact of vulnerability"),
        "description": _section_text(soup, "Problem"),
        "solution": _section_text(soup, "Solution"),
    }


def _item_from_detail(adapter: Struts2BulletinAdapter, url: str, title: str, detail: dict) -> dict:
    source_uid = _s2_id(title)
    cve = extract_cve(detail.get("cve", ""))
    return adapter.item(
        source_uid=source_uid,
        title=title,
        severity=_severity(detail.get("severity", "")),
        cve_id=cve,
        aliases=[value for value in [source_uid, cve] if value],
        description=detail.get("description"),
        url=url,
        raw=detail,
    )


def _table_value(soup: BeautifulSoup, label: str) -> str:
    for th in soup.find_all("th"):
        if label.lower() in th.get_text(" ", strip=True).lower():
            td = th.find_next_sibling("td")
            return td.get_text(" ", strip=True) if td else ""
    return ""


def _section_text(soup: BeautifulSoup, suffix: str) -> str:
    for heading in soup.find_all(["h1", "h2", "h3"]):
        if (heading.get("id") or "").endswith(f"-{suffix}"):
            node = heading.find_next_sibling(["p", "div"])
            return node.get_text(" ", strip=True) if node else ""
    return ""


def _severity(value: str) -> str:
    mapping = {
        "critical": "critical",
        "important": "high",
        "moderate": "medium",
        "low": "low",
    }
    return normalize_severity(mapping.get(value.strip().lower(), value))


def _s2_id(value: str) -> str:
    match = re.search(r"S2-\d{3}", value or "")
    return match.group(0) if match else value[:80]


def _chrome_ua() -> str:
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )
