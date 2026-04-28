from __future__ import annotations

import httpx
from bs4 import BeautifulSoup

from ..browser_cookie import fetch_avd_html_with_browser, get_avd_cookie_header, get_avd_user_agent
from .base import SourceAdapter, extract_cve, normalize_severity


class AvdHighRiskAdapter(SourceAdapter):
    name = "avd_high_risk"
    title = "Alibaba AVD High Risk"
    category = "slow"
    schedule = "daily at 10:00 and 18:00"

    url = "https://avd.aliyun.com/high-risk/list"

    async def fetch(self) -> list[dict]:
        headers = {"User-Agent": get_avd_user_agent()}
        cookie = get_avd_cookie_header()
        if cookie:
            headers["Cookie"] = cookie
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.get(self.url)
            response.raise_for_status()

        html = response.text
        if _looks_like_waf(html, response.headers):
            html = await fetch_avd_html_with_browser()
        items = _parse_avd_html(self, html)
        if not items and not _looks_like_waf(html, response.headers):
            html = await fetch_avd_html_with_browser()
            items = _parse_avd_html(self, html)
        return items


def _parse_avd_html(adapter: AvdHighRiskAdapter, html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    rows = soup.select("table tr")
    items = []
    for row in rows:
        cells = [cell.get_text(" ", strip=True) for cell in row.select("td")]
        link = row.select_one("a[href*='/detail?id=']")
        if len(cells) < 4 or not link:
            continue
        avd_id = cells[0]
        title = cells[1]
        cve = extract_cve(title)
        href = link.get("href", "")
        url = href if href.startswith("http") else f"https://avd.aliyun.com{href}"
        status_text = " ".join(cells[4:]) if len(cells) > 4 else ""
        severity = "high" if "高危" in soup.get_text(" ", strip=True) else normalize_severity("")
        items.append(
            adapter.item(
                source_uid=avd_id,
                title=title,
                severity=severity,
                cve_id=cve,
                aliases=[value for value in [avd_id, cve] if value],
                published_at=cells[3],
                url=url,
                raw={"avd_id": avd_id, "type": cells[2], "status": status_text},
            )
        )
    return items


def _looks_like_waf(html: str, headers: httpx.Headers) -> bool:
    text = html.lower()
    return "Punish-Type" in headers or any(marker in text for marker in ["_waf_", "sigchl", "captcha", "验证码"])
