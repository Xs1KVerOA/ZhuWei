from __future__ import annotations

from pathlib import PurePosixPath

import httpx
from bs4 import BeautifulSoup

from .base import SourceAdapter, extract_cve, infer_cn_severity, normalize_severity


class VenustechNoticeAdapter(SourceAdapter):
    name = "venustech_notice"
    title = "Venustech Security Notice"
    category = "slow"
    schedule = "daily at 10:00 and 18:00"

    url = "https://www.venustech.com.cn/new_type/aqtg/"

    async def fetch(self) -> list[dict]:
        headers = {"User-Agent": _chrome_ua()}
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.select(
                "body > div > div.wrapper.clearfloat > div.right.main-content > div "
                "> div.main-inner-bt > ul > li > a"
            )
            items = []
            for link in links[:16]:
                title = link.get_text(" ", strip=True)
                if "多个安全漏洞" in title:
                    continue
                href = link.get("href", "")
                detail_url = href if href.startswith("http") else f"https://www.venustech.com.cn{href}"
                detail = await _detail(client, detail_url)
                items.append(_item_from_detail(self, detail_url, title, detail))
            return items


async def _detail(client: httpx.AsyncClient, url: str) -> dict:
    try:
        response = await client.get(url)
        response.raise_for_status()
    except httpx.HTTPError:
        return {}
    soup = BeautifulSoup(response.text, "html.parser")
    content = soup.select_one("div.news-content.ctn") or soup
    table_values = _table_values(content)
    description = ""
    table = content.select_one("table")
    if table:
        texts = []
        for node in table.find_all_next(["p", "section"], limit=8):
            text = node.get_text(" ", strip=True)
            if text and "参考链接" not in text:
                texts.append(text)
        description = " ".join(texts[:3])
    return {"table": table_values, "description": description}


def _item_from_detail(adapter: VenustechNoticeAdapter, url: str, fallback_title: str, detail: dict) -> dict:
    table = detail.get("table") or {}
    title = table.get("漏洞名称") or fallback_title.replace("【漏洞通告】", "")
    cve = extract_cve(table.get("CVEID", "") or title)
    filename = PurePosixPath(url).stem
    severity = normalize_severity(table.get("漏洞等级") or table.get("等级"))
    if severity == "unknown":
        severity = infer_cn_severity(title, detail.get("description", ""))
    return adapter.item(
        source_uid=f"{filename}_venustech",
        title=title,
        severity=severity,
        cve_id=cve,
        aliases=[value for value in [cve, table.get("CVEID")] if value],
        published_at=table.get("发现时间") or table.get("披露时间"),
        description=detail.get("description"),
        url=url,
        raw=detail,
    )


def _table_values(content) -> dict[str, str]:
    values = {}
    cells = content.select("table td")
    for index in range(0, max(len(cells) - 1, 0), 2):
        key = cells[index].get_text("", strip=True).replace("\xa0", "").replace(" ", "")
        value = cells[index + 1].get_text(" ", strip=True)
        if key:
            values[key] = value
    return values


def _chrome_ua() -> str:
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )
