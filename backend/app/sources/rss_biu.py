from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from email.utils import parsedate_to_datetime
import logging
import random
import re
from urllib.parse import urljoin
from xml.etree import ElementTree

from bs4 import BeautifulSoup
import httpx

from ..config import settings
from ..db import product_key as canonical_product_key
from .base import SourceAdapter, extract_cve, infer_cn_severity, stable_id


class BiuRssAdapter(SourceAdapter):
    name = "biu_rss"
    title = "biu.life RSS"
    category = "regular"
    schedule = "every 30 minutes"

    url = "https://rss.biu.life/feed/"
    latest_url = "https://rss.biu.life/"

    async def fetch(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response, latest_response = await asyncio.gather(
                client.get(self.url, headers={"Accept": "application/rss+xml, application/xml"}),
                client.get(self.latest_url, headers={"Accept": "text/html"}),
            )
            response.raise_for_status()
            latest_response.raise_for_status()

        latest_items = _parse_latest_page(latest_response.text)
        latest_by_title = {_title_key(item["title"]): item for item in latest_items}
        seen_titles: set[str] = set()
        root = ElementTree.fromstring(response.content)
        items = []
        for node in root.findall("./channel/item"):
            title = _text(node, "title")
            link = _text(node, "link")
            description = _text(node, "description")
            pub_date = _parse_pub_date(_text(node, "pubDate"))
            latest = latest_by_title.get(_title_key(title), {})
            detail_url = latest.get("url") or ""
            poc_marked = bool(latest.get("poc_available"))
            poc_url = detail_url if poc_marked and detail_url else ""
            poc_available = bool(poc_url)
            cve = extract_cve(title) or extract_cve(description)
            aliases = [cve] if cve else []
            item = self.item(
                source_uid=stable_id(title, link, pub_date or ""),
                title=title,
                severity=infer_cn_severity(title, description),
                cve_id=cve,
                aliases=aliases,
                published_at=pub_date,
                description=description,
                url=detail_url or link,
                product=_infer_product(title),
                raw={
                    "title": title,
                    "link": link,
                    "description": description,
                    "biu_detail_url": detail_url,
                    "poc_available": poc_available,
                    "poc_marked": poc_marked,
                    "poc_url": poc_url,
                    "poc_note": "biu.life 页面标记 POC 已公开" if poc_available else "",
                },
            )
            if poc_available:
                item.update(
                    {
                        "poc_available": True,
                        "poc_url": poc_url,
                        "poc_content": "biu.life 页面标记 POC 已公开，详情页可能包含检测模板或验证信息。",
                    }
                )
            items.append(item)
            seen_titles.add(_title_key(title))

        for latest in latest_items:
            key = _title_key(latest["title"])
            if key in seen_titles:
                continue
            cve = extract_cve(latest["title"])
            item = self.item(
                source_uid=stable_id(latest["title"], latest.get("url", ""), latest.get("published_at", "")),
                title=latest["title"],
                severity=infer_cn_severity(latest["title"]),
                cve_id=cve,
                aliases=[cve] if cve else [],
                published_at=latest.get("published_at", ""),
                description="",
                url=latest.get("url", ""),
                product=_infer_product(latest["title"]),
                raw={
                    **latest,
                    "poc_available": bool(latest.get("poc_available") and latest.get("url")),
                    "poc_marked": bool(latest.get("poc_available")),
                    "poc_url": latest.get("url", "") if latest.get("poc_available") and latest.get("url") else "",
                    "poc_note": "biu.life 页面标记 POC 已公开" if latest.get("poc_available") and latest.get("url") else "",
                },
            )
            if latest.get("poc_available") and latest.get("url"):
                item.update(
                    {
                        "poc_available": True,
                        "poc_url": latest.get("url", ""),
                        "poc_content": "biu.life 页面标记 POC 已公开，详情页可能包含检测模板或验证信息。",
                    }
                )
            items.append(item)
        return items


logger = logging.getLogger("sources.rss_biu")


def _log_warning(msg: str) -> None:
    logger.warning(msg)


class BiuProductCatalogAdapter(SourceAdapter):
    name = "biu_products"
    title = "biu.life 产品库"
    category = "slow"
    schedule = "daily at 10:00 and 18:00"

    url = "https://rss.biu.life/ti/product"
    last_warning = ""

    async def fetch(self) -> list[dict]:
        return []

    async def stream_products(self) -> AsyncIterator[list[dict]]:
        """Yield products page by page so the caller can upsert incrementally."""
        self.last_warning = ""
        seen: set[str] = set()
        max_pages = settings.biu_product_max_pages
        max_retries = settings.biu_product_retry_count
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            page = 1
            while True:
                params = {} if page == 1 else {"page": page}
                retries = 0
                while True:
                    response = await client.get(
                        self.url, params=params,
                        headers={"Accept": "text/html",
                                 "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                                               "Chrome/147.0.0.0 Safari/537.36"},
                    )
                    if response.status_code != 429:
                        break
                    retries += 1
                    if retries > max_retries:
                        self.last_warning = (
                            f"biu_products: page {page} still 429 after {max_retries} retries, "
                            f"aborting. collected {len(seen)} products so far."
                        )
                        _log_warning(self.last_warning)
                        return
                    retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
                    backoff = retry_after or min(
                        settings.biu_product_retry_base_seconds * (2 ** (retries - 1)),
                        180,
                    )
                    _log_warning(
                        f"biu_products: page {page} got 429, "
                        f"backing off {backoff:.1f}s (attempt {retries}/{max_retries})"
                    )
                    await asyncio.sleep(backoff)
                response.raise_for_status()
                page_products, has_next = _parse_product_page(response.text)
                if not page_products:
                    break
                batch = []
                for product in page_products:
                    key = product["product_key"]
                    if key in seen:
                        continue
                    seen.add(key)
                    batch.append(product)
                if batch:
                    yield batch
                if max_pages and page >= max_pages:
                    break
                if not has_next:
                    break
                page += 1
                delay = _crawl_delay_seconds()
                if delay:
                    await asyncio.sleep(delay)

    async def fetch_products(self) -> list[dict]:
        """Legacy: collect all products in memory (kept for backward compat)."""
        products: list[dict] = []
        async for batch in self.stream_products():
            products.extend(batch)
        return products


def _retry_after_seconds(value: str | None) -> int:
    if not value:
        return 0
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def _crawl_delay_seconds() -> float:
    base = max(0, settings.biu_product_page_delay_ms) / 1000
    jitter = max(0, settings.biu_product_page_jitter_ms) / 1000
    return base + (random.uniform(0, jitter) if jitter else 0)


def _text(node: ElementTree.Element, tag: str) -> str:
    child = node.find(tag)
    return "" if child is None or child.text is None else child.text.strip()


def _parse_pub_date(value: str) -> str:
    if not value:
        return ""
    try:
        return parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError):
        return value.strip()


def _parse_latest_page(html: str) -> list[dict]:
    soup = BeautifulSoup(html or "", "html.parser")
    items: list[dict] = []
    for node in soup.select("ul.vuln-list li.poc-item"):
        link = node.select_one("a[href]")
        if link is None:
            continue
        date_node = link.select_one(".datetime")
        published_at = date_node.get_text(strip=True) if date_node else ""
        title = link.get_text(" ", strip=True)
        if published_at and title.startswith(published_at):
            title = title[len(published_at):].strip()
        href = link.get("href") or ""
        items.append(
            {
                "title": title,
                "url": urljoin("https://rss.biu.life/", href),
                "published_at": published_at,
                "poc_available": node.select_one(".poc-tag") is not None,
            }
        )
    return items


def _parse_product_page(html: str) -> tuple[list[dict], bool]:
    soup = BeautifulSoup(html or "", "html.parser")
    products: list[dict] = []
    for card in soup.select(".product-card"):
        link = card.select_one("a[href]")
        if link is None:
            continue
        name = link.get_text(" ", strip=True)
        if not name:
            continue
        if _is_generic_product_name(name):
            continue
        href = link.get("href") or ""
        meta = card.select_one(".meta")
        count = _first_int(meta.get_text(" ", strip=True) if meta else "")
        products.append(
            {
                "source": BiuProductCatalogAdapter.name,
                "source_uid": stable_id(name, href),
                "product_key": _product_key(name),
                "name": name,
                "url": urljoin("https://rss.biu.life/", href),
                "vulnerability_count": count,
                "poc_count": 0,
                "raw": {
                    "name": name,
                    "href": href,
                    "vulnerability_count": count,
                    "source": "rss.biu.life/ti/product",
                },
            }
        )
    has_next = any(link.get_text(" ", strip=True) == "下一页" for link in soup.select(".pagination a[href]"))
    return products, has_next


def _is_generic_product_name(name: str) -> bool:
    return re.sub(r"\s+", " ", (name or "").strip()).lower() in {
        "file",
        "config",
        "configuration",
        "security",
        "vulnerability",
        "unknown",
    }


def _title_key(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).lower()


def _infer_product(title: str) -> str:
    text = re.sub(r"\s+", " ", (title or "").strip())
    if not text:
        return ""
    if text.upper().startswith("CVE-") and ":" in text:
        text = text.split(":", 1)[1].strip()
    match = re.search(
        r"(.+?)(?:\s+/(?:[^\s]|$)|\s+(?:存在|漏洞|远程|命令|代码|SQL|文件|权限|未授权|默认口令)|（?CVE-|\(?CVE-)",
        text,
        flags=re.I,
    )
    product = (match.group(1) if match else text).strip(" -:：")
    return product[:120]


def _product_key(name: str) -> str:
    return canonical_product_key(name)


def _first_int(text: str) -> int:
    match = re.search(r"\d+", text or "")
    return int(match.group(0)) if match else 0
