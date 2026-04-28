from __future__ import annotations

import httpx
from bs4 import BeautifulSoup

from ..browser_cookie import (
    CNVD_URL,
    cnvd_form_data,
    cnvd_form_headers,
    cnvd_list_params,
    get_cnvd_cookie_header,
    get_cnvd_user_agent,
    looks_like_cnvd_challenge,
    mark_cnvd_session_success,
    refresh_cnvd_browser_cookie,
)
from ..config import settings
from .base import SourceAdapter, extract_cve, infer_cn_severity, normalize_severity, stable_id


class CnvdListAdapter(SourceAdapter):
    name = "cnvd_list"
    title = "CNVD List"
    category = "slow"
    schedule = "daily at 10:00 and 18:00"

    url = CNVD_URL

    async def fetch(self) -> list[dict]:
        items_by_uid: dict[str, dict] = {}
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            for page in range(settings.cnvd_max_pages):
                offset = page * settings.cnvd_page_size
                html = await self._get_list_page(client, offset)
                page_items = _parse_cnvd_html(self, html, "", offset)
                if not page_items:
                    break
                for item in page_items:
                    items_by_uid[item["source_uid"]] = item
            for keyword in settings.cnvd_keywords:
                html = await self._post_list(client, keyword)
                for item in _parse_cnvd_html(self, html, keyword, 0):
                    items_by_uid[item["source_uid"]] = item
        return list(items_by_uid.values())

    async def _get_list_page(self, client: httpx.AsyncClient, offset: int) -> str:
        try:
            response = await client.get(
                self.url,
                headers=cnvd_form_headers(),
                params=cnvd_list_params(offset=offset),
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if not _should_refresh_session(exc.response.status_code):
                raise
            return await self._refresh_and_get(client, offset)
        html = response.text
        if not looks_like_cnvd_challenge(html):
            mark_cnvd_session_success()
            return html
        return await self._refresh_and_get(client, offset)

    async def _post_list(self, client: httpx.AsyncClient, keyword: str) -> str:
        try:
            response = await client.post(
                self.url,
                headers=cnvd_form_headers(),
                data=cnvd_form_data(keyword),
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if not _should_refresh_session(exc.response.status_code):
                raise
            return await self._refresh_and_post(client, keyword)
        html = response.text
        if not looks_like_cnvd_challenge(html):
            mark_cnvd_session_success()
            return html
        return await self._refresh_and_post(client, keyword)

    async def _refresh_and_get(self, client: httpx.AsyncClient, offset: int) -> str:
        await refresh_cnvd_browser_cookie()
        response = await client.get(
            self.url,
            headers=cnvd_form_headers(
                cookie_header=get_cnvd_cookie_header(),
                user_agent=get_cnvd_user_agent(),
            ),
            params=cnvd_list_params(offset=offset),
        )
        response.raise_for_status()
        html = response.text
        if looks_like_cnvd_challenge(html):
            raise RuntimeError("CNVD challenge/captcha returned after browser session refresh")
        mark_cnvd_session_success()
        return html

    async def _refresh_and_post(self, client: httpx.AsyncClient, keyword: str) -> str:
        await refresh_cnvd_browser_cookie()
        response = await client.post(
            self.url,
            headers=cnvd_form_headers(
                cookie_header=get_cnvd_cookie_header(),
                user_agent=get_cnvd_user_agent(),
            ),
            data=cnvd_form_data(keyword),
        )
        response.raise_for_status()
        html = response.text
        if looks_like_cnvd_challenge(html):
            raise RuntimeError("CNVD challenge/captcha returned after browser session refresh")
        mark_cnvd_session_success()
        return html


def _should_refresh_session(status_code: int) -> bool:
    return status_code in {403, 412, 418, 429, 521}


def _parse_cnvd_html(adapter: CnvdListAdapter, html: str, keyword: str = "", offset: int = 0) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    items = []
    for row in soup.select("table tr"):
        cells = [cell.get_text(" ", strip=True) for cell in row.select("td")]
        link = row.select_one("a[href*='/flaw/show/']")
        if len(cells) < 6 or not link:
            continue
        title = cells[0].lstrip(">").strip()
        href = link.get("href", "")
        url = href if href.startswith("http") else f"https://www.cnvd.org.cn{href}"
        cnvd_id = url.rsplit("/", 1)[-1]
        cve = extract_cve(" ".join([title, *cells]))
        severity = normalize_severity(cells[1] if len(cells) > 1 else "")
        if severity == "unknown":
            severity = infer_cn_severity(title)
        items.append(
            adapter.item(
                source_uid=cnvd_id or stable_id(title, url),
                title=title,
                severity=severity,
                cve_id=cve,
                aliases=[value for value in [cnvd_id, cve] if value],
                published_at=cells[-1],
                url=url,
                raw={"cells": cells, "keyword": keyword, "offset": offset},
            )
        )
    return items
