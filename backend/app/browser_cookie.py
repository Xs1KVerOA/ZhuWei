from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx

from . import db
from .config import settings


AVD_COOKIE_KEY = "source_session.avd_high_risk.cookie"
AVD_UA_KEY = "source_session.avd_high_risk.user_agent"
AVD_STATUS_KEY = "source_session.avd_high_risk.status"
AVD_ERROR_KEY = "source_session.avd_high_risk.error"
AVD_URL = "https://avd.aliyun.com/high-risk/list"
CNVD_COOKIE_KEY = "source_session.cnvd_list.cookie"
CNVD_UA_KEY = "source_session.cnvd_list.user_agent"
CNVD_STATUS_KEY = "source_session.cnvd_list.status"
CNVD_ERROR_KEY = "source_session.cnvd_list.error"
CNVD_URL = "https://www.cnvd.org.cn/flaw/list?flag=true"


def get_avd_cookie_header() -> str:
    return db.get_setting(AVD_COOKIE_KEY) or settings.avd_cookie


def get_avd_user_agent() -> str:
    return db.get_setting(AVD_UA_KEY) or settings.avd_user_agent


def get_cnvd_cookie_header() -> str:
    return db.get_setting(CNVD_COOKIE_KEY) or settings.cnvd_cookie


def get_cnvd_user_agent() -> str:
    return db.get_setting(CNVD_UA_KEY) or settings.cnvd_user_agent


def get_avd_session_status() -> dict[str, Any]:
    dynamic_cookie = db.get_setting(AVD_COOKIE_KEY)
    env_cookie = settings.avd_cookie
    cookie_meta = db.get_setting_meta(AVD_COOKIE_KEY)
    status = db.get_setting(AVD_STATUS_KEY)
    error = db.get_setting(AVD_ERROR_KEY)
    return {
        "source": "browser" if dynamic_cookie else "env" if env_cookie else "empty",
        "configured": bool(dynamic_cookie or env_cookie),
        "browser_cookie_configured": bool(dynamic_cookie),
        "env_cookie_configured": bool(env_cookie),
        "updated_at": cookie_meta["updated_at"] if cookie_meta else "",
        "status": status or ("ready" if dynamic_cookie or env_cookie else "missing"),
        "error": error,
        "masked_cookie": _mask_cookie(dynamic_cookie or env_cookie),
        "user_agent": get_avd_user_agent(),
        "browser_executable": _browser_executable_path(),
        "headless_default": settings.avd_browser_headless,
    }


def get_cnvd_session_status() -> dict[str, Any]:
    dynamic_cookie = db.get_setting(CNVD_COOKIE_KEY)
    env_cookie = settings.cnvd_cookie
    cookie_meta = db.get_setting_meta(CNVD_COOKIE_KEY)
    status = db.get_setting(CNVD_STATUS_KEY)
    error = db.get_setting(CNVD_ERROR_KEY)
    return {
        "source": "browser" if dynamic_cookie else "env" if env_cookie else "empty",
        "configured": bool(dynamic_cookie or env_cookie),
        "browser_cookie_configured": bool(dynamic_cookie),
        "env_cookie_configured": bool(env_cookie),
        "updated_at": cookie_meta["updated_at"] if cookie_meta else "",
        "status": status or ("ready" if dynamic_cookie or env_cookie else "missing"),
        "error": error,
        "masked_cookie": _mask_cookie(dynamic_cookie or env_cookie),
        "user_agent": get_cnvd_user_agent(),
        "browser_executable": _browser_executable_path(),
        "headless_default": settings.avd_browser_headless,
        "probe_keyword": settings.cnvd_probe_keyword,
        "keywords": settings.cnvd_keywords,
        "page_size": settings.cnvd_page_size,
        "max_pages": settings.cnvd_max_pages,
    }


def mark_cnvd_session_success() -> None:
    db.set_setting(CNVD_STATUS_KEY, "success")
    db.delete_setting(CNVD_ERROR_KEY)


async def refresh_avd_browser_cookie(headless: bool | None = None) -> dict[str, Any]:
    db.set_setting(AVD_STATUS_KEY, "running")
    db.delete_setting(AVD_ERROR_KEY)
    try:
        _html, cookie_header, user_agent = await collect_avd_page_with_browser(headless=headless)
    except Exception as exc:
        error = str(exc)
        db.set_setting(AVD_STATUS_KEY, "failed")
        db.set_setting(AVD_ERROR_KEY, error)
        raise RuntimeError(error) from exc

    db.set_setting(AVD_COOKIE_KEY, cookie_header)
    db.set_setting(AVD_UA_KEY, user_agent)
    validation_error = await _validate_avd_cookie(cookie_header, user_agent)
    if validation_error:
        db.set_setting(AVD_STATUS_KEY, "browser_only")
        db.set_setting(AVD_ERROR_KEY, validation_error)
    else:
        db.set_setting(AVD_STATUS_KEY, "success")
        db.delete_setting(AVD_ERROR_KEY)
    return get_avd_session_status()


async def refresh_cnvd_browser_cookie(headless: bool | None = None) -> dict[str, Any]:
    db.set_setting(CNVD_STATUS_KEY, "running")
    db.delete_setting(CNVD_ERROR_KEY)
    try:
        _html, cookie_header, user_agent = await collect_cnvd_page_with_browser(headless=headless)
    except Exception as exc:
        error = str(exc)
        db.set_setting(CNVD_STATUS_KEY, "failed")
        db.set_setting(CNVD_ERROR_KEY, error)
        raise RuntimeError(error) from exc

    db.set_setting(CNVD_COOKIE_KEY, cookie_header)
    db.set_setting(CNVD_UA_KEY, user_agent)
    validation_error = await validate_cnvd_cookie(cookie_header, user_agent)
    if validation_error:
        db.set_setting(CNVD_STATUS_KEY, "browser_only")
        db.set_setting(CNVD_ERROR_KEY, validation_error)
    else:
        db.set_setting(CNVD_STATUS_KEY, "success")
        db.delete_setting(CNVD_ERROR_KEY)
    return get_cnvd_session_status()


async def set_cnvd_browser_cookie(cookie_header: str, user_agent: str = "") -> dict[str, Any]:
    cookie = cookie_header.strip()
    if not cookie:
        raise ValueError("CNVD Cookie 不能为空")
    ua = user_agent.strip() or settings.cnvd_user_agent
    db.set_setting(CNVD_COOKIE_KEY, cookie)
    db.set_setting(CNVD_UA_KEY, ua)
    validation_error = await validate_cnvd_cookie(cookie, ua)
    if validation_error:
        db.set_setting(CNVD_STATUS_KEY, "manual_unverified")
        db.set_setting(CNVD_ERROR_KEY, validation_error)
    else:
        db.set_setting(CNVD_STATUS_KEY, "success")
        db.delete_setting(CNVD_ERROR_KEY)
    return get_cnvd_session_status()


async def fetch_avd_html_with_browser(headless: bool | None = None) -> str:
    html, cookie_header, user_agent = await collect_avd_page_with_browser(headless=headless)
    db.set_setting(AVD_COOKIE_KEY, cookie_header)
    db.set_setting(AVD_UA_KEY, user_agent)
    validation_error = await _validate_avd_cookie(cookie_header, user_agent)
    if validation_error:
        db.set_setting(AVD_STATUS_KEY, "browser_only")
        db.set_setting(AVD_ERROR_KEY, validation_error)
    else:
        db.set_setting(AVD_STATUS_KEY, "success")
        db.delete_setting(AVD_ERROR_KEY)
    return html


async def fetch_cnvd_html_with_browser(headless: bool | None = None) -> str:
    html, cookie_header, user_agent = await collect_cnvd_page_with_browser(headless=headless)
    db.set_setting(CNVD_COOKIE_KEY, cookie_header)
    db.set_setting(CNVD_UA_KEY, user_agent)
    validation_error = await validate_cnvd_cookie(cookie_header, user_agent)
    if validation_error:
        db.set_setting(CNVD_STATUS_KEY, "browser_only")
        db.set_setting(CNVD_ERROR_KEY, validation_error)
    else:
        db.set_setting(CNVD_STATUS_KEY, "success")
        db.delete_setting(CNVD_ERROR_KEY)
    return html


async def clear_avd_browser_cookie() -> dict[str, Any]:
    db.delete_setting(AVD_COOKIE_KEY)
    db.delete_setting(AVD_UA_KEY)
    db.delete_setting(AVD_STATUS_KEY)
    db.delete_setting(AVD_ERROR_KEY)
    return get_avd_session_status()


async def clear_cnvd_browser_cookie() -> dict[str, Any]:
    db.delete_setting(CNVD_COOKIE_KEY)
    db.delete_setting(CNVD_UA_KEY)
    db.delete_setting(CNVD_STATUS_KEY)
    db.delete_setting(CNVD_ERROR_KEY)
    return get_cnvd_session_status()


async def collect_avd_page_with_browser(headless: bool | None = None) -> tuple[str, str, str]:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright 未安装，请执行 pip install -r requirements.txt") from exc

    timeout_ms = max(10, settings.avd_browser_timeout_seconds) * 1000
    use_headless = settings.avd_browser_headless if headless is None else bool(headless)
    executable_path = _browser_executable_path()
    launch_options: dict[str, Any] = {
        "headless": use_headless,
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
        ],
    }
    if executable_path:
        launch_options["executable_path"] = executable_path

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**launch_options)
        try:
            context = await browser.new_context(
                locale="zh-CN",
                timezone_id=settings.scheduler_timezone,
                viewport={"width": 1440, "height": 960},
            )
            page = await context.new_page()
            await page.goto(AVD_URL, wait_until="domcontentloaded", timeout=timeout_ms)
            await _wait_until_avd_ready(page, timeout_ms)
            html = await page.content()
            user_agent = await page.evaluate("navigator.userAgent")
            cookies = await context.cookies("https://avd.aliyun.com")
            cookie_header = _cookie_header(cookies)
            if not cookie_header:
                raise RuntimeError("Chrome 未返回 avd.aliyun.com Cookie")
            return html, cookie_header, user_agent
        finally:
            await browser.close()


async def collect_cnvd_page_with_browser(headless: bool | None = None) -> tuple[str, str, str]:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright 未安装，请执行 pip install -r requirements.txt") from exc

    timeout_ms = max(10, settings.avd_browser_timeout_seconds) * 1000
    use_headless = settings.avd_browser_headless if headless is None else bool(headless)
    executable_path = _browser_executable_path()
    launch_options: dict[str, Any] = {
        "headless": use_headless,
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
        ],
    }
    if executable_path:
        launch_options["executable_path"] = executable_path

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**launch_options)
        try:
            context = await browser.new_context(
                locale="zh-CN",
                timezone_id=settings.scheduler_timezone,
                viewport={"width": 1440, "height": 960},
            )
            page = await context.new_page()
            await page.goto(CNVD_URL, wait_until="domcontentloaded", timeout=timeout_ms)
            await _wait_until_cnvd_ready(page, timeout_ms)
            html = await _safe_page_content(page, timeout_ms)
            user_agent = await page.evaluate("navigator.userAgent")
            cookies = await context.cookies("https://www.cnvd.org.cn")
            cookie_header = _cookie_header(cookies)
            if not cookie_header:
                raise RuntimeError("Chrome 未返回 www.cnvd.org.cn Cookie")
            return html, cookie_header, user_agent
        finally:
            await browser.close()


async def _wait_until_avd_ready(page, timeout_ms: int) -> None:
    deadline = time.monotonic() + timeout_ms / 1000
    last_title = ""
    while time.monotonic() < deadline:
        html = await page.content()
        last_title = await page.title()
        if _looks_like_avd_page(html) and not _looks_like_challenge(html):
            return
        await page.wait_for_timeout(1500)
    raise RuntimeError(f"AVD 浏览器挑战超时，最后页面标题：{last_title}")


async def _wait_until_cnvd_ready(page, timeout_ms: int) -> None:
    deadline = time.monotonic() + timeout_ms / 1000
    last_title = ""
    while time.monotonic() < deadline:
        try:
            html = await page.content()
            last_title = await page.title()
        except Exception:
            await page.wait_for_timeout(500)
            continue
        if looks_like_cnvd_page(html) and not looks_like_cnvd_challenge(html):
            return
        await page.wait_for_timeout(1500)
    raise RuntimeError(f"CNVD 浏览器挑战超时，最后页面标题：{last_title}")


async def _safe_page_content(page, timeout_ms: int) -> str:
    deadline = time.monotonic() + timeout_ms / 1000
    last_error = ""
    while time.monotonic() < deadline:
        try:
            return await page.content()
        except Exception as exc:
            last_error = str(exc)
            await page.wait_for_timeout(500)
    raise RuntimeError(f"浏览器页面内容读取失败：{last_error}")


async def _validate_avd_cookie(cookie_header: str, user_agent: str) -> str:
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Cookie": cookie_header,
        "Pragma": "no-cache",
        "Referer": "https://avd.aliyun.com/",
        "User-Agent": user_agent,
    }
    async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
        try:
            response = await client.get(AVD_URL)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return f"后端 HTTP 校验失败：{exc}"
    html = response.text
    if _looks_like_challenge(html) or not _looks_like_avd_page(html):
        return "后端 HTTP 校验未通过，将使用 Chrome 回退抓取"
    return ""


async def validate_cnvd_cookie(cookie_header: str, user_agent: str) -> str:
    headers = cnvd_form_headers(cookie_header=cookie_header, user_agent=user_agent)
    params = cnvd_list_params(offset=0)
    async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
        try:
            response = await client.get(CNVD_URL, params=params)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return f"后端 HTTP 校验失败：{exc}"
    html = response.text
    if looks_like_cnvd_challenge(html) or not looks_like_cnvd_page(html):
        return "后端 HTTP 校验未通过，将使用 Chrome 回退抓取"
    return ""


def cnvd_form_headers(cookie_header: str = "", user_agent: str = "") -> dict[str, str]:
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://www.cnvd.org.cn",
        "Pragma": "no-cache",
        "Referer": CNVD_URL,
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": user_agent or get_cnvd_user_agent(),
    }
    cookie = cookie_header or get_cnvd_cookie_header()
    if cookie:
        headers["Cookie"] = cookie
    return headers


def cnvd_list_params(offset: int = 0, page_size: int | None = None) -> dict[str, str]:
    size = page_size or settings.cnvd_page_size
    size = max(1, min(int(size), 50))
    safe_offset = max(0, int(offset))
    return {
        "flag": "true",
        "numPerPage": str(size),
        "offset": str(safe_offset),
        "keywordFlag": "0",
        "cnvdIdFlag": "0",
        "baseinfoBeanFlag": "0",
        "max": str(size),
    }


def cnvd_form_data(keyword: str = "") -> dict[str, str]:
    return {
        "number": "请输入精确编号",
        "startDate": "",
        "endDate": "",
        "field": "",
        "order": "",
        "keyword": keyword,
        "condition": "1",
        "keywordFlag": "0",
        "cnvdId": "",
        "cnvdIdFlag": "0",
        "baseinfoBeanbeginTime": "",
        "baseinfoBeanendTime": "",
        "baseinfoBeanFlag": "0",
        "refenceInfo": "",
        "referenceScope": "-1",
        "manufacturerId": "-1",
        "categoryId": "-1",
        "editionId": "-1",
        "causeIdStr": "",
        "threadIdStr": "",
        "serverityIdStr": "",
        "positionIdStr": "",
    }


def _looks_like_challenge(html: str) -> bool:
    text = html.lower()
    return any(
        marker in text
        for marker in [
            "_waf_",
            "sigchl",
            "punish",
            "captcha",
            "验证码",
            "安全验证",
            "enable javascript",
        ]
    )


def _looks_like_avd_page(html: str) -> bool:
    return "/detail?id=" in html or "阿里云漏洞库" in html or "AVD" in html


def looks_like_cnvd_challenge(html: str) -> bool:
    text = html.lower()
    return any(
        marker in text
        for marker in [
            "__jsl_clearance",
            "jsl_clearance",
            "验证码",
            "安全验证",
            "enable javascript",
            "document.cookie",
        ]
    )


def looks_like_cnvd_page(html: str) -> bool:
    return "/flaw/show/" in html or "国家信息安全漏洞共享平台" in html or "CNVD" in html


def _cookie_header(cookies: list[dict[str, Any]]) -> str:
    values = []
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if name and value is not None:
            values.append(f"{name}={value}")
    return "; ".join(values)


def _browser_executable_path() -> str:
    configured = settings.avd_browser_executable_path
    if configured and Path(configured).exists():
        return configured
    candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return ""


def _mask_cookie(cookie_header: str) -> str:
    if not cookie_header:
        return ""
    names = []
    for chunk in cookie_header.split(";"):
        name = chunk.split("=", 1)[0].strip()
        if name:
            names.append(name)
    if not names:
        return "configured"
    visible = ", ".join(names[:4])
    suffix = "" if len(names) <= 4 else f", +{len(names) - 4}"
    return f"{visible}{suffix}"
