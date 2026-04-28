from __future__ import annotations

import asyncio
import contextlib
import html
import json
import logging
import secrets
import shlex
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
import websockets
from fastapi import Request, WebSocket
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from .auth import SESSION_COOKIE, session_is_valid, token_is_valid
from .browser_cookie import (
    CNVD_URL,
    get_cnvd_user_agent,
    set_cnvd_browser_cookie,
)
from .config import settings


logger = logging.getLogger("zhuwei.browser_proxy")


class BrowserProxyError(RuntimeError):
    pass


@dataclass(frozen=True)
class BrowserSource:
    key: str
    label: str
    target_url: str
    cookie_origin: str
    aliases: tuple[str, ...] = ()


@dataclass
class BrowserProxySession:
    source: BrowserSource
    image: str
    container_name: str
    vnc_port: int
    webdriver_port: int
    webdriver_session_id: str
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def browse_url(self) -> str:
        source = quote(self.source.key)
        return (
            f"/proxy/browse/{source}/?autoconnect=1&resize=scale"
            f"&path=proxy/browse/{source}/websockify"
        )

    @property
    def webdriver_url(self) -> str:
        if settings.browser_proxy_connect_mode == "container":
            return f"http://{self.container_name}:4444"
        return f"http://{settings.browser_proxy_connect_host}:{self.webdriver_port}"

    @property
    def vnc_url(self) -> str:
        if settings.browser_proxy_connect_mode == "container":
            return f"http://{self.container_name}:7900"
        return f"http://{settings.browser_proxy_connect_host}:{self.vnc_port}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.key,
            "label": self.source.label,
            "container_name": self.container_name,
            "browse_url": self.browse_url,
            "vnc_url": self.vnc_url,
            "webdriver_url": self.webdriver_url,
            "vnc_port": self.vnc_port,
            "webdriver_port": self.webdriver_port,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat(),
            "image": self.image,
        }


SOURCES: dict[str, BrowserSource] = {
    "cnvd": BrowserSource(
        key="cnvd",
        label="CNVD",
        target_url=CNVD_URL,
        cookie_origin="https://www.cnvd.org.cn",
        aliases=("cnvd_list",),
    ),
}
SOURCE_ALIASES = {
    alias: source.key
    for source in SOURCES.values()
    for alias in (source.key, *source.aliases)
}
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


_sessions: dict[str, BrowserProxySession] = {}
_lock = asyncio.Lock()
_cleanup_task: asyncio.Task | None = None


def normalize_browser_source(value: str) -> BrowserSource:
    key = SOURCE_ALIASES.get((value or "").strip().lower())
    if not key:
        raise BrowserProxyError(f"不支持的浏览器数据源：{value}")
    return SOURCES[key]


def browser_proxy_status() -> dict[str, Any]:
    return {
        "enabled": settings.browser_proxy_enabled,
        "image": settings.browser_proxy_image,
        "candidate_images": _candidate_images(),
        "host": settings.browser_proxy_host,
        "bind_host": settings.browser_proxy_bind_host,
        "connect_host": settings.browser_proxy_connect_host,
        "connect_mode": settings.browser_proxy_connect_mode,
        "ttl_seconds": settings.browser_proxy_ttl_seconds,
        "pull_timeout_seconds": settings.browser_proxy_pull_timeout_seconds,
        "sessions": [session.as_dict() for session in _sessions.values()],
        "sources": [
            {
                "key": source.key,
                "label": source.label,
                "target_url": source.target_url,
                "aliases": list(source.aliases),
                "active": source.key in _sessions,
                "browse_url": f"/proxy/browse/{quote(source.key)}",
            }
            for source in SOURCES.values()
        ],
    }


async def open_browser_proxy(source_key: str) -> dict[str, Any]:
    session = await ensure_browser_session(source_key)
    return {"status": "ok", "data": session.as_dict()}


async def ensure_browser_session(source_key: str) -> BrowserProxySession:
    if not settings.browser_proxy_enabled:
        raise BrowserProxyError("容器浏览器代理未启用")
    source = normalize_browser_source(source_key)
    async with _lock:
        current = _sessions.get(source.key)
        if current and await _session_is_alive(current):
            _touch_session(current)
            return current
        if current:
            await _stop_session(current)
            _sessions.pop(source.key, None)

        session = await _start_session(source)
        _sessions[source.key] = session
        return session


async def capture_browser_proxy_session(source_key: str) -> dict[str, Any]:
    source = normalize_browser_source(source_key)
    session = _sessions.get(source.key)
    if not session or not await _session_is_alive(session):
        raise BrowserProxyError("容器浏览器会话不存在，请先打开 /proxy/browse 完成访问")
    _touch_session(session)
    cookies = await _webdriver_get_cookies(session)
    cookie_header = _cookie_header(cookies)
    if not cookie_header:
        raise BrowserProxyError("当前浏览器页面没有可用 Cookie，请先在容器浏览器中完成访问")
    user_agent = await _webdriver_user_agent(session)
    if source.key != "cnvd":
        raise BrowserProxyError(f"暂不支持保存 {source.label} 会话")
    status = await set_cnvd_browser_cookie(cookie_header, user_agent)
    return {
        "status": "ok",
        "source": source.key,
        "cookie_names": [cookie.get("name") for cookie in cookies if cookie.get("name")],
        "user_agent": user_agent,
        "session": status,
    }


async def stop_browser_proxy_session(source_key: str) -> dict[str, Any]:
    source = normalize_browser_source(source_key)
    async with _lock:
        session = _sessions.pop(source.key, None)
    if session:
        await _stop_session(session)
    return {"status": "ok", "source": source.key}


async def browser_proxy_landing(source_key: str) -> HTMLResponse:
    source = normalize_browser_source(source_key)
    session = await ensure_browser_session(source.key)
    escaped_label = html.escape(source.label)
    escaped_target = html.escape(source.target_url)
    browse_url = html.escape(session.browse_url)
    source_json = json.dumps(source.key)
    label_json = json.dumps(source.label)
    return HTMLResponse(
        f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{escaped_label} 容器浏览器</title>
  <style>
    html, body {{ width: 100%; height: 100%; margin: 0; background: #0f172a; color: #e5e7eb; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    .bar {{ height: 42px; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 0 14px; background: #111827; border-bottom: 1px solid rgba(148, 163, 184, .22); box-sizing: border-box; }}
    .bar strong {{ font-size: 14px; }}
    .bar span {{ color: #94a3b8; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .bar a {{ color: #93c5fd; font-size: 12px; text-decoration: none; }}
    .status {{ min-width: 220px; color: #a7f3d0; font-size: 12px; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .status.waiting {{ color: #fef3c7; }}
    .status.error {{ color: #fecaca; }}
    iframe {{ width: 100%; height: calc(100% - 42px); border: 0; background: #020617; }}
  </style>
</head>
<body>
  <div class="bar">
    <strong>{escaped_label} 容器浏览器</strong>
    <span>{escaped_target}</span>
    <div id="autoStatus" class="status waiting">通过验证后将自动保存会话并采集</div>
    <a href="/app#sessionPanel">返回后台</a>
  </div>
  <iframe src="{browse_url}" allow="clipboard-read; clipboard-write"></iframe>
  <script>
    const sourceKey = {source_json};
    const sourceLabel = {label_json};
    const statusNode = document.querySelector("#autoStatus");
    let autoFinished = false;
    let autoRunning = false;
    let attempts = 0;

    function setStatus(text, kind = "waiting") {{
      statusNode.textContent = text;
      statusNode.className = `status ${{kind}}`;
    }}

    async function autoCaptureAndRun() {{
      if (autoFinished || autoRunning) return;
      autoRunning = true;
      attempts += 1;
      try {{
        const response = await fetch(`/api/browser-proxy/${{encodeURIComponent(sourceKey)}}/capture-run`, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ attempt: attempts }}),
        }});
        const data = await response.json().catch(() => ({{}}));
        if (!response.ok) throw new Error(data.detail || response.statusText || "自动接管失败");
        if (data.status === "done") {{
          autoFinished = true;
          const run = data.run || {{}};
          setStatus(`${{sourceLabel}} 会话已保存，采集完成：${{run.item_count ?? 0}} 条`, "success");
          window.setTimeout(() => {{
            window.location.href = data.redirect || "/app#sourcesPanel";
          }}, 1400);
        }} else if (data.status === "running") {{
          setStatus(data.message || "验证已通过，正在采集漏洞情报...", "success");
        }} else {{
          setStatus(data.message || "等待验证通过...", "waiting");
        }}
      }} catch (error) {{
        setStatus(`自动接管等待中：${{error.message}}`, "error");
      }} finally {{
        autoRunning = false;
      }}
    }}

    window.setTimeout(autoCaptureAndRun, 5000);
    window.setInterval(autoCaptureAndRun, 6000);
  </script>
</body>
</html>"""
    )


async def proxy_browser_http(source_key: str, proxy_path: str, request: Request) -> Response:
    source = normalize_browser_source(source_key)
    if not proxy_path and not request.url.path.endswith("/"):
        return RedirectResponse(url=f"/proxy/browse/{quote(source.key)}/", status_code=307)
    session = await ensure_browser_session(source.key)
    _touch_session(session)
    target_url = _target_url(session.vnc_url, proxy_path, request.url.query)
    body = await request.body()
    headers = _proxy_request_headers(request.headers, session.vnc_url)
    async with httpx.AsyncClient(timeout=None, follow_redirects=False) as client:
        upstream = await client.request(
            request.method,
            target_url,
            content=body,
            headers=headers,
        )
    response_headers = _proxy_response_headers(upstream.headers, source.key, session.vnc_url)
    content = _rewrite_proxy_body(upstream.content, upstream.headers.get("content-type", ""), source.key)
    return Response(content=content, status_code=upstream.status_code, headers=response_headers)


async def proxy_browser_websocket(source_key: str, proxy_path: str, websocket: WebSocket) -> None:
    if not _websocket_is_authenticated(websocket):
        await websocket.close(code=1008)
        return
    source = normalize_browser_source(source_key)
    session = await ensure_browser_session(source.key)
    _touch_session(session)
    query = websocket.url.query
    upstream_uri = _target_url(session.vnc_url, proxy_path, query, scheme="ws")
    subprotocols = _websocket_subprotocols(websocket)
    upstream_headers = {
        key: value
        for key, value in websocket.headers.items()
        if key.lower()
        not in {
            "host",
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
        }
    }
    try:
        async with websockets.connect(
            upstream_uri,
            additional_headers=upstream_headers,
            subprotocols=subprotocols or None,
            ping_interval=None,
            max_size=None,
        ) as upstream:
            await websocket.accept(subprotocol=getattr(upstream, "subprotocol", None))
            await _bridge_websockets(websocket, upstream)
    except Exception as exc:
        logger.warning("browser websocket proxy failed: %s", exc)
        with contextlib.suppress(Exception):
            await websocket.close(code=1011)


async def cleanup_browser_proxy_orphans() -> None:
    if not settings.browser_proxy_enabled:
        return
    try:
        ids = await _docker(
            [
                "ps",
                "-aq",
                "--filter",
                "label=zhuwei.browser-proxy=true",
            ],
            timeout=15,
        )
    except Exception as exc:
        logger.info("skip browser proxy orphan cleanup: %s", exc)
        return
    container_ids = [line.strip() for line in ids.splitlines() if line.strip()]
    if not container_ids:
        return
    with contextlib.suppress(Exception):
        await _docker(["rm", "-f", *container_ids], timeout=30)


def start_browser_proxy_cleanup_task() -> None:
    global _cleanup_task
    if _cleanup_task and not _cleanup_task.done():
        return
    _cleanup_task = asyncio.create_task(_cleanup_loop())


async def stop_all_browser_proxy_sessions() -> None:
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _cleanup_task
        _cleanup_task = None
    sessions = list(_sessions.values())
    _sessions.clear()
    for session in sessions:
        await _stop_session(session)


async def _cleanup_loop() -> None:
    while True:
        await asyncio.sleep(60)
        await _cleanup_expired_sessions()


async def _cleanup_expired_sessions() -> None:
    now = datetime.now(timezone.utc)
    expired = [key for key, session in _sessions.items() if session.expires_at <= now]
    for key in expired:
        session = _sessions.pop(key, None)
        if session:
            await _stop_session(session)


async def _start_session(source: BrowserSource) -> BrowserProxySession:
    errors: list[str] = []
    for image in _candidate_images():
        try:
            return await _start_session_with_image(source, image)
        except BrowserProxyError as exc:
            errors.append(f"{image}: {exc}")
            continue
    raise BrowserProxyError("容器浏览器启动失败：" + " | ".join(errors))


async def _start_session_with_image(source: BrowserSource, image: str) -> BrowserProxySession:
    if settings.browser_proxy_pull_image:
        await _docker(["pull", image], timeout=settings.browser_proxy_pull_timeout_seconds)
    else:
        await _ensure_docker_image(image)
    if settings.browser_proxy_connect_mode == "container":
        if not settings.browser_proxy_docker_network:
            raise BrowserProxyError("容器直连模式需要配置 BROWSER_PROXY_DOCKER_NETWORK")
        vnc_port = 7900
        webdriver_port = 4444
    else:
        vnc_port = _free_port()
        webdriver_port = _free_port()
    token = secrets.token_hex(4)
    container_name = f"zhuwei-browser-{source.key}-{token}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=settings.browser_proxy_ttl_seconds)
    run_args = [
        "run",
        "-d",
        "--rm",
        "--name",
        container_name,
        "--shm-size",
        "2g",
        "--label",
        "zhuwei.browser-proxy=true",
        "--label",
        f"zhuwei.source={source.key}",
        "--label",
        f"zhuwei.expires-at={expires_at.isoformat()}",
        "-e",
        "SE_START_XVFB=true",
        "-e",
        "SE_VNC_NO_PASSWORD=true",
        "-e",
        "SE_SCREEN_WIDTH=1440",
        "-e",
        "SE_SCREEN_HEIGHT=960",
        "-e",
        f"SE_NODE_SESSION_TIMEOUT={settings.browser_proxy_ttl_seconds}",
    ]
    if settings.browser_proxy_connect_mode == "published":
        run_args.extend(
            [
                "-p",
                f"{settings.browser_proxy_bind_host}:{vnc_port}:7900",
                "-p",
                f"{settings.browser_proxy_bind_host}:{webdriver_port}:4444",
            ]
        )
    if settings.browser_proxy_docker_network:
        run_args.extend(["--network", settings.browser_proxy_docker_network])
    run_args.append(image)
    try:
        await _docker(run_args, timeout=settings.browser_proxy_start_timeout_seconds)
        webdriver_session_id = await _create_webdriver_session(
            source,
            _webdriver_endpoint(container_name, webdriver_port),
        )
        session = BrowserProxySession(
            source=source,
            image=image,
            container_name=container_name,
            vnc_port=vnc_port,
            webdriver_port=webdriver_port,
            webdriver_session_id=webdriver_session_id,
            created_at=now,
            expires_at=expires_at,
            last_used_at=now,
        )
        try:
            await _webdriver_navigate(session, source.target_url)
        except Exception as exc:
            logger.warning("initial browser navigation failed for %s: %s", source.key, exc)
        return session
    except Exception:
        with contextlib.suppress(Exception):
            await _docker(["rm", "-f", container_name], timeout=20)
        raise


async def _create_webdriver_session(source: BrowserSource, base_url: str) -> str:
    deadline = asyncio.get_event_loop().time() + settings.browser_proxy_start_timeout_seconds
    last_error = ""
    async with httpx.AsyncClient(timeout=10) as client:
        while asyncio.get_event_loop().time() < deadline:
            try:
                response = await client.get(f"{base_url}/status")
                if response.status_code < 500:
                    break
            except httpx.HTTPError as exc:
                last_error = str(exc)
            await asyncio.sleep(1)
        else:
            raise BrowserProxyError(f"Selenium Chrome 启动超时：{last_error}")

        payload = {
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "chrome",
                    "goog:chromeOptions": {
                        "args": [
                            "--disable-blink-features=AutomationControlled",
                            "--disable-dev-shm-usage",
                            "--lang=zh-CN",
                            "--window-size=1440,960",
                            f"--user-agent={_source_user_agent(source)}",
                        ]
                    },
                }
            }
        }
        response = await client.post(f"{base_url}/session", json=payload)
        response.raise_for_status()
        data = response.json()
        value = data.get("value") or {}
        session_id = value.get("sessionId") or data.get("sessionId")
        if not session_id:
            raise BrowserProxyError(f"Selenium 未返回 sessionId：{json.dumps(data, ensure_ascii=False)[:300]}")
        return str(session_id)


async def _webdriver_navigate(session: BrowserProxySession, url: str) -> None:
    await _webdriver_request(session, "POST", f"/session/{session.webdriver_session_id}/url", {"url": url})


async def _webdriver_get_cookies(session: BrowserProxySession) -> list[dict[str, Any]]:
    response = await _webdriver_request(session, "GET", f"/session/{session.webdriver_session_id}/cookie")
    value = response.get("value") or []
    return value if isinstance(value, list) else []


async def _webdriver_user_agent(session: BrowserProxySession) -> str:
    response = await _webdriver_request(
        session,
        "POST",
        f"/session/{session.webdriver_session_id}/execute/sync",
        {"script": "return navigator.userAgent", "args": []},
    )
    return str(response.get("value") or "")


async def _webdriver_request(
    session: BrowserProxySession,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.request(method, f"{session.webdriver_url}{path}", json=payload)
        response.raise_for_status()
        return response.json()


async def _session_is_alive(session: BrowserProxySession) -> bool:
    if session.expires_at <= datetime.now(timezone.utc):
        return False
    try:
        await _webdriver_request(session, "GET", f"/session/{session.webdriver_session_id}/url")
        return True
    except Exception:
        return False


async def _stop_session(session: BrowserProxySession) -> None:
    with contextlib.suppress(Exception):
        await _webdriver_request(session, "DELETE", f"/session/{session.webdriver_session_id}")
    with contextlib.suppress(Exception):
        await _docker(["rm", "-f", session.container_name], timeout=20)


async def _docker(args: list[str], timeout: int = 30) -> str:
    command = [*_docker_command(), *args]
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        raise BrowserProxyError(f"Docker 命令超时：{' '.join(command)}") from exc
    out = stdout.decode("utf-8", "replace").strip()
    err = stderr.decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        raise BrowserProxyError(err or out or f"Docker 命令失败：{' '.join(command)}")
    return out


async def _ensure_docker_image(image: str) -> None:
    try:
        await _docker(["image", "inspect", image], timeout=15)
        return
    except BrowserProxyError:
        pass
    await _docker(["pull", image], timeout=settings.browser_proxy_pull_timeout_seconds)


def _docker_command() -> list[str]:
    return shlex.split(settings.browser_proxy_docker_command) or ["docker"]


def _candidate_images() -> list[str]:
    images = [settings.browser_proxy_image]
    if _host_is_arm():
        images.extend(
            [
                "seleniarm/standalone-chromium:latest",
                "selenium/standalone-chromium:latest",
            ]
        )
    fallback = "selenium/standalone-chromium:latest"
    if "standalone-chrome" in settings.browser_proxy_image and fallback not in images:
        images.append(fallback)
    return [image for index, image in enumerate(images) if image and image not in images[:index]]


def _host_is_arm() -> bool:
    return platform_machine() in {"arm64", "aarch64"} or platform_machine().startswith("arm")


def platform_machine() -> str:
    try:
        import platform

        return platform.machine().strip().lower()
    except Exception:
        return ""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((settings.browser_proxy_bind_host, 0))
        return int(sock.getsockname()[1])


def _webdriver_endpoint(container_name: str, port: int) -> str:
    if settings.browser_proxy_connect_mode == "container":
        return f"http://{container_name}:4444"
    return f"http://{settings.browser_proxy_connect_host}:{port}"


def _touch_session(session: BrowserProxySession) -> None:
    now = datetime.now(timezone.utc)
    session.last_used_at = now
    session.expires_at = now + timedelta(seconds=settings.browser_proxy_ttl_seconds)


def _source_user_agent(source: BrowserSource) -> str:
    return get_cnvd_user_agent()


def _cookie_header(cookies: list[dict[str, Any]]) -> str:
    pairs = []
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if name and value is not None:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def _target_url(base_url: str, proxy_path: str, query: str, scheme: str | None = None) -> str:
    parsed = urlsplit(base_url)
    target_scheme = scheme or parsed.scheme or "http"
    netloc = parsed.netloc
    path = "/" + (proxy_path or "").lstrip("/")
    if path == "/":
        path = "/"
    return urlunsplit((target_scheme, netloc, path, query, ""))


def _proxy_request_headers(headers: Any, base_url: str) -> dict[str, str]:
    proxied = {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS | {"host", "content-length", "accept-encoding"}
    }
    proxied["host"] = urlsplit(base_url).netloc
    return proxied


def _proxy_response_headers(headers: httpx.Headers, source_key: str, base_url: str) -> dict[str, str]:
    proxied: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in HOP_BY_HOP_HEADERS | {"content-length", "content-encoding"}:
            continue
        if lower == "location":
            value = _rewrite_location(value, source_key, base_url)
        proxied[key] = value
    return proxied


def _rewrite_location(value: str, source_key: str, base_url: str) -> str:
    prefix = f"/proxy/browse/{quote(source_key)}"
    direct_base = base_url.rstrip("/")
    if value.startswith(direct_base):
        parsed = urlsplit(value)
        return urlunsplit(("", "", f"{prefix}{parsed.path}", parsed.query, parsed.fragment))
    if value.startswith("/"):
        return f"{prefix}{value}"
    return value


def _rewrite_proxy_body(content: bytes, content_type: str, source_key: str) -> bytes:
    lower = content_type.lower()
    if not content or "text/html" not in lower:
        return content
    prefix = f"/proxy/browse/{quote(source_key)}/".encode()
    return (
        content.replace(b'href="/', b'href="' + prefix)
        .replace(b'src="/', b'src="' + prefix)
        .replace(b'action="/', b'action="' + prefix)
    )


def _websocket_is_authenticated(websocket: WebSocket) -> bool:
    token = websocket.headers.get("x-app-token", "")
    bearer = websocket.headers.get("authorization", "")
    auth_token = ""
    if bearer.lower().startswith("bearer "):
        auth_token = bearer.split(" ", 1)[1].strip()
    session_cookie = websocket.cookies.get(SESSION_COOKIE, "")
    return token_is_valid(token) or token_is_valid(auth_token) or session_is_valid(session_cookie)


def _websocket_subprotocols(websocket: WebSocket) -> list[str]:
    header = websocket.headers.get("sec-websocket-protocol", "")
    return [item.strip() for item in header.split(",") if item.strip()]


async def _bridge_websockets(websocket: WebSocket, upstream: Any) -> None:
    async def client_to_upstream() -> None:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                await upstream.close()
                return
            if "bytes" in message and message["bytes"] is not None:
                await upstream.send(message["bytes"])
            elif "text" in message and message["text"] is not None:
                await upstream.send(message["text"])

    async def upstream_to_client() -> None:
        async for message in upstream:
            if isinstance(message, bytes):
                await websocket.send_bytes(message)
            else:
                await websocket.send_text(str(message))

    tasks = [
        asyncio.create_task(client_to_upstream()),
        asyncio.create_task(upstream_to_client()),
    ]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    for task in done:
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("browser websocket bridge task failed: %s", exc)
    with contextlib.suppress(Exception):
        await websocket.close()
