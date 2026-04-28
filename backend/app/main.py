from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from . import db
from .async_utils import run_blocking
from .analysis import (
    cancel_vulnerability_analysis,
    enqueue_vulnerability_analysis,
    follow_vulnerability_product,
    list_followed_products,
    requeue_failed_analyses,
    start_analysis_queue,
    unfollow_product,
)
from .auth import clear_session_cookie, issue_session_cookie, request_is_authenticated, require_auth
from .browser_cookie import (
    clear_avd_browser_cookie,
    clear_cnvd_browser_cookie,
    get_avd_session_status,
    get_cnvd_session_status,
    refresh_avd_browser_cookie,
    refresh_cnvd_browser_cookie,
    set_cnvd_browser_cookie,
)
from .browser_proxy import (
    BrowserProxyError,
    browser_proxy_landing,
    browser_proxy_status,
    capture_browser_proxy_session,
    cleanup_browser_proxy_orphans,
    open_browser_proxy,
    proxy_browser_http,
    proxy_browser_websocket,
    start_browser_proxy_cleanup_task,
    stop_all_browser_proxy_sessions,
    stop_browser_proxy_session,
)
from .claude_code import ensure_claude_code, get_claude_code_status
from .config import settings
from .deepseek import (
    clear_deepseek_api_key,
    get_deepseek_status,
    refresh_deepseek_balance,
    set_deepseek_api_key,
)
from .enrichment import backfill_missing_cvss
from .github_intel import (
    GitHubSearchError,
    refresh_github_evidence_for_vulnerability,
    refresh_recent_github_evidence,
)
from .infra import infrastructure_status
from .minio_store import presigned_get_url
from .monitor import current_alert_filters, get_monitor_rules, set_monitor_rules
from .neo4j_graph import graph_status, product_neighborhood, sync_graph, vulnerability_neighborhood
from .product_resolution import backfill_products_direct, schedule_deepseek_flash_for_alerts
from .scheduler import list_jobs, start_scheduler, stop_scheduler
from .services import source_service
from .source_archive import (
    create_source_archive_from_stream,
    delete_source_archive,
    retry_minio_upload,
    schedule_source_archive_processing,
    start_source_archive_workers,
)
from .update_manager import (
    create_update_from_stream,
    get_update,
    list_updates,
    schedule_update_processing,
    start_update_workers,
    update_state,
)


app = FastAPI(title="烛微 ZhuWei")
logger = logging.getLogger("zhuwei")


@app.on_event("startup")
async def on_startup() -> None:
    db.init_db()
    db.recover_interrupted_runs()
    await ensure_claude_code()
    source_service.register_sources()
    start_source_archive_workers()
    start_update_workers()
    start_analysis_queue()
    start_scheduler()
    await cleanup_browser_proxy_orphans()
    start_browser_proxy_cleanup_task()
    login_url = "http://127.0.0.1:8010/login"
    logger.warning("烛微 login: %s", login_url)
    logger.warning("Random login token for this startup: %s", settings.app_token)
    print(f"[烛微] login: {login_url}", flush=True)
    print(f"[烛微] random token: {settings.app_token}", flush=True)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    stop_scheduler()
    await stop_all_browser_proxy_sessions()


@app.middleware("http")
async def protect_frontend_and_api(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path != "/api/auth/session":
        if not request_is_authenticated(request):
            return JSONResponse({"detail": "token required"}, status_code=401)
    if path == "/app" or path.startswith("/assets/") or path.startswith("/proxy/"):
        if not request_is_authenticated(request):
            next_path = path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(url=f"/login?next={quote(next_path, safe='')}", status_code=302)
    return await call_next(request)


@app.get("/")
async def root(request: Request):
    if request_is_authenticated(request):
        return RedirectResponse(url="/app", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login")
async def login_page():
    return FileResponse(settings.frontend_dir / "login.html")


def _frontend_file(base_dir: Path, asset_path: str) -> Path:
    base = base_dir.resolve()
    asset = (base / asset_path).resolve()
    if base not in asset.parents and asset != base:
        raise HTTPException(status_code=404, detail="not found")
    if not asset.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return asset


@app.get("/favicon.ico")
async def favicon():
    return FileResponse(settings.frontend_dir / "brand" / "logo-mark.svg", media_type="image/svg+xml")


@app.get("/brand/{asset_path:path}")
async def brand_asset(asset_path: str):
    return FileResponse(_frontend_file(settings.frontend_dir / "brand", asset_path))


@app.get("/app")
async def app_page():
    return FileResponse(settings.frontend_dir / "index.html")


@app.get("/assets/{asset_path:path}")
async def frontend_asset(asset_path: str):
    return FileResponse(_frontend_file(settings.frontend_dir, asset_path))


@app.get("/proxy/browse")
async def browser_proxy_page(source: str = "cnvd", _: None = Depends(require_auth)):
    try:
        return await browser_proxy_landing(source)
    except BrowserProxyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/proxy/browse/{source}")
async def browser_proxy_source_page(source: str, _: None = Depends(require_auth)):
    return RedirectResponse(url=f"/proxy/browse/{source}/", status_code=307)


@app.api_route(
    "/proxy/browse/{source}/{proxy_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def browser_proxy_route(source: str, proxy_path: str, request: Request, _: None = Depends(require_auth)):
    try:
        return await proxy_browser_http(source, proxy_path, request)
    except BrowserProxyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.websocket("/proxy/browse/{source}/{proxy_path:path}")
async def browser_proxy_ws(source: str, proxy_path: str, websocket: WebSocket):
    await proxy_browser_websocket(source, proxy_path, websocket)


@app.post("/api/auth/session")
async def create_session(response: Response, _: None = Depends(require_auth)):
    issue_session_cookie(response)
    return {"status": "ok"}


@app.post("/api/auth/logout")
async def logout(response: Response, _: None = Depends(require_auth)):
    clear_session_cookie(response)
    return {"status": "ok"}


@app.get("/api/summary")
async def get_summary(_: None = Depends(require_auth)):
    payload = await run_blocking(db.summary)
    graph = await run_blocking(graph_status)
    payload["graph_nodes"] = graph.get("nodes", 0) if graph.get("available") else 0
    payload["graph_relationships"] = graph.get("relationships", 0) if graph.get("available") else 0
    return payload


@app.get("/api/infra/status")
async def get_infra_status(_: None = Depends(require_auth)):
    return await run_blocking(infrastructure_status)


@app.get("/api/graph/status")
async def get_graph_status(_: None = Depends(require_auth)):
    return await run_blocking(graph_status)


@app.post("/api/graph/sync")
async def sync_graph_endpoint(payload: dict | None = None, _: None = Depends(require_auth)):
    try:
        limit = max(50, min(int((payload or {}).get("limit") or 800), 5000))
        return await run_blocking(sync_graph, limit=limit)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/graph/vulnerabilities/{vulnerability_id}")
async def get_vulnerability_graph(vulnerability_id: int, depth: int = 2, _: None = Depends(require_auth)):
    try:
        return await run_blocking(vulnerability_neighborhood, vulnerability_id, depth=depth)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/graph/search")
async def search_graph(
    q: str,
    kind: str = "auto",
    depth: int = 2,
    _: None = Depends(require_auth),
):
    query = q.strip()
    if not query:
        raise HTTPException(status_code=400, detail="q is required")
    kind = kind.strip().lower() or "auto"
    if kind not in {"auto", "vulnerability", "product"}:
        raise HTTPException(status_code=400, detail="kind must be auto, vulnerability, or product")
    depth = max(1, min(int(depth or 2), 4))
    try:
        def find_vulnerability() -> dict | None:
            vulnerability = None
            if query.isdigit():
                vulnerability = db.get_vulnerability(int(query))
            if not vulnerability:
                matches = db.list_vulnerabilities(query=query, limit=1, offset=0).get("data", [])
                vulnerability = matches[0] if matches else None
            return vulnerability

        def find_product() -> dict | None:
            product = None
            if query.startswith("product:"):
                product = db.get_product_detail(query)
            if not product:
                matches = db.list_products(query=query, limit=1, offset=0).get("data", [])
                product = matches[0] if matches else None
            return product

        def vulnerability_payload(vulnerability: dict) -> dict:
            graph = vulnerability_neighborhood(int(vulnerability["id"]), depth=depth)
            return {
                "target": {
                    "kind": "vulnerability",
                    "id": vulnerability["id"],
                    "label": vulnerability.get("cve_id") or vulnerability.get("title") or str(vulnerability["id"]),
                    "title": vulnerability.get("title") or "",
                    "product": vulnerability.get("product") or "",
                },
                "graph": graph,
            }

        def product_payload(product: dict) -> dict:
            product_key = str(product.get("canonical_product_key") or product.get("product_key") or "")
            graph = product_neighborhood(product_key, depth=depth)
            return {
                "target": {
                    "kind": "product",
                    "product_key": product_key,
                    "label": product.get("name") or product_key,
                    "vendor": product.get("vendor") or "",
                },
                "graph": graph,
            }

        vulnerability_first = query.isdigit() or query.upper().startswith("CVE-")
        if kind == "vulnerability" or (kind == "auto" and vulnerability_first):
            vulnerability = await run_blocking(find_vulnerability)
            if vulnerability:
                return await run_blocking(vulnerability_payload, vulnerability)

        if kind in {"auto", "product"}:
            product = await run_blocking(find_product)
            if product:
                return await run_blocking(product_payload, product)

        if kind == "auto" and not vulnerability_first:
            vulnerability = await run_blocking(find_vulnerability)
            if vulnerability:
                return await run_blocking(vulnerability_payload, vulnerability)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    raise HTTPException(status_code=404, detail="未找到匹配的漏洞或产品")


@app.get("/api/graph/products/{product_key:path}")
async def get_product_graph(product_key: str, depth: int = 2, _: None = Depends(require_auth)):
    try:
        return await run_blocking(product_neighborhood, product_key, depth=depth)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/messages")
async def get_messages(
    status: str = "",
    category: str = "",
    limit: int = 30,
    offset: int = 0,
    _: None = Depends(require_auth),
):
    if status not in {"", "unread", "read"}:
        raise HTTPException(status_code=400, detail="status must be unread or read")
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    return await run_blocking(db.list_messages, status=status, category=category, limit=limit, offset=offset)


@app.post("/api/messages/{message_id}/read")
async def read_message(message_id: int, _: None = Depends(require_auth)):
    if not await run_blocking(db.mark_message_read, message_id, True):
        raise HTTPException(status_code=404, detail="message not found")
    return {"status": "ok"}


@app.post("/api/messages/{message_id}/unread")
async def unread_message(message_id: int, _: None = Depends(require_auth)):
    if not await run_blocking(db.mark_message_read, message_id, False):
        raise HTTPException(status_code=404, detail="message not found")
    return {"status": "ok"}


@app.post("/api/messages/read-all")
async def read_all_messages(_: None = Depends(require_auth)):
    return {"status": "ok", "count": await run_blocking(db.mark_all_messages_read)}


@app.get("/api/sources")
async def get_sources(_: None = Depends(require_auth)):
    sources = await run_blocking(db.list_sources)
    return {"data": sources, "jobs": list_jobs()}


@app.get("/api/source-archives")
async def get_source_archives(
    status: str = "",
    q: str = "",
    version_role: str = "",
    limit: int = 30,
    offset: int = 0,
    _: None = Depends(require_auth),
):
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    payload = await run_blocking(
        db.list_source_archives,
        status=status,
        query=q,
        version_role=version_role,
        limit=limit,
        offset=offset,
    )
    payload["data"] = [_public_source_archive(item) for item in payload.get("data", [])]
    return payload


@app.post("/api/source-archives/upload")
async def upload_source_archive(request: Request, _: None = Depends(require_auth)):
    filename = unquote(request.headers.get("x-source-filename") or "source.zip")
    product_hint = unquote(request.headers.get("x-source-product") or "")
    source_version = unquote(request.headers.get("x-source-version") or "")
    content_type = request.headers.get("content-type") or "application/octet-stream"
    try:
        archive = await create_source_archive_from_stream(
            request.stream(),
            filename=filename,
            content_type=content_type,
            product_hint=product_hint,
            source_version=source_version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return {"status": "queued", "data": _public_source_archive(archive)}


@app.get("/api/source-archives/{archive_id}")
async def get_source_archive(archive_id: int, _: None = Depends(require_auth)):
    archive = await run_blocking(db.get_source_archive, archive_id)
    if not archive:
        raise HTTPException(status_code=404, detail="source archive not found")
    return _public_source_archive(archive)


@app.post("/api/source-archives/{archive_id}/confirm-product")
async def confirm_source_archive_product(archive_id: int, payload: dict, _: None = Depends(require_auth)):
    try:
        archive = await run_blocking(
            db.confirm_source_archive_product,
            archive_id,
            product_name=str(payload.get("product_name") or ""),
            product_key_value=str(payload.get("product_key") or ""),
            vendor=str(payload.get("vendor") or ""),
            aliases=payload.get("aliases") if isinstance(payload.get("aliases"), list) else [],
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not archive:
        raise HTTPException(status_code=404, detail="source archive not found")
    await run_blocking(
        db.create_message,
        level="success",
        category="source_archive",
        title="源码产品已确认",
        body=f"{archive.get('filename')}\n产品：{archive.get('product_name')}",
        entity_type="source_archive",
        entity_id=archive_id,
        raw={"source_archive_id": archive_id, "product_key": archive.get("product_key")},
    )
    return {"status": "ok", "data": _public_source_archive(archive)}


@app.post("/api/source-archives/{archive_id}/cancel")
async def cancel_source_archive_ingest(archive_id: int, payload: dict | None = None, _: None = Depends(require_auth)):
    try:
        archive = await run_blocking(
            delete_source_archive,
            archive_id,
            reason=str((payload or {}).get("reason") or ""),
            require_unconfirmed=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not archive:
        raise HTTPException(status_code=404, detail="source archive not found")
    await run_blocking(
        db.create_message,
        level="warning",
        category="source_archive",
        title="源码入库已取消并删除",
        body=f"{archive.get('filename')}\n已删除源码记录、本地源码文件，并尝试删除 MinIO 对象。",
        entity_type="source_archive",
        entity_id=archive_id,
        raw={"source_archive_id": archive_id, "cleanup": archive.get("cleanup")},
    )
    return {"status": "ok", "data": _public_source_archive(archive)}


@app.delete("/api/source-archives/{archive_id}")
async def delete_source_archive_endpoint(archive_id: int, payload: dict | None = None, _: None = Depends(require_auth)):
    archive = await run_blocking(
        delete_source_archive,
        archive_id,
        reason=str((payload or {}).get("reason") or ""),
    )
    if not archive:
        raise HTTPException(status_code=404, detail="source archive not found")
    await run_blocking(
        db.create_message,
        level="warning",
        category="source_archive",
        title="源码已删除",
        body=f"{archive.get('filename')}\n已删除源码记录、本地源码文件，并尝试删除 MinIO 对象。",
        entity_type="source_archive",
        entity_id=archive_id,
        raw={"source_archive_id": archive_id, "cleanup": archive.get("cleanup")},
    )
    return {"status": "ok", "data": _public_source_archive(archive)}


@app.post("/api/source-archives/{archive_id}/reanalyze")
async def reanalyze_source_archive(archive_id: int, _: None = Depends(require_auth)):
    if not await run_blocking(db.get_source_archive, archive_id):
        raise HTTPException(status_code=404, detail="source archive not found")
    await run_blocking(db.update_source_archive, archive_id, status="queued", error="")
    schedule_source_archive_processing(archive_id)
    archive = await run_blocking(db.get_source_archive, archive_id)
    return {"status": "queued", "data": _public_source_archive(archive or {})}


@app.post("/api/source-archives/{archive_id}/retry-minio")
async def retry_source_archive_minio(archive_id: int, _: None = Depends(require_auth)):
    archive = await run_blocking(retry_minio_upload, archive_id)
    if not archive:
        raise HTTPException(status_code=404, detail="source archive not found")
    return {"status": "ok", "data": _public_source_archive(archive)}


@app.get("/api/source-archives/{archive_id}/download")
async def download_source_archive(archive_id: int, _: None = Depends(require_auth)):
    archive = await run_blocking(db.get_source_archive, archive_id)
    if not archive:
        raise HTTPException(status_code=404, detail="source archive not found")
    if archive.get("minio_status") != "uploaded" or not archive.get("minio_object_key"):
        raise HTTPException(status_code=404, detail="source archive is not available in MinIO")
    try:
        url = await run_blocking(presigned_get_url, str(archive["minio_object_key"]), expires_seconds=900)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"failed to create MinIO download URL: {str(exc)[:300]}") from exc
    return RedirectResponse(url=url, status_code=302)


def _public_source_archive(archive: dict[str, Any]) -> dict[str, Any]:
    public = dict(archive or {})
    for key in ["local_path", "extracted_path"]:
        public[key] = _display_managed_path(str(public.get(key) or ""))
    if public.get("minio_status") == "uploaded" and public.get("minio_object_key"):
        public["minio_download_url"] = f"/api/source-archives/{public.get('id')}/download"
    return public


def _display_managed_path(value: str) -> str:
    if not value:
        return ""
    try:
        path = Path(value).expanduser().resolve()
        project = settings.database_path.parents[1].resolve()
        if path == project:
            return "."
        if _path_is_relative_to(path, project):
            return str(path.relative_to(project))
        home = Path.home().resolve()
        if path == home:
            return "~"
        if _path_is_relative_to(path, home):
            return "~/" + str(path.relative_to(home))
    except OSError:
        pass
    return value


def _path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


@app.get("/api/updates")
async def get_updates(limit: int = 30, _: None = Depends(require_auth)):
    payload = await run_blocking(list_updates, limit=max(1, min(limit, 100)))
    payload["data"] = [_public_update(item) for item in payload.get("data", [])]
    return payload


@app.post("/api/updates/upload")
async def upload_update(request: Request, _: None = Depends(require_auth)):
    filename = unquote(request.headers.get("x-update-filename") or "update.update")
    content_type = request.headers.get("content-type") or "application/octet-stream"
    try:
        update = await create_update_from_stream(
            request.stream(),
            filename=filename,
            content_type=content_type,
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 413 if "超过上传限制" in message else 400
        raise HTTPException(status_code=status_code, detail=message) from exc
    return {"status": "queued", "data": _public_update(update)}


@app.get("/api/updates/{update_id}")
async def get_update_endpoint(update_id: str, _: None = Depends(require_auth)):
    update = await run_blocking(get_update, update_id)
    if not update:
        raise HTTPException(status_code=404, detail="update not found")
    return _public_update(update)


@app.post("/api/updates/{update_id}/reanalyze")
async def reanalyze_update(update_id: str, _: None = Depends(require_auth)):
    if not await run_blocking(get_update, update_id):
        raise HTTPException(status_code=404, detail="update not found")
    await run_blocking(
        update_state,
        update_id,
        status="queued",
        error="",
        summary="",
        finished_at="",
    )
    schedule_update_processing(update_id)
    update = await run_blocking(get_update, update_id)
    return {"status": "queued", "data": _public_update(update or {})}


def _public_update(update: dict[str, Any]) -> dict[str, Any]:
    public = dict(update or {})
    for key in ["package_path", "report_path", "result_path", "stdout_path", "stderr_path", "validated_dir"]:
        public[key] = _display_managed_path(str(public.get(key) or ""))
    for key in ["report", "summary", "error"]:
        if public.get(key):
            public[key] = _sanitize_known_paths(str(public[key]))
    return public


def _sanitize_known_paths(text: str) -> str:
    value = text or ""
    try:
        project = settings.database_path.parents[1].resolve()
        value = value.replace(str(project), ".")
        home = Path.home().resolve()
        value = value.replace(str(home), "~")
    except OSError:
        pass
    return value


@app.patch("/api/sources/{name}")
async def update_source(name: str, payload: dict, _: None = Depends(require_auth)):
    if name not in source_service.adapters:
        raise HTTPException(status_code=404, detail="unknown source")
    if "enabled" not in payload:
        raise HTTPException(status_code=400, detail="enabled is required")
    await run_blocking(db.set_source_enabled, name, bool(payload["enabled"]))
    return {"status": "ok"}


@app.post("/api/sources/{name}/run")
async def run_source(name: str, _: None = Depends(require_auth)):
    if name not in source_service.adapters:
        raise HTTPException(status_code=404, detail="unknown source")
    return await source_service.run_source(name, force=True)


@app.get("/api/source-sessions/avd")
async def get_avd_session(_: None = Depends(require_auth)):
    return await run_blocking(get_avd_session_status)


@app.post("/api/source-sessions/avd/refresh")
async def refresh_avd_session(payload: dict | None = None, _: None = Depends(require_auth)):
    try:
        headless = None if payload is None or "headless" not in payload else bool(payload["headless"])
        return await refresh_avd_browser_cookie(headless=headless)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.delete("/api/source-sessions/avd")
async def delete_avd_session(_: None = Depends(require_auth)):
    return await clear_avd_browser_cookie()


@app.get("/api/source-sessions/cnvd")
async def get_cnvd_session(_: None = Depends(require_auth)):
    return await run_blocking(get_cnvd_session_status)


@app.post("/api/source-sessions/cnvd/refresh")
async def refresh_cnvd_session(payload: dict | None = None, _: None = Depends(require_auth)):
    try:
        headless = None if payload is None or "headless" not in payload else bool(payload["headless"])
        return await refresh_cnvd_browser_cookie(headless=headless)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.put("/api/source-sessions/cnvd")
async def update_cnvd_session(payload: dict, _: None = Depends(require_auth)):
    try:
        return await set_cnvd_browser_cookie(
            str(payload.get("cookie") or ""),
            str(payload.get("user_agent") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/source-sessions/cnvd")
async def delete_cnvd_session(_: None = Depends(require_auth)):
    return await clear_cnvd_browser_cookie()


@app.get("/api/browser-proxy/status")
async def get_browser_proxy_status(_: None = Depends(require_auth)):
    return browser_proxy_status()


@app.post("/api/browser-proxy/{source}/open")
async def open_browser_proxy_endpoint(source: str, _: None = Depends(require_auth)):
    try:
        return await open_browser_proxy(source)
    except BrowserProxyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/browser-proxy/{source}/capture")
async def capture_browser_proxy_endpoint(source: str, _: None = Depends(require_auth)):
    try:
        return await capture_browser_proxy_session(source)
    except BrowserProxyError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/browser-proxy/{source}/capture-run")
async def capture_and_run_browser_proxy_endpoint(source: str, _: None = Depends(require_auth)):
    source_names = {
        "cnvd": "cnvd_list",
    }
    try:
        capture = await capture_browser_proxy_session(source)
    except BrowserProxyError as exc:
        return {
            "status": "pending",
            "stage": "capture",
            "message": str(exc),
        }

    session = capture.get("session") or {}
    if session.get("status") != "success":
        return {
            "status": "pending",
            "stage": "verify",
            "message": session.get("error") or "等待站点验证通过",
            "capture": capture,
        }

    source_name = source_names.get(str(capture.get("source") or "").lower())
    if not source_name:
        return {
            "status": "done",
            "stage": "capture",
            "message": "会话已保存",
            "capture": capture,
            "redirect": "/app#sessionPanel",
        }

    run_result = await source_service.run_source(source_name, force=True)
    if run_result.get("status") == "skipped":
        return {
            "status": "running",
            "stage": "run",
            "message": run_result.get("error") or "数据源已有采集任务在运行",
            "capture": capture,
            "run": run_result,
        }
    if run_result.get("status") == "failed":
        return {
            "status": "pending",
            "stage": "run",
            "message": run_result.get("error") or "数据源采集失败",
            "capture": capture,
            "run": run_result,
        }
    return {
        "status": "done",
        "stage": "run",
        "message": "会话已保存，数据源采集完成",
        "capture": capture,
        "run": run_result,
        "redirect": "/app#sourcesPanel",
    }


@app.delete("/api/browser-proxy/{source}")
async def stop_browser_proxy_endpoint(source: str, _: None = Depends(require_auth)):
    try:
        return await stop_browser_proxy_session(source)
    except BrowserProxyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/jobs/{category}/run")
async def run_category(category: str, _: None = Depends(require_auth)):
    if category not in {"regular", "slow"}:
        raise HTTPException(status_code=400, detail="category must be regular or slow")
    return {"data": await source_service.run_category(category)}


@app.get("/api/vulnerabilities")
async def get_vulnerabilities(
    source: str = "",
    severity: str = "",
    q: str = "",
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_auth),
):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    return await run_blocking(db.list_vulnerabilities, source=source, severity=severity, query=q, limit=limit, offset=offset)


@app.get("/api/vulnerabilities/{vulnerability_id}")
async def get_vulnerability(vulnerability_id: int, _: None = Depends(require_auth)):
    vulnerability = await run_blocking(db.get_vulnerability, vulnerability_id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    return vulnerability


@app.get("/api/vulnerabilities/{vulnerability_id}/github-evidence")
async def get_vulnerability_github_evidence(vulnerability_id: int, _: None = Depends(require_auth)):
    if not await run_blocking(db.get_vulnerability, vulnerability_id):
        raise HTTPException(status_code=404, detail="vulnerability not found")
    return {"data": await run_blocking(db.list_github_evidence, vulnerability_id)}


@app.post("/api/vulnerabilities/{vulnerability_id}/github-evidence/refresh")
async def refresh_vulnerability_github_evidence(vulnerability_id: int, _: None = Depends(require_auth)):
    try:
        return await refresh_github_evidence_for_vulnerability(vulnerability_id, force=True)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GitHubSearchError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


@app.post("/api/github-evidence/refresh-recent")
async def refresh_recent_github_evidence_endpoint(limit: int = 20, _: None = Depends(require_auth)):
    return await refresh_recent_github_evidence(limit=max(1, min(limit, 100)))


@app.get("/api/analysis")
async def get_analysis_workbench(
    q: str = "",
    limit: int = 8,
    _: None = Depends(require_auth),
):
    return await run_blocking(db.list_analysis_workbench, query=q, limit=limit)


@app.get("/api/vulnerabilities/{vulnerability_id}/analysis/events")
async def get_vulnerability_analysis_events(
    vulnerability_id: int,
    run_id: str = "",
    limit: int = 80,
    offset: int = 0,
    _: None = Depends(require_auth),
):
    if not await run_blocking(db.get_vulnerability, vulnerability_id):
        raise HTTPException(status_code=404, detail="vulnerability not found")
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    return await run_blocking(db.list_analysis_events, vulnerability_id, run_id=run_id, limit=limit, offset=offset)


@app.get("/api/vulnerabilities/{vulnerability_id}/analysis/source")
async def get_vulnerability_analysis_source(vulnerability_id: int, _: None = Depends(require_auth)):
    vulnerability = await run_blocking(db.get_vulnerability, vulnerability_id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    source_url = str(vulnerability.get("analysis_source_url") or "").strip()
    if source_url:
        return RedirectResponse(url=source_url, status_code=302)
    for key in ["analysis_source_archive_path", "analysis_source_local_path"]:
        value = str(vulnerability.get(key) or "").strip()
        if not value:
            continue
        path = Path(value).expanduser().resolve()
        workspace = settings.vulnerability_analysis_workspace_dir.resolve()
        if workspace not in path.parents and path != workspace:
            continue
        if path.is_file():
            return FileResponse(path, filename=path.name)
    raise HTTPException(status_code=404, detail="source artifact not found")


@app.post("/api/vulnerabilities/{vulnerability_id}/follow")
async def follow_vulnerability(vulnerability_id: int, _: None = Depends(require_auth)):
    try:
        return await run_blocking(follow_vulnerability_product, vulnerability_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/vulnerabilities/{vulnerability_id}/analysis/run")
async def run_vulnerability_analysis(
    vulnerability_id: int,
    payload: dict | None = None,
    _: None = Depends(require_auth),
):
    try:
        force = bool(payload.get("force")) if payload else False
        priority = payload.get("priority") if payload and "priority" in payload else None
        mode = str(payload.get("mode") or "").strip().lower() if payload else ""
        model_choice = str(
            payload.get("model_choice")
            or payload.get("analysis_model_choice")
            or ""
        ).strip().lower() if payload else ""
        analysis_model = str(payload.get("analysis_model") or payload.get("model") or "").strip() if payload else ""
        red_team_enhanced = bool(
            payload
            and (
                payload.get("red_team_enhanced")
                or payload.get("red_team")
                or mode in {"red_team", "red_team_enhanced", "enhanced_exp"}
            )
        )
        vulnerability = await run_blocking(
            enqueue_vulnerability_analysis,
            vulnerability_id,
            trigger="manual",
            force=force,
            priority=None if priority is None else int(priority),
            red_team_enhanced=red_team_enhanced,
            model_choice=model_choice,
            analysis_model=analysis_model,
        )
        return {
            "status": "queued",
            "mode": "red_team_enhanced" if red_team_enhanced else "standard",
            "model_choice": model_choice,
            "analysis_model": vulnerability.get("analysis_model"),
            "vulnerability": vulnerability,
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/vulnerabilities/{vulnerability_id}/analysis")
async def delete_vulnerability_analysis(vulnerability_id: int, _: None = Depends(require_auth)):
    vulnerability = await run_blocking(db.get_vulnerability, vulnerability_id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    if vulnerability.get("analysis_status") in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="analysis is queued or running")
    deleted = await run_blocking(db.delete_vulnerability_analysis, vulnerability_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    await run_blocking(
        db.create_message,
        level="info",
        category="analysis",
        title="漏洞分析已删除",
        body=f"{deleted.get('title') or vulnerability_id}\n分析报告、过程输出和生成的 POC/EXP 已清理。",
        entity_type="vulnerability",
        entity_id=vulnerability_id,
        raw={"vulnerability_id": vulnerability_id},
    )
    return {"status": "ok", "vulnerability": deleted}


@app.post("/api/vulnerabilities/{vulnerability_id}/analysis/feedback")
async def analysis_feedback(vulnerability_id: int, payload: dict, _: None = Depends(require_auth)):
    try:
        feedback = await run_blocking(
            db.upsert_analysis_feedback,
            vulnerability_id,
            str(payload.get("rating") or ""),
            str(payload.get("note") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not feedback:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    return {"status": "ok", "feedback": feedback}


@app.get("/api/followed-products")
async def get_followed_products(_: None = Depends(require_auth)):
    return {"data": await run_blocking(list_followed_products)}


@app.get("/api/products")
async def get_products(
    source: str = "",
    q: str = "",
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_auth),
):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    return await run_blocking(db.list_products, source=source, query=q, limit=limit, offset=offset)


@app.post("/api/products/align-vulnerabilities")
async def align_products(payload: dict | None = None, _: None = Depends(require_auth)):
    payload = payload or {}
    limit = max(0, min(int(payload.get("limit") or 0), 10000))
    only_unlinked = bool(payload.get("only_unlinked", True))
    result = await run_blocking(backfill_products_direct, limit=limit, only_unlinked=only_unlinked)
    ai_scheduled = False
    if bool(payload.get("deepseek_flash", True)):
        ai_scheduled = await run_blocking(
            schedule_deepseek_flash_for_alerts,
            limit=max(1, min(int(payload.get("ai_limit") or 5), 20)),
        )
    return {**result, "deepseek_flash_scheduled": ai_scheduled}


@app.get("/api/products/duplicates")
async def product_duplicates(limit: int = 30, _: None = Depends(require_auth)):
    return {"data": await run_blocking(db.product_duplicate_candidates, limit=limit)}


@app.post("/api/products/normalize")
async def normalize_products(payload: dict | None = None, _: None = Depends(require_auth)):
    payload = payload or {}
    return await run_blocking(
        db.normalize_product_catalog,
        auto_merge=bool(payload.get("auto_merge", True)),
        merge_limit=max(1, min(int(payload.get("merge_limit") or 200), 1000)),
    )


@app.post("/api/products/follow")
async def follow_product(payload: dict, _: None = Depends(require_auth)):
    product = str(payload.get("product") or "").strip()
    if not product:
        raise HTTPException(status_code=400, detail="product is required")
    try:
        followed = await run_blocking(db.add_followed_product, product)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await run_blocking(
        db.create_message,
        level="info",
        category="analysis",
        title="已关注产品",
        body=f"{product} 已从产品库加入关注列表。后续出现 high/critical 漏洞会自动触发分析。",
        entity_type="product",
        entity_id=followed.get("product_key", ""),
        raw={"product": product, "product_key": followed.get("product_key")},
    )
    return {"followed_product": followed}


@app.post("/api/products/aliases")
async def add_product_alias(payload: dict, _: None = Depends(require_auth)):
    try:
        alias = await run_blocking(
            db.add_product_alias,
            str(payload.get("product_key") or ""),
            str(payload.get("alias") or ""),
            str(payload.get("vendor") or ""),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "alias": alias}


@app.delete("/api/products/aliases/{alias_id}")
async def delete_product_alias(alias_id: int, _: None = Depends(require_auth)):
    if not await run_blocking(db.delete_product_alias, alias_id):
        raise HTTPException(status_code=404, detail="alias not found")
    return {"status": "ok"}


@app.post("/api/products/merge")
async def merge_products(payload: dict, _: None = Depends(require_auth)):
    sources = payload.get("source_product_keys") or payload.get("sources") or []
    if isinstance(sources, str):
        sources = [item.strip() for item in sources.replace("\n", ",").split(",") if item.strip()]
    if not isinstance(sources, list):
        raise HTTPException(status_code=400, detail="source_product_keys must be a list")
    try:
        return await run_blocking(
            db.merge_products,
            str(payload.get("target_product_key") or ""),
            [str(item) for item in sources],
            str(payload.get("note") or ""),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/products/{product_key:path}")
async def get_product_detail(product_key: str, _: None = Depends(require_auth)):
    detail = await run_blocking(db.get_product_detail, product_key)
    if not detail:
        raise HTTPException(status_code=404, detail="product not found")
    return detail


@app.delete("/api/followed-products/{product_key:path}")
async def delete_followed_product(product_key: str, _: None = Depends(require_auth)):
    if not await run_blocking(unfollow_product, product_key):
        raise HTTPException(status_code=404, detail="followed product not found")
    return {"status": "ok"}


@app.get("/api/runs")
async def get_runs(_: None = Depends(require_auth)):
    return {"data": await run_blocking(db.latest_runs)}


@app.get("/api/monitor/rules")
async def get_rules(_: None = Depends(require_auth)):
    return await run_blocking(get_monitor_rules)


@app.put("/api/monitor/rules")
async def update_rules(payload: dict, _: None = Depends(require_auth)):
    return await run_blocking(set_monitor_rules, payload)


@app.get("/api/alerts")
async def get_alerts(
    status: str = "new",
    source: str = "",
    q: str = "",
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_auth),
):
    if status not in {"", "new", "acknowledged"}:
        raise HTTPException(status_code=400, detail="status must be new or acknowledged")
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    filters = await run_blocking(current_alert_filters)
    return await run_blocking(
        db.list_alerts,
        status=status,
        source=source,
        query=q,
        limit=limit,
        offset=offset,
        min_severity=filters["min_severity"],
        published_after=filters["published_after"],
    )


@app.post("/api/alerts/{alert_id}/ack")
async def ack_alert(alert_id: int, _: None = Depends(require_auth)):
    if not await run_blocking(db.acknowledge_alert, alert_id):
        raise HTTPException(status_code=404, detail="alert not found")
    return {"status": "ok"}


@app.get("/api/claude-code/status")
async def get_claude_status(_: None = Depends(require_auth)):
    return get_claude_code_status()


@app.get("/api/deepseek/status")
async def get_deepseek(_: None = Depends(require_auth)):
    return await run_blocking(get_deepseek_status)


@app.put("/api/deepseek/config")
async def update_deepseek_config(payload: dict, _: None = Depends(require_auth)):
    try:
        return await run_blocking(
            set_deepseek_api_key,
            str(payload.get("api_key") or ""),
            str(payload.get("base_url") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/deepseek/config")
async def delete_deepseek_config(_: None = Depends(require_auth)):
    return await run_blocking(clear_deepseek_api_key)


@app.post("/api/deepseek/balance/run")
async def run_deepseek_balance(_: None = Depends(require_auth)):
    return await refresh_deepseek_balance()


@app.post("/api/enrichment/nvd/run")
async def run_nvd_enrichment(_: None = Depends(require_auth)):
    return await backfill_missing_cvss()


# ═══ 数据源健康中心 ═══

@app.get("/api/sources/health")
async def get_source_health(_: None = Depends(require_auth)):
    return {"data": await run_blocking(db.source_health)}


# ═══ 日报/周报 ═══

@app.get("/api/report/daily")
async def get_daily_report(_: None = Depends(require_auth)):
    return await run_blocking(db.daily_report, hour_offset=24)


@app.get("/api/report/weekly")
async def get_weekly_report(_: None = Depends(require_auth)):
    return await run_blocking(db.daily_report, hour_offset=168)


# ═══ 情报质量评分告警列表 ═══

@app.get("/api/alerts/scored")
async def get_scored_alerts(
    status: str = "new",
    source: str = "",
    q: str = "",
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_auth),
):
    if status not in {"", "new", "acknowledged"}:
        raise HTTPException(status_code=400, detail="status must be new or acknowledged")
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    filters = await run_blocking(current_alert_filters)
    return await run_blocking(
        db.list_scored_alerts,
        status=status,
        source=source,
        query=q,
        limit=limit,
        offset=offset,
        min_severity=filters["min_severity"],
        published_after=filters["published_after"],
    )


@app.get("/api/vulnerabilities/{vulnerability_id}/threat-score")
async def get_threat_score(vulnerability_id: int, _: None = Depends(require_auth)):
    vuln = await run_blocking(db.get_vulnerability, vulnerability_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    return await run_blocking(db.compute_threat_score, vuln)


# ═══ 分析任务控制 ═══

@app.get("/api/analysis/settings")
async def get_analysis_settings(_: None = Depends(require_auth)):
    return await run_blocking(db.get_analysis_settings)


@app.put("/api/analysis/settings")
async def update_analysis_settings(payload: dict, _: None = Depends(require_auth)):
    return await run_blocking(db.set_analysis_settings, payload)


@app.get("/api/analysis/failure-stats")
async def get_analysis_failure_stats(_: None = Depends(require_auth)):
    return {"data": await run_blocking(db.analysis_failure_stats)}


@app.post("/api/analysis/requeue-failed")
async def requeue_failed_analysis(_: None = Depends(require_auth)):
    return await run_blocking(requeue_failed_analyses)


@app.post("/api/vulnerabilities/{vulnerability_id}/analysis/cancel")
async def cancel_analysis(vulnerability_id: int, _: None = Depends(require_auth)):
    result = await run_blocking(cancel_vulnerability_analysis, vulnerability_id)
    if not result:
        raise HTTPException(status_code=404, detail="no active analysis to cancel")
    return {"status": "canceled", "vulnerability": result}


# ═══ SBOM / 依赖清单 ═══

@app.get("/api/sbom/projects")
async def list_sbom_projects(limit: int = 50, offset: int = 0, _: None = Depends(require_auth)):
    return await run_blocking(db.list_sbom_projects, limit=limit, offset=offset)


@app.post("/api/sbom/projects")
async def create_sbom_project(payload: dict, _: None = Depends(require_auth)):
    try:
        return await run_blocking(db.create_sbom_project, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/sbom/projects/{project_id}")
async def get_sbom_project(project_id: int, _: None = Depends(require_auth)):
    project = await run_blocking(db.get_sbom_project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="sbom project not found")
    return project


@app.post("/api/sbom/projects/{project_id}/match")
async def match_sbom_project(project_id: int, _: None = Depends(require_auth)):
    project = await run_blocking(db.match_sbom_project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="sbom project not found")
    return project


# ═══ 模型预算 / RAG 知识库 ═══

@app.get("/api/model/settings")
async def get_model_settings(_: None = Depends(require_auth)):
    return await run_blocking(db.get_model_settings)


@app.put("/api/model/settings")
async def update_model_settings(payload: dict, _: None = Depends(require_auth)):
    return await run_blocking(db.set_model_settings, payload)


@app.get("/api/model/usage")
async def get_model_usage(hours: int = 24, _: None = Depends(require_auth)):
    return await run_blocking(db.model_usage_summary, hours=hours)


@app.get("/api/rag/notes")
async def get_rag_notes(
    scope: str = "",
    q: str = "",
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_auth),
):
    return await run_blocking(db.list_rag_notes, scope=scope, query=q, limit=limit, offset=offset)


@app.post("/api/rag/notes")
async def create_rag_note(payload: dict, _: None = Depends(require_auth)):
    try:
        return await run_blocking(db.add_rag_note, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
