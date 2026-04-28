from __future__ import annotations

import asyncio
import threading
from typing import Any

from . import db
from .async_utils import run_blocking
from .analysis import queue_followed_analysis_for_items
from .enrichment import enrich_items
from .github_intel import enrich_items_with_github_evidence
from .monitor import process_alerts
from .product_resolution import resolve_products_direct, schedule_deepseek_flash_for_alerts
from .sources import ADAPTERS
from .sources.base import SourceAdapter


class SourceService:
    def __init__(self) -> None:
        self.adapters: dict[str, SourceAdapter] = {adapter.name: adapter for adapter in ADAPTERS}
        self._locks: dict[str, threading.Lock] = {
            name: threading.Lock() for name in self.adapters
        }

    def register_sources(self) -> None:
        for adapter in self.adapters.values():
            db.register_source(
                adapter.name,
                adapter.title,
                adapter.category,
                adapter.schedule,
                enabled_by_default=bool(getattr(adapter, "enabled_by_default", True)),
            )

    async def run_source(self, name: str, *, force: bool = False) -> dict[str, Any]:
        adapter = self.adapters.get(name)
        if adapter is None:
            raise KeyError(f"unknown source: {name}")
        if not force and not await run_blocking(db.source_is_enabled, name):
            return {"source": name, "status": "skipped", "item_count": 0, "error": "source disabled"}

        lock = self._locks[name]
        if not lock.acquire(blocking=False):
            await run_blocking(
                db.create_message,
                level="warning",
                category="source",
                title="数据源正在运行",
                body=f"{name} 已有采集任务在运行。",
                entity_type="source",
                entity_id=name,
            )
            return {"source": name, "status": "skipped", "item_count": 0, "error": "source already running"}

        run_id = 0
        try:
            run_id = await run_blocking(db.create_run, name)
            items = await adapter.fetch()
            product_count = 0

            # Streaming ingestion: upsert products page by page as they arrive
            if hasattr(adapter, "stream_products"):
                async for batch in adapter.stream_products():  # type: ignore[attr-defined]
                    if batch:
                        product_count += await run_blocking(db.upsert_products, batch)

            items = await enrich_items(items)
            count = await run_blocking(db.upsert_vulnerabilities, items)
            should_refresh_github_evidence = bool(getattr(adapter, "github_evidence_auto_search", True))
            github_evidence = await enrich_items_with_github_evidence(items) if items and should_refresh_github_evidence else {
                "checked": 0,
                "changed": 0,
                "warning": "",
                "skipped": bool(items) and not should_refresh_github_evidence,
            }
            product_alignment = await run_blocking(resolve_products_direct, items)
            alert_enabled = bool(getattr(adapter, "alert_enabled", True))
            alert_count = await run_blocking(process_alerts, items) if items and alert_enabled else 0
            if alert_count or count:
                await run_blocking(schedule_deepseek_flash_for_alerts)
            analysis_count = await run_blocking(queue_followed_analysis_for_items, items) if items else 0
            total_count = count + product_count
            source_warning = str(getattr(adapter, "last_warning", "") or "")
            github_warning = str(github_evidence.get("warning") or "")
            status = "partial" if source_warning else "success"
            await run_blocking(db.finish_run, run_id, name, status, total_count, source_warning)
            if force or alert_count or analysis_count or product_count or source_warning or github_warning:
                github_warning_text = f"{chr(10)}GitHub 证据刷新提示：{github_warning}" if github_warning else ""
                await run_blocking(
                    db.create_message,
                    level="warning" if source_warning else "success",
                    category="source",
                    title="数据源采集部分完成" if source_warning else "数据源采集完成",
                    body=(
                        f"{adapter.title} 入库 {count} 条，"
                        f"产品 {product_count} 个，"
                        f"{'新增告警 ' + str(alert_count) + ' 条' if alert_enabled else '告警已跳过'}，"
                        f"触发分析 {analysis_count} 条，"
                        f"产品归属 {product_alignment.get('linked', 0)} 条，"
                        f"GitHub 证据刷新 {github_evidence.get('checked', 0)} 条。"
                        f"{chr(10) + source_warning if source_warning else ''}"
                        f"{github_warning_text}"
                    ),
                    entity_type="source",
                    entity_id=name,
                    raw={
                        "source": name,
                        "run_id": run_id,
                        "item_count": count,
                        "product_count": product_count,
                        "product_alignment": product_alignment,
                        "alert_count": alert_count,
                        "alert_enabled": alert_enabled,
                        "analysis_count": analysis_count,
                        "github_evidence": github_evidence,
                        "warning": source_warning,
                        "github_warning": github_warning,
                    },
                )
            return {
                "source": name,
                "status": status,
                "item_count": total_count,
                "vulnerability_count": count,
                "product_count": product_count,
                "product_alignment": product_alignment,
                "alert_count": alert_count,
                "analysis_count": analysis_count,
                "github_evidence": github_evidence,
                "error": source_warning,
            }
        except Exception as exc:
            error = str(exc)
            if run_id:
                await run_blocking(db.finish_run, run_id, name, "failed", 0, error)
            await run_blocking(
                db.create_message,
                level="error",
                category="source",
                title="数据源采集失败",
                body=f"{adapter.title} 采集失败：{error[:2000]}",
                entity_type="source",
                entity_id=name,
                raw={"source": name, "run_id": run_id, "error": error},
            )
            return {"source": name, "status": "failed", "item_count": 0, "error": error}
        finally:
            lock.release()

    async def run_category(self, category: str) -> list[dict[str, Any]]:
        names = [adapter.name for adapter in self.adapters.values() if adapter.category == category]
        results = []
        for name in names:
            results.append(await self.run_source(name))
        return results

    def run_category_sync(self, category: str) -> None:
        asyncio.run(self.run_category(category))


source_service = SourceService()
