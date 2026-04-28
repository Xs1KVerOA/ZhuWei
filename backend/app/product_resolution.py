from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import db
from .claude_code import claude_code_subprocess_env, ensure_claude_code, resolve_claude_code_command
from .config import settings
from .deepseek import get_deepseek_api_key


logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="product-resolution")
_lock = threading.Lock()
_running = False


def resolve_products_direct(items: list[dict[str, Any]]) -> dict[str, int]:
    return db.align_products_for_items(items)


def backfill_products_direct(*, limit: int = 0, only_unlinked: bool = True) -> dict[str, int]:
    return db.align_vulnerability_products(limit=limit, only_unlinked=only_unlinked)


def schedule_deepseek_flash_for_alerts(*, limit: int = 5) -> bool:
    if not get_deepseek_api_key():
        return False
    global _running
    with _lock:
        if _running:
            return False
        _running = True
    _executor.submit(_run_background_resolution, max(1, min(limit, 20)))
    return True


def _run_background_resolution(limit: int) -> None:
    global _running
    try:
        asyncio.run(resolve_unmatched_alerts_with_deepseek(limit=limit))
    except Exception:
        logger.exception("DeepSeek product resolution failed")
    finally:
        with _lock:
            _running = False


async def resolve_unmatched_alerts_with_deepseek(*, limit: int = 5) -> dict[str, int]:
    candidates = db.ai_product_resolution_candidates(limit=limit)
    if not candidates:
        return {"checked": 0, "linked": 0, "empty": 0, "failed": 0}
    if not get_deepseek_api_key():
        return {"checked": len(candidates), "linked": 0, "empty": 0, "failed": 0}

    status = await ensure_claude_code()
    command_path = resolve_claude_code_command() or str(status.get("resolved_path") or "")
    if not command_path:
        db.create_message(
            level="warning",
            category="product",
            title="产品归属解析未运行",
            body="Claude Code CLI 不可用，无法调用 DeepSeek Flash 做联网产品识别。",
            raw={"status": status},
        )
        return {"checked": len(candidates), "linked": 0, "empty": 0, "failed": len(candidates)}

    checked = linked = empty = failed = 0
    for vuln in candidates:
        checked += 1
        try:
            parsed = await _resolve_one_with_deepseek(command_path, vuln)
            product = str(parsed.get("product_name") or parsed.get("existing_product_name") or "").strip()
            confidence = _confidence_value(parsed.get("confidence"))
            evidence = str(parsed.get("evidence") or parsed.get("reason") or "").strip()
            if not product or confidence < 0.55:
                db.mark_product_resolution_attempt(
                    int(vuln["id"]),
                    "deepseek_product_empty",
                    evidence or "DeepSeek Flash/Pro 未给出足够可信的产品归属。",
                    raw=parsed,
                )
                empty += 1
                continue
            existing_key = str(parsed.get("existing_product_key") or "").strip()
            if existing_key:
                _apply_product_alias_and_merge(parsed, product)
            result = db.link_vulnerability_to_product(
                int(vuln["id"]),
                product,
                "deepseek_product_pro",
                confidence,
                evidence or f"DeepSeek Flash 现网搜索后由 Pro 识别为 {product}",
                raw=parsed,
            )
            linked += int(result["linked"])
        except Exception as exc:
            failed += 1
            db.mark_product_resolution_attempt(
                int(vuln["id"]),
                "deepseek_product_failed",
                str(exc)[:1000],
                raw={"error": str(exc)},
            )
    if checked:
        db.create_message(
            level="success" if failed == 0 else "warning",
            category="product",
            title="产品归属解析完成",
            body=f"DeepSeek Flash+Pro 检查 {checked} 条新告警/新漏洞，入库 {linked} 条，未确认 {empty} 条，失败 {failed} 条。",
            raw={"checked": checked, "linked": linked, "empty": empty, "failed": failed},
        )
    return {"checked": checked, "linked": linked, "empty": empty, "failed": failed}


async def _resolve_one_with_deepseek(command_path: str, vuln: dict[str, Any]) -> dict[str, Any]:
    workspace = settings.vulnerability_analysis_workspace_dir / "product_resolution"
    workspace.mkdir(parents=True, exist_ok=True)
    model_settings = db.get_model_settings()
    flash_model = str(model_settings.get("flash_model") or settings.anthropic_default_haiku_model)
    pro_model = str(model_settings.get("pro_model") or settings.anthropic_model)
    flash = await _run_product_resolution_model(
        command_path,
        workspace,
        _product_resolution_flash_prompt(vuln),
        flash_model,
        timeout_seconds=180,
    )
    terms = [
        str(vuln.get("title") or ""),
        str(vuln.get("product") or ""),
        str(vuln.get("description") or ""),
        *[str(item) for item in (vuln.get("aliases") or [])],
        *[str(item) for item in flash.get("candidate_product_names") or [] if item],
        str(flash.get("product_name") or ""),
        str(flash.get("vendor") or ""),
    ]
    catalog = db.product_catalog_candidates_for_terms(terms, limit=30)
    pro = await _run_product_resolution_model(
        command_path,
        workspace,
        _product_resolution_pro_prompt(vuln, flash, catalog),
        pro_model,
        timeout_seconds=180,
    )
    pro["flash_research"] = flash
    pro["catalog_candidates"] = catalog[:20]
    return pro


async def _run_product_resolution_model(
    command_path: str,
    workspace: Path,
    prompt: str,
    model: str,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    command = [
        command_path,
        "-p",
        prompt,
        "--output-format",
        "json",
        "--allowedTools",
        "WebSearch,WebFetch",
        "--permission-mode",
        "acceptEdits",
    ]
    env = claude_code_subprocess_env()
    env["ANTHROPIC_MODEL"] = model
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(workspace),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=min(settings.vulnerability_analysis_timeout_seconds, timeout_seconds),
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        raise RuntimeError(f"{model} 产品归属识别超时")
    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise RuntimeError((stderr_text or stdout_text or f"Claude exited {process.returncode}")[:2000])
    db.record_claude_model_usage(
        task_type="product_resolution",
        default_model=model,
        stdout_text=stdout_text,
        status="success",
        raw={"model": model},
    )
    parsed = _json_from_text(stdout_text)
    if isinstance(parsed, dict):
        result = parsed.get("result") or parsed.get("message") or parsed.get("content")
        if isinstance(result, str):
            inner = _json_from_text(result)
            if isinstance(inner, dict):
                return inner
        if "product_name" in parsed or "existing_product_key" in parsed:
            return parsed
    return {
        "product_name": "",
        "confidence": 0,
        "evidence": "模型输出无法解析为产品归属 JSON。",
        "raw": stdout_text[-4000:],
    }


def _apply_product_alias_and_merge(parsed: dict[str, Any], product_name: str) -> None:
    existing_key = str(parsed.get("existing_product_key") or "").strip()
    if not existing_key:
        return
    vendor = str(parsed.get("vendor") or "").strip()
    aliases = parsed.get("aliases_to_add") or []
    if product_name:
        aliases = [*aliases, {"alias": product_name, "vendor": vendor}]
    for alias in aliases:
        if isinstance(alias, dict):
            alias_name = str(alias.get("alias") or alias.get("name") or "").strip()
            alias_vendor = str(alias.get("vendor") or vendor).strip()
        else:
            alias_name = str(alias or "").strip()
            alias_vendor = vendor
        if not alias_name:
            continue
        try:
            db.add_product_alias(existing_key, alias_name, alias_vendor)
        except Exception:
            logger.debug("failed to add product alias %s -> %s", alias_name, existing_key, exc_info=True)

    merge_values: list[str] = []
    for key in ["merge_product_keys", "merge_product_names", "merge_candidates"]:
        values = parsed.get(key) or []
        if isinstance(values, str):
            values = [values]
        if isinstance(values, list):
            merge_values.extend(str(value) for value in values if value)
    if merge_values:
        try:
            db.merge_products(existing_key, merge_values, "DeepSeek Pro 判断为同一产品")
        except Exception:
            logger.debug("failed to merge product aliases into %s", existing_key, exc_info=True)


def _product_resolution_flash_prompt(vuln: dict[str, Any]) -> str:
    payload = {
        "id": vuln.get("id"),
        "source": vuln.get("source"),
        "title": vuln.get("title"),
        "cve_id": vuln.get("cve_id"),
        "aliases": vuln.get("aliases"),
        "published_at": vuln.get("published_at"),
        "description": vuln.get("description"),
        "url": vuln.get("url"),
    }
    return f"""
	你是漏洞情报产品归属搜索助手。只做“该漏洞对应哪个软件/设备/组件产品”的现网搜索，不做利用分析。

	约束：
	1. 只使用 WebSearch/WebFetch 搜索产品归属、厂商公告、CVE/NVD 描述或原始情报页面。
	2. 不要搜索 POC、EXP、利用代码、绕过、攻击 payload，也不要输出利用细节。
	3. 优先搜索厂商官网、NVD/CVE、GitHub Advisory、原始情报页面；只收集产品归属证据。
	4. 只输出一个 JSON 对象，不要 Markdown，不要额外解释。

	待识别漏洞：
{json.dumps(payload, ensure_ascii=False, indent=2)}

	JSON schema:
	{{
	  "product_name": "现网证据最支持的产品名；不能确认则为空",
	  "vendor": "厂商名；未知则为空",
	  "candidate_product_names": ["产品候选名、英文名、中文名、历史名"],
	  "confidence": 0.0,
	  "evidence": "一句中文证据，说明搜索结果支持哪个产品",
	  "references": [{{"title": "...", "url": "..."}}]
	}}
	""".strip()


def _product_resolution_pro_prompt(
    vuln: dict[str, Any],
    flash: dict[str, Any],
    catalog: list[dict[str, Any]],
) -> str:
    payload = {
        "id": vuln.get("id"),
        "source": vuln.get("source"),
        "title": vuln.get("title"),
        "cve_id": vuln.get("cve_id"),
        "aliases": vuln.get("aliases"),
        "published_at": vuln.get("published_at"),
        "description": vuln.get("description"),
        "url": vuln.get("url"),
    }
    compact_catalog = [
        {
            "product_key": item.get("product_key"),
            "name": item.get("name"),
            "vendor": item.get("vendor"),
            "source": item.get("source"),
            "vulnerability_count": item.get("vulnerability_count"),
            "match_score": item.get("match_score"),
            "aliases": [
                {"alias": alias.get("alias"), "vendor": alias.get("vendor")}
                for alias in (item.get("aliases") or [])[:6]
            ],
        }
        for item in catalog[:30]
    ]
    return f"""
	你是漏洞情报产品归属审校助手。你需要基于 Flash 的现网搜索结果和本地产品库候选，判断该漏洞是否应归入已有产品、对应规范产品名，以及是否需要新增别名或合并重复产品。

	约束：
	1. 只做产品归属、别名和合并判断，不输出 POC/EXP/攻击利用细节。
	2. 优先选择本地产品库中已经存在的规范产品；如果没有合适产品，再给出新的 product_name。
	3. 如果英文/拼音/历史名与中文产品一致，例如 Yonyou/Yongyou/UFIDA 与 用友，应输出 aliases_to_add 或 merge_product_keys。
	4. 只有证据明确时才建议 merge_product_keys；不确定时只建议 aliases_to_add。
	5. 只输出一个 JSON 对象，不要 Markdown，不要额外解释。

	待识别漏洞：
	{json.dumps(payload, ensure_ascii=False, indent=2)}

	Flash 现网搜索结果：
	{json.dumps(flash, ensure_ascii=False, indent=2)}

	本地产品库候选：
	{json.dumps(compact_catalog, ensure_ascii=False, indent=2)}

	JSON schema:
	{{
	  "product_name": "最终用于关联漏洞的规范产品名；不能确认则为空",
	  "vendor": "厂商名；未知则为空",
	  "existing_product_key": "若命中本地产品库，填写 product_key；否则为空",
	  "existing_product_name": "若命中本地产品库，填写库内规范产品名；否则为空",
	  "confidence": 0.0,
	  "evidence": "一句中文证据，说明为什么归属到该产品，以及是否命中本地产品库",
	  "aliases_to_add": [{{"alias": "Yonyou NC", "vendor": "用友"}}],
	  "merge_product_keys": ["需要合并进 existing_product_key 的重复 product_key"],
	  "merge_product_names": ["需要合并进 existing_product_key 的重复产品名"],
	  "references": [{{"title": "...", "url": "..."}}]
	}}
	""".strip()


def _json_from_text(text: str) -> Any:
    cleaned = (text or "").strip()
    if not cleaned:
        return {}
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", cleaned, flags=re.S)
    if not match:
        return {}
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}


def _confidence_value(value: Any) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(float(value), 1.0))
    text = str(value or "").strip().lower()
    if text in {"high", "高", "高置信"}:
        return 0.86
    if text in {"medium", "中", "中置信"}:
        return 0.68
    if text in {"low", "低", "低置信"}:
        return 0.4
    match = re.search(r"\d+(?:\.\d+)?", text)
    if not match:
        return 0.0
    number = float(match.group(0))
    return max(0.0, min(number / 100 if number > 1 else number, 1.0))
