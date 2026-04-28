from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import shutil
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from . import db, redis_queue
from .claude_code import claude_code_subprocess_env, ensure_claude_code
from .config import settings
from .deepseek import get_deepseek_api_key
from .source_archive import register_analysis_source_artifact


logger = logging.getLogger(__name__)

HIGH_RISK_SEVERITIES = {"high", "critical"}
MAX_ANALYSIS_WORKERS = 10
_executor = ThreadPoolExecutor(max_workers=MAX_ANALYSIS_WORKERS, thread_name_prefix="vuln-analysis")
_active_lock = threading.Lock()
_active_ids: set[int] = set()


class AnalysisFailure(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        self.detail = detail.strip() or reason
        super().__init__(f"{reason}：{self.detail}")


class AnalysisCanceled(Exception):
    pass


def list_followed_products() -> list[dict[str, Any]]:
    return db.list_followed_products()


def start_analysis_queue() -> None:
    recovered = db.recover_interrupted_analysis()
    if recovered:
        db.create_message(
            level="warning",
            category="analysis",
            title="分析任务已恢复",
            body=f"{recovered} 个上次中断的分析任务已重新放回队列。",
            raw={"recovered_count": recovered},
        )
    _sync_redis_analysis_queue()
    _drain_analysis_queue()


def follow_vulnerability_product(vulnerability_id: int) -> dict[str, Any]:
    vuln = db.get_vulnerability(vulnerability_id)
    if not vuln:
        raise KeyError("vulnerability not found")
    product = db.product_label_for_item(vuln)
    followed = db.add_followed_product(product)
    db.create_message(
        level="info",
        category="analysis",
        title="已关注产品",
        body=f"{product} 已加入关注列表。后续出现 high/critical 漏洞会自动触发分析。",
        entity_type="vulnerability",
        entity_id=vulnerability_id,
        raw={"product": product, "product_key": followed.get("product_key")},
    )
    if _is_auto_analysis_candidate(vuln):
        enqueue_vulnerability_analysis(vulnerability_id, trigger="followed_product")
    refreshed = db.get_vulnerability(vulnerability_id) or vuln
    return {"followed_product": followed, "vulnerability": refreshed}


def unfollow_product(product_key: str) -> bool:
    return db.delete_followed_product(product_key)


def enqueue_vulnerability_analysis(
    vulnerability_id: int,
    *,
    trigger: str = "manual",
    force: bool = False,
    priority: int | None = None,
    red_team_enhanced: bool = False,
    model_choice: str = "",
    analysis_model: str = "",
) -> dict[str, Any]:
    effective_trigger = "red_team_enhanced" if red_team_enhanced else trigger
    model_selection = _analysis_model_selection(model_choice=model_choice, model=analysis_model)
    vuln = db.request_vulnerability_analysis(
        vulnerability_id,
        trigger=effective_trigger,
        force=force,
        priority=_default_analysis_priority() if priority is None else priority,
        analysis_model=model_selection["model"],
    )
    if not vuln:
        raise KeyError("vulnerability not found")
    mode_label = "红队增强" if red_team_enhanced else "标准分析"
    model_label = f"{model_selection['label']} · {model_selection['model']}"
    db.create_message(
        level="info",
        category="analysis",
        title="漏洞分析已排队",
        body=(
            f"{vuln.get('title') or vulnerability_id}\n"
            f"触发方式：{effective_trigger}\n"
            f"分析模式：{mode_label}\n"
            f"模型：{model_label}"
        ),
        entity_type="vulnerability",
        entity_id=vulnerability_id,
        raw={
            "trigger": effective_trigger,
            "red_team_enhanced": red_team_enhanced,
            "analysis_model_choice": model_selection["choice"],
            "analysis_model_label": model_selection["label"],
            "analysis_model": model_selection["model"],
            "vulnerability_id": vulnerability_id,
            "cve_id": vuln.get("cve_id"),
            "source": vuln.get("source"),
            "priority": vuln.get("analysis_priority"),
        },
    )
    _enqueue_analysis_queue(vuln)
    _drain_analysis_queue()
    return db.get_vulnerability(vulnerability_id) or vuln


def cancel_vulnerability_analysis(vulnerability_id: int) -> dict[str, Any] | None:
    result = db.cancel_vulnerability_analysis(vulnerability_id)
    if result:
        redis_queue.remove_analysis(vulnerability_id)
    return result


def requeue_failed_analyses() -> dict[str, Any]:
    ids = db.requeue_failed_analysis_ids()
    if ids:
        db.create_message(
            level="info",
            category="analysis",
            title="失败分析已重新排队",
            body=f"{len(ids)} 个失败分析任务已重新进入队列。",
            raw={"vulnerability_ids": ids[:200], "total": len(ids)},
        )
        _enqueue_analysis_ids(ids)
        _drain_analysis_queue()
    return {"status": "ok", "requeued_count": len(ids)}


def queue_followed_analysis_for_items(items: list[dict[str, Any]]) -> int:
    queued = 0
    for item in items:
        product = db.product_label_for_item(item)
        followed = db.get_followed_product(product)
        if not followed or not _is_auto_analysis_candidate(item):
            continue
        vuln = db.get_vulnerability_for_item(item)
        if not vuln:
            continue
        status = str(vuln.get("analysis_status") or "idle")
        if status in {"queued", "running", "finished"}:
            continue
        enqueue_vulnerability_analysis(int(vuln["id"]), trigger="auto_followed_product")
        db.mark_followed_product_match(str(followed["product_key"]), int(vuln["id"]))
        queued += 1
    return queued


def _drain_analysis_queue() -> None:
    with _active_lock:
        capacity = _analysis_concurrency() - len(_active_ids)
        if capacity <= 0:
            return
        queued = _next_queued_analysis(capacity)
        for item in queued:
            vulnerability_id = int(item["id"])
            if vulnerability_id in _active_ids:
                continue
            _active_ids.add(vulnerability_id)
            try:
                _executor.submit(_run_analysis_thread, vulnerability_id)
            except Exception:
                _active_ids.discard(vulnerability_id)
                _release_analysis_queue(item)
                raise


def _sync_redis_analysis_queue() -> None:
    if not redis_queue.redis_queue_configured():
        return
    queued = db.list_queued_analysis()
    if redis_queue.reset_analysis_queue(queued):
        logger.info("Redis analysis queue synced with %s queued item(s)", len(queued))


def _enqueue_analysis_queue(vuln: dict[str, Any]) -> None:
    if str(vuln.get("analysis_status") or "") != "queued":
        return
    redis_queue.enqueue_analysis(vuln)


def _enqueue_analysis_ids(vulnerability_ids: list[int]) -> None:
    for vulnerability_id in vulnerability_ids:
        vuln = db.get_vulnerability(int(vulnerability_id))
        if vuln:
            _enqueue_analysis_queue(vuln)


def _release_analysis_queue(vuln: dict[str, Any]) -> None:
    if redis_queue.redis_queue_configured():
        redis_queue.release_analysis(vuln)


def _finish_analysis_queue(vulnerability_id: int) -> None:
    if redis_queue.redis_queue_configured():
        redis_queue.finish_analysis(vulnerability_id)


def _next_queued_analysis(capacity: int) -> list[dict[str, Any]]:
    if redis_queue.redis_queue_configured() and redis_queue.redis_queue_available():
        queued = _next_redis_queued_analysis(capacity)
        if queued:
            return queued
        if not redis_queue.redis_queue_available():
            return db.next_queued_analysis(capacity, exclude_ids=_active_ids)
        heal = db.next_queued_analysis(max(capacity, 20), exclude_ids=_active_ids)
        for item in heal:
            _enqueue_analysis_queue(item)
        if heal:
            if not redis_queue.redis_queue_available():
                return db.next_queued_analysis(capacity, exclude_ids=_active_ids)
            return _next_redis_queued_analysis(capacity)
        return []
    return db.next_queued_analysis(capacity, exclude_ids=_active_ids)


def _next_redis_queued_analysis(capacity: int) -> list[dict[str, Any]]:
    queued: list[dict[str, Any]] = []
    attempts = 0
    max_attempts = max(capacity * 5, 10)
    while len(queued) < capacity and attempts < max_attempts:
        ids = redis_queue.reserve_analysis_ids(capacity - len(queued))
        if not ids:
            break
        attempts += len(ids)
        for vulnerability_id in ids:
            if vulnerability_id in _active_ids:
                vuln = db.get_vulnerability(vulnerability_id)
                if vuln:
                    _release_analysis_queue(vuln)
                else:
                    _finish_analysis_queue(vulnerability_id)
                continue
            vuln = db.get_vulnerability(vulnerability_id)
            if not vuln or vuln.get("analysis_status") != "queued" or vuln.get("analysis_cancel_requested"):
                _finish_analysis_queue(vulnerability_id)
                continue
            queued.append(vuln)
            if len(queued) >= capacity:
                break
    return queued


def _analysis_concurrency() -> int:
    try:
        settings_payload = db.get_analysis_settings()
        value = settings_payload.get("max_concurrency")
        if value is None:
            value = settings_payload.get("concurrency")
        return max(1, min(int(value or 2), MAX_ANALYSIS_WORKERS))
    except (TypeError, ValueError):
        return 2


def _default_analysis_priority() -> int:
    try:
        return max(0, min(int(db.get_analysis_settings().get("default_priority", 50)), 100))
    except (TypeError, ValueError):
        return 50


def _analysis_model_selection(*, model_choice: str = "", model: str = "") -> dict[str, str]:
    model_settings = db.get_model_settings()
    flash_model = str(model_settings.get("flash_model") or settings.anthropic_default_haiku_model).strip()
    pro_model = str(model_settings.get("pro_model") or settings.anthropic_model).strip()
    default_choice = str(model_settings.get("default_analysis_model") or "pro").strip().lower()
    choice = str(model_choice or "").strip().lower()
    selected_model = str(model or "").strip()[:120]
    if choice not in {"flash", "pro"}:
        if selected_model:
            choice = _infer_analysis_model_choice(selected_model, flash_model, pro_model, default_choice)
        else:
            choice = default_choice if default_choice in {"flash", "pro"} else "pro"
    if not selected_model:
        selected_model = flash_model if choice == "flash" else pro_model
    if not selected_model:
        selected_model = settings.anthropic_model
    if choice not in {"flash", "pro"}:
        choice = _infer_analysis_model_choice(selected_model, flash_model, pro_model, "custom")
    label = "Flash" if choice == "flash" else "Pro" if choice == "pro" else "自定义"
    return {
        "choice": choice,
        "label": label,
        "model": selected_model,
        "flash_model": flash_model,
        "pro_model": pro_model,
    }


def _infer_analysis_model_choice(model: str, flash_model: str, pro_model: str, fallback: str = "pro") -> str:
    marker = str(model or "").strip().lower()
    if marker and marker == str(flash_model or "").strip().lower():
        return "flash"
    if marker and marker == str(pro_model or "").strip().lower():
        return "pro"
    if "flash" in marker or "haiku" in marker:
        return "flash"
    if "pro" in marker or "opus" in marker or "sonnet" in marker:
        return "pro"
    return fallback if fallback in {"flash", "pro", "custom"} else "pro"


def _analysis_model_profile_for_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    profile = dict(db.get_model_settings())
    profile.setdefault("source_triage_model", settings.anthropic_default_haiku_model)
    model_selection = _analysis_model_selection(model=str(vuln.get("analysis_model") or ""))
    selected_model = model_selection["model"]
    profile.update(
        {
            "analysis_model_choice": model_selection["choice"],
            "analysis_model_label": model_selection["label"],
            "selected_analysis_model": selected_model,
            "product_attribution_model": selected_model,
            "source_triage_model": selected_model,
            "root_cause_model": selected_model,
            "poc_generation_model": selected_model,
            "fix_advice_model": selected_model,
        }
    )
    trigger = str(vuln.get("analysis_trigger") or "").strip().lower()
    red_team_requested = trigger in {"red_team", "red_team_enhanced", "enhanced_exp"} or (
        "red" in trigger and "team" in trigger
    )
    if red_team_requested:
        profile["red_team_mode"] = True
        profile["enhanced_exp_enabled"] = True
        profile["analysis_mode"] = "red_team_enhanced"
    elif trigger in {"manual", "standard", ""}:
        profile["red_team_mode"] = False
        profile["analysis_mode"] = "standard"
    else:
        profile["red_team_mode"] = bool(profile.get("red_team_mode"))
        profile["analysis_mode"] = "red_team_enhanced" if profile["red_team_mode"] else "standard"
    return profile


def _analysis_mode_label(model_profile: dict[str, Any]) -> str:
    if bool(model_profile.get("red_team_mode")) or str(model_profile.get("analysis_mode") or "") == "red_team_enhanced":
        return "红队增强"
    return "标准分析"


def _run_analysis_thread(vulnerability_id: int) -> None:
    try:
        asyncio.run(_run_analysis(vulnerability_id))
    finally:
        _finish_analysis_queue(vulnerability_id)
        with _active_lock:
            _active_ids.discard(vulnerability_id)
        _drain_analysis_queue()


async def _run_analysis(vulnerability_id: int) -> None:
    queued_vuln = db.get_vulnerability(vulnerability_id)
    if not queued_vuln or queued_vuln.get("analysis_status") != "queued":
        return
    if _analysis_is_canceled(vulnerability_id):
        return

    run_id = str(uuid.uuid4())
    model_profile = _analysis_model_profile_for_vuln(queued_vuln)
    model = str(model_profile.get("selected_analysis_model") or model_profile.get("poc_generation_model") or settings.anthropic_model)
    if not db.start_vulnerability_analysis(vulnerability_id, run_id, model):
        return
    vuln = db.get_vulnerability(vulnerability_id)
    if not vuln:
        return
    db.create_message(
        level="info",
        category="analysis",
        title="漏洞分析开始",
        body=(
            f"{vuln.get('title') or vulnerability_id}\n"
            f"模型：{model_profile.get('analysis_model_label') or '模型'} · {model}\n"
            f"分析模式：{_analysis_mode_label(model_profile)}"
        ),
        entity_type="vulnerability",
        entity_id=vulnerability_id,
        raw={
            "run_id": run_id,
            "model": model,
            "analysis_model_choice": model_profile.get("analysis_model_choice"),
            "analysis_model_label": model_profile.get("analysis_model_label"),
            "model_profile": model_profile,
        },
    )

    stdout_text = ""
    stderr_text = ""
    workspace: Path | None = None
    try:
        _analysis_event(
            vulnerability_id,
            run_id,
            "stage",
            "准备检查 Claude Code CLI 和 DeepSeek 模型配置。",
        )
        _check_analysis_canceled(vulnerability_id)
        status = await ensure_claude_code()
        command_path = shutil.which(settings.claude_code_command) or status.get("path") or ""
        if not command_path:
            raise AnalysisFailure("分析失败", status.get("error") or "Claude Code CLI is not available")
        if not get_deepseek_api_key():
            raise AnalysisFailure("模型源异常", "DeepSeek API key 未配置，无法调用 DeepSeek 模型源。")
        _check_analysis_canceled(vulnerability_id)
        _analysis_event(
            vulnerability_id,
            run_id,
            "stage",
            f"Claude Code 可用：{command_path}",
            {"path": command_path},
        )

        workspace = _workspace_for_vulnerability(vuln)
        workspace.mkdir(parents=True, exist_ok=True)
        _analysis_event(
            vulnerability_id,
            run_id,
            "stage",
            f"分析工作目录已准备：{workspace}",
            {"workspace": str(workspace)},
        )
        prompt = _analysis_prompt(vuln, model_profile)
        prompt_path = workspace / "analysis_prompt.txt"
        with contextlib.suppress(OSError):
            prompt_path.write_text(prompt, encoding="utf-8")
        _analysis_event(
            vulnerability_id,
            run_id,
            "prompt",
            "模型分析提示词已写入工作目录，便于后续审计与复盘。",
            {"prompt_path": str(prompt_path), "prompt_length": len(prompt)},
        )
        _check_analysis_canceled(vulnerability_id)
        command = [
            command_path,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--allowedTools",
            settings.vulnerability_analysis_allowed_tools,
            "--permission-mode",
            "acceptEdits",
        ]
        _analysis_event(
            vulnerability_id,
            run_id,
            "stage",
            "启动 Claude Code CLI，开始检索公告、源码仓库、补丁与公开分析。",
            {"command": [command_path, "-p", "<prompt>", "--output-format", "json"]},
        )
        subprocess_env = claude_code_subprocess_env()
        subprocess_env.update(
            {
                "ANTHROPIC_MODEL": model,
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": str(
                    model_profile.get("product_attribution_model")
                    or subprocess_env.get("ANTHROPIC_DEFAULT_HAIKU_MODEL")
                    or ""
                ),
                "ANTHROPIC_DEFAULT_SONNET_MODEL": str(
                    model_profile.get("root_cause_model")
                    or subprocess_env.get("ANTHROPIC_DEFAULT_SONNET_MODEL")
                    or ""
                ),
                "ANTHROPIC_DEFAULT_OPUS_MODEL": str(
                    model_profile.get("poc_generation_model")
                    or subprocess_env.get("ANTHROPIC_DEFAULT_OPUS_MODEL")
                    or ""
                ),
            }
        )
        _analysis_event(
            vulnerability_id,
            run_id,
            "model",
            (
                "模型请求已准备："
                f"主模型 {model}；"
                f"Flash/轻量任务 {subprocess_env.get('ANTHROPIC_DEFAULT_HAIKU_MODEL') or '-'}；"
                f"深度任务 {subprocess_env.get('ANTHROPIC_DEFAULT_SONNET_MODEL') or '-'}；"
                f"允许工具 {settings.vulnerability_analysis_allowed_tools}。"
            ),
            {
                "model": model,
                "model_profile": model_profile,
                "base_url": subprocess_env.get("ANTHROPIC_BASE_URL", ""),
                "allowed_tools": settings.vulnerability_analysis_allowed_tools,
                "workspace": str(workspace),
            },
        )
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(workspace),
            env=subprocess_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        returncode, stdout_text, stderr_text = await _collect_process_output(
            process,
            vulnerability_id,
            run_id,
            workspace,
        )
        _analysis_event(
            vulnerability_id,
            run_id,
            "stage",
            "模型原始 stdout/stderr 已保存到工作目录，可用于复盘模型对话与工具调用。",
            {
                "stdout_path": str(workspace / "model_stdout.log"),
                "stderr_path": str(workspace / "model_stderr.log"),
                "stdout_length": len(stdout_text),
                "stderr_length": len(stderr_text),
            },
        )
        if returncode != 0:
            recovered = _workspace_analysis_result(workspace)
            if recovered:
                _analysis_event(
                    vulnerability_id,
                    run_id,
                    "stage",
                    "Claude Code 进程返回非 0，但工作目录中已发现可恢复 JSON 结果，优先回填数据库。",
                    {
                        "returncode": returncode,
                        "result_file": recovered.get("_workspace_result_file", ""),
                        "stderr_tail": stderr_text[-1000:],
                    },
                )
                _persist_analysis_result(
                    vulnerability_id,
                    vuln,
                    run_id,
                    model,
                    model_profile,
                    workspace,
                    recovered,
                    stdout_text,
                    stderr_text,
                    recovered_from="nonzero_workspace_result",
                )
                return
            raise _classify_analysis_failure(
                stderr_text or stdout_text or f"Claude exited {returncode}"
            )

        _check_analysis_canceled(vulnerability_id)
        _analysis_event(vulnerability_id, run_id, "stage", "模型输出已返回，开始解析 JSON 结果。")
        parsed = _parse_claude_output(stdout_text, workspace)
        _persist_analysis_result(
            vulnerability_id,
            vuln,
            run_id,
            model,
            model_profile,
            workspace,
            parsed,
            stdout_text,
            stderr_text,
        )
    except AnalysisCanceled as exc:
        _analysis_event(vulnerability_id, run_id, "cancel", str(exc) or "用户取消分析任务。")
        db.create_message(
            level="warning",
            category="analysis",
            title="漏洞分析已取消",
            body=f"{vuln.get('title') or vulnerability_id}\n{str(exc) or '用户取消分析任务。'}",
            entity_type="vulnerability",
            entity_id=vulnerability_id,
            raw={"run_id": run_id},
        )
    except asyncio.TimeoutError:
        stdout_text = stdout_text or _workspace_stream_text(workspace, "stdout")
        stderr_text = stderr_text or _workspace_stream_text(workspace, "stderr")
        if _recover_workspace_result_after_timeout(
            vulnerability_id,
            vuln,
            run_id,
            model,
            model_profile,
            workspace,
            stdout_text,
            stderr_text,
        ):
            return
        _record_analysis_failure(
            vulnerability_id,
            vuln,
            run_id,
            AnalysisFailure(
                "分析超时",
                f"Claude Code 超过 {settings.vulnerability_analysis_timeout_seconds}s 未完成，且未在工作目录发现可恢复 JSON 结果。",
            ),
            stdout_text=stdout_text,
        )
    except AnalysisFailure as exc:
        _record_analysis_failure(vulnerability_id, vuln, run_id, exc, stdout_text=stdout_text)
    except Exception as exc:
        logger.exception("Vulnerability analysis failed for %s", vulnerability_id)
        _record_analysis_failure(
            vulnerability_id,
            vuln,
            run_id,
            _classify_analysis_failure(str(exc)),
            stdout_text=stdout_text,
        )


def _recover_workspace_result_after_timeout(
    vulnerability_id: int,
    vuln: dict[str, Any],
    run_id: str,
    model: str,
    model_profile: dict[str, Any],
    workspace: Path | None,
    stdout_text: str,
    stderr_text: str,
) -> bool:
    if workspace is None:
        return False
    parsed = _workspace_analysis_result(workspace)
    if not parsed:
        _analysis_event(
            vulnerability_id,
            run_id,
            "error",
            "分析超时后检查工作目录，未发现 output.json/result.json 等可恢复结果文件。",
            {"workspace": str(workspace)},
        )
        return False
    result_file = str(parsed.get("_workspace_result_file") or "")
    _analysis_event(
        vulnerability_id,
        run_id,
        "stage",
        "Claude Code 超时退出，但工作目录中已发现可恢复 JSON 结果，正在回填数据库。",
        {"workspace": str(workspace), "result_file": result_file},
    )
    try:
        _persist_analysis_result(
            vulnerability_id,
            vuln,
            run_id,
            model,
            model_profile,
            workspace,
            parsed,
            stdout_text,
            stderr_text,
            recovered_from="timeout_workspace_result",
        )
        return True
    except Exception as exc:
        logger.exception("failed to recover analysis result from workspace for %s", vulnerability_id)
        _analysis_event(
            vulnerability_id,
            run_id,
            "error",
            f"工作目录结果回填失败：{str(exc)[:1000]}",
            {"workspace": str(workspace), "result_file": result_file},
        )
        return False


def _persist_analysis_result(
    vulnerability_id: int,
    vuln: dict[str, Any],
    run_id: str,
    model: str,
    model_profile: dict[str, Any],
    workspace: Path,
    parsed: dict[str, Any],
    stdout_text: str,
    stderr_text: str,
    *,
    recovered_from: str = "",
) -> dict[str, Any] | None:
    sources = _source_refs(parsed)
    source_repositories = _source_repository_refs(parsed)
    source_artifact = _source_artifact_metadata(
        vulnerability_id,
        run_id,
        workspace,
        source_repositories,
    )
    poc_content = _artifact_content(parsed, "poc")
    exp_content = _artifact_content(parsed, "exp")
    poc_status = _artifact_validation_label(parsed, "poc")
    exp_status = _artifact_validation_label(parsed, "exp")
    poc_available = _artifact_available(parsed, "poc", poc_content)
    exp_available = _artifact_available(parsed, "exp", exp_content)
    _analysis_event(
        vulnerability_id,
        run_id,
        "poc",
        f"公开 POC 检索与验证：{poc_status}，内容长度 {len(poc_content)} 字符。",
        {"available": poc_available, "validation": poc_status, "content_length": len(poc_content)},
    )
    _analysis_event(
        vulnerability_id,
        run_id,
        "exp",
        f"公开 EXP 与红队增强 EXP 验证：{exp_status}，内容长度 {len(exp_content)} 字符。",
        {"available": exp_available, "validation": exp_status, "content_length": len(exp_content)},
    )
    source_msg, source_found = _analysis_source_status(parsed)
    source_label = "源码已找到" if source_found else "源码未找到"
    _analysis_event(
        vulnerability_id,
        run_id,
        "source",
        f"源码检索结果：{source_label}。",
        {"source_found": source_found, "repositories": source_repositories, "artifact": source_artifact},
    )
    raw = {
        "claude_output": parsed,
        "stdout": stdout_text[-12000:],
        "stderr": stderr_text[-4000:],
        "workspace": str(workspace),
        "model_profile": model_profile,
        "analysis_model": model,
        "analysis_model_choice": model_profile.get("analysis_model_choice"),
        "analysis_model_label": model_profile.get("analysis_model_label"),
        "analysis_contract_version": 2,
        "source_found": source_found,
        "source_found_label": source_label,
        "source_artifact": source_artifact,
        "poc_validation": poc_status,
        "exp_validation": exp_status,
    }
    if recovered_from:
        raw["recovered_from"] = recovered_from
    updated = db.finish_vulnerability_analysis(
        vulnerability_id,
        summary=_summary_text(parsed),
        sources=sources,
        raw=raw,
        analysis_error=source_msg,
        source_found=source_found,
        source_url=source_artifact.get("url", ""),
        source_local_path=source_artifact.get("local_path", ""),
        source_title=source_artifact.get("title", ""),
        source_archive_path=source_artifact.get("archive_path", ""),
        source_retained_until=source_artifact.get("retained_until", ""),
        poc_available=poc_available,
        poc_url=_artifact_url(parsed, "poc"),
        poc_content=poc_content,
        exp_available=exp_available,
        exp_url=_artifact_url(parsed, "exp"),
        exp_content=exp_content,
    )
    try:
        archived_source = register_analysis_source_artifact(updated or vuln, source_artifact)
        if archived_source:
            _analysis_event(
                vulnerability_id,
                run_id,
                "source",
                "源码压缩包已加入源码库，后台会异步上传 MinIO 并等待产品确认。",
                {"source_archive_id": archived_source.get("id")},
            )
    except Exception:
        logger.warning("failed to register source artifact for vulnerability %s", vulnerability_id, exc_info=True)
    db.create_message(
        level="success",
        category="analysis",
        title="漏洞分析完成（超时恢复）" if recovered_from else "漏洞分析完成",
        body=_analysis_message_body(updated or vuln, poc_content, exp_content, source_msg, source_found),
        entity_type="vulnerability",
        entity_id=vulnerability_id,
        raw={
            "run_id": run_id,
            "poc_available": bool((updated or {}).get("poc_available")),
            "exp_available": bool((updated or {}).get("exp_available")),
            "sources": sources,
            "source_found": source_found,
            "recovered_from": recovered_from,
            "analysis_model": model,
            "analysis_model_choice": model_profile.get("analysis_model_choice"),
            "analysis_model_label": model_profile.get("analysis_model_label"),
        },
    )
    usage_recorded = db.record_claude_model_usage(
        task_type="deep_analysis",
        default_model=model,
        stdout_text=stdout_text,
        status="success",
        raw={
            "run_id": run_id,
            "vulnerability_id": vulnerability_id,
            "source_found": source_found,
            "recovered_from": recovered_from,
            "analysis_model_choice": model_profile.get("analysis_model_choice"),
            "analysis_model_label": model_profile.get("analysis_model_label"),
        },
    )
    if not usage_recorded:
        db.record_model_usage(
            task_type="deep_analysis",
            model=model,
            status="success",
            raw={
                "run_id": run_id,
                "vulnerability_id": vulnerability_id,
                "source_found": source_found,
                "recovered_from": recovered_from,
                "analysis_model_choice": model_profile.get("analysis_model_choice"),
                "analysis_model_label": model_profile.get("analysis_model_label"),
            },
        )
    _analysis_event(
        vulnerability_id,
        run_id,
        "finish",
        "分析结果已写入数据库并刷新 POC/EXP 状态。"
        + (" 本次结果来自超时后的工作目录 JSON 回收。" if recovered_from else ""),
        {"recovered_from": recovered_from} if recovered_from else {},
    )
    return updated


async def _collect_process_output(
    process: asyncio.subprocess.Process,
    vulnerability_id: int,
    run_id: str,
    workspace: Path | None = None,
) -> tuple[int, str, str]:
    async def read_stream(stream: asyncio.StreamReader | None, stream_name: str) -> str:
        if stream is None:
            return ""
        chunks: list[str] = []
        try:
            while True:
                chunk = await stream.readline()
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                chunks.append(text)
                message, raw = _stream_event_payload(text, stream_name)
                if message:
                    _analysis_event(
                        vulnerability_id,
                        run_id,
                        stream_name,
                        message,
                        {"bytes": len(chunk), **raw},
                    )
            return "".join(chunks)
        finally:
            if workspace is not None and chunks:
                transcript_path = workspace / f"model_{stream_name}.log"
                with contextlib.suppress(OSError):
                    transcript_path.write_text("".join(chunks), encoding="utf-8")

    stdout_task = asyncio.create_task(read_stream(process.stdout, "stdout"))
    stderr_task = asyncio.create_task(read_stream(process.stderr, "stderr"))
    loop = asyncio.get_running_loop()
    timeout_seconds = settings.vulnerability_analysis_timeout_seconds
    deadline = loop.time() + timeout_seconds
    returncode: int
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            _analysis_event(
                vulnerability_id,
                run_id,
                "error",
                f"Claude Code 超过 {timeout_seconds}s 未完成，已终止进程。",
            )
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            raise asyncio.TimeoutError
        try:
            returncode = await asyncio.wait_for(process.wait(), timeout=min(1.0, remaining))
            break
        except asyncio.TimeoutError:
            if _analysis_is_canceled(vulnerability_id):
                _analysis_event(vulnerability_id, run_id, "cancel", "检测到取消请求，正在终止 Claude Code 进程。")
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.wait()
                await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
                raise AnalysisCanceled("用户取消分析任务，Claude Code 进程已终止。")
    stdout_text, stderr_text = await asyncio.gather(stdout_task, stderr_task)
    return returncode, stdout_text, stderr_text


def _workspace_stream_text(workspace: Path | None, stream_name: str) -> str:
    if workspace is None:
        return ""
    try:
        return (workspace / f"model_{stream_name}.log").read_text(encoding="utf-8")
    except OSError:
        return ""


def _stream_event_payload(text: str, stream_name: str) -> tuple[str, dict[str, Any]]:
    clean = " ".join((text or "").strip().split())
    if not clean:
        return "", {}
    if clean.startswith("{"):
        try:
            payload = json.loads(clean)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            result_text = str(payload.get("result") or "")
            usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
            model_usage = payload.get("modelUsage") if isinstance(payload.get("modelUsage"), dict) else {}
            model_names = ", ".join(str(name) for name in list(model_usage)[:4])
            token_parts = []
            for key, label in [
                ("input_tokens", "input"),
                ("cache_creation_input_tokens", "cache_create"),
                ("cache_read_input_tokens", "cache_read"),
                ("output_tokens", "output"),
            ]:
                if usage and usage.get(key) is not None:
                    token_parts.append(f"{label}={usage.get(key)}")
            summary = [
                f"{stream_name} 模型事件 {payload.get('type') or '-'} / {payload.get('subtype') or '-'}",
                f"stop={payload.get('stop_reason')}" if payload.get("stop_reason") else "",
                f"turns={payload.get('num_turns')}" if payload.get("num_turns") is not None else "",
                f"duration={payload.get('duration_ms')}ms" if payload.get("duration_ms") is not None else "",
                f"tokens {' '.join(token_parts)}" if token_parts else "",
                f"models {model_names}" if model_names else "",
                f"result: {result_text[:700]}" if result_text else "",
            ]
            return "；".join(part for part in summary if part), {
                "json_event": {
                    "type": payload.get("type"),
                    "subtype": payload.get("subtype"),
                    "is_error": payload.get("is_error"),
                    "stop_reason": payload.get("stop_reason"),
                    "duration_ms": payload.get("duration_ms"),
                    "duration_api_ms": payload.get("duration_api_ms"),
                    "num_turns": payload.get("num_turns"),
                    "session_id": payload.get("session_id"),
                    "total_cost_usd": payload.get("total_cost_usd"),
                    "usage": usage,
                    "model_usage_keys": list(model_usage)[:12],
                    "result_preview": result_text[:2000],
                }
            }
    if clean.startswith("{") and len(clean) > 800:
        return f"{stream_name} 返回 JSON 结果，长度 {len(clean)} 字符。", {}
    return clean[:2000], {}


def _stream_event_message(text: str, stream_name: str) -> str:
    message, _ = _stream_event_payload(text, stream_name)
    return message


def _analysis_event(
    vulnerability_id: int,
    run_id: str,
    stream: str,
    message: str,
    raw: dict[str, Any] | None = None,
) -> None:
    try:
        db.create_analysis_event(vulnerability_id, run_id, stream, message, raw or {})
    except Exception:
        logger.debug("Failed to persist analysis event", exc_info=True)


def _analysis_is_canceled(vulnerability_id: int) -> bool:
    vuln = db.get_vulnerability(vulnerability_id)
    if not vuln:
        return True
    return bool(vuln.get("analysis_cancel_requested")) or vuln.get("analysis_status") == "canceled"


def _check_analysis_canceled(vulnerability_id: int) -> None:
    if _analysis_is_canceled(vulnerability_id):
        raise AnalysisCanceled("用户取消分析任务。")


def _workspace_for_vulnerability(vuln: dict[str, Any]) -> Path:
    label = vuln.get("cve_id") or vuln.get("source_uid") or str(vuln.get("id"))
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(label)).strip("-") or str(vuln.get("id"))
    return settings.vulnerability_analysis_workspace_dir / f"{vuln.get('id')}-{safe[:80]}"


def _record_analysis_failure(
    vulnerability_id: int,
    vuln: dict[str, Any],
    run_id: str,
    failure: AnalysisFailure,
    stdout_text: str = "",
) -> None:
    detail = f"{failure.reason}：{failure.detail}"[:4000]
    _analysis_event(vulnerability_id, run_id, "error", detail)
    db.fail_vulnerability_analysis(vulnerability_id, detail)
    model = str(vuln.get("analysis_model") or settings.anthropic_model)
    usage_recorded = db.record_claude_model_usage(
        task_type="deep_analysis",
        default_model=model,
        stdout_text=stdout_text,
        status="failed",
        raw={"run_id": run_id, "vulnerability_id": vulnerability_id, "reason": failure.reason},
    )
    if not usage_recorded and not db.model_usage_recorded_for_run(run_id):
        db.record_model_usage(
            task_type="deep_analysis",
            model=model,
            status="failed",
            raw={"run_id": run_id, "vulnerability_id": vulnerability_id, "reason": failure.reason},
        )
    db.create_message(
        level="error",
        category="analysis",
        title=failure.reason,
        body=f"{vuln.get('title') or vulnerability_id}\n{failure.detail[:2000]}",
        entity_type="vulnerability",
        entity_id=vulnerability_id,
        raw={"run_id": run_id, "reason": failure.reason, "detail": failure.detail},
    )


def _classify_analysis_failure(text: str) -> AnalysisFailure:
    detail = (text or "未知错误").strip()[:4000]
    lower = detail.lower()
    model_markers = [
        "deepseek",
        "anthropic",
        "api key",
        "auth",
        "unauthorized",
        "forbidden",
        "quota",
        "balance",
        "rate limit",
        "429",
        "401",
        "403",
        "model",
    ]
    if any(marker in lower for marker in model_markers):
        return AnalysisFailure("模型源异常", detail)
    source_markers = [
        "no repository",
        "repository not found",
        "source not found",
        "could not find source",
        "未找到源码",
        "源码未找到",
        "源码未搜索到",
    ]
    if any(marker in lower for marker in source_markers):
        return AnalysisFailure("源码未搜索到", detail)
    return AnalysisFailure("分析失败", detail)


def _analysis_prompt(vuln: dict[str, Any], model_profile: dict[str, Any] | None = None) -> str:
    model_profile = model_profile or db.get_model_settings()
    payload = {
        "id": vuln.get("id"),
        "source": vuln.get("source"),
        "source_uid": vuln.get("source_uid"),
        "title": vuln.get("title"),
        "severity": vuln.get("severity"),
        "cve_id": vuln.get("cve_id"),
        "aliases": vuln.get("aliases"),
        "published_at": vuln.get("published_at"),
        "updated_at": vuln.get("updated_at"),
        "description": vuln.get("description"),
        "url": vuln.get("url"),
        "product": vuln.get("product"),
        "cvss_score": vuln.get("cvss_score"),
        "cvss_vector": vuln.get("cvss_vector"),
        "existing_local_source": _existing_source_context(vuln),
        "raw": vuln.get("raw"),
    }
    red_team_mode = bool(model_profile.get("red_team_mode", True))
    return _two_stage_prompt(payload, model_profile, red_team_mode)


def _existing_source_context(vuln: dict[str, Any]) -> dict[str, Any]:
    source_found = bool(vuln.get("analysis_source_found"))
    local_path = str(vuln.get("analysis_source_local_path") or "").strip()
    archive_path = str(vuln.get("analysis_source_archive_path") or "").strip()
    return {
        "source_found": source_found,
        "title": str(vuln.get("analysis_source_title") or "").strip(),
        "url": str(vuln.get("analysis_source_url") or "").strip(),
        "local_path": local_path,
        "archive_path": archive_path,
        "retained_until": str(vuln.get("analysis_source_retained_until") or "").strip(),
        "cleaned_at": str(vuln.get("analysis_source_cleaned_at") or "").strip(),
        "local_path_exists": bool(local_path and Path(local_path).exists()),
        "archive_exists": bool(archive_path and Path(archive_path).exists()),
    }


def _two_stage_prompt(payload: dict[str, Any], model_profile: dict[str, Any], red_team: bool) -> str:
    mode_label = "红队攻击模拟" if red_team else "防御分析"
    exp_instruction = (
        "在授权红队模式下生成增强 EXP：必须基于公开 POC/EXP 与源码证据，写清利用条件、参数、失败条件和安全边界；"
        "如果证据不足，只输出可复现实验思路与缺失证据，不要编造代码。"
        if red_team
        else "仅输出防御侧利用可能性分析、检测步骤和缓解建议，不生成可直接攻击公网目标的武器化代码。"
    )
    return f"""
你是{mode_label}助手。请严格按顺序完成下面这条漏洞的后端 LLM 深度分析。必须先查公开 POC/EXP，再优先使用本地已保留源码做版本与根因核验；只有本地源码缺失、版本不匹配或证据不足时，才继续搜索现网源码，最后再决定是否生成增强 EXP：

{json.dumps(payload, ensure_ascii=False, indent=2)}

---
### 阶段一：公开 POC/EXP 现网检索与可用性判断
1. 使用 WebSearch/WebFetch 优先搜索：CVE ID、漏洞标题、产品名、版本号、`poc`、`exploit`、`exp`、`github`、`exploit-db`、`packet storm`、`nuclei`、`metasploit`。
2. 覆盖 GitHub、GitLab、Exploit-DB、Packet Storm、NVD、GitHub Advisory、厂商公告、安全研究博客。
3. 如果发现公开 POC/EXP 仓库或脚本，可以在当前工作目录使用 git clone、curl、npm pack、pip download 下载，只阅读必要文件。
4. 判断公开 POC/EXP 是否可用：必须说明证据、入口点、受影响版本、运行条件、是否只是占位/转载/误报。
5. 没有公开 POC/EXP 时，`poc_available`/`exp_available` 必须为 false，不要把“存在标记”当成可用代码。

### 阶段二：本地源码优先、版本对比与源码辅助验证
1. 如果 `existing_local_source.source_found=true`，优先读取 `existing_local_source.local_path`；如果展开目录已清理但 `archive_path` 存在，可以先解压到当前工作目录的临时目录再读取。不要在完成本地判断前搜索现网源码。
2. 从漏洞告警、NVD/CVE、厂商公告和包元数据中提取受影响版本、修复版本、组件名；从本地源码的 package.json、pom.xml、setup.py、go.mod、CHANGELOG、tag/commit 信息中提取当前源码版本。
3. 明确输出“本地源码版本是否落在受影响范围内”：affected / fixed / unknown / mismatch。若 mismatch 或 unknown 会影响根因、POC/EXP 可用性判断，再使用 WebSearch/WebFetch 搜索现网源码、受影响版本包、修复版本包或补丁提交。
4. 如果没有可用本地源码，使用 WebSearch 在官网、npm、PyPI、GitHub、GitLab 搜索产品源码或包源码。搜索顺序：官方仓库/官网源码链接 -> GitHub/GitLab 组织仓库 -> npm 包 -> PyPI 包 -> 其他公开镜像。
5. 找到源码后下载到当前工作目录，优先使用 git clone；npm/PyPI 包可使用 npm pack 或 pip download 后解包。
6. 只阅读与漏洞有关的路由、控制器、解析器、依赖版本、补丁提交、变更记录，不做大范围无关扫描。
7. 结合源码验证 POC/EXP 是否真实有效：定位受影响函数/文件/版本，说明触发路径、失败条件、以及本地源码版本对结论的影响。
8. 如果找不到可下载源码，直接跳过源码验证，不得因此判定整个分析失败；`source_found=false`，`source_found_label="源码未找到"`。若数据库中已有历史源码证据，请在 `source_analysis` 说明“本轮未找到新源码，但保留历史源码证据”。

### 阶段三：红队增强 EXP / 防御输出
{exp_instruction}

### 阶段四：最终 JSON 输出
1. 将工作拆成：产品归属、公开 POC/EXP 验证、源码检索、源码根因、增强 EXP/检测、修复建议。
2. 最后只输出一个统一 JSON 对象，不要 Markdown 围栏，不要额外解释。
3. 对输出做结构化自检：字段缺失时填空字符串或空数组，不要编造来源；confidence 使用 0 到 1 的数字。

模型任务配置：
{json.dumps(model_profile, ensure_ascii=False, indent=2)}

模型使用建议：
- `source_triage_model`/`product_attribution_model` 可用于轻量产品归属、本地源码版本适配和是否需要现网源码的判断。
- 深度根因、POC/EXP 可靠性和红队增强结论使用更强模型完成。

JSON schema:
{{
  "summary": "中文概要，包含影响、根因、POC/EXP 可用性、源码是否找到、{'攻击建议' if red_team else '处置建议'}",
  "affected_products": ["..."],
  "product_attribution": {{"product": "...", "confidence": 0.0, "evidence": "..."}},
  "root_cause": "...",
  "attack_surface": "...",
  "source_found": true,
  "source_found_label": "源码已找到 | 源码未找到",
  "source_analysis": "源码仓库、文件路径、函数/类、受影响版本、本地源码版本、版本匹配结论和触发路径；没有源码则说明已跳过",
  "source_version_assessment": {{"alert_affected_versions": "...", "local_source_version": "...", "match": "affected | fixed | unknown | mismatch", "impact_on_analysis": "...", "needs_online_source": false}},
  "public_poc_exp": [
    {{"kind": "poc | exp", "title": "...", "url": "...", "local_path": "...", "validation": "usable | partial | unverified | invalid | not_found", "evidence": "..."}}
  ],
  "poc_validation": {{"status": "usable | partial | unverified | invalid | not_found", "evidence": "..."}},
  "poc_available": true,
  "poc_content": "只有在 POC 可用或可部分验证时填写非破坏性验证步骤、请求样例、curl/Python 脚本；否则为空字符串",
  "exp_validation": {{"status": "usable | partial | unverified | invalid | not_found", "evidence": "..."}},
  "exp_available": true,
  "exp_content": "{'增强 EXP 或授权渗透步骤；必须基于证据并说明安全边界' if red_team else 'EXP/利用可能性分析、前置条件、检测与缓解；不要给出武器化利用载荷'}",
  "enhanced_exp_available": true,
  "enhanced_exp_summary": "增强 EXP 基于哪些公开 POC/EXP 和源码证据；证据不足时说明缺口",
  "exp_type": "rce | file_upload | sqli | ssti | deserialize | ssrf | auth_bypass | other",
  "exp_command_example": "python3 exploit.py -t 192.168.1.100 -p 8080",
  "remediation": "修复建议、升级版本、临时缓解、检测排查步骤",
  "references": [{{"title": "...", "url": "..."}}],
  "source_repositories": [{{"name": "...", "url": "...", "local_path": "..."}}],
  "confidence": 0.0
}}
""".strip()


def _parse_claude_output(stdout_text: str, workspace: Path | None = None) -> dict[str, Any]:
    workspace_result = _workspace_analysis_result(workspace)
    outer = _json_from_text(stdout_text)
    if isinstance(outer, dict):
        result = outer.get("result") or outer.get("message") or outer.get("content")
        if isinstance(result, str):
            inner = _json_from_text(result)
            if isinstance(inner, dict) and ("summary" in inner or "poc_available" in inner or "exp_available" in inner):
                return inner
            if workspace_result:
                return workspace_result
        if all(key in outer for key in ["summary", "poc_available", "exp_available"]):
            return outer
        if "summary" in outer:
            return outer
    if isinstance(outer, list):
        for item in reversed(outer):
            if isinstance(item, dict) and item.get("type") == "result":
                result = item.get("result")
                if isinstance(result, str):
                    inner = _json_from_text(result)
                    if isinstance(inner, dict):
                        return inner
                    if workspace_result:
                        return workspace_result
    fallback = _json_from_text(stdout_text.strip())
    if isinstance(fallback, dict) and "summary" in fallback:
        return fallback
    if workspace_result:
        return workspace_result
    return {"summary": stdout_text.strip()[:12000], "poc_available": False, "exp_available": False}


def _workspace_analysis_result(workspace: Path | None) -> dict[str, Any]:
    if workspace is None:
        return {}
    for name in ["output.json", "analysis_result.json", "analysis.json", "result.json"]:
        path = workspace / name
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        normalized = _normalize_analysis_payload(payload)
        if normalized:
            normalized.setdefault("_workspace_result_file", str(path))
            return normalized
    return {}


def _normalize_analysis_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if "summary" in payload or "poc_available" in payload or "exp_available" in payload:
        return payload
    for key in ["result", "message", "content"]:
        value = payload.get(key)
        if isinstance(value, dict):
            nested = _normalize_analysis_payload(value)
            if nested:
                return nested
        if isinstance(value, str):
            nested = _json_from_text(value)
            if isinstance(nested, dict):
                normalized = _normalize_analysis_payload(nested)
                if normalized:
                    return normalized
    return {}


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


def _summary_text(parsed: dict[str, Any]) -> str:
    source_label = str(parsed.get("source_found_label") or "").strip()
    if not source_label:
        source_label = "源码已找到" if _analysis_source_status(parsed)[1] else "源码未找到"
    parts = [
        str(parsed.get("summary") or "").strip(),
        f"公开 POC 验证：{_artifact_validation_label(parsed, 'poc')}",
        f"公开/增强 EXP 验证：{_artifact_validation_label(parsed, 'exp')}",
        f"源码检索：{source_label}",
        f"源码分析：{parsed.get('source_analysis')}" if parsed.get("source_analysis") else "",
        f"根因：{parsed.get('root_cause')}" if parsed.get("root_cause") else "",
        f"攻击面：{parsed.get('attack_surface')}" if parsed.get("attack_surface") else "",
        f"增强 EXP：{parsed.get('enhanced_exp_summary')}" if parsed.get("enhanced_exp_summary") else "",
        f"置信度：{parsed.get('confidence')}" if parsed.get("confidence") else "",
    ]
    return "\n\n".join(part for part in parts if part)


def _source_refs(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for key in ["references", "source_repositories", "public_poc_exp", "poc_candidates", "exp_candidates"]:
        values = parsed.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, dict):
                title = str(value.get("title") or value.get("name") or value.get("url") or "").strip()
                url = str(value.get("url") or "").strip()
                local_path = str(value.get("local_path") or "").strip()
                kind = str(value.get("kind") or key).strip()
                validation = str(value.get("validation") or value.get("status") or "").strip()
                if title or url or local_path:
                    refs.append(
                        {
                            "title": title,
                            "url": url,
                            "local_path": local_path,
                            "kind": kind,
                            "validation": validation,
                        }
                    )
            elif isinstance(value, str) and value.strip():
                refs.append({"title": value.strip(), "url": "", "local_path": "", "kind": key})
    return refs


def _source_repository_refs(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for key in ["source_repositories", "source_candidates", "source_code_repositories"]:
        repos = parsed.get(key)
        if not isinstance(repos, list):
            continue
        for value in repos:
            if not isinstance(value, dict):
                continue
            url = str(value.get("url") or "").strip()
            local_path = str(value.get("local_path") or "").strip()
            name = str(value.get("name") or value.get("title") or url or local_path).strip()
            if url or local_path:
                refs.append({"title": name, "url": url, "local_path": local_path, "kind": "source"})
    return refs


def _source_artifact_metadata(
    vulnerability_id: int,
    run_id: str,
    workspace: Path,
    source_refs: list[dict[str, Any]],
) -> dict[str, str]:
    local_paths = _source_local_paths(workspace, source_refs)
    primary = _primary_source_ref(source_refs)
    archive_path = _archive_source_paths(vulnerability_id, run_id, workspace, local_paths)
    retained_until = (
        datetime.now(timezone.utc) + timedelta(days=settings.vulnerability_source_retention_days)
    ).isoformat(timespec="seconds")
    if archive_path:
        primary["archive_path"] = archive_path
        primary["retained_until"] = retained_until
        primary["cleanup_paths"] = [str(path) for path in local_paths]
    return primary


def _primary_source_ref(source_refs: list[dict[str, Any]]) -> dict[str, str]:
    for ref in source_refs:
        url = str(ref.get("url") or "").strip()
        local_path = str(ref.get("local_path") or "").strip()
        title = str(ref.get("title") or ref.get("name") or url or local_path or "源码").strip()
        if url or local_path:
            return {
                "title": title,
                "url": url,
                "local_path": local_path,
                "archive_path": "",
                "retained_until": "",
            }
    return {"title": "", "url": "", "local_path": "", "archive_path": "", "retained_until": ""}


def _source_local_paths(workspace: Path, source_refs: list[dict[str, Any]]) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for ref in source_refs:
        raw_path = str(ref.get("local_path") or "").strip()
        if not raw_path:
            continue
        path = Path(raw_path)
        if not path.is_absolute():
            path = workspace / path
        try:
            resolved = path.resolve()
            workspace_resolved = workspace.resolve()
        except OSError:
            continue
        if not _path_is_relative_to(resolved, workspace_resolved) or not resolved.exists():
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        paths.append(resolved)
        ref["local_path"] = str(resolved)
    return paths


def _archive_source_paths(
    vulnerability_id: int,
    run_id: str,
    workspace: Path,
    source_paths: list[Path],
) -> str:
    if not source_paths:
        return ""
    archive_dir = workspace / "_source_archives"
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{vulnerability_id}-{run_id[:8]}-source.zip"
    workspace_resolved = workspace.resolve()
    try:
        with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as zf:
            for source_path in source_paths:
                if source_path.is_dir():
                    for child in source_path.rglob("*"):
                        if not child.is_file():
                            continue
                        if ".git" in child.parts or "_source_archives" in child.parts:
                            continue
                        zf.write(child, child.relative_to(workspace_resolved))
                elif source_path.is_file():
                    zf.write(source_path, source_path.relative_to(workspace_resolved))
    except OSError:
        logger.warning("failed to archive source paths for vulnerability %s", vulnerability_id, exc_info=True)
        return ""
    return str(archive_path)


def _path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def cleanup_expired_source_artifacts_sync(limit: int = 100) -> dict[str, int]:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = db.list_expired_analysis_source_artifacts(now, limit=limit)
    checked = cleaned = deleted_paths = failed = 0
    workspace_root = settings.vulnerability_analysis_workspace_dir.resolve()
    for row in rows:
        checked += 1
        paths = _cleanup_paths_from_row(row)
        archive_path = str(row.get("analysis_source_archive_path") or "")
        for path in paths:
            try:
                resolved = Path(path).resolve()
            except OSError:
                continue
            if not _path_is_relative_to(resolved, workspace_root):
                continue
            if archive_path and str(resolved) == archive_path:
                continue
            if "_source_archives" in resolved.parts:
                continue
            try:
                if resolved.is_dir():
                    shutil.rmtree(resolved)
                    deleted_paths += 1
                elif resolved.is_file() and resolved.suffix.lower() not in {".zip", ".tgz", ".tar", ".gz"}:
                    resolved.unlink()
                    deleted_paths += 1
            except OSError:
                failed += 1
                logger.warning("failed to clean expired source path: %s", resolved, exc_info=True)
        db.mark_analysis_source_cleaned(int(row["id"]), now)
        cleaned += 1
    return {"checked": checked, "cleaned": cleaned, "deleted_paths": deleted_paths, "failed": failed}


def _cleanup_paths_from_row(row: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    raw = row.get("analysis_raw")
    if raw:
        try:
            payload = json.loads(str(raw))
        except (TypeError, json.JSONDecodeError):
            payload = {}
        artifact = payload.get("source_artifact") if isinstance(payload, dict) else {}
        cleanup_paths = artifact.get("cleanup_paths") if isinstance(artifact, dict) else []
        if isinstance(cleanup_paths, list):
            paths.extend(str(item) for item in cleanup_paths if item)
    local_path = str(row.get("analysis_source_local_path") or "")
    if local_path:
        paths.append(local_path)
    seen: set[str] = set()
    unique: list[str] = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    return unique


def _analysis_source_status(parsed: dict[str, Any]) -> tuple[str, bool]:
    source_found = bool(parsed.get("source_found")) or bool(_source_repository_refs(parsed))
    if source_found:
        return "", True
    return "未搜索到可下载的源码仓库；POC/EXP 基于公开情报分析生成。", False


def _artifact_url(parsed: dict[str, Any], kind: str) -> str:
    for key in [f"{kind}_url", f"{kind}_source_url"]:
        direct = str(parsed.get(key) or "").strip()
        if direct:
            return direct
    for value in _artifact_candidate_dicts(parsed, kind):
        url = str(value.get("url") or value.get("source_url") or "").strip()
        if url:
            return url
    for ref in _source_refs(parsed):
        url = ref.get("url") or ""
        if kind in url.lower():
            return url
    return ""


def _artifact_content(parsed: dict[str, Any], kind: str) -> str:
    keys = [f"{kind}_content", kind]
    if kind == "poc":
        keys.extend(["proof_of_concept", "validation_poc"])
    else:
        keys.extend(["enhanced_exp_content", "enhanced_exp", "red_team_exp", "exploit", "exploit_content"])
    for key in keys:
        value = parsed.get(key)
        text = _text_from_artifact_value(value)
        if text:
            return text
    for value in _artifact_candidate_dicts(parsed, kind):
        text = _text_from_artifact_value(
            value.get("content")
            or value.get("code")
            or value.get("script")
            or value.get("analysis")
            or value.get("evidence")
        )
        if text and not _looks_negative_artifact(text):
            return text
    return ""


def _text_from_artifact_value(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ["content", "code", "script", "body", "text", "analysis", "summary"]:
            text = _text_from_artifact_value(value.get(key))
            if text:
                return text
    if isinstance(value, list):
        parts = [_text_from_artifact_value(item) for item in value]
        return "\n\n".join(part for part in parts if part).strip()
    return ""


def _artifact_available(parsed: dict[str, Any], kind: str, content: str) -> bool:
    status = _artifact_status_value(parsed, kind)
    if status in {"invalid", "not_found", "unusable", "unsafe"}:
        return False
    if _looks_negative_artifact(content):
        return False
    flags = [
        parsed.get(f"{kind}_available"),
        parsed.get(f"{kind}_valid"),
        parsed.get(f"{kind}_usable"),
    ]
    if kind == "exp":
        flags.extend([parsed.get("enhanced_exp_available"), parsed.get("red_team_exp_available")])
    if any(_bool(flag) for flag in flags):
        return bool(content or _artifact_url(parsed, kind))
    return bool(content) and status not in {"unverified", "not_found", "invalid"}


def _artifact_validation_label(parsed: dict[str, Any], kind: str) -> str:
    status = _artifact_status_value(parsed, kind)
    labels = {
        "usable": "可用",
        "partial": "部分可用",
        "verified": "已验证",
        "unverified": "未验证",
        "invalid": "无效",
        "not_found": "未找到",
        "unusable": "不可用",
        "unsafe": "需人工复核",
        "unknown": "未说明",
    }
    evidence = _artifact_evidence(parsed, kind)
    label = labels.get(status, status or "未说明")
    if evidence:
        return f"{label}：{evidence[:180]}"
    return label


def _artifact_status_value(parsed: dict[str, Any], kind: str) -> str:
    candidates: list[Any] = [
        parsed.get(f"{kind}_validation"),
        parsed.get(f"{kind}_validity"),
        parsed.get(f"{kind}_usability"),
        parsed.get(f"{kind}_status"),
    ]
    if kind == "exp":
        candidates.extend([parsed.get("enhanced_exp_validation"), parsed.get("enhanced_exp_status")])
    for value in candidates:
        status = _status_from_value(value)
        if status:
            return status
    for value in _artifact_candidate_dicts(parsed, kind):
        status = _status_from_value(value.get("validation") or value.get("status"))
        if status:
            return status
    return "unknown"


def _status_from_value(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("status") or value.get("result") or value.get("label")
    text = str(value or "").strip().lower()
    if not text:
        return ""
    mapping = [
        ("not_found", ["not_found", "not found", "no public", "none", "未找到", "无公开", "没有公开"]),
        ("invalid", ["invalid", "false", "误报", "无效", "不可复现"]),
        ("unusable", ["unusable", "不可用", "无法使用"]),
        ("unsafe", ["unsafe", "危险", "需人工复核"]),
        ("partial", ["partial", "partially", "部分", "可部分"]),
        ("verified", ["verified", "confirmed", "已验证", "确认"]),
        ("usable", ["usable", "available", "working", "可用", "可复现"]),
        ("unverified", ["unverified", "unknown", "未验证", "无法验证", "未确认"]),
    ]
    for normalized, markers in mapping:
        if any(marker in text for marker in markers):
            return normalized
    return text[:40]


def _artifact_evidence(parsed: dict[str, Any], kind: str) -> str:
    for key in [f"{kind}_validation", f"{kind}_validity", f"{kind}_usability"]:
        value = parsed.get(key)
        if isinstance(value, dict):
            text = str(value.get("evidence") or value.get("reason") or "").strip()
            if text:
                return text
    for value in _artifact_candidate_dicts(parsed, kind):
        text = str(value.get("evidence") or value.get("reason") or value.get("title") or "").strip()
        if text:
            return text
    return ""


def _artifact_candidate_dicts(parsed: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    keys = ["public_poc_exp", f"{kind}_candidates", f"{kind}_references"]
    if kind == "poc":
        keys.extend(["poc_repositories", "poc_sources"])
    else:
        keys.extend(["exp_repositories", "exploit_repositories", "exploit_sources"])
    candidates: list[dict[str, Any]] = []
    for key in keys:
        values = parsed.get(key)
        if isinstance(values, dict):
            values = [values]
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, dict):
                continue
            item_kind = str(value.get("kind") or key).lower()
            if kind == "poc" and "exp" in item_kind and "poc" not in item_kind:
                continue
            if kind == "exp" and not any(token in item_kind for token in ["exp", "exploit", "public_poc_exp"]):
                continue
            candidates.append(value)
    return candidates


def _looks_negative_artifact(text: str) -> bool:
    sample = str(text or "").strip().lower()[:500]
    if not sample:
        return True
    negative_markers = [
        "暂无",
        "未找到",
        "无公开",
        "没有公开",
        "无法验证",
        "不可用",
        "无效",
        "not found",
        "no public",
        "unavailable",
        "invalid",
        "placeholder",
    ]
    return len(sample) < 240 and any(marker in sample for marker in negative_markers)


def _analysis_message_body(
    vuln: dict[str, Any],
    poc_content: str,
    exp_content: str,
    source_msg: str = "",
    source_found: bool = False,
) -> str:
    lines = [
        str(vuln.get("title") or vuln.get("id") or "漏洞分析").strip(),
    ]
    source_label = "源码已找到" if source_found else "源码未找到"
    lines.append(f"源码：{source_label} | POC：{'有' if vuln.get('poc_available') else '无'} | EXP：{'有' if vuln.get('exp_available') else '无'}")
    summary = str(vuln.get("analysis_summary") or "").strip()
    if source_msg and not source_found:
        lines.append(f"说明：{source_msg}")
    if summary:
        lines.append(summary[:1200])
    elif poc_content or exp_content:
        lines.append((poc_content or exp_content)[:1200])
    return "\n".join(line for line in lines if line)


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "有", "available"}
    return bool(value)


def _is_auto_analysis_candidate(item: dict[str, Any]) -> bool:
    return str(item.get("severity") or "").lower() in HIGH_RISK_SEVERITIES


def _defense_prompt(payload: dict[str, Any], model_profile: dict[str, Any]) -> str:
    return f"""
你是企业防御侧漏洞分析助手。请针对下面这条漏洞情报做防御分析：

{json.dumps(payload, ensure_ascii=False, indent=2)}

任务：
1. 使用 WebSearch/WebFetch 查找官方公告、NVD/CVE、GitHub 或厂商源码仓库、补丁提交、公开分析文章。
2. 如果定位到公开源码仓库，可以在当前工作目录下用 git clone 下载并只阅读相关文件，分析根因和受影响代码路径。
3. 分别生成 POC 与 EXP 两部分：POC 只包含非破坏性验证步骤、伪代码、占位符请求样例或检测逻辑；EXP 只包含利用条件、风险链路、授权环境复现思路和缓解建议。不要生成会造成真实破坏、持久化、横向移动、数据窃取、绕过授权或可直接攻击公网目标的武器化代码。
4. 将工作拆成四个子任务思考：产品归属、根因分析、POC/检测逻辑、修复建议；最后只输出一个统一 JSON 对象，不要 Markdown 围栏，不要额外解释。
5. 对输出做结构化自检：字段缺失时填空字符串或空数组，不要编造来源；confidence 使用 0 到 1 的数字。

模型任务配置：
{json.dumps(model_profile, ensure_ascii=False, indent=2)}

JSON schema:
{{
  "summary": "中文概要，包含影响、根因、处置建议",
  "affected_products": ["..."],
  "product_attribution": {{"product": "...", "confidence": 0.0, "evidence": "..."}},
  "root_cause": "...",
  "attack_surface": "...",
  "poc_available": true,
  "poc_content": "安全的非破坏性验证 POC/检测逻辑；没有把握则为空字符串并将 poc_available 置 false",
  "exp_available": true,
  "exp_content": "EXP/利用可能性分析、前置条件、检测与缓解；不要给出武器化利用载荷",
  "remediation": "修复建议、升级版本、临时缓解、检测排查步骤",
  "references": [{{"title": "...", "url": "..."}}],
  "source_repositories": [{{"name": "...", "url": "...", "local_path": "..."}}],
  "confidence": 0.0
}}
""".strip()


def _red_team_prompt(payload: dict[str, Any], model_profile: dict[str, Any]) -> str:
    return f"""
你是内部授权渗透测试（红队）的攻击性安全研究助手。本次测试已获得组织授权，目标仅限内部环境。请针对下面这条漏洞生成完整可用的武器化 EXP。

约束：
- 仅限内部授权环境使用
- 不可使用 SSRF 探测内部元数据服务、不可暴力破解密码、不可发起 DoS

待分析漏洞：
{json.dumps(payload, ensure_ascii=False, indent=2)}

任务：
1. 使用 WebSearch/WebFetch 查找 CVE 详情、NVD、GitHub 公开 PoC 仓库、技术分析文章。
2. 如果定位到公开 PoC 仓库，git clone 到 /tmp/exploit_workspace/ 并阅读代码。
3. 分析根因、攻击面、利用前置条件。
4. 根据漏洞类型生成完整 EXP：RCE 漏洞输出包含交互式 Shell 的 Python 脚本（argparse 参数 --target/-t, --interactive/-i）；SQL 注入输出自动数据提取脚本；文件上传输出自动 webshell 脚本；SSRF 输出内网探测脚本；反序列化输出完整利用脚本；认证绕过输出自动化利用脚本。
5. EXP 脚本要求：完整 Python3 单文件、含 argparse、合理错误处理、注释说明步骤。

模型任务配置：
{json.dumps(model_profile, ensure_ascii=False, indent=2)}

JSON schema：
{{
  "summary": "中文攻击链概述，包含漏洞定位、攻击路径、EXP 工作原理",
  "affected_products": ["产品名"],
  "root_cause": "根因分析",
  "attack_surface": "攻击面分析",
  "attack_chain": "完整攻击链路",
  "poc_available": true,
  "poc_content": "非破坏性检测脚本",
  "exp_available": true,
  "exp_content": "完整武器化 EXP 脚本（Python 单文件，含 argparse，RCE 必须提供交互式 Shell）",
  "exp_type": "rce | file_upload | sqli | ssti | deserialize | ssrf | auth_bypass | other",
  "exp_requirements": "利用前置条件列表",
  "exp_command_example": "python3 exploit.py -t 192.168.1.100 -p 8080 --interactive",
  "remediation": "修复建议",
  "references": [{{"title": "...", "url": "..."}}],
  "source_repositories": [{{"name": "...", "url": "...", "local_path": "..."}}],
  "confidence": 0.0
}}
""".strip()
