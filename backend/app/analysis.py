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
from .claude_code import claude_code_subprocess_env, ensure_claude_code, resolve_claude_code_command
from .config import settings
from .deepseek import get_deepseek_api_key
from .source_archive import register_analysis_source_artifact


logger = logging.getLogger(__name__)

HIGH_RISK_SEVERITIES = {"high", "critical"}
MAX_ANALYSIS_WORKERS = 10
SOURCE_PACKAGE_SUFFIXES = (".whl", ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
SOURCE_MARKER_FILES = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "package.json",
    "pom.xml",
    "go.mod",
    "Cargo.toml",
    "composer.json",
)
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
    flash_model = str(profile.get("flash_model") or settings.anthropic_default_haiku_model or selected_model)
    deep_model = selected_model
    light_model = flash_model or selected_model
    profile.update(
        {
            "analysis_model_choice": model_selection["choice"],
            "analysis_model_label": model_selection["label"],
            "selected_analysis_model": selected_model,
            "task_model_policy": "flash_for_light_tasks",
            "light_task_model": light_model,
            "deep_task_model": deep_model,
            "product_attribution_model": light_model,
            "source_triage_model": light_model,
            "root_cause_model": deep_model,
            "poc_generation_model": deep_model,
            "fix_advice_model": deep_model,
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
    if _is_red_team_profile(model_profile):
        return "红队增强"
    return "标准分析"


def _is_red_team_profile(model_profile: dict[str, Any]) -> bool:
    return bool(model_profile.get("red_team_mode")) or str(model_profile.get("analysis_mode") or "") == "red_team_enhanced"


def _analysis_allows_source_fetch(model_profile: dict[str, Any]) -> bool:
    return not _is_red_team_profile(model_profile)


def _analysis_allowed_tools(model_profile: dict[str, Any]) -> str:
    allowed = str(settings.vulnerability_analysis_allowed_tools or "").strip()
    if _analysis_allows_source_fetch(model_profile):
        return allowed
    blocked_prefixes = (
        "Bash(git clone:",
        "Bash(gh repo clone:",
        "Bash(npm pack:",
        "Bash(python -m pip download:",
        "Bash(python3 -m pip download:",
        "Bash(curl:",
        "Bash(wget:",
        "Bash(tar:",
        "Bash(unzip:",
        "Bash(mkdir:",
    )
    filtered = [
        item.strip()
        for item in allowed.split(",")
        if item.strip() and not item.strip().startswith(blocked_prefixes)
    ]
    return ",".join(filtered)


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
        command_path = resolve_claude_code_command() or str(status.get("resolved_path") or "")
        if not command_path:
            raise AnalysisFailure("分析失败", status.get("error") or "Claude Code CLI is not available")
        command_path = str(Path(command_path).expanduser())
        if not Path(command_path).is_file():
            raise AnalysisFailure(
                "分析失败",
                f"Claude Code CLI 路径不存在：{command_path}",
            )
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
        existing_source_context = await asyncio.to_thread(_existing_source_context, vuln)
        _analysis_event(
            vulnerability_id,
            run_id,
            "source",
            _existing_source_context_message(existing_source_context),
            existing_source_context,
        )
        prompt = _analysis_prompt(vuln, model_profile, existing_source_context)
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
        allowed_tools = _analysis_allowed_tools(model_profile)
        command = [
            command_path,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--allowedTools",
            allowed_tools,
            "--permission-mode",
            "acceptEdits",
        ]
        _analysis_event(
            vulnerability_id,
            run_id,
            "stage",
            (
                "启动 Claude Code CLI，开始检索公告、源码仓库、补丁与公开分析。"
                if _analysis_allows_source_fetch(model_profile)
                else "启动 Claude Code CLI，开始红队增强检索；本轮仅复用已有源码证据，不拉取源码。"
            ),
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
                f"允许工具 {allowed_tools}。"
            ),
            {
                "model": model,
                "model_profile": model_profile,
                "base_url": subprocess_env.get("ANTHROPIC_BASE_URL", ""),
                "allowed_tools": allowed_tools,
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
        _analysis_event(
            vulnerability_id,
            run_id,
            "stage",
            (
                f"Claude Code 进程已启动：pid={process.pid}，超时 {settings.vulnerability_analysis_timeout_seconds}s；源码进度监控已启用。"
                if _analysis_allows_source_fetch(model_profile)
                else f"Claude Code 进程已启动：pid={process.pid}，超时 {settings.vulnerability_analysis_timeout_seconds}s；红队增强不启用源码拉取监控。"
            ),
            {
                "pid": process.pid,
                "timeout_seconds": settings.vulnerability_analysis_timeout_seconds,
                "workspace": str(workspace),
                "source_monitor": _analysis_allows_source_fetch(model_profile),
            },
        )
        source_monitor_task = (
            asyncio.create_task(_monitor_analysis_workspace_sources(vulnerability_id, run_id, workspace))
            if _analysis_allows_source_fetch(model_profile)
            else None
        )
        try:
            returncode, stdout_text, stderr_text = await _collect_process_output(
                process,
                vulnerability_id,
                run_id,
                workspace,
            )
        finally:
            if source_monitor_task is not None:
                source_monitor_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await source_monitor_task
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
        stdout_failure = _claude_result_failure(stdout_text, stderr_text)
        if stdout_failure:
            recovered = _workspace_analysis_result(workspace)
            if recovered:
                _analysis_event(
                    vulnerability_id,
                    run_id,
                    "stage",
                    "Claude Code 输出标记为模型错误，但工作目录中已发现可恢复 JSON 结果，优先回填数据库。",
                    {
                        "returncode": returncode,
                        "result_file": recovered.get("_workspace_result_file", ""),
                        "error": stdout_failure.detail[:1000],
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
                    recovered_from="model_error_workspace_result",
                )
                return
            raise stdout_failure
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
    if not source_repositories:
        existing_source_context = _existing_source_context(vuln)
        source_repositories = _source_repositories_from_existing_context(existing_source_context)
        if source_repositories:
            parsed["source_repositories"] = source_repositories
            parsed["source_found"] = True
            parsed["source_found_label"] = "源码已找到"
    source_artifacts = _source_artifacts_metadata(
        vulnerability_id,
        run_id,
        workspace,
        source_repositories,
        archive_local_sources=_analysis_allows_source_fetch(model_profile),
    )
    source_artifact = source_artifacts[0] if source_artifacts else _empty_source_artifact()
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
    assessment = parsed.get("source_version_assessment") if isinstance(parsed.get("source_version_assessment"), dict) else {}
    if assessment:
        _analysis_event(
            vulnerability_id,
            run_id,
            "source",
            (
                "源码版本判断："
                f"本地 {assessment.get('local_source_version') or '-'}；"
                f"最新 {assessment.get('latest_source_version') or '-'}；"
                f"匹配结论 {assessment.get('match') or 'unknown'}。"
            ),
            assessment,
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
        "source_artifacts": source_artifacts,
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
        archived_sources = []
        seen_archive_paths: set[str] = set()
        if _analysis_allows_source_fetch(model_profile):
            for artifact in source_artifacts or [source_artifact]:
                archive_path = str(artifact.get("archive_path") or "")
                if archive_path in seen_archive_paths:
                    continue
                seen_archive_paths.add(archive_path)
                archived_source = register_analysis_source_artifact(updated or vuln, artifact)
                if archived_source:
                    archived_sources.append(archived_source)
        if archived_sources:
            _analysis_event(
                vulnerability_id,
                run_id,
                "source",
                f"{len(archived_sources)} 个源码版本压缩包已加入源码库，后台会异步上传 MinIO 并等待产品确认。",
                {"source_archive_ids": [item.get("id") for item in archived_sources]},
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


async def _monitor_analysis_workspace_sources(vulnerability_id: int, run_id: str, workspace: Path) -> None:
    start_ts = datetime.now(timezone.utc).timestamp()
    last_seen_mtime: dict[str, float] = {}
    logged: set[str] = set()
    _analysis_event(
        vulnerability_id,
        run_id,
        "source",
        "源码进度监控已启动：将实时记录新下载的源码包、git 仓库和可识别源码目录。",
        {"workspace": str(workspace), "poll_seconds": 3},
    )
    while True:
        try:
            candidates = await asyncio.to_thread(_discover_workspace_source_candidates, workspace)
            for candidate in candidates:
                key = str(candidate.get("key") or "")
                if not key:
                    continue
                mtime = float(candidate.get("mtime") or 0)
                previous_mtime = last_seen_mtime.get(key)
                last_seen_mtime[key] = max(mtime, previous_mtime or 0)
                if key in logged:
                    continue
                if previous_mtime is None and mtime < start_ts - 2:
                    continue
                if previous_mtime is not None and mtime < start_ts - 2:
                    continue
                logged.add(key)
                _analysis_event(
                    vulnerability_id,
                    run_id,
                    "source",
                    _source_progress_message(candidate),
                    candidate,
                )
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(
                        db.update_vulnerability_analysis_source_progress,
                        vulnerability_id,
                        run_id=run_id,
                        source_title=str(candidate.get("title") or ""),
                        source_url=str(candidate.get("url") or ""),
                        source_local_path=str(candidate.get("local_path") or ""),
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("analysis source monitor failed for %s", vulnerability_id, exc_info=True)
            _analysis_event(
                vulnerability_id,
                run_id,
                "source",
                f"源码进度监控暂时无法读取工作目录：{str(exc)[:300]}",
                {"workspace": str(workspace)},
            )
        await asyncio.sleep(3)


def _discover_workspace_source_candidates(workspace: Path) -> list[dict[str, Any]]:
    if not workspace.exists():
        return []
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    roots = _workspace_scan_roots(workspace)
    for path in roots:
        candidate = _source_candidate_from_path(path, workspace)
        if not candidate:
            continue
        key = str(candidate.get("key") or "")
        if key in seen:
            continue
        seen.add(key)
        candidates.append(candidate)
    candidates.sort(key=lambda item: float(item.get("mtime") or 0), reverse=True)
    return candidates


def _workspace_scan_roots(workspace: Path) -> list[Path]:
    roots: list[Path] = []
    skip_names = {"_source_archives", "__pycache__"}
    for child in workspace.iterdir():
        name = child.name
        if name in skip_names or name.startswith("model_") or name == "analysis_prompt.txt":
            continue
        roots.append(child)
        if child.is_dir() and not (child / ".git").exists():
            with contextlib.suppress(OSError):
                for nested in child.iterdir():
                    if nested.name in skip_names or nested.name.startswith("."):
                        continue
                    roots.append(nested)
    return roots


def _source_candidate_from_path(path: Path, workspace: Path) -> dict[str, Any] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    if _is_public_exploit_artifact_path(path):
        return None
    role = _source_role_from_path(path)
    if path.is_file():
        if not _is_source_package(path):
            return None
        version = _version_from_package_filename(path.name)
        return _source_candidate_payload(
            path,
            workspace,
            kind="source_package",
            role=role,
            title=f"{path.name}（源码包）",
            mtime=stat.st_mtime,
            source_version=version,
            details={"size_bytes": stat.st_size, "size": _format_bytes(stat.st_size)},
        )
    if not path.is_dir():
        return None
    is_git_repo = (path / ".git").exists()
    marker_files = [name for name in SOURCE_MARKER_FILES if (path / name).is_file()]
    package_files = _direct_source_packages(path)
    if not is_git_repo and not marker_files:
        return None
    kind = "git_repository" if is_git_repo else "source_directory"
    version = _source_version_from_path(path) or _version_from_package_filename(package_files[0].name if package_files else "")
    details: dict[str, Any] = {
        "marker_files": marker_files[:8],
        "package_files": [item.name for item in package_files[:8]],
        "entry_count": _safe_entry_count(path),
    }
    if is_git_repo:
        details.update(_git_repository_metadata(path))
    if package_files:
        details["package_size"] = _format_bytes(sum(_safe_size(item) for item in package_files))
    title = f"{path.name}（{'git 仓库' if is_git_repo else '源码目录'}）"
    return _source_candidate_payload(
        path,
        workspace,
        kind=kind,
        role=role,
        title=title,
        mtime=stat.st_mtime,
        source_version=version,
        details=details,
    )


def _source_candidate_payload(
    path: Path,
    workspace: Path,
    *,
    kind: str,
    role: str,
    title: str,
    mtime: float,
    source_version: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved = path.resolve()
    try:
        display_path = str(resolved.relative_to(workspace.resolve()))
    except ValueError:
        display_path = str(resolved)
    payload = {
        "key": str(resolved),
        "kind": kind,
        "version_role": role,
        "title": title,
        "local_path": str(resolved),
        "display_path": display_path,
        "source_version": source_version,
        "mtime": mtime,
        "mtime_iso": datetime.fromtimestamp(mtime, timezone.utc).isoformat(timespec="seconds"),
    }
    payload.update(details or {})
    url = str(payload.get("remote_url") or "")
    if url:
        payload["url"] = url
    return payload


def _source_progress_message(candidate: dict[str, Any]) -> str:
    role = str(candidate.get("version_role") or "unknown")
    role_label = {
        "affected": "受影响版本",
        "latest": "最新版本",
        "uploaded": "上传源码",
        "unknown": "未知版本",
    }.get(role, "未知版本")
    kind = str(candidate.get("kind") or "")
    kind_label = {
        "git_repository": "git 源码仓库",
        "source_directory": "源码目录",
        "source_package": "源码包",
    }.get(kind, "源码")
    details = []
    if candidate.get("source_version"):
        details.append(f"版本 {candidate.get('source_version')}")
    if candidate.get("remote_url"):
        details.append(f"远端 {candidate.get('remote_url')}")
    if candidate.get("size"):
        details.append(f"大小 {candidate.get('size')}")
    if candidate.get("package_size"):
        details.append(f"包大小 {candidate.get('package_size')}")
    if candidate.get("entry_count") is not None:
        details.append(f"顶层条目 {candidate.get('entry_count')}")
    suffix = "；" + "；".join(details) if details else ""
    return (
        f"源码发现：已识别{role_label} {kind_label} `{candidate.get('display_path')}`，"
        f"源码状态已更新为“源码已找到”{suffix}。"
    )


def _is_public_exploit_artifact_path(path: Path) -> bool:
    name = path.name.lower()
    exploit_markers = [
        "poc",
        "exp",
        "exploit",
        "metasploit",
        "nuclei",
        "packetstorm",
        "proof-of-concept",
    ]
    return any(
        name == marker
        or name.startswith(f"{marker}_")
        or name.startswith(f"{marker}-")
        or f"_{marker}" in name
        or f"-{marker}" in name
        for marker in exploit_markers
    )


def _source_role_from_path(path: Path) -> str:
    text = " ".join(part.lower() for part in path.parts[-3:])
    if any(marker in text for marker in ["affected", "vulnerable", "vuln", "old", "fixed_before"]):
        return "affected"
    if any(marker in text for marker in ["latest", "current", "head", "main", "master", "fixed"]):
        return "latest"
    if "upload" in text or "manual" in text:
        return "uploaded"
    return "unknown"


def _is_source_package(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in SOURCE_PACKAGE_SUFFIXES)


def _direct_source_packages(path: Path) -> list[Path]:
    packages: list[Path] = []
    with contextlib.suppress(OSError):
        for child in path.iterdir():
            if child.is_file() and _is_source_package(child):
                packages.append(child)
    return packages


def _version_from_package_filename(filename: str) -> str:
    match = re.search(r"-([0-9][A-Za-z0-9_.!+-]*)\.(?:whl|zip|tar|tgz)", filename or "", flags=re.I)
    return match.group(1).replace("_", ".") if match else ""


def _source_version_from_path(path: Path) -> str:
    package_json = path / "package.json"
    if package_json.is_file():
        with contextlib.suppress(Exception):
            payload = json.loads(package_json.read_text(encoding="utf-8")[:200000])
            version = str(payload.get("version") or "").strip()
            if version:
                return version[:120]
    pyproject = path / "pyproject.toml"
    if pyproject.is_file():
        with contextlib.suppress(OSError):
            text = pyproject.read_text(encoding="utf-8")[:200000]
            match = re.search(r"(?m)^\s*version\s*=\s*[\"']([^\"']+)[\"']", text)
            if match:
                return match.group(1).strip()[:120]
    return ""


def _git_repository_metadata(path: Path) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    git_dir = path / ".git"
    head = ""
    with contextlib.suppress(OSError):
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        metadata["git_ref"] = ref
        with contextlib.suppress(OSError):
            commit = (git_dir / ref).read_text(encoding="utf-8").strip()
            if commit:
                metadata["git_commit"] = commit[:12]
    elif head:
        metadata["git_commit"] = head[:12]
    with contextlib.suppress(OSError):
        config = (git_dir / "config").read_text(encoding="utf-8")[:200000]
        match = re.search(r'url\s*=\s*(.+)', config)
        if match:
            metadata["remote_url"] = match.group(1).strip()
    return metadata


def _safe_entry_count(path: Path) -> int:
    with contextlib.suppress(OSError):
        return sum(1 for _ in path.iterdir())
    return 0


def _safe_size(path: Path) -> int:
    with contextlib.suppress(OSError):
        return int(path.stat().st_size)
    return 0


def _format_bytes(size: int) -> str:
    value = float(size or 0)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} GB"


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
                f"api_error={payload.get('api_error_status')}" if payload.get("api_error_status") else "",
                "is_error=true" if payload.get("is_error") else "",
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
                    "api_error_status": payload.get("api_error_status"),
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


def _claude_result_failure(stdout_text: str, stderr_text: str = "") -> AnalysisFailure | None:
    for payload in reversed(_claude_result_payloads(stdout_text)):
        if not isinstance(payload, dict):
            continue
        if not _claude_payload_is_error(payload):
            continue
        detail = _claude_payload_error_detail(payload, stderr_text)
        return _classify_analysis_failure(detail)
    return None


def _claude_result_payloads(stdout_text: str) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    outer = _json_from_text(stdout_text)
    if isinstance(outer, dict):
        payloads.append(outer)
    elif isinstance(outer, list):
        payloads.extend(item for item in outer if isinstance(item, dict))
    for line in (stdout_text or "").splitlines():
        clean = line.strip()
        if not clean.startswith("{"):
            continue
        try:
            payload = json.loads(clean)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload not in payloads:
            payloads.append(payload)
    return payloads


def _claude_payload_is_error(payload: dict[str, Any]) -> bool:
    if payload.get("is_error") is True:
        return True
    if payload.get("api_error_status"):
        return True
    error = payload.get("error")
    if isinstance(error, dict) and (error.get("type") or error.get("message")):
        return True
    return str(payload.get("subtype") or "").lower() == "error"


def _claude_payload_error_detail(payload: dict[str, Any], stderr_text: str = "") -> str:
    status = str(payload.get("api_error_status") or "").strip()
    error = payload.get("error")
    result_value = payload.get("result") or payload.get("message") or payload.get("content") or stderr_text or ""
    if isinstance(error, dict) and not result_value:
        result_value = error.get("message") or error.get("type") or ""
    result_text = str(result_value)
    message = _redact_model_error_message(_extract_model_error_message(result_text))
    source_match = re.search(r"\[([^\]]+)\]\s+status\s*=\s*\d+", message or result_text, flags=re.I)
    source = source_match.group(1) if source_match else ""
    status_label = f" {status}" if status else ""
    source_label = f"（{source}）" if source else ""
    if status == "402":
        prefix = f"模型源{source_label}返回 402：余额不足或支付受限"
    else:
        prefix = f"模型源{source_label}返回错误{status_label}".strip()
    return f"{prefix}。{message or result_text or stderr_text or '未知模型错误'}"


def _extract_model_error_message(text: str) -> str:
    clean = (text or "").strip()
    if not clean:
        return ""
    payload = _json_from_text(clean)
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str) and message.strip():
                return message.strip()
        for key in ["message", "result", "content", "detail"]:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return clean


def _redact_model_error_message(message: str) -> str:
    redacted = re.sub(r"(ProjectId:\s*)[A-Za-z0-9_-]+", r"\1<redacted>", message or "", flags=re.I)
    redacted = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1<redacted>", redacted, flags=re.I)
    redacted = re.sub(r"\bsk-[A-Za-z0-9._-]{12,}\b", "sk-<redacted>", redacted)
    return redacted.strip()


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
        "balance not enough",
        "payment required",
        "rate limit",
        "non-sse",
        "upstream returned",
        "api_error",
        "retcode",
        "402",
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


def _analysis_prompt(
    vuln: dict[str, Any],
    model_profile: dict[str, Any] | None = None,
    existing_source_context: dict[str, Any] | None = None,
) -> str:
    model_profile = model_profile or db.get_model_settings()
    existing_source_context = existing_source_context or _existing_source_context(vuln)
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
        "existing_local_source": existing_source_context,
        "previous_analysis": _previous_analysis_context(vuln),
        "raw": vuln.get("raw"),
    }
    red_team_mode = bool(model_profile.get("red_team_mode", True))
    return _two_stage_prompt(payload, model_profile, red_team_mode)


def _previous_analysis_context(vuln: dict[str, Any]) -> dict[str, Any]:
    raw = vuln.get("analysis_raw")
    if isinstance(raw, str):
        with contextlib.suppress(json.JSONDecodeError):
            raw = json.loads(raw)
    raw = raw if isinstance(raw, dict) else {}
    claude_output = raw.get("claude_output") if isinstance(raw.get("claude_output"), dict) else {}
    selected_output = {
        key: claude_output.get(key)
        for key in [
            "summary",
            "affected_products",
            "product_attribution",
            "root_cause",
            "attack_surface",
            "source_analysis",
            "source_version_assessment",
            "public_poc_exp",
            "poc_validation",
            "exp_validation",
            "enhanced_exp_summary",
            "exp_type",
            "remediation",
            "references",
            "confidence",
        ]
        if claude_output.get(key) not in (None, "", [], {})
    }
    analysis_sources = vuln.get("analysis_sources")
    if isinstance(analysis_sources, str):
        with contextlib.suppress(json.JSONDecodeError):
            analysis_sources = json.loads(analysis_sources)
    if not isinstance(analysis_sources, list):
        analysis_sources = []
    context = {
        "available": bool(vuln.get("analysis_summary") or selected_output),
        "status": str(vuln.get("analysis_status") or ""),
        "trigger": str(vuln.get("analysis_trigger") or ""),
        "model": str(vuln.get("analysis_model") or ""),
        "summary": _trim_text(vuln.get("analysis_summary"), 6000),
        "poc_available": bool(vuln.get("poc_available")),
        "poc_url": str(vuln.get("poc_url") or ""),
        "poc_content": _trim_text(vuln.get("poc_content"), 5000),
        "exp_available": bool(vuln.get("exp_available")),
        "exp_url": str(vuln.get("exp_url") or ""),
        "exp_content": _trim_text(vuln.get("exp_content"), 7000),
        "source_found": bool(vuln.get("analysis_source_found")),
        "source_title": str(vuln.get("analysis_source_title") or ""),
        "source_url": str(vuln.get("analysis_source_url") or ""),
        "source_local_path": str(vuln.get("analysis_source_local_path") or ""),
        "source_archive_path": str(vuln.get("analysis_source_archive_path") or ""),
        "sources": analysis_sources[:20],
        "structured": selected_output,
    }
    return context


def _trim_text(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"


def _existing_source_context(vuln: dict[str, Any]) -> dict[str, Any]:
    source_found = bool(vuln.get("analysis_source_found"))
    local_path = str(vuln.get("analysis_source_local_path") or "").strip()
    archive_path = str(vuln.get("analysis_source_archive_path") or "").strip()
    raw = vuln.get("analysis_raw")
    if isinstance(raw, str):
        with contextlib.suppress(json.JSONDecodeError):
            raw = json.loads(raw)
    source_artifacts = raw.get("source_artifacts") if isinstance(raw, dict) else []
    if not isinstance(source_artifacts, list):
        source_artifacts = []
    artifacts: list[dict[str, Any]] = []
    if local_path or archive_path:
        artifacts.append(
            {
                "title": str(vuln.get("analysis_source_title") or "").strip(),
                "url": str(vuln.get("analysis_source_url") or "").strip(),
                "local_path": local_path,
                "archive_path": archive_path,
                "source_version": "",
                "version_role": "unknown",
                "evidence": "历史漏洞分析保留源码",
            }
        )
    for artifact in source_artifacts:
        if isinstance(artifact, dict):
            artifacts.append(artifact)
    source_archive_artifacts = _matching_source_archive_artifacts(vuln)
    workspace_artifacts = _workspace_source_artifacts(vuln)
    seen_paths = {
        str(item.get("local_path") or item.get("archive_path") or "").strip()
        for item in artifacts
        if isinstance(item, dict)
    }
    for artifact in [*source_archive_artifacts, *workspace_artifacts]:
        key = str(artifact.get("local_path") or artifact.get("archive_path") or "").strip()
        if key and key not in seen_paths:
            seen_paths.add(key)
            artifacts.append(artifact)
    if source_archive_artifacts or workspace_artifacts:
        primary_artifact = (source_archive_artifacts or workspace_artifacts)[0]
        source_found = True
        if not local_path:
            local_path = str(primary_artifact.get("local_path") or "")
        if not archive_path:
            archive_path = str(primary_artifact.get("archive_path") or "")
    archive_roles: dict[str, int] = {}
    all_source_artifacts = [*source_archive_artifacts, *workspace_artifacts]
    for artifact in all_source_artifacts:
        role = str(artifact.get("version_role") or "unknown")
        archive_roles[role] = archive_roles.get(role, 0) + 1
    return {
        "source_found": source_found,
        "title": str(vuln.get("analysis_source_title") or "").strip(),
        "url": str(vuln.get("analysis_source_url") or "").strip(),
        "local_path": local_path,
        "archive_path": archive_path,
        "artifacts": artifacts[:12],
        "source_archive_matches": source_archive_artifacts[:12],
        "source_archive_match_count": len(source_archive_artifacts),
        "workspace_source_matches": workspace_artifacts[:12],
        "workspace_source_match_count": len(workspace_artifacts),
        "source_archive_roles": archive_roles,
        "has_latest_source": any(str(item.get("version_role") or "") == "latest" for item in all_source_artifacts),
        "has_affected_source": any(str(item.get("version_role") or "") in {"affected", "uploaded", "unknown"} for item in all_source_artifacts),
        "retained_until": str(vuln.get("analysis_source_retained_until") or "").strip(),
        "cleaned_at": str(vuln.get("analysis_source_cleaned_at") or "").strip(),
        "local_path_exists": bool(local_path and Path(local_path).exists()),
        "archive_exists": bool(archive_path and Path(archive_path).exists()),
    }


def _existing_source_context_message(context: dict[str, Any]) -> str:
    count = int(context.get("source_archive_match_count") or 0)
    workspace_count = int(context.get("workspace_source_match_count") or 0)
    roles = context.get("source_archive_roles") if isinstance(context.get("source_archive_roles"), dict) else {}
    role_text = "，".join(
        f"{label} {roles.get(role)}"
        for role, label in [("affected", "受影响"), ("latest", "最新"), ("uploaded", "上传"), ("unknown", "未知")]
        if int(roles.get(role) or 0) > 0
    )
    if count:
        return (
            f"源码库匹配：找到 {count} 个可复用源码"
            f"{'（' + role_text + '）' if role_text else ''}。"
            "本轮分析会优先读取本地源码库；已匹配版本不会再现网重复拉取。"
        )
    if workspace_count:
        return (
            f"源码库匹配：发现历史分析工作目录中 {workspace_count} 个可复用源码"
            f"{'（' + role_text + '）' if role_text else ''}。"
            "本轮会优先复用这些源码证据。"
        )
    if context.get("source_found"):
        return "源码库匹配：发现历史分析保留的本地源码，本轮会优先复用该路径。"
    return "源码库匹配：未找到可复用源码；若需要最新版本，请先在源码库点击“拉取最新版本”。"


def _workspace_source_artifacts(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    workspace = _workspace_for_vulnerability(vuln)
    if not workspace.exists():
        return []
    artifacts: list[dict[str, Any]] = []
    with contextlib.suppress(Exception):
        candidates = _discover_workspace_source_candidates(workspace)
        labels = {_source_match_norm(label) for label in _source_lookup_labels(vuln) if _source_match_norm(label)}
        product_candidates = [item for item in candidates if _workspace_source_candidate_matches_labels(item, labels)]
        if product_candidates:
            candidates = product_candidates
        candidates.sort(
            key=lambda item: (
                _workspace_source_candidate_score(item, labels),
                float(item.get("mtime") or 0),
            ),
            reverse=True,
        )
        for candidate in candidates[:12]:
            local_path = str(candidate.get("local_path") or "").strip()
            if not local_path:
                continue
            artifacts.append(
                {
                    "title": str(candidate.get("title") or Path(local_path).name or "历史源码").strip(),
                    "url": str(candidate.get("url") or candidate.get("remote_url") or "").strip(),
                    "local_path": local_path,
                    "archive_path": "",
                    "source_version": str(candidate.get("source_version") or "").strip()[:120],
                    "version": str(candidate.get("source_version") or "").strip()[:120],
                    "version_role": _normalize_source_version_role(candidate.get("version_role")),
                    "evidence": "历史分析工作目录中已存在的源码证据",
                    "status": "workspace",
                }
            )
    return artifacts


def _source_repositories_from_existing_context(context: dict[str, Any]) -> list[dict[str, Any]]:
    repositories: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for key in ["source_archive_matches", "workspace_source_matches"]:
        items = context.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            local_path = str(item.get("local_path") or "").strip()
            archive_path = str(item.get("archive_path") or "").strip()
            marker = (local_path, archive_path)
            if not any(marker) or marker in seen:
                continue
            seen.add(marker)
            repositories.append(
                {
                    "name": str(item.get("title") or item.get("name") or Path(local_path or archive_path).name or "已有源码").strip(),
                    "url": str(item.get("url") or "").strip(),
                    "local_path": local_path,
                    "archive_path": archive_path,
                    "version": str(item.get("version") or item.get("source_version") or "").strip(),
                    "version_role": _normalize_source_version_role(item.get("version_role")),
                    "evidence": str(item.get("evidence") or "复用已有源码证据").strip(),
                }
            )
            if len(repositories) >= 12:
                return repositories
    return repositories


def _workspace_source_candidate_score(candidate: dict[str, Any], labels: set[str]) -> int:
    role = _normalize_source_version_role(candidate.get("version_role"))
    kind = str(candidate.get("kind") or "")
    score = 0
    if _workspace_source_candidate_matches_labels(candidate, labels):
        score += 120
    elif kind == "source_package":
        score -= 80
    if role == "latest":
        score += 40
    elif role == "affected":
        score += 30
    elif role == "uploaded":
        score += 20
    if kind == "git_repository":
        score += 20
    elif kind == "source_directory":
        score += 12
    elif kind == "source_package":
        score += 8
    if candidate.get("source_version"):
        score += 5
    return score


def _workspace_source_candidate_matches_labels(candidate: dict[str, Any], labels: set[str]) -> bool:
    if not labels:
        return False
    local_path = str(candidate.get("local_path") or "")
    name_norm = _source_match_norm(Path(local_path).name)
    title_norm = _source_match_norm(candidate.get("title"))
    return any(label and (label in name_norm or label in title_norm) for label in labels)


def _matching_source_archive_artifacts(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    labels = _source_lookup_labels(vuln)
    if not labels:
        return []
    rows: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for label in labels[:8]:
        try:
            payload = db.list_source_archives(query=label, limit=20, offset=0)
        except Exception:
            continue
        for row in payload.get("data", []):
            archive_id = int(row.get("id") or 0)
            if archive_id and archive_id not in seen_ids:
                seen_ids.add(archive_id)
                rows.append(row)
    normalized_labels = {_source_match_norm(label) for label in labels if _source_match_norm(label)}
    artifacts: list[dict[str, Any]] = []
    for row in rows:
        status = str(row.get("status") or "")
        if status in {"failed", "canceled", "fetching"}:
            continue
        path = _source_archive_path_for_analysis(row)
        if not path:
            continue
        names = [
            row.get("product_name"),
            row.get("suggested_product_name"),
            row.get("product_hint"),
            row.get("filename"),
        ]
        archive_norms = {_source_match_norm(str(value or "")) for value in names if str(value or "").strip()}
        if normalized_labels and archive_norms and not any(
            a == b or (a and b and (a in b or b in a)) for a in archive_norms for b in normalized_labels
        ):
            continue
        artifacts.append(_source_archive_artifact_from_row(row, path))
    role_order = {"affected": 0, "uploaded": 1, "latest": 2, "unknown": 3}
    artifacts.sort(
        key=lambda item: (
            role_order.get(str(item.get("version_role") or "unknown"), 9),
            0 if item.get("product_confirmed") else 1,
            str(item.get("title") or ""),
        )
    )
    return artifacts[:12]


def _source_archive_path_for_analysis(row: dict[str, Any]) -> str:
    for key in ["extracted_path", "local_path"]:
        raw = str(row.get(key) or "").strip()
        if not raw:
            continue
        path = Path(raw).expanduser()
        if path.exists():
            return str(path.resolve())
    return ""


def _source_archive_artifact_from_row(row: dict[str, Any], path: str) -> dict[str, Any]:
    local_path = str(row.get("local_path") or "").strip()
    archive_path = ""
    if local_path:
        with contextlib.suppress(OSError):
            local = Path(local_path).expanduser()
            if local.is_file():
                archive_path = str(local.resolve())
    role = _normalize_source_version_role(row.get("version_role"))
    product = str(row.get("product_name") or row.get("suggested_product_name") or row.get("product_hint") or "").strip()
    version = str(row.get("source_version") or "").strip()
    title_parts = ["源码库", product or str(row.get("filename") or "源码")]
    if version:
        title_parts.append(version)
    if role:
        title_parts.append(role)
    return {
        "source_archive_id": row.get("id"),
        "title": " / ".join(title_parts),
        "url": "",
        "local_path": path,
        "archive_path": archive_path,
        "source_version": version,
        "version": version,
        "version_role": role,
        "evidence": str(row.get("product_evidence") or "源码库中已存在匹配源码").strip()[:500],
        "product_name": product,
        "product_confirmed": bool(row.get("product_confirmed")),
        "status": row.get("status"),
    }


def _source_lookup_labels(vuln: dict[str, Any]) -> list[str]:
    labels: list[str] = []

    def add(value: Any) -> None:
        text = str(value or "").strip()
        if not text:
            return
        lower = text.lower()
        if lower in {"unknown", "n/a", "none", "security", "vulnerability"}:
            return
        labels.append(text)

    add(vuln.get("product"))
    title = str(vuln.get("title") or "")
    raw = vuln.get("raw")
    if isinstance(raw, dict):
        for key in ["product", "package", "vendorProject", "project", "repo", "repository"]:
            add(raw.get(key))
    analysis_raw = vuln.get("analysis_raw")
    if isinstance(analysis_raw, str):
        with contextlib.suppress(json.JSONDecodeError):
            analysis_raw = json.loads(analysis_raw)
    if isinstance(analysis_raw, dict):
        claude_output = analysis_raw.get("claude_output") if isinstance(analysis_raw.get("claude_output"), dict) else {}
        attribution = claude_output.get("product_attribution") if isinstance(claude_output.get("product_attribution"), dict) else {}
        add(attribution.get("product"))
        affected = claude_output.get("affected_products")
        if isinstance(affected, list):
            for item in affected[:6]:
                add(item)
    for token in re.findall(r"\b[A-Za-z][A-Za-z0-9_.@+/-]{2,}\b", title):
        if token.lower() in {"cve", "cvss", "poc", "exp", "rce", "sql", "xss", "ssrf", "csrf"}:
            continue
        if re.match(r"(?i)^cve-\d{4}-\d{4,}$", token):
            continue
        add(token)
    result: list[str] = []
    seen: set[str] = set()
    for label in labels:
        key = _source_match_norm(label)
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(label)
    return result[:12]


def _source_match_norm(value: str) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"cve-\d{4}-\d{4,}", " ", text, flags=re.I)
    text = re.sub(r"\b(?:critical|high|medium|low|vulnerability|security|advisory)\b", " ", text, flags=re.I)
    for token in ["漏洞", "安全", "存在", "高危", "严重"]:
        text = text.replace(token, " ")
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", text)[:180]


def _two_stage_prompt(payload: dict[str, Any], model_profile: dict[str, Any], red_team: bool) -> str:
    if red_team:
        return _red_team_enhancement_prompt(payload, model_profile)
    return _standard_vulnerability_analysis_prompt(payload, model_profile)


def _standard_vulnerability_analysis_prompt(payload: dict[str, Any], model_profile: dict[str, Any]) -> str:
    return f"""
你是企业防御侧漏洞分析助手。请严格按顺序完成下面这条漏洞的后端 LLM 深度分析。漏洞分析负责检索公告、公开 POC/EXP、源码仓库、补丁与受影响版本代码；如果源码库没有匹配源码，而根因或版本判断需要源码，请在当前工作目录下载必要的受影响版本源码或补丁相关源码，并把下载路径写入 `source_repositories.local_path`，便于系统归档到源码库。

{json.dumps(payload, ensure_ascii=False, indent=2)}

---
### 阶段一：公开 POC/EXP 现网检索与可用性判断
1. 使用 WebSearch/WebFetch 优先搜索：CVE ID、漏洞标题、产品名、版本号、`poc`、`exploit`、`exp`、`github`、`exploit-db`、`packet storm`、`nuclei`、`metasploit`。
2. 覆盖 GitHub、GitLab、Exploit-DB、Packet Storm、NVD、GitHub Advisory、厂商公告、安全研究博客。
3. 如果发现公开 POC/EXP 仓库或脚本，可以在当前工作目录使用 git clone、curl、npm pack、pip download 下载，只阅读必要文件。
4. 判断公开 POC/EXP 是否可用：必须说明证据、入口点、受影响版本、运行条件、是否只是占位/转载/误报。
5. 没有公开 POC/EXP 时，`poc_available`/`exp_available` 必须为 false，不要把“存在标记”当成可用代码。

### 阶段二：源码库优先、版本判断与源码辅助验证
1. 如果 `existing_local_source.source_found=true`，优先读取 `existing_local_source.local_path` 和 `existing_local_source.artifacts` 中的本地路径；如果展开目录已清理但 `archive_path` 存在，可以先解压到当前工作目录的临时目录再读取。不要在完成本地判断前搜索现网源码。
2. 如果 `existing_local_source.source_archive_matches` 中已有匹配源码，必须直接复用这些源码；同一产品、同一 `version_role` 或同一版本不得再次 git clone、npm pack 或 pip download。
3. 从漏洞告警、NVD/CVE、厂商公告和包元数据中提取受影响版本、修复版本、组件名；从本地源码的 package.json、pom.xml、setup.py、go.mod、CHANGELOG、tag/commit 信息中提取当前源码版本。
4. 明确输出“本地源码版本是否落在受影响范围内”：affected / fixed / unknown / mismatch。若缺少受影响版本源码且确实需要读代码，可以现网拉取该受影响版本源码；下载目录名应包含 affected/vulnerable/old 等语义。
5. 漏洞分析可以为根因与修复判断下载补丁相关源码或修复版本源码；如果下载的是最新/修复版本，目录名应包含 latest/fixed/current 等语义，并在 `source_version_assessment.latest_source_version` 写明版本来源。
6. 完整的大范围版本差异仍由源码库“拉取最新版本”按钮承接；本轮只下载完成漏洞根因、POC/EXP 可用性和修复版本判断所必需的源码。
7. 只阅读与漏洞有关的路由、控制器、解析器、依赖版本、补丁提交、变更记录，不做大范围无关扫描。
8. 结合源码验证 POC/EXP 是否真实有效：定位受影响函数/文件/版本，说明触发路径、失败条件、以及本地源码版本对结论的影响。
9. 如果找不到可下载源码，直接跳过源码验证，不得因此判定整个分析失败；`source_found=false`，`source_found_label="源码未找到"`。若数据库中已有历史源码证据，请在 `source_analysis` 说明“本轮未找到新源码，但保留历史源码证据”。

### 阶段三：防御输出
仅输出防御侧利用可能性分析、检测步骤和缓解建议，不生成可直接攻击公网目标的武器化代码。POC 可以包含非破坏性验证步骤、请求样例或检测逻辑；EXP 部分描述利用条件、风险链路、授权环境复现思路和缓解建议。

### 阶段四：最终 JSON 输出
1. 将工作拆成：产品归属、公开 POC/EXP 验证、源码检索、源码根因、增强 EXP/检测、修复建议。
2. 最后只输出一个统一 JSON 对象，不要 Markdown 围栏，不要额外解释。
3. 对输出做结构化自检：字段缺失时填空字符串或空数组，不要编造来源；confidence 使用 0 到 1 的数字。

模型任务配置：
{json.dumps(model_profile, ensure_ascii=False, indent=2)}

模型使用建议：
- 即使主模型是 Pro，产品归属、源码库匹配、版本标签判断等轻量任务也优先使用 `light_task_model` / `source_triage_model` / `product_attribution_model`。
- 深度根因、POC/EXP 可靠性和红队增强结论使用更强模型完成。

JSON schema:
{{
  "summary": "中文概要，包含影响、根因、POC/EXP 可用性、源码是否找到、处置建议",
  "affected_products": ["..."],
  "product_attribution": {{"product": "...", "confidence": 0.0, "evidence": "..."}},
  "root_cause": "...",
  "attack_surface": "...",
  "source_found": true,
  "source_found_label": "源码已找到 | 源码未找到",
  "source_analysis": "源码仓库、文件路径、函数/类、受影响版本、本地源码版本、版本匹配结论和触发路径；没有源码则说明已跳过",
  "source_version_assessment": {{"alert_affected_versions": "...", "local_source_version": "...", "latest_source_version": "仅当源码库已有最新版本时填写，否则 unknown", "match": "affected | fixed | unknown | mismatch", "impact_on_analysis": "...", "needs_online_source": false}},
  "public_poc_exp": [
    {{"kind": "poc | exp", "title": "...", "url": "...", "local_path": "...", "validation": "usable | partial | unverified | invalid | not_found", "evidence": "..."}}
  ],
  "poc_validation": {{"status": "usable | partial | unverified | invalid | not_found", "evidence": "..."}},
  "poc_available": true,
  "poc_content": "只有在 POC 可用或可部分验证时填写非破坏性验证步骤、请求样例、curl/Python 脚本；否则为空字符串",
  "exp_validation": {{"status": "usable | partial | unverified | invalid | not_found", "evidence": "..."}},
  "exp_available": true,
  "exp_content": "EXP/利用可能性分析、前置条件、检测与缓解；不要给出武器化利用载荷",
  "enhanced_exp_available": true,
  "enhanced_exp_summary": "增强 EXP 基于哪些公开 POC/EXP 和源码证据；证据不足时说明缺口",
  "exp_type": "rce | file_upload | sqli | ssti | deserialize | ssrf | auth_bypass | other",
  "exp_command_example": "python3 exploit.py -t 192.168.1.100 -p 8080",
  "remediation": "修复建议、升级版本、临时缓解、检测排查步骤",
  "references": [{{"title": "...", "url": "..."}}],
  "source_repositories": [{{"name": "...", "url": "...", "local_path": "...", "version": "...", "version_role": "affected | latest | uploaded | unknown", "evidence": "版本来源，例如 tag、package manifest、release 页面"}}],
  "confidence": 0.0
}}
""".strip()


def _red_team_enhancement_prompt(payload: dict[str, Any], model_profile: dict[str, Any]) -> str:
    return f"""
你是内部授权红队增强助手。红队增强不是重新做完整漏洞分析；必须参考 `previous_analysis` 的摘要、POC/EXP 判断、源码根因、`existing_local_source` 中已经存在的源码路径/源码库记录，并通过现网搜索公开 POC/EXP、公告和技术文章来生成增强 EXP 或授权验证方案。

重要边界：
- 本轮禁止拉取源码：不要执行 git clone、npm pack、pip download、下载源码压缩包、解压源码包或拉取最新版本代码。
- 可以读取 `existing_local_source` 和 `previous_analysis` 里已经存在的本地源码路径、源码库归档和历史分析工作目录。
- 现网搜索只用于确认公开 POC/EXP、攻击条件、修复公告、技术分析文章和可验证请求，不用于下载产品源码。
- 如果没有可用的历史漏洞分析摘要或源码证据，必须明确写出“缺少标准漏洞分析/源码证据”，不要编造源码根因或 EXP。
- 如果证据不足以安全生成 EXP，只输出可复现实验思路、检测脚本或缺失证据清单。

待增强漏洞：
{json.dumps(payload, ensure_ascii=False, indent=2)}

---
### 阶段一：复用漏洞分析结论
1. 先阅读 `previous_analysis.summary`、`previous_analysis.structured`、`previous_analysis.poc_content`、`previous_analysis.exp_content`、`previous_analysis.sources`。
2. 读取 `existing_local_source.artifacts` / `existing_local_source.workspace_source_matches` 中已有源码路径，验证关键函数、参数入口、受影响版本和修复线索；不要下载新源码。
3. 如果前置分析中已有 `source_version_assessment`，沿用并复核；不要为了版本差异去拉最新版本。

### 阶段二：现网 POC/EXP 检索
1. 使用 WebSearch/WebFetch 搜索 CVE/GHSA/XVE、漏洞标题、产品名、`poc`、`exploit`、`exp`、`nuclei`、`metasploit`、安全厂商分析。
2. 判断公开 POC/EXP 是否真实可用：来源、入口点、前置条件、失败条件、是否只是占位或转载。
3. 现网内容只能作为证据来源；若需要代码，优先引用网页/仓库中的公开片段与思路，不拉取产品源码。

### 阶段三：红队增强输出
1. 基于漏洞分析摘要、已有源码证据和公开 POC/EXP，输出增强 EXP 或授权验证方案。
2. 写清利用条件、参数、请求样例、失败条件、安全边界、检测回滚方式。
3. SQL 注入/RCE/SSRF/文件上传等高风险内容必须标注授权环境限制；不要把不确定结论写成可用 EXP。

### 阶段四：最终 JSON 输出
1. 最后只输出一个统一 JSON 对象，不要 Markdown 围栏，不要额外解释。
2. 对输出做结构化自检：字段缺失时填空字符串或空数组，不要编造来源；confidence 使用 0 到 1 的数字。

模型任务配置：
{json.dumps(model_profile, ensure_ascii=False, indent=2)}

JSON schema:
{{
  "summary": "中文概要，包含红队增强结论、利用条件、证据充分性和安全边界",
  "affected_products": ["..."],
  "product_attribution": {{"product": "...", "confidence": 0.0, "evidence": "..."}},
  "root_cause": "复用漏洞分析和已有源码证据得到的根因；证据不足则说明缺口",
  "attack_surface": "...",
  "source_found": true,
  "source_found_label": "源码已找到 | 源码未找到",
  "source_analysis": "只引用已有源码路径、历史漏洞分析和源码库证据；不要写本轮下载了源码",
  "source_version_assessment": {{"alert_affected_versions": "...", "local_source_version": "...", "latest_source_version": "仅当已有源码证据中存在时填写，否则 unknown", "match": "affected | fixed | unknown | mismatch", "impact_on_analysis": "...", "needs_online_source": false}},
  "public_poc_exp": [
    {{"kind": "poc | exp", "title": "...", "url": "...", "local_path": "", "validation": "usable | partial | unverified | invalid | not_found", "evidence": "..."}}
  ],
  "poc_validation": {{"status": "usable | partial | unverified | invalid | not_found", "evidence": "..."}},
  "poc_available": true,
  "poc_content": "非破坏性验证步骤、请求样例或检测脚本；否则为空字符串",
  "exp_validation": {{"status": "usable | partial | unverified | invalid | not_found", "evidence": "..."}},
  "exp_available": true,
  "exp_content": "增强 EXP 或授权渗透步骤；必须基于 previous_analysis、已有源码证据和公开 POC/EXP，说明安全边界",
  "enhanced_exp_available": true,
  "enhanced_exp_summary": "增强 EXP 基于哪些漏洞分析摘要、已有源码和公开 POC/EXP 证据；证据不足时说明缺口",
  "exp_type": "rce | file_upload | sqli | ssti | deserialize | ssrf | auth_bypass | other",
  "exp_command_example": "python3 exploit.py -t 192.168.1.100 -p 8080",
  "remediation": "修复建议、升级版本、临时缓解、检测排查步骤",
  "references": [{{"title": "...", "url": "..."}}],
  "source_repositories": [{{"name": "已有源码证据名称", "url": "", "local_path": "已有本地路径", "version": "...", "version_role": "affected | latest | uploaded | unknown", "evidence": "历史分析/源码库/本地路径来源"}}],
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
            narrative = _analysis_payload_from_result_text(result, outer)
            if narrative:
                return narrative
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
                    narrative = _analysis_payload_from_result_text(result, item)
                    if narrative:
                        return narrative
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


def _analysis_payload_from_result_text(result_text: str, outer: dict[str, Any] | None = None) -> dict[str, Any]:
    text = str(result_text or "").strip()
    if not text:
        return {}
    poc_available = _narrative_artifact_available(text, "poc")
    exp_available = _narrative_artifact_available(text, "exp")
    source_found = _narrative_source_found(text)
    if not any([poc_available, exp_available, source_found, _narrative_has_analysis_signal(text)]):
        return {}
    poc_evidence = _narrative_evidence(text, "poc")
    exp_evidence = _narrative_evidence(text, "exp")
    source_analysis = _narrative_source_analysis(text)
    payload = {
        "summary": text[:12000],
        "affected_products": _narrative_affected_products(text),
        "root_cause": _narrative_section(text, ["根因", "源码验证", "source"]),
        "attack_surface": _narrative_section(text, ["影响严重", "攻击面", "impact"]),
        "source_found": source_found,
        "source_found_label": "源码已找到" if source_found else "源码未找到",
        "source_analysis": source_analysis,
        "source_version_assessment": _narrative_source_version_assessment(text),
        "public_poc_exp": _narrative_public_poc_exp(text),
        "poc_validation": {
            "status": "usable" if poc_available else "not_found",
            "evidence": poc_evidence,
        },
        "poc_available": poc_available,
        "poc_content": _narrative_artifact_content(text, "poc") if poc_available else "",
        "exp_validation": {
            "status": "usable" if exp_available else "not_found",
            "evidence": exp_evidence,
        },
        "exp_available": exp_available,
        "exp_content": _narrative_artifact_content(text, "exp") if exp_available else "",
        "enhanced_exp_available": exp_available,
        "enhanced_exp_summary": exp_evidence if exp_available else "",
        "exp_type": _narrative_exp_type(text),
        "remediation": _narrative_section(text, ["修复版本", "修复建议", "remediation"]),
        "references": [],
        "confidence": 0.65,
        "_recovered_from_result_text": True,
    }
    if outer:
        payload["_result_wrapper"] = {
            "type": outer.get("type"),
            "subtype": outer.get("subtype"),
            "session_id": outer.get("session_id"),
            "duration_ms": outer.get("duration_ms"),
            "api_error_status": outer.get("api_error_status"),
        }
    return payload


def _narrative_has_analysis_signal(text: str) -> bool:
    lower = text.lower()
    markers = [
        "cve-",
        "ghsa-",
        "root cause",
        "poc",
        "exp",
        "exploit",
        "源码",
        "根因",
        "修复版本",
        "影响严重",
        "漏洞",
    ]
    return any(marker in lower or marker in text for marker in markers)


def _narrative_artifact_available(text: str, kind: str) -> bool:
    lower = text.lower()
    negative = {
        "poc": ["poc：无", "poc: no", "poc 未", "无 poc", "没有公开 poc", "not found poc"],
        "exp": ["exp：无", "exp: no", "exp 未", "无 exp", "没有公开 exp", "not found exp"],
    }[kind]
    if any(marker in lower for marker in negative) or any(marker in text for marker in negative):
        return False
    shared_positive = ["poc/exp 可用", "poc 和 exp 可用", "poc 与 exp 可用", "poc exp 可用"]
    if any(marker in lower or marker in text.lower() for marker in shared_positive):
        return True
    if kind == "poc":
        markers = ["poc 可用", "poc 完整可用", "poc 载荷", "proof-of-concept", "proof of concept", "公开 poc", "有 poc"]
    else:
        markers = ["exp 可用", "exp 包含", "增强 exp", "exploit 可用", "公开 exp", "有 exp", "在野利用", "observed exploitation", "利用脚本"]
    return any(marker in lower or marker in text for marker in markers)


def _narrative_source_found(text: str) -> bool:
    lower = text.lower()
    negative = ["源码未找到", "未搜索到可下载的源码", "source not found", "no source"]
    if any(marker in lower or marker in text for marker in negative):
        return False
    positive = ["源码验证通过", "本地源码", "源码确认", "源码中", "本地保留", "source verified", "local source", "源码根因"]
    return any(marker in lower or marker in text for marker in positive)


def _narrative_evidence(text: str, kind: str) -> str:
    if kind == "poc":
        return _narrative_section(text, ["POC/EXP 可用", "POC", "PoC", "proof"])
    return _narrative_section(text, ["POC/EXP 可用", "EXP", "exploit", "在野利用"])


def _narrative_artifact_content(text: str, kind: str) -> str:
    evidence = _narrative_evidence(text, kind)
    body = evidence or text[:2000]
    if kind == "poc":
        return f"验证步骤/证据：\n{body}"
    return f"利用条件/证据：\n{body}"


def _narrative_source_analysis(text: str) -> str:
    return _narrative_section(text, ["源码验证通过", "源码", "source"]) or ""


def _narrative_section(text: str, markers: list[str]) -> str:
    lines = [line.strip(" \t-*") for line in str(text or "").splitlines() if line.strip()]
    selected: list[str] = []
    for line in lines:
        lower = line.lower()
        if any(marker.lower() in lower for marker in markers):
            selected.append(line)
    if selected:
        return "\n".join(selected[:4])[:2000]
    for marker in markers:
        index = text.lower().find(marker.lower())
        if index >= 0:
            return text[index:index + 1200].strip()
    return ""


def _narrative_affected_products(text: str) -> list[str]:
    products: list[str] = []
    if re.search(r"\bLiteLLM\b", text, flags=re.I):
        products.append("LiteLLM")
    return products


def _narrative_exp_type(text: str) -> str:
    lower = text.lower()
    if "sql" in lower or "sqli" in lower or "sql 注入" in text:
        return "sqli"
    if "ssti" in lower or "template injection" in lower:
        return "ssti"
    if "rce" in lower or "remote code" in lower or "命令执行" in text:
        return "rce"
    if "ssrf" in lower:
        return "ssrf"
    if "file upload" in lower or "文件上传" in text:
        return "file_upload"
    if "auth" in lower or "认证绕过" in text:
        return "auth_bypass"
    return "other"


def _narrative_public_poc_exp(text: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    urls = re.findall(r"https?://[^\s)）\\]】\"']+", text)
    for url in urls[:8]:
        items.append({"kind": "reference", "title": url, "url": url, "validation": "unverified", "evidence": "模型自然语言结果中提到的公开来源"})
    if _narrative_artifact_available(text, "poc") or _narrative_artifact_available(text, "exp"):
        items.append(
            {
                "kind": "poc | exp",
                "title": "模型自然语言结果提到 POC/EXP 可用",
                "url": "",
                "validation": "usable",
                "evidence": _narrative_evidence(text, "poc") or _narrative_evidence(text, "exp"),
            }
        )
    return items


def _narrative_source_version_assessment(text: str) -> dict[str, str | bool]:
    versions = []
    for match in re.finditer(r"\bv?\d+\.\d+(?:\.\d+)?(?:[A-Za-z0-9_.+-]*)\b", text):
        version = match.group(0)
        prefix = text[max(0, match.start() - 30):match.start()].lower()
        if not version.lower().startswith("v") and version.count(".") == 1 and any(marker in prefix for marker in ["cvss", "score", "评分"]):
            continue
        versions.append(version)
    unique: list[str] = []
    seen: set[str] = set()
    for version in versions:
        if version not in seen:
            seen.add(version)
            unique.append(version)
    fixed = ""
    affected = ""
    for version in unique:
        marker = version.lower().lstrip("v")
        if "83.14" in marker or "83.7" in marker:
            fixed = version
        elif not affected:
            affected = version
    return {
        "alert_affected_versions": ", ".join(unique[:6]),
        "local_source_version": affected,
        "latest_source_version": fixed or "unknown",
        "match": "affected" if affected else "unknown",
        "impact_on_analysis": _narrative_source_analysis(text)[:600],
        "needs_online_source": False,
    }


def _json_from_text(text: str) -> Any:
    cleaned = (text or "").strip()
    if not cleaned:
        return {}
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    for match in re.finditer(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.S | re.I):
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            continue
    decoder = json.JSONDecoder()
    for index, char in enumerate(cleaned):
        if char not in "{[":
            continue
        with contextlib.suppress(json.JSONDecodeError):
            payload, _ = decoder.raw_decode(cleaned[index:])
            if isinstance(payload, (dict, list)):
                return payload
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
            source_version = str(value.get("source_version") or value.get("version") or "").strip()
            version_role = _normalize_source_version_role(value.get("version_role") or value.get("role") or "")
            evidence = str(value.get("evidence") or value.get("version_evidence") or "").strip()
            if url or local_path:
                refs.append(
                    {
                        "title": name,
                        "url": url,
                        "local_path": local_path,
                        "kind": "source",
                        "source_version": source_version,
                        "version": source_version,
                        "version_role": version_role,
                        "evidence": evidence,
                    }
                )
    return refs


def _source_artifacts_metadata(
    vulnerability_id: int,
    run_id: str,
    workspace: Path,
    source_refs: list[dict[str, Any]],
    *,
    archive_local_sources: bool = True,
) -> list[dict[str, str]]:
    _source_local_paths(workspace, source_refs)
    retained_until = (
        datetime.now(timezone.utc) + timedelta(days=settings.vulnerability_source_retention_days)
    ).isoformat(timespec="seconds")
    artifacts: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    workspace_resolved = workspace.resolve()
    for index, ref in enumerate(source_refs):
        local_path_text = str(ref.get("local_path") or "").strip()
        if not local_path_text:
            continue
        try:
            local_path = Path(local_path_text).resolve()
        except OSError:
            continue
        key = str(local_path)
        if key in seen_paths or not local_path.exists():
            continue
        seen_paths.add(key)
        if not _path_is_relative_to(local_path, workspace_resolved):
            artifacts.append(_source_artifact_from_ref(ref))
            continue
        version_role = _normalize_source_version_role(ref.get("version_role"))
        artifact = _source_artifact_from_ref(ref)
        archive_path = (
            _archive_source_path(vulnerability_id, run_id, workspace, local_path, index, version_role)
            if archive_local_sources
            else ""
        )
        if archive_path:
            artifact["archive_path"] = archive_path
            artifact["retained_until"] = retained_until
            artifact["cleanup_paths"] = [str(local_path)]
        artifacts.append(artifact)
    if artifacts:
        return artifacts
    primary = _primary_source_ref(source_refs)
    return [primary] if primary.get("url") or primary.get("local_path") else []


def _empty_source_artifact() -> dict[str, str]:
    return {
        "title": "",
        "url": "",
        "local_path": "",
        "archive_path": "",
        "retained_until": "",
        "source_version": "",
        "version_role": "",
        "version_evidence": "",
    }


def _source_artifact_from_ref(ref: dict[str, Any]) -> dict[str, str]:
    return {
        "title": str(ref.get("title") or ref.get("name") or ref.get("url") or ref.get("local_path") or "源码").strip(),
        "url": str(ref.get("url") or "").strip(),
        "local_path": str(ref.get("local_path") or "").strip(),
        "archive_path": "",
        "retained_until": "",
        "source_version": str(ref.get("source_version") or ref.get("version") or "").strip()[:120],
        "version_role": _normalize_source_version_role(ref.get("version_role")),
        "version_evidence": str(ref.get("evidence") or ref.get("version_evidence") or "").strip()[:500],
    }


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
                "source_version": str(ref.get("source_version") or ref.get("version") or "").strip()[:120],
                "version_role": _normalize_source_version_role(ref.get("version_role")),
                "version_evidence": str(ref.get("evidence") or ref.get("version_evidence") or "").strip()[:500],
            }
    return _empty_source_artifact()


def _normalize_source_version_role(value: Any) -> str:
    text = re.sub(r"[^a-z_]+", "_", str(value or "").strip().lower()).strip("_")
    mapping = {
        "vulnerable": "affected",
        "vulnerability": "affected",
        "problem": "affected",
        "fixed": "latest",
        "current": "latest",
        "newest": "latest",
        "upload": "uploaded",
        "user_upload": "uploaded",
    }
    normalized = mapping.get(text, text)
    return normalized if normalized in {"affected", "latest", "uploaded", "unknown"} else "unknown"


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


def _archive_source_path(
    vulnerability_id: int,
    run_id: str,
    workspace: Path,
    source_path: Path,
    index: int,
    version_role: str,
) -> str:
    if not source_path.exists():
        return ""
    archive_dir = workspace / "_source_archives"
    archive_dir.mkdir(parents=True, exist_ok=True)
    suffix = version_role or "source"
    archive_path = archive_dir / f"{vulnerability_id}-{run_id[:8]}-{index + 1}-{suffix}-source.zip"
    workspace_resolved = workspace.resolve()
    try:
        with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as zf:
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
        artifacts: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            artifact = payload.get("source_artifact")
            if isinstance(artifact, dict):
                artifacts.append(artifact)
            source_artifacts = payload.get("source_artifacts")
            if isinstance(source_artifacts, list):
                artifacts.extend(item for item in source_artifacts if isinstance(item, dict))
        for artifact in artifacts:
            cleanup_paths = artifact.get("cleanup_paths")
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
