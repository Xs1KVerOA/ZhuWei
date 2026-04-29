from __future__ import annotations

import re
from typing import Any

from . import db


DIFF_ROLE_ORDER = ["affected", "fixed", "latest"]
HIGH_SIGNAL_PATHS = (
    "controller",
    "route",
    "handler",
    "parser",
    "auth",
    "security",
    "filter",
    "proxy",
    "sql",
    "query",
    "upload",
    "deserialize",
    "template",
    "render",
)


def analyze_source_diff(payload: dict[str, Any]) -> dict[str, Any]:
    vulnerability_id = int(payload.get("vulnerability_id") or 0)
    archives = _resolve_archives(payload)
    if len([item for item in archives.values() if item]) < 2:
        raise ValueError("至少需要 affected/fixed/latest 中任意两个源码包。")
    vulnerability = db.get_vulnerability(vulnerability_id) if vulnerability_id else None
    product_name = str(
        payload.get("product_name")
        or _first_archive_value(archives, "product_name")
        or _first_archive_value(archives, "suggested_product_name")
        or ((vulnerability or {}).get("product") or "")
    ).strip()
    product_key = str(
        payload.get("product_key")
        or _first_archive_value(archives, "product_key")
        or (db.product_key(product_name) if product_name else "")
    ).strip()
    report = _build_diff_report(
        archives=archives,
        vulnerability=vulnerability or {},
        product_name=product_name,
        product_key=product_key,
    )
    record = db.create_source_diff_analysis(
        {
            **report,
            "vulnerability_id": vulnerability_id,
            "product_name": product_name,
            "product_key": product_key,
            "affected_archive_id": int((archives.get("affected") or {}).get("id") or 0),
            "fixed_archive_id": int((archives.get("fixed") or {}).get("id") or 0),
            "latest_archive_id": int((archives.get("latest") or {}).get("id") or 0),
            "status": "finished",
            "agent_model": "local-source-diff-agent",
            "raw": {
                "request": payload,
                "archives": {role: _archive_digest(archive) for role, archive in archives.items() if archive},
            },
        }
    )
    return record


def _resolve_archives(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    archives: dict[str, dict[str, Any]] = {}
    for role in DIFF_ROLE_ORDER:
        archive_id = int(payload.get(f"{role}_archive_id") or 0)
        if archive_id:
            archive = db.get_source_archive(archive_id)
            if not archive:
                raise KeyError(f"{role} source archive not found")
            archives[role] = archive
    if len(archives) >= 2:
        return archives
    product_name = str(payload.get("product_name") or "").strip()
    product_key = str(payload.get("product_key") or "").strip()
    query = product_name or product_key
    if not query:
        return archives
    candidates = db.list_source_archives(query=query, limit=100, offset=0).get("data", [])
    for archive in candidates:
        role = str(archive.get("version_role") or "unknown")
        if role in DIFF_ROLE_ORDER and role not in archives:
            if product_key and archive.get("product_key") and archive.get("product_key") != product_key:
                continue
            archives[role] = archive
    return archives


def _build_diff_report(
    *,
    archives: dict[str, dict[str, Any]],
    vulnerability: dict[str, Any],
    product_name: str,
    product_key: str,
) -> dict[str, Any]:
    compared = [role for role in DIFF_ROLE_ORDER if archives.get(role)]
    archive_text = "，".join(
        f"{_role_label(role)} {archives[role].get('source_version') or archives[role].get('filename') or '-'}"
        for role in compared
    )
    manifests = {role: _manifest(archive) for role, archive in archives.items() if archive}
    path_sets = {role: _sample_path_set(manifest) for role, manifest in manifests.items()}
    affected_paths = path_sets.get("affected", set())
    fixed_paths = path_sets.get("fixed", set())
    latest_paths = path_sets.get("latest", set())
    fixed_or_latest = fixed_paths or latest_paths
    removed = sorted(affected_paths - fixed_or_latest)[:30] if affected_paths and fixed_or_latest else []
    added = sorted(fixed_or_latest - affected_paths)[:30] if affected_paths and fixed_or_latest else []
    common = sorted(affected_paths & fixed_or_latest)[:30] if affected_paths and fixed_or_latest else []
    high_signal = _high_signal_paths([*removed, *added, *common])
    vuln_output = _analysis_output(vulnerability)
    root_cause = str(vuln_output.get("root_cause") or "").strip()
    source_analysis = str(vuln_output.get("source_analysis") or "").strip()
    summary = (
        f"已按企业本地源码优先模式对比 {product_name or product_key or '目标组件'} 的 {archive_text}。"
        f"当前基于源码清单、产品归属、架构摘要和历史漏洞分析生成第一版 Diff 证据链；"
        f"高信号路径 {len(high_signal)} 个，疑似新增/修复相关路径 {len(added)} 个，疑似移除路径 {len(removed)} 个。"
    )
    key_changes = []
    if high_signal:
        key_changes.append("高信号路径：" + "；".join(high_signal[:12]))
    if common:
        key_changes.append("affected 与 fixed/latest 均存在的重点路径：" + "；".join(common[:12]))
    if added:
        key_changes.append("fixed/latest 中新增或更名路径：" + "；".join(added[:12]))
    if removed:
        key_changes.append("affected 中存在但 fixed/latest 样本未见路径：" + "；".join(removed[:12]))
    if not key_changes:
        key_changes.append("源码清单样本不足，需 Agent 后续深读补丁提交或关键文件内容。")
    fix_points = [
        "优先深读 high-signal 路径中的鉴权、参数校验、SQL/模板/解析器调用点。",
        "结合 fixed/latest 版本确认是否新增边界检查、参数化查询、鉴权校验或危险函数替换。",
    ]
    if root_cause:
        fix_points.append(f"历史根因提示：{root_cause[:700]}")
    exploit_condition = source_analysis or root_cause or "当前缺少足够源码根因文本；可先从入口点、版本范围、补丁路径三类证据回溯触发条件。"
    bypass_risk = (
        "如果修复只覆盖单一路由、单一参数名或单一组件版本，需要继续搜索相似代码模式与旁路入口。"
        if high_signal
        else "当前只能从清单级别判断旁路风险，建议补充 fixed 与 affected 的完整文件级 diff。"
    )
    similar_patterns = _similar_patterns(high_signal or [*common, *added, *removed])
    evidence = [
        f"{_role_label(role)}源码：{archive.get('filename') or '-'} / {archive.get('source_version') or '-'} / archive#{archive.get('id')}"
        for role, archive in archives.items()
        if archive
    ]
    if source_analysis:
        evidence.append(f"历史源码分析：{source_analysis[:900]}")
    return {
        "summary": summary,
        "key_function_changes": key_changes,
        "fix_points": fix_points,
        "exploit_condition_backtrace": exploit_condition[:12000],
        "bypass_risk": bypass_risk,
        "similar_patterns": similar_patterns,
        "evidence": evidence,
    }


def _manifest(archive: dict[str, Any]) -> dict[str, Any]:
    raw = archive.get("analysis_raw") if isinstance(archive.get("analysis_raw"), dict) else {}
    manifest = raw.get("manifest") if isinstance(raw.get("manifest"), dict) else {}
    return manifest


def _sample_path_set(manifest: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    for key in ["sample_files", "important_files", "entrypoints"]:
        values = manifest.get(key)
        if isinstance(values, list):
            for value in values:
                text = str(value or "").strip()
                if text:
                    paths.add(text)
    manifest_files = manifest.get("manifests")
    if isinstance(manifest_files, dict):
        for value in manifest_files:
            text = str(value or "").strip()
            if text:
                paths.add(text)
    return {path for path in paths if not _looks_like_vendor_path(path)}


def _high_signal_paths(paths: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for path in paths:
        lowered = path.lower()
        if not any(token in lowered for token in HIGH_SIGNAL_PATHS):
            continue
        key = re.sub(r"[^a-z0-9_/.-]+", "", lowered)
        if key and key not in seen:
            seen.add(key)
            result.append(path)
    return result[:30]


def _similar_patterns(paths: list[str]) -> list[str]:
    patterns: list[str] = []
    lowered = " ".join(path.lower() for path in paths)
    checks = [
        ("sql/query", ["sql", "query", "repository", "dao"]),
        ("auth/filter", ["auth", "security", "filter", "permission"]),
        ("route/controller", ["route", "controller", "handler", "endpoint"]),
        ("parser/template", ["parser", "template", "render", "deserialize"]),
        ("upload/file", ["upload", "file", "path", "multipart"]),
    ]
    for label, tokens in checks:
        if any(token in lowered for token in tokens):
            patterns.append(label)
    return patterns[:12]


def _analysis_output(vulnerability: dict[str, Any]) -> dict[str, Any]:
    raw = vulnerability.get("analysis_raw") if isinstance(vulnerability.get("analysis_raw"), dict) else {}
    output = raw.get("claude_output") if isinstance(raw.get("claude_output"), dict) else {}
    return output


def _archive_digest(archive: dict[str, Any]) -> dict[str, Any]:
    manifest = _manifest(archive)
    return {
        "id": archive.get("id"),
        "filename": archive.get("filename"),
        "source_version": archive.get("source_version"),
        "version_role": archive.get("version_role"),
        "product_name": archive.get("product_name") or archive.get("suggested_product_name"),
        "total_files": manifest.get("total_files"),
        "languages": manifest.get("languages"),
    }


def _first_archive_value(archives: dict[str, dict[str, Any]], key: str) -> str:
    for role in DIFF_ROLE_ORDER:
        value = (archives.get(role) or {}).get(key)
        if value:
            return str(value)
    return ""


def _role_label(role: str) -> str:
    return {"affected": "受影响版本", "fixed": "修复版本", "latest": "最新版本"}.get(role, role)


def _looks_like_vendor_path(path: str) -> bool:
    lowered = path.lower()
    return any(part in lowered for part in ["/node_modules/", "/vendor/", "/dist/", "/build/", "/target/"])
