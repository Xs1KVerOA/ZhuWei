from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import shutil
import subprocess
import tarfile
import uuid
from collections.abc import AsyncIterable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree as ET
from zipfile import ZipFile

from . import db
from .claude_code import claude_code_subprocess_env, resolve_claude_code_command
from .config import settings
from .deepseek import get_deepseek_api_key
from .minio_store import delete_object, minio_configured, upload_file


logger = logging.getLogger(__name__)

SOURCE_ARCHIVE_WORKERS = 2
EXTRACT_NOTE_FILE = ".zhuwei_extract_notes.json"
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__macosx",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
}
SOURCE_DIR_HINTS = {
    "app",
    "apps",
    "backend",
    "cmd",
    "core",
    "frontend",
    "internal",
    "lib",
    "libs",
    "modules",
    "packages",
    "pkg",
    "server",
    "src",
    "source",
}
_executor = ThreadPoolExecutor(max_workers=SOURCE_ARCHIVE_WORKERS, thread_name_prefix="source-archive")


def start_source_archive_workers() -> None:
    for status in ["queued", "analyzing"]:
        rows = db.list_source_archives(status=status, limit=50, offset=0).get("data", [])
        for row in rows:
            if status == "analyzing":
                db.update_source_archive(int(row["id"]), status="queued", error="服务重启后恢复源码分析任务。")
            schedule_source_archive_processing(int(row["id"]))


async def create_source_archive_from_stream(
    chunks: AsyncIterable[bytes],
    *,
    filename: str,
    content_type: str = "application/octet-stream",
    product_hint: str = "",
    source_version: str = "",
) -> dict[str, Any]:
    root = _upload_root()
    root.mkdir(parents=True, exist_ok=True)
    safe_name = _safe_filename(filename) or "source.zip"
    path = root / f"{uuid.uuid4().hex}-{safe_name}"
    size = 0
    digest = hashlib.sha256()
    max_bytes = settings.source_upload_max_mb * 1024 * 1024
    try:
        with path.open("wb") as handle:
            async for chunk in chunks:
                if not chunk:
                    continue
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"源码包超过上传限制：{settings.source_upload_max_mb} MB")
                digest.update(chunk)
                await asyncio.to_thread(handle.write, chunk)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    archive_payload = {
        "origin": "user_upload",
        "filename": safe_name,
        "content_type": content_type or "application/octet-stream",
        "size_bytes": size,
        "sha256": digest.hexdigest(),
        "source_version": _clean_source_version(source_version),
        "version_role": "uploaded",
        "status": "queued",
        "minio_status": "pending",
        "local_path": str(path),
        "product_hint": product_hint.strip()[:200],
    }
    archive = await asyncio.to_thread(db.create_source_archive, archive_payload)
    schedule_source_archive_processing(int(archive["id"]))
    await asyncio.to_thread(
        db.create_message,
        level="info",
        category="source_archive",
        title="源码包已上传",
        body=f"{safe_name}\n已进入异步结构分析队列，完成后需要确认产品名。",
        entity_type="source_archive",
        entity_id=archive["id"],
        raw={"source_archive_id": archive["id"], "filename": safe_name},
    )
    return archive


def register_analysis_source_artifact(vulnerability: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any] | None:
    archive_path = Path(str(artifact.get("archive_path") or "")).expanduser()
    if not archive_path.is_file():
        return None
    source_url = str(artifact.get("url") or "").strip()
    digest, size = _file_digest(archive_path)
    product_hint = _product_hint_from_vulnerability(vulnerability)
    record = db.create_source_archive(
        {
            "origin": "analysis_discovered",
            "filename": archive_path.name,
            "content_type": "application/zip",
            "size_bytes": size,
            "sha256": digest,
            "source_version": _clean_source_version(artifact.get("source_version") or artifact.get("version")),
            "version_role": _clean_version_role(artifact.get("version_role") or "affected"),
            "status": "queued",
            "minio_status": "pending",
            "local_path": str(archive_path),
            "product_hint": product_hint,
            "suggested_product_name": product_hint,
            "analysis_raw": {
                "vulnerability_id": vulnerability.get("id"),
                "cve_id": vulnerability.get("cve_id"),
                "title": vulnerability.get("title"),
                "source_url": source_url,
                "source_title": artifact.get("title"),
                "source_version": artifact.get("source_version") or artifact.get("version"),
                "version_role": artifact.get("version_role"),
                "version_evidence": artifact.get("version_evidence"),
            },
        }
    )
    schedule_source_archive_processing(int(record["id"]))
    return record


def schedule_source_archive_processing(archive_id: int) -> None:
    _executor.submit(process_source_archive_sync, archive_id)


def process_source_archive_sync(archive_id: int) -> dict[str, Any] | None:
    archive = db.get_source_archive(archive_id)
    if not archive:
        return None
    db.update_source_archive(archive_id, status="analyzing", error="")
    try:
        archive = db.get_source_archive(archive_id) or archive
        _upload_to_minio(archive)
        local_path = Path(str(archive.get("local_path") or "")).expanduser()
        extracted = _extract_source(local_path, archive_id)
        manifest = _source_manifest(extracted)
        model_result = _flash_source_analysis(archive, extracted, manifest)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        updated = db.update_source_archive(
            archive_id,
            status="needs_confirmation",
            source_version=_clean_source_version(archive.get("source_version") or model_result.get("source_version") or ""),
            version_role=_clean_version_role(archive.get("version_role") or model_result.get("version_role") or ""),
            extracted_path=str(extracted),
            suggested_product_name=str(model_result.get("suggested_product_name") or archive.get("product_hint") or "").strip()[:200],
            suggested_vendor=str(model_result.get("suggested_vendor") or "").strip()[:160],
            suggested_aliases=_clean_aliases(model_result.get("suggested_aliases")),
            architecture_summary=str(model_result.get("architecture_summary") or "").strip()[:12000],
            function_summary=str(model_result.get("function_summary") or "").strip()[:12000],
            product_evidence=str(model_result.get("product_evidence") or "").strip()[:12000],
            analysis_model=str(model_result.get("analysis_model") or settings.anthropic_default_haiku_model),
            analysis_raw={**model_result, "manifest": manifest},
            analyzed_at=now,
        )
        db.create_message(
            level="success",
            category="source_archive",
            title="源码结构分析完成",
            body=f"{archive.get('filename')}\n建议产品：{(updated or {}).get('suggested_product_name') or '待确认'}",
            entity_type="source_archive",
            entity_id=archive_id,
            raw={"source_archive_id": archive_id},
        )
        return updated
    except Exception as exc:
        logger.warning("source archive processing failed: %s", archive_id, exc_info=True)
        updated = db.update_source_archive(
            archive_id,
            status="failed",
            error=str(exc)[:4000],
            analyzed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        db.create_message(
            level="error",
            category="source_archive",
            title="源码结构分析失败",
            body=f"{archive.get('filename')}\n{str(exc)[:500]}",
            entity_type="source_archive",
            entity_id=archive_id,
            raw={"source_archive_id": archive_id, "error": str(exc)[:1000]},
        )
        return updated


def retry_minio_upload(archive_id: int) -> dict[str, Any] | None:
    archive = db.get_source_archive(archive_id)
    if not archive:
        return None
    _upload_to_minio(archive, force=True)
    return db.get_source_archive(archive_id)


def delete_source_archive(
    archive_id: int,
    *,
    reason: str = "",
    require_unconfirmed: bool = False,
) -> dict[str, Any] | None:
    archive = db.get_source_archive(archive_id)
    if not archive:
        return None
    if require_unconfirmed and archive.get("product_confirmed"):
        raise ValueError("source archive has already been confirmed")
    cleanup = _delete_source_archive_artifacts(archive)
    deleted = db.delete_source_archive_record(archive_id)
    if deleted is None:
        return None
    deleted["delete_reason"] = reason or ("取消入库并删除源码。" if require_unconfirmed else "删除源码。")
    deleted["cleanup"] = cleanup
    return deleted


def _upload_to_minio(archive: dict[str, Any], *, force: bool = False) -> None:
    archive_id = int(archive["id"])
    if archive.get("minio_status") == "uploaded" and not force:
        return
    if not minio_configured():
        db.update_source_archive(
            archive_id,
            minio_status="skipped",
            minio_error="MinIO 未配置，源码已保留在本地。",
        )
        return
    path = Path(str(archive.get("local_path") or "")).expanduser()
    if not path.is_file():
        db.update_source_archive(archive_id, minio_status="failed", minio_error="本地源码包不存在。")
        return
    try:
        object_key = _minio_object_key(archive, path)
        result = upload_file(path, object_key, content_type=str(archive.get("content_type") or "application/octet-stream"))
        db.update_source_archive(
            archive_id,
            minio_status="uploaded",
            minio_bucket=result["bucket"],
            minio_object_key=result["object_key"],
            minio_url=result["url"],
            minio_error="",
        )
    except Exception as exc:
        db.update_source_archive(
            archive_id,
            minio_status="failed",
            minio_error=str(exc)[:1000],
        )


def _delete_source_archive_artifacts(archive: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "local_deleted": 0,
        "minio_deleted": False,
        "errors": [],
    }
    seen: set[Path] = set()
    for key in ["local_path", "extracted_path"]:
        raw_path = str(archive.get(key) or "").strip()
        if not raw_path:
            continue
        try:
            path = Path(raw_path).expanduser().resolve()
        except OSError as exc:
            result["errors"].append(f"{key}: {exc}")
            continue
        if path in seen:
            continue
        seen.add(path)
        if not _source_delete_allowed(path):
            result["errors"].append(f"{key}: path outside managed source directories")
            continue
        try:
            if path.is_dir():
                shutil.rmtree(path)
                result["local_deleted"] += 1
            elif path.is_file():
                path.unlink()
                result["local_deleted"] += 1
        except OSError as exc:
            result["errors"].append(f"{key}: {exc}")
    object_key = str(archive.get("minio_object_key") or "").strip()
    if object_key and minio_configured():
        try:
            result["minio_deleted"] = bool(delete_object(object_key))
        except Exception as exc:
            result["errors"].append(f"minio: {str(exc)[:300]}")
    return result


def _source_delete_allowed(path: Path) -> bool:
    allowed_roots = [
        _upload_root().resolve(),
        settings.vulnerability_analysis_workspace_dir.resolve(),
    ]
    return any(_path_is_relative_to(path, root) or path == root for root in allowed_roots)


def _extract_source(path: Path, archive_id: int) -> Path:
    if path.is_dir():
        return path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"source archive not found: {path}")
    dest = _extract_root() / str(archive_id)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    lower = path.name.lower()
    if lower.endswith(".zip"):
        _extract_zip(path, dest)
    elif lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")):
        _extract_tar(path, dest)
    else:
        shutil.copy2(path, dest / path.name)
    return dest.resolve()


def _extract_zip(path: Path, dest: Path) -> None:
    extracted = 0
    total_size = 0
    stats = _extract_stats("zip")
    dest_root = dest.resolve()
    with ZipFile(path) as zf:
        items = [item for item in zf.infolist() if not item.is_dir()]
        stats["archive_entries"] = len(items)
        stats["archive_declared_bytes"] = sum(int(item.file_size or 0) for item in items)
        for item in sorted(items, key=lambda entry: _archive_sort_key(entry.filename)):
            if item.is_dir():
                continue
            file_size = int(item.file_size or 0)
            reason = _archive_skip_reason(item.filename, file_size)
            if reason:
                _count_skip(stats, reason)
                continue
            if extracted >= _max_extract_files() or total_size + file_size > _max_extract_bytes():
                stats["truncated"] = True
                stats["skipped_by_limit"] += 1
                continue
            target = _archive_target_path(dest, item.filename)
            if not _path_is_relative_to(target, dest_root):
                _count_skip(stats, "unsafe_path")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(item) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            extracted += 1
            total_size += file_size
    stats["extracted_files"] = extracted
    stats["extracted_bytes"] = total_size
    _write_extract_note(dest, stats)
    if extracted == 0:
        raise ValueError("源码包未提取到可分析源码文件；可能只包含依赖、构建产物或超大二进制文件。")


def _extract_tar(path: Path, dest: Path) -> None:
    extracted = 0
    total_size = 0
    stats = _extract_stats("tar")
    dest_root = dest.resolve()
    with tarfile.open(path) as tf:
        items = [item for item in tf.getmembers() if item.isfile()]
        stats["archive_entries"] = len(items)
        stats["archive_declared_bytes"] = sum(int(item.size or 0) for item in items)
        for item in sorted(items, key=lambda entry: _archive_sort_key(entry.name)):
            if not item.isfile():
                continue
            file_size = int(item.size or 0)
            reason = _archive_skip_reason(item.name, file_size)
            if reason:
                _count_skip(stats, reason)
                continue
            if extracted >= _max_extract_files() or total_size + file_size > _max_extract_bytes():
                stats["truncated"] = True
                stats["skipped_by_limit"] += 1
                continue
            target = _archive_target_path(dest, item.name)
            if not _path_is_relative_to(target, dest_root):
                _count_skip(stats, "unsafe_path")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            handle = tf.extractfile(item)
            if handle is None:
                _count_skip(stats, "unreadable")
                continue
            with handle, target.open("wb") as output:
                shutil.copyfileobj(handle, output)
            extracted += 1
            total_size += file_size
    stats["extracted_files"] = extracted
    stats["extracted_bytes"] = total_size
    _write_extract_note(dest, stats)
    if extracted == 0:
        raise ValueError("源码包未提取到可分析源码文件；可能只包含依赖、构建产物或超大二进制文件。")


def _max_extract_files() -> int:
    return int(getattr(settings, "source_extract_max_files", 20000))


def _max_extract_bytes() -> int:
    return int(getattr(settings, "source_extract_max_mb", 1024)) * 1024 * 1024


def _max_extract_file_bytes() -> int:
    return int(getattr(settings, "source_extract_max_file_mb", 25)) * 1024 * 1024


def _extract_stats(archive_type: str) -> dict[str, Any]:
    return {
        "archive_type": archive_type,
        "archive_entries": 0,
        "archive_declared_bytes": 0,
        "extracted_files": 0,
        "extracted_bytes": 0,
        "skipped_ignored_dirs": 0,
        "skipped_oversized_files": 0,
        "skipped_unsafe_paths": 0,
        "skipped_by_limit": 0,
        "skipped_unreadable": 0,
        "truncated": False,
        "limits": {
            "max_files": _max_extract_files(),
            "max_bytes": _max_extract_bytes(),
            "max_file_bytes": _max_extract_file_bytes(),
        },
    }


def _count_skip(stats: dict[str, Any], reason: str) -> None:
    if reason == "ignored_dir":
        stats["skipped_ignored_dirs"] += 1
    elif reason == "oversized_file":
        stats["skipped_oversized_files"] += 1
    elif reason == "unsafe_path":
        stats["skipped_unsafe_paths"] += 1
    elif reason == "unreadable":
        stats["skipped_unreadable"] += 1
    else:
        stats["skipped_by_limit"] += 1


def _archive_skip_reason(name: str, file_size: int) -> str:
    parts = _archive_parts(name)
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return "unsafe_path"
    lowered = [part.lower() for part in parts]
    if any(part in SKIP_DIRS for part in lowered):
        return "ignored_dir"
    if lowered[-1] in {".ds_store", "thumbs.db"}:
        return "ignored_dir"
    if file_size > _max_extract_file_bytes():
        return "oversized_file"
    return ""


def _archive_parts(name: str) -> tuple[str, ...]:
    normalized = str(name or "").replace("\\", "/").lstrip("/")
    parts = PurePosixPath(normalized).parts
    return tuple(part for part in parts if part not in {"", "."})


def _archive_target_path(dest: Path, name: str) -> Path:
    parts = _archive_parts(name)
    if not parts:
        return dest.resolve()
    return dest.joinpath(*parts).resolve()


def _archive_sort_key(name: str) -> tuple[int, int, str]:
    parts = _archive_parts(name)
    if not parts:
        return (99, 99, str(name))
    lowered = [part.lower() for part in parts]
    filename = lowered[-1]
    if _is_manifest_filename(filename) or filename in {"license", "copying", "notice"}:
        return (0, len(parts), str(name))
    if any(part in SOURCE_DIR_HINTS for part in lowered):
        return (1, len(parts), str(name))
    if len(parts) <= 3:
        return (2, len(parts), str(name))
    return (5, len(parts), str(name))


def _write_extract_note(dest: Path, stats: dict[str, Any]) -> None:
    try:
        (dest / EXTRACT_NOTE_FILE).write_text(
            json.dumps(stats, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass


def _read_extract_note(root: Path) -> dict[str, Any]:
    try:
        note = json.loads((root / EXTRACT_NOTE_FILE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return note if isinstance(note, dict) else {}


def _display_source_path(path: Path) -> str:
    try:
        data_root = settings.database_path.parent.resolve()
        resolved = path.resolve()
        if _path_is_relative_to(resolved, data_root):
            return str(resolved.relative_to(data_root))
        home = Path.home().resolve()
        if resolved == home:
            return "~"
        if _path_is_relative_to(resolved, home):
            return "~/" + str(resolved.relative_to(home))
    except OSError:
        pass
    return str(path)


def _source_manifest(root: Path) -> dict[str, Any]:
    files: list[str] = []
    suffix_counts: dict[str, int] = {}
    manifests: dict[str, str] = {}
    extraction_notes = _read_extract_note(root)
    total_files = 0
    for path in _iter_source_files(root):
        total_files += 1
        rel = str(path.relative_to(root))
        if len(files) < 220:
            files.append(rel)
        suffix = path.suffix.lower() or "[none]"
        suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
        if _is_manifest_file(path) and len(manifests) < 30:
            manifests[rel] = _read_text_preview(path, 6000)
    languages = _language_summary(suffix_counts)
    return {
        "root": _display_source_path(root),
        "total_files": total_files,
        "sample_files": files,
        "suffix_counts": dict(sorted(suffix_counts.items(), key=lambda item: item[1], reverse=True)[:30]),
        "languages": languages,
        "manifests": manifests,
        "extraction": extraction_notes,
    }


def _flash_source_analysis(archive: dict[str, Any], root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    fallback = _fallback_source_analysis(archive, manifest)
    command_path = resolve_claude_code_command()
    if not command_path or not get_deepseek_api_key():
        return fallback
    prompt = _source_analysis_prompt(archive, manifest)
    analysis_model = str(db.get_model_settings().get("flash_model") or settings.anthropic_default_haiku_model)
    env = claude_code_subprocess_env()
    env["ANTHROPIC_MODEL"] = analysis_model
    try:
        completed = subprocess.run(
            [
                command_path,
                "-p",
                prompt,
                "--output-format",
                "json",
                "--allowedTools",
                "Read,Bash(find:*),Bash(rg:*),Bash(cat:*),Bash(head:*),Bash(ls:*),Bash(pwd:*)",
                "--permission-mode",
                "acceptEdits",
            ],
            cwd=str(root),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=240,
            check=False,
        )
    except Exception as exc:
        fallback["analysis_error"] = str(exc)[:1000]
        return fallback
    parsed = _json_from_text(completed.stdout)
    if not parsed:
        parsed = _json_from_text(completed.stderr)
    if not isinstance(parsed, dict):
        fallback["analysis_error"] = (completed.stderr or completed.stdout or "Flash 分析没有返回 JSON")[:1000]
        return fallback
    if isinstance(parsed.get("result"), str):
        parsed = _json_from_text(parsed["result"]) or parsed
    db.record_claude_model_usage(
        task_type="source_archive_analysis",
        default_model=analysis_model,
        stdout_text=completed.stdout,
        status="success" if completed.returncode == 0 else "failed",
        raw={"source_archive_id": archive.get("id")},
    )
    result = {**fallback, **parsed}
    result["analysis_model"] = analysis_model
    result["claude_returncode"] = completed.returncode
    if completed.stderr:
        result["stderr_tail"] = completed.stderr[-1000:]
    return _clean_source_product_result(result, archive, manifest)


def _source_analysis_prompt(archive: dict[str, Any], manifest: dict[str, Any]) -> str:
    payload = {
        "filename": archive.get("filename"),
        "origin": archive.get("origin"),
        "product_hint": archive.get("product_hint"),
        "source_version": archive.get("source_version"),
        "version_role": archive.get("version_role"),
        "sha256": archive.get("sha256"),
        "manifest": manifest,
    }
    return f"""
你是软件源码架构分析助手。请只分析当前工作目录中的源码，识别项目架构、主要功能、可能对应的软件产品和厂商，并给出需要用户确认的产品名。

输入信息：
{json.dumps(payload, ensure_ascii=False, indent=2)}

要求：
1. 优先读取 package.json、pyproject.toml、pom.xml、go.mod、Cargo.toml、README、源码入口文件。
2. 不要进行漏洞利用、红队攻击或外网访问；只做产品归属、架构和功能分析。
3. 如果产品名不确定，给出最可能的建议名，并在 product_evidence 里说明证据和不确定点。
4. 尽量从 package.json、pyproject.toml、pom.xml、go.mod、Cargo.toml、composer.json、README、CHANGELOG 或 tag/commit 信息中识别源码版本。
5. 最后只输出 JSON，不要 Markdown 围栏。

JSON schema:
{{
  "suggested_product_name": "建议产品名，供用户确认",
  "suggested_vendor": "厂商或组织，可为空",
  "suggested_aliases": ["别名1", "别名2"],
  "source_version": "源码版本，可为空",
  "version_role": "uploaded | affected | latest | unknown",
  "architecture_summary": "中文说明源码目录结构、技术栈、入口、核心模块",
  "function_summary": "中文说明该源码实现的业务/组件能力",
  "product_evidence": "从包名、README、命名空间、组织名、文件结构中得到的产品归属证据",
  "confidence": 0.0
}}
""".strip()


def _fallback_source_analysis(archive: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    product_hint = str(archive.get("product_hint") or "").strip()
    product = "" if _is_noisy_source_product(product_hint) else product_hint
    vendor = ""
    aliases: list[str] = []
    package_info = _package_identity(manifest)
    if not product:
        product = package_info.get("name") or Path(str(archive.get("filename") or "")).stem
    if package_info.get("name") and package_info["name"] != product:
        aliases.append(package_info["name"])
    if archive.get("product_hint") and archive.get("product_hint") != product:
        aliases.append(str(archive.get("product_hint")))
    languages = manifest.get("languages") or []
    language_text = "、".join(f"{item['language']} {item['count']}" for item in languages[:6]) or "未识别"
    manifest_names = "、".join((manifest.get("manifests") or {}).keys()) or "未发现常见清单"
    extraction_text = _extraction_summary_text(manifest)
    return {
        "suggested_product_name": product,
        "suggested_vendor": vendor,
        "suggested_aliases": _clean_aliases(aliases),
        "source_version": _clean_source_version(archive.get("source_version") or package_info.get("version") or ""),
        "version_role": _clean_version_role(archive.get("version_role") or "uploaded"),
        "architecture_summary": (
            f"已解压 {manifest.get('total_files', 0)} 个可分析文件；主要语言/类型：{language_text}；"
            f"清单文件：{manifest_names}。{extraction_text}"
        ),
        "function_summary": package_info.get("description") or "未从清单中提取到明确功能说明，建议人工确认 README 与入口模块。",
        "product_evidence": package_info.get("evidence") or "基于文件名、上传提示和包清单做保守推断。",
        "confidence": 0.45 if package_info.get("name") else 0.25,
        "analysis_model": "fallback-manifest",
    }


def _product_hint_from_vulnerability(vulnerability: dict[str, Any]) -> str:
    raw = vulnerability.get("analysis_raw") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = {}
    if isinstance(raw, dict):
        claude_output = raw.get("claude_output") or {}
        if isinstance(claude_output, dict):
            attribution = claude_output.get("product_attribution") or {}
            if isinstance(attribution, dict):
                product = str(attribution.get("product") or "").strip()
                if product and not _is_noisy_source_product(product):
                    return product[:200]
            affected = claude_output.get("affected_products") or []
            if isinstance(affected, list):
                for item in affected:
                    product = str(item or "").strip()
                    if product and not _is_noisy_source_product(product):
                        return product[:200]
    product = str(vulnerability.get("product") or "").strip()
    if product and not _is_noisy_source_product(product):
        return product[:200]
    return ""


def _clean_source_product_result(
    result: dict[str, Any],
    archive: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    package_info = _package_identity(manifest)
    package_name = str(package_info.get("name") or "").strip()
    package_version = str(package_info.get("version") or "").strip()
    suggested = str(result.get("suggested_product_name") or "").strip()
    if not str(result.get("source_version") or "").strip() and package_version:
        result["source_version"] = package_version
    result["source_version"] = _clean_source_version(result.get("source_version") or archive.get("source_version") or "")
    result["version_role"] = _clean_version_role(result.get("version_role") or archive.get("version_role") or "unknown")
    if _is_noisy_source_product(suggested) and package_name:
        result["suggested_product_name"] = package_name
        aliases = _clean_aliases([*(result.get("suggested_aliases") or []), suggested])
        result["suggested_aliases"] = aliases
        result["product_evidence"] = package_info.get("evidence") or result.get("product_evidence") or ""
        result["confidence"] = max(_float_confidence(result.get("confidence")), 0.75)
    elif not suggested and package_name:
        result["suggested_product_name"] = package_name
        result["product_evidence"] = package_info.get("evidence") or result.get("product_evidence") or ""
        result["confidence"] = max(_float_confidence(result.get("confidence")), 0.75)
    return result


def _float_confidence(value: Any) -> float:
    try:
        return max(0.0, min(float(value or 0), 1.0))
    except (TypeError, ValueError):
        return 0.0


def _is_noisy_source_product(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    normalized = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", text)
    noisy = {
        "asecurityvulnerabilityhas",
        "asecurityflawhas",
        "avulnerabilitywas",
        "avulnerabilityhas",
        "anissuewas",
        "thisissue",
        "file",
        "function",
        "component",
        "argument",
        "security",
        "vulnerability",
    }
    return normalized in noisy or text.startswith(
        (
            "a security vulnerability has",
            "a security flaw has",
            "a vulnerability was",
            "a vulnerability has",
            "an issue was",
            "this issue",
        )
    )


def _package_identity(manifest: dict[str, Any]) -> dict[str, str]:
    manifests = manifest.get("manifests") or {}
    items = sorted(manifests.items(), key=lambda item: (str(item[0]).count("/"), str(item[0])))
    for name, text in items:
        if name.endswith("package.json"):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                return {
                    "name": str(payload.get("name") or "").strip(),
                    "version": str(payload.get("version") or "").strip(),
                    "description": str(payload.get("description") or "").strip(),
                    "evidence": f"package.json: name={payload.get('name') or ''}, version={payload.get('version') or ''}",
                }
    for name, text in items:
        if name.endswith("pyproject.toml"):
            match = re.search(r"(?m)^\s*name\s*=\s*[\"']([^\"']+)[\"']", text)
            version = re.search(r"(?m)^\s*version\s*=\s*[\"']([^\"']+)[\"']", text)
            desc = re.search(r"(?m)^\s*description\s*=\s*[\"']([^\"']+)[\"']", text)
            if match:
                return {
                    "name": match.group(1).strip(),
                    "version": version.group(1).strip() if version else "",
                    "description": desc.group(1).strip() if desc else "",
                    "evidence": f"pyproject.toml: name={match.group(1).strip()}, version={version.group(1).strip() if version else ''}",
                }
    for name, text in items:
        if name.endswith("pom.xml"):
            pom = _pom_identity(text)
            if pom:
                pom["evidence"] = f"{name}: {pom['evidence']}"
                return pom
    return {}


def _pom_identity(text: str) -> dict[str, str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return _pom_identity_from_text(text)

    def direct_child(parent: ET.Element, local_name: str) -> str:
        for child in list(parent):
            if str(child.tag).rsplit("}", 1)[-1] == local_name:
                return (child.text or "").strip()
        return ""

    parent = next(
        (child for child in list(root) if str(child.tag).rsplit("}", 1)[-1] == "parent"),
        None,
    )
    group_id = direct_child(root, "groupId") or (direct_child(parent, "groupId") if parent is not None else "")
    artifact_id = direct_child(root, "artifactId")
    version = direct_child(root, "version") or (direct_child(parent, "version") if parent is not None else "")
    name = direct_child(root, "name") or artifact_id
    description = direct_child(root, "description")
    if not artifact_id and not name:
        return {}
    return {
        "name": name,
        "version": version,
        "description": description,
        "evidence": f"groupId={group_id}, artifactId={artifact_id}, version={version}",
    }


def _pom_identity_from_text(text: str) -> dict[str, str]:
    body = re.sub(r"<parent\b.*?</parent>", "", text or "", flags=re.S)

    def tag(block: str, name: str) -> str:
        match = re.search(rf"<{re.escape(name)}>\s*([^<]+?)\s*</{re.escape(name)}>", block, flags=re.S)
        return match.group(1).strip() if match else ""

    group_id = tag(body, "groupId") or tag(text, "groupId")
    artifact_id = tag(body, "artifactId") or tag(text, "artifactId")
    version = tag(body, "version") or tag(text, "version")
    name = tag(body, "name") or artifact_id
    description = tag(body, "description")
    if not artifact_id and not name:
        return {}
    return {
        "name": name,
        "version": version,
        "description": description,
        "evidence": f"groupId={group_id}, artifactId={artifact_id}, version={version}",
    }


def _iter_source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name == EXTRACT_NOTE_FILE:
            continue
        if any(part.lower() in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
        except OSError:
            continue
        yield path


def _is_manifest_file(path: Path) -> bool:
    return _is_manifest_filename(path.name)


def _is_manifest_filename(name: str) -> bool:
    name = str(name or "").lower()
    return (
        name in {
            "package.json",
            "pyproject.toml",
            "setup.py",
            "requirements.txt",
            "pom.xml",
            "build.gradle",
            "go.mod",
            "cargo.toml",
            "composer.json",
        }
        or name.startswith("readme")
    )


def _extraction_summary_text(manifest: dict[str, Any]) -> str:
    extraction = manifest.get("extraction") or {}
    if not isinstance(extraction, dict):
        return ""
    archive_entries = int(extraction.get("archive_entries") or 0)
    extracted_files = int(extraction.get("extracted_files") or 0)
    skipped_ignored = int(extraction.get("skipped_ignored_dirs") or 0)
    skipped_large = int(extraction.get("skipped_oversized_files") or 0)
    skipped_limit = int(extraction.get("skipped_by_limit") or 0)
    if not archive_entries:
        return ""
    extras = []
    if skipped_ignored:
        extras.append(f"过滤依赖/构建目录 {skipped_ignored} 个文件")
    if skipped_large:
        extras.append(f"跳过超大文件 {skipped_large} 个")
    if skipped_limit:
        extras.append(f"因安全上限跳过 {skipped_limit} 个文件")
    if extraction.get("truncated"):
        extras.append("已启用大包抽样分析")
    if not extras:
        return f"解压策略：从源码包 {archive_entries} 个文件中提取 {extracted_files} 个。"
    return f"解压策略：从源码包 {archive_entries} 个文件中提取 {extracted_files} 个，" + "，".join(extras) + "。"


def _read_text_preview(path: Path, limit: int) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def _language_summary(suffix_counts: dict[str, int]) -> list[dict[str, Any]]:
    suffix_lang = {
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".py": "Python",
        ".java": "Java",
        ".go": "Go",
        ".rs": "Rust",
        ".php": "PHP",
        ".rb": "Ruby",
        ".cs": "C#",
        ".c": "C/C++",
        ".cc": "C/C++",
        ".cpp": "C/C++",
        ".h": "C/C++",
        ".hpp": "C/C++",
        ".xml": "XML",
        ".json": "JSON",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".md": "Markdown",
    }
    counts: dict[str, int] = {}
    for suffix, count in suffix_counts.items():
        language = suffix_lang.get(suffix, suffix)
        counts[language] = counts.get(language, 0) + count
    return [
        {"language": language, "count": count}
        for language, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:12]
    ]


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


def _file_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _safe_filename(value: str) -> str:
    text = Path(str(value or "")).name.strip()
    text = re.sub(r"[^A-Za-z0-9._@+\-\u4e00-\u9fff]+", "-", text).strip(".-")
    return text[:180]


def _clean_source_version(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip(" \t\r\n,:;，；")
    if text.lower() in {"none", "null", "unknown", "n/a", "na", "-"}:
        return ""
    return text[:120]


def _clean_version_role(value: Any) -> str:
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
    return normalized if normalized in {"uploaded", "affected", "latest", "unknown"} else "unknown"


def _clean_aliases(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        alias = str(value or "").strip()
        key = alias.lower()
        if not alias or key in seen:
            continue
        seen.add(key)
        result.append(alias[:160])
    return result[:12]


def _minio_object_key(archive: dict[str, Any], path: Path) -> str:
    digest = str(archive.get("sha256") or "")[:16] or uuid.uuid4().hex[:16]
    filename = _safe_filename(str(archive.get("filename") or path.name)) or path.name
    return f"{archive.get('id')}/{digest}-{filename}"


def _upload_root() -> Path:
    return settings.database_path.parent / "source_uploads"


def _extract_root() -> Path:
    return settings.database_path.parent / "source_uploads" / "extracted"


def _path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def run_async(coro: Any) -> Any:
    return asyncio.run(coro)
