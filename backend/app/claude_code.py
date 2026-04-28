from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from . import db
from .config import settings
from .deepseek import get_deepseek_api_key, get_model_base_url


logger = logging.getLogger(__name__)
_status: dict[str, Any] = {
    "status": "not_checked",
    "available": False,
    "installed": False,
    "attempted_install": False,
    "command": settings.claude_code_command,
    "path": "",
    "error": "",
    "auth_token_configured": False,
}


def _display_path(path: str) -> str:
    if not path:
        return ""
    try:
        home = str(Path.home())
        if path == home:
            return "~"
        if path.startswith(home + os.sep):
            return "~" + path[len(home) :]
    except Exception:
        pass
    return path


def apply_claude_code_environment() -> None:
    for key, value in _claude_code_env().items():
        if value:
            os.environ[key] = value


def claude_code_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update({key: value for key, value in _claude_code_env().items() if value})
    return env


def get_claude_code_status() -> dict[str, Any]:
    current_path = _resolve_claude_command()
    runtime_env = _claude_code_env()
    return {
        **_status,
        "available": bool(current_path) or bool(_status.get("available")),
        "path": _display_path(current_path or _status.get("path", "")),
        "auth_token_configured": bool(get_deepseek_api_key()),
        "install_on_startup": settings.claude_code_install_on_startup,
        "required": settings.claude_code_required,
        "base_url": runtime_env.get("ANTHROPIC_BASE_URL") or settings.anthropic_base_url,
        "model": runtime_env.get("ANTHROPIC_MODEL") or settings.anthropic_model,
        "opus_model": runtime_env.get("ANTHROPIC_DEFAULT_OPUS_MODEL") or settings.anthropic_default_opus_model,
        "sonnet_model": runtime_env.get("ANTHROPIC_DEFAULT_SONNET_MODEL") or settings.anthropic_default_sonnet_model,
        "haiku_model": runtime_env.get("ANTHROPIC_DEFAULT_HAIKU_MODEL") or settings.anthropic_default_haiku_model,
        "subagent_model": runtime_env.get("CLAUDE_CODE_SUBAGENT_MODEL") or settings.claude_code_subagent_model,
        "effort_level": settings.claude_code_effort_level,
    }


def _claude_code_env() -> dict[str, str]:
    env = settings.claude_code_env()
    model_settings = db.get_model_settings()
    flash_model = str(model_settings.get("flash_model") or settings.anthropic_default_haiku_model)
    pro_model = str(model_settings.get("pro_model") or settings.anthropic_model)
    env.update(
        {
            "ANTHROPIC_BASE_URL": get_model_base_url(),
            "ANTHROPIC_MODEL": pro_model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": pro_model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": str(model_settings.get("root_cause_model") or pro_model),
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": flash_model,
            "CLAUDE_CODE_SUBAGENT_MODEL": pro_model,
        }
    )
    api_key = get_deepseek_api_key()
    if api_key:
        env["DEEPSEEK_API_KEY"] = api_key
        env["ANTHROPIC_AUTH_TOKEN"] = api_key
    return env


async def ensure_claude_code() -> dict[str, Any]:
    apply_claude_code_environment()

    existing_path = _resolve_claude_command()
    if existing_path:
        _status.update(
            {
                "status": "available",
                "available": True,
                "installed": False,
                "attempted_install": False,
                "path": existing_path,
                "error": "",
            }
        )
        logger.info("Claude Code is available at %s", _display_path(existing_path))
        return get_claude_code_status()

    if not settings.claude_code_install_on_startup:
        _status.update(
            {
                "status": "skipped",
                "available": False,
                "installed": False,
                "attempted_install": False,
                "path": "",
                "error": "startup install disabled",
            }
        )
        logger.warning("Claude Code startup install is disabled")
        return get_claude_code_status()

    result = await _install_claude_code()
    if result["status"] == "failed" and settings.claude_code_required:
        raise RuntimeError(result["error"])
    return result


async def _install_claude_code() -> dict[str, Any]:
    command = settings.claude_code_install_command
    _status.update(
        {
            "status": "installing",
            "available": False,
            "installed": False,
            "attempted_install": True,
            "path": "",
            "error": "",
        }
    )
    if not command:
        return _fail("CLAUDE_CODE_INSTALL_COMMAND is empty")
    if shutil.which(command[0]) is None:
        return _fail(f"installer command not found: {command[0]}")

    logger.info("Installing Claude Code with command: %s", " ".join(command))
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            env=claude_code_subprocess_env(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=settings.claude_code_install_timeout_seconds,
        )
    except asyncio.TimeoutError:
        return _fail(
            f"Claude Code install timed out after {settings.claude_code_install_timeout_seconds}s"
        )
    except OSError as exc:
        return _fail(str(exc))

    if process.returncode != 0:
        message = stderr.decode("utf-8", errors="replace").strip()
        if not message:
            message = stdout.decode("utf-8", errors="replace").strip()
        return _fail(message or f"installer exited with {process.returncode}")

    path = _resolve_claude_command()
    _status.update(
        {
            "status": "installed" if path else "installed_but_not_on_path",
            "available": bool(path),
            "installed": True,
            "attempted_install": True,
            "path": path,
            "error": "" if path else f"{settings.claude_code_command} not found on PATH after install",
        }
    )
    logger.info("Claude Code install finished: %s", _status["status"])
    return get_claude_code_status()


def _fail(error: str) -> dict[str, Any]:
    _status.update(
        {
            "status": "failed",
            "available": False,
            "installed": False,
            "attempted_install": True,
            "path": "",
            "error": error,
        }
    )
    logger.error("Claude Code install failed: %s", error)
    return get_claude_code_status()


def _resolve_claude_command() -> str:
    command = settings.claude_code_command
    if not command:
        return ""
    path = shutil.which(command)
    if path:
        return path
    candidate = Path(command).expanduser()
    if candidate.is_file():
        return str(candidate)
    local_candidate = Path.home() / ".local" / "bin" / command
    if local_candidate.is_file():
        return str(local_candidate)
    return ""
