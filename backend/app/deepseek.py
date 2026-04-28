from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib.parse import urlparse

import httpx

from . import db
from .async_utils import run_blocking
from .config import settings


DEEPSEEK_API_KEY_SETTING = "deepseek_api_key"
MODEL_BASE_URL_SETTING = "model_source_base_url"


def get_deepseek_api_key() -> str:
    return db.get_setting(DEEPSEEK_API_KEY_SETTING) or settings.anthropic_auth_token


def get_deepseek_api_key_source() -> str:
    if db.get_setting(DEEPSEEK_API_KEY_SETTING):
        return "database"
    if settings.anthropic_auth_token:
        return "environment"
    return "none"


def get_model_base_url() -> str:
    return db.get_setting(MODEL_BASE_URL_SETTING) or settings.anthropic_base_url


def get_model_base_url_source() -> str:
    if db.get_setting(MODEL_BASE_URL_SETTING):
        return "database"
    if os.getenv("ANTHROPIC_BASE_URL"):
        return "environment"
    return "default"


def set_deepseek_api_key(api_key: str = "", base_url: str = "") -> dict[str, Any]:
    cleaned = api_key.strip()
    cleaned_base_url = base_url.strip()
    if not cleaned and not cleaned_base_url:
        raise ValueError("api_key or base_url is required")
    if cleaned:
        db.set_setting(DEEPSEEK_API_KEY_SETTING, cleaned)
        _apply_runtime_key(cleaned)
    if cleaned_base_url:
        normalized_base_url = _normalize_base_url(cleaned_base_url)
        db.set_setting(MODEL_BASE_URL_SETTING, normalized_base_url)
        _apply_runtime_base_url(normalized_base_url)
    return get_deepseek_status()


def clear_deepseek_api_key() -> dict[str, Any]:
    db.delete_setting(DEEPSEEK_API_KEY_SETTING)
    if settings.anthropic_auth_token:
        _apply_runtime_key(settings.anthropic_auth_token)
    else:
        _clear_runtime_key()
    return get_deepseek_status()


def get_deepseek_status() -> dict[str, Any]:
    key = get_deepseek_api_key()
    meta = db.get_setting_meta(DEEPSEEK_API_KEY_SETTING)
    base_meta = db.get_setting_meta(MODEL_BASE_URL_SETTING)
    return {
        "configured": bool(key),
        "key_source": get_deepseek_api_key_source(),
        "masked_api_key": _mask_key(key),
        "updated_at": meta["updated_at"] if meta else None,
        "base_url": get_model_base_url(),
        "base_url_source": get_model_base_url_source(),
        "base_url_updated_at": base_meta["updated_at"] if base_meta else None,
        "balance_url": settings.deepseek_balance_url,
        "balance_interval_minutes": settings.deepseek_balance_interval_minutes,
        "latest_balance": db.latest_deepseek_balance_check(),
    }


async def refresh_deepseek_balance() -> dict[str, Any]:
    api_key = await run_blocking(get_deepseek_api_key)
    if not api_key:
        return {**(await run_blocking(get_deepseek_status)), "balance_status": "unconfigured"}

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.get(
                settings.deepseek_balance_url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
            )
        raw = _response_json(response)
        if response.status_code >= 400:
            error = _compact_error(response.status_code, raw)
            latest = await run_blocking(db.insert_deepseek_balance_check, status="failed", raw=raw, error=error)
            return {**(await run_blocking(get_deepseek_status)), "balance_status": "failed", "latest_balance": latest}

        primary = _primary_balance(raw)
        latest = await run_blocking(
            db.insert_deepseek_balance_check,
            status="success",
            is_available=_bool_or_none(raw.get("is_available")),
            currency=str(primary.get("currency") or ""),
            total_balance=str(primary.get("total_balance") or ""),
            granted_balance=str(primary.get("granted_balance") or ""),
            topped_up_balance=str(primary.get("topped_up_balance") or ""),
            raw=raw,
        )
        return {**(await run_blocking(get_deepseek_status)), "balance_status": "success", "latest_balance": latest}
    except httpx.HTTPError as exc:
        latest = await run_blocking(db.insert_deepseek_balance_check, status="failed", error=str(exc))
        return {**(await run_blocking(get_deepseek_status)), "balance_status": "failed", "latest_balance": latest}


def refresh_deepseek_balance_sync() -> None:
    asyncio.run(refresh_deepseek_balance())


def _apply_runtime_key(api_key: str) -> None:
    os.environ["DEEPSEEK_API_KEY"] = api_key
    os.environ["ANTHROPIC_AUTH_TOKEN"] = api_key


def _apply_runtime_base_url(base_url: str) -> None:
    os.environ["ANTHROPIC_BASE_URL"] = base_url


def _clear_runtime_key() -> None:
    os.environ.pop("DEEPSEEK_API_KEY", None)
    os.environ.pop("ANTHROPIC_AUTH_TOKEN", None)


def _normalize_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be a valid http(s) URL")
    return base_url.rstrip("/")


def _mask_key(api_key: str) -> str:
    if not api_key:
        return ""
    if len(api_key) <= 8:
        return "*" * len(api_key)
    return f"{api_key[:3]}...{api_key[-4:]}"


def _response_json(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        return {"text": response.text[:1000]}
    return data if isinstance(data, dict) else {"data": data}


def _primary_balance(raw: dict[str, Any]) -> dict[str, Any]:
    infos = raw.get("balance_infos")
    if isinstance(infos, list) and infos and isinstance(infos[0], dict):
        return infos[0]
    return {}


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _compact_error(status_code: int, raw: dict[str, Any]) -> str:
    message = raw.get("message") or raw.get("error") or raw.get("text") or str(raw)
    return f"DeepSeek balance API returned {status_code}: {str(message)[:500]}"
