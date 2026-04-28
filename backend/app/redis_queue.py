from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .config import settings


logger = logging.getLogger(__name__)

_client_lock = threading.Lock()
_client: Any | None = None
_last_error = ""
_last_attempt_at = 0.0
_RECONNECT_BACKOFF_SECONDS = 5.0


def queue_backend_name() -> str:
    backend = str(getattr(settings, "queue_backend", "") or "").strip().lower()
    if backend:
        return backend
    return "redis" if settings.redis_url else "database"


def redis_queue_configured() -> bool:
    return queue_backend_name() == "redis" and bool(settings.redis_url)


def redis_queue_available() -> bool:
    return _redis_client() is not None


def redis_queue_status() -> dict[str, Any]:
    configured = redis_queue_configured()
    available = False
    queued = 0
    running = 0
    if configured:
        client = _redis_client()
        available = client is not None
        if client is not None:
            try:
                queued = int(client.zcard(_analysis_queue_key()))
                running = int(client.zcard(_analysis_running_key()))
            except Exception as exc:
                _remember_error(exc)
                available = False
    return {
        "backend": queue_backend_name(),
        "configured": configured,
        "available": available,
        "active": configured and available,
        "queued": queued,
        "running": running,
        "queue_key": _analysis_queue_key() if configured else "",
        "running_key": _analysis_running_key() if configured else "",
        "error": "" if available or not configured else _last_error,
    }


def reset_analysis_queue(items: list[dict[str, Any]]) -> bool:
    client = _redis_client()
    if client is None:
        return False
    try:
        pipe = client.pipeline()
        pipe.delete(_analysis_queue_key(), _analysis_running_key())
        for item in items:
            member = str(int(item["id"]))
            pipe.zadd(_analysis_queue_key(), {member: _analysis_score(item)})
        pipe.execute()
        return True
    except Exception as exc:
        _remember_error(exc)
        return False


def enqueue_analysis(item: dict[str, Any]) -> bool:
    client = _redis_client()
    if client is None:
        return False
    try:
        member = str(int(item["id"]))
        pipe = client.pipeline()
        pipe.zrem(_analysis_running_key(), member)
        pipe.zadd(_analysis_queue_key(), {member: _analysis_score(item)})
        pipe.execute()
        return True
    except Exception as exc:
        _remember_error(exc)
        return False


def remove_analysis(vulnerability_id: int) -> bool:
    client = _redis_client()
    if client is None:
        return False
    try:
        member = str(int(vulnerability_id))
        pipe = client.pipeline()
        pipe.zrem(_analysis_queue_key(), member)
        pipe.zrem(_analysis_running_key(), member)
        pipe.execute()
        return True
    except Exception as exc:
        _remember_error(exc)
        return False


def reserve_analysis_ids(limit: int) -> list[int]:
    client = _redis_client()
    if client is None:
        return []
    limit = max(1, min(int(limit), 50))
    try:
        rows = client.zpopmin(_analysis_queue_key(), limit)
        ids: list[int] = []
        now_score = time.time()
        pipe = client.pipeline()
        for member, _score in rows:
            try:
                vulnerability_id = int(member)
            except (TypeError, ValueError):
                continue
            ids.append(vulnerability_id)
            pipe.zadd(_analysis_running_key(), {str(vulnerability_id): now_score})
        if ids:
            pipe.execute()
        return ids
    except Exception as exc:
        _remember_error(exc)
        return []


def release_analysis(item: dict[str, Any]) -> bool:
    client = _redis_client()
    if client is None:
        return False
    try:
        member = str(int(item["id"]))
        pipe = client.pipeline()
        pipe.zrem(_analysis_running_key(), member)
        pipe.zadd(_analysis_queue_key(), {member: _analysis_score(item)})
        pipe.execute()
        return True
    except Exception as exc:
        _remember_error(exc)
        return False


def finish_analysis(vulnerability_id: int) -> bool:
    client = _redis_client()
    if client is None:
        return False
    try:
        client.zrem(_analysis_running_key(), str(int(vulnerability_id)))
        return True
    except Exception as exc:
        _remember_error(exc)
        return False


def _redis_client() -> Any | None:
    global _client, _last_attempt_at, _last_error
    if not redis_queue_configured():
        return None
    with _client_lock:
        if _client is not None:
            return _client
        now = time.monotonic()
        if _last_error and now - _last_attempt_at < _RECONNECT_BACKOFF_SECONDS:
            return None
        _last_attempt_at = now
        try:
            import redis

            client = redis.Redis.from_url(
                settings.redis_url,
                socket_connect_timeout=2,
                socket_timeout=2,
                health_check_interval=30,
                decode_responses=True,
            )
            client.ping()
            _client = client
            _last_error = ""
            return _client
        except Exception as exc:
            _remember_error(exc)
            return None


def _remember_error(exc: Exception) -> None:
    global _client, _last_error
    _client = None
    _last_error = str(exc)[:500]
    logger.warning("Redis queue unavailable: %s", _last_error)


def _analysis_queue_key() -> str:
    return f"{_prefix()}:analysis:queued"


def _analysis_running_key() -> str:
    return f"{_prefix()}:analysis:running"


def _prefix() -> str:
    raw = str(getattr(settings, "redis_queue_prefix", "") or "zhuwei").strip()
    return raw.strip(":") or "zhuwei"


def _analysis_score(item: dict[str, Any]) -> float:
    priority = _clamp_int(item.get("analysis_priority"), 50, 0, 100)
    requested_at = item.get("analysis_requested_at") or item.get("first_seen_at") or ""
    epoch_ms = _epoch_ms(requested_at) or int(time.time() * 1000)
    return float((100 - priority) * 10_000_000_000_000 + epoch_ms)


def _clamp_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(low, min(high, parsed))


def _epoch_ms(value: Any) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)
