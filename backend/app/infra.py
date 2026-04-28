from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import settings
from .minio_store import minio_status
from .neo4j_graph import graph_status
from .redis_queue import redis_queue_status


def infrastructure_status() -> dict[str, Any]:
    postgres = _postgres_status(settings.database_url)
    redis = _redis_status(settings.redis_url)
    return {
        "active_database_backend": settings.database_backend or "sqlite",
        "sqlite": {
            "configured": True,
            "path": _display_path(settings.database_path),
            "exists": settings.database_path.exists(),
            "size_bytes": _file_size(settings.database_path),
            "active": (settings.database_backend or "sqlite") == "sqlite",
        },
        "postgres": postgres,
        "redis": redis,
        "minio": minio_status(),
        "neo4j": graph_status(),
        "queue": redis_queue_status(),
        "worker_role": settings.worker_role,
        "will_switch_on_restart": False,
    }


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _display_path(path: Path) -> str:
    try:
        resolved = path.resolve()
        project = settings.database_path.parents[1].resolve()
        if resolved == project:
            return "."
        if _path_is_relative_to(resolved, project):
            return str(resolved.relative_to(project))
        home = Path.home().resolve()
        if resolved == home:
            return "~"
        if _path_is_relative_to(resolved, home):
            return "~/" + str(resolved.relative_to(home))
    except OSError:
        pass
    return str(path)


def _path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _postgres_status(url: str) -> dict[str, Any]:
    if not url:
        return {"configured": False, "available": False, "error": ""}
    try:
        import psycopg

        with psycopg.connect(url, connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_database(), current_user, version()")
                database, user, version = cur.fetchone()
        return {
            "configured": True,
            "available": True,
            "database": database,
            "user": user,
            "version": str(version).splitlines()[0],
            "active": (settings.database_backend or "sqlite") == "postgresql",
            "error": "",
        }
    except Exception as exc:
        return {
            "configured": True,
            "available": False,
            "active": False,
            "error": str(exc)[:500],
        }


def _redis_status(url: str) -> dict[str, Any]:
    if not url:
        return {"configured": False, "available": False, "error": ""}
    try:
        import redis

        client = redis.Redis.from_url(
            url,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=True,
        )
        pong = client.ping()
        info = client.info(section="server")
        return {
            "configured": True,
            "available": bool(pong),
            "version": info.get("redis_version", ""),
            "active": bool(url),
            "error": "",
        }
    except Exception as exc:
        return {
            "configured": True,
            "available": False,
            "active": False,
            "error": str(exc)[:500],
        }
