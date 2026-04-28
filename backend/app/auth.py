from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from fastapi import Cookie, Header, HTTPException, Request, Response, status

from .config import settings


SESSION_COOKIE = "zhuwei_session"


def _session_digest() -> str:
    return hmac.new(
        settings.session_secret.encode("utf-8"),
        settings.app_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _extract_bearer(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return token.strip()


def token_is_valid(token: str) -> bool:
    return bool(token) and hmac.compare_digest(token, settings.app_token)


def session_is_valid(session_value: str) -> bool:
    return bool(session_value) and hmac.compare_digest(session_value, _session_digest())


def request_is_authenticated(request: Request) -> bool:
    header_token = request.headers.get("x-app-token", "")
    bearer_token = _extract_bearer(request.headers.get("authorization"))
    cookie_session = request.cookies.get(SESSION_COOKIE, "")
    return (
        token_is_valid(header_token)
        or token_is_valid(bearer_token)
        or session_is_valid(cookie_session)
    )


def require_auth(
    authorization: Optional[str] = Header(default=None),
    x_app_token: Optional[str] = Header(default=None),
    session: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
) -> None:
    if (
        token_is_valid(x_app_token or "")
        or token_is_valid(_extract_bearer(authorization))
        or session_is_valid(session or "")
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="token required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def issue_session_cookie(response: Response) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        _session_digest(),
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 12,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
