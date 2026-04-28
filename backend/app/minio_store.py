from __future__ import annotations

import datetime as dt
import hashlib
import hmac
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlparse

import httpx

from .config import settings


def minio_configured() -> bool:
    return bool(settings.minio_endpoint and settings.minio_access_key and settings.minio_secret_key)


def minio_status() -> dict[str, Any]:
    if not minio_configured():
        return {
            "configured": False,
            "available": False,
            "bucket": settings.minio_bucket,
            "endpoint": settings.minio_endpoint,
            "error": "",
        }
    try:
        client = MinioS3Client()
        client.ensure_bucket()
        return {
            "configured": True,
            "available": True,
            "bucket": settings.minio_bucket,
            "endpoint": client.endpoint,
            "error": "",
        }
    except Exception as exc:
        return {
            "configured": True,
            "available": False,
            "bucket": settings.minio_bucket,
            "endpoint": settings.minio_endpoint,
            "error": str(exc)[:500],
        }


def upload_file(path: Path, object_key: str, *, content_type: str = "application/octet-stream") -> dict[str, str]:
    client = MinioS3Client()
    client.ensure_bucket()
    response = client.put_file(object_key, path, content_type=content_type)
    if response.status_code not in {200, 201, 204}:
        raise RuntimeError(f"MinIO upload failed: HTTP {response.status_code} {response.text[:300]}")
    return {
        "bucket": settings.minio_bucket,
        "object_key": object_key,
        "url": client.object_url(object_key),
    }


def presigned_get_url(object_key: str, *, expires_seconds: int = 900) -> str:
    client = MinioS3Client()
    return client.presigned_get_url(object_key, expires_seconds=expires_seconds)


def delete_object(object_key: str) -> bool:
    client = MinioS3Client()
    response = client.delete_object(object_key)
    if response.status_code in {200, 204, 404}:
        return response.status_code != 404
    raise RuntimeError(f"MinIO delete failed: HTTP {response.status_code} {response.text[:300]}")


class MinioS3Client:
    def __init__(self) -> None:
        if not minio_configured():
            raise RuntimeError("MinIO is not configured")
        endpoint = settings.minio_endpoint.strip()
        if "://" not in endpoint:
            endpoint = ("https://" if settings.minio_secure else "http://") + endpoint
        self.endpoint = endpoint.rstrip("/")
        self.region = settings.minio_region
        self.bucket = settings.minio_bucket
        parsed = urlparse(self.endpoint)
        self.host = parsed.netloc

    def ensure_bucket(self) -> None:
        head = self._request("HEAD", f"/{self.bucket}")
        if head.status_code in {200, 204}:
            return
        put = self._request("PUT", f"/{self.bucket}")
        if put.status_code in {200, 201, 204, 409}:
            return
        raise RuntimeError(f"MinIO bucket check failed: HTTP {put.status_code} {put.text[:300]}")

    def put_object(self, object_key: str, body: bytes, *, content_type: str) -> httpx.Response:
        safe_key = "/".join(part for part in object_key.split("/") if part)
        return self._request(
            "PUT",
            f"/{self.bucket}/{safe_key}",
            body=body,
            extra_headers={"content-type": content_type or "application/octet-stream"},
        )

    def put_file(self, object_key: str, path: Path, *, content_type: str) -> httpx.Response:
        safe_key = "/".join(part for part in object_key.split("/") if part)
        payload_hash, size = _file_sha256_and_size(path)
        return self._request(
            "PUT",
            f"/{self.bucket}/{safe_key}",
            body=_file_chunks(path),
            payload_hash=payload_hash,
            content_length=size,
            extra_headers={"content-type": content_type or "application/octet-stream"},
        )

    def object_url(self, object_key: str) -> str:
        path = quote(f"/{self.bucket}/{object_key}", safe="/-_.~")
        return f"{self.endpoint}{path}"

    def presigned_get_url(self, object_key: str, *, expires_seconds: int = 900) -> str:
        safe_key = "/".join(part for part in object_key.split("/") if part)
        expires = max(1, min(int(expires_seconds or 900), 604800))
        now = dt.datetime.now(dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        credential_scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        canonical_uri = quote(f"/{self.bucket}/{safe_key}", safe="/-_.~")
        query = {
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": f"{settings.minio_access_key}/{credential_scope}",
            "X-Amz-Date": amz_date,
            "X-Amz-Expires": str(expires),
            "X-Amz-SignedHeaders": "host",
        }
        canonical_query = urlencode(sorted(query.items()), quote_via=quote, safe="-_.~")
        canonical_headers = f"host:{self.host}\n"
        canonical_request = "\n".join(
            [
                "GET",
                canonical_uri,
                canonical_query,
                canonical_headers,
                "host",
                "UNSIGNED-PAYLOAD",
            ]
        )
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signing_key = _signing_key(settings.minio_secret_key, date_stamp, self.region)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{self.endpoint}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}"

    def delete_object(self, object_key: str) -> httpx.Response:
        safe_key = "/".join(part for part in object_key.split("/") if part)
        return self._request("DELETE", f"/{self.bucket}/{safe_key}")

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | Iterator[bytes] = b"",
        payload_hash: str | None = None,
        content_length: int | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        now = dt.datetime.now(dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        if payload_hash is None:
            if not isinstance(body, bytes):
                raise ValueError("payload_hash is required for streaming request bodies")
            payload_hash = hashlib.sha256(body).hexdigest()
        headers = {
            "host": self.host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
            **{k.lower(): v for k, v in (extra_headers or {}).items()},
        }
        if content_length is not None:
            headers["content-length"] = str(max(0, int(content_length)))
        canonical_uri = quote(path, safe="/-_.~")
        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in sorted(headers))
        canonical_request = "\n".join(
            [
                method.upper(),
                canonical_uri,
                "",
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )
        credential_scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signing_key = _signing_key(settings.minio_secret_key, date_stamp, self.region)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            "AWS4-HMAC-SHA256 "
            f"Credential={settings.minio_access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        url = f"{self.endpoint}{canonical_uri}"
        with httpx.Client(timeout=30) as client:
            return client.request(method.upper(), url, content=body, headers=headers)


def _signing_key(secret_key: str, date_stamp: str, region: str) -> bytes:
    key = ("AWS4" + secret_key).encode("utf-8")
    for value in [date_stamp, region, "s3", "aws4_request"]:
        key = hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()
    return key


def _file_sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _file_chunks(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            yield chunk
