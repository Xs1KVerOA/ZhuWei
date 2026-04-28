from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any


class SourceAdapter(ABC):
    name: str
    title: str
    category: str
    schedule: str

    @abstractmethod
    async def fetch(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def stream_products(self) -> AsyncIterator[list[dict[str, Any]]]:
        """Override to support streaming product ingestion page by page.
        Default returns the full list from fetch_products()."""
        fetch_products = getattr(self, "fetch_products", None)
        if callable(fetch_products):
            products = await fetch_products()
            if products:
                yield products

    def item(
        self,
        *,
        source_uid: str,
        title: str,
        severity: str | None = None,
        cve_id: str | None = None,
        aliases: list[str] | None = None,
        published_at: str | None = None,
        updated_at: str | None = None,
        description: str | None = None,
        url: str | None = None,
        product: str | None = None,
        raw: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "source": self.name,
            "source_uid": source_uid,
            "title": title.strip(),
            "severity": normalize_severity(severity),
            "cve_id": cve_id or "",
            "aliases": aliases or [],
            "published_at": published_at,
            "updated_at": updated_at,
            "description": description,
            "url": url,
            "product": product,
            "raw": raw or {},
        }


def stable_id(*parts: str) -> str:
    payload = "|".join(part or "" for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def normalize_severity(value: str | None) -> str:
    if not value:
        return "unknown"
    text = value.strip().lower()
    mapping = {
        "critical": "critical",
        "极危": "critical",
        "严重": "critical",
        "超危": "critical",
        "紧急": "critical",
        "high": "high",
        "高危": "high",
        "高风险": "high",
        "高": "high",
        "medium": "medium",
        "中危": "medium",
        "中风险": "medium",
        "中": "medium",
        "low": "low",
        "低危": "low",
        "低风险": "low",
        "低": "low",
        "none": "none",
        "暂无": "unknown",
        "未知": "unknown",
    }
    return mapping.get(text, text)


def extract_cve(text: str) -> str:
    import re

    match = re.search(r"CVE-\d{4}-\d{4,}", text or "", flags=re.I)
    return match.group(0).upper() if match else ""


def infer_cn_severity(title: str, description: str = "") -> str:
    text = f"{title} {description}".lower()
    high_keywords = [
        "rce",
        "远程代码执行",
        "代码执行",
        "命令执行",
        "身份认证绕过",
        "认证绕过",
        "未授权",
        "文件上传",
        "getshell",
    ]
    medium_keywords = ["sql 注入", "sql注入", "ssrf", "信息泄露", "路径遍历", "文件读取"]
    if any(keyword in text for keyword in high_keywords):
        return "high"
    if any(keyword in text for keyword in medium_keywords):
        return "medium"
    return "unknown"
