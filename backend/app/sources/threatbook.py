from __future__ import annotations

import httpx

from .base import SourceAdapter, extract_cve, normalize_severity


class ThreatbookVulnAdapter(SourceAdapter):
    name = "threatbook_vuln"
    title = "ThreatBook Vulnerability"
    category = "regular"
    schedule = "every 30 minutes"

    url = "https://x.threatbook.com/v5/node/vul_module/homePage"

    async def fetch(self) -> list[dict]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": "https://x.threatbook.com/v5/vulIntelligence",
            "User-Agent": _chrome_ua(),
        }
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            payload = response.json()

        items = []
        for entry in payload.get("data", {}).get("highrisk", []):
            title = entry.get("vuln_name_zh") or entry.get("id")
            affects = _affects_list(entry.get("affects"))
            tags = []
            if entry.get("is0day"):
                tags.append("0day")
            if entry.get("pocExist"):
                tags.append("有POC")
            if entry.get("premium"):
                tags.append("有漏洞分析")
            if entry.get("solution"):
                tags.append("有修复方案")
            severity = normalize_severity(entry.get("riskLevel") or "critical")
            items.append(
                self.item(
                    source_uid=entry.get("id"),
                    title=title,
                    severity=severity if severity != "unknown" else "critical",
                    cve_id=extract_cve(title),
                    aliases=[entry.get("id")],
                    published_at=entry.get("vuln_publish_time") or entry.get("vuln_update_time"),
                    updated_at=entry.get("vuln_update_time"),
                    description=", ".join(affects),
                    url=f"https://x.threatbook.com/v5/vul/{entry.get('id')}",
                    product=_product_from_affects(affects),
                    raw={**entry, "tags": tags},
                )
            )
        return items


def _affects_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return []


def _product_from_affects(affects: list[str]) -> str:
    for value in affects:
        text = str(value or "").strip()
        if not text:
            continue
        label = text.rsplit(">", 1)[-1].strip()
        if label.lower() == "litellm":
            return "LiteLLM"
        if label:
            return label
    return ""


def _chrome_ua() -> str:
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )
