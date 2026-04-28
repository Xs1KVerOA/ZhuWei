from __future__ import annotations

from typing import Any

import httpx

from ..config import settings
from .base import SourceAdapter


class GitHubSecurityAdvisoriesAdapter(SourceAdapter):
    name = "github_advisories"
    title = "GitHub Security Advisories"
    category = "regular"
    schedule = "every 30 minutes"
    alert_enabled = False
    github_evidence_auto_search = False

    url = "https://api.github.com/advisories"

    def __init__(self) -> None:
        self.last_warning = ""

    async def fetch(self) -> list[dict[str, Any]]:
        self.last_warning = ""
        headers = _github_headers()
        items: list[dict[str, Any]] = []
        async with httpx.AsyncClient(
            timeout=settings.github_search_timeout_seconds,
            follow_redirects=True,
            headers=headers,
        ) as client:
            for page in range(1, settings.github_advisory_max_pages + 1):
                response = await client.get(
                    self.url,
                    params={
                        "per_page": settings.github_advisory_page_size,
                        "page": page,
                        "sort": "updated",
                        "direction": "desc",
                    },
                )
                if response.status_code == 403:
                    self.last_warning = _github_rate_warning(response)
                    break
                response.raise_for_status()
                advisories = response.json()
                if not isinstance(advisories, list) or not advisories:
                    break
                items.extend(_advisory_item(self, advisory) for advisory in advisories if isinstance(advisory, dict))
        return items


def _github_headers(*, text_matches: bool = False) -> dict[str, str]:
    accept = "application/vnd.github.text-match+json" if text_matches else "application/vnd.github+json"
    headers = {
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": settings.github_user_agent,
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


def _github_rate_warning(response: httpx.Response) -> str:
    remaining = response.headers.get("X-RateLimit-Remaining", "")
    reset = response.headers.get("X-RateLimit-Reset", "")
    if remaining == "0":
        return f"GitHub API rate limit reached; reset={reset or 'unknown'}"
    return f"GitHub API returned 403: {response.text[:200]}"


def _advisory_item(adapter: GitHubSecurityAdvisoriesAdapter, advisory: dict[str, Any]) -> dict[str, Any]:
    ghsa_id = str(advisory.get("ghsa_id") or "").strip()
    cve_id = str(advisory.get("cve_id") or "").strip().upper()
    aliases = [str(alias).strip().upper() for alias in advisory.get("aliases") or [] if str(alias).strip()]
    if cve_id and cve_id not in aliases:
        aliases.append(cve_id)
    if ghsa_id and ghsa_id not in aliases:
        aliases.append(ghsa_id)
    summary = str(advisory.get("summary") or ghsa_id or "GitHub Security Advisory").strip()
    product = _primary_package(advisory)
    html_url = str(advisory.get("html_url") or advisory.get("url") or "").strip()
    source_uid = ghsa_id or cve_id or html_url
    references = advisory.get("references") if isinstance(advisory.get("references"), list) else []
    raw = {
        "github_advisory": _sanitized_advisory(advisory),
        "github_evidence": {
            "type": "advisory",
            "artifact_kind": "advisory",
            "url": html_url,
            "score": 92,
            "confidence": "high",
            "references": references,
        },
    }
    return adapter.item(
        source_uid=source_uid,
        title=summary,
        severity=str(advisory.get("severity") or "unknown"),
        cve_id=cve_id,
        aliases=aliases,
        published_at=_date(advisory.get("published_at")),
        updated_at=_date(advisory.get("updated_at")),
        description=str(advisory.get("description") or summary),
        url=html_url or None,
        product=product,
        raw=raw,
    )


def _date(value: Any) -> str:
    return str(value or "")[:10]


def _primary_package(advisory: dict[str, Any]) -> str:
    packages: list[str] = []
    for vuln in advisory.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        package = vuln.get("package") if isinstance(vuln.get("package"), dict) else {}
        name = str(package.get("name") or "").strip()
        ecosystem = str(package.get("ecosystem") or "").strip()
        if name:
            packages.append(f"{ecosystem}:{name}" if ecosystem else name)
    return packages[0] if packages else ""


def _sanitized_advisory(advisory: dict[str, Any]) -> dict[str, Any]:
    vulnerabilities = []
    for vuln in advisory.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        package = vuln.get("package") if isinstance(vuln.get("package"), dict) else {}
        vulnerabilities.append(
            {
                "package": {
                    "ecosystem": package.get("ecosystem"),
                    "name": package.get("name"),
                },
                "vulnerable_version_range": vuln.get("vulnerable_version_range"),
                "patched_versions": vuln.get("patched_versions"),
                "vulnerable_functions": vuln.get("vulnerable_functions") or [],
            }
        )
    return {
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_id": advisory.get("cve_id"),
        "aliases": advisory.get("aliases") or [],
        "summary": advisory.get("summary"),
        "description": advisory.get("description"),
        "severity": advisory.get("severity"),
        "published_at": advisory.get("published_at"),
        "updated_at": advisory.get("updated_at"),
        "html_url": advisory.get("html_url"),
        "references_count": len(advisory.get("references") or []),
        "vulnerabilities": vulnerabilities,
    }
