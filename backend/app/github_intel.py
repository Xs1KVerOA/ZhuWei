from __future__ import annotations

import asyncio
import math
import re
from typing import Any

import httpx

from . import db
from .config import settings


GITHUB_API = "https://api.github.com"
POC_WORDS = {"poc", "proof-of-concept", "proof_of_concept", "proof of concept", "复现"}
EXP_WORDS = {"exp", "exploit", "exploits", "metasploit", "weaponized", "利用"}


class GitHubSearchError(RuntimeError):
    pass


async def enrich_items_with_github_evidence(items: list[dict[str, Any]]) -> dict[str, Any]:
    if not settings.github_evidence_enabled or not settings.github_evidence_auto_search_enabled:
        return {"status": "disabled", "checked": 0, "changed": 0, "warning": ""}
    budget = settings.github_evidence_auto_search_per_run
    if budget <= 0:
        return {"status": "disabled", "checked": 0, "changed": 0, "warning": ""}

    checked = 0
    changed = 0
    warning = ""
    seen: set[int] = set()
    for item in items:
        vulnerability = await asyncio.to_thread(db.get_vulnerability_for_item, item)
        if not vulnerability:
            continue
        vulnerability_id = int(vulnerability["id"])
        if vulnerability_id in seen:
            continue
        seen.add(vulnerability_id)

        advisory_result = await asyncio.to_thread(_persist_advisory_evidence, vulnerability)
        changed += int(advisory_result.get("changed") or 0)

        if checked >= budget:
            continue
        if not await asyncio.to_thread(
            db.github_evidence_needs_refresh,
            vulnerability_id,
            settings.github_evidence_refresh_hours,
        ):
            continue
        try:
            result = await refresh_github_evidence_for_vulnerability(vulnerability_id, force=True)
        except GitHubSearchError as exc:
            warning = str(exc)
            break
        checked += 1
        changed += int(result.get("changed") or 0)
    return {"status": "ok", "checked": checked, "changed": changed, "warning": warning}


async def refresh_github_evidence_for_vulnerability(
    vulnerability_id: int,
    *,
    force: bool = False,
) -> dict[str, Any]:
    vulnerability = await asyncio.to_thread(db.get_vulnerability, vulnerability_id)
    if not vulnerability:
        raise KeyError("vulnerability not found")
    if not force and not await asyncio.to_thread(
        db.github_evidence_needs_refresh,
        vulnerability_id,
        settings.github_evidence_refresh_hours,
    ):
        return {
            "status": "cached",
            "changed": 0,
            "summary": vulnerability.get("github_evidence_summary") or {},
        }

    advisory_result = await asyncio.to_thread(_persist_advisory_evidence, vulnerability)
    target = _search_target(vulnerability)
    if not target:
        checked = await asyncio.to_thread(db.mark_github_evidence_checked, vulnerability_id, "no strong GitHub search target")
        return {"status": "skipped", "changed": advisory_result.get("changed", 0), "summary": checked.get("summary", {})}

    evidence = await _search_github_evidence(vulnerability, target)
    result = await asyncio.to_thread(db.upsert_github_evidence, vulnerability_id, evidence, mark_checked=True)
    result["changed"] = int(result.get("changed") or 0) + int(advisory_result.get("changed") or 0)
    result["status"] = "ok"
    result["target"] = target
    return result


async def refresh_recent_github_evidence(limit: int = 20) -> dict[str, Any]:
    vulnerabilities = await asyncio.to_thread(db.recent_vulnerabilities_for_github_evidence, limit)
    checked = 0
    changed = 0
    warning = ""
    for vulnerability in vulnerabilities:
        try:
            result = await refresh_github_evidence_for_vulnerability(int(vulnerability["id"]), force=True)
        except GitHubSearchError as exc:
            warning = str(exc)
            break
        checked += 1
        changed += int(result.get("changed") or 0)
    return {"status": "partial" if warning else "ok", "checked": checked, "changed": changed, "warning": warning}


async def _search_github_evidence(vulnerability: dict[str, Any], target: str) -> list[dict[str, Any]]:
    headers = _github_headers()
    timeout = settings.github_search_timeout_seconds
    limit = settings.github_evidence_search_max_results
    evidence: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        repo_queries = [
            f'"{target}" poc',
            f'"{target}" exploit',
        ]
        for query in repo_queries:
            payload = await _github_get(
                client,
                "/search/repositories",
                {"q": query, "sort": "updated", "order": "desc", "per_page": max(1, limit // 2)},
            )
            evidence.extend(_repo_evidence(vulnerability, target, query, payload.get("items") or []))
            await asyncio.sleep(0.15)

        if settings.github_token:
            code_query = f'"{target}" in:file'
            payload = await _github_get(
                client,
                "/search/code",
                {"q": code_query, "sort": "indexed", "order": "desc", "per_page": limit},
                text_matches=True,
            )
            evidence.extend(_code_evidence(vulnerability, target, code_query, payload.get("items") or []))
    return _dedupe_evidence(evidence)[: max(limit * 3, 10)]


async def _github_get(
    client: httpx.AsyncClient,
    path: str,
    params: dict[str, Any],
    *,
    text_matches: bool = False,
) -> dict[str, Any]:
    headers = _github_headers(text_matches=text_matches)
    response = await client.get(f"{GITHUB_API}{path}", params=params, headers=headers)
    if response.status_code == 403:
        remaining = response.headers.get("X-RateLimit-Remaining", "")
        reset = response.headers.get("X-RateLimit-Reset", "")
        message = f"GitHub Search API 受限：remaining={remaining or '?'} reset={reset or '?'}"
        raise GitHubSearchError(message)
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


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


def _repo_evidence(
    vulnerability: dict[str, Any],
    target: str,
    query: str,
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results = []
    for repo in items:
        full_name = str(repo.get("full_name") or "").strip()
        description = str(repo.get("description") or "").strip()
        html_url = str(repo.get("html_url") or "").strip()
        text = " ".join([full_name, description, html_url, query]).lower()
        if target.lower() not in text:
            continue
        kind = _artifact_kind(text)
        score = _repo_score(repo, text, kind)
        results.append(
            {
                "cve_id": vulnerability.get("cve_id") or target,
                "query": query,
                "evidence_type": "repository",
                "artifact_kind": kind,
                "title": full_name or html_url,
                "url": html_url,
                "repository": full_name,
                "path": "",
                "snippet": description,
                "score": score,
                "confidence": _confidence(score),
                "source_api": "github_repo_search",
                "raw": _safe_repo_raw(repo),
            }
        )
    return results


def _code_evidence(
    vulnerability: dict[str, Any],
    target: str,
    query: str,
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results = []
    for item in items:
        repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
        repo_name = str(repo.get("full_name") or "").strip()
        path = str(item.get("path") or "").strip()
        html_url = str(item.get("html_url") or "").strip()
        text_matches = item.get("text_matches") if isinstance(item.get("text_matches"), list) else []
        snippet = _text_match_fragment(text_matches)
        text = " ".join([repo_name, path, html_url, snippet]).lower()
        if target.lower() not in text and target.lower() not in snippet.lower():
            continue
        kind = _artifact_kind(text)
        score = _code_score(path, text, kind)
        results.append(
            {
                "cve_id": vulnerability.get("cve_id") or target,
                "query": query,
                "evidence_type": "code",
                "artifact_kind": kind,
                "title": f"{repo_name}/{path}".strip("/"),
                "url": html_url,
                "repository": repo_name,
                "path": path,
                "snippet": snippet,
                "score": score,
                "confidence": _confidence(score),
                "source_api": "github_code_search",
                "raw": {
                    "name": item.get("name"),
                    "path": path,
                    "repository": _safe_repo_raw(repo),
                    "sha": item.get("sha"),
                },
            }
        )
    return results


def _persist_advisory_evidence(vulnerability: dict[str, Any]) -> dict[str, Any]:
    raw = vulnerability.get("raw") if isinstance(vulnerability.get("raw"), dict) else {}
    advisory = raw.get("github_advisory") if isinstance(raw.get("github_advisory"), dict) else {}
    evidence_raw = raw.get("github_evidence") if isinstance(raw.get("github_evidence"), dict) else {}
    if not advisory and not evidence_raw:
        return {"status": "skipped", "changed": 0}
    html_url = str(advisory.get("html_url") or advisory.get("url") or evidence_raw.get("url") or vulnerability.get("url") or "").strip()
    if not html_url:
        return {"status": "skipped", "changed": 0}
    score = 92 if advisory else 75
    evidence = [
        {
            "cve_id": vulnerability.get("cve_id") or "",
            "query": vulnerability.get("cve_id") or vulnerability.get("title") or "",
            "evidence_type": "advisory",
            "artifact_kind": "advisory",
            "title": advisory.get("summary") or vulnerability.get("title") or "GitHub Security Advisory",
            "url": html_url,
            "repository": "",
            "path": "",
            "snippet": advisory.get("description") or "",
            "score": score,
            "confidence": "high" if score >= 78 else "medium",
            "source_api": "github_security_advisory",
            "raw": {"github_advisory": advisory or evidence_raw},
        }
    ]
    return db.upsert_github_evidence(int(vulnerability["id"]), evidence, mark_checked=False)


def _search_target(vulnerability: dict[str, Any]) -> str:
    cve = str(vulnerability.get("cve_id") or "").strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        return cve
    aliases = vulnerability.get("aliases") if isinstance(vulnerability.get("aliases"), list) else []
    for alias in aliases:
        text = str(alias or "").strip().upper()
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", text) or text.startswith("GHSA-"):
            return text
    return ""


def _artifact_kind(text: str) -> str:
    lowered = text.lower()
    if any(word in lowered for word in EXP_WORDS):
        return "exp"
    if any(word in lowered for word in POC_WORDS):
        return "poc"
    return "unknown"


def _repo_score(repo: dict[str, Any], text: str, kind: str) -> float:
    stars = int(repo.get("stargazers_count") or 0)
    forks = int(repo.get("forks_count") or 0)
    score = 42
    if kind == "exp":
        score += 20
    elif kind == "poc":
        score += 16
    if any(token in text for token in ["cve-", "ghsa-", "vulnerability"]):
        score += 8
    if any(token in text for token in ["nuclei", "metasploit", "scanner", "exploit"]):
        score += 7
    score += min(10, math.log10(stars + 1) * 4)
    score += min(5, math.log10(forks + 1) * 2)
    if repo.get("archived"):
        score -= 8
    return round(max(20, min(score, 88)), 1)


def _code_score(path: str, text: str, kind: str) -> float:
    score = 48
    if kind == "exp":
        score += 24
    elif kind == "poc":
        score += 18
    lowered_path = path.lower()
    if lowered_path.endswith((".py", ".rb", ".go", ".js", ".ts", ".sh", ".java", ".php", ".yaml", ".yml")):
        score += 8
    if any(token in lowered_path for token in ["test", "docs", "readme"]):
        score -= 7
    if any(token in text for token in ["curl", "payload", "reverse shell", "metasploit", "nuclei"]):
        score += 8
    return round(max(20, min(score, 92)), 1)


def _confidence(score: float) -> str:
    if score >= 78:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def _text_match_fragment(matches: list[dict[str, Any]]) -> str:
    fragments = []
    for item in matches[:3]:
        fragment = str(item.get("fragment") or "").strip()
        if fragment:
            fragments.append(fragment)
    return "\n".join(fragments)[:4000]


def _safe_repo_raw(repo: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": repo.get("id"),
        "full_name": repo.get("full_name"),
        "html_url": repo.get("html_url"),
        "description": repo.get("description"),
        "stargazers_count": repo.get("stargazers_count"),
        "forks_count": repo.get("forks_count"),
        "updated_at": repo.get("updated_at"),
        "pushed_at": repo.get("pushed_at"),
        "archived": repo.get("archived"),
    }


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        key = (str(item.get("url") or ""), str(item.get("path") or ""))
        if key not in best or float(item.get("score") or 0) > float(best[key].get("score") or 0):
            best[key] = item
    return sorted(best.values(), key=lambda item: float(item.get("score") or 0), reverse=True)
