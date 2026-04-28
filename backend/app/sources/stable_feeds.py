from __future__ import annotations

from datetime import datetime
from email.utils import parsedate_to_datetime
import re
from typing import Any
from urllib.parse import urljoin
from xml.etree import ElementTree

from bs4 import BeautifulSoup
import httpx

from ..config import settings
from .base import SourceAdapter, extract_cve, infer_cn_severity, stable_id
from .github import _github_headers, _github_rate_warning


class SploitusRssAdapter(SourceAdapter):
    name = "sploitus_rss"
    title = "Sploitus RSS"
    category = "regular"
    schedule = "every 30 minutes"
    alert_enabled = False
    github_evidence_auto_search = False
    enabled_by_default = False

    url = "https://sploitus.com/rss"

    def __init__(self) -> None:
        self.last_warning = ""

    async def fetch(self) -> list[dict[str, Any]]:
        self.last_warning = ""
        entries = await _fetch_rss_entries(self, self.url)
        return [_rss_item(self, entry, artifact_kind="exploit") for entry in entries]


class CxsecurityRssAdapter(SourceAdapter):
    name = "cxsecurity_wlb_rss"
    title = "CXSecurity WLB RSS"
    category = "regular"
    schedule = "every 30 minutes"
    alert_enabled = False
    github_evidence_auto_search = False
    enabled_by_default = False

    url = "https://cxsecurity.com/wlb/rss/all/"

    def __init__(self) -> None:
        self.last_warning = ""

    async def fetch(self) -> list[dict[str, Any]]:
        self.last_warning = ""
        entries = await _fetch_rss_entries(self, self.url)
        return [_rss_item(self, entry, artifact_kind="exploit") for entry in entries]


class GobyVulsGitHubAdapter(SourceAdapter):
    name = "goby_vuls_github"
    title = "GobyVuls GitHub"
    category = "regular"
    schedule = "every 30 minutes"
    alert_enabled = False
    github_evidence_auto_search = False

    repo = "gobysec/GobyVuls"
    url = f"https://api.github.com/repos/{repo}/commits"
    max_commits = 12
    max_items = 60

    def __init__(self) -> None:
        self.last_warning = ""

    async def fetch(self) -> list[dict[str, Any]]:
        self.last_warning = ""
        headers = _github_headers()
        timeout = settings.github_search_timeout_seconds
        items: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
            response = await client.get(self.url, params={"per_page": self.max_commits})
            if response.status_code == 403:
                self.last_warning = _github_rate_warning(response)
                return []
            response.raise_for_status()
            commits = response.json()
            if not isinstance(commits, list):
                return []
            for commit in commits:
                if not isinstance(commit, dict):
                    continue
                detail_url = str(commit.get("url") or "").strip()
                if not detail_url:
                    continue
                detail = await client.get(detail_url)
                if detail.status_code == 403:
                    self.last_warning = _github_rate_warning(detail)
                    break
                detail.raise_for_status()
                payload = detail.json()
                if not isinstance(payload, dict):
                    continue
                for file_info in payload.get("files") or []:
                    if not isinstance(file_info, dict):
                        continue
                    path = str(file_info.get("filename") or "").strip()
                    if not path.lower().endswith(".md") or path in seen_paths:
                        continue
                    if str(file_info.get("status") or "").lower() == "removed":
                        continue
                    seen_paths.add(path)
                    item = _goby_file_item(self, payload, file_info)
                    if item:
                        items.append(item)
                    if len(items) >= self.max_items:
                        return items
        return items


class GitHubSecurityLabAdvisoriesAdapter(SourceAdapter):
    name = "github_security_lab"
    title = "GitHub Security Lab Advisories"
    category = "regular"
    schedule = "every 30 minutes"
    alert_enabled = False
    github_evidence_auto_search = False

    url = "https://securitylab.github.com/advisories/"
    max_items = 40

    def __init__(self) -> None:
        self.last_warning = ""

    async def fetch(self) -> list[dict[str, Any]]:
        self.last_warning = ""
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml",
            "User-Agent": settings.github_user_agent,
        }
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
                response = await client.get(self.url)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.last_warning = f"{self.title} 暂不可达：{_http_error_text(exc)}"
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        items: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        for card in soup.select(".disclosure-year-item"):
            link_node = card.select_one(".post-title a[href]") or card.select_one("a[href*='/advisories/']")
            if link_node is None:
                continue
            url = urljoin(self.url, str(link_node.get("href") or ""))
            if url in seen_urls:
                continue
            seen_urls.add(url)
            title = _clean_text(link_node.get_text(" ", strip=True))
            description_node = card.select_one(".post-description")
            description = _clean_text(description_node.get_text(" ", strip=True) if description_node else "")
            date_node = card.select_one(".post-date span") or card.select_one(".post-date")
            published_at = _parse_date(date_node.get_text(" ", strip=True) if date_node else "")
            cve = extract_cve(f"{title} {description}")
            ghsl = _extract_ghsl_id(title) or _extract_ghsl_id(url)
            aliases = [alias for alias in [cve, ghsl] if alias]
            raw = {
                "title": title,
                "description": description,
                "link": url,
                "source_page": self.url,
                "github_evidence": {
                    "type": "advisory",
                    "artifact_kind": "security_lab_advisory",
                    "url": url,
                    "score": 94,
                    "confidence": "high",
                    "source": self.title,
                },
            }
            items.append(
                self.item(
                    source_uid=stable_id(self.name, url),
                    title=title,
                    severity=_infer_severity(title, description),
                    cve_id=cve,
                    aliases=aliases,
                    published_at=published_at,
                    description=description or title,
                    url=url,
                    product=_infer_product(title, description),
                    raw=raw,
                )
            )
            if len(items) >= self.max_items:
                break
        return items


async def _fetch_rss_entries(adapter: SourceAdapter, url: str) -> list[dict[str, str]]:
    headers = {
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
        "User-Agent": _browser_ua(),
    }
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.get(url)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        setattr(adapter, "last_warning", f"{adapter.title} 暂不可达：{_http_error_text(exc)}")
        return []

    try:
        root = ElementTree.fromstring(response.content)
    except ElementTree.ParseError as exc:
        setattr(adapter, "last_warning", f"{adapter.title} RSS 解析失败：{exc}")
        return []
    return list(_iter_feed_entries(root))


def _iter_feed_entries(root: ElementTree.Element) -> list[dict[str, str]]:
    rss_items = root.findall("./channel/item")
    if rss_items:
        return [
            {
                "title": _xml_text(node, "title"),
                "link": _xml_text(node, "link"),
                "description": _xml_text_any(node, {"description", "encoded", "summary", "content"}),
                "published_at": _parse_date(_xml_text(node, "pubDate") or _xml_text(node, "date")),
                "category": _xml_text(node, "category"),
                "guid": _xml_text(node, "guid"),
            }
            for node in rss_items
        ]

    entries: list[dict[str, str]] = []
    for node in root.findall(".//{http://www.w3.org/2005/Atom}entry"):
        link = ""
        for child in node.findall("{http://www.w3.org/2005/Atom}link"):
            rel = str(child.attrib.get("rel") or "alternate")
            if rel == "alternate":
                link = str(child.attrib.get("href") or "")
                break
        entries.append(
            {
                "title": _xml_text_ns(node, "title"),
                "link": link,
                "description": _xml_text_ns(node, "summary") or _xml_text_ns(node, "content"),
                "published_at": _parse_date(_xml_text_ns(node, "published") or _xml_text_ns(node, "updated")),
                "category": "",
                "guid": _xml_text_ns(node, "id"),
            }
        )
    return entries


def _rss_item(adapter: SourceAdapter, entry: dict[str, str], *, artifact_kind: str) -> dict[str, Any]:
    title = _clean_text(entry.get("title") or "Untitled vulnerability")
    link = (entry.get("link") or "").strip()
    description = _clean_text(entry.get("description") or "")
    category = _clean_text(entry.get("category") or "")
    published_at = entry.get("published_at") or ""
    cve = extract_cve(f"{title} {description} {category}")
    aliases = [cve] if cve else []
    raw: dict[str, Any] = {
        "title": title,
        "link": link,
        "description": description,
        "category": category,
        "guid": entry.get("guid") or "",
        "source_feed": getattr(adapter, "url", ""),
        "github_evidence": {
            "type": "external_feed",
            "artifact_kind": artifact_kind,
            "url": link,
            "score": 76,
            "confidence": "medium",
            "source": adapter.title,
        },
    }
    if artifact_kind == "exploit" and link:
        raw["exploit_url"] = link
        raw["exploit_reference"] = {
            "source": adapter.title,
            "url": link,
        }
    return adapter.item(
        source_uid=stable_id(adapter.name, entry.get("guid") or "", title, link, published_at),
        title=title,
        severity=_infer_severity(title, description),
        cve_id=cve,
        aliases=aliases,
        published_at=published_at,
        description=description or category or title,
        url=link or None,
        product=_infer_product(title, description),
        raw=raw,
    )


def _goby_file_item(
    adapter: GobyVulsGitHubAdapter,
    commit_payload: dict[str, Any],
    file_info: dict[str, Any],
) -> dict[str, Any] | None:
    path = str(file_info.get("filename") or "").strip()
    if not path:
        return None
    commit = commit_payload.get("commit") if isinstance(commit_payload.get("commit"), dict) else {}
    author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
    published_at = _parse_date(str(author.get("date") or ""))
    message = str(commit.get("message") or "").strip()
    patch = str(file_info.get("patch") or "")
    title = _markdown_title_from_patch(patch) or _filename_title(path) or message.splitlines()[0]
    description = _markdown_excerpt(patch) or message
    cve = extract_cve(f"{title} {description} {path}")
    aliases = [alias for alias in [cve, _short_sha(commit_payload.get("sha"))] if alias]
    blob_url = str(file_info.get("blob_url") or "").strip()
    raw_url = str(file_info.get("raw_url") or "").strip()
    raw = {
        "repository": adapter.repo,
        "path": path,
        "commit_sha": str(commit_payload.get("sha") or ""),
        "commit_url": str(commit_payload.get("html_url") or ""),
        "blob_url": blob_url,
        "raw_url": raw_url,
        "description": description,
        "github_evidence": {
            "type": "repository_document",
            "artifact_kind": "vulnerability_document",
            "url": blob_url or raw_url,
            "score": 84,
            "confidence": "medium",
            "repository": adapter.repo,
            "path": path,
        },
        "source_repositories": [
            {
                "name": adapter.repo,
                "url": f"https://github.com/{adapter.repo}",
                "local_path": "",
            }
        ],
    }
    return adapter.item(
        source_uid=stable_id(adapter.name, path),
        title=_clean_text(title),
        severity=_infer_severity(title, description),
        cve_id=cve,
        aliases=aliases,
        published_at=published_at,
        updated_at=published_at,
        description=_clean_text(description),
        url=blob_url or raw_url or f"https://github.com/{adapter.repo}",
        product=_infer_product(title, description),
        raw=raw,
    )


def _xml_text(node: ElementTree.Element, tag: str) -> str:
    child = node.find(tag)
    return "" if child is None or child.text is None else child.text.strip()


def _xml_text_ns(node: ElementTree.Element, local_name: str) -> str:
    child = node.find(f"{{http://www.w3.org/2005/Atom}}{local_name}")
    return "" if child is None or child.text is None else child.text.strip()


def _xml_text_any(node: ElementTree.Element, names: set[str]) -> str:
    for child in list(node):
        local = child.tag.rsplit("}", 1)[-1]
        if local in names and child.text:
            return child.text.strip()
    return ""


def _parse_date(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    for parser in (
        lambda raw: datetime.fromisoformat(raw.replace("Z", "+00:00")),
        parsedate_to_datetime,
        lambda raw: datetime.strptime(raw, "%B %d, %Y"),
        lambda raw: datetime.strptime(raw, "%b %d, %Y"),
    ):
        try:
            parsed = parser(text)
        except (TypeError, ValueError, OverflowError):
            continue
        return parsed.date().isoformat()
    return text[:40]


def _clean_text(value: str, *, max_length: int = 2000) -> str:
    raw = value or ""
    if "<" in raw and ">" in raw:
        text = BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)
    else:
        text = raw
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_length]


def _markdown_title_from_patch(patch: str) -> str:
    for raw_line in (patch or "").splitlines():
        line = raw_line.lstrip("+").strip()
        match = re.match(r"#{1,3}\s+(.+)", line)
        if match:
            return match.group(1).strip()
    return ""


def _markdown_excerpt(patch: str) -> str:
    lines: list[str] = []
    for raw_line in (patch or "").splitlines():
        if raw_line.startswith(("@@", "---", "+++")):
            continue
        line = raw_line.lstrip("+").strip()
        if not line or line.startswith("|"):
            continue
        if line.startswith("#"):
            line = re.sub(r"^#{1,6}\s*", "", line)
        lines.append(line)
        if len(" ".join(lines)) > 800:
            break
    return _clean_text(" ".join(lines), max_length=1000)


def _filename_title(path: str) -> str:
    name = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    name = name.replace("_", " ").replace("-", " ")
    name = re.sub(r"\s+", " ", name).strip()
    return name


def _infer_product(title: str, description: str = "") -> str:
    text = _clean_text(title, max_length=500)
    if not text:
        return ""
    text = re.sub(r"^(?:GHSL-\d{4}-\d+:\s*)", "", text, flags=re.I).strip()
    in_match = re.search(
        r"\bin\s+([A-Za-z0-9][A-Za-z0-9_. +/\-]{1,100}?)(?:\s+-|\s+leading|\s+via|\s+through|,|$)",
        text,
    )
    if in_match:
        return _trim_product(in_match.group(1))
    for pattern in [
        r"(.+?)\s+(?:remote code execution|rce|code execution|command injection|command execution)",
        r"(.+?)\s+(?:sql injection|xml external entity injection|xxe|ssrf|xss|cross-site scripting)",
        r"(.+?)\s+(?:file upload|file read|file inclusion|path traversal|directory traversal)",
        r"(.+?)\s+(?:authentication bypass|authorization bypass|privilege escalation|information disclosure)",
        r"(.+?)\s+(?:vulnerability|漏洞|CVE-\d{4}-\d{4,})",
    ]:
        match = re.search(pattern, text, flags=re.I)
        if match:
            return _trim_product(match.group(1))
    desc_product = re.search(r"([A-Z][A-Za-z0-9_. +/\-]{2,80})\s+version\s+v?\d", description or "")
    if desc_product:
        return _trim_product(desc_product.group(1))
    return _trim_product(text)


def _trim_product(value: str) -> str:
    product = re.sub(r"\b(?:stored|reflected|unauthorized|authenticated|unauthenticated)\b", "", value, flags=re.I)
    product = re.sub(r"\s+", " ", product).strip(" -:：|()[]")
    return product[:120]


def _infer_severity(title: str, description: str = "") -> str:
    inferred = infer_cn_severity(title, description)
    if inferred != "unknown":
        return inferred
    text = f"{title} {description}".lower()
    if any(word in text for word in ["critical", "rce", "remote code execution", "pre-auth", "preauth"]):
        return "critical"
    if any(
        word in text
        for word in [
            "command injection",
            "command execution",
            "xml external entity",
            "xxe",
            "file inclusion",
            "privilege escalation",
            "authentication bypass",
            "authorization bypass",
            "account takeover",
        ]
    ):
        return "high"
    if any(word in text for word in ["xss", "cross-site scripting", "information disclosure", "file read"]):
        return "medium"
    return "unknown"


def _extract_ghsl_id(value: str) -> str:
    match = re.search(r"GHSL-\d{4}-\d{3,}", value or "", flags=re.I)
    return match.group(0).upper() if match else ""


def _short_sha(value: Any) -> str:
    text = str(value or "").strip()
    return text[:12] if text else ""


def _browser_ua() -> str:
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )


def _http_error_text(exc: httpx.HTTPError) -> str:
    text = str(exc).strip()
    if text:
        return text[:300]
    cause = getattr(exc, "__cause__", None)
    if cause:
        return f"{exc.__class__.__name__}: {cause}"[:300]
    detail = repr(exc).strip()
    if detail and detail != f"{exc.__class__.__name__}('')":
        return detail[:300]
    return exc.__class__.__name__
