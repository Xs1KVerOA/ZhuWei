from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import db
from .config import settings


RULES_SETTING = "monitor_rules"
SEVERITY_ORDER = {
    "none": 0,
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
DEFAULT_RULES: dict[str, Any] = {
    "min_severity": "high",
    "enable_cve_dedup": True,
    "no_filter": False,
    "max_age_days": 30,
    "white_keywords": [],
    "black_keywords": [],
}


def get_monitor_rules() -> dict[str, Any]:
    raw = db.get_setting(RULES_SETTING)
    if not raw:
        return DEFAULT_RULES.copy()
    try:
        saved = json.loads(raw)
    except json.JSONDecodeError:
        saved = {}
    return _normalize_rules({**DEFAULT_RULES, **saved})


def set_monitor_rules(payload: dict[str, Any]) -> dict[str, Any]:
    rules = _normalize_rules({**DEFAULT_RULES, **payload})
    db.set_setting(RULES_SETTING, json.dumps(rules, ensure_ascii=False))
    return rules


def process_alerts(items: list[dict[str, Any]]) -> int:
    rules = get_monitor_rules()
    created = 0
    for item in items:
        passed, reason = evaluate_item(item, rules)
        if not passed:
            continue
        vuln = db.get_vulnerability_for_item(item)
        if not vuln:
            continue
        dedupe_key = _dedupe_key(item, rules)
        if db.create_alert_if_absent(int(vuln["id"]), dedupe_key, reason):
            created += 1
    return created


def evaluate_item(item: dict[str, Any], rules: dict[str, Any]) -> tuple[bool, str]:
    text = _match_text(item)
    if not _is_recent_item(item, int(rules.get("max_age_days") or 0)):
        return False, f"published older than {rules['max_age_days']} days"

    keyword_reason = ""
    if not rules["no_filter"]:
        black_hit = _keyword_hit(text, rules["black_keywords"])
        if black_hit:
            return False, f"black keyword: {black_hit}"

        white_keywords = rules["white_keywords"]
        if white_keywords:
            white_hit = _keyword_hit(text, white_keywords)
            if not white_hit:
                return False, "white keyword missed"
            keyword_reason = f"white keyword: {white_hit}; "

    severity = item.get("severity") or "unknown"
    if _severity_rank(severity) < _severity_rank(rules["min_severity"]):
        return False, f"severity below {rules['min_severity']}"
    return True, f"{keyword_reason}severity >= {rules['min_severity']}"


def _normalize_rules(payload: dict[str, Any]) -> dict[str, Any]:
    min_severity = str(payload.get("min_severity") or DEFAULT_RULES["min_severity"]).lower()
    if min_severity not in SEVERITY_ORDER:
        min_severity = DEFAULT_RULES["min_severity"]
    try:
        max_age_days = int(payload.get("max_age_days") or DEFAULT_RULES["max_age_days"])
    except (TypeError, ValueError):
        max_age_days = DEFAULT_RULES["max_age_days"]
    return {
        "min_severity": min_severity,
        "enable_cve_dedup": bool(payload.get("enable_cve_dedup")),
        "no_filter": bool(payload.get("no_filter")),
        "max_age_days": max(1, min(max_age_days, 3650)),
        "white_keywords": _keyword_list(payload.get("white_keywords")),
        "black_keywords": _keyword_list(payload.get("black_keywords")),
    }


def current_alert_filters(rules: dict[str, Any] | None = None) -> dict[str, str]:
    active_rules = rules or get_monitor_rules()
    max_age_days = int(active_rules.get("max_age_days") or DEFAULT_RULES["max_age_days"])
    min_severity = str(active_rules.get("min_severity") or DEFAULT_RULES["min_severity"]).lower()
    if _severity_rank(min_severity) < _severity_rank(DEFAULT_RULES["min_severity"]):
        min_severity = DEFAULT_RULES["min_severity"]
    return {
        "min_severity": min_severity,
        "published_after": _cutoff_date(max_age_days),
    }


def _is_recent_item(item: dict[str, Any], max_age_days: int) -> bool:
    if max_age_days <= 0:
        return True
    item_date = _parse_item_date(item.get("published_at") or item.get("updated_at"))
    if item_date is None:
        return True
    return item_date >= datetime.fromisoformat(_cutoff_date(max_age_days)).date()


def _cutoff_date(max_age_days: int) -> str:
    try:
        today = datetime.now(ZoneInfo(settings.scheduler_timezone)).date()
    except ZoneInfoNotFoundError:
        today = datetime.now(timezone.utc).date()
    return (today - timedelta(days=max_age_days)).isoformat()


def _parse_item_date(value: Any):
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text.replace("Z", "+0000"), fmt).date()
        except ValueError:
            pass
    match = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", text)
    if not match:
        return None
    try:
        return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3))).date()
    except ValueError:
        return None


def _keyword_list(value: Any) -> list[str]:
    if isinstance(value, str):
        parts = value.replace(",", "\n").splitlines()
    elif isinstance(value, list):
        parts = [str(item) for item in value]
    else:
        parts = []
    seen = set()
    keywords = []
    for part in parts:
        keyword = part.strip()
        marker = keyword.lower()
        if keyword and marker not in seen:
            seen.add(marker)
            keywords.append(keyword)
    return keywords


def _match_text(item: dict[str, Any]) -> str:
    aliases = " ".join(str(alias) for alias in item.get("aliases") or [])
    return " ".join(
        str(item.get(key) or "")
        for key in ["title", "description", "product", "cve_id", "source"]
    ).lower() + " " + aliases.lower()


def _keyword_hit(text: str, keywords: list[str]) -> str:
    for keyword in keywords:
        if keyword.lower() in text:
            return keyword
    return ""


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(str(severity).lower(), 0)


def _dedupe_key(item: dict[str, Any], rules: dict[str, Any]) -> str:
    cve = str(item.get("cve_id") or "").upper()
    if rules["enable_cve_dedup"] and cve:
        return f"cve:{cve}"
    if item.get("dedupe_key"):
        return f"dedupe:{item['dedupe_key']}"
    canonical = db.dedupe_key_for_item(item)
    if canonical:
        return f"dedupe:{canonical}"
    return f"source:{item['source']}:{item['source_uid']}"
