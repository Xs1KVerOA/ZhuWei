from __future__ import annotations

from datetime import datetime
import re
from xml.etree import ElementTree

import httpx

from .base import SourceAdapter, extract_cve, infer_cn_severity, stable_id


class DoonsecWechatRssAdapter(SourceAdapter):
    name = "doonsec_wechat"
    title = "Doonsec WeChat RSS"
    category = "regular"
    schedule = "every 30 minutes"
    alert_enabled = False

    url = "https://wechat.doonsec.com/rss.xml"

    async def fetch(self) -> list[dict]:
        headers = {
            "Accept": "application/rss+xml, application/xml, text/xml",
            "User-Agent": _chrome_ua(),
        }
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
            response = await client.get(self.url)
            response.raise_for_status()

        root = ElementTree.fromstring(response.content)
        items: list[dict] = []
        for node in root.findall("./channel/item"):
            title = _text(node, "title")
            link = _text(node, "link")
            author = _text(node, "author")
            category = _text(node, "category")
            description = _text(node, "description")
            pub_date = _parse_pub_date(_text(node, "pubDate"))
            article_text = " ".join([title, description])
            if not _is_vulnerability_article(article_text):
                continue
            haystack = " ".join([article_text, author, category])
            cve = extract_cve(haystack)
            items.append(
                self.item(
                    source_uid=stable_id(title, link, pub_date),
                    title=title,
                    severity=infer_cn_severity(title, description),
                    cve_id=cve,
                    aliases=[cve] if cve else [],
                    published_at=pub_date,
                    description=description or f"微信公众号：{author or category or '未知'}",
                    url=link,
                    product=_infer_product(title),
                    raw={
                        "title": title,
                        "link": link,
                        "author": author,
                        "category": category,
                        "description": description,
                        "source_feed": self.url,
                    },
                )
            )
        return items


def _text(node: ElementTree.Element, tag: str) -> str:
    child = node.find(tag)
    return "" if child is None or child.text is None else child.text.strip()


def _parse_pub_date(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


def _is_vulnerability_article(text: str) -> bool:
    value = (text or "").lower()
    keywords = [
        "cve-",
        "qvd-",
        "cnvd-",
        "cnnvd-",
        "漏洞预警",
        "漏洞通告",
        "漏洞利用",
        "漏洞修复",
        "任意文件",
        "文件读取",
        "文件下载",
        "文件上传",
        "代码执行",
        "命令执行",
        "远程执行",
        "权限绕过",
        "认证绕过",
        "身份验证绕过",
        "未授权",
        "信息泄露",
        "拒绝服务",
        "sql注入",
        "sql 注入",
        "rce",
        "ssrf",
        "xxe",
        "ssti",
        "xss",
        "dos",
        "反序列化",
        "提权",
        "0day",
        "1day",
        "getshell",
    ]
    return any(keyword in value for keyword in keywords)


def _infer_product(title: str) -> str:
    text = re.sub(r"\s+", " ", (title or "").strip())
    if not text:
        return ""
    prefixes = ["漏洞预警 |", "漏洞通告 |", "安全警报 |", "安全通告 |"]
    for prefix in prefixes:
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    match = re.search(
        r"(.+?)(?:\s+(?:存在|漏洞|远程|命令|代码|SQL|文件|权限|未授权|默认口令|身份验证)|（?CVE-|\(?CVE-)",
        text,
        flags=re.I,
    )
    product = (match.group(1) if match else text).strip(" -:：|")
    return product[:120]


def _chrome_ua() -> str:
    return (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )
