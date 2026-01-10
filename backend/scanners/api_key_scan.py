import re
import math
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import Dict, List, Set

HEADERS = {"User-Agent": "APT-Scanner/2.0"}
CONCURRENCY_LIMIT = 10

PUBLIC_KEY_WHITELIST = [
    "google-analytics",
    "googletagmanager",
    "firebase",
    "firebaseapp",
    "mixpanel",
    "amplitude",
    "hotjar",
    "segment",
    "plausible",
    "logrocket",
    "matomo",
    "posthog",
    "analytics",
    "tracking",
]

API_KEY_PATTERNS = {
    "Firebase API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "Discord Token": r"[MN][A-Za-z0-9-_]{23}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27}",
    "Telegram Bot Token": r"[0-9]{9}:[A-Za-z0-9_-]{35}",
    "Slack Bot Token": r"xox[bp]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}",
    "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Generic Key": r"(?i)(api[_-]?key|secret|token)[\"'\s:=]+[A-Za-z0-9\-_]{16,}",
}

def shannon_entropy(value: str) -> float:
    entropy = 0.0
    for c in set(value):
        p = value.count(c) / len(value)
        entropy -= p * math.log2(p)
    return entropy

def is_high_entropy(value: str) -> bool:
    return shannon_entropy(value) >= 4.0

async def _fetch(session, url, seen):
    if url in seen:
        return ""
    seen.add(url)
    try:
        async with session.get(url, headers=HEADERS, timeout=8) as resp:
            if resp.status == 200:
                return await resp.text()
    except Exception:
        pass
    return ""

def _extract_js(html, base):
    soup = BeautifulSoup(html, "html.parser")
    items = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            items.append(urljoin(base, src))
        elif tag.string:
            items.append(("inline", tag.string))
    return items

def _extract_imports(js, base):
    imports = re.findall(r"""import\s*['"]([^'"]+)['"]""", js)
    return [urljoin(base, i) for i in imports]

def _scan_content(content, source):
    findings = []
    source_lower = source.lower()
    for name, pattern in API_KEY_PATTERNS.items():
        for match in re.findall(pattern, content):
            value = match if isinstance(match, str) else match[0]
            if is_high_entropy(value):
                severity = "LOW" if any(k in source_lower for k in PUBLIC_KEY_WHITELIST) else "HIGH"
                findings.append({
                    "type": name,
                    "severity": severity,
                    "impact": "Exposed API credential",
                    "recommendation": "Restrict or rotate the API key",
                    "source": source,
                })
    return findings

async def _process_js(session, item, base, findings, sem, seen):
    async with sem:
        if isinstance(item, tuple):
            content = item[1]
            findings.extend(_scan_content(content, "inline JS"))
            imports = _extract_imports(content, base)
        else:
            content = await _fetch(session, item, seen)
            findings.extend(_scan_content(content, item))
            imports = _extract_imports(content, item)
        tasks = [_process_js(session, i, base, findings, sem, seen) for i in imports if i not in seen]
        if tasks:
            await asyncio.gather(*tasks)

async def scan_api_keys(url: str) -> Dict:
    findings = []
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    seen = set()
    async with aiohttp.ClientSession() as session:
        html = await _fetch(session, url, seen)
        findings.extend(_scan_content(html, "HTML"))
        js_items = _extract_js(html, url)
        tasks = [_process_js(session, js, url, findings, sem, seen) for js in js_items]
        if tasks:
            await asyncio.gather(*tasks)
    unique = {(f["type"], f["source"]): f for f in findings}
    return {"findings": list(unique.values())}
