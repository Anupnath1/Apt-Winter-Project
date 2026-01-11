"""
API Key Scanner
• Full async fetching
• Inline JS scanning
• Unlimited JS files (unique only)
• Recursion for dynamic imports
• Better patterns + entropy gating
• Robust error handling/logging
• Still safe + passive
"""

import re
import math
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set


HEADERS = {"User-Agent": "APT-Scanner/2.0"}

CONCURRENCY_LIMIT = 10    # async requests at once
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

SEEN_URLS: Set[str] = set()

API_KEY_PATTERNS = {
    "Firebase API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Discord Token": r"[MN][A-Za-z0-9-_]{23}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27}",
    "Telegram Bot Token": r"[0-9]{9}:[A-Za-z0-9_-]{35}",
    "Twitter Bearer": r"A{10,}[A-Za-z0-9%=_-]{30,}",
    "Mailgun": r"key-[0-9a-zA-Z]{32}",
    "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Generic Key": r"(?i)(api[_-]?key|secret|token)[\"'\s:=]+[A-Za-z0-9\-_]{16,}",
}

API_KEY_PATTERNS.update({
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-_\.]+",
    "OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "OAuth Client Secret": r"(?i)client_secret[\"'\s:=]+[A-Za-z0-9\-_]{16,}",
    "OAuth Refresh Token": r"(?i)refresh[_-]?token[\"'\s:=]+[A-Za-z0-9\-_]{16,}",
    "Slack Bot Token": r"xox[bp]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}",
    "Slack Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]+/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
})

def shannon_entropy(value: str) -> float:
    entropy = 0
    for char in set(value):
        p = value.count(char) / len(value)
        entropy -= p * math.log2(p)
    return entropy

def is_high_entropy(value: str, threshold: float = 4.0) -> bool:
    return shannon_entropy(value) >= threshold


async def fetch(session: aiohttp.ClientSession, url: str) -> str:
    if url in SEEN_URLS:
        return ""
    SEEN_URLS.add(url)

    try:
        async with session.get(url, headers=HEADERS, timeout=8) as resp:
            if resp.status == 200:
                return await resp.text()
    except:
        return ""
    return ""


def extract_js(html: str, base: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = set()

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            urls.add(urljoin(base, src))
        else:
            # inline scripts - extract JS
            if tag.string:
                urls.add(("inline", tag.string))

    return list(urls)


def extract_dynamic_imports(js: str, base: str) -> List[str]:
    imports = re.findall(r"""import\s*['"]([^'"]+)['"]""", js)
    return [urljoin(base, i) for i in imports]


def scan_content(content: str, source: str) -> List[Dict]:
    findings = []
    source_lower = source.lower()

    for name, pattern in API_KEY_PATTERNS.items():
        for match in re.findall(pattern, content):
            value = match if isinstance(match, str) else match[0]

            if is_high_entropy(value):

                # classify severity
                severity = "HIGH"
                if any(keyword in source_lower for keyword in PUBLIC_KEY_WHITELIST):
                    severity = "LOW"

                findings.append({
                    "type": name,
                    "value": value[:6] + "..." + value[-4:],
                    "source": source,
                    "severity": severity
                })

    return findings



async def process_js(session, item, base_url, findings, sem):
    async with sem:
        if isinstance(item, tuple):     # inline JS
            content = item[1]
            findings.extend(scan_content(content, "inline JS"))
            imports = extract_dynamic_imports(content, base_url)

        else:                           # external JS URL
            content = await fetch(session, item)
            findings.extend(scan_content(content, item))
            imports = extract_dynamic_imports(content, item)

        # recursively process imported JS
        tasks = [process_js(session, imp, base_url, findings, sem)
                 for imp in imports if imp not in SEEN_URLS]

        await asyncio.gather(*tasks)

def dedupe_findings(findings: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []

    for f in findings:
        key = (f["type"], f["value"], f["source"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique

async def scan_api_keys(url: str):
    findings = []
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        html = await fetch(session, url)
        findings.extend(scan_content(html, "HTML"))

        js_items = extract_js(html, url)

        tasks = [process_js(session, js, url, findings, sem)
                 for js in js_items]

        await asyncio.gather(*tasks)

    cleaned = dedupe_findings(findings)

    return {
      "status": "ok",
      "count": len(cleaned),
      "findings": cleaned,
   }
def analyze_extracted_value(value: str, source: str) -> List[Dict]:
    """
    Analyze a single extracted string (NO fetching, NO crawling).
    Used by glue pipeline.
    """
    findings = []

    for name, pattern in API_KEY_PATTERNS.items():
        for match in re.findall(pattern, value):
            token = match if isinstance(match, str) else match[0]

            if is_high_entropy(token):
                findings.append({
                    "type": name,
                    "severity": "HIGH",
                    "impact": "Exposed API credential",
                    "recommendation": "Restrict or rotate the API key",
                    "source": source
                })

    return findings




if __name__ == "__main__":
    result = asyncio.run(scan_api_keys("https://example.com"))
    print(result)
