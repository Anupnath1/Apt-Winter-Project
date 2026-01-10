import re
import json
import subprocess
import asyncio
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
from git import Repo, InvalidGitRepositoryError

HEADERS = {"User-Agent": "APT-Security-Scanner/1.0"}
HTTP_TIMEOUT = 10
EXPOSURE_TIMEOUT = 8
MAX_PAGES = 10
TRUFFLEHOG_TIMEOUT = 30

SENSITIVE_PATTERNS = {
    "email": {"regex": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "severity": "LOW", "impact": "Public email exposure", "recommendation": "Remove or obfuscate email addresses"},
    "aws_key": {"regex": r"AKIA[0-9A-Z]{16}", "severity": "CRITICAL", "impact": "AWS credentials exposed", "recommendation": "Immediately rotate AWS keys"},
    "jwt": {"regex": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "severity": "HIGH", "impact": "JWT token leakage", "recommendation": "Invalidate tokens and prevent client-side exposure"}
}

EXPOSED_PATHS = {
    "/.env": {"severity": "CRITICAL", "impact": "Environment secrets exposed", "recommendation": "Block public access to .env files"},
    "/.git/HEAD": {"severity": "CRITICAL", "impact": "Git repository exposed", "recommendation": "Disable public access to .git directory"},
    "/backup.zip": {"severity": "HIGH", "impact": "Backup archive publicly accessible", "recommendation": "Remove backups from web root"}
}

ADMIN_PATHS = ["/admin", "/admin/login", "/phpmyadmin", "/wp-admin"]

def _validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Invalid URL")

def _mask(value):
    return value[:3] + "***" + value[-3:] if len(value) > 6 else "***"

def scan_text(text):
    findings = []
    for name, rule in SENSITIVE_PATTERNS.items():
        for match in set(re.findall(rule["regex"], text)):
            findings.append({
                "type": name,
                "evidence": _mask(match),
                "severity": rule["severity"],
                "impact": rule["impact"],
                "recommendation": rule["recommendation"]
            })
    return findings

async def scan_html(url):
    _validate_url(url)
    async with httpx.AsyncClient(headers=HEADERS, timeout=HTTP_TIMEOUT) as client:
        resp = await client.get(url)
        soup = BeautifulSoup(resp.text, "html.parser")
    return {"url": url, "findings": scan_text(soup.get_text())}

async def crawl_and_scan(start_url):
    _validate_url(start_url)
    visited = set()
    queue = [start_url]
    results = []
    async with httpx.AsyncClient(headers=HEADERS, timeout=HTTP_TIMEOUT) as client:
        while queue and len(visited) < MAX_PAGES:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = await client.get(url)
            except Exception:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            findings = scan_text(soup.get_text())
            if findings:
                results.append({"url": url, "findings": findings})
            for link in soup.find_all("a", href=True):
                full = urljoin(url, link["href"])
                if urlparse(full).netloc == urlparse(start_url).netloc:
                    queue.append(full)
    return {"pages_scanned": len(visited), "results": results}

async def scan_exposed_resources(url):
    _validate_url(url)
    findings = []
    async with httpx.AsyncClient(headers=HEADERS, timeout=EXPOSURE_TIMEOUT, follow_redirects=True) as client:
        for path, meta in EXPOSED_PATHS.items():
            target = urljoin(url, path)
            try:
                resp = await client.get(target)
                if resp.status_code == 200:
                    findings.append({"type": "exposed_file", "url": target, **meta})
            except Exception:
                pass
        for path in ADMIN_PATHS:
            target = urljoin(url, path)
            try:
                resp = await client.get(target)
                if resp.status_code in (200, 401, 403):
                    findings.append({"type": "admin_panel", "url": target, "severity": "MEDIUM", "impact": "Admin interface exposed", "recommendation": "Restrict access"})
            except Exception:
                pass
    return {"target": url, "findings": findings}

async def _scan_data_leaks_async(url):
    return {
        "html": await scan_html(url),
        "crawl": await crawl_and_scan(url),
        "exposed": await scan_exposed_resources(url)
    }

def scan_data_leaks(url):
    return asyncio.run(_scan_data_leaks_async(url))
