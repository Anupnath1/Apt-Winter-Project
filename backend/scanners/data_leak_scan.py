from __future__ import annotations

import re
import json
import subprocess
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
    "email": {
        "regex": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "severity": "LOW",
        "impact": "Public email exposure",
        "recommendation": "Remove or obfuscate email addresses"
    },
    "aws_key": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "impact": "AWS credentials exposed",
        "recommendation": "Immediately rotate AWS keys"
    },
    "jwt": {
        "regex": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "severity": "HIGH",
        "impact": "JWT token leakage",
        "recommendation": "Invalidate tokens and prevent client-side exposure"
    }
}


EXPOSED_PATHS = {
    "/.env": {
        "severity": "CRITICAL",
        "impact": "Environment secrets exposed",
        "recommendation": "Block public access to .env files"
    },
    "/.git/HEAD": {
        "severity": "CRITICAL",
        "impact": "Git repository exposed",
        "recommendation": "Disable public access to .git directory"
    },
    "/backup.zip": {
        "severity": "HIGH",
        "impact": "Backup archive publicly accessible",
        "recommendation": "Remove backups from web root"
    },
    "/config.php": {
        "severity": "HIGH",
        "impact": "Configuration file exposed",
        "recommendation": "Restrict direct access to config files"
    },
    "/phpinfo.php": {
        "severity": "HIGH",
        "impact": "PHP environment information exposed",
        "recommendation": "Delete phpinfo.php from production"
    }
}

ADMIN_PATHS = [
    "/admin",
    "/admin/login",
    "/phpmyadmin",
    "/wp-admin"
]


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Invalid URL")

def _mask(value: str) -> str:
    if len(value) <= 6:
        return "***"
    return value[:3] + "***" + value[-3:]



def scan_text(text: str) -> List[Dict]:
    findings = []

    for name, rule in SENSITIVE_PATTERNS.items():
        matches = set(re.findall(rule["regex"], text))
        for match in matches:
            findings.append({
                "type": name,
                "evidence": _mask(match),
                "severity": rule["severity"],
                "impact": rule["impact"],
                "recommendation": rule["recommendation"]
            })

    return findings


async def scan_html(url: str) -> Dict:
    _validate_url(url)

    async with httpx.AsyncClient(headers=HEADERS, timeout=HTTP_TIMEOUT) as client:
        resp = await client.get(url)
        soup = BeautifulSoup(resp.text, "html.parser")

    return {
        "url": url,
        "findings": scan_text(soup.get_text())
    }



async def crawl_and_scan(start_url: str) -> Dict:
    _validate_url(start_url)

    visited: Set[str] = set()
    queue: List[str] = [start_url]
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
                full_url = urljoin(url, link["href"])
                if urlparse(full_url).netloc == urlparse(start_url).netloc:
                    queue.append(full_url)

    return {
        "pages_scanned": len(visited),
        "results": results
    }



async def scan_exposed_resources(url: str) -> Dict:
    _validate_url(url)
    findings: List[Dict] = []

    async with httpx.AsyncClient(
        headers=HEADERS,
        timeout=EXPOSURE_TIMEOUT,
        follow_redirects=True
    ) as client:

        # Exposed files
        for path, meta in EXPOSED_PATHS.items():
            target = urljoin(url, path)
            try:
                resp = await client.get(target)
                if resp.status_code == 200 and resp.text:
                    findings.append({
                        "type": "exposed_file",
                        "url": target,
                        "severity": meta["severity"],
                        "impact": meta["impact"],
                        "recommendation": meta["recommendation"]
                    })
            except Exception:
                continue

        # Admin panels
        for path in ADMIN_PATHS:
            target = urljoin(url, path)
            try:
                resp = await client.get(target)
                if resp.status_code in (200, 401, 403):
                    findings.append({
                        "type": "admin_panel",
                        "url": target,
                        "severity": "MEDIUM",
                        "impact": "Admin interface publicly reachable",
                        "recommendation": "Restrict admin access by IP or authentication"
                    })
            except Exception:
                continue

        # Directory listing
        try:
            resp = await client.get(url)
            if "Index of /" in resp.text or "<title>Index of" in resp.text:
                findings.append({
                    "type": "directory_listing",
                    "url": url,
                    "severity": "MEDIUM",
                    "impact": "Directory listing enabled",
                    "recommendation": "Disable directory indexing"
                })
        except Exception:
            pass

    return {"target": url, "findings": findings}


def run_trufflehog(path: str) -> List[Dict]:
    try:
        proc = subprocess.run(
            ["trufflehog", "filesystem", path, "--json"],
            capture_output=True,
            text=True,
            timeout=TRUFFLEHOG_TIMEOUT
        )
        return [json.loads(line) for line in proc.stdout.splitlines() if line]
    except Exception:
        return [{"error": "TruffleHog execution failed"}]


def scan_git_repository(repo_path: str) -> Dict:
    try:
        repo = Repo(repo_path)
    except InvalidGitRepositoryError:
        return {"error": "Invalid git repository"}

    raw_findings = []

    for blob in repo.tree().traverse():
        if blob.type == "blob":
            try:
                content = blob.data_stream.read().decode(errors="ignore")
                raw_findings.extend(
                    extract_raw_secrets(content, blob.path)
                )
            except Exception:    
                continue

    return {
        "repo": repo_path,
        "raw_findings": raw_findings,
        "trufflehog": run_trufflehog(repo_path)
    }


async def scan_data_leaks(
    *,
    url: str | None = None,
    repo_path: str | None = None,
    local_path: str | None = None
) -> Dict:

    report: Dict = {}

    if url:
        report["html_scan"] = await scan_html(url)
        report["crawler_scan"] = await crawl_and_scan(url)
        report["exposure_scan"] = await scan_exposed_resources(url)

    if repo_path:
        report["git_repo_scan"] = scan_git_repository(repo_path)

    if local_path:
        report["filesystem_scan"] = run_trufflehog(local_path)

    return report
