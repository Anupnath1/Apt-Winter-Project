from datetime import datetime
from typing import Dict, List
import asyncio

from scanners.headers_scan import scan_headers
from scanners.api_key_scan import scan_api_keys
from scanners.data_leak_scan import scan_data_leaks
from scanners.zap_passive_scan import run_zap_passive_scan
from scanners.zap_active_scan import run_active_scan


def normalize_finding(raw: Dict) -> Dict:
    return {
        "title": raw.get("title")
        or raw.get("type")
        or raw.get("alert")
        or raw.get("name")
        or "Unknown Issue",

        "severity": raw.get("severity")
        or raw.get("risk")
        or "LOW",

        "description": raw.get("description")
        or raw.get("details")
        or raw.get("impact")
        or "",

        "evidence": raw.get("evidence")
        or raw.get("url")
        or "",

        "recommendation": raw.get("recommendation")
        or raw.get("solution")
        or "Review and apply security best practices.",

        "source": raw.get("source")
        or raw.get("scanner")
        or "internal"
    }


def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity")
        if sev in summary:
            summary[sev] += 1
    return summary


def _overall_risk(summary: Dict[str, int]) -> str:
    if summary["CRITICAL"] > 0:
        return "CRITICAL"
    if summary["HIGH"] > 0:
        return "HIGH"
    if summary["MEDIUM"] > 0:
        return "MEDIUM"
    return "LOW"


def generate_report(*, target: str, findings: List[Dict]) -> Dict:
    normalized = [normalize_finding(f) for f in findings]
    severity_summary = _count_severities(normalized)

    return {
        "meta": {
            "target": target,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(normalized),
            "risk_level": _overall_risk(severity_summary)
        },
        "summary": severity_summary,
        "findings": normalized
    }


async def run_passive_scans_and_generate_report(*, target: str) -> Dict:
    findings: List[Dict] = []

    findings.extend(scan_headers(target).get("findings", []))

    api_keys = await scan_api_keys(target)
    findings.extend(api_keys.get("findings", []))

    data_leaks = await scan_data_leaks(url=target)
    for section in data_leaks.values():
        if isinstance(section, dict):
            findings.extend(section.get("findings", []))

    findings.extend(run_zap_passive_scan(target).get("findings", []))

    return generate_report(target=target, findings=findings)



def run_active_scan_and_generate_report(*, target: str) -> Dict:
    zap_active = run_active_scan(target)
    findings = zap_active.get("alerts", zap_active.get("findings", []))
    return generate_report(target=target, findings=findings)


def generate_html_report(report: Dict) -> str:
    rows = ""
    for f in report["findings"]:
        rows += f"""
        <tr>
            <td>{f["title"]}</td>
            <td>{f["severity"]}</td>
            <td>{f["description"]}</td>
            <td>{f["recommendation"]}</td>
        </tr>
        """

    return f"""
    <html>
    <head>
        <title>Security Report</title>
        <style>
            body {{ font-family: Arial; padding: 20px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; }}
            th {{ background: #f4f4f4; }}
        </style>
    </head>
    <body>
        <h1>Security Report</h1>
        <p><b>Target:</b> {report["meta"]["target"]}</p>
        <p><b>Risk Level:</b> {report["meta"]["risk_level"]}</p>
        <p><b>Generated At:</b> {report["meta"]["generated_at"]}</p>

        <h2>Findings</h2>
        <table>
            <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Recommendation</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """
