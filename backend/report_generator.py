from datetime import datetime
from typing import Dict, List, Optional

def _normalize_severity(sev: str) -> str:
    if not sev: return "INFO"
    s = str(sev).strip().upper()

    if sev in ["INFORMATIONAL"]:
        return "INFO"
    return s

# def _calculate_risk(summary: Dict[str, int]) -> str:
#     if summary.get("CRITICAL", 0) > 0: return "CRITICAL"
#     if summary.get("HIGH", 0) > 0: return "HIGH"
#     if summary.get("MEDIUM", 0) > 0: return "MEDIUM"
#     return "LOW"

def generate_report_for_frontend(
    target: str,
    headers_results: Optional[Dict] = None,
    api_results: Optional[Dict] = None,
    data_leak_results: Optional[Dict] = None,
    active_results: Optional[Dict] = None
) -> Dict:
    
    passive_findings = []
    active_findings = []

    if headers_results and "issues" in headers_results:
        for issue in headers_results["issues"]:
            passive_findings.append({
                "type": "Security Header",
                "name": issue.get("header"),
                "severity": _normalize_severity(issue.get("severity")),
                "impact": issue.get("risk"),
                "recommendation": "Configure the missing security header.",
                "evidence": issue.get("status"),
                "source": "Header Scanner"
            })

    if api_results and "findings" in api_results:
        for finding in api_results["findings"]:
            passive_findings.append({
                "type": "Exposed Credential",
                "name": finding.get("type"),
                "severity": _normalize_severity(finding.get("severity")),
                "impact": finding.get("impact", "Potential unauthorized access."),
                "recommendation": finding.get("recommendation", "Rotate key immediately."),
                "evidence": finding.get("value"),
                "source": finding.get("source")
            })

    if data_leak_results:
        for category, results in data_leak_results.items():
            if isinstance(results, dict) and "findings" in results:
                for leak in results["findings"]:
                    passive_findings.append({
                        "type": "Data Leak",
                        "name": leak.get("type"),
                        "severity": _normalize_severity(leak.get("severity")),
                        "impact": leak.get("impact"),
                        "recommendation": leak.get("recommendation"),
                        "evidence": leak.get("evidence") or leak.get("url"),
                        "source": f"Data Leak ({category})"
                    })

    # UPDATED SECTION: Handle aggregated active scan results
    if active_results and "alerts" in active_results:
        for alert in active_results["alerts"]:
            active_findings.append({
                "type": "Vulnerability",
                # Aggregation logic uses 'alert' for the name, falling back to 'name' if needed
                "name": alert.get("alert") or alert.get("name"),
                "severity": _normalize_severity(alert.get("risk")),
                "impact": alert.get("description"),
                "recommendation": alert.get("solution"),
                "evidence": alert.get("evidence"),
                # Changed 'url' to 'urls' to support the list of URLs from aggregation
                "urls": alert.get("urls", []), 
                "source": "OWASP ZAP Active"
            })

    all_findings = passive_findings + active_findings
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    for f in all_findings:
        sev = f["severity"]

        if sev in summary:
            summary[sev] += 1
        else:
            summary["INFO"] += 1 # Safety check if severity key missing from default summary

    return {
        "meta": {
            "target": target,
            "generated_at": datetime.utcnow().isoformat(),
            # "risk_level": _calculate_risk(summary),
            "total_findings": len(all_findings)
        },
        "summary": summary,
        "scans": {
            "passive": {
                "count": len(passive_findings),
                "findings": passive_findings
            },
            "active": {
                "count": len(active_findings),
                "findings": active_findings,
                "is_enabled": active_results is not None
            }
        }
    }