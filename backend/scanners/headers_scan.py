"""
headers_scanner.py
------------------
OWASP Security Headers Scanner

"""

from typing import Dict, Any
from urllib.parse import urlparse
import httpx
import ssl
import socket
import logging

# --------------------------------------------------
# Logging Configuration
# --------------------------------------------------
logger = logging.getLogger(__name__)

# --------------------------------------------------
# OWASP Recommended Security Headers
# --------------------------------------------------
RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Protects against XSS and data injection",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Strict-Transport-Security": "Enforces HTTPS",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Restricts browser features",
}

# --------------------------------------------------
# Helper: URL Validation & Normalization
# --------------------------------------------------
def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"https://{url}"
    return url


# --------------------------------------------------
# Helper: TLS / HTTPS Verification
# --------------------------------------------------
def verify_tls(url: str) -> Dict[str, Any]:
    result = {
        "https": False,
        "tls_valid_certificate": False,
        "issuer": None,
        "subject": None,
        "expiry": None,
        "error": None,
    }

    parsed = urlparse(url)

    if parsed.scheme != "https":
        return result

    result["https"] = True

    try:
        context = ssl.create_default_context()

        with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                cert = ssock.getpeercert()

                result["tls_valid_certificate"] = True
                result["issuer"] = cert.get("issuer")
                result["subject"] = cert.get("subject")
                result["expiry"] = cert.get("notAfter")

    except Exception as e:
        result["error"] = str(e)

    return result


# --------------------------------------------------
# Core Scanner Function
# --------------------------------------------------
def scan_headers(target_url: str) -> Dict[str, Any]:
    """
    Main entry point for header scanning
    """

    # 1. Normalize URL
    url = normalize_url(target_url)

    # 2. TLS / HTTPS Verification
    tls_info = verify_tls(url)

    # 3. Send Passive HTTP Request
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=10,
            verify=False
        ) as client:
            response = client.head(url)

    except httpx.RequestError as e:
        logger.error(f"Request failed: {e}")
        return {
            "target": url,
            "error": "Unable to connect to target",
            "details": str(e),
        }

    # 4. Extract Headers
    response_headers = dict(response.headers)

    # 5. Security Header Analysis
    findings = []

    for header, purpose in RECOMMENDED_HEADERS.items():
        if header not in response_headers:
            findings.append({
                "header": header,
                "status": "missing",
                "risk": purpose,
                "severity": "high",
            })
        else:
            findings.append({
                "header": header,
                "status": "present",
                "value": response_headers.get(header),
                "severity": "low",
            })

    # 6. TLS-Dependent Checks (HSTS)
    if tls_info["https"]:
        hsts = response_headers.get("Strict-Transport-Security")
        if not hsts:
            findings.append({
                "header": "Strict-Transport-Security",
                "status": "missing",
                "risk": "SSL stripping attack possible",
                "severity": "high",
            })
    else:
        findings.append({
            "header": "HTTPS",
            "status": "not enabled",
            "risk": "All headers can be bypassed",
            "severity": "critical",
        })

    # 7. Final Structured Result
    return {
        "target": url,
        "status_code": response.status_code,
        "tls": tls_info,
        "headers_scanned": list(RECOMMENDED_HEADERS.keys()),
        "issues": findings,
    }


"""
 if __name__ == "__main__":
        test_url = "http://testphp.vulnweb.com"
        result = scan_headers(test_url)
        from pprint import pprint
        pprint(result)
    
"""