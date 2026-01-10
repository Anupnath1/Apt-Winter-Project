from zapv2 import ZAPv2
from typing import Dict, Any
import time
import os
import logging
from dotenv import load_dotenv

load_dotenv()

# --------------------------------------------------
# Configuration
# --------------------------------------------------

ZAP_PROXY = os.getenv("ZAP_PROXY", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
SCAN_TIMEOUT = int(os.getenv("ZAP_ACTIVE_TIMEOUT", "900"))  # 15 minutes

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

zap = ZAPv2(
    apikey=ZAP_API_KEY or None,
    proxies={
        "http": ZAP_PROXY,
        "https": ZAP_PROXY,
    }
)

def _wait_for_active_scan(scan_id: str):
    """Wait until active scan completes or timeout occurs"""
    start = time.time()

    while True:
        status = int(zap.ascan.status(scan_id))

        if status >= 100:
            return

        if time.time() - start > SCAN_TIMEOUT:
            raise TimeoutError("Active scan timeout exceeded")

        time.sleep(5)


def _run_spider(target_url: str):

    logger.info("Starting traditional spider")

    spider_id = zap.spider.scan(target_url)

    while int(zap.spider.status(spider_id)) < 100:
        time.sleep(2)

    logger.info("Traditional spider completed")


def _run_ajax_spider(target_url: str):

    logger.info("Starting AJAX Spider")

    zap.ajaxSpider.scan(target_url)

    while zap.ajaxSpider.status == "running":
        time.sleep(5)

    logger.info("AJAX Spider completed")


def _format_alert(alert: Dict[str, Any]) -> Dict[str, Any]:

    return {
        "name": alert.get("alert"),
        "risk": alert.get("risk"),
        "confidence": alert.get("confidence"),
        "description": alert.get("description"),
        "solution": alert.get("solution"),
        "evidence": alert.get("evidence"),
        "url": alert.get("url"),
        "parameter": alert.get("param"),
        "attack": alert.get("attack"),
        "cwe_id": alert.get("cweid"),
        "wasc_id": alert.get("wascid"),
        "reference": alert.get("reference"),
    }


def enable_native_active_rules():
    zap.ascan.enable_all_scanners()


def run_active_scan(target_url: str) -> Dict[str, Any]:

    logger.warning(f"ACTIVE SCAN STARTED: {target_url}")

    results: Dict[str, Any] = {
        "target": target_url,
        "scan_type": "active",
        "engine": "owasp-zap",
        "alerts": [],
        "summary": {
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
    }

    try:
        zap.urlopen(target_url)
        time.sleep(2)

        _run_spider(target_url)

        _run_ajax_spider(target_url)

        enable_native_active_rules()

        scan_id = zap.ascan.scan(target_url)
        _wait_for_active_scan(scan_id)

        alerts = zap.core.alerts(baseurl=target_url)
        seen_alerts = set()

        for alert in alerts:
            alert_name = alert.get("alert")

            if alert_name in seen_alerts:
                continue

            seen_alerts.add(alert_name)

            formatted = _format_alert(alert)
            results["alerts"].append(formatted)

            risk = (formatted.get("risk") or "").lower()
            if risk in results["summary"]:
                results["summary"][risk] += 1
            else:
                results["summary"]["info"] += 1

        logger.info(
            f"Active scan completed | "
            f"H:{results['summary']['high']} "
            f"M:{results['summary']['medium']} "
            f"L:{results['summary']['low']} "
            f"I:{results['summary']['info']}"
        )

        return results

    except Exception as exc:
        logger.error("Active scan failed", exc_info=True)
        return {
            "target": target_url,
            "scan_type": "active",
            "status": "failed",
            "error": str(exc),
        }
