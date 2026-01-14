from zapv2 import ZAPv2
from typing import Dict, Any, Optional
import time
import os
import logging
from dotenv import load_dotenv

from .selenium_auth import DefenderAutomation, AppConfig

load_dotenv()

# Configuration
ZAP_PROXY_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PROXY_PORT = os.getenv("ZAP_PORT", "8080")
ZAP_PROXY_URL = f"http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# FIX: Return to standard initialization (Use Proxies)
# This fixes "ValueError: A non ZAP API url was specified"
zap = ZAPv2(
    apikey=None, # Key disabled in step 1
    proxies={
        "http": ZAP_PROXY_URL,
        "https": ZAP_PROXY_URL
    }
)

def _wait_for_active_scan(scan_id: str):
    start = time.time()
    while True:
        try:
            status = int(zap.ascan.status(scan_id))
            if status >= 100: return
            if time.time() - start > 900: raise TimeoutError("Active scan timeout")
            time.sleep(5)
        except ValueError:
            pass

def _run_spider(target_url: str):
    logger.info("Starting traditional spider")
    spider_id = zap.spider.scan(target_url)
    # Wait for spider to start
    time.sleep(2)
    while int(zap.spider.status(spider_id)) < 100:
        time.sleep(2)
    logger.info("Traditional spider completed")

def _run_ajax_spider(target_url: str):
    logger.info("Starting AJAX Spider")
    zap.ajaxSpider.scan(target_url)
    timeout = time.time() + 300
    while zap.ajaxSpider.status == "running":
        if time.time() > timeout: break
        time.sleep(5)
    logger.info("AJAX Spider completed")

def _setup_authentication(target_url: str, auth_config: Dict[str, str]):
    logger.info("Starting Authenticated Session setup...")
    
    try:
        zap.replacer.remove_rule("AuthCookieInjection")
    except Exception:
        pass

    selenium_config = AppConfig(
        LOGIN_URL=target_url,
        USERNAME=auth_config.get("username"),
        PASSWORD=auth_config.get("password"),
        TENANT_VALUE=auth_config.get("tenant", ""),
        PROXY=f"{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}", 
        HEADLESS=True
    )
    
    bot = DefenderAutomation(selenium_config)
    cookies = bot.login()
    
    if not cookies:
        logger.error("No cookies captured! Authentication likely failed.")
        return

    # Format cookies: "name=value; name2=value2"
    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
    logger.info(f"Captured {len(cookies)} cookies. Injecting into ZAP.")

    # This will now work because of the Config Fix in Step 1
    zap.replacer.add_rule(
        description="AuthCookieInjection",
        enabled="true",
        matchtype="REQ_HEADER",
        matchregex="false",
        matchstring="Cookie",
        replacement=cookie_str,
        initiators="" 
    )

def run_active_scan(target_url: str, auth_creds: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    logger.warning(f"ACTIVE SCAN STARTED: {target_url}")
    results = {
        "target": target_url, 
        "scan_type": "active", 
        "alerts": [], 
        "summary": {"high": 0, "medium": 0, "low": 0, "info": 0}
    }

    try:
        if auth_creds and auth_creds.get("username"):
            _setup_authentication(target_url, auth_creds)
        else:
            zap.urlopen(target_url)

        _run_spider(target_url)
        _run_ajax_spider(target_url)

        zap.ascan.enable_all_scanners()
        scan_id = zap.ascan.scan(target_url)
        _wait_for_active_scan(scan_id)

        alerts = zap.core.alerts(baseurl=target_url)
        seen_alerts = set()
        
        for alert in alerts:
            name = alert.get("alert")
            if name in seen_alerts: continue
            seen_alerts.add(name)
            
            results["alerts"].append({
                "name": name,
                "risk": alert.get("risk"),
                "description": alert.get("description"),
                "solution": alert.get("solution"),
                "url": alert.get("url")
            })
            
            risk = (alert.get("risk") or "").lower()
            if risk in results["summary"]:
                results["summary"][risk] += 1
            else:
                results["summary"]["info"] += 1

        try: zap.replacer.remove_rule("AuthCookieInjection")
        except: pass

        return results

    except Exception as exc:
        logger.error("Active scan failed", exc_info=True)
        try: zap.replacer.remove_rule("AuthCookieInjection")
        except: pass
        return {"target": target_url, "status": "failed", "error": str(exc)}