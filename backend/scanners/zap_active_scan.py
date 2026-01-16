import time
import os
import sys
import logging
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List
from zapv2 import ZAPv2
from dotenv import load_dotenv

# Ensure selenium_auth is importable
try:
    from .selenium_auth import DefenderAutomation, AppConfig
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from selenium_auth import DefenderAutomation, AppConfig

load_dotenv()

# --- Configuration ---
ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = os.getenv("ZAP_PORT", "8080")
ZAP_PROXY_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("ZAP_Orchestrator")

class ZAPScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.base_url = self._get_base_url(target_url)  # NEW: Calculate the root domain
        self.zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_PROXY_URL, "https": ZAP_PROXY_URL})
        self.context_name = "TargetContext"
        self.context_id = None

    def _get_base_url(self, url: str) -> str:
        """Extracts 'https://site.com' from 'https://site.com/login'"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def check_connection(self):
        try:
            self.zap.core.version
        except Exception as e:
            logger.critical(f"Could not connect to ZAP at {ZAP_PROXY_URL}. Ensure ZAP is running.")
            raise ConnectionError(f"ZAP connection failed: {e}")

    def setup_context(self):
        """Creates a dedicated scan context covering the WHOLE domain."""
        logger.info(f"Setting up ZAP Context for domain: {self.base_url}")
        
        self.zap.core.new_session(name="Automated_Scan", overwrite=True)
        self.context_id = self.zap.context.new_context(self.context_name)
        
        # FIX: Scope is now the Base URL (e.g. site.com.*) not just login page
        self.zap.context.include_in_context(self.context_name, f"{self.base_url}.*")
        
        # Optional: Exclude logout to prevent killing the session
        self.zap.context.exclude_from_context(self.context_name, f".*logout.*")
        self.zap.context.exclude_from_context(self.context_name, f".*signout.*")

    def perform_login_and_hook(self, creds: Dict[str, str], manual_token: Optional[str] = None):
        logger.info("--- Phase 1: Authentication Setup ---")
        
        # Clean previous rules
        self._manage_replacer_rule("AuthCookieInjection", remove=True)
        self._manage_replacer_rule("AuthHeaderInjection", remove=True)

        token_val = None
        cookies = []

        # 1. Manual Token Logic
        if manual_token:
            logger.info("Using Manual Token.")
            token_val = manual_token
        else:
            # 2. Selenium Logic
            logger.info("Starting Selenium Automation...")
            config = AppConfig(
                LOGIN_URL=self.target_url,
                USERNAME=creds['username'],
                PASSWORD=creds['password'],
                TENANT_VALUE=creds.get('tenant', ''),
                PROXY=f"{ZAP_HOST}:{ZAP_PORT}",
                HEADLESS=False 
            )
            bot = DefenderAutomation(config)
            auth_data = bot.login()
            
            cookies = auth_data.get("cookies", [])
            tokens = auth_data.get("tokens", {})
            
            if not cookies and not tokens:
                raise ValueError("Authentication Failed: Selenium captured 0 tokens/cookies.")
            
            token_val = self._extract_best_token(tokens)

        # 3. Inject into ZAP
        self._inject_auth_state(cookies, token_val)

    def _inject_auth_state(self, cookies: list, token_val: Optional[str]):
        """Configures ZAP Global Replacer Rules."""
        logger.info("--- Phase 2: Injecting Session State into ZAP ---")

        # Inject Cookies
        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            self._manage_replacer_rule("AuthCookieInjection", match_string="Cookie", replacement=cookie_str)
            logger.info(f"Applied Cookie Rule (Length: {len(cookie_str)})")

        # Inject Bearer Token (CRITICAL for APIs)
        if token_val:
            # Ensure "Bearer " prefix exists
            auth_val = f"Bearer {token_val}" if not token_val.lower().startswith("bearer") and not token_val.lower().startswith("basic") else token_val
            
            self._manage_replacer_rule(
                "AuthHeaderInjection", 
                match_string="Authorization", 
                replacement=auth_val
            )
            logger.info(f"Applied Authorization Header Rule: {auth_val[:20]}...")
        else:
            logger.warning("No Token found for Authorization Header injection.")

    def _extract_best_token(self, tokens: dict) -> Optional[str]:
        """Prioritizes access tokens."""
        for key, val in tokens.items():
            if "access" in key.lower() or "id_token" in key.lower():
                return val
        # Fallback to any token found
        return list(tokens.values())[0] if tokens else None

    def _manage_replacer_rule(self, description, remove=False, match_string=None, replacement=None):
        try:
            self.zap.replacer.remove_rule(description)
        except: pass
        
        if not remove and match_string and replacement:
            try:
                self.zap.replacer.add_rule(
                    description=description,
                    enabled="true",
                    matchtype="REQ_HEADER",
                    matchregex="false",
                    matchstring=match_string,
                    replacement=replacement
                )
            except Exception as e:
                logger.error(f"Failed to set replacer rule {description}: {e}")

    def run_scans(self):
        # Scan the BASE URL, not the Login URL, to find the dashboard
        scan_target = self.base_url 

        logger.info(f"--- Phase 3: Spidering {scan_target} ---")
        scan_id = self.zap.spider.scan(scan_target, contextname=self.context_name)
        self._poll_status(self.zap.spider, scan_id, "Spider")

        logger.info("Starting AJAX Spider (Critical for React/Angular)...")
        self.zap.ajaxSpider.scan(scan_target, contextname=self.context_name)
        
        timeout = time.time() + 300 
        while self.zap.ajaxSpider.status == "running":
            if time.time() > timeout:
                self.zap.ajaxSpider.stop()
                break
            time.sleep(5)
        logger.info("AJAX Spider complete.")

        logger.info(f"--- Phase 4: Active Scanning {scan_target} ---")
        self.zap.ascan.enable_all_scanners()
        
        # Scan recursively from the root
        scan_id = self.zap.ascan.scan(scan_target, contextid=self.context_id, recurse=True)
        self._poll_status(self.zap.ascan, scan_id, "Active Scan")

    def _poll_status(self, component, scan_id, name):
        while True:
            try:
                status = int(component.status(scan_id))
                if status >= 100:
                    logger.info(f"{name} Completed.")
                    break
                logger.info(f"{name} Progress: {status}%")
                time.sleep(10)
            except ValueError:
                break

    def get_results(self) -> Dict[str, Any]:
        try:
            raw_alerts = self.zap.core.alerts(baseurl=self.base_url)
            grouped_alerts = {}

            for alert in raw_alerts:
                # Use vulnerability name as the unique key
                name = alert.get("alert") or alert.get("name")
                if not name:
                    continue

                if name not in grouped_alerts:
                    # Create new entry if it doesn't exist
                    grouped_alerts[name] = {
                        "alert": name,
                        "risk": alert.get("risk", "Informational"),
                        "description": alert.get("description", ""),
                        "solution": alert.get("solution", ""),
                        "urls": set()  # Use set to handle duplicate URLs automatically
                    }
                
                # Add the URL to the set
                if alert.get("url"):
                    grouped_alerts[name]["urls"].add(alert["url"])

            # Convert sets to lists for JSON response
            final_alerts = []
            for item in grouped_alerts.values():
                item["urls"] = sorted(list(item["urls"]))
                final_alerts.append(item)

            logger.info(f"Scan formatted. Aggregated {len(raw_alerts)} raw alerts into {len(final_alerts)} unique vulnerabilities.")
            
            return {
                "target": self.base_url,
                "scan_type": "active",
                "alerts": final_alerts
            }

        except Exception as e:
            logger.error(f"Error fetching ZAP results: {str(e)}")
            return {
                "target": self.base_url, 
                "scan_type": "active", 
                "alerts": []
            }

if __name__ == "__main__":
    print("Run via main.py")