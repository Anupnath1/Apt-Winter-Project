from zapv2 import ZAPv2
import time
import os
from dotenv import load_dotenv
from utils.zap_manager import start_zap

load_dotenv()

ZAP_PROXY = os.getenv("ZAP_PROXY", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

def run_zap_passive_scan(target):
    start_zap()
    zap = ZAPv2(apikey=ZAP_API_KEY or None, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
    zap.urlopen(target)
    time.sleep(2)
    while True:
        try:
            if int(zap.pscan.records_to_scan()) == 0:
                break
        except:
            break
        time.sleep(1)
    alerts = zap.core.alerts(baseurl=target)
   return {
        "findings": [{
            "title": a.get("alert"),
            "severity": (a.get("risk") or "LOW").upper(),
            "description": a.get("description"),
            "recommendation": a.get("solution"),
            "evidence": a.get("evidence"),
            "url": a.get("url"),
            "source": "owasp-zap-passive"
        }]
    }
