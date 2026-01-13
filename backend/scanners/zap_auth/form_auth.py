import os
import time
import urllib.parse
from zapv2 import ZAPv2


# -------------------- CONFIG --------------------
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "pd6lnksuimrd3bd840bisjesn7")  # DO NOT hardcode in prod
ZAP_API_URL = "http://127.0.0.1:8080"

CONTEXT_ID = 1
CONTEXT_NAME = "Default Context"
TARGET_URL = "https://defender.aptsoftware.in"
LOGIN_URL = "https://defender.aptsoftware.in/login"

# Credentials (move to env vars in prod)
USERNAME = os.getenv("APP_USERNAME", "IdexApprover")
PASSWORD = os.getenv("APP_PASSWORD", "IDEXApp@0424")
TENANT = os.getenv("APP_TENANT", "IDEXDEMO")

# -------------------- ZAP CLIENT --------------------
zap = ZAPv2(apikey=ZAP_API_KEY)  # ❗ NO proxies for API calls
zap.base = "http://127.0.0.1:8080/JSON/"

# 🔒 HARD disable proxies at requests level
zap._request_session.proxies = {}
zap._request_session.trust_env = False

# -------------------- HEALTH CHECK --------------------
def zap_health_check():
    try:
        version = zap.core.version
        print(f"Connected to ZAP version: {version}")
    except Exception as exc:
        raise RuntimeError(
            "ZAP API not reachable. Ensure ZAP is running and API is enabled."
        ) from exc


# -------------------- CONTEXT --------------------
def set_include_in_context():
    include_regex = r"https://defender\.aptsoftware\.in/.*"
    exclude_regex = r"https://defender\.aptsoftware\.in/logout.*"

    zap.context.include_in_context(CONTEXT_NAME, include_regex)
    zap.context.exclude_from_context(CONTEXT_NAME, exclude_regex)
    print("Context include/exclude configured")


# -------------------- AUTH --------------------
def set_form_based_auth():
    login_request_data = (
        "username={%username%}&password={%password%}&tenant={%tenant%}"
    )
    auth_config = (
        f"loginUrl={urllib.parse.quote(LOGIN_URL)}"
        f"&loginRequestData={urllib.parse.quote(login_request_data)}"
    )

    zap.authentication.set_authentication_method(
        CONTEXT_ID, "formBasedAuthentication", auth_config
    )
    print("Form-based authentication configured")


def set_logged_in_indicator():
    # Must be something ONLY visible when logged in
    logged_in_regex = r"(Dashboard|Logout|Welcome)"
    zap.authentication.set_logged_in_indicator(CONTEXT_ID, logged_in_regex)
    print("Logged-in indicator configured")


# -------------------- USER --------------------
def set_user_auth_config():
    user_name = "Apt Defender Test User"

    user_id = zap.users.new_user(CONTEXT_ID, user_name)

    creds = (
        f"username={urllib.parse.quote(USERNAME)}"
        f"&password={urllib.parse.quote(PASSWORD)}"
        f"&tenant={urllib.parse.quote(TENANT)}"
    )

    zap.users.set_authentication_credentials(CONTEXT_ID, user_id, creds)
    zap.users.set_user_enabled(CONTEXT_ID, user_id, "true")

    zap.forcedUser.set_forced_user(CONTEXT_ID, user_id)
    zap.forcedUser.set_forced_user_mode_enabled("true")

    print(f"User configured (id={user_id})")
    return user_id


# -------------------- SPIDER --------------------
def start_spider(user_id: int):
    scan_id = zap.spider.scan_as_user(
        CONTEXT_ID, user_id, TARGET_URL, recurse="true"
    )
    print(f"Spider started (scan id={scan_id})")

    # Wait until spider completes
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(2)

    print("Spider completed")


# -------------------- MAIN --------------------
if __name__ == "__main__":
    zap_health_check()

    set_include_in_context()
    set_form_based_auth()
    set_logged_in_indicator()
    user_id = set_user_auth_config()
    start_spider(user_id)

    print("Authenticated scan flow completed")
