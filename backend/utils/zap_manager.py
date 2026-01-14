from dotenv import load_dotenv
import subprocess
import socket
import time
import os

load_dotenv()

ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.getenv("ZAP_PORT", 8080))
ZAP_PATH = os.getenv("ZAP_PATH")


def is_zap_running():
    try:
        with socket.create_connection((ZAP_HOST, ZAP_PORT), timeout=2):
            return True
    except OSError:
        return False


def start_zap():
    if is_zap_running():
        print("[ZAP] Already running")
        return True

    if not ZAP_PATH or not os.path.exists(ZAP_PATH):
        print("[ZAP] Invalid ZAP_PATH. Check your .env file.")
        return False

    print("[ZAP] Starting OWASP ZAP...")

    # Added config flags to bypass API security checks (Host header & API Key)
    # shell=True is used to execute .bat files correctly on Windows
    subprocess.Popen(
        f'"{ZAP_PATH}" -daemon -host {ZAP_HOST} -port {ZAP_PORT} '
        '-config api.disablekey=true '
        '-config api.addrs.addr.name=.* '
        '-config api.addrs.addr.regex=true',
        cwd=os.path.dirname(ZAP_PATH),
        shell=True
    )

    return wait_for_zap()


def wait_for_zap(timeout=60):
    start_time = time.time()

    while time.time() - start_time < timeout:
        if is_zap_running():
            print("[ZAP] Started successfully")
            return True
        time.sleep(2)

    print("[ZAP] Failed to start within timeout")
    return False