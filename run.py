import subprocess
import threading
import time
import socket
import webbrowser
import os
import sys

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8000
FRONTEND_HOST = "127.0.0.1"
FRONTEND_PORT = 5173   # Vite / React default. Change if needed.

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")


def run_backend():
    try:
        subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn",
                "backend.main:app",
                "--host", BACKEND_HOST,
                "--port", str(BACKEND_PORT),
                "--reload"
            ],
            cwd=PROJECT_ROOT,
        )
    except Exception as e:
        print(f"Backend failed: {e}")


def run_frontend():
    try:
        if os.name == "nt":  # Windows
            subprocess.Popen(
                ["npm", "run", "dev"],
                cwd=FRONTEND_DIR,
                shell=True
            )
        else:  # Linux / Mac
            subprocess.Popen(
                ["npm", "run", "dev"],
                cwd=FRONTEND_DIR
            )
    except Exception as e:
        print(f"Frontend failed: {e}")


def wait_for_port(host, port, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def main():
    print("Starting backend...")
    threading.Thread(target=run_backend, daemon=True).start()

    print("Starting frontend...")
    threading.Thread(target=run_frontend, daemon=True).start()

    print("Waiting for backend...")
    if not wait_for_port(BACKEND_HOST, BACKEND_PORT):
        print("Backend failed to start")
        return

    print("Waiting for frontend...")
    if not wait_for_port(FRONTEND_HOST, FRONTEND_PORT):
        print("Frontend failed to start")
        return

    url = f"http://{FRONTEND_HOST}:{FRONTEND_PORT}"
    print(f"Opening browser → {url}")
    webbrowser.open(url)


if __name__ == "__main__":
    main()
