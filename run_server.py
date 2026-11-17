#!/usr/bin/env python
import os
import subprocess
import sys
import time
import urllib.request
import webbrowser


def wait_for_health(url: str, timeout_seconds: int = 30) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if 200 <= getattr(response, "status", 200) < 500:
                    return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


project_root = os.path.dirname(__file__)
backend_dir = os.path.join(project_root, "backend")
host = os.getenv("API_HOST", "127.0.0.1")
port = os.getenv("API_PORT", "8000")
dashboard_url = f"http://{host}:{port}/"
health_url = f"http://{host}:{port}/health"

os.chdir(backend_dir)

server_process = subprocess.Popen([
    sys.executable,
    "-m",
    "uvicorn",
    "app.main:app",
    "--reload",
    "--host",
    host,
    "--port",
    port,
    "--log-level",
    "info",
])

try:
    if wait_for_health(health_url):
        webbrowser.open(dashboard_url, new=2)
    else:
        print(f"Server started, but health check did not respond within 30s: {dashboard_url}")

    server_process.wait()
except KeyboardInterrupt:
    server_process.terminate()
    server_process.wait()
