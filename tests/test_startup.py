import os
import socket
import subprocess
import sys
import time
import requests


def test_documented_streamlit_server_starts(tmp_path):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    environment = dict(os.environ, STREAMLIT_BROWSER_GATHER_USAGE_STATS='false')
    with (tmp_path/'startup.log').open('w+', encoding='utf-8') as log:
        process = subprocess.Popen([sys.executable, '-m', 'streamlit', 'run', 'app.py',
            '--server.headless=true', f'--server.port={port}'], stdout=log, stderr=log, env=environment)
        try:
            deadline = time.monotonic()+30
            ready = False
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    health = requests.get(f'http://127.0.0.1:{port}/_stcore/health', timeout=1)
                    if health.status_code == 200:
                        ready = True
                        break
                except requests.RequestException:
                    pass
                time.sleep(.1)
            log.flush(); log.seek(0)
            assert ready, log.read()
            page = requests.get(f'http://127.0.0.1:{port}/', timeout=5)
            assert page.status_code == 200 and 'streamlit' in page.text.lower()
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
