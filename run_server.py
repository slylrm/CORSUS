#!/usr/bin/env python
import os
import subprocess
import sys

# Change to backend directory
os.chdir(os.path.join(os.path.dirname(__file__), 'backend'))

# Run uvicorn bound to localhost so link is clickable
subprocess.run([
    sys.executable, '-m', 'uvicorn',
    'app.main:app',
    '--reload',
    '--host', '127.0.0.1',
    '--port', os.getenv('API_PORT', '8000'),
    '--log-level', 'info'
])
