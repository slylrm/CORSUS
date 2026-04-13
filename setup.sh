#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV_PATH="$PROJECT_ROOT/.venv"
PYTHON_BIN=""

for candidate in python3.12 python3.11 python3.13 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v "$candidate")"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "No compatible Python interpreter found. Install Python 3.12 or 3.11."
    exit 1
fi

echo "WeppenTest Platform - Environment Setup"
echo "======================================"
echo "Using Python: $PYTHON_BIN"
"$PYTHON_BIN" --version

rm -rf "$VENV_PATH"
"$PYTHON_BIN" -m venv "$VENV_PATH"

"$VENV_PATH/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_PATH/bin/python" -m pip install -r "$PROJECT_ROOT/backend/requirements-dev.txt"

if [ ! -f "$PROJECT_ROOT/.env" ]; then
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
fi

mkdir -p "$PROJECT_ROOT/logs" "$PROJECT_ROOT/reports" "$PROJECT_ROOT/nmap_output" "$PROJECT_ROOT/sqlmap_output"

"$VENV_PATH/bin/python" -c "import sys; sys.path.insert(0, 'backend'); import app.main; print('Import check: OK')"

echo
echo "Setup complete."
echo "source .venv/bin/activate"
echo ".venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload"
