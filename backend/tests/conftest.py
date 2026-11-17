from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TEST_TEMP_DIR = _PROJECT_ROOT / ".tmp" / "pytest-temp"
_TEST_TEMP_DIR.mkdir(parents=True, exist_ok=True)

os.environ["TMP"] = str(_TEST_TEMP_DIR)
os.environ["TEMP"] = str(_TEST_TEMP_DIR)
tempfile.tempdir = str(_TEST_TEMP_DIR)


@pytest.fixture
def workspace_tmp_dir() -> Path:
    root = _PROJECT_ROOT / ".tmp" / "test-work"
    root.mkdir(parents=True, exist_ok=True)
    case_dir = root / f"case-{uuid.uuid4().hex}"
    case_dir.mkdir(parents=True, exist_ok=False)
    try:
        yield case_dir
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)
