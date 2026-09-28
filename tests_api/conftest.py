"""Shared fixtures for the FastAPI service tests. Every test drives the FULL app over HTTP
(TestClient(create_app(settings)), all middleware on) unless it says otherwise.

The test API key is generated per run and never printed; only its sha256 goes to a temp keys file.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ledgermind_api.app import create_app  # noqa: E402
from ledgermind_api.config import load_settings  # noqa: E402

RECORDED = REPO_ROOT / "tests" / "fixtures" / "recorded"
ADVERSARIAL = REPO_ROOT / "tests" / "fixtures" / "derived_from_source" / "adversarial"
ADV_CASES = sorted(p.stem for p in ADVERSARIAL.glob("*.json"))
UPLOAD_FIXED_NAMES = ("postings_and_hashes.json", "journal_checkpoint.json", "journal_verify.json",
                      "journal_audit.json")
STAGE_GLOB = "lm-api-*"
# Taken when pytest imports this conftest, i.e. before any test of the run (AC-A.12 temp hygiene).
PRE_EXISTING_STAGE_DIRS = frozenset(p.name for p in Path(tempfile.gettempdir()).glob(STAGE_GLOB))

TEST_KEY = secrets.token_urlsafe(32)
TEST_KEY_ID = "test-client"
KEY_HEADERS = {"X-API-Key": TEST_KEY}


def write_keys_file(directory: Path, key: str = TEST_KEY, key_id: str = TEST_KEY_ID) -> Path:
    path = directory / "api-keys.txt"
    path.write_text(key_id + " sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest() + "\n", encoding="utf-8")
    return path


def make_settings(keys_file: Path, **overrides: Any):
    env = {"LEDGERMIND_API_KEYS_FILE": str(keys_file)}
    env.update({name: str(value) for name, value in overrides.items()})
    return load_settings(env)


@pytest.fixture(scope="session")
def keys_file(tmp_path_factory) -> Path:
    return write_keys_file(tmp_path_factory.mktemp("keys"))


@pytest.fixture(scope="session")
def settings(keys_file):
    return make_settings(keys_file)


@pytest.fixture(scope="session")
def client(settings):
    with TestClient(create_app(settings), headers=KEY_HEADERS) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def anon_client(settings):
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def direct_cli(*args: str) -> tuple[int, dict]:
    """The operator's own run: `py -m tools.verify_report ... --json`, ambient environment, repo cwd."""
    proc = subprocess.run([sys.executable, "-m", "tools.verify_report", *args, "--json"], cwd=REPO_ROOT,
                          capture_output=True, text=True, check=False)
    return proc.returncode, json.loads(proc.stdout)


def recorded_upload_body(half: str, label: str | None = None, drop: tuple = (), overrides: dict | None = None) -> dict:
    directory = RECORDED / half
    names = list(UPLOAD_FIXED_NAMES) + sorted(p.name for p in directory.glob("account_*.json"))
    files = {name: json.loads((directory / name).read_text(encoding="utf-8")) for name in names if name not in drop}
    if overrides:
        files.update(overrides)
    return {"kind": "recorded", "label": label or half, "files": files}


def adversarial_upload_body(case: str) -> dict:
    document = json.loads((ADVERSARIAL / (case + ".json")).read_text(encoding="utf-8"))
    return {"kind": "adversarial", "case_label": case, "document": document}
