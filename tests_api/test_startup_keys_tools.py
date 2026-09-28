"""Run A, AC-A.10 (fail-closed startup), the keygen round trip, AC-A.13 (tool catalog)."""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
import time

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from conftest import REPO_ROOT, write_keys_file
from ledgermind_api.app import create_app
from ledgermind_api.config import ENV_KEYS_FILE, ConfigError

SENTINEL = "SENTINEL-PLAINTEXT-" + secrets.token_hex(16)


def _base_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("LEDGERMIND_")}


def _broken_case(case: str, tmp_path) -> dict[str, str]:
    if case == "unset":
        return {}
    if case == "missing":
        return {ENV_KEYS_FILE: str(tmp_path / "does-not-exist.txt")}
    path = tmp_path / ("keys-" + case + ".txt")
    path.write_text("" if case == "empty" else "k1 " + SENTINEL + "\n", encoding="utf-8")
    return {ENV_KEYS_FILE: str(path)}


CASES = ("unset", "missing", "empty", "no_sha256_prefix")


@pytest.mark.parametrize("case", CASES)
def test_AC_A10_create_app_raises_ConfigError(case, tmp_path):
    with pytest.raises(ConfigError) as caught:
        create_app(environ=_broken_case(case, tmp_path))
    assert ENV_KEYS_FILE in str(caught.value)
    assert SENTINEL not in str(caught.value)


@pytest.mark.parametrize("case", CASES)
def test_AC_A10_the_process_exits_nonzero_naming_the_variable(case, tmp_path):
    env = {**_base_env(), **_broken_case(case, tmp_path)}
    proc = subprocess.run([sys.executable, "-m", "ledgermind_api"], cwd=REPO_ROOT, env=env,
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode != 0
    assert ENV_KEYS_FILE in proc.stderr
    assert (proc.stdout + proc.stderr).count(SENTINEL) == 0


def test_AC_A10_other_outcome_a_valid_keys_file_starts_and_keeps_serving(tmp_path):
    keys = write_keys_file(tmp_path)
    create_app(environ={ENV_KEYS_FILE: str(keys)})  # does not raise
    env = {**_base_env(), ENV_KEYS_FILE: str(keys), "LEDGERMIND_API_PORT": "0"}
    proc = subprocess.Popen([sys.executable, "-m", "ledgermind_api"], cwd=REPO_ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(4)
        still_running = proc.poll() is None
    finally:
        proc.kill()
        proc.wait(timeout=30)
    assert still_running


def test_keygen_writes_the_key_privately_prints_no_value_and_the_key_works(tmp_path):
    keys = tmp_path / "keys.txt"
    out_dir = tmp_path / "private"
    cmd = [sys.executable, "-m", "ledgermind_api.keygen", "--id", "ci-agent", "--keys-file", str(keys),
           "--out-dir", str(out_dir)]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    key = (out_dir / "ci-agent.key").read_text(encoding="utf-8").strip()
    assert len(key) >= 40
    assert (proc.stdout + proc.stderr).count(key) == 0
    assert re.fullmatch(r"ci-agent sha256:[0-9a-f]{64}", keys.read_text(encoding="utf-8").strip())
    with TestClient(create_app(environ={ENV_KEYS_FILE: str(keys)})) as client:
        assert client.get("/v1/health", headers={"X-API-Key": key}).status_code == 200
        assert client.get("/v1/health", headers={"X-API-Key": key + "x"}).status_code == 401
    again = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    assert again.returncode != 0  # refuses a duplicate key_id and never overwrites the key file


def test_AC_A13_one_tool_per_POST_route_with_the_openapi_request_schema(client):
    app = client.app
    spec = client.get("/openapi.json").json()
    post_paths = {r.path for r in app.routes
                  if isinstance(r, APIRoute) and "POST" in r.methods and r.path.startswith("/v1/")}
    tools = client.get("/v1/tools").json()
    assert {t["http"]["path"] for t in tools} == post_paths
    # Plan v2 section 2 Routes: Run A 2 tools; Run B +1 (POST /v1/java/audit). Edited in Run B, same strictness.
    assert len(tools) == len(post_paths) == 3
    for tool in tools:
        assert tool["read_only"] is True
        assert tool["http"]["method"] == "POST"
        body_schema = spec["paths"][tool["http"]["path"]]["post"]["requestBody"]["content"]["application/json"]["schema"]
        component = spec["components"]["schemas"][body_schema["$ref"].rsplit("/", 1)[1]]
        assert tool["input_schema"] == component
        assert tool["input_schema"]  # a real schema, not an empty dict
