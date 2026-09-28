"""Amend round 1 (2026-09-27): fixes for the security gate r1 findings on 7c81d33.

A1 (F3) the recorded file-name allowlist used ``$``, which in Python ``re`` also matches before a
   trailing newline, so ``account_x.json\\n`` passed and reached ``open()`` -> uncaught OSError -> 500.
A2      ``_write_json`` turns a name the file system refuses into a 422 problem, never a 500.
A3 (F1) the JSON-depth guard was quadratic on unterminated strings and ran in the event loop.
A4      the adversarial case label is checked with ``fullmatch`` (defense in depth; pydantic's Rust
   regex already treats ``$`` as end-of-text, and a ``\\Z`` in the shared pydantic pattern fails to build).
A5      a request body that has not fully arrived within LEDGERMIND_API_BODY_TIMEOUT_S gets 408.

The live tests start the real service (``py -m ledgermind_api``, real uvicorn, real sockets) in a
child process so a blocked event loop can never hang this test process.
"""

from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import KEY_HEADERS, REPO_ROOT, TEST_KEY, make_settings, recorded_upload_body, write_keys_file
from ledgermind_api import app as app_module
from ledgermind_api import runner
from ledgermind_api.app import create_app, json_depth_exceeds
from ledgermind_api.config import ConfigError

SNAPSHOT = "/v1/verify/snapshot"
LIVE_BODY_TIMEOUT_S = 1.5


# ---- A1 ----------------------------------------------------------------------------------------

def test_A1_the_allowlist_refuses_a_trailing_newline_file_name():
    assert runner.recorded_name_allowed("account_x.json") is True
    assert runner.recorded_name_allowed("account_x.json\n") is False
    assert runner.recorded_name_allowed("postings_and_hashes.json\n") is False


def test_A1_an_upload_with_a_trailing_newline_file_name_is_422_problem_never_500(settings):
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as client:
        body = recorded_upload_body("clean")
        body["files"]["account_x.json\n"] = {}
        response = client.post(SNAPSHOT, json=body)
    assert response.status_code == 422, response.text[:300]
    assert "problem+json" in response.headers["content-type"]


# ---- A2 ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["a" * 300 + ".json", "account_a\x00b.json"], ids=["too_long", "nul_byte"])
def test_A2_write_json_turns_a_refused_name_into_a_422_problem(tmp_path, name):
    with pytest.raises(runner.ApiProblem) as caught:
        runner._write_json(tmp_path, name, {})
    assert caught.value.status == 422 and caught.value.code == "validation_error"
    assert str(tmp_path) not in caught.value.detail


def test_A2_with_the_allowlist_bypassed_a_refused_name_is_still_4xx_never_5xx(settings, monkeypatch):
    """Defense in depth: even if a future allowlist lets a bad name through, the write guard answers 4xx."""
    monkeypatch.setattr(runner, "recorded_name_allowed", lambda name: True)
    monkeypatch.setattr(app_module, "recorded_name_allowed", lambda name: True)
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as client:
        body = recorded_upload_body("clean")
        body["files"]["a" * 300 + ".json"] = {}
        response = client.post(SNAPSHOT, json=body)
    assert 400 <= response.status_code < 500, response.text[:300]
    assert "problem+json" in response.headers["content-type"]


# ---- A3 ----------------------------------------------------------------------------------------

def _reference_depth_exceeds(body: bytes, limit: int) -> bool:
    """What a JSON parser does, byte by byte: a string runs from an unescaped quote to the next
    unescaped quote (or to the end of the body when it never closes); brackets count only outside."""
    depth, in_string, escaped = 0, False, False
    for byte in body:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > limit:
                return True
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return False


def test_A3_the_depth_guard_equals_the_byte_by_byte_reference_on_20000_random_bodies():
    rng = random.Random(20260927)
    alphabet = b'[]{}"\\ax\n'
    mismatches = []
    for _ in range(20000):
        body = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        limit = rng.randint(0, 6)
        if json_depth_exceeds(body, limit) != _reference_depth_exceeds(body, limit):
            mismatches.append((body, limit))
    print("mismatches:", len(mismatches), mismatches[:3])
    assert mismatches == []


def _nested(rng: random.Random, depth: int) -> object:
    tricky = ['[', ']', '{', '}', '"', '\\', '\\"', '"[[', 'a']
    leaf = "".join(rng.choice(tricky) for _ in range(rng.randint(0, 6)))
    if depth == 0:
        return leaf
    inner = _nested(rng, depth - 1)
    return [leaf, inner] if rng.random() < 0.5 else {leaf: inner}


def test_A3_valid_json_is_measured_at_its_true_depth_even_with_brackets_and_escapes_in_strings():
    rng = random.Random(7)
    for _ in range(300):
        depth = rng.randint(1, 12)
        body = json.dumps(_nested(rng, depth)).encode("utf-8")
        assert json_depth_exceeds(body, depth) is False
        assert json_depth_exceeds(body, depth - 1) is True


@pytest.mark.parametrize("shape", ["escaped_quotes", "brackets_pairs"])
def test_A3_one_mib_adversarial_body_is_scanned_in_under_one_second(shape):
    code = (
        "import sys, time; sys.path.insert(0, sys.argv[1]); from ledgermind_api.app import json_depth_exceeds\n"
        "body = (b'\"\\\\' if sys.argv[2] == 'escaped_quotes' else b'[]') * (1 << 19)\n"
        "assert len(body) == 1 << 20\n"
        "started = time.perf_counter(); result = json_depth_exceeds(body, 64)\n"
        "print(result, round(time.perf_counter() - started, 3))\n"
    )
    proc = subprocess.run([sys.executable, "-c", code, str(REPO_ROOT), shape], capture_output=True, text=True,
                          timeout=20)
    assert proc.returncode == 0, proc.stderr[-500:]
    result, seconds = proc.stdout.split()
    print(shape, "->", result, seconds, "s")
    assert result == "False" and float(seconds) < 1.0


# ---- A4 ----------------------------------------------------------------------------------------

def test_A4_a_case_label_with_a_trailing_newline_is_refused_before_anything_is_staged():
    with pytest.raises(ValueError, match="case_label"):
        runner.verify_adversarial_upload(sys.executable, REPO_ROOT, "upload\n", {}, 5.0)


def test_A4_the_http_route_still_refuses_it_with_422(client):
    response = client.post(SNAPSHOT, json={"kind": "adversarial", "case_label": "upload\n", "document": {}})
    assert response.status_code == 422


# ---- A5 config ---------------------------------------------------------------------------------

def test_A5_body_timeout_defaults_to_10_s_and_an_invalid_value_fails_closed(keys_file):
    assert make_settings(keys_file).body_timeout_s == 10.0
    assert make_settings(keys_file, LEDGERMIND_API_BODY_TIMEOUT_S="2.5").body_timeout_s == 2.5
    for bad in ("0", "-1", "soon"):
        with pytest.raises(ConfigError, match="LEDGERMIND_API_BODY_TIMEOUT_S"):
            make_settings(keys_file, LEDGERMIND_API_BODY_TIMEOUT_S=bad)


# ---- live service (real uvicorn in a child process) ----------------------------------------------

def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _raw_request(port: int, request: bytes, timeout: float) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
        conn.sendall(request)
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return data
            data += chunk


def _post_bytes(port: int, path: str, body: bytes, timeout: float) -> bytes:
    head = ("POST " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nX-API-Key: " + TEST_KEY + "\r\n"
            "Content-Type: application/json\r\nContent-Length: " + str(len(body)) + "\r\nConnection: close\r\n\r\n")
    return _raw_request(port, head.encode("ascii") + body, timeout)


def _health(port: int, timeout: float) -> bytes:
    return _raw_request(port, ("GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-API-Key: " + TEST_KEY +
                               "\r\nConnection: close\r\n\r\n").encode("ascii"), timeout)


@pytest.fixture()
def live_server(tmp_path):
    port = _free_port()
    keys = write_keys_file(tmp_path)
    log_path = tmp_path / "server.log"
    env = dict(os.environ, LEDGERMIND_API_KEYS_FILE=str(keys), LEDGERMIND_API_PORT=str(port),
               LEDGERMIND_API_BODY_TIMEOUT_S=str(LIVE_BODY_TIMEOUT_S))
    with open(log_path, "wb") as log:
        proc = subprocess.Popen([sys.executable, "-m", "ledgermind_api"], cwd=REPO_ROOT, env=env, stdout=log,
                                stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                if _health(port, 2.0).startswith(b"HTTP/1.1 200"):
                    break
            except OSError:
                pass
            assert proc.poll() is None, "server exited: " + log_path.read_text(errors="replace")[-500:]
            assert time.monotonic() < deadline, "server never became ready"
            time.sleep(0.2)
        yield port, log_path
    finally:
        proc.kill()
        proc.wait(timeout=10)


def _five_xx_lines(log_path: Path) -> list[str]:
    return [line for line in log_path.read_text(errors="replace").splitlines() if '" 5' in line and "HTTP/1.1" in line]


def test_positive_control_the_5xx_counter_fires_on_a_planted_access_log_line(tmp_path):
    log = tmp_path / "planted.log"
    log.write_text('INFO:     127.0.0.1:1 - "POST /v1/verify/snapshot HTTP/1.1" 500 Internal Server Error\n'
                   'INFO:     127.0.0.1:1 - "GET /v1/health HTTP/1.1" 200 OK\n', encoding="utf-8")
    assert len(_five_xx_lines(log)) == 1


def test_A3_live_health_stays_fast_while_a_one_mib_escaped_quote_body_is_in_flight(live_server):
    port, log_path = live_server
    body = b'"\\' * ((1 << 19) - 64)
    outcome: dict = {}

    def post() -> None:
        try:
            outcome["response"] = _post_bytes(port, SNAPSHOT, body, timeout=15.0)
        except OSError as exc:
            outcome["error"] = type(exc).__name__

    worker = threading.Thread(target=post, daemon=True)
    worker.start()
    time.sleep(0.2)
    started = time.monotonic()
    health = _health(port, timeout=5.0)
    elapsed = time.monotonic() - started
    worker.join(timeout=15.0)
    print("health", health[:12], round(elapsed, 3), "s; post", outcome.get("response", b"")[:12], outcome.get("error"))
    assert health.startswith(b"HTTP/1.1 200") and elapsed < 2.0
    assert outcome.get("response", b"").startswith(b"HTTP/1.1 422")
    newline_name = recorded_upload_body("clean")
    newline_name["files"]["account_x.json\n"] = {}
    assert _post_bytes(port, SNAPSHOT, json.dumps(newline_name).encode("utf-8"), 30.0).startswith(b"HTTP/1.1 422")
    assert _five_xx_lines(log_path) == []


def test_A5_live_a_slow_drip_body_gets_408_problem_within_the_body_timeout(live_server):
    port, log_path = live_server
    head = ("POST " + SNAPSHOT + " HTTP/1.1\r\nHost: 127.0.0.1\r\nX-API-Key: " + TEST_KEY + "\r\n"
            "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n").encode("ascii")
    received = b""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.sendall(head)
        started = time.monotonic()
        conn.settimeout(0.4)
        for _ in range(20):  # one byte every 0.4 s: 20 bytes of the 100 declared, 8 s in total
            try:
                conn.sendall(b" ")
            except OSError:
                break
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            received += chunk
            break
        elapsed = time.monotonic() - started
    print("slow drip answered after", round(elapsed, 2), "s:", received[:40])
    assert received.startswith(b"HTTP/1.1 408"), received[:200]
    assert b"problem+json" in received
    assert elapsed < LIVE_BODY_TIMEOUT_S + 3.0
    assert _five_xx_lines(log_path) == []


# ---- P4 guard (parity gate r1): the API side of an unreadable amount ------------------------------

def test_P4_an_uploaded_amount_of_1e999_is_502_backend_tool_error_never_a_verdict(client):
    body = recorded_upload_body("clean")
    body["files"]["postings_and_hashes.json"]["postings"][0]["amount"] = "__AMOUNT__"
    raw = json.dumps(body).replace('"__AMOUNT__"', "1e999").encode("utf-8")
    response = client.post(SNAPSHOT, content=raw, headers={"Content-Type": "application/json"})
    assert response.status_code == 502, response.text[:300]
    assert response.json()["code"] == "backend_tool_error"
