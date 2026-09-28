"""Run A, AC-A.9 (auth on every route), AC-A.11 (size and depth), AC-A.12 (timeout)."""

from __future__ import annotations

import json
import os
import secrets
import sys
import time

import pytest
from fastapi.testclient import TestClient

from conftest import KEY_HEADERS, TEST_KEY, make_settings, recorded_upload_body
from ledgermind_api.app import create_app

METHODS = ("GET", "POST", "HEAD", "OPTIONS")


def test_AC_A9_no_route_and_no_method_answers_without_a_valid_key(settings):
    app = create_app(settings)
    paths = sorted({route.path for route in app.routes}) + ["/nonexistent"]
    assert {"/openapi.json", "/docs", "/v1/health", "/v1/verify/corpus", "/v1/verify/snapshot", "/v1/tools"} <= set(paths)
    answered_without_key = []
    pairs = 0
    with TestClient(app) as anon:
        for path in paths:
            for method in METHODS:
                pairs += 1
                missing = anon.request(method, path)
                wrong = anon.request(method, path, headers={"X-API-Key": "wrong-" + secrets.token_hex(8)})
                if missing.status_code != 401 or (method != "HEAD" and missing.json()["code"] != "auth_missing"):
                    answered_without_key.append((method, path, "missing", missing.status_code))
                if wrong.status_code != 401 or (method != "HEAD" and wrong.json()["code"] != "auth_invalid"):
                    answered_without_key.append((method, path, "wrong", wrong.status_code))
        print("AC-A.9 (route, method) pairs =", pairs, "non-401 without a valid key =", len(answered_without_key))
        assert answered_without_key == []
        ok = anon.get("/v1/health", headers={"X-API-Key": TEST_KEY})
        assert ok.status_code == 200
        assert ok.json() == {"status": "ok"}
        # the other outcome: with the key the automatic routes DO answer (the guard is not a 401-everything stub)
        assert anon.get("/openapi.json", headers={"X-API-Key": TEST_KEY}).status_code == 200
        assert anon.get("/docs", headers={"X-API-Key": TEST_KEY}).status_code == 200
        assert anon.get("/nonexistent", headers={"X-API-Key": TEST_KEY}).status_code == 404


def test_AC_A11_content_length_over_the_limit_is_413(client, settings):
    body = b" " * (settings.max_body_bytes + 1)
    response = client.post("/v1/verify/snapshot", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert response.json()["code"] == "body_too_large"


def test_AC_A11_a_chunked_body_over_the_limit_without_content_length_is_413(client, settings):
    def chunks():
        remaining = settings.max_body_bytes + 1
        while remaining > 0:
            size = min(65536, remaining)
            remaining -= size
            yield b" " * size

    response = client.post("/v1/verify/snapshot", content=chunks(), headers={"Content-Type": "application/json"})
    assert "content-length" not in {name.lower() for name in response.request.headers}
    assert response.status_code == 413


def test_AC_A11_the_counting_guard_stops_reading_a_streamed_body_early(settings):
    """ASGI-level drive of the FULL app (all middleware): 64 KiB chunks, more_body=True, no Content-Length."""
    import anyio

    app = create_app(settings)
    chunk = b" " * 65536
    total_chunks = settings.max_body_bytes // len(chunk) + 50
    state = {"sent": 0, "status": None}

    async def receive():
        state["sent"] += 1
        return {"type": "http.request", "body": chunk, "more_body": state["sent"] < total_chunks}

    async def send(message):
        if message["type"] == "http.response.start":
            state["status"] = message["status"]

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/v1/verify/snapshot", "raw_path": b"/v1/verify/snapshot", "query_string": b"", "root_path": "",
        "headers": [(b"x-api-key", TEST_KEY.encode()), (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 1), "server": ("testserver", 80),
    }
    anyio.run(app, scope, receive, send)
    print("chunks read before 413:", state["sent"], "of", total_chunks)
    assert state["status"] == 413
    assert state["sent"] < total_chunks


def test_AC_A11_a_Content_Length_over_the_limit_is_413_before_the_body_is_read(settings):
    """Gate fix A5 (2026-09-25), plan rule D-5: the body is rejected BEFORE it is read. Removing the
    Content-Length pre-check left the whole suite green (mutant M14), because the byte-counting guard
    also answers 413 once it has read the body. Pure-ASGI drive of the FULL app (all middleware): the
    over-limit request must get 413 with receive() never called; the control request (a declared
    length within the limit) must reach receive(), so the counter is shown able to move."""
    import anyio

    app = create_app(settings)

    def drive(declared_length: int) -> dict:
        state = {"receive_calls": 0, "status": None}

        async def receive():
            state["receive_calls"] += 1
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(message):
            if message["type"] == "http.response.start":
                state["status"] = message["status"]

        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
            "path": "/v1/verify/snapshot", "raw_path": b"/v1/verify/snapshot", "query_string": b"", "root_path": "",
            "headers": [(b"x-api-key", TEST_KEY.encode()), (b"content-type", b"application/json"),
                        (b"content-length", str(declared_length).encode("ascii"))],
            "client": ("127.0.0.1", 1), "server": ("testserver", 80),
        }
        anyio.run(app, scope, receive, send)
        return state

    over = drive(settings.max_body_bytes + 1)
    within = drive(2)
    # Boundary (delta-gate A4): a declared length EQUAL to the limit is allowed and gets read.
    at_limit = drive(settings.max_body_bytes)
    print("Content-Length over limit:", over, "; within limit:", within, "; at limit:", at_limit)
    assert over["status"] == 413
    assert over["receive_calls"] == 0
    assert within["receive_calls"] >= 1
    assert within["status"] != 413
    assert at_limit["status"] != 413
    assert at_limit["receive_calls"] >= 1


def test_AC_A11_an_oversized_body_without_a_key_is_401_not_413(anon_client, settings):
    body = b" " * (settings.max_body_bytes + 1)
    response = anon_client.post("/v1/verify/snapshot", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 401


def test_AC_A11_the_largest_recorded_half_upload_is_200(client, settings):
    bodies = [recorded_upload_body("clean"), recorded_upload_body("tampered")]
    largest = max(bodies, key=lambda b: len(json.dumps(b)))
    print("largest recorded upload bytes:", len(json.dumps(largest)), "limit:", settings.max_body_bytes)
    assert client.post("/v1/verify/snapshot", json=largest).status_code == 200


def test_AC_A11_json_nested_10000_deep_is_422_and_never_5xx(client, settings):
    depth = 10_000
    bare = ("[" * depth + "]" * depth).encode()
    inside = ('{"kind":"adversarial","document":' + '{"a":' * depth + "1" + "}" * depth + "}").encode()
    statuses = []
    for body in (bare, inside):
        assert len(body) <= settings.max_body_bytes
        statuses.append(client.post("/v1/verify/snapshot", content=body,
                                    headers={"Content-Type": "application/json"}).status_code)
    print("deep-JSON statuses:", statuses)
    assert statuses == [422, 422]
    assert sum(1 for s in statuses if s >= 500) == 0


def test_the_depth_guard_fires_at_65_and_not_at_64(client):
    def body_with_total_depth(total: int) -> bytes:
        inner = total - 1  # the request object itself is one level
        return ('{"kind":"adversarial","document":' + '{"a":' * inner + "1" + "}" * inner + "}").encode()

    at_limit = client.post("/v1/verify/snapshot", content=body_with_total_depth(64),
                           headers={"Content-Type": "application/json"})
    over = client.post("/v1/verify/snapshot", content=body_with_total_depth(65),
                       headers={"Content-Type": "application/json"})
    print("depth 64 ->", at_limit.status_code, "; depth 65 ->", over.status_code)
    assert at_limit.status_code != 422
    assert over.status_code == 422


def test_AC_A12_a_backend_that_sleeps_past_the_timeout_is_504(keys_file, tmp_path):
    if os.name == "nt":
        stub = tmp_path / "slow-python.bat"
        stub.write_text('@"' + sys.executable + '" -c "import time; time.sleep(30)"\r\n', encoding="ascii")
    else:
        stub = tmp_path / "slow-python.sh"
        stub.write_text("#!/bin/sh\nexec sleep 30\n", encoding="ascii")
        stub.chmod(0o755)
    settings = make_settings(keys_file, LEDGERMIND_PY_EXE=stub, LEDGERMIND_PY_TIMEOUT_S=2)
    with TestClient(create_app(settings), headers=KEY_HEADERS) as client:
        started = time.monotonic()
        response = client.post("/v1/verify/corpus", json={"corpus_id": "repo-recorded", "half": "clean"})
        elapsed = time.monotonic() - started
    print("timeout leg: status", response.status_code, "elapsed %.1fs" % elapsed)
    assert response.status_code == 504
    assert response.json()["code"] == "backend_timeout"
    assert elapsed < 20, "the process tree was not killed: the 30 s grandchild held the pipes"


def _stub_backend(tmp_path, exit_code: int, verdict: str):
    """A fake verifier that prints a well-formed JSON verdict and exits with ``exit_code``."""
    script = tmp_path / "fake_cli.py"
    payload = {"verdict": verdict, "subject": "stub", "violation_count": 0, "checks": [], "signature": {}}
    script.write_text("import sys\nprint(" + repr(json.dumps(payload)) + ")\nsys.exit(" + str(exit_code) + ")\n",
                      encoding="utf-8")
    if os.name == "nt":
        stub = tmp_path / "fake-python.bat"
        stub.write_text('@"' + sys.executable + '" "' + str(script) + '"\r\n@exit /b %errorlevel%\r\n', encoding="ascii")
    else:
        stub = tmp_path / "fake-python.sh"
        stub.write_text('#!/bin/sh\nexec "' + sys.executable + '" "' + str(script) + '"\n', encoding="ascii")
        stub.chmod(0o755)
    return stub


@pytest.mark.parametrize("exit_code, verdict, http_status, code", [
    (3, "OK", 502, "backend_tool_error"),          # tool error with JSON on stdout: still never a verdict
    (5, "TAMPERED", 502, "backend_tool_error"),    # an exit code outside the taxonomy
    (0, "TAMPERED", 502, "verdict_exit_mismatch"),  # exit 0 whose JSON is not OK
    (1, "OK", 502, "verdict_exit_mismatch"),        # exit 1 whose JSON is not TAMPERED
    (0, "OK", 200, None),                           # the other outcome: a coherent pair maps to a verdict
])
def test_section_3_1_exit_code_is_authoritative_and_incoherent_pairs_are_502(keys_file, tmp_path, exit_code,
                                                                                verdict, http_status, code):
    settings = make_settings(keys_file, LEDGERMIND_PY_EXE=_stub_backend(tmp_path, exit_code, verdict))
    with TestClient(create_app(settings), headers=KEY_HEADERS) as client:
        response = client.post("/v1/verify/corpus", json={"corpus_id": "repo-recorded", "half": "clean"})
    assert response.status_code == http_status, response.text
    if code is not None:
        assert response.json()["code"] == code
        assert "TAMPER_SUSPECTED" not in response.text
    else:
        assert response.json()["status"] == "VERIFIED"
