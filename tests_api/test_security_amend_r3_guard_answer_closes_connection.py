"""Amend round 3 (2026-09-28): security gate r3 finding S1 on 5801b5c.

Once a pure-ASGI guard answers (401 without a valid key, 408 for a body that arrives too slowly) while
the request body is still incomplete, the server must close the TCP connection. At 5801b5c a client
that kept sending one more byte after the answer held the socket open with no limit, even without a
key (the gate measured it still open at 25 s). The fix sends ``Connection: close`` with every guard
problem response, so uvicorn closes the connection once the answer is out.

Control: a complete keyed request still gets HTTP keep-alive (a second request on the same socket).

The live tests start the real service (``py -m ledgermind_api``, real uvicorn, real sockets) in a
child process and stop it by the PID they started (the whole process tree of that PID on Windows,
where a venv ``python.exe`` is a launcher whose child owns the listening socket).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

import pytest

from conftest import REPO_ROOT, TEST_KEY, write_keys_file

SNAPSHOT = "/v1/verify/snapshot"
LIVE_BODY_TIMEOUT_S = 1.5
DRIP_INTERVAL_S = 0.4
DECLARED_LENGTH = 100


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _read_one_response(conn: socket.socket, deadline_s: float) -> bytes:
    """Read exactly one HTTP/1.1 response framed by Content-Length (the service always sends one)."""
    data = b""
    end = time.monotonic() + deadline_s
    while b"\r\n\r\n" not in data:
        assert time.monotonic() < end, "no complete response head: " + repr(data[:200])
        chunk = conn.recv(65536)
        assert chunk, "connection closed before a response head: " + repr(data[:200])
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        assert time.monotonic() < end, "response body incomplete"
        chunk = conn.recv(65536)
        assert chunk, "connection closed inside the response body"
        body += chunk
    return head + b"\r\n\r\n" + body


def _health_once(port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as conn:
        conn.sendall(("GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-API-Key: " + TEST_KEY +
                      "\r\n\r\n").encode("ascii"))
        return _read_one_response(conn, 2.0)


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.kill()
    proc.wait(timeout=10)


@pytest.fixture()
def live_port(tmp_path):
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
                if _health_once(port).startswith(b"HTTP/1.1 200"):
                    break
            except (OSError, AssertionError):
                pass
            assert proc.poll() is None, "server exited: " + log_path.read_text(errors="replace")[-500:]
            assert time.monotonic() < deadline, "server never became ready"
            time.sleep(0.2)
        yield port
    finally:
        _stop(proc)


def _drip_after_answer(port: int, with_key: bool, cap_s: float) -> tuple[bytes, float | None, float | None]:
    """Send the head (Content-Length 100) and 3 body bytes, then keep sending one byte every 0.4 s,
    also AFTER the server has answered. Returns (bytes received, seconds to the first response byte,
    seconds to the server closing the connection, or None if it was still open at ``cap_s``)."""
    key_line = ("X-API-Key: " + TEST_KEY + "\r\n") if with_key else ""
    head = ("POST " + SNAPSHOT + " HTTP/1.1\r\nHost: 127.0.0.1\r\n" + key_line +
            "Content-Type: application/json\r\nContent-Length: " + str(DECLARED_LENGTH) + "\r\n\r\n")
    received = b""
    first = None
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as conn:
        conn.sendall(head.encode("ascii") + b"{  ")
        started = time.monotonic()
        conn.settimeout(DRIP_INTERVAL_S)
        sent = 3
        while time.monotonic() - started < cap_s:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                chunk = None
            except OSError:  # a reset is the server closing the connection too
                return received, first, time.monotonic() - started
            if chunk == b"":
                return received, first, time.monotonic() - started
            if chunk:
                received += chunk
                if first is None:
                    first = time.monotonic() - started
                continue
            if sent < DECLARED_LENGTH - 1:  # never complete the body: it stays incomplete throughout
                try:
                    conn.sendall(b" ")
                    sent += 1
                except OSError:
                    return received, first, time.monotonic() - started
    return received, first, None


def test_S1_keyed_slow_body_gets_408_and_the_connection_closes_even_while_bytes_keep_coming(live_port):
    received, first, closed_at = _drip_after_answer(live_port, with_key=True, cap_s=12.0)
    print("keyed drip:", received[:15], "first byte at", first, "s; closed at", closed_at, "s")
    assert received.startswith(b"HTTP/1.1 408"), received[:200]
    assert closed_at is not None, "connection still open 12 s after the 408 while the client kept dripping"
    assert closed_at < LIVE_BODY_TIMEOUT_S + 2.0


def test_S1_no_key_slow_body_gets_401_and_the_connection_closes_even_while_bytes_keep_coming(live_port):
    received, first, closed_at = _drip_after_answer(live_port, with_key=False, cap_s=8.0)
    print("no-key drip:", received[:15], "first byte at", first, "s; closed at", closed_at, "s")
    assert received.startswith(b"HTTP/1.1 401"), received[:200]
    assert closed_at is not None, "connection still open 8 s after the 401 while the client kept dripping"
    assert closed_at < 2.0


def test_S1_control_a_complete_keyed_request_keeps_the_connection_alive(live_port):
    request = ("GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-API-Key: " + TEST_KEY + "\r\n\r\n").encode("ascii")
    with socket.create_connection(("127.0.0.1", live_port), timeout=5.0) as conn:
        conn.sendall(request)
        first = _read_one_response(conn, 5.0)
        time.sleep(1.0)
        conn.sendall(request)
        second = _read_one_response(conn, 5.0)
    print("keep-alive:", first[:15], second[:15])
    assert first.startswith(b"HTTP/1.1 200") and b"connection: close" not in first.lower()
    assert second.startswith(b"HTTP/1.1 200")
