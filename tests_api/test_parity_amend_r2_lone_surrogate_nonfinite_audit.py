"""Amend round 2 (2026-09-27), parity gate r2 findings.

A1: a lone-surrogate JSON escape (``"\\udc00x"``, legal JSON) echoed in ``native`` made the API answer
HTTP 500 text/plain, while the CLI gives a verdict on the same files. Bodies are sent as ASCII-escaped
JSON text on purpose: httpx's ``json=`` would fail to encode a lone surrogate on the client side.
A3: a Java audit holding NaN or an overflow (1e999) came back with null in ``native``; it is now refused
with 422, and a finite audit of the same shape is still served.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import KEY_HEADERS, REPO_ROOT, recorded_upload_body
from ledgermind_api.app import create_app

LONE = "\udc00x"
JSON_HEADERS = {"Content-Type": "application/json"}


@pytest.fixture()
def lenient_client(settings):
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as client:
        yield client


def _post(client: TestClient, path: str, body: dict):
    return client.post(path, content=json.dumps(body).encode("ascii"), headers=JSON_HEADERS)


def _cli_on_files(tmp_path: Path, label: str, files: dict) -> tuple[int, dict]:
    half = tmp_path / "corpus" / label
    half.mkdir(parents=True)
    for name, value in files.items():
        (half / name).write_text(json.dumps(value), encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "tools.verify_report", "--corpus", "recorded", "--half", label,
                           "--corpus-root", str(tmp_path / "corpus"), "--json"],
                          cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=120)
    return proc.returncode, json.loads(proc.stdout)


def _body_with(edit) -> dict:
    body = recorded_upload_body("clean")
    bundle = json.loads(json.dumps(body["files"]["postings_and_hashes.json"]))
    edit(bundle)
    body["files"]["postings_and_hashes.json"] = bundle
    return body


def _set_prev_hash(bundle: dict) -> None:
    bundle["postingHashes"][1]["prevHash"] = LONE


def _set_address(bundle: dict) -> None:
    bundle["accounts"][0]["address"] = LONE


@pytest.mark.parametrize("edit, expected", [(_set_prev_hash, "TAMPER_SUSPECTED"), (_set_address, "VERIFIED")],
                         ids=["prevHash", "accounts.address"])
def test_A1_a_lone_surrogate_in_the_snapshot_gets_the_cli_verdict_not_500(lenient_client, tmp_path, edit, expected):
    body = _body_with(edit)
    response = _post(lenient_client, "/v1/verify/snapshot", body)
    print(response.status_code, response.headers.get("content-type"), response.text[:200])
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    result = response.json()
    cli_exit, cli_native = _cli_on_files(tmp_path, "clean", body["files"])
    assert result["status"] == expected
    assert (result["exit_code"], result["native"]) == (cli_exit, cli_native)


def test_A1_a_java_audit_verdict_text_with_a_lone_surrogate_is_200(lenient_client):
    audit = {"tamperDetected": False, "chainIntact": True, "checkpointPresent": False, "verdict": LONE}
    response = _post(lenient_client, "/v1/java/audit", {"audit": audit})
    print(response.status_code, response.text[:200])
    assert response.status_code == 200
    java = response.json()["java"]
    assert java["native"]["verdict"] == LONE
    assert "java verdict text: " + LONE in java["notes"]


def test_A1_sibling_a_validation_problem_that_echoes_a_lone_surrogate_key_is_422_not_500(lenient_client):
    audit = {"tamperDetected": False, "chainIntact": True, "checkpointPresent": False}
    response = _post(lenient_client, "/v1/java/audit", {"audit": audit, LONE: 1})
    print(response.status_code, response.text[:200])
    assert response.status_code == 422
    assert "problem+json" in response.headers["content-type"]


FINITE_AUDIT = '{"audit":{"tamperDetected":false,"chainIntact":true,"checkpointPresent":false,' \
               '"chainedCount":__N__,"extra":{"deep":[__N__]}}}'


@pytest.mark.parametrize("literal", ["1e999", "-1e999", "NaN", "Infinity", "-Infinity"])
def test_A3_a_java_audit_holding_a_non_finite_number_is_422(lenient_client, literal):
    response = lenient_client.post("/v1/java/audit", content=FINITE_AUDIT.replace("__N__", literal),
                                   headers=JSON_HEADERS)
    print(literal, response.status_code, response.text[:300])
    assert response.status_code == 422
    assert "problem+json" in response.headers["content-type"]
    assert "non-finite" in response.text


@pytest.mark.parametrize("literal", ["1e308", "3", "-2.5"])
def test_A3_does_not_fire_the_same_audit_with_a_finite_number_is_200(lenient_client, literal):
    response = lenient_client.post("/v1/java/audit", content=FINITE_AUDIT.replace("__N__", literal),
                                   headers=JSON_HEADERS)
    assert response.status_code == 200, response.text[:300]
    assert response.json()["java"]["native"]["extra"]["deep"] == [json.loads(literal)]


def test_A3_holds_non_finite_fires_both_ways_at_any_position():
    from ledgermind_api.java_audit import holds_non_finite

    assert holds_non_finite({"a": [{"b": float("inf")}]}) is True
    assert holds_non_finite([float("nan")]) is True
    assert holds_non_finite({"a": [{"b": 1e308}], "c": "Infinity", "d": None, "e": True}) is False
