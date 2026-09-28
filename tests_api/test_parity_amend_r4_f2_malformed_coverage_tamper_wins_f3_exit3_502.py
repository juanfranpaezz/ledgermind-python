"""Amend round 4 (2026-09-28): plan v2 section 3.2, the two "[Pinned 2026-09-28]" lines.

F2 (parity gate r3 A2): rule 1 applies whenever tamperDetected is true, even when coverageDegraded is
present but not a boolean. Worst wins: a malformed coverage field must never hide a tamper signal, so
such an audit is TAMPER_SUSPECTED, never ERROR unknown_shape. RED at c413a82: java_status checked the
type of coverageDegraded BEFORE tamperDetected and answered ERROR. With tamperDetected=false the same
malformed field stays ERROR unknown_shape (unchanged). The ERROR note never says "not a tamper finding"
when the upload says tamperDetected=true (reachable when a required boolean is missing).

F3: a Python exit 3 inside POST /v1/java/audit fails the whole request with 502 and returns no partial
verdict (no java, python or agree in the body). This pins the behaviour c413a82 already had.
"""

from __future__ import annotations

import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

from conftest import KEY_HEADERS, make_settings, recorded_upload_body
from ledgermind_api.app import create_app

ROUTE = "/v1/java/audit"
NOT_A_TAMPER_FINDING = "not a tamper finding"

# JSON values that are present but not a boolean: a string, a number, an array, an object, null.
MALFORMED_COVERAGE = ["yes", 1, [], {}, None]
MALFORMED_IDS = ["string_yes", "number_1", "empty_array", "empty_object", "null"]


def _audit(tamper: bool, coverage: object) -> dict:
    # chainIntact=false: when the status is TAMPER_SUSPECTED the formula also proves it.
    return {"tamperDetected": tamper, "coverageDegraded": coverage, "coverageReason": "ATRASADO",
            "chainIntact": not tamper, "checkpointPresent": True, "signatureValid": True,
            "signedHeadStillInChain": True, "balancesConsistent": True}


@pytest.fixture(scope="module")
def client_500_visible(settings):
    # raise_server_exceptions=False: a crash shows as the HTTP 500 a real client would get.
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as test_client:
        yield test_client


def _java(client, audit: dict) -> dict:
    response = client.post(ROUTE, json={"audit": audit})
    assert response.status_code == 200, response.text[:300]
    return response.json()["java"]


# ---- F2 -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("coverage", MALFORMED_COVERAGE, ids=MALFORMED_IDS)
def test_F2_tamper_detected_true_with_a_non_boolean_coverage_degraded_is_tamper_suspected(client_500_visible,
                                                                                          coverage):
    java = _java(client_500_visible, _audit(True, coverage))
    print("tamperDetected=true coverageDegraded", repr(coverage), "->", java["status"], java["notes"])
    assert (java["status"], java["mapping_basis"], java["tamper_proven"]) == ("TAMPER_SUSPECTED", "field", True)
    assert java["coverage_degraded"] is False  # only a JSON true counts as degraded
    assert not any(note.startswith("unknown_shape") for note in java["notes"])
    assert not any(NOT_A_TAMPER_FINDING in note for note in java["notes"])
    assert any(note.startswith("coverageDegraded is not a boolean") for note in java["notes"])


@pytest.mark.parametrize("coverage", MALFORMED_COVERAGE, ids=MALFORMED_IDS)
def test_F2_control_tamper_detected_false_with_the_same_field_stays_error_unknown_shape(client_500_visible,
                                                                                        coverage):
    java = _java(client_500_visible, _audit(False, coverage))
    assert (java["status"], java["mapping_basis"], java["tamper_proven"]) == ("ERROR", "field", False)
    assert any(note.startswith("unknown_shape") and NOT_A_TAMPER_FINDING in note for note in java["notes"])


def test_F2_an_error_note_never_says_not_a_tamper_finding_when_tamper_detected_is_true(client_500_visible):
    # checkpointPresent missing: a required boolean is missing, so the status is ERROR unknown_shape.
    java = _java(client_500_visible, {"tamperDetected": True, "coverageDegraded": False, "chainIntact": False})
    print("tamper=true, checkpointPresent missing ->", java["status"], java["notes"])
    assert (java["status"], java["tamper_proven"]) == ("ERROR", False)
    shape_notes = [note for note in java["notes"] if note.startswith("unknown_shape")]
    assert len(shape_notes) == 1
    assert NOT_A_TAMPER_FINDING not in shape_notes[0]
    assert "tamperDetected=true" in shape_notes[0]


def test_F2_control_the_same_error_with_tamper_detected_false_still_says_not_a_tamper_finding(client_500_visible):
    java = _java(client_500_visible, {"tamperDetected": False, "coverageDegraded": False, "chainIntact": True})
    assert java["status"] == "ERROR"
    assert any(note.startswith("unknown_shape") and NOT_A_TAMPER_FINDING in note for note in java["notes"])


# ---- F3 -----------------------------------------------------------------------------------------

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


def _post_java_with_snapshot(keys_file, tmp_path, exit_code: int, verdict: str):
    settings = make_settings(keys_file, LEDGERMIND_PY_EXE=_stub_backend(tmp_path, exit_code, verdict))
    body = {"audit": _audit(True, False), "snapshot": recorded_upload_body("clean")}
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as client:
        return client.post(ROUTE, json=body)


def test_F3_a_python_exit_3_fails_the_whole_java_audit_request_with_502_and_no_partial_verdict(keys_file, tmp_path):
    response = _post_java_with_snapshot(keys_file, tmp_path, 3, "OK")
    print("F3 exit 3 ->", response.status_code, response.text[:200])
    assert response.status_code == 502, response.text[:300]
    body = response.json()
    assert body["code"] == "backend_tool_error"
    assert not {"java", "python", "agree"} & set(body)
    for status in ("TAMPER_SUSPECTED", "VERIFIED", "COVERAGE_DEGRADED", "INCOMPLETE"):
        assert status not in response.text


def test_F3_control_the_same_request_with_a_python_exit_0_returns_both_verdicts(keys_file, tmp_path):
    response = _post_java_with_snapshot(keys_file, tmp_path, 0, "OK")
    assert response.status_code == 200, response.text[:300]
    body = response.json()
    assert (body["java"]["status"], body["python"]["status"], body["agree"]) == ("TAMPER_SUSPECTED", "VERIFIED", "NO")
