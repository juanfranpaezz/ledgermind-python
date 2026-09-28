"""Pre-publish fix (2026-09-28): the ERROR ``unknown_shape`` note and a tamperDetected that is present but
not the JSON boolean ``false``.

When tamperDetected is present but is not exactly ``false`` (the string "true", a number, null, an array,
an object), the report's shape is unknown and nothing is concluded. The note must then NOT say "not a
tamper finding": the upload may be claiming a tamper, so the honest reading is "the tamper question is
unanswered", not "clean". RED at 7108d37: the note said "this is not a tamper finding" for every such
value. Control: with tamperDetected=false the note still says "not a tamper finding" (unchanged).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from conftest import KEY_HEADERS
from ledgermind_api.app import create_app
from ledgermind_api.java_audit import map_java

ROUTE = "/v1/java/audit"
NOT_A_TAMPER_FINDING = "not a tamper finding"

# Present, but not the JSON boolean false. A string "true" is the case that reads most like a claim.
NON_FALSE_TAMPER = ["true", "false", 1, 0, None, [], {}]
NON_FALSE_IDS = ["string_true", "string_false", "number_1", "number_0", "null", "empty_array", "empty_object"]


def _audit(tamper: object) -> dict:
    # Every other required boolean is well formed, so tamperDetected alone decides the ERROR.
    return {"tamperDetected": tamper, "coverageDegraded": False, "chainIntact": True,
            "checkpointPresent": True, "signatureValid": True, "signedHeadStillInChain": True}


def _unknown_shape_notes(java: dict) -> list[str]:
    return [note for note in java["notes"] if note.startswith("unknown_shape")]


@pytest.mark.parametrize("tamper", NON_FALSE_TAMPER, ids=NON_FALSE_IDS)
def test_non_false_tamper_detected_error_note_never_says_not_a_tamper_finding(tamper):
    java = map_java(_audit(tamper), "upload")
    print("tamperDetected", repr(tamper), "->", java["status"], java["notes"])
    assert java["status"] == "ERROR"
    notes = _unknown_shape_notes(java)
    assert len(notes) == 1
    assert NOT_A_TAMPER_FINDING not in notes[0]
    assert "tamper question is unanswered" in notes[0]
    assert java["tamper_proven"] is False


def test_control_tamper_detected_false_keeps_not_a_tamper_finding():
    audit = _audit(False)
    del audit["checkpointPresent"]  # a missing required boolean: ERROR unknown_shape with tamper=false
    java = map_java(audit, "upload")
    notes = _unknown_shape_notes(java)
    assert java["status"] == "ERROR" and len(notes) == 1
    assert NOT_A_TAMPER_FINDING in notes[0]


def test_route_string_true_tamper_detected_note_over_http(settings):
    # The deployed wiring: the same audit through POST /v1/java/audit.
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as client:
        response = client.post(ROUTE, json={"audit": _audit("true")})
    assert response.status_code == 200, response.text[:300]
    java = response.json()["java"]
    print("HTTP tamperDetected='true' ->", java["status"], java["notes"])
    assert java["status"] == "ERROR"
    assert not any(NOT_A_TAMPER_FINDING in note for note in java["notes"])
    assert any("tamper question is unanswered" in note for note in _unknown_shape_notes(java))
