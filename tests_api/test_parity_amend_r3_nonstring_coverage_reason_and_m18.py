"""Amend round 3 (2026-09-28): parity gate r3 on 5801b5c.

F1/A1: a ``coverageReason`` that is a JSON array or object (with coverageDegraded=true and
tamperDetected=false) crashed POST /v1/java/audit with HTTP 500: the set lookup raised
``TypeError: unhashable type``. Plan v2 section 3.2: any reason that is not a known value -> ERROR
unknown_shape, and client input never gets a 500. The fix checks ``isinstance(reason, str)`` before
the lookup. Real Java cannot emit it (the field is an enum); a malformed or crafted upload can.

F4/A3: mutant M18 (``tamper_proven`` no longer gated on ``status == "TAMPER_SUSPECTED"``) left every
earlier test green. The row below pins the gate: tamperDetected=true, chainIntact=false and
checkpointPresent missing is ERROR (a required boolean is missing), so it can never read tamper_proven=true.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from conftest import KEY_HEADERS
from ledgermind_api.app import create_app
from ledgermind_api.java_audit import java_tamper_proven

ROUTE = "/v1/java/audit"


@pytest.fixture(scope="module")
def client_500_visible(settings):
    # raise_server_exceptions=False: a crash shows as the HTTP 500 a real client would get.
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as test_client:
        yield test_client


def _degraded_audit(reason: object) -> dict:
    return {"tamperDetected": False, "coverageDegraded": True, "coverageReason": reason, "chainIntact": True,
            "checkpointPresent": True, "signatureValid": True, "signedHeadStillInChain": True}


@pytest.mark.parametrize("reason", [[], {}, ["ATRASADO"], {"ATRASADO": True}],
                         ids=["empty_array", "empty_object", "array_of_a_known_reason", "object_keyed_by_a_known_reason"])
def test_A1_a_non_string_coverage_reason_is_200_error_unknown_shape_never_500(client_500_visible, reason):
    response = client_500_visible.post(ROUTE, json={"audit": _degraded_audit(reason)})
    print("coverageReason", reason, "->", response.status_code, response.text[:120])
    assert response.status_code == 200, response.text[:300]
    java = response.json()["java"]
    assert java["status"] == "ERROR" and java["tamper_proven"] is False
    assert any(note.startswith("unknown_shape") for note in java["notes"])


def test_A1_control_the_same_audit_with_a_known_string_reason_is_coverage_degraded(client_500_visible):
    response = client_500_visible.post(ROUTE, json={"audit": _degraded_audit("ATRASADO")})
    assert response.status_code == 200
    assert response.json()["java"]["status"] == "COVERAGE_DEGRADED"


M18_ROW = {"tamperDetected": True, "chainIntact": False}  # checkpointPresent missing


def test_A3_M18_tamper_proven_is_false_whenever_the_status_is_not_tamper_suspected(client_500_visible):
    # The formula alone says proven (tamperDetected and not chainIntact); only the status gate stops it.
    assert java_tamper_proven(M18_ROW) is True
    response = client_500_visible.post(ROUTE, json={"audit": M18_ROW})
    assert response.status_code == 200
    java = response.json()["java"]
    print("M18 row ->", java["status"], java["tamper_proven"])
    assert java["status"] == "ERROR"
    assert java["tamper_proven"] is False


def test_A3_control_the_same_row_with_checkpointPresent_false_is_tamper_suspected_and_proven(client_500_visible):
    response = client_500_visible.post(ROUTE, json={"audit": dict(M18_ROW, checkpointPresent=False)})
    java = response.json()["java"]
    assert java["status"] == "TAMPER_SUSPECTED" and java["tamper_proven"] is True
