"""Run B: POST /v1/java/audit. Every test drives the FULL app over HTTP (all middleware on).

AC-B.1 golden rows (tests_api/golden/java/*.json; expected values hand-derived from plan v2 section 3.2),
AC-B.2 the status can take all 5 values, AC-B.3 the safety property over 500 generated audits,
AC-B.4 the differential ``agree`` takes all 3 values.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from conftest import REPO_ROOT, direct_cli, recorded_upload_body

GOLDEN_DIR = Path(__file__).resolve().parent / "golden" / "java"
GOLDEN_FILES = sorted(GOLDEN_DIR.glob("*.json"))
EXPECTED_ROWS = 13
ROUTE = "/v1/java/audit"
FIVE_STATUSES = {"VERIFIED", "COVERAGE_DEGRADED", "TAMPER_SUSPECTED", "INCOMPLETE", "ERROR"}


def load_row(path: Path) -> tuple[dict, dict]:
    row = json.loads(path.read_text(encoding="utf-8"))
    if "audit_fixture" in row:
        audit = json.loads((REPO_ROOT / row["audit_fixture"]).read_text(encoding="utf-8"))
    else:
        audit = row["audit"]
    return audit, row["expected"]


def post_audit(client, audit: dict, snapshot: dict | None = None) -> dict:
    body = {"audit": audit} if snapshot is None else {"audit": audit, "snapshot": snapshot}
    response = client.post(ROUTE, json=body)
    assert response.status_code == 200, response.text[:500]
    return response.json()


# ---- AC-B.1 ----------------------------------------------------------------------------------

def test_AC_B1_the_golden_set_has_every_named_row():
    names = [p.stem for p in GOLDEN_FILES]
    print("golden rows:", len(names))
    assert len(names) == EXPECTED_ROWS
    assert {"12_recorded_clean_real", "13_recorded_tampered_real"} <= set(names)


@pytest.mark.parametrize("path", GOLDEN_FILES, ids=[p.stem for p in GOLDEN_FILES])
def test_AC_B1_golden_row_maps_exactly_per_section_3_2(client, path):
    audit, expected = load_row(path)
    body = post_audit(client, audit)
    java = body["java"]
    got = {"status": java["status"], "mapping_basis": java["mapping_basis"],
           "tamper_proven": java["tamper_proven"], "coverage_degraded": java["coverage_degraded"]}
    assert got == expected
    assert java["native"] == audit
    assert java["backend"] == "java-ledger-audit" and java["exit_code"] is None
    assert body["python"] is None and body["agree"] is None


# ---- AC-B.2 ----------------------------------------------------------------------------------

def test_AC_B2_over_the_golden_set_status_takes_all_five_values(client):
    statuses = [post_audit(client, load_row(p)[0])["java"]["status"] for p in GOLDEN_FILES]
    print("golden status distribution:", {s: statuses.count(s) for s in sorted(set(statuses))})
    assert set(statuses) == FIVE_STATUSES


# ---- AC-B.3 ----------------------------------------------------------------------------------

MISSING = object()
FIELD_DOMAINS = {
    "tamperDetected": (True, False, MISSING, None, "true"),
    "coverageDegraded": (True, False, MISSING, None),
    "coverageReason": ("ATRASADO", "DETENIDO", "SIN_CHECKPOINT", None, "OTRO", MISSING),
    "chainIntact": (True, False, MISSING),
    "checkpointPresent": (True, False, MISSING),
    "signatureValid": (True, False, MISSING),
    "signedHeadStillInChain": (True, False, MISSING),
    "balancesConsistent": (True, False, MISSING),
}


def generated_audits(count: int, seed: int = 20260926) -> list[dict]:
    rng = random.Random(seed)
    audits = []
    for _ in range(count):
        audit = {}
        for name, domain in FIELD_DOMAINS.items():
            value = rng.choice(domain)
            if value is not MISSING:
                audit[name] = value
        audits.append(audit)
    return audits


def unsafe_verified(pairs: list[tuple[dict, str]]) -> int:
    """The property's counter: VERIFIED while tamperDetected == true or coverageDegraded == true."""
    return sum(1 for audit, status in pairs
               if status == "VERIFIED" and (audit.get("tamperDetected") is True
                                            or audit.get("coverageDegraded") is True))


def test_positive_control_the_property_counter_fires_on_a_planted_unsafe_output():
    planted = [({"tamperDetected": True}, "VERIFIED"), ({"coverageDegraded": True}, "VERIFIED"),
               ({"tamperDetected": False}, "VERIFIED")]
    assert unsafe_verified(planted) == 2


def verified_without_checkpoint(pairs: list[tuple[dict, str]]) -> int:
    """Second counter (parity gate r1, 2026-09-27): VERIFIED while checkpointPresent is not true.
    Section 3.2 reaches VERIFIED only through checkpointPresent=true, on both bases."""
    return sum(1 for audit, status in pairs if status == "VERIFIED" and audit.get("checkpointPresent") is not True)


def test_positive_control_the_checkpoint_counter_fires_on_planted_unsafe_outputs():
    planted = [({"checkpointPresent": False}, "VERIFIED"), ({}, "VERIFIED"), ({"checkpointPresent": "true"}, "VERIFIED"),
               ({"checkpointPresent": True}, "VERIFIED"), ({"checkpointPresent": False}, "INCOMPLETE")]
    assert verified_without_checkpoint(planted) == 3


def test_AC_B3_no_verified_while_tamper_or_degraded_over_golden_plus_500_generated(client):
    audits = [load_row(p)[0] for p in GOLDEN_FILES] + generated_audits(500)
    pairs = [(audit, post_audit(client, audit)["java"]["status"]) for audit in audits]
    statuses = [s for _, s in pairs]
    risky = sum(1 for a, _ in pairs if a.get("tamperDetected") is True or a.get("coverageDegraded") is True)
    print("audits:", len(pairs), "with tamper or degraded:", risky,
          "statuses:", {s: statuses.count(s) for s in sorted(set(statuses))})
    assert len(pairs) == EXPECTED_ROWS + 500
    assert risky >= 100, "the generator must actually exercise the risky region"
    assert unsafe_verified(pairs) == 0
    no_checkpoint = sum(1 for a, _ in pairs if a.get("checkpointPresent") is not True)
    print("audits without checkpointPresent=true:", no_checkpoint)
    assert no_checkpoint >= 100, "the generator must actually exercise the no-checkpoint region"
    assert verified_without_checkpoint(pairs) == 0


# ---- AC-B.4 ----------------------------------------------------------------------------------

def _audit(name: str) -> dict:
    return load_row(GOLDEN_DIR / (name + ".json"))[0]


def test_AC_B4_differential_agree_takes_yes_no_and_not_comparable(client):
    tampered_audit = _audit("13_recorded_tampered_real")
    assert tampered_audit["tamperDetected"] is True  # the premise of the YES leg: the real audit says tamper
    planted_tamper = dict(_audit("12_recorded_clean_real"), tamperDetected=True, chainIntact=False, brokenAtSeq=5)
    cases = {
        "YES": post_audit(client, tampered_audit, recorded_upload_body("tampered")),
        "NO": post_audit(client, planted_tamper, recorded_upload_body("clean")),
        "NOT_COMPARABLE": post_audit(client, _audit("12_recorded_clean_real"),
                                     recorded_upload_body("clean", drop=("journal_checkpoint.json",))),
    }
    summary = {k: (v["java"]["status"], v["python"]["status"], v["agree"]) for k, v in cases.items()}
    print("differential cases (java, python, agree):", summary)
    assert summary["YES"] == ("TAMPER_SUSPECTED", "TAMPER_SUSPECTED", "YES")
    assert summary["NO"][0] == "TAMPER_SUSPECTED" and summary["NO"][1] != "TAMPER_SUSPECTED"
    assert summary["NO"][2] == "NO", "clean snapshot must reach VERIFIED here (openssl >= 3.5 on PATH)"
    assert summary["NOT_COMPARABLE"][1] == "INCOMPLETE" and summary["NOT_COMPARABLE"][2] == "NOT_COMPARABLE"
    assert len({v["agree"] for v in cases.values()}) == 3
    # the Python side is the same verifier: parity with a direct CLI run on the tampered half
    exit_code, native = direct_cli("--corpus", "recorded", "--half", "tampered")
    assert (cases["YES"]["python"]["exit_code"], cases["YES"]["python"]["native"]) == (exit_code, native)


def test_AC_B4_a_degraded_java_side_is_not_comparable_even_with_a_tampered_snapshot(client):
    body = post_audit(client, _audit("03_field_atrasado"), recorded_upload_body("tampered"))
    assert (body["java"]["status"], body["python"]["status"], body["agree"]) == \
        ("COVERAGE_DEGRADED", "TAMPER_SUSPECTED", "NOT_COMPARABLE")


# ---- request validation ----------------------------------------------------------------------

def test_the_audit_must_be_an_object_and_the_snapshot_must_be_recorded(client):
    assert client.post(ROUTE, json={"audit": [1, 2]}).status_code == 422
    assert client.post(ROUTE, json={}).status_code == 422
    adversarial = {"kind": "adversarial", "document": {}}
    assert client.post(ROUTE, json={"audit": _audit("01_field_all_clean"), "snapshot": adversarial}).status_code == 422
    assert client.post(ROUTE, json={"audit": {}, "extra": 1}).status_code == 422


def test_an_unknown_shape_is_http_200_status_error_with_the_reason_never_tamper(client):
    body = post_audit(client, {"hello": "world"})
    assert body["java"]["status"] == "ERROR" and body["java"]["tamper_proven"] is False
    assert any(note.startswith("unknown_shape") for note in body["java"]["notes"])


# ---- Amend round 1 (parity gate r1, 2026-09-27) ------------------------------------------------
# Rows the verifier's mutants M2, M3, M4, M5, M7, M9 and M10 survived. Each expected value is read off
# plan v2 section 3.2 as implemented in java_audit.py's docstrings: VERIFIED only with a checkpoint;
# a degraded coverage needs a KNOWN upper-case reason; required fields must be real booleans;
# tamper is proven by a signed head that left the chain; a Java side that is INCOMPLETE is not comparable.

AMEND_R1_ROWS = {
    "legacy_no_tamper_no_checkpoint_is_incomplete": (
        {"tamperDetected": False, "chainIntact": True, "checkpointPresent": False},
        {"status": "INCOMPLETE", "mapping_basis": "legacy", "tamper_proven": False}),
    "field_not_degraded_no_checkpoint_is_incomplete": (
        {"tamperDetected": False, "coverageDegraded": False, "chainIntact": True, "checkpointPresent": False},
        {"status": "INCOMPLETE", "mapping_basis": "field", "tamper_proven": False}),
    "field_degraded_null_reason_is_error": (
        {"tamperDetected": False, "coverageDegraded": True, "coverageReason": None, "chainIntact": True,
         "checkpointPresent": True, "signatureValid": True},
        {"status": "ERROR", "mapping_basis": "field", "tamper_proven": False}),
    "field_degraded_lower_case_reason_is_error": (
        {"tamperDetected": False, "coverageDegraded": True, "coverageReason": "atrasado", "chainIntact": True,
         "checkpointPresent": True, "signatureValid": True},
        {"status": "ERROR", "mapping_basis": "field", "tamper_proven": False}),
    "tamper_with_only_the_signed_head_gone_is_proven": (
        {"tamperDetected": True, "coverageDegraded": False, "chainIntact": True, "checkpointPresent": True,
         "signatureValid": True, "signedHeadStillInChain": False},
        {"status": "TAMPER_SUSPECTED", "mapping_basis": "field", "tamper_proven": True}),
    "tamper_detected_as_the_string_true_is_error": (
        {"tamperDetected": "true", "coverageDegraded": False, "chainIntact": True, "checkpointPresent": True,
         "signatureValid": True},
        {"status": "ERROR", "mapping_basis": "field", "tamper_proven": False}),
}


@pytest.mark.parametrize("name", sorted(AMEND_R1_ROWS))
def test_amend_r1_row_maps_exactly(client, name):
    audit, expected = AMEND_R1_ROWS[name]
    java = post_audit(client, audit)["java"]
    assert {k: java[k] for k in expected} == expected


def test_amend_r1_a_java_side_incomplete_is_not_comparable_even_against_python_tamper(client):
    audit = AMEND_R1_ROWS["legacy_no_tamper_no_checkpoint_is_incomplete"][0]
    body = post_audit(client, audit, recorded_upload_body("tampered"))
    assert (body["java"]["status"], body["python"]["status"], body["agree"]) ==         ("INCOMPLETE", "TAMPER_SUSPECTED", "NOT_COMPARABLE")
