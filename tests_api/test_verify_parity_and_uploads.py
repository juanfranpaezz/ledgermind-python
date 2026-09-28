"""Run A, AC-A.1..A.8 and the traversal half of AC-A.12: the API returns exactly what the CLI returns."""

from __future__ import annotations

import pytest

from conftest import (
    ADV_CASES,
    adversarial_upload_body,
    direct_cli,
    recorded_upload_body,
)


def _verdict_pair(response) -> tuple:
    if response.status_code != 200:
        return ("HTTP", response.status_code, response.text[:300])
    body = response.json()
    return (body["exit_code"], body["native"])


def test_AC_A1_recorded_clean_upload_equals_a_direct_cli_run(client):
    expected = direct_cli("--corpus", "recorded", "--half", "clean")
    response = client.post("/v1/verify/snapshot", json=recorded_upload_body("clean"))
    assert response.status_code == 200, response.text
    assert _verdict_pair(response) == expected


def test_AC_A2_recorded_tampered_upload_is_TAMPER_SUSPECTED_and_equals_the_cli(client):
    exit_code, native = direct_cli("--corpus", "recorded", "--half", "tampered")
    response = client.post("/v1/verify/snapshot", json=recorded_upload_body("tampered", label="tampered"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "TAMPER_SUSPECTED"
    assert body["exit_code"] == 1 == exit_code
    assert body["tamper_proven"] is True
    assert body["native"]["violation_count"] >= 1
    assert body["native"] == native


def test_AC_A3_a_valid_snapshot_is_VERIFIED_where_the_direct_cli_exits_0(client):
    candidates = [
        (("--corpus", "recorded", "--half", "clean"), recorded_upload_body("clean")),
        (("--corpus", "adversarial", "--case", "clean_must_not_fire"), adversarial_upload_body("clean_must_not_fire")),
    ]
    proven = []
    for args, body in candidates:
        exit_code, _native = direct_cli(*args)
        if exit_code != 0:
            continue
        response = client.post("/v1/verify/snapshot", json=body)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "VERIFIED"
        proven.append(" ".join(args))
    print("AC-A.3 VERIFIED proven on:", proven)
    assert proven, "no fixture exits 0 on this machine: AC-A.3 is UNPROVEN here"


def test_AC_A4_parity_every_adversarial_case_and_both_halves_by_corpus_and_by_upload(client):
    mismatches = []
    compared = 0
    for case in ADV_CASES:
        expected = direct_cli("--corpus", "adversarial", "--case", case)
        by_corpus = client.post("/v1/verify/corpus", json={"corpus_id": "repo-adversarial", "case": case})
        by_upload = client.post("/v1/verify/snapshot", json=adversarial_upload_body(case))
        for how, response in (("corpus", by_corpus), ("upload", by_upload)):
            compared += 1
            if _verdict_pair(response) != expected:
                mismatches.append((case, how))
    for half in ("clean", "tampered"):
        expected = direct_cli("--corpus", "recorded", "--half", half)
        by_corpus = client.post("/v1/verify/corpus", json={"corpus_id": "repo-recorded", "half": half})
        by_upload = client.post("/v1/verify/snapshot", json=recorded_upload_body(half))
        for how, response in (("corpus", by_corpus), ("upload", by_upload)):
            compared += 1
            if _verdict_pair(response) != expected:
                mismatches.append(("recorded/" + half, how))
    print("AC-A.4 cases_compared =", compared, "file_count =", len(ADV_CASES), "mismatches =", mismatches)
    assert len(ADV_CASES) > 0
    assert mismatches == []
    assert compared == 2 * len(ADV_CASES) + 4


def test_AC_A5_status_takes_at_least_three_distinct_values(client):
    bodies = [
        recorded_upload_body("clean"),
        recorded_upload_body("tampered"),
        recorded_upload_body("clean", drop=("journal_checkpoint.json",)),
    ]
    seen = set()
    for body in bodies:
        response = client.post("/v1/verify/snapshot", json=body)
        assert response.status_code == 200, response.text
        seen.add(response.json()["status"])
    print("AC-A.5 distinct statuses:", sorted(seen))
    assert len(seen) >= 3


def test_AC_A6_the_label_is_cosmetic(client):
    as_clean = client.post("/v1/verify/snapshot", json=recorded_upload_body("tampered", label="clean")).json()
    as_tampered = client.post("/v1/verify/snapshot", json=recorded_upload_body("tampered", label="tampered")).json()
    assert as_clean["exit_code"] == as_tampered["exit_code"]
    assert as_clean["native"]["verdict"] == as_tampered["native"]["verdict"]
    assert as_clean["native"]["violation_count"] == as_tampered["native"]["violation_count"]


def test_AC_A7_the_same_request_twice_gives_the_same_response(client):
    first = client.post("/v1/verify/snapshot", json=recorded_upload_body("clean")).json()
    second = client.post("/v1/verify/snapshot", json=recorded_upload_body("clean")).json()
    for volatile in ("request_id", "duration_ms"):
        first.pop(volatile)
        second.pop(volatile)
    differing = sorted(k for k in set(first) | set(second) if first.get(k) != second.get(k))
    assert differing == []


def test_AC_A8_an_upload_without_postings_is_422(client):
    response = client.post("/v1/verify/snapshot", json=recorded_upload_body("clean", drop=("postings_and_hashes.json",)))
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


def test_AC_A8_a_recorded_upload_without_checkpoint_is_INCOMPLETE_exit_2(client):
    response = client.post("/v1/verify/snapshot", json=recorded_upload_body("clean", drop=("journal_checkpoint.json",)))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["exit_code"] == 2
    assert body["status"] == "INCOMPLETE"


def test_tamper_proven_is_False_on_the_VERIFIED_and_INCOMPLETE_responses(client):
    """Gate fix A4 (2026-09-25): a mutant that set tamper_proven to True on every response passed the
    whole suite, because only the tampered case (A.2, where it must be True) ever read the field.
    This pins the other outcome: A.1/A.3 (VERIFIED) and A.8 (INCOMPLETE) must say False."""
    cases = [
        ("A.1 recorded clean", recorded_upload_body("clean"), "VERIFIED"),
        ("A.3 adversarial clean_must_not_fire", adversarial_upload_body("clean_must_not_fire"), "VERIFIED"),
        ("A.8 recorded clean without checkpoint",
         recorded_upload_body("clean", drop=("journal_checkpoint.json",)), "INCOMPLETE"),
    ]
    seen = []
    for name, request_body, expected_status in cases:
        response = client.post("/v1/verify/snapshot", json=request_body)
        assert response.status_code == 200, (name, response.text)
        body = response.json()
        assert body["status"] == expected_status, (name, body["status"])
        assert body["tamper_proven"] is False, name
        seen.append((name, body["status"], body["tamper_proven"]))
    print("tamper_proven on non-tamper verdicts:", seen)


def test_AC_A8_a_null_checkpoint_is_502_backend_tool_error_never_tamper(client):
    body = recorded_upload_body("clean", overrides={"journal_checkpoint.json": None})
    response = client.post("/v1/verify/snapshot", json=body)
    assert response.status_code == 502
    assert response.json()["code"] == "backend_tool_error"
    assert "TAMPER_SUSPECTED" not in response.text


@pytest.mark.parametrize("bad", ["../x", "C:\\x", "a/b", "\\\\?\\UNC\\x"])
def test_AC_A12_traversal_values_in_ids_and_labels_are_422(client, bad):
    assert client.post("/v1/verify/corpus", json={"corpus_id": bad, "half": "clean"}).status_code == 422
    assert client.post("/v1/verify/corpus", json={"corpus_id": "repo-adversarial", "case": bad}).status_code == 422
    snapshot = {"kind": "adversarial", "case_label": bad, "document": {}}
    assert client.post("/v1/verify/snapshot", json=snapshot).status_code == 422


def test_AC_A12_a_traversal_file_name_is_422(client):
    body = recorded_upload_body("clean")
    body["files"]["../postings_and_hashes.json"] = body["files"].pop("postings_and_hashes.json")
    assert client.post("/v1/verify/snapshot", json=body).status_code == 422
    body = recorded_upload_body("clean")
    body["files"]["../account_x.json"] = {}
    assert client.post("/v1/verify/snapshot", json=body).status_code == 422


def test_upload_limits_and_unknown_names_are_422_and_unknown_ids_404(client):
    body = recorded_upload_body("clean")
    body["files"]["reconciliation.json"] = {}
    assert client.post("/v1/verify/snapshot", json=body).status_code == 422
    body = recorded_upload_body("clean")
    body["files"].update({"account_extra_" + str(i) + ".json": {} for i in range(64)})
    assert client.post("/v1/verify/snapshot", json=body).status_code == 422
    assert client.post("/v1/verify/corpus", json={"corpus_id": "no-such-corpus", "half": "clean"}).status_code == 404
    unknown_case = {"corpus_id": "repo-adversarial", "case": "no_such_case"}
    assert client.post("/v1/verify/corpus", json=unknown_case).status_code == 404
