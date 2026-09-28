"""The source-derived fixture corpus, and the AC-0.2 reporter that must refuse it.

Plan reference: AC-0.2 (manifest v1) and section 2.6. AC-0.2 demands
``fixture_files >= 6`` and ``distinct_verdicts >= 2``; section 2.6 adds that the
tampered half must come from a real ``POST /api/demo/tamper`` against a running
LedgerMind, because "a hand-edited fixture proves the test, not the instrument".

The corpus this repository ships today is DERIVED FROM THE JAVA SOURCE, not recorded,
because the Docker daemon is down. It would otherwise sail past a naive file-count
check: it holds 20 fixture files and 2 distinct verdicts. The tests below pin BOTH
halves of the behaviour that keeps that from becoming a false pass - the reporter
refuses the derived corpus, and it accepts a corpus that is genuinely eligible.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools import fixture_report

REPO_ROOT = Path(__file__).resolve().parents[1]
DERIVED = REPO_ROOT / "tests" / "fixtures" / "derived_from_source"
RECORDED = REPO_ROOT / "tests" / "fixtures" / "recorded"
GENESIS = "0" * 64


def _load(rel):
    return json.loads((DERIVED / rel).read_text(encoding="utf-8"))


def _canonical(p):
    return "|".join(
        [
            str(p["id"]),
            str(p["debitAccountId"]),
            str(p["creditAccountId"]),
            str(p["amount"]),
            p["asset"],
            p["idempotencyKey"],
            p["createdAt"],
        ]
    )


def _entry_hash(prev, p):
    return hashlib.sha256((prev + _canonical(p)).encode("utf-8")).hexdigest()


# --- The corpus is arithmetically what the Java source implies -----------------

def test_clean_balances_sum_to_zero_and_match_the_demo_seed():
    funding = _load("clean/account_external_funding.json")
    ana = _load("clean/account_wallet_ana.json")
    beto = _load("clean/account_wallet_beto.json")
    assert funding["balance"] == -158_000     # 100000 + 50000 + 8000 debited
    assert ana["balance"] == 107_500          # 150000 credited, 42500 debited
    assert beto["balance"] == 50_500          # 30000 + 12500 + 8000 credited
    assert funding["balance"] + ana["balance"] + beto["balance"] == 0


def test_clean_hash_chain_recomputes_intact():
    data = _load("clean/postings_and_hashes.json")
    by_id = {p["id"]: p for p in data["postings"]}
    prev = GENESIS
    for link in sorted(data["postingHashes"], key=lambda x: x["seq"]):
        p = by_id[link["postingId"]]
        assert link["prevHash"] == prev
        assert link["entryHash"] == _entry_hash(prev, p)
        prev = link["entryHash"]
    assert _load("clean/journal_verify.json") == {
        "intact": True,
        "chainedCount": 5,
        "brokenAtSeq": None,
    }


def test_tampered_corpus_breaks_at_the_last_posting_and_leaves_counters_untouched():
    verify = _load("tampered/journal_verify.json")
    assert verify["intact"] is False
    assert verify["brokenAtSeq"] == 5
    assert verify["chainedCount"] == 4
    # POST /api/demo/tamper edits the posting row by SQL only: the counters still
    # describe the pre-tamper amounts, which is a second independent signal.
    assert _load("tampered/account_wallet_beto.json") == _load("clean/account_wallet_beto.json")
    tampered_last = _load("tampered/postings_and_hashes.json")["postings"][-1]
    clean_last = _load("clean/postings_and_hashes.json")["postings"][-1]
    assert tampered_last["amount"] == clean_last["amount"] + 1


def test_the_two_audit_verdicts_are_distinct():
    clean = _load("clean/journal_audit.json")
    tampered = _load("tampered/journal_audit.json")
    assert clean["verdict"] != tampered["verdict"]
    assert clean["tamperDetected"] is False
    assert tampered["tamperDetected"] is True


def test_no_invented_key_material_in_the_corpus():
    """Placeholders are named as placeholders; a derived fixture cannot know a key."""
    material = _load("clean/journal_audit.json")["_signing_material"]
    assert material["publicKeyBase64"].startswith("NOT-CAPTURED")
    assert material["signature"].startswith("NOT-CAPTURED")


# --- The adversarial cases ------------------------------------------------------

def test_every_adversarial_case_declares_its_expectation():
    cases = sorted((DERIVED / "adversarial").glob("*.json"))
    assert len(cases) >= 6
    names = set()
    for path in cases:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["case"]
        assert "expected_violation" in payload
        assert payload["why"]
        names.add(payload["case"])
    assert {
        "unbalanced_posting",
        "overdraft_account",
        "chain_link_posting_deleted",
        "chain_prev_hash_rewritten",
        "counters_disagree_with_postings",
        "clean_must_not_fire",
    } <= names


def test_the_negative_control_case_expects_no_violation():
    """Without a case that must NOT fire, an over-firing checker looks perfect."""
    payload = json.loads((DERIVED / "adversarial" / "clean_must_not_fire.json").read_text(encoding="utf-8"))
    assert payload["expected_violation"] is None
    assert payload["allow_negative_by_address"]["external:funding"] is True
    assert payload["allow_negative_by_address"]["wallet:ana"] is False


def test_overdraft_case_targets_an_account_that_forbids_negatives():
    payload = json.loads((DERIVED / "adversarial" / "overdraft_account.json").read_text(encoding="utf-8"))
    assert payload["allow_negative_by_address"]["wallet:ana"] is False
    assert payload["accounts"]["wallet:ana"]["balance"] < 0
    # external:funding is legally negative in the very same file.
    assert payload["accounts"]["external:funding"]["balance"] < 0
    assert payload["allow_negative_by_address"]["external:funding"] is True


# --- AC-0.2's reporter must fire both ways --------------------------------------

def test_reporter_REFUSES_the_derived_corpus_despite_enough_files_and_verdicts(capsys):
    """The corpus clears the raw thresholds and is still correctly rejected."""
    paths = list(fixture_report._iter_fixture_files(DERIVED))
    verdicts = fixture_report._verdicts(paths)
    assert len(paths) >= fixture_report.MIN_FIXTURE_FILES
    assert len(verdicts) >= fixture_report.MIN_DISTINCT_VERDICTS

    assert fixture_report.report(DERIVED) == 1
    out = capsys.readouterr().out
    assert "AC_0_2_ELIGIBLE: no" in out
    assert "AC_0_2: NOT MET" in out


def test_reporter_REFUSES_an_empty_corpus_directory(tmp_path, capsys):
    """CHANGED 2026-09-14, and the change is flagged in the handoff, not hidden.

    This test used to point at ``RECORDED`` and assert the SHIPPED corpus was empty. That
    was a statement about the world (Docker was down), not about the instrument, and on
    2026-09-14 the recorded corpus was captured from a running stack, so the world moved.
    The INVARIANT it was really protecting - the reporter refuses a corpus with nothing in
    it - is preserved verbatim and is now asserted against an empty directory, which makes
    it independent of whether a corpus happens to exist. Strictly stronger, not weaker: it
    can no longer pass merely because nobody has recorded anything yet. The post-condition
    twin lives in ``test_the_recorded_corpus_now_EXISTS_and_is_ac_0_2_eligible``.
    """
    assert fixture_report.report(tmp_path) == 1
    out = capsys.readouterr().out
    assert "AC_0_2: NOT MET" in out


def test_reporter_ACCEPTS_a_genuinely_eligible_corpus(tmp_path, capsys):
    """The other outcome, on a corpus shaped exactly like a recorded one."""
    (tmp_path / "_corpus.json").write_text(
        json.dumps({"corpus_kind": "recorded", "ac_0_2_eligible": True, "ac_0_2_reason": "captured"}),
        encoding="utf-8",
    )
    for i in range(5):
        (tmp_path / ("capture_" + str(i) + ".json")).write_text(
            json.dumps({"address": "wallet:x", "balance": i}), encoding="utf-8"
        )
    (tmp_path / "journal_audit_clean.json").write_text(
        json.dumps({"verdict": "SIN EVIDENCIA DE EDICION: ...", "tamperDetected": False}), encoding="utf-8"
    )
    (tmp_path / "journal_audit_tampered.json").write_text(
        json.dumps({"verdict": "MANIPULACION DETECTADA: ...", "tamperDetected": True}), encoding="utf-8"
    )
    assert fixture_report.report(tmp_path) == 0
    out = capsys.readouterr().out
    assert "AC_0_2: MET" in out


def test_reporter_REFUSES_an_eligible_corpus_with_only_one_verdict(tmp_path):
    """The distinct-verdicts leg fires on its own, not only through eligibility."""
    (tmp_path / "_corpus.json").write_text(
        json.dumps({"corpus_kind": "recorded", "ac_0_2_eligible": True, "ac_0_2_reason": "captured"}),
        encoding="utf-8",
    )
    for i in range(8):
        (tmp_path / ("capture_" + str(i) + ".json")).write_text(
            json.dumps({"verdict": "SIN EVIDENCIA DE EDICION: ..."}), encoding="utf-8"
        )
    assert fixture_report.report(tmp_path) == 1


def test_the_recorded_corpus_now_EXISTS_and_is_ac_0_2_eligible():
    """CHANGED 2026-09-14, and the change is flagged in the handoff, not hidden.

    The previous body asserted ``captures == []`` with the message "recorded corpus
    appeared: re-score AC-0.2 rather than trusting this file". That message is an
    instruction for exactly this moment: the corpus was recorded from a running LedgerMind
    on 2026-09-14, so AC-0.2 was re-scored and this test now pins the post-condition
    instead of the blocked pre-condition. It is a strictly stronger assertion - the old one
    was satisfied by an empty directory, this one is not satisfiable without a real
    capture. The full AC-0.2 / B2b / B2c assertions live in
    ``tests/test_recorded_corpus_ac_0_2.py``.
    """
    meta_path = RECORDED / "_corpus.json"
    assert meta_path.exists(), "the recorded corpus metadata is missing"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["corpus_kind"] == "recorded"
    assert meta["ac_0_2_eligible"] is True
    assert fixture_report.report(RECORDED) == 0
