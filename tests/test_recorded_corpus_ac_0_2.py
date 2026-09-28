"""AC-0.2 on the RECORDED corpus, plus the Phase 0 go-conditions B2b and B2c.

Every assertion here is about a corpus that was CAPTURED from a running LedgerMind on
2026-09-14, not computed. The derived corpus has its own file; this one exists so that a
regression in the recorder, or a silent re-record against a different stack, reddens
something instead of sliding through.

The load-bearing test in this file is ``test_SELF_CHAIN_recomputes_every_recorded_hash``.
It is the project's only MODEL-FREE leg: three agents read the same Java and agreed about
the canonical string, and correlated errors are a law, so agreement between readers proves
nothing. Recomputing the Java's own ``entry_hash`` column from the Java's own rows does.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDED = REPO_ROOT / "tests" / "fixtures" / "recorded"
sys.path.insert(0, str(REPO_ROOT))

from tools import compare_corpora, fixture_report, record_fixtures  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (RECORDED / "_corpus.json").exists(),
    reason="no recorded corpus on disk; run py -m tools.record_fixtures against a live stack",
)


def _meta():
    return json.loads((RECORDED / "_corpus.json").read_text(encoding="utf-8"))


def _half(name):
    return json.loads((RECORDED / name / "postings_and_hashes.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# AC-0.2 itself
# --------------------------------------------------------------------------------------
def test_ac_0_2_is_MET_on_the_recorded_corpus(capsys):
    assert fixture_report.report(RECORDED) == 0
    out = capsys.readouterr().out
    assert "AC_0_2: MET" in out
    assert "AC_0_2_ELIGIBLE: yes" in out
    assert "CORPUS_KIND: recorded" in out


def test_the_corpus_declares_itself_recorded_not_computed():
    meta = _meta()
    assert meta["corpus_kind"] == "recorded"
    assert meta["ac_0_2_eligible"] is True
    assert "POST /api/demo/tamper" in meta["ac_0_2_reason"]


def test_at_least_six_files_and_two_distinct_verdicts():
    files = [p for p in RECORDED.rglob("*.json") if p.name != "_corpus.json"]
    assert len(files) >= 6
    verdicts = set()
    for p in files:
        payload = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("verdict"), str):
            verdicts.add(payload["verdict"])
    assert len(verdicts) >= 2


# --------------------------------------------------------------------------------------
# B2b - the DB-level capture the DB-level capture decision requires
# --------------------------------------------------------------------------------------
def test_B2b_posting_hash_rows_are_present_with_seq_prev_and_entry():
    payload = _half("clean")
    links = payload["postingHashes"]
    assert len(links) >= 5
    for link in links:
        assert set(link) >= {"postingId", "seq", "prevHash", "entryHash"}
        assert len(link["prevHash"]) == 64
        assert len(link["entryHash"]) == 64


def test_B2b_accounts_carry_pendingDebits_and_allowNegative():
    """The two columns ``AccountView`` hides, without which the no-overdraft check is useless."""
    accounts = _half("clean")["accounts"]
    assert len(accounts) >= 3
    for a in accounts:
        assert "pendingDebits" in a
        assert "allowNegative" in a
    external = [a for a in accounts if a["address"] == "external:funding"][0]
    # The exact case that makes a REST-only no-overdraft check fire on a LEGAL balance.
    assert external["allowNegative"] is True
    assert external["postedCredits"] - external["postedDebits"] - external["pendingDebits"] < 0


def test_B2b_idempotencyKey_is_captured_because_no_wire_surface_carries_it():
    for p in _half("clean")["postings"]:
        assert p["idempotencyKey"].startswith("ORD-")


# --------------------------------------------------------------------------------------
# B2c - RISK A closed
# --------------------------------------------------------------------------------------
def test_B2c_every_saved_response_was_200_and_no_429_reached_the_corpus():
    meta = _meta()
    statuses = meta["saved_response_statuses"]
    assert statuses, "no response statuses recorded; the recorder cannot be audited"
    for name, status in statuses.items():
        assert status in (200, "db-select-read-only"), (name, status)
    assert 429 not in statuses.values()


def test_B2c_the_clean_capture_asserted_chain_completeness_before_writing():
    detail = _meta()["chain_completeness_at_clean_capture"]
    assert detail["chainedCount"] == detail["postings"]
    assert detail["posting_hash_rows"] == detail["postings"]
    assert detail["intact"] is True


def test_the_tampered_half_really_came_from_a_broken_chain():
    after = _meta()["tampered_verify_after_stabilising"]
    assert after["intact"] is False
    assert after["brokenAtSeq"] is not None
    tampered_audit = json.loads((RECORDED / "tampered" / "journal_audit.json").read_text(encoding="utf-8"))
    assert tampered_audit["tamperDetected"] is True


def test_the_db_capture_issued_no_writes_and_was_server_side_read_only():
    db = _meta()["db_capture"]
    assert db["writes_issued"] == 0
    assert "default_transaction_read_only=on" in db["how"]
    for stmt in db["statements"]:
        assert stmt.strip().upper().startswith("SELECT")


# --------------------------------------------------------------------------------------
# The model-free leg
# --------------------------------------------------------------------------------------
def test_SELF_CHAIN_recomputes_every_recorded_hash():
    """Our reading of JournalChainer.entryHash, checked against the Java's own output."""
    result = compare_corpora.self_chain_check(RECORDED / "clean")
    assert result["links"] >= 5
    assert result["matched"] == result["links"]
    assert result["first_mismatch_seq"] is None
    assert result["linkage_breaks"] == []
    assert result["bad_timestamp_format"] == []


def test_SELF_CHAIN_detects_the_planted_tamper_the_negative_control():
    """If this passed on the tampered half too, the recomputation would be reading nothing."""
    result = compare_corpora.self_chain_check(RECORDED / "tampered")
    assert result["first_mismatch_seq"] is not None
    assert result["matched"] < result["links"]


def test_SELF_CHAIN_reddens_when_a_single_amount_is_altered(tmp_path):
    """The instrument's FIRES half, on the deployment shape rather than a toy."""
    payload = _half("clean")
    payload["postings"][0]["amount"] += 1
    half = tmp_path / "clean"
    half.mkdir()
    (half / "postings_and_hashes.json").write_text(json.dumps(payload), encoding="utf-8")
    result = compare_corpora.self_chain_check(half)
    assert result["first_mismatch_seq"] == 1
    assert result["matched"] < result["links"]


# --------------------------------------------------------------------------------------
# The createdAt precision rule, which is what makes the recomputation possible at all
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "postgres_value,expected",
    [
        ("2026-09-14T16:02:15.000000", "2026-09-14T16:02:15Z"),
        ("2026-09-14T16:02:15.123000", "2026-09-14T16:02:15.123Z"),
        ("2026-09-14T16:02:15.037738", "2026-09-14T16:02:15.037738Z"),
        ("2026-09-14T16:02:15", "2026-09-14T16:02:15Z"),
    ],
)
def test_java_instant_rendering_matches_Instant_toString(postgres_value, expected):
    """Instant.toString() emits 0, 3, 6 or 9 fractional digits - never a fixed width."""
    assert record_fixtures.java_instant_string(postgres_value) == expected


def test_a_fixed_width_rendering_would_break_the_chain():
    """Why the rule above is load-bearing rather than cosmetic: naive zero-padding differs."""
    naive = "2026-09-14T16:02:15.123000Z"          # what a fixed 6-digit renderer emits
    correct = record_fixtures.java_instant_string("2026-09-14T16:02:15.123000")
    assert naive != correct
    posting = dict(_half("clean")["postings"][0])
    posting["createdAt"] = naive
    assert compare_corpora.entry_hash(compare_corpora.GENESIS, posting) != _half("clean")["postingHashes"][0]["entryHash"]


# --------------------------------------------------------------------------------------
# The recorder's own client-side guard
# --------------------------------------------------------------------------------------
def test_the_recorder_refuses_a_non_SELECT_statement_WITHOUT_reaching_the_database():
    """The refusal must come from the client guard, never from a round trip.

    Written this way after a mutation run: with the prefix check neutered, the naive
    version of this test still PASSED, because the statement reached psql and PostgreSQL's
    own read-only session refused it. That is a one-sided instrument dressed as a
    two-sided one - and worse, it means the test itself would ship an UPDATE at a live
    database. Asserting on the client-side refusal message keeps the two guards separable
    and keeps a write statement off the wire.
    """
    with pytest.raises(record_fixtures.RecorderError) as exc:
        record_fixtures.db_select("UPDATE posting SET amount = amount WHERE 1=0")
    assert "only SELECT statements" in str(exc.value)


def test_the_recorder_accepts_a_SELECT_shaped_statement_past_the_client_guard():
    """The other outcome of the same guard, without needing a live database.

    The client-side prefix check is the WEAKER of the two guards - the real one is
    PostgreSQL's ``default_transaction_read_only=on`` - so this only proves the prefix
    check does not reject valid input. It gets past the regex and fails later on the
    subprocess when no stack is up, which is a different error than the refusal above.
    """
    assert record_fixtures._SELECT_ONLY.match("SELECT 1") is not None
    assert record_fixtures._SELECT_ONLY.match("  select count(*) from posting") is not None
    assert record_fixtures._SELECT_ONLY.match("DELETE FROM posting") is None


# --------------------------------------------------------------------------------------
# The cross-corpus oracle, at the frozen class list
# --------------------------------------------------------------------------------------
def test_the_derived_and_recorded_corpora_agree_on_everything_that_is_not_pre_registered():
    derived = REPO_ROOT / "tests" / "fixtures" / "derived_from_source"
    if not (derived / "_corpus.json").exists():
        pytest.skip("no derived corpus")
    findings = compare_corpora.cross_corpus_diff(RECORDED, derived)
    x1 = [f for f in findings if f["class"] == "X1"]
    assert x1 == [], "unexpected diff class X1 - halt Phase 1 and send this to a fresh-context verifier"


def test_the_normalization_rule_was_written_down_before_the_comparison():
    doc = REPO_ROOT / "docs" / "evidence" / "derived-vs-recorded-normalization.md"
    assert doc.exists()
    text = doc.read_text(encoding="utf-8")
    assert "createdAt" in text
    assert "PRECISION only" in text
    assert "X1" in text


def test_the_oracle_FIRES_on_a_planted_value_difference(tmp_path):
    """The X1 half of the instrument, on a realistic planted defect."""
    import shutil

    plant = tmp_path / "recorded"
    shutil.copytree(RECORDED, plant)
    target = plant / "clean" / "account_wallet_ana.json"
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["balance"] += 1
    target.write_text(json.dumps(payload), encoding="utf-8")
    derived = REPO_ROOT / "tests" / "fixtures" / "derived_from_source"
    findings = compare_corpora.cross_corpus_diff(plant, derived)
    x1 = [f for f in findings if f["class"] == "X1"]
    assert len(x1) >= 1
    assert any("balance" in f["path"] for f in x1)
