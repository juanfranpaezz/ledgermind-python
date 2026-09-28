"""Phase-1 acceptance tests for the deterministic verifier (manifest AC-1.1 .. AC-1.3).

WHAT EACH BLOCK IS FOR, so a reviewer can tell an acceptance test from an
instrument-fitness test:

* ``AC_1_x``            - the frozen plan criteria, scored literally.
* ``FIXTURE``           - the shipped planted-defect corpus, each case scored against
                          the ``expected_violation`` the fixture itself declares.
* ``FIRES`` / ``SILENT`` - the PAIRED instrument-fitness tests. Every leg of every
                          check has to be shown returning BOTH answers on a realistic
                          input, because a leg that can only ever return one is inert
                          whatever its contract says.
* ``INDEPENDENT``       - a second implementation, written here from the Java rule,
                          that must reproduce the ledger's own hashes. If this and
                          ``journal_chain`` ever agree only because they are the same
                          code, the whole chain leg is worthless.

No network, no Docker, no LedgerMind, no model.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from ledger_verification_agent.deterministic_verifier import (  # noqa: E402
    check_all,
    check_hash_chain_continuity,
    check_money_conservation,
    check_no_overdraft,
)
from ledger_verification_agent.journal_chain import (  # noqa: E402
    GENESIS,
    ChainLink,
    Posting,
    verify_chain,
)
from ledger_verification_agent.ledger_snapshot import (  # noqa: E402
    AccountRow,
    LedgerSnapshot,
    load_adversarial,
    load_recorded,
)
from ledger_verification_agent.verdict import (  # noqa: E402
    HASH_CHAIN_CONTINUITY,
    MONEY_CONSERVATION,
    NO_DATA,
    NO_OVERDRAFT,
    OK,
    VERDICT_INCOMPLETE,
    VERDICT_OK,
    VERDICT_TAMPERED,
    VIOLATION,
    CheckVerdict,
    Citation,
    Violation,
    decide,
)

ADVERSARIAL = REPO_ROOT / "tests" / "fixtures" / "derived_from_source" / "adversarial"


# --------------------------------------------------------------------------- #
# AC-1.1 / AC-1.2 / AC-1.3 - the frozen plan criteria
# --------------------------------------------------------------------------- #
def test_AC_1_1_clean_corpus_zero_violations_and_verdict_OK():
    result = check_all(load_recorded("clean"))
    assert result.violation_count == 0, [v.message for v in result.violations]
    assert result.verdict == VERDICT_OK
    # and every check actually RAN - an OK built out of NO_DATA would be theatre
    assert [check.status for check in result.checks] == [OK, OK, OK]


def test_AC_1_2_tampered_corpus_names_the_broken_seq_and_verdict_TAMPERED():
    result = check_all(load_recorded("tampered"))
    assert result.verdict == VERDICT_TAMPERED
    assert result.violation_count >= 1
    chain = result.violations_of(HASH_CHAIN_CONTINUITY)
    assert len(chain) == 1
    violation = chain[0]
    assert violation.code == "entry_hash_mismatch"
    # "the report names the exact broken seq" - in the message AND in a citation
    assert "seq=5" in violation.message
    assert any(citation.ref == "chain_link:seq=5" for citation in violation.citations)
    assert check_hash_chain_continuity(load_recorded("tampered")).examined["broken_at_seq"] == 5


def test_AC_1_3_a_hand_constructed_unbalanced_posting_is_exactly_one_conservation_violation():
    result = check_all(load_adversarial("unbalanced_posting"))
    assert result.conservation_violations == 1
    violation = result.violations_of(MONEY_CONSERVATION)[0]
    assert violation.code == "entry_legs_differ"
    assert "posting id=3" in violation.message
    assert violation.citations[0].ref == "posting:3"


# --------------------------------------------------------------------------- #
# FIXTURE - every shipped adversarial case against its OWN declared expectation
# --------------------------------------------------------------------------- #
CASE_TO_CHECK = {
    "conservation": MONEY_CONSERVATION,
    "no_overdraft": NO_OVERDRAFT,
    "hash_chain": HASH_CHAIN_CONTINUITY,
}


@pytest.mark.parametrize("case_path", sorted(ADVERSARIAL.glob("*.json")), ids=lambda p: p.stem)
def test_FIXTURE_each_adversarial_case_matches_the_expectation_it_declares(case_path):
    declared = json.loads(case_path.read_text(encoding="utf-8"))
    expected = declared.get("expected_violation")
    result = check_all(load_adversarial(case_path.stem))

    if expected is None:
        assert result.violation_count == 0, (
            "the negative control fired: an over-firing checker is as useless as an inert one: "
            + str([v.message for v in result.violations])
        )
        assert result.verdict == VERDICT_OK
        return

    check_name = CASE_TO_CHECK[expected]
    assert result.violations_of(check_name), (
        case_path.stem + " declares expected_violation=" + expected + " and the checker missed it"
    )
    if "expected_broken_at_seq" in declared:
        assert (
            result.check(HASH_CHAIN_CONTINUITY).examined["broken_at_seq"]
            == declared["expected_broken_at_seq"]
        )


# --------------------------------------------------------------------------- #
# INDEPENDENT - a second implementation of the Java rule, written here
# --------------------------------------------------------------------------- #
def _independent_entry_hash(prev_hash: str, raw: dict) -> str:
    """JournalChainer.entryHash, re-typed from the Java here and NOT imported.

    id | debitAccountId | creditAccountId | amount | asset | idempotencyKey | createdAt
    joined with "|", then sha256hex(prevHash + canonical).
    """
    canonical = "|".join(
        [
            str(raw["id"]),
            str(raw["debitAccountId"]),
            str(raw["creditAccountId"]),
            str(raw["amount"]),
            raw["asset"],
            raw["idempotencyKey"],
            raw["createdAt"],
        ]
    )
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def test_INDEPENDENT_recomputation_reproduces_every_recorded_entry_hash():
    """The model-free leg: our hash rule must reproduce the JAVA's own hash column."""
    bundle = json.loads(
        (REPO_ROOT / "tests/fixtures/recorded/clean/postings_and_hashes.json").read_text("utf-8")
    )
    postings = {item["id"]: item for item in bundle["postings"]}
    prev = GENESIS
    matched = 0
    for link in sorted(bundle["postingHashes"], key=lambda item: item["seq"]):
        assert link["prevHash"] == prev
        assert _independent_entry_hash(prev, postings[link["postingId"]]) == link["entryHash"]
        prev = link["entryHash"]
        matched += 1
    assert matched == 5


def test_INDEPENDENT_the_tamper_is_explained_to_the_byte():
    """Restoring the one tampered field must reproduce the ORIGINAL recorded hash."""
    tampered = json.loads(
        (REPO_ROOT / "tests/fixtures/recorded/tampered/postings_and_hashes.json").read_text("utf-8")
    )
    clean = json.loads(
        (REPO_ROOT / "tests/fixtures/recorded/clean/postings_and_hashes.json").read_text("utf-8")
    )
    broken = [p for p in tampered["postings"] if p["id"] == 5][0]
    original = [p for p in clean["postings"] if p["id"] == 5][0]
    assert broken["amount"] != original["amount"]

    prev = [link for link in tampered["postingHashes"] if link["seq"] == 5][0]["prevHash"]
    stored = [link for link in tampered["postingHashes"] if link["seq"] == 5][0]["entryHash"]
    assert _independent_entry_hash(prev, broken) != stored
    restored = dict(broken, amount=original["amount"])
    assert _independent_entry_hash(prev, restored) == stored


# --------------------------------------------------------------------------- #
# hash chain - both outcomes, and agreement with the ledger's own answer
# --------------------------------------------------------------------------- #
def test_SILENT_hash_chain_clean_agrees_with_the_ledgers_own_verify():
    snapshot = load_recorded("clean")
    check = check_hash_chain_continuity(snapshot)
    assert check.status == OK
    assert check.examined["intact"] is True
    assert check.examined["chained_count"] == 5
    assert snapshot.reported_verify == {"intact": True, "chainedCount": 5, "brokenAtSeq": None}


def test_FIRES_hash_chain_tampered_agrees_with_the_ledgers_own_verify():
    snapshot = load_recorded("tampered")
    check = check_hash_chain_continuity(snapshot)
    assert check.status == VIOLATION
    assert (check.examined["intact"], check.examined["chained_count"], check.examined["broken_at_seq"]) == (
        False,
        4,
        5,
    )
    assert snapshot.reported_verify == {"intact": False, "chainedCount": 4, "brokenAtSeq": 5}


def test_FIRES_the_cross_oracle_when_the_ledgers_own_answer_disagrees_with_ours():
    """Plant a doctored self-report: a checker that mirrors the ledger cannot see this."""
    snapshot = load_recorded("clean")
    doctored = dataclasses.replace(
        snapshot, reported_verify={"intact": False, "chainedCount": 2, "brokenAtSeq": 3}
    )
    check = check_hash_chain_continuity(doctored)
    codes = [v.code for v in check.violations]
    assert "ledger_self_report_disagrees" in codes


def test_SILENT_the_cross_oracle_stays_quiet_when_the_two_agree():
    check = check_hash_chain_continuity(load_recorded("clean"))
    assert [v.code for v in check.violations] == []
    assert any("cross-oracle" in note for note in check.notes)


def test_FIRES_when_the_signed_head_hash_row_is_rewritten():
    """H2: the checkpoint anchors a head that the hash table no longer holds."""
    snapshot = load_recorded("clean")
    rewritten = tuple(
        ChainLink(link.posting_id, link.seq, link.prev_hash, "f" * 64) if link.seq == 5 else link
        for link in snapshot.links
    )
    check = check_hash_chain_continuity(dataclasses.replace(snapshot, links=rewritten))
    assert "signed_head_rewritten" in [v.code for v in check.violations]


def test_SILENT_the_signed_head_is_intact_on_both_halves_of_the_recorded_corpus():
    """It stays TRUE on the tampered half too: the tamper edits a posting, not a hash row."""
    for half in ("clean", "tampered"):
        check = check_hash_chain_continuity(load_recorded(half))
        assert "signed_head_rewritten" not in [v.code for v in check.violations]
        assert any("signed head" in note for note in check.notes)


def test_a_chain_with_no_links_is_NO_DATA_and_never_a_pass():
    check = check_hash_chain_continuity(LedgerSnapshot(subject="empty"))
    assert check.status == NO_DATA
    assert check.violation_count == 0
    assert decide((check,)) == VERDICT_INCOMPLETE


def test_verify_chain_stops_at_the_FIRST_break_like_the_java_does():
    postings = {
        1: Posting(1, 1, 2, 10, "ARS", "A", "2026-01-01T00:00:00Z"),
        2: Posting(2, 2, 1, 20, "ARS", "B", "2026-01-01T00:00:01Z"),
    }
    links = [
        ChainLink(1, 1, GENESIS, "deadbeef"),
        ChainLink(2, 2, "deadbeef", "cafebabe"),
    ]
    result = verify_chain(postings, links)
    assert (result.intact, result.chained_count, result.broken_at_seq) == (False, 0, 1)
    assert result.broken_reason == "entry_hash_mismatch"


# --------------------------------------------------------------------------- #
# money conservation - each leg shown firing and not firing
# --------------------------------------------------------------------------- #
def test_SILENT_conservation_is_clean_on_the_recorded_corpus_with_every_leg_run():
    check = check_money_conservation(load_recorded("clean"))
    assert check.status == OK
    assert check.examined["legs_skipped"] == []
    assert check.examined["debit_legs_total"] == check.examined["credit_legs_total"] == 200500


def test_FIRES_counters_vs_replay_on_a_planted_counter_drift():
    """L2: the ledger's own hash chain cannot see this - it protects postings, not counters."""
    snapshot = load_recorded("clean")
    drifted = tuple(
        dataclasses.replace(row, posted_credits=row.posted_credits + 1)
        if row.address == "wallet:beto"
        else row
        for row in snapshot.accounts
    )
    check = check_money_conservation(dataclasses.replace(snapshot, accounts=drifted))
    assert "counters_disagree_with_postings" in [v.code for v in check.violations]


def test_FIRES_the_system_wide_net_when_the_period_does_not_conserve():
    check = check_money_conservation(load_adversarial("counters_disagree_with_postings"))
    assert "posted_counters_do_not_net_to_zero" in [v.code for v in check.violations]


def test_a_skipped_leg_is_named_and_never_silently_green():
    check = check_money_conservation(load_adversarial("unbalanced_posting"))
    skipped = check.examined["legs_skipped"]
    assert any("L2" in reason for reason in skipped)
    assert any("L3" in reason for reason in skipped)


def test_conservation_with_neither_postings_nor_accounts_is_NO_DATA():
    check = check_money_conservation(LedgerSnapshot(subject="empty"))
    assert check.status == NO_DATA


# --------------------------------------------------------------------------- #
# no overdraft - both outcomes, including the over-firing trap
# --------------------------------------------------------------------------- #
def test_FIRES_no_overdraft_on_the_planted_fixture_and_cites_the_account():
    check = check_no_overdraft(load_adversarial("overdraft_account"))
    assert check.status == VIOLATION
    violation = [v for v in check.violations if v.code == "account_below_floor"][0]
    assert "wallet:ana" in violation.message
    assert violation.citations[0].ref == "account:wallet:ana"


def test_SILENT_the_legally_negative_funding_account_does_NOT_fire():
    """external:funding sits at -158000 with allowNegative=true. Flagging it is the trap."""
    for snapshot in (load_recorded("clean"), load_adversarial("clean_must_not_fire")):
        check = check_no_overdraft(snapshot)
        assert check.violation_count == 0, [v.message for v in check.violations]
        assert any(
            citation.ref == "account:external:funding" and "none (allowNegative)" in citation.detail
            for citation in check.citations
        )


def test_FIRES_on_a_mid_replay_dip_that_ends_perfectly_legal():
    """N2: the end state is fine and only the REPLAY sees the breach."""
    postings = (
        Posting(1, 2, 3, 500, "ARS", "OUT-1", "2026-01-01T00:00:01Z"),
        Posting(2, 1, 2, 500, "ARS", "IN-1", "2026-01-01T00:00:02Z"),
    )
    accounts = (
        AccountRow("external:funding", "ARS", 500, 0, 0, True, account_id=1),
        AccountRow("wallet:ana", "ARS", 500, 500, 0, False, account_id=2),
        AccountRow("wallet:beto", "ARS", 0, 500, 0, False, account_id=3),
    )
    snapshot = LedgerSnapshot(subject="mid-replay-dip", postings=postings, accounts=accounts)
    end_state = check_no_overdraft(
        LedgerSnapshot(subject="end-state-only", accounts=accounts)
    )
    assert end_state.violation_count == 0  # the end state is legal...

    check = check_no_overdraft(snapshot)
    codes = [v.code for v in check.violations]
    assert "account_below_floor_during_replay" in codes  # ...and the replay still catches it
    assert check.examined["replay_steps"] == 2


def test_SILENT_when_the_same_dip_belongs_to_an_allowNegative_account():
    postings = (
        Posting(1, 1, 2, 500, "ARS", "OUT-1", "2026-01-01T00:00:01Z"),
        Posting(2, 2, 1, 500, "ARS", "IN-1", "2026-01-01T00:00:02Z"),
    )
    accounts = (
        AccountRow("external:funding", "ARS", 500, 500, 0, True, account_id=1),
        AccountRow("wallet:ana", "ARS", 500, 500, 0, False, account_id=2),
    )
    check = check_no_overdraft(
        LedgerSnapshot(subject="legal-dip", postings=postings, accounts=accounts)
    )
    assert check.violation_count == 0
    assert check.examined["replay_steps"] == 2


def test_an_undeclared_floor_is_NOT_guessed_in_either_direction():
    """Guessing False over-fires on external:funding; guessing True hides a real overdraft."""
    check = check_no_overdraft(load_adversarial("counters_disagree_with_postings"))
    assert check.status == NO_DATA
    assert check.examined["accounts_with_an_undeclared_floor"] == 3
    assert any("floor undeclared" in note for note in check.notes)


def test_the_pending_debits_term_is_load_bearing_in_the_balance():
    """Account.availableBalance is THREE terms. Dropping pendingDebits hides a reservation."""
    reserved = AccountRow("wallet:ana", "ARS", 0, 100, 150, False, account_id=2)
    assert reserved.available_balance == -50
    check = check_no_overdraft(LedgerSnapshot(subject="reserved", accounts=(reserved,)))
    assert "account_below_floor" in [v.code for v in check.violations]


# --------------------------------------------------------------------------- #
# the verdict object itself
# --------------------------------------------------------------------------- #
def test_every_violation_the_shipped_corpus_can_produce_carries_a_citation():
    subjects = [load_recorded("clean"), load_recorded("tampered")]
    subjects += [load_adversarial(path.stem) for path in sorted(ADVERSARIAL.glob("*.json"))]
    seen = 0
    for snapshot in subjects:
        for violation in check_all(snapshot).violations:
            assert violation.citations
            assert all(citation.source for citation in violation.citations)
            seen += 1
    assert seen >= 5


def test_a_violation_without_citations_is_REFUSED_at_construction():
    with pytest.raises(ValueError):
        Violation(check=MONEY_CONSERVATION, code="x", message="y", citations=())


def test_NO_DATA_can_never_be_read_as_a_pass_and_never_masks_a_violation():
    no_data = CheckVerdict(check=MONEY_CONSERVATION, status=NO_DATA)
    ok = CheckVerdict(check=NO_OVERDRAFT, status=OK)
    violated = CheckVerdict(
        check=HASH_CHAIN_CONTINUITY,
        status=VIOLATION,
        violations=(
            Violation(
                check=HASH_CHAIN_CONTINUITY,
                code="entry_hash_mismatch",
                message="planted",
                citations=(Citation(kind="chain_link", ref="chain_link:seq=1", source="test"),),
            ),
        ),
    )
    assert decide((ok,)) == VERDICT_OK
    assert decide((ok, no_data)) == VERDICT_INCOMPLETE
    assert decide((ok, no_data, violated)) == VERDICT_TAMPERED


def test_the_verdict_serialises_to_the_shape_the_phase_2_endpoint_will_return():
    payload = check_all(load_recorded("tampered")).as_dict()
    assert payload["verdict"] == VERDICT_TAMPERED
    assert payload["violation_count"] == len(payload["checks"][0]["violations"]) + len(
        payload["checks"][1]["violations"]
    ) + len(payload["checks"][2]["violations"])
    assert {check["check"] for check in payload["checks"]} == {
        MONEY_CONSERVATION,
        NO_OVERDRAFT,
        HASH_CHAIN_CONTINUITY,
    }
    assert payload["signature"]["status"] in ("VERIFIED", "INVALID", "UNVERIFIED-SIGNATURE")
    assert json.dumps(payload)  # must be JSON-serialisable as it stands


def test_the_cli_exits_0_on_clean_and_1_on_tampered():
    from tools import verify_report

    assert verify_report.main(["--corpus", "recorded", "--half", "clean"]) == 0
    assert verify_report.main(["--corpus", "recorded", "--half", "tampered"]) == 1
    assert verify_report.main(["--corpus", "adversarial", "--case", "unbalanced_posting"]) == 1
