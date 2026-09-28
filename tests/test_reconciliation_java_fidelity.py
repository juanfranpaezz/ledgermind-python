"""The derived reconciliation report, pinned to the Java it claims to mirror.

Primary source: LedgerMind commit 872505f,
src/main/java/com/ledgermind/ledger/reconciliation/ReconciliationMatcher.java and
ReconciliationService.java. Every expected value below was read off the Java, not off
our own output - a fixture generator tested against its own previous output only pins
the drift in place.

These tests exist because a Java-fidelity review (2026-09-13) found the generator
overwriting by ref where the Java SUMS, dropping the ``difference == 0`` term of
``balanced``, counting distinct refs where the Java counts raw list entries, and
inventing the Spanish detail and summary strings.
"""

from __future__ import annotations

from tools import derive_fixtures as df


def _feed(*pairs):
    return [{"externalRef": ref, "amount": amount, "occurredAt": None} for ref, amount in pairs]


def _ledger(*pairs):
    return [{"ref": ref, "amount": amount} for ref, amount in pairs]


# ---------------------------------------------------------------------------
# 1. Split settlements: the case the overwrite bug got wrong.
# ---------------------------------------------------------------------------


def test_a_SPLIT_settlement_on_one_ref_reconciles_to_ZERO_discrepancies():
    """ReconciliationMatcher.java:27-30. A PSP settles ORD-1001 in two legs, 60000 then
    40000, against one ledger entry of 100000. Summing per ref is the whole point of the
    grouping, and the Java comment says so."""
    report = df.reconcile(_feed(("ORD-1001", 60_000), ("ORD-1001", 40_000)), _ledger(("ORD-1001", 100_000)))
    assert report["discrepancies"] == []
    assert report["matched"] == 1
    assert report["balanced"] is True
    assert report["difference"] == 0
    assert report["summary"] == (
        "Conciliado: 1 referencias cuadran; feed y ledger coinciden en 100000 centavos."
    )


def test_the_OVERWRITE_behaviour_that_was_fixed_would_have_failed_that_same_case():
    """Not vacuous: the pre-fix logic, reproduced here, calls the split a mismatch.

    If this test ever goes green against df.reconcile, the SUM has been lost again.
    """
    feed = _feed(("ORD-1001", 60_000), ("ORD-1001", 40_000))
    overwriting = {}
    for record in feed:
        overwriting[record["externalRef"]] = record["amount"]  # the old line, verbatim
    assert overwriting["ORD-1001"] == 40_000
    assert overwriting["ORD-1001"] != df.reconcile(feed, _ledger(("ORD-1001", 100_000)))["feedTotal"]


def test_a_duplicated_feed_line_is_caught_instead_of_silently_matching():
    """The failure the Java comment says the grouping exists to prevent: the PSP reports
    ORD-1002 twice, so the summed feed side is double the ledger side."""
    report = df.reconcile(_feed(("ORD-1002", 50_000), ("ORD-1002", 50_000)), _ledger(("ORD-1002", 50_000)))
    assert [d["type"] for d in report["discrepancies"]] == ["AMOUNT_MISMATCH"]
    assert report["discrepancies"][0]["feedAmount"] == 100_000
    assert report["balanced"] is False


# ---------------------------------------------------------------------------
# 2. Counts and totals come from the RAW lists (Java :63-65, :69).
# ---------------------------------------------------------------------------


def test_counts_and_totals_come_from_the_raw_lists_not_the_by_ref_dicts():
    report = df.reconcile(_feed(("ORD-1001", 60_000), ("ORD-1001", 40_000)), _ledger(("ORD-1001", 100_000)))
    assert report["feedCount"] == 2, "feed.size(), not the number of distinct refs"
    assert report["ledgerCount"] == 1
    assert report["feedTotal"] == 100_000
    assert report["ledgerTotal"] == 100_000


def test_the_demo_corpus_keeps_the_raw_counts_the_java_emits():
    postings = df.build_postings()
    report = df.reconciliation_report(postings)
    assert report["feedCount"] == 5, "4 kept postings + the PSP-only line"
    assert report["ledgerCount"] == 5, "one LedgerEntry per posting, de-duplicated by nothing"


# ---------------------------------------------------------------------------
# 3. balanced needs BOTH terms (Java :67).
# ---------------------------------------------------------------------------


def test_is_balanced_returns_TRUE_only_with_no_discrepancies_and_a_zero_difference():
    assert df.is_balanced([], 0) is True


def test_is_balanced_returns_FALSE_when_the_difference_is_non_zero_despite_an_empty_list():
    """The term that was dropped. Unreachable through reconcile() by construction, which
    is precisely why it needs its own test before someone deletes it as dead code."""
    assert df.is_balanced([], 1) is False
    assert df.is_balanced([], -1) is False


def test_is_balanced_returns_FALSE_on_any_discrepancy():
    assert df.is_balanced([{"type": "AMOUNT_MISMATCH"}], 0) is False


# ---------------------------------------------------------------------------
# 4. The strings are the Java's, character for character.
# ---------------------------------------------------------------------------


def test_MISSING_IN_LEDGER_detail_is_the_java_string():
    report = df.reconcile(_feed(("PSP-ONLY-9999", 4_300)), _ledger())
    assert report["discrepancies"][0]["detail"] == (
        "el PSP liquidó 4300 para 'PSP-ONLY-9999' y no hay asiento"
    )


def test_MISSING_IN_FEED_detail_is_the_java_string():
    report = df.reconcile(_feed(), _ledger(("ORD-1002", 50_000)))
    assert report["discrepancies"][0]["detail"] == (
        "el ledger tiene 50000 para 'ORD-1002' que el PSP no reporta"
    )


def test_AMOUNT_MISMATCH_detail_carries_the_right_hint_on_each_sign():
    short = df.reconcile(_feed(("ORD-1003", 29_961)), _ledger(("ORD-1003", 30_000)))
    assert short["discrepancies"][0]["detail"] == (
        "diferencia de -39 en 'ORD-1003' (el PSP liquidó menos: posible comisión/retención no asentada)"
    )
    over = df.reconcile(_feed(("ORD-1003", 30_050)), _ledger(("ORD-1003", 30_000)))
    assert over["discrepancies"][0]["detail"] == (
        "diferencia de 50 en 'ORD-1003' (el PSP liquidó de más que lo asentado)"
    )


def test_the_unbalanced_summary_is_the_java_string():
    report = df.reconciliation_report(df.build_postings())
    assert report["summary"] == (
        "Descuadre: 3 discrepancia(s). Feed=154761 Ledger=200500 (diferencia -45739)."
    )


# ---------------------------------------------------------------------------
# 5. Null-safety, Java :27-30 (Objects.requireNonNullElse -> the "" bucket).
# ---------------------------------------------------------------------------


def test_a_null_ref_collapses_into_the_empty_string_bucket_instead_of_raising():
    report = df.reconcile(_feed((None, 500)), _ledger())
    assert report["discrepancies"][0]["ref"] == ""
    assert report["discrepancies"][0]["type"] == "MISSING_IN_LEDGER"


# ---------------------------------------------------------------------------
# 6. The demo feed shape itself (ReconciliationService.java:41-53).
# ---------------------------------------------------------------------------


def test_the_demo_feed_drops_index_one_and_shaves_thirty_nine_off_index_two():
    postings = df.build_postings()
    feed = df.demo_feed(postings)
    refs = [r["externalRef"] for r in feed]
    assert "ORD-1002" not in refs, "index 1 is dropped -> MISSING_IN_FEED"
    assert refs == ["ORD-1001", "ORD-1003", "ORD-1004", "ORD-1005", "PSP-ONLY-9999"]
    by_ref = {r["externalRef"]: r["amount"] for r in feed}
    assert by_ref["ORD-1003"] == 30_000 - 39
    assert by_ref["PSP-ONLY-9999"] == 4_300
