"""Generate the SOURCE-DERIVED fixture corpus for the LedgerMind verification agent.

WHAT THIS IS, STATED FIRST SO IT CANNOT BE MISREAD
==================================================
These fixtures are DERIVED FROM THE JAVA SOURCE, not RECORDED from a running
LedgerMind. They reproduce, by hand-executing the Java logic in Python, exactly
what ``POST /api/demo/reset`` seeds and exactly what ``POST /api/demo/tamper``
breaks, including the real SHA-256 hash chain, which is recomputed here with the
same canonical string the Java chainer uses.

They DO NOT satisfy AC-0.2, and they DO NOT satisfy the manifest's section 2.6
instrument-fitness leg, both of which require a corpus captured from a running
stack ("a hand-edited fixture proves the test, not the instrument"). The recorded
corpus belongs in ``tests/fixtures/recorded/`` and does not exist yet, because the
Docker daemon is down. Every file this script writes lands under
``tests/fixtures/derived_from_source/`` and its corpus metadata carries
``ac_0_2_eligible: false``.

WHAT THEY ARE GOOD FOR (claim corrected 2026-09-13 - see below)
==============================================================
Building and unit-testing the Phase-1 deterministic checker without a running
service, and being a STRUCTURAL AND ARITHMETIC oracle the recorded corpus can later
be diffed against: field shapes, account balances, counters, verdict strings, the
reconciliation report, and the chain's INTERNAL consistency.

WHAT THEY ARE NOT, stated because the first version of this docstring called them an
"exact expected-value oracle" and that was too strong:

* ``createdAt`` here is INVENTED (whole seconds, 17:00:01Z..17:00:05Z). A real
  Postgres ``created_at`` is an Instant carrying MICROSECONDS, and ``createdAt`` is
  part of the canonical string ``JournalChainer.entryHash`` signs. So the entryHash
  values in this corpus can NEVER equal those of a real capture, whatever the
  precision - not because the formula is wrong, but because the inputs are ours.
  Against a recorded corpus, compare the chain by RE-DERIVING it from the recorded
  rows, never by comparing hash literals.
* Timestamp PRECISION is therefore a normalisation the derived-vs-recorded diff may
  apply to the timestamp field only. It must never be widened into "ignore
  differences": the diff stays a real oracle on every other field.
* Account ``version`` numbers are derived (one increment per UPDATE), not observed.

If the recorded clean corpus disagrees with this one on anything OUTSIDE that list,
either the demo seeding changed or our reading of the Java source is wrong, and both
are worth knowing.

PRIMARY SOURCES (LedgerMind @ commit 872505f, read-only)
========================================================
* DemoSupportController.reset      - 3 accounts, 5 transfers ORD-1001..ORD-1005
* DemoSupportController.tamper     - UPDATE posting SET amount = amount + 1
                                     on max(id); counters are NOT touched
* Account.availableBalance         - postedCredits - postedDebits - pendingDebits
* JournalChainer.entryHash         - SHA-256(prevHash + "id|dr|cr|amount|asset|key|createdAt")
* JournalChainer.GENESIS           - "0" * 64
* JournalCheckpointService.verdict - the two verdict strings reproduced below
* LedgerController.AccountView     - (address, asset, balance, postedDebits, postedCredits, version)
* ReconciliationService.reconcileDemoFeed - i==1 dropped, i==2 minus 39, plus PSP-ONLY-9999 at 4300
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = REPO_ROOT / "tests" / "fixtures" / "derived_from_source"

GENESIS = "0" * 64
ALGORITHM = "ML-DSA-65"

# The signing material is generated at runtime by an EPHEMERAL demo key. A derived
# fixture cannot know it, and inventing a realistic-looking key blob would be a lie
# that a later reader could mistake for a capture. Placeholders, named as such.
PUBLIC_KEY_PLACEHOLDER = "NOT-CAPTURED-derived-fixture-has-no-ephemeral-demo-public-key"
SIGNATURE_PLACEHOLDER = "NOT-CAPTURED-derived-fixture-has-no-ephemeral-demo-signature"
SIGNED_AT = "2026-09-13T17:00:06Z"

ACCOUNTS = [
    # id, address, asset, allow_negative
    # (insertion order = IDENTITY order after TRUNCATE ... RESTART IDENTITY)
    (1, "external:funding", "ARS", True),
    (2, "wallet:ana", "ARS", False),
    (3, "wallet:beto", "ARS", False),
]

TRANSFERS = [
    # id, debit_account_id, credit_account_id, amount, idempotency_key, created_at
    (1, 1, 2, 100_000, "ORD-1001", "2026-09-13T17:00:01Z"),
    (2, 1, 2, 50_000, "ORD-1002", "2026-09-13T17:00:02Z"),
    (3, 2, 3, 30_000, "ORD-1003", "2026-09-13T17:00:03Z"),
    (4, 2, 3, 12_500, "ORD-1004", "2026-09-13T17:00:04Z"),
    (5, 1, 3, 8_000, "ORD-1005", "2026-09-13T17:00:05Z"),
]
ASSET = "ARS"


def canonical(posting):
    """JournalChainer.entryHash's canonical string, byte for byte."""
    return "|".join(
        [
            str(posting["id"]),
            str(posting["debitAccountId"]),
            str(posting["creditAccountId"]),
            str(posting["amount"]),
            posting["asset"],
            posting["idempotencyKey"],
            posting["createdAt"],
        ]
    )


def entry_hash(prev_hash, posting):
    return hashlib.sha256((prev_hash + canonical(posting)).encode("utf-8")).hexdigest()


def build_postings():
    out = []
    for pid, dr, cr, amount, key, created in TRANSFERS:
        out.append(
            {
                "id": pid,
                "debitAccountId": dr,
                "creditAccountId": cr,
                "amount": amount,
                "asset": ASSET,
                "idempotencyKey": key,
                "createdAt": created,
            }
        )
    return out


def build_chain(postings):
    """posting_hash rows, exactly as JournalChainer.chainPendingPostings writes them."""
    chain = []
    prev = GENESIS
    for seq, p in enumerate(postings, start=1):
        eh = entry_hash(prev, p)
        chain.append({"postingId": p["id"], "seq": seq, "prevHash": prev, "entryHash": eh})
        prev = eh
    return chain


def verify_chain(postings, chain):
    """JournalChainer.verify, reimplemented. Returns a VerifyResult-shaped dict."""
    by_id = {p["id"]: p for p in postings}
    prev = GENESIS
    checked = 0
    for link in sorted(chain, key=lambda link: link["seq"]):
        p = by_id.get(link["postingId"])
        if p is None:
            return {"intact": False, "chainedCount": checked, "brokenAtSeq": link["seq"]}
        if prev != link["prevHash"] or entry_hash(prev, p) != link["entryHash"]:
            return {"intact": False, "chainedCount": checked, "brokenAtSeq": link["seq"]}
        prev = link["entryHash"]
        checked += 1
    return {"intact": True, "chainedCount": checked, "brokenAtSeq": None}


def account_counters(postings):
    counters = {}
    for aid, _address, _asset, _allow in ACCOUNTS:
        counters[aid] = {
            "postedDebits": 0,
            "postedCredits": 0,
            "pendingDebits": 0,
            "pendingCredits": 0,
            "updates": 0,
        }
    for p in postings:
        counters[p["debitAccountId"]]["postedDebits"] += p["amount"]
        counters[p["debitAccountId"]]["updates"] += 1
        counters[p["creditAccountId"]]["postedCredits"] += p["amount"]
        counters[p["creditAccountId"]]["updates"] += 1
    return counters


def account_views(counters):
    """LedgerController.AccountView for each account.

    NOTE, load-bearing for Phase 1: AccountView exposes NEITHER pendingDebits NOR
    allowNegative. The three-term available-balance formula and the no-overdraft
    exemption are therefore NOT recomputable from the REST view alone. See the
    corpus metadata and the Phase-0 handoff; this is a Phase 0 design decision.
    """
    views = {}
    for aid, address, asset, _allow_negative in ACCOUNTS:
        c = counters[aid]
        balance = c["postedCredits"] - c["postedDebits"] - c["pendingDebits"]
        views[address] = {
            "address": address,
            "asset": asset,
            "balance": balance,
            "postedDebits": c["postedDebits"],
            "postedCredits": c["postedCredits"],
            # @Version increments once per UPDATE. Derived, not observed, and not
            # load-bearing for any acceptance criterion.
            "version": c["updates"],
        }
    return views


def clean_verdict(chained_count, chain_seq):
    return (
        "SIN EVIDENCIA DE EDICION: la hash-chain recomputa limpia sobre "
        + str(chained_count)
        + " asientos y la firma del ultimo checkpoint ("
        + ALGORITHM
        + ", seq "
        + str(chain_seq)
        + ", firmado "
        + SIGNED_AT
        + ") cierra bajo la clave que el propio checkpoint guarda (integridad-de-mensaje,"
        " NO autenticidad: probar QUIEN firmo exige una clave anclada fuera de la DB)."
        " No descarta el truncado de la cola posterior al checkpoint. Tamper-EVIDENCE,"
        " no prevencion."
    )


def tampered_verdict(broken_at_seq):
    return (
        "MANIPULACION DETECTADA: la hash-chain se rompe en seq "
        + str(broken_at_seq)
        + " (un asiento fue editado o borrado tras encadenarse);"
    )


def audit_report(verify, chain, verdict, tamper_detected):
    head = chain[-1]
    signed_head_still_in_chain = any(
        link["seq"] == head["seq"] and link["entryHash"] == head["entryHash"] for link in chain
    )
    return {
        "tamperDetected": tamper_detected,
        "verdict": verdict,
        "chainIntact": verify["intact"],
        "chainedCount": verify["chainedCount"],
        "brokenAtSeq": verify["brokenAtSeq"],
        "checkpointPresent": True,
        "signatureAlgorithm": ALGORITHM,
        "signedChainSeq": head["seq"],
        "signedHeadHash": head["entryHash"],
        "signatureValid": True,
        "signedHeadStillInChain": signed_head_still_in_chain,
        "signedHeadIsLatest": True,
        "signedAt": SIGNED_AT,
        "_signing_material": {
            "publicKeyBase64": PUBLIC_KEY_PLACEHOLDER,
            "signature": SIGNATURE_PLACEHOLDER,
            "note": "Ephemeral demo key. Placeholders, never invented key material.",
        },
    }


def is_balanced(discrepancies, difference):
    """ReconciliationMatcher.java:67 - BOTH terms, kept as a named function.

    ``boolean balanced = discrepancies.isEmpty() && difference == 0;``

    The Java comment states the reason for the second term: "dos errores opuestos no
    pueden cantar OK". Through ``reconcile`` alone the second term is unreachable - if
    every ref agrees on both sides the totals are equal by construction - which is
    exactly why it is easy to delete as dead code and why it is pulled out here, where
    both of its outcomes can be exercised directly.
    """
    return not discrepancies and difference == 0


def reconcile(feed, ledger_entries):
    """ReconciliationMatcher.reconcile, mirrored term by term from the Java.

    Source: src/main/java/com/ledgermind/ledger/reconciliation/ReconciliationMatcher.java
    at LedgerMind commit 872505f. Four things here are NOT free choices and were each
    drifting in the first version of this file (found by the Java-fidelity review,
    2026-09-13):

    1. BOTH SIDES AGGREGATE BY REF WITH A SUM (:27-30). A PSP can settle one order in
       several legs (split / adjustment / reversal), so the amounts are SUMMED per ref
       and the sums are compared. Overwriting by ref instead - which is what a plain
       dict assignment does - silently drops a leg, and a duplicated feed line would
       then "match" in silence, the exact failure the Java comment says the grouping
       exists to prevent.
    2. A NULL REF COLLAPSES TO "" (:27-30, Objects.requireNonNullElse), a single
       mismatch bucket, rather than raising.
    3. balanced REQUIRES difference == 0 AS WELL as an empty discrepancy list (:67).
       Two opposite errors must not be able to sing "OK".
    4. feedCount / ledgerCount / feedTotal / ledgerTotal are computed over the RAW
       LISTS (:63-65, :69), not over the by-ref dictionaries. With split settlements
       those two numbers genuinely differ, and the raw-list one is what the Java emits.

    The detail and summary strings are copied VERBATIM from the Java, accents included,
    because a fixture whose text is paraphrased cannot be diffed against a real capture.

    ORDERING CAVEAT, named not hidden: Java iterates two HashMaps, whose iteration order
    is neither insertion order nor sorted order, so the ORDER of the discrepancy list in
    a real capture is not reproducible here. The loop ORDER (feed side first, then
    ledger side) is mirrored; within a side, compare discrepancies as a SET, not a list.
    """
    feed_by_ref = {}
    for record in feed:
        ref = record["externalRef"] if record["externalRef"] is not None else ""
        feed_by_ref[ref] = feed_by_ref.get(ref, 0) + record["amount"]

    ledger_by_ref = {}
    for entry in ledger_entries:
        ref = entry["ref"] if entry["ref"] is not None else ""
        ledger_by_ref[ref] = ledger_by_ref.get(ref, 0) + entry["amount"]

    discrepancies = []
    matched = 0

    for ref, feed_amount in feed_by_ref.items():
        ledger_amount = ledger_by_ref.get(ref)
        if ledger_amount is None:
            discrepancies.append(
                {
                    "type": "MISSING_IN_LEDGER",
                    "ref": ref,
                    "feedAmount": feed_amount,
                    "ledgerAmount": 0,
                    "detail": "el PSP liquidó " + str(feed_amount) + " para '" + ref + "' y no hay asiento",
                }
            )
        elif ledger_amount != feed_amount:
            diff = feed_amount - ledger_amount
            hint = (
                " (el PSP liquidó menos: posible comisión/retención no asentada)"
                if diff < 0
                else " (el PSP liquidó de más que lo asentado)"
            )
            discrepancies.append(
                {
                    "type": "AMOUNT_MISMATCH",
                    "ref": ref,
                    "feedAmount": feed_amount,
                    "ledgerAmount": ledger_amount,
                    "detail": "diferencia de " + str(diff) + " en '" + ref + "'" + hint,
                }
            )
        else:
            matched += 1

    for ref, ledger_amount in ledger_by_ref.items():
        if ref not in feed_by_ref:
            discrepancies.append(
                {
                    "type": "MISSING_IN_FEED",
                    "ref": ref,
                    "feedAmount": 0,
                    "ledgerAmount": ledger_amount,
                    "detail": "el ledger tiene "
                    + str(ledger_amount)
                    + " para '"
                    + ref
                    + "' que el PSP no reporta",
                }
            )

    feed_total = sum(record["amount"] for record in feed)
    ledger_total = sum(entry["amount"] for entry in ledger_entries)
    difference = feed_total - ledger_total
    balanced = is_balanced(discrepancies, difference)
    if balanced:
        summary = (
            "Conciliado: "
            + str(matched)
            + " referencias cuadran; feed y ledger coinciden en "
            + str(feed_total)
            + " centavos."
        )
    else:
        summary = (
            "Descuadre: "
            + str(len(discrepancies))
            + " discrepancia(s). Feed="
            + str(feed_total)
            + " Ledger="
            + str(ledger_total)
            + " (diferencia "
            + str(difference)
            + ")."
        )

    return {
        "feedCount": len(feed),
        "ledgerCount": len(ledger_entries),
        "matched": matched,
        "feedTotal": feed_total,
        "ledgerTotal": ledger_total,
        "difference": difference,
        "discrepancies": discrepancies,
        "balanced": balanced,
        "summary": summary,
    }


def demo_feed(postings):
    """ReconciliationService.reconcileDemoFeed lines 41-53, mirrored.

    Postings ordered by id; index 1 is dropped (MISSING_IN_FEED), index 2 is settled 39
    cents short (AMOUNT_MISMATCH), and one PSP-only line at 4300 is appended
    (MISSING_IN_LEDGER).
    """
    feed = []
    for i, posting in enumerate(postings):
        if i == 1:
            continue
        amount = posting["amount"] - 39 if i == 2 else posting["amount"]
        feed.append(
            {
                "externalRef": posting["idempotencyKey"],
                "amount": amount,
                "occurredAt": posting["createdAt"],
            }
        )
    feed.append(
        {
            "externalRef": "PSP-ONLY-9999",
            "amount": 4_300,
            "occurredAt": postings[0]["createdAt"] if postings else None,
        }
    )
    return feed


def ledger_entries(postings):
    """ReconciliationService.ledgerEntries :61-62 - a RAW list projection, one entry per
    posting, keeping duplicates. It is not de-duplicated by ref."""
    return [{"ref": p["idempotencyKey"], "amount": p["amount"]} for p in postings]


def reconciliation_report(postings):
    """ReconciliationService.reconcileDemoFeed + the matcher, reimplemented."""
    report = reconcile(demo_feed(postings), ledger_entries(postings))
    report["_note"] = (
        "SHAPE NOTE: this is the demo feed produced by POST /api/demo/reconcile. The"
        " agent's own reconcile_against_feed tool posts a feed body to POST"
        " /api/reconciliation and gets this same ReconciliationReport shape back."
        " ORDERING: the Java builds the discrepancy list from two HashMaps, so compare"
        " discrepancies as a set, never by index."
    )
    return report


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    postings = build_postings()
    chain = build_chain(postings)

    # ---------------- CLEAN corpus ----------------
    clean_verify = verify_chain(postings, chain)
    assert clean_verify["intact"], "derived clean corpus must verify intact"
    counters = account_counters(postings)
    views = account_views(counters)
    clean_dir = OUT_ROOT / "clean"
    for address, view in views.items():
        write_json(clean_dir / ("account_" + address.replace(":", "_") + ".json"), view)
    write_json(clean_dir / "journal_verify.json", clean_verify)
    write_json(
        clean_dir / "journal_audit.json",
        audit_report(
            clean_verify,
            chain,
            clean_verdict(clean_verify["chainedCount"], chain[-1]["seq"]),
            False,
        ),
    )
    write_json(clean_dir / "reconciliation.json", reconciliation_report(postings))
    write_json(
        clean_dir / "postings_and_hashes.json",
        {
            "postings": postings,
            "postingHashes": chain,
            "_note": (
                "DB-LEVEL capture. No REST endpoint and no MCP tool exposes posting_hash"
                " rows, so an independent Python recomputation of the hash chain requires"
                " a read-only SELECT against Postgres. Without it the checker can only"
                " CONSUME the Java verdict. Phase 0 design decision."
            ),
        },
    )

    # ---------------- TAMPERED corpus ----------------
    # DemoSupportController.tamper: UPDATE posting SET amount = amount + 1 WHERE id = max(id).
    # The chain rows and the account counters are NOT touched - that is the whole point.
    tampered_postings = [dict(p) for p in postings]
    tampered_postings[-1]["amount"] += 1
    tampered_verify = verify_chain(tampered_postings, chain)
    assert not tampered_verify["intact"], "derived tampered corpus must break the chain"
    tampered_dir = OUT_ROOT / "tampered"
    for address, view in views.items():  # counters unchanged by the SQL tamper
        write_json(tampered_dir / ("account_" + address.replace(":", "_") + ".json"), view)
    write_json(tampered_dir / "journal_verify.json", tampered_verify)
    write_json(
        tampered_dir / "journal_audit.json",
        audit_report(tampered_verify, chain, tampered_verdict(tampered_verify["brokenAtSeq"]), True),
    )
    write_json(tampered_dir / "reconciliation.json", reconciliation_report(tampered_postings))
    write_json(
        tampered_dir / "postings_and_hashes.json",
        {
            "postings": tampered_postings,
            "postingHashes": chain,
            "_note": (
                "The posting amount moved by +1; the posting_hash rows did not. The chain"
                " therefore breaks at the seq of the edited posting, and the account"
                " counters still describe the PRE-tamper amounts - a second, independent"
                " signal the Phase-1 checker can derive without trusting the Java verdict."
            ),
        },
    )

    # ---------------- ADVERSARIAL cases (hand-constructed on purpose) ----------------
    adv = OUT_ROOT / "adversarial"

    # A1 - unbalanced posting: debit leg and credit leg disagree. AC-1.3's input.
    unbalanced = [dict(p) for p in postings]
    unbalanced[2]["creditAmount"] = unbalanced[2]["amount"] - 500
    write_json(
        adv / "unbalanced_posting.json",
        {
            "case": "unbalanced_posting",
            "expected_violation": "conservation",
            "why": (
                "A double-entry posting whose credit leg is 500 smaller than its debit leg."
                " LedgerMind's own schema cannot represent this (one amount column serves"
                " both legs), so it can ONLY arrive from a corrupted feed or a hand-built"
                " payload - which is exactly why the checker must not assume the invariant"
                " holds."
            ),
            "postings": unbalanced,
        },
    )

    # A2 - overdraft on an account that does not allow it.
    overdraft_counters = {}
    for aid, c in counters.items():
        overdraft_counters[aid] = dict(c)
    overdraft_counters[2]["postedDebits"] += 200_000  # wallet:ana, allow_negative = false
    overdraft_views = account_views(overdraft_counters)
    allow_map = {}
    for a in ACCOUNTS:
        allow_map[a[1]] = a[3]
    write_json(
        adv / "overdraft_account.json",
        {
            "case": "overdraft_account",
            "expected_violation": "no_overdraft",
            "why": (
                "wallet:ana is created with allowNegative = false, so a negative available"
                " balance is a violation. external:funding is created with allowNegative ="
                " true and its -158000 is LEGAL - a checker that flags every negative"
                " balance fires on the clean corpus and is therefore useless."
            ),
            "allow_negative_by_address": allow_map,
            "accounts": overdraft_views,
        },
    )

    # A3 - a chain link whose posting row was deleted outright.
    deleted_postings = [p for p in postings if p["id"] != 3]
    write_json(
        adv / "chain_link_posting_deleted.json",
        {
            "case": "chain_link_posting_deleted",
            "expected_violation": "hash_chain",
            "expected_broken_at_seq": 3,
            "why": "JournalChainer.verify returns broken at the seq whose posting row is gone.",
            "postings": deleted_postings,
            "postingHashes": chain,
        },
    )

    # A4 - prevHash rewritten so the links no longer join, content untouched.
    rewritten = [dict(link) for link in chain]
    rewritten[3]["prevHash"] = "f" * 64
    write_json(
        adv / "chain_prev_hash_rewritten.json",
        {
            "case": "chain_prev_hash_rewritten",
            "expected_violation": "hash_chain",
            "expected_broken_at_seq": 4,
            "why": (
                "Content is untouched; only the link is cut. A checker that only re-hashes"
                " posting content and never compares prevHash to the previous entryHash will"
                " MISS this, and it is the cheaper attack of the two."
            ),
            "postings": postings,
            "postingHashes": rewritten,
        },
    )

    # A5 - counters that disagree with the postings they supposedly summarise.
    drifted = {}
    for aid, c in counters.items():
        drifted[aid] = dict(c)
    drifted[3]["postedCredits"] += 1  # wallet:beto claims one unit more than the postings say
    write_json(
        adv / "counters_disagree_with_postings.json",
        {
            "case": "counters_disagree_with_postings",
            "expected_violation": "conservation",
            "why": (
                "Balances are DERIVED from counters, never stored, so a counter that drifts"
                " from the posting history is invisible to the ledger's own hash chain: the"
                " chain protects the postings, not the counters. This is the gap the Python"
                " checker closes and the ledger does not."
            ),
            "accounts": account_views(drifted),
            "postings": postings,
        },
    )

    # A5b - a drift that ONLY the DEBIT half of the L2 counters-vs-replay comparison can see.
    # A5 moves a single postedCredits counter, so it is caught by the system-wide net (L3) as
    # well; until 2026-09-22 nothing in the corpus isolated the debit half, and the 2026-09-20
    # mutation sweep showed it could be deleted (mutant M1d) with the whole suite still green.
    # Moving TWO postedDebits counters in opposite directions keeps the net at zero, so L3, L1
    # and the no-overdraft floor all stay silent and the debit leg is the only thing left.
    debit_only = {aid: dict(c) for aid, c in counters.items()}
    debit_only[1]["postedDebits"] -= 1000  # external:funding claims 1000 less than it paid
    debit_only[2]["postedDebits"] += 1000  # wallet:ana claims 1000 more than it spent
    write_json(
        adv / "counters_debit_leg_only_drift.json",
        {
            "case": "counters_debit_leg_only_drift",
            "expected_violation": "conservation",
            "why": (
                "ONLY the DEBIT half of the L2 counters-vs-replay comparison can catch this."
                " The two postedDebits counters are moved 1000 in opposite directions, so the"
                " system-wide net still sums to zero (L3 stays silent), every postedCredits"
                " counter still agrees with the replay (the CREDIT half of L2 stays silent),"
                " every entry still balances leg-for-leg (L1 stays silent) and no account"
                " crosses its floor (no-overdraft stays silent). Before 2026-09-22 no fixture"
                " isolated this leg: the 2026-09-20 mutation sweep deleted the debit"
                " comparison (mutant M1d) and all 210 tests stayed green."
            ),
            "accounts": account_views(debit_only),
            "account_id_by_address": {address: aid for aid, address, _a, _n in ACCOUNTS},
            "allow_negative_by_address": allow_map,
            "postings": postings,
        },
    )

    # A6 - the trap case: a clean corpus that must NOT fire anything.
    write_json(
        adv / "clean_must_not_fire.json",
        {
            "case": "clean_must_not_fire",
            "expected_violation": None,
            "why": (
                "The negative-control case. external:funding sits at -158000 legally and the"
                " three balances sum to zero. Any checker that reports a violation here is"
                " over-firing, and an over-firing checker is as useless as an inert one."
            ),
            "accounts": views,
            "allow_negative_by_address": allow_map,
            "postings": postings,
            "postingHashes": chain,
        },
    )

    # ---------------- corpus metadata ----------------
    write_json(
        OUT_ROOT / "_corpus.json",
        {
            "corpus_kind": "derived_from_source",
            "ac_0_2_eligible": False,
            "ac_0_2_reason": (
                "AC-0.2 and manifest section 2.6 require a corpus RECORDED from a running"
                " LedgerMind (the tampered half must come from a real POST /api/demo/tamper)."
                " This corpus was computed from the Java source instead, because the Docker"
                " daemon is down. It proves the tests; it does not prove the instrument."
            ),
            "derived_from": {
                "repo": "github.com/juanfranpaezz/ledgermind",
                "commit": "872505f03605e60168288ef056eed58794e9a1fc",
                "symbols": [
                    "DemoSupportController.reset",
                    "DemoSupportController.tamper",
                    "JournalChainer.entryHash",
                    "JournalChainer.verify",
                    "Account.availableBalance",
                    "LedgerController.AccountView",
                    "JournalCheckpointService.audit",
                    "ReconciliationService.reconcileDemoFeed",
                ],
            },
            "known_shape_gaps": [
                "AccountView exposes neither pendingDebits nor allowNegative, so neither the"
                " three-term balance formula nor the no-overdraft exemption is recomputable"
                " from REST alone.",
                "No REST endpoint and no MCP tool exposes posting_hash rows, so the hash"
                " chain is not independently recomputable without a read-only Postgres"
                " SELECT.",
                "Account version numbers are derived (one increment per UPDATE), not"
                " observed.",
                "createdAt is INVENTED and whole-second (17:00:01Z..17:00:05Z) while a"
                " real Postgres created_at carries microseconds. createdAt is part of the"
                " canonical string entryHash signs, so no entryHash here can ever equal a"
                " recorded one. Re-derive the chain from recorded rows; never compare hash"
                " literals across the two corpora. The derived-vs-recorded diff may"
                " normalise timestamp PRECISION only - never widen that into ignoring"
                " differences.",
                "Discrepancy ORDER in the reconciliation report follows two Java HashMaps"
                " and is not reproducible; compare discrepancies as a set.",
                "Checkpoint public key and signature are ephemeral runtime values and appear"
                " here as named placeholders, never as invented key material.",
            ],
            "regenerate_with": "py tools/derive_fixtures.py",
        },
    )

    files = sorted(p.relative_to(OUT_ROOT).as_posix() for p in OUT_ROOT.rglob("*.json"))
    print("wrote " + str(len(files)) + " files under " + str(OUT_ROOT))
    for f in files:
        print("  " + f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
