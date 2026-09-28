"""The DETERMINISTIC VERIFIER. Three invariants, no model, no network, no clock.

Manifest AC-1.1 .. AC-1.4. This module is the thing that produces the verdict in
``POST /ask``; the Phase-2 model may only narrate what this decided. Nothing here
imports an HTTP client, an LLM client, ``subprocess`` or ``socket``, and
``tests/test_verifier_read_only_reachability.py`` proves that mechanically rather
than by this sentence.

THE THREE CHECKS AND THE LEGS EACH ONE ACTUALLY RUNS

(a) ``money_conservation``
    L1  per transfer  - a posting's debit leg equals its credit leg. LedgerMind's
        schema cannot represent a difference (one ``amount`` column serves both
        legs), so a difference can only arrive from a corrupted feed or a hand-built
        payload - which is precisely why the checker must not assume the invariant.
    L2  per period    - the account counters the ledger reports equal the counters
        reconstructed by replaying every posting from a zero opening state.
        This is the gap the ledger's OWN hash chain does not cover: the chain
        protects postings, not counters, and balances are derived from counters.
    L3  per period    - system-wide, ``sum(postedCredits - postedDebits) == 0``.
    A leg whose input is missing is SKIPPED BY NAME (``legs_skipped``), never
    silently passed.

    NOT a leg, deliberately: "sum of all debit legs == sum of all credit legs over
    the postings". Computed from the same postings it is the algebraic identity
    ``sum(d_i - c_i) == sum(d_i) - sum(c_i)`` and can only ever return one answer -
    an inert check. The per-period statement gets its force from comparing the
    postings against an INDEPENDENT source (the ledger's counters), which is L2/L3.

(b) ``no_overdraft``
    N1  snapshot  - no account sits below its floor now. The floor is 0 for
        ``allowNegative == false`` and there is NO floor for ``allowNegative ==
        true``: ``external:funding`` legally sits at -158000, so a checker that
        flags every negative balance fires on the clean corpus and is useless.
        Balance is ``postedCredits - postedDebits - pendingDebits``
        (``Account.availableBalance``, the three-term form - dropping the pending
        term is mutation M1 in the Phase-0 record).
    N2  replay    - and no account was below its floor at ANY point: the postings
        are replayed in CHAIN order (``posting_hash.seq``, the order ``JournalChainer``
        assigned - never posting-id order, because a posting that commits late can
        carry a lower id and a higher seq) and the floor is tested after every one.
        Postings not yet chained follow, in id order; with no ``posting_hash`` rows at
        all the replay falls back to id order and says so by name (``_replay_order``).
        Today's ``pendingDebits`` is applied at every step and that is declared too.

(c) ``hash_chain_continuity``
    H1  every link recomputes (``journal_chain.verify_chain``, re-derived from
        ``JournalChainer.java``).
    H2  the signed checkpoint anchors the chain: its ``headHash`` is still the
        stored ``entryHash`` at its ``chainSeq`` and its ``signedMessage`` is the
        canonical string. (Java calls the first ``signedHeadStillInChain``. It stays
        TRUE on the tampered corpus - the tamper edits a posting, not the hash row -
        and that is correct: the break is H1's to report, not H2's.)
    H3  cross-oracle: when the corpus carries LedgerMind's own
        ``/api/journal/verify`` answer, this module's INDEPENDENT recomputation must
        agree with it on ``intact`` / ``chainedCount`` / ``brokenAtSeq``. A
        disagreement is a finding either way and is reported as a violation; the
        ledger's answer is never used as this module's answer.

    H4  a cryptographically INVALID checkpoint signature is a violation, exactly as
        ``JournalCheckpointService.audit()`` folds ``!signatureValid`` into ``tampered``.
        ONLY ``INVALID`` gates (a backend ran and the signature does not close under the
        key the checkpoint carries). ``UNVERIFIED-SIGNATURE`` never gates, because
        "could not verify" is not evidence of tamper.

The checkpoint SIGNATURE is still reported on its own plane (``SignatureReport``) so the
reader sees VERIFIED / INVALID / UNVERIFIED / absent separately from the chain; H4 is
the one place the two planes meet. See ``checkpoint_signature``.
"""

from __future__ import annotations

from typing import Iterable

from .checkpoint_signature import MlDsaBackend, verify_checkpoint
from .journal_chain import ChainResult, Posting, verify_chain
from .ledger_snapshot import AccountRow, LedgerSnapshot
from .verdict import (
    HASH_CHAIN_CONTINUITY,
    MONEY_CONSERVATION,
    NO_DATA,
    NO_OVERDRAFT,
    OK,
    SIGNATURE_INVALID,
    VIOLATION,
    CheckVerdict,
    Citation,
    LedgerVerdict,
    SignatureReport,
    Violation,
    decide,
)


def _status(violations: Iterable[Violation]) -> str:
    return VIOLATION if tuple(violations) else OK


def _account_citation(row: AccountRow, source: str, detail: str) -> Citation:
    return Citation(kind="account", ref="account:" + row.address, source=source, detail=detail)


def _replay_order(snapshot: LedgerSnapshot, skipped: list[str]) -> tuple[list[Posting], str]:
    """The order the N2 replay walks the journal: CHAIN order, never posting-id order.

    ``JournalChainer.chainPendingPostings`` chains by ABSENCE from ``posting_hash``, not by
    an id watermark, and its own comment names the consequence: a posting with a LOWER id
    that commits late carries a HIGHER seq. Walking by id would replay it too early and
    report a dip the journal never had (open-list finding O1, 2026-09-17). The rule:

    1. postings that have a chain link are walked by ``seq``; a duplicate seq (which a sound
       ``posting_hash`` cannot hold - the chainer assigns ``++seq``) breaks the tie on
       posting id, so the order is total and deterministic;
    2. postings with NO link yet (the chainer runs asynchronously) follow the chained ones,
       in id order - exactly the order ``findUnchainedOrderByIdAsc`` will hand them to the
       chainer - and that is DISCLOSED by name;
    3. with no ``posting_hash`` rows at all, chain order is unknowable: fall back to id order
       and SAY SO in ``legs_skipped``.
    """
    if not snapshot.links:
        skipped.append(
            "N2 replay: this snapshot carries no posting_hash rows, so chain order is unknown and "
            "the postings were replayed in posting-id order. A posting that committed late with a "
            "lower id would be replayed out of order here."
        )
        return sorted(snapshot.postings, key=lambda p: p.id), "posting-id (no chain links)"
    seq_of: dict[int, int] = {}
    for link in sorted(snapshot.links, key=lambda item: (item.seq, item.posting_id)):
        seq_of.setdefault(link.posting_id, link.seq)
    chained = sorted(
        (p for p in snapshot.postings if p.id in seq_of), key=lambda p: (seq_of[p.id], p.id)
    )
    unchained = sorted((p for p in snapshot.postings if p.id not in seq_of), key=lambda p: p.id)
    if not unchained:
        return chained, "chain-seq"
    skipped.append(
        "N2 replay: " + str(len(unchained)) + " posting(s) not yet chained (id="
        + ",".join(str(p.id) for p in unchained) + ") were replayed after the chained ones, in "
        "id order - the order the chainer will assign them (findUnchainedOrderByIdAsc)"
    )
    return chained + unchained, "chain-seq, then " + str(len(unchained)) + " unchained by posting id"


# --------------------------------------------------------------------------- #
# (a) money conservation
# --------------------------------------------------------------------------- #
def check_money_conservation(snapshot: LedgerSnapshot) -> CheckVerdict:
    violations: list[Violation] = []
    skipped: list[str] = []
    postings_source = snapshot.source_of("postings")
    accounts_source = snapshot.source_of("accounts")

    if not snapshot.postings and not snapshot.accounts:
        return CheckVerdict(
            check=MONEY_CONSERVATION,
            status=NO_DATA,
            examined={"postings": 0, "accounts": 0},
            notes=("no postings and no accounts in this snapshot: nothing to conserve",),
        )

    # --- L1: per transfer -------------------------------------------------- #
    debit_total = 0
    credit_total = 0
    for posting in snapshot.postings:
        debit_total += posting.debit_leg
        credit_total += posting.credit_leg
        if posting.debit_leg != posting.credit_leg:
            violations.append(
                Violation(
                    check=MONEY_CONSERVATION,
                    code="entry_legs_differ",
                    message=(
                        "posting id=" + str(posting.id) + " (" + posting.idempotency_key
                        + ") debits " + str(posting.debit_leg) + " but credits "
                        + str(posting.credit_leg) + ": "
                        + str(posting.debit_leg - posting.credit_leg) + " "
                        + posting.asset + " is created or destroyed by this entry"
                    ),
                    citations=(
                        Citation(
                            kind="posting",
                            ref="posting:" + str(posting.id),
                            source=postings_source,
                            detail="debit_account=" + str(posting.debit_account_id)
                            + " credit_account=" + str(posting.credit_account_id)
                            + " amount=" + str(posting.amount),
                        ),
                    ),
                )
            )
    if not snapshot.postings:
        skipped.append("L1 per-transfer: the snapshot carries no postings")

    # --- L2: per period, counters vs a replay of the postings --------------- #
    by_id = {row.account_id: row for row in snapshot.accounts if row.account_id is not None}
    if snapshot.postings and by_id and len(by_id) == len(snapshot.accounts):
        replayed_debits = {account_id: 0 for account_id in by_id}
        replayed_credits = {account_id: 0 for account_id in by_id}
        unmapped: set[int] = set()
        for posting in snapshot.postings:
            if posting.debit_account_id in replayed_debits:
                replayed_debits[posting.debit_account_id] += posting.debit_leg
            else:
                unmapped.add(posting.debit_account_id)
            if posting.credit_account_id in replayed_credits:
                replayed_credits[posting.credit_account_id] += posting.credit_leg
            else:
                unmapped.add(posting.credit_account_id)
        if unmapped:
            skipped.append(
                "L2 counters-vs-replay: postings reference account ids not in the snapshot: "
                + ",".join(str(i) for i in sorted(unmapped))
            )
        else:
            for account_id, row in sorted(by_id.items()):
                if row.posted_debits != replayed_debits[account_id] or (
                    row.posted_credits != replayed_credits[account_id]
                ):
                    violations.append(
                        Violation(
                            check=MONEY_CONSERVATION,
                            code="counters_disagree_with_postings",
                            message=(
                                "account " + row.address + " reports postedDebits="
                                + str(row.posted_debits) + "/postedCredits="
                                + str(row.posted_credits) + " but replaying every posting gives "
                                + str(replayed_debits[account_id]) + "/"
                                + str(replayed_credits[account_id])
                                + ". Balances are DERIVED from counters and the hash chain protects "
                                "postings, not counters, so this drift is invisible to the ledger "
                                "itself."
                            ),
                            citations=(
                                _account_citation(
                                    row,
                                    accounts_source,
                                    "replayed_debits=" + str(replayed_debits[account_id])
                                    + " replayed_credits=" + str(replayed_credits[account_id]),
                                ),
                                Citation(
                                    kind="corpus",
                                    ref="postings:replay",
                                    source=postings_source,
                                    detail="replayed " + str(len(snapshot.postings)) + " postings "
                                    "from a zero opening state",
                                ),
                            ),
                        )
                    )
    else:
        reason = "L2 counters-vs-replay: "
        if not snapshot.postings:
            reason += "no postings in this snapshot"
        elif not snapshot.accounts:
            reason += "no account rows in this snapshot"
        else:
            reason += (
                "the account rows carry no numeric id, so postings (which reference accounts by "
                "id) cannot be mapped onto them without guessing"
            )
        skipped.append(reason)

    # --- L3: per period, the whole system nets to zero ---------------------- #
    if snapshot.accounts:
        net = sum(row.posted_credits - row.posted_debits for row in snapshot.accounts)
        if net != 0:
            violations.append(
                Violation(
                    check=MONEY_CONSERVATION,
                    code="posted_counters_do_not_net_to_zero",
                    message=(
                        "across all " + str(len(snapshot.accounts)) + " accounts, "
                        "sum(postedCredits - postedDebits) = " + str(net)
                        + ", not 0: the period does not conserve money"
                    ),
                    citations=tuple(
                        _account_citation(
                            row,
                            accounts_source,
                            "postedCredits-postedDebits="
                            + str(row.posted_credits - row.posted_debits),
                        )
                        for row in snapshot.accounts
                    ),
                )
            )
    else:
        skipped.append("L3 system-wide net: no account rows in this snapshot")

    citations = (
        Citation(
            kind="corpus",
            ref="postings:all",
            source=postings_source,
            detail=str(len(snapshot.postings)) + " postings, debit legs " + str(debit_total)
            + ", credit legs " + str(credit_total),
        ),
    )
    return CheckVerdict(
        check=MONEY_CONSERVATION,
        status=_status(violations),
        violations=tuple(violations),
        examined={
            "postings": len(snapshot.postings),
            "accounts": len(snapshot.accounts),
            "debit_legs_total": debit_total,
            "credit_legs_total": credit_total,
            "legs_skipped": skipped,
        },
        citations=citations,
        notes=tuple(skipped),
    )


# --------------------------------------------------------------------------- #
# (b) no overdraft
# --------------------------------------------------------------------------- #
def check_no_overdraft(snapshot: LedgerSnapshot) -> CheckVerdict:
    if not snapshot.accounts:
        return CheckVerdict(
            check=NO_OVERDRAFT,
            status=NO_DATA,
            examined={"accounts": 0},
            notes=("no account rows in this snapshot: no balance to floor-test",),
        )

    violations: list[Violation] = []
    skipped: list[str] = []
    accounts_source = snapshot.source_of("accounts")
    postings_source = snapshot.source_of("postings")

    undeclared = [row.address for row in snapshot.accounts if not row.floor_is_declared]
    if undeclared:
        skipped.append(
            "floor undeclared for " + ",".join(undeclared) + ": this corpus does not carry "
            "allowNegative for them, and assuming false would flag a legally-negative account "
            "(external:funding sits at -158000 by design). They were NOT floor-tested."
        )
    if len(undeclared) == len(snapshot.accounts):
        return CheckVerdict(
            check=NO_OVERDRAFT,
            status=NO_DATA,
            examined={
                "accounts": len(snapshot.accounts),
                "accounts_with_a_floor": 0,
                "accounts_with_an_undeclared_floor": len(undeclared),
                "replay_steps": 0,
                "legs_skipped": skipped,
            },
            notes=tuple(skipped),
        )

    # --- N1: the snapshot as it stands now ---------------------------------- #
    for row in snapshot.accounts:
        if not row.has_floor:
            continue
        if row.available_balance < 0:
            violations.append(
                Violation(
                    check=NO_OVERDRAFT,
                    code="account_below_floor",
                    message=(
                        "account " + row.address + " has allowNegative=false and an available "
                        "balance of " + str(row.available_balance) + " (postedCredits "
                        + str(row.posted_credits) + " - postedDebits " + str(row.posted_debits)
                        + " - pendingDebits " + str(row.pending_debits) + "), below its floor of 0"
                    ),
                    citations=(
                        _account_citation(
                            row,
                            accounts_source,
                            "available=" + str(row.available_balance)
                            + " allowNegative=false"
                            + (" pendingDebits ASSUMED 0" if row.pending_debits_assumed else ""),
                        ),
                    ),
                )
            )

    # --- N2: and at every point of the replay -------------------------------- #
    by_id = {row.account_id: row for row in snapshot.accounts if row.account_id is not None}
    replay_steps = 0
    replay_order = "not run"
    if snapshot.postings and by_id and len(by_id) == len(snapshot.accounts):
        running = {account_id: 0 for account_id in by_id}
        flagged: set[tuple[int, int]] = set()
        ordered, replay_order = _replay_order(snapshot, skipped)
        for posting in ordered:
            if posting.debit_account_id not in running or posting.credit_account_id not in running:
                skipped.append(
                    "N2 replay: posting id=" + str(posting.id) + " references an account id "
                    "that is not in the snapshot"
                )
                break
            running[posting.debit_account_id] -= posting.debit_leg
            running[posting.credit_account_id] += posting.credit_leg
            replay_steps += 1
            for account_id in (posting.debit_account_id, posting.credit_account_id):
                row = by_id[account_id]
                if not row.has_floor:
                    continue
                available = running[account_id] - row.pending_debits
                if available < 0 and (account_id, posting.id) not in flagged:
                    flagged.add((account_id, posting.id))
                    violations.append(
                        Violation(
                            check=NO_OVERDRAFT,
                            code="account_below_floor_during_replay",
                            message=(
                                "replaying the journal in " + replay_order + " order, account "
                                + row.address
                                + " (allowNegative=false) reaches " + str(available)
                                + " immediately after posting id=" + str(posting.id) + " ("
                                + posting.idempotency_key + "), below its floor of 0. "
                                "The end-state balance can be legal while an intermediate one is not."
                            ),
                            citations=(
                                _account_citation(
                                    row, accounts_source, "available_at_step=" + str(available)
                                ),
                                Citation(
                                    kind="posting",
                                    ref="posting:" + str(posting.id),
                                    source=postings_source,
                                    detail="amount=" + str(posting.amount) + " debit_account="
                                    + str(posting.debit_account_id) + " credit_account="
                                    + str(posting.credit_account_id),
                                ),
                            ),
                        )
                    )
        # O5 (2026-09-17): the corpus carries no reservation history, so the replay can only
        # apply TODAY's pendingDebits at every step. Declared by name, never silent.
        reserved = sorted(
            row.address for row in by_id.values() if row.has_floor and row.pending_debits != 0
        )
        if reserved and replay_steps:
            skipped.append(
                "N2 replay: pendingDebits as it stands NOW was applied at every replay step for "
                + ",".join(reserved) + ". The corpus carries no reservation history, so each "
                "intermediate available balance is today's reservation projected onto the past, "
                "not the reservation that existed at that step."
            )
    else:
        if not snapshot.postings:
            skipped.append("N2 replay: no postings in this snapshot; only the current state was floor-tested")
        else:
            skipped.append(
                "N2 replay: the account rows carry no numeric id, so postings cannot be mapped "
                "onto them without guessing; only the current state was floor-tested"
            )

    assumed = [row.address for row in snapshot.accounts if row.pending_debits_assumed]
    if assumed:
        skipped.append(
            "pendingDebits was not in the corpus for " + ",".join(assumed)
            + " and was taken as 0: the three-term balance is degraded to two terms for them"
        )

    citations = tuple(
        _account_citation(
            row,
            accounts_source,
            "available=" + str(row.available_balance) + " floor=" + row.floor_description,
        )
        for row in snapshot.accounts
    )
    return CheckVerdict(
        check=NO_OVERDRAFT,
        status=_status(violations),
        violations=tuple(violations),
        examined={
            "accounts": len(snapshot.accounts),
            "accounts_with_a_floor": sum(1 for row in snapshot.accounts if row.has_floor),
            "accounts_with_an_undeclared_floor": len(undeclared),
            "replay_steps": replay_steps,
            "replay_order": replay_order,
            "legs_skipped": skipped,
        },
        citations=citations,
        notes=tuple(skipped),
    )


# --------------------------------------------------------------------------- #
# (c) hash-chain continuity
# --------------------------------------------------------------------------- #
def check_hash_chain_continuity(
    snapshot: LedgerSnapshot, signature: SignatureReport | None = None
) -> CheckVerdict:
    violations: list[Violation] = []
    notes: list[str] = []

    # --- H4: a cryptographically INVALID checkpoint signature gates the verdict ------ #
    # JournalCheckpointService.audit():
    #     tampered = !chain.intact() || !s.signatureValid() || !s.signedHeadStillInChain()
    # ONLY the INVALID status counts here: a backend actually ran and the signature does not
    # close under the key the checkpoint carries. UNVERIFIED-SIGNATURE (no backend, or a
    # backend that failed structurally) is "could not verify", which is not evidence of
    # tamper and never becomes a violation. (Open-list finding O3, 2026-09-17.)
    if signature is not None and signature.status == SIGNATURE_INVALID:
        # WHICH term of signatureValid failed. The Java folds algorithmMatches into the same
        # boolean (JournalCheckpointService.java:149-150), so both arrive here under one code -
        # but a rewritten algorithm column is a different attack from a rewritten signature and
        # the operator must be told which one this is.
        structural = dict(signature.structural or {})
        algorithm_is_the_cause = (
            structural.get("key_algorithm_oid") is not None
            and structural.get("key_algorithm_matches_declared") is False
        )
        cause = (
            " CAUSE: the DECLARED algorithm (" + str(structural.get("declared_algorithm"))
            + ") disagrees with the key's own OID (" + str(structural.get("key_algorithm_oid"))
            + "): the algorithm column was rewritten while signature and key stayed intact."
            if algorithm_is_the_cause
            else ""
        )
        violations.append(
            Violation(
                check=HASH_CHAIN_CONTINUITY,
                code="checkpoint_signature_invalid",
                message=(
                    "the checkpoint signature at chainSeq=" + str(signature.chain_seq)
                    + " does NOT close under the key the checkpoint carries (backend "
                    + signature.backend + "): the signed head, the signature, the key row or "
                    "the declared algorithm was rewritten. LedgerMind's own audit() reports "
                    "this as tampered, and so does this verifier." + cause
                ),
                citations=signature.citations
                or (
                    Citation(
                        kind="checkpoint",
                        ref="checkpoint:chainSeq=" + str(signature.chain_seq),
                        source=snapshot.source_of("journal_checkpoint"),
                        detail="status=" + signature.status,
                    ),
                ),
            )
        )

    if not snapshot.links:
        return CheckVerdict(
            check=HASH_CHAIN_CONTINUITY,
            status=VIOLATION if violations else NO_DATA,
            violations=tuple(violations),
            examined={"links": 0},
            notes=(
                "no posting_hash rows in this snapshot. They have no REST and no MCP surface, so "
                "they only exist in a corpus captured through a read-only DB session.",
            ),
        )

    links_source = snapshot.source_of("posting_hashes")
    result: ChainResult = verify_chain(snapshot.postings_by_id, snapshot.links)

    # --- H1 ------------------------------------------------------------------ #
    if not result.intact:
        violations.append(
            Violation(
                check=HASH_CHAIN_CONTINUITY,
                code=result.broken_reason or "chain_broken",
                message=(
                    "the hash chain breaks at seq=" + str(result.broken_at_seq) + " after "
                    + str(result.chained_count) + " intact links: " + result.broken_detail
                ),
                citations=(
                    Citation(
                        kind="chain_link",
                        ref="chain_link:seq=" + str(result.broken_at_seq),
                        source=links_source,
                        detail=result.broken_detail,
                    ),
                ),
            )
        )

    # --- H2: the signed checkpoint anchors the chain -------------------------- #
    checkpoint = snapshot.checkpoint
    if checkpoint is not None:
        checkpoint_source = snapshot.source_of("journal_checkpoint")
        anchored = None
        for link in snapshot.links:
            if link.seq == checkpoint.chain_seq:
                anchored = link
                break
        if anchored is None:
            violations.append(
                Violation(
                    check=HASH_CHAIN_CONTINUITY,
                    code="signed_link_absent",
                    message=(
                        "the checkpoint signs chainSeq=" + str(checkpoint.chain_seq)
                        + " but there is no chain link at that seq: the signed head was deleted"
                    ),
                    citations=(
                        Citation(
                            kind="checkpoint",
                            ref="checkpoint:chainSeq=" + str(checkpoint.chain_seq),
                            source=checkpoint_source,
                            detail="headHash=" + checkpoint.head_hash,
                        ),
                    ),
                )
            )
        elif anchored.entry_hash != checkpoint.head_hash:
            violations.append(
                Violation(
                    check=HASH_CHAIN_CONTINUITY,
                    code="signed_head_rewritten",
                    message=(
                        "the checkpoint signs headHash=" + checkpoint.head_hash + " at seq="
                        + str(checkpoint.chain_seq) + " but the chain link at that seq now stores "
                        + anchored.entry_hash + ": the hash row itself was rewritten"
                    ),
                    citations=(
                        Citation(
                            kind="checkpoint",
                            ref="checkpoint:chainSeq=" + str(checkpoint.chain_seq),
                            source=checkpoint_source,
                            detail="headHash=" + checkpoint.head_hash,
                        ),
                        Citation(
                            kind="chain_link",
                            ref="chain_link:seq=" + str(anchored.seq),
                            source=links_source,
                            detail="entryHash=" + anchored.entry_hash,
                        ),
                    ),
                )
            )
        else:
            notes.append(
                "the signed head (seq=" + str(checkpoint.chain_seq) + ") is still present with its "
                "signed entryHash"
            )
    else:
        notes.append("no signed checkpoint in this snapshot: the chain head is not anchored in time")

    # --- H3: cross-oracle against the ledger's own answer --------------------- #
    reported = snapshot.reported_verify
    if reported is not None:
        reported_intact = bool(reported.get("intact"))
        reported_count = reported.get("chainedCount")
        reported_seq = reported.get("brokenAtSeq")
        mine = (result.intact, result.chained_count, result.broken_at_seq)
        theirs = (
            reported_intact,
            None if reported_count is None else int(reported_count),
            None if reported_seq is None else int(reported_seq),
        )
        if mine != theirs:
            violations.append(
                Violation(
                    check=HASH_CHAIN_CONTINUITY,
                    code="ledger_self_report_disagrees",
                    message=(
                        "this module's independent recomputation says "
                        "(intact=" + str(mine[0]) + ", chainedCount=" + str(mine[1])
                        + ", brokenAtSeq=" + str(mine[2]) + ") while LedgerMind's own "
                        "/api/journal/verify says (intact=" + str(theirs[0]) + ", chainedCount="
                        + str(theirs[1]) + ", brokenAtSeq=" + str(theirs[2])
                        + "). One of the two is wrong and neither may be assumed."
                    ),
                    citations=(
                        Citation(
                            kind="corpus",
                            ref="journal_verify",
                            source=snapshot.source_of("journal_verify"),
                            detail="the ledger's own answer",
                        ),
                        Citation(
                            kind="chain_link",
                            ref="chain_link:recomputed",
                            source=links_source,
                            detail="independent SHA-256 recomputation of every link",
                        ),
                    ),
                )
            )
        else:
            notes.append(
                "cross-oracle: the ledger's own /api/journal/verify agrees with this independent "
                "recomputation on intact/chainedCount/brokenAtSeq"
            )
    else:
        notes.append("no /api/journal/verify answer in this snapshot: the cross-oracle leg did not run")

    citations = (
        Citation(
            kind="chain_link",
            ref="chain_link:seq=1.." + str(max(link.seq for link in snapshot.links)),
            source=links_source,
            detail=str(result.chained_count) + " of " + str(len(snapshot.links))
            + " links recomputed intact from GENESIS",
        ),
    )
    return CheckVerdict(
        check=HASH_CHAIN_CONTINUITY,
        status=_status(violations),
        violations=tuple(violations),
        examined={
            "links": len(snapshot.links),
            "postings": len(snapshot.postings),
            "intact": result.intact,
            "chained_count": result.chained_count,
            "broken_at_seq": result.broken_at_seq,
            "checkpoint_present": checkpoint is not None,
        },
        citations=citations,
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------- #
# the whole verdict
# --------------------------------------------------------------------------- #
def check_all(
    snapshot: LedgerSnapshot,
    signature_backend: MlDsaBackend | None = None,
) -> LedgerVerdict:
    """Run the three checks and produce the object the Phase-2 endpoint returns.

    The signature plane is verified FIRST because an INVALID result is an input to the
    chain check (leg H4): the verdict must gate on it, as the Java ``audit()`` does.
    """
    signature = verify_checkpoint(
        snapshot.checkpoint,
        backend=signature_backend,
        source=snapshot.source_of("journal_checkpoint"),
    )
    checks = (
        check_money_conservation(snapshot),
        check_no_overdraft(snapshot),
        check_hash_chain_continuity(snapshot, signature=signature),
    )
    return LedgerVerdict(
        verdict=decide(checks),
        subject=snapshot.subject,
        checks=checks,
        signature=signature,
    )
