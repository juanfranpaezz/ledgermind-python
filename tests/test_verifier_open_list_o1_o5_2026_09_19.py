"""Regression guards for the Phase-1 verifier's OPEN LIST (fresh-context verification of
2026-09-17, findings O1 .. O5). Written RED against commit 88db264, then the fixes were applied.

Every block is PAIRED - a case that must FIRE and a case that must stay SILENT - on the
wiring the verifier really runs (``check_all`` / ``load_recorded`` / ``check_no_overdraft``),
so none of the fixes can be inert and none can be always-on.

O1  the N2 replay walks the journal in CHAIN order (``posting_hash.seq``), never in posting-id
    order. ``JournalChainer.chainPendingPostings`` chains by ABSENCE from ``posting_hash`` and
    its own comment names the case: a posting with a LOWER id can commit late and carry a
    HIGHER seq. Before the fix that snapshot produced a FALSE ``account_below_floor_during_replay``.
O2  ``load_recorded`` never guesses a floor: ``allowNegative`` null or absent -> ``None``,
    three-state, reported by name. Before the fix ``bool(None)`` silently became a floor of 0.
O3  a cryptographically INVALID checkpoint signature gates the verdict, exactly as
    ``JournalCheckpointService.audit()`` does
    (``tampered = !chain.intact() || !s.signatureValid() || !s.signedHeadStillInChain()``).
    ``UNVERIFIED-SIGNATURE`` (no backend, or a backend that failed) must NOT gate: "could not
    verify" is not evidence of tamper. Before the fix INVALID left the verdict at OK / exit 0.
O5  the replay applies TODAY's ``pendingDebits`` at every historical step because the corpus
    carries no reservation history; that is now DECLARED by name, never silent.

No network, no Docker, no LedgerMind, no model.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from ledger_verification_agent import mldsa_openssl_backend  # noqa: E402
from ledger_verification_agent.deterministic_verifier import (  # noqa: E402
    check_all,
    check_hash_chain_continuity,
    check_no_overdraft,
)
from ledger_verification_agent.journal_chain import (  # noqa: E402
    GENESIS,
    ChainLink,
    Posting,
    entry_hash,
)
from ledger_verification_agent.ledger_snapshot import (  # noqa: E402
    RECORDED_CORPUS,
    AccountRow,
    LedgerSnapshot,
    load_adversarial,
    load_recorded,
)
from ledger_verification_agent.mldsa_openssl_backend import OpensslCliMlDsaBackend  # noqa: E402
from ledger_verification_agent.verdict import (  # noqa: E402
    HASH_CHAIN_CONTINUITY,
    NO_DATA,
    NO_OVERDRAFT,
    OK,
    SIGNATURE_INVALID,
    SIGNATURE_UNVERIFIED,
    SIGNATURE_VERIFIED,
    VERDICT_OK,
    VERDICT_TAMPERED,
    VIOLATION,
)

REPLAY_DIP = "account_below_floor_during_replay"
SIGNATURE_GATE = "checkpoint_signature_invalid"


# --------------------------------------------------------------------------- #
# O1 - replay order is CHAIN order (seq), not posting-id order
# --------------------------------------------------------------------------- #
def _chain(postings_in_chain_order: tuple[Posting, ...]) -> tuple[ChainLink, ...]:
    """Real posting_hash rows for the given chain order, seq 1..n, hashes recomputed."""
    links = []
    prev = GENESIS
    for seq, posting in enumerate(postings_in_chain_order, start=1):
        digest = entry_hash(prev, posting)
        links.append(ChainLink(posting.id, seq, prev, digest))
        prev = digest
    return tuple(links)


# Posting id=1 DEBITS wallet:ana by 500 and committed LATE; posting id=2 CREDITS ana 500.
# In the journal the credit was chained first (seq=1) and the late debit second (seq=2),
# so the account never dipped. Walked by posting id, the debit comes first and ana "reaches -500".
DEBIT_ANA_LATE = Posting(1, 2, 1, 500, "ARS", "OUT-committed-late", "2026-01-01T00:00:02Z")
CREDIT_ANA_FIRST = Posting(2, 1, 2, 500, "ARS", "IN-chained-first", "2026-01-01T00:00:01Z")
TWO_ACCOUNTS = (
    AccountRow("external:funding", "ARS", 500, 500, 0, True, account_id=1),
    AccountRow("wallet:ana", "ARS", 500, 500, 0, False, account_id=2),
)


def _late_commit_snapshot(links: tuple[ChainLink, ...], subject: str) -> LedgerSnapshot:
    # postings are listed in id order, as a captured corpus lists them
    return LedgerSnapshot(
        subject=subject,
        postings=(DEBIT_ANA_LATE, CREDIT_ANA_FIRST),
        links=links,
        accounts=TWO_ACCOUNTS,
    )


def test_O1_FIXED_a_lower_id_that_carries_a_higher_seq_is_replayed_in_chain_order_and_stays_clean():
    """RED at 88db264: sorted by id, the late debit ran first and a false dip was reported."""
    snapshot = _late_commit_snapshot(_chain((CREDIT_ANA_FIRST, DEBIT_ANA_LATE)), "late-commit")
    result = check_all(snapshot)

    # the fixture is a coherent ledger: the chain recomputes intact over the TRUE seq order...
    chain = result.check(HASH_CHAIN_CONTINUITY)
    assert (chain.examined["intact"], chain.examined["chained_count"]) == (True, 2)
    # ...and the journal never dipped, so nothing may fire
    overdraft = result.check(NO_OVERDRAFT)
    assert overdraft.status == OK, [v.message for v in overdraft.violations]
    assert overdraft.examined["replay_steps"] == 2
    assert overdraft.examined["replay_order"] == "chain-seq"
    assert result.verdict == VERDICT_OK
    assert result.violation_count == 0


def test_O1_FIRES_when_the_chain_order_itself_dips():
    """The paired positive: same postings, same accounts, links in the order that DOES dip."""
    snapshot = _late_commit_snapshot(_chain((DEBIT_ANA_LATE, CREDIT_ANA_FIRST)), "chain-dips")
    overdraft = check_no_overdraft(snapshot)
    dips = [v for v in overdraft.violations if v.code == REPLAY_DIP]
    assert len(dips) == 1
    assert "wallet:ana" in dips[0].message
    assert "chain-seq" in dips[0].message  # the message names the order it really used
    assert any(c.ref == "posting:1" for c in dips[0].citations)
    assert overdraft.examined["replay_order"] == "chain-seq"


def test_O1_a_posting_not_yet_chained_is_replayed_AFTER_the_chained_ones_in_id_order_and_named():
    """The chainer is async: a posting can exist with no posting_hash row yet. It follows the
    chained ones in id order (the order findUnchainedOrderByIdAsc will hand it to the chainer)."""
    only_credit_chained = _chain((CREDIT_ANA_FIRST,))
    snapshot = _late_commit_snapshot(only_credit_chained, "one-unchained")
    overdraft = check_no_overdraft(snapshot)
    assert overdraft.violation_count == 0, [v.message for v in overdraft.violations]
    assert overdraft.examined["replay_steps"] == 2
    assert overdraft.examined["replay_order"].startswith("chain-seq, then 1 unchained")
    assert any("not yet chained" in note for note in overdraft.notes)


def test_O1_with_NO_chain_links_the_id_order_fallback_is_NAMED_and_still_fires():
    """Chain order is unknowable without posting_hash rows: fall back to id order, say so."""
    snapshot = _late_commit_snapshot((), "no-links")
    overdraft = check_no_overdraft(snapshot)
    assert overdraft.examined["replay_order"] == "posting-id (no chain links)"
    assert any("posting-id order" in note for note in overdraft.notes)
    assert any("posting-id order" in reason for reason in overdraft.examined["legs_skipped"])
    # on THIS input the old behaviour is the only one available, and it is disclosed
    assert REPLAY_DIP in [v.code for v in overdraft.violations]


def test_O1_SILENT_the_recorded_corpus_is_unchanged_because_there_id_order_equals_seq_order():
    overdraft = check_no_overdraft(load_recorded("clean"))
    assert overdraft.status == OK
    assert overdraft.examined["replay_order"] == "chain-seq"
    assert overdraft.examined["replay_steps"] == 5


# --------------------------------------------------------------------------- #
# O2 - load_recorded never guesses a floor
# --------------------------------------------------------------------------- #
def _clean_copy_with(tmp_path: Path, mutate) -> Path:
    """A private copy of the recorded clean half with the account rows edited by ``mutate``."""
    root = tmp_path / "recorded"
    shutil.copytree(RECORDED_CORPUS / "clean", root / "clean")
    bundle_path = root / "clean" / "postings_and_hashes.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    mutate(bundle["accounts"])
    bundle_path.write_text(json.dumps(bundle, indent=1), encoding="utf-8")
    return root


def test_O2_FIXED_a_null_allowNegative_is_undeclared_and_never_a_floor_of_zero(tmp_path):
    """RED at 88db264: bool(None) == False made external:funding (-158000) an 'overdraft'."""
    def null_funding(accounts):
        for row in accounts:
            if row["address"] == "external:funding":
                row["allowNegative"] = None

    snapshot = load_recorded("clean", root=_clean_copy_with(tmp_path, null_funding))
    funding = snapshot.account("external:funding")
    assert funding is not None
    assert funding.allow_negative is None
    assert funding.floor_is_declared is False
    assert funding.has_floor is False

    overdraft = check_no_overdraft(snapshot)
    assert "account_below_floor" not in [v.code for v in overdraft.violations]
    assert overdraft.status == OK  # the two DECLARED floors were tested and hold
    assert overdraft.examined["accounts_with_an_undeclared_floor"] == 1
    assert any("floor undeclared for external:funding" in note for note in overdraft.notes)


def test_O2_a_MISSING_allowNegative_key_is_undeclared_too_not_a_crash(tmp_path):
    def drop_key(accounts):
        for row in accounts:
            row.pop("allowNegative", None)

    snapshot = load_recorded("clean", root=_clean_copy_with(tmp_path, drop_key))
    assert [row.allow_negative for row in snapshot.accounts] == [None, None, None]


def test_O2_every_floor_null_is_NO_DATA_never_OK(tmp_path):
    def null_all(accounts):
        for row in accounts:
            row["allowNegative"] = None

    overdraft = check_no_overdraft(load_recorded("clean", root=_clean_copy_with(tmp_path, null_all)))
    assert overdraft.status == NO_DATA
    assert overdraft.violation_count == 0
    assert overdraft.examined["accounts_with_an_undeclared_floor"] == 3


def test_O2_SILENT_declared_floors_still_parse_as_real_booleans():
    """The paired negative: the fix must not turn a declared value into 'undeclared'."""
    rows = {row.address: row.allow_negative for row in load_recorded("clean").accounts}
    assert rows == {"external:funding": True, "wallet:ana": False, "wallet:beto": False}
    assert all(isinstance(value, bool) for value in rows.values())


# --------------------------------------------------------------------------- #
# O3 - an INVALID signature gates the verdict; UNVERIFIED does not
# --------------------------------------------------------------------------- #
class _Backend:
    def __init__(self, answer):
        self.name = "test-double"
        self._answer = answer

    def verify(self, message, signature, public_key_der):
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


def test_O3_FIXED_an_INVALID_signature_makes_the_verdict_TAMPERED_with_a_cited_violation():
    """RED at 88db264: verdict OK, signature INVALID, violations 0."""
    result = check_all(load_recorded("clean"), signature_backend=_Backend(False))
    assert result.signature.status == SIGNATURE_INVALID
    assert result.verdict == VERDICT_TAMPERED
    assert result.violation_count == 1
    gate = result.violations_of(HASH_CHAIN_CONTINUITY)
    assert [v.code for v in gate] == [SIGNATURE_GATE]
    assert gate[0].citations and gate[0].citations[0].kind == "checkpoint"
    assert "does NOT close" in gate[0].message
    assert result.check(HASH_CHAIN_CONTINUITY).status == VIOLATION


def test_O3_SILENT_UNVERIFIED_VERIFIED_and_absent_signatures_do_not_gate():
    clean = load_recorded("clean")
    unverified = check_all(clean, signature_backend=_Backend(RuntimeError("provider missing")))
    assert unverified.signature.status == SIGNATURE_UNVERIFIED
    assert unverified.verdict == VERDICT_OK
    assert SIGNATURE_GATE not in [v.code for v in unverified.violations]

    verified = check_all(clean, signature_backend=_Backend(True))
    assert verified.signature.status == SIGNATURE_VERIFIED
    assert verified.verdict == VERDICT_OK

    default = check_all(clean)  # no backend injected: whatever this machine resolves to
    assert default.verdict == VERDICT_OK

    no_checkpoint = check_all(load_adversarial("clean_must_not_fire"))
    assert no_checkpoint.verdict == VERDICT_OK


def test_O3_the_gate_runs_even_when_the_snapshot_carries_no_chain_links():
    """Java: tampered = !intact || !signatureValid || ... - an empty chain is intact, the
    signature alone decides. NO_DATA must not swallow the violation."""
    report = check_all(load_recorded("clean"), signature_backend=_Backend(False)).signature
    check = check_hash_chain_continuity(LedgerSnapshot(subject="no-links"), signature=report)
    assert check.status == VIOLATION
    assert [v.code for v in check.violations] == [SIGNATURE_GATE]
    # and without a signature report the empty chain is still NO_DATA, never a pass
    assert check_hash_chain_continuity(LedgerSnapshot(subject="no-links")).status == NO_DATA


def test_O3_the_REAL_openssl_backend_on_a_forged_signature_gates_the_verdict():
    """Deployment wiring: check_all -> verify_checkpoint -> the opt-in OpenSSL CLI backend."""
    clean = load_recorded("clean")
    backend = OpensslCliMlDsaBackend()
    if not backend.available():
        # no openssl >= 3.5 here: prove the gate on the injected double instead, never skip
        backend = _Backend(False)
        forged = clean
    else:
        raw = bytearray(base64.b64decode(clean.checkpoint.signature_base64))
        raw[0] ^= 0x01
        forged = dataclasses.replace(
            clean,
            checkpoint=dataclasses.replace(
                clean.checkpoint, signature_base64=base64.b64encode(bytes(raw)).decode("ascii")
            ),
        )
        untouched = check_all(clean, signature_backend=backend)
        assert untouched.signature.status == SIGNATURE_VERIFIED
        assert untouched.verdict == VERDICT_OK

    result = check_all(forged, signature_backend=backend)
    assert result.signature.status == SIGNATURE_INVALID
    assert result.verdict == VERDICT_TAMPERED
    assert SIGNATURE_GATE in [v.code for v in result.violations]


def test_O3_the_CLI_exit_code_follows_the_gated_verdict(monkeypatch, capsys):
    """`py -m tools.verify_report --mldsa-openssl` must exit 1 when the backend says INVALID."""
    from tools import verify_report

    class _InvalidSayingBackend:
        name = "openssl-cli"

        def available(self):
            return True

        def verify(self, message, signature, public_key_der):
            return False

    monkeypatch.setattr(mldsa_openssl_backend, "OpensslCliMlDsaBackend", _InvalidSayingBackend)
    code = verify_report.main(["--corpus", "recorded", "--half", "clean", "--mldsa-openssl"])
    out = capsys.readouterr().out
    assert code == verify_report.EXIT_TAMPERED
    assert "verdict: TAMPERED" in out
    assert "checkpoint signature: INVALID" in out
    assert SIGNATURE_GATE in out


# --------------------------------------------------------------------------- #
# O5 - today's pendingDebits projected onto every replay step is DECLARED
# --------------------------------------------------------------------------- #
def test_O5_FIRES_a_live_reservation_on_a_floored_account_is_declared_when_the_replay_ran():
    postings = (Posting(1, 1, 2, 500, "ARS", "IN-1", "2026-01-01T00:00:01Z"),)
    accounts = (
        AccountRow("external:funding", "ARS", 500, 0, 0, True, account_id=1),
        AccountRow("wallet:ana", "ARS", 0, 500, 100, False, account_id=2),  # 100 reserved today
    )
    overdraft = check_no_overdraft(
        LedgerSnapshot(subject="reserved", postings=postings, links=_chain(postings), accounts=accounts)
    )
    assert overdraft.examined["replay_steps"] == 1
    declared = [note for note in overdraft.notes if "every replay step" in note]
    assert len(declared) == 1
    assert "wallet:ana" in declared[0]
    assert "pendingDebits" in declared[0]


def test_O5_SILENT_no_reservation_no_note_on_the_recorded_corpus():
    for half in ("clean", "tampered"):
        overdraft = check_no_overdraft(load_recorded(half))
        assert overdraft.examined["replay_steps"] == 5
        assert not any("every replay step" in note for note in overdraft.notes)
