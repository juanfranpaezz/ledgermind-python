"""Regression guards for items 1-7 of the REVISED OPEN LIST (fresh-context verification of
2026-09-20, section 8). Written RED against commit 996de69, then the fixes were applied.

Every block is PAIRED - a case that must FIRE and a case that must stay SILENT - on the
wiring the verifier really runs (``load_recorded`` / ``load_adversarial`` / ``check_all``),
so no fix here can be inert and none can be always-on.

item 1+2  ``allowNegative`` is THREE-STATE in BOTH loaders, and a value that is not a JSON
          boolean is a NAMED REFUSAL, never a coercion. The live column is
          ``allow_negative BOOLEAN NOT NULL`` (V1__create_ledger_core.sql:39) read into a
          Java primitive ``boolean`` (Account.java:48-49), so a string/number/list is not a
          ledger state at all - it is a corrupt or rewritten snapshot, and guessing from it
          is how a checker gets silently disarmed (the JSON string "false" used to delete
          the account's overdraft floor while the loader still reported floor_is_declared).
item 3    the README correction block states that the equivalence with ``audit()`` is PARTIAL
          and names the attacker H4 cannot catch, WITHOUT weakening the disclosure already in
          docs/evidence/phase1-verifier.md.
item 4    an algorithm/OID disagreement reaches the VERDICT. LedgerMind folds it into
          ``signatureValid`` (JournalCheckpointService.java:149-150), so a checker that only
          prints it is strictly weaker than the system it verifies.
item 5    the DEBIT leg of the L2 counters-vs-replay comparison has a fixture of its own.
item 6    README's test count is re-derived from a real collection, not copied.
item 7    (a claim-sweep allowlist rule) is not part of the public repository: that tool
          scanned private project notes and was removed from this export.
"""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ledger_verification_agent import checkpoint_signature
from ledger_verification_agent.checkpoint_signature import verify_checkpoint
from ledger_verification_agent.deterministic_verifier import check_all, check_money_conservation
from ledger_verification_agent.ledger_snapshot import (
    ADVERSARIAL_DIR,
    RECORDED_CORPUS,
    load_adversarial,
    load_recorded,
)
from ledger_verification_agent.mldsa_openssl_backend import OpensslCliMlDsaBackend
from ledger_verification_agent.verdict import (
    OK,
    SIGNATURE_INVALID,
    SIGNATURE_VERIFIED,
    VERDICT_OK,
    VERDICT_TAMPERED,
    VIOLATION,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
EVIDENCE_DOC = REPO_ROOT / "docs" / "evidence" / "phase1-verifier.md"
SIGNATURE_GATE = "checkpoint_signature_invalid"
COUNTER_DRIFT = "counters_disagree_with_postings"


# --------------------------------------------------------------------------- #
# items 1 + 2 - allowNegative in BOTH loaders
# --------------------------------------------------------------------------- #
def _recorded_corpus(tmp_path: Path, allow_negative_value, present: bool = True) -> Path:
    """A minimal RECORDED corpus on disk, shaped exactly like the shipped one."""
    half = tmp_path / "clean"
    half.mkdir(parents=True, exist_ok=True)
    wallet = {
        "id": 2,
        "address": "wallet:ana",
        "asset": "ARS",
        "postedDebits": 500,
        "postedCredits": 0,
        "pendingDebits": 0,
    }
    if present:
        wallet["allowNegative"] = allow_negative_value
    bundle = {
        "accounts": [
            {
                "id": 1,
                "address": "external:funding",
                "asset": "ARS",
                "postedDebits": 500,
                "postedCredits": 0,
                "pendingDebits": 0,
                "allowNegative": True,
            },
            wallet,
        ],
        "postings": [],
        "postingHashes": [],
    }
    (half / "postings_and_hashes.json").write_text(json.dumps(bundle), encoding="utf-8")
    return tmp_path


def _adversarial_corpus(tmp_path: Path, allow_negative_value, present: bool = True) -> Path:
    """A minimal ADVERSARIAL/derived case on disk, shaped exactly like the shipped ones."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    payload = {
        "case": "tmp_case",
        "expected_violation": None,
        "why": "loader probe",
        "accounts": {
            "wallet:ana": {
                "address": "wallet:ana",
                "asset": "ARS",
                "balance": -500,
                "postedDebits": 500,
                "postedCredits": 0,
            }
        },
        "account_id_by_address": {"wallet:ana": 2},
        "postings": [],
    }
    if present:
        payload["allow_negative_by_address"] = {"wallet:ana": allow_negative_value}
    (tmp_path / "tmp_case.json").write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


NON_BOOLEANS = ["false", "true", "", 0, 1, [], {}, "no"]


@pytest.mark.parametrize("value", NON_BOOLEANS, ids=repr)
def test_item2_FIRES_a_non_boolean_allowNegative_is_REFUSED_BY_NAME_in_load_recorded(
    tmp_path, value
):
    """RED at 996de69: bool(value) silently invented a floor (or deleted one) and the loader
    still reported floor_is_declared=True."""
    from ledger_verification_agent.ledger_snapshot import MalformedSnapshotError

    root = _recorded_corpus(tmp_path, value)
    with pytest.raises(MalformedSnapshotError) as excinfo:
        load_recorded("clean", root=root)
    message = str(excinfo.value)
    assert "wallet:ana" in message, message
    assert "allowNegative" in message, message
    assert type(value).__name__ in message, message


@pytest.mark.parametrize("value", NON_BOOLEANS, ids=repr)
def test_item2_FIRES_a_non_boolean_allowNegative_is_REFUSED_BY_NAME_in_load_adversarial(
    tmp_path, value
):
    """The SECOND loader, the one the O2 fix never reached. Same refusal, same wording."""
    from ledger_verification_agent.ledger_snapshot import MalformedSnapshotError

    root = _adversarial_corpus(tmp_path, value)
    with pytest.raises(MalformedSnapshotError) as excinfo:
        load_adversarial("tmp_case", root=root)
    message = str(excinfo.value)
    assert "wallet:ana" in message, message
    assert type(value).__name__ in message, message


def test_item1_FIXED_a_JSON_null_is_UNDECLARED_in_load_adversarial_not_a_floor_of_zero(tmp_path):
    """RED at 996de69: ledger_snapshot.py:299 did bool(None) -> False -> an invented floor of 0
    on the live verdict path `py -m tools.verify_report --corpus adversarial --case X`."""
    snapshot = load_adversarial("tmp_case", root=_adversarial_corpus(tmp_path, None))
    row = snapshot.account("wallet:ana")
    assert row.allow_negative is None
    assert row.floor_is_declared is False
    assert row.has_floor is False, "an undeclared floor must never be guessed into a floor of 0"


def test_item1_SILENT_real_booleans_and_absent_keys_are_unchanged_in_BOTH_loaders(tmp_path):
    """The negative control: the refusal must not touch a well-formed corpus."""
    true_root = _recorded_corpus(tmp_path / "t", True)
    assert load_recorded("clean", root=true_root).account("wallet:ana").allow_negative is True
    false_root = _recorded_corpus(tmp_path / "f", False)
    row = load_recorded("clean", root=false_root).account("wallet:ana")
    assert (row.allow_negative, row.has_floor, row.floor_is_declared) == (False, True, True)

    adv_true = load_adversarial("tmp_case", root=_adversarial_corpus(tmp_path / "at", True))
    assert adv_true.account("wallet:ana").allow_negative is True
    adv_absent = load_adversarial(
        "tmp_case", root=_adversarial_corpus(tmp_path / "aa", None, present=False)
    )
    assert adv_absent.account("wallet:ana").allow_negative is None
    missing_key = load_recorded("clean", root=_recorded_corpus(tmp_path / "mk", None, present=False))
    assert missing_key.account("wallet:ana").allow_negative is None


def test_item1_SILENT_every_shipped_corpus_still_loads_and_keeps_its_verdict():
    """The whole point of a refusal is that it refuses NOTHING that is well-formed."""
    assert check_all(load_recorded("clean")).verdict == VERDICT_OK
    assert check_all(load_recorded("tampered")).verdict == VERDICT_TAMPERED
    for path in sorted(ADVERSARIAL_DIR.glob("*.json")):
        load_adversarial(path.stem)  # must not raise


def test_item2_the_shipped_CLI_fails_CLOSED_on_a_coerced_allowNegative(
    tmp_path, capsys, monkeypatch
):
    """Deployment wiring, not a unit: `py -m tools.verify_report --corpus adversarial` is a
    live verdict path. The operator must get a named refusal and a non-zero exit, never a
    verdict computed off a guessed floor."""
    from ledger_verification_agent import ledger_snapshot
    from tools import verify_report

    root = _adversarial_corpus(tmp_path, "false")
    assert ledger_snapshot.ADVERSARIAL_DIR.exists()  # the flag, not a patched global
    exit_code = verify_report.main(
        ["--corpus", "adversarial", "--case", "tmp_case", "--corpus-root", str(root)]
    )
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert exit_code == verify_report.EXIT_TOOL_ERROR, out
    assert "REFUSED" in out, out
    assert "wallet:ana" in out, out


# --------------------------------------------------------------------------- #
# item 4 - the algorithm column must reach the verdict, as the Java fold does
# --------------------------------------------------------------------------- #
class _AlwaysValidBackend:
    """The attacker's own situation: the ML-DSA signature really does close over the message
    (key and signature untouched) and ONLY the algorithm label was rewritten."""

    name = "stub-always-valid"

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return True


def _relabelled(half: str, algorithm: str):
    snapshot = load_recorded(half)
    return dataclasses.replace(
        snapshot,
        checkpoint=dataclasses.replace(snapshot.checkpoint, algorithm=algorithm),
    )


def test_item4_FIRES_an_algorithm_column_rewrite_gates_the_verdict():
    """RED at 996de69: verdict OK, violations 0 - the Python printed the disagreement as a
    structural note and never let it reach the verdict, while
    JournalCheckpointService.signalsFor (lines 149-150) computes
    `signatureValid = algorithmMatches && signer.verify(...)`, i.e. audit() says TAMPERED."""
    snapshot = _relabelled("clean", "Ed25519")
    result = check_all(snapshot, signature_backend=_AlwaysValidBackend())

    assert result.signature.status == SIGNATURE_INVALID, result.signature.reason
    assert result.verdict == VERDICT_TAMPERED
    codes = [v.code for v in result.violations]
    assert SIGNATURE_GATE in codes, codes
    named = [v.message for v in result.violations if v.code == SIGNATURE_GATE]
    assert any("algorithm" in m for m in named), named


def test_item4_SILENT_the_untouched_checkpoint_still_verifies_and_stays_OK():
    """The paired must-not-fire: same wiring, correct label -> VERIFIED and a clean verdict."""
    result = check_all(load_recorded("clean"), signature_backend=_AlwaysValidBackend())
    assert result.signature.status == SIGNATURE_VERIFIED
    assert result.verdict == VERDICT_OK
    assert result.violation_count == 0


def test_item4_SILENT_the_structural_plane_still_agrees_on_the_untouched_checkpoint():
    """Over-firing guard: the fold must not relabel a sound checkpoint."""
    snapshot = load_recorded("clean")
    report = verify_checkpoint(snapshot.checkpoint, backend=_AlwaysValidBackend())
    assert report.status == SIGNATURE_VERIFIED
    assert report.structural["key_algorithm_matches_declared"] is True


def test_item4_the_REAL_openssl_backend_reaches_the_same_verdict_on_a_relabelled_checkpoint():
    """The same case on the shipped opt-in backend, when this machine has openssl >= 3.5."""
    backend = OpensslCliMlDsaBackend()
    if not backend.available():  # pragma: no cover - machine without openssl 3.5
        pytest.raises(RuntimeError, backend.verify, b"m", b"s", b"k")
        return
    clean = check_all(load_recorded("clean"), signature_backend=backend)
    assert (clean.signature.status, clean.verdict) == (SIGNATURE_VERIFIED, VERDICT_OK)
    relabelled = check_all(_relabelled("clean", "Ed25519"), signature_backend=backend)
    assert relabelled.signature.status == SIGNATURE_INVALID
    assert relabelled.verdict == VERDICT_TAMPERED


# --------------------------------------------------------------------------- #
# item 5 - the DEBIT leg of L2 counters-vs-replay
# --------------------------------------------------------------------------- #
DEBIT_ONLY_CASE = "counters_debit_leg_only_drift"


def test_item5_FIRES_a_debit_only_counter_drift_is_caught():
    """RED at 996de69: no fixture existed, so deleting the DEBIT half of the L2 comparison
    (mutant M1d) left all 210 tests green."""
    check = check_money_conservation(load_adversarial(DEBIT_ONLY_CASE))
    drifts = [v for v in check.violations if v.code == COUNTER_DRIFT]
    assert check.status == VIOLATION
    assert drifts, [v.code for v in check.violations]
    assert any("wallet:ana" in v.message for v in drifts)


def test_item5_the_new_fixture_really_isolates_the_DEBIT_leg():
    """Without this, the fixture could kill the mutant through the CREDIT leg and prove
    nothing. Every account's postedCredits must agree with the replay; exactly one
    account's postedDebits must not."""
    payload = json.loads(
        (ADVERSARIAL_DIR / (DEBIT_ONLY_CASE + ".json")).read_text(encoding="utf-8")
    )
    snapshot = load_adversarial(DEBIT_ONLY_CASE)
    by_id = {row.account_id: row for row in snapshot.accounts}
    replayed_debits = {account_id: 0 for account_id in by_id}
    replayed_credits = {account_id: 0 for account_id in by_id}
    for posting in snapshot.postings:
        replayed_debits[posting.debit_account_id] += posting.debit_leg
        replayed_credits[posting.credit_account_id] += posting.credit_leg

    credit_drifts = [a for a, r in by_id.items() if r.posted_credits != replayed_credits[a]]
    debit_drifts = [a for a, r in by_id.items() if r.posted_debits != replayed_debits[a]]
    assert credit_drifts == [], "the CREDIT leg must be clean or this fixture proves nothing"
    assert len(debit_drifts) == 2, debit_drifts
    assert payload["expected_violation"] == "conservation"

    # and no OTHER leg may fire, or the mutant could die through a leg that is already
    # covered: the two counters are moved in opposite directions, so the system-wide net
    # (L3) still sums to zero and nothing is skipped.
    check = check_money_conservation(snapshot)
    assert {v.code for v in check.violations} == {COUNTER_DRIFT}, [
        v.code for v in check.violations
    ]
    assert check.examined["legs_skipped"] == []
    assert check_all(snapshot).violations_of("no_overdraft") == ()


def test_item5_SILENT_the_negative_control_case_still_does_not_fire():
    """Paired: the same checker on the case that must stay clean."""
    assert check_money_conservation(load_adversarial("clean_must_not_fire")).status == OK


# --------------------------------------------------------------------------- #
# A1 / A2 / A3 - the live-ledger findings of 2026-09-22
# --------------------------------------------------------------------------- #
def _forged_recorded_corpus(tmp_path: Path) -> Path:
    """A copy of the recorded corpus OUTSIDE the repo with one byte of the ML-DSA
    signature flipped - the exact shape of the live-ledger A1 probe."""
    dest = tmp_path / "recorded"
    shutil.copytree(RECORDED_CORPUS, dest)
    path = dest / "clean" / "journal_checkpoint.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    signature = raw["signature"]
    raw["signature"] = ("B" if signature[0] != "B" else "C") + signature[1:]
    path.write_text(json.dumps(raw), encoding="utf-8")
    return dest


def test_A1_FIRES_the_FLAGLESS_command_can_never_exit_0_on_a_forged_signature(tmp_path, capsys):
    """RED at 996de69: `py -m tools.verify_report --corpus recorded --half clean` printed
    `verdict: OK` and exited 0 over a signature with a flipped byte, on a machine that HAD a
    working OpenSSL 3.5.5, because the backend was opt-in behind --mldsa-openssl. A detector
    that cannot go red on the default command is confident green over forged data."""
    from tools import verify_report

    root = _forged_recorded_corpus(tmp_path)
    code = verify_report.main(
        ["--corpus", "recorded", "--half", "clean", "--corpus-root", str(root)]
    )
    captured = capsys.readouterr()
    assert code != verify_report.EXIT_OK, captured.out
    if OpensslCliMlDsaBackend().available():
        assert code == verify_report.EXIT_TAMPERED
        assert "INVALID" in captured.out
    else:  # pragma: no cover - a machine with no openssl >= 3.5
        assert code == verify_report.EXIT_INCOMPLETE


def test_A1_a_machine_with_NO_backend_gets_INCOMPLETE_never_a_pass(tmp_path, capsys, monkeypatch):
    """The other half of A1, on the honest machine: when the signature genuinely cannot be
    verified the tool refuses to say OK. The VERDICT object is untouched - 'could not verify'
    is still not evidence of tamper - only the exit code the gate reads changes."""
    from ledger_verification_agent import mldsa_openssl_backend
    from tools import verify_report

    monkeypatch.setattr(mldsa_openssl_backend.OpensslCliMlDsaBackend, "available", lambda self: False)
    monkeypatch.setattr(checkpoint_signature, "default_backend", lambda: None)
    code = verify_report.main(["--corpus", "recorded", "--half", "clean"])
    captured = capsys.readouterr()
    assert code == verify_report.EXIT_INCOMPLETE
    assert "verdict: OK" in captured.out, "the verdict object must NOT be re-labelled"
    assert "INCOMPLETE" in captured.err

    # and the explicit flag still turns a missing backend into a hard tool error
    assert (
        verify_report.main(["--corpus", "recorded", "--half", "clean", "--mldsa-openssl"])
        == verify_report.EXIT_TOOL_ERROR
    )


def test_A1_SILENT_a_clean_corpus_still_exits_0_on_the_flagless_command(capsys):
    """The paired must-not-fire: the fix may not turn every run into a refusal."""
    from tools import verify_report

    assert verify_report.main(["--corpus", "recorded", "--half", "clean"]) == 0
    assert verify_report.main(["--corpus", "recorded", "--half", "tampered"]) == 1


def test_A1_a_PROVEN_break_is_never_softened_into_INCOMPLETE(tmp_path, capsys, monkeypatch):
    """Over-firing guard on the new exit path: a tampered corpus with no backend must keep
    exit 1, not be downgraded to 'could not verify'."""
    from ledger_verification_agent import mldsa_openssl_backend
    from tools import verify_report

    monkeypatch.setattr(mldsa_openssl_backend.OpensslCliMlDsaBackend, "available", lambda self: False)
    monkeypatch.setattr(checkpoint_signature, "default_backend", lambda: None)
    assert verify_report.main(["--corpus", "recorded", "--half", "tampered"]) == 1


def test_A2_corpus_root_verifies_a_corpus_that_lives_outside_the_repo(tmp_path, capsys):
    """RED at 996de69: --corpus-root did not exist, so verifying a live capture meant
    copying the whole repository around it."""
    from tools import verify_report

    dest = tmp_path / "live-capture"
    shutil.copytree(RECORDED_CORPUS, dest)
    code = verify_report.main(
        ["--corpus", "recorded", "--half", "clean", "--corpus-root", str(dest)]
    )
    out = capsys.readouterr().out
    assert code == verify_report.EXIT_OK, out
    assert "verdict: OK" in out
    assert not str(dest).startswith(str(REPO_ROOT)), "the point is that it is OUTSIDE the repo"


class _RecordingClient:
    """Stands in for RateLimitedClient and RECORDS every request the recorder issues.

    The stack is not reachable from this test, so what is exercised is the shipped ``main()``
    control flow - the only place the new flag lives - with the network replaced. Named as a
    limit in the handoff, not presented as an end-to-end run.
    """

    def __init__(self, base_url=None):
        self.calls = []
        self.http_log = []
        self.retries_after_429 = 0

    def post_json(self, path, body=None):
        self.calls.append(("POST", path))
        return {}

    def get_json(self, path):
        self.calls.append(("GET", path))
        return {}

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        return 200, {}


def _run_recorder(tmp_path, monkeypatch, argv):
    """Drive the shipped main() with the network and the DB capture stubbed out."""
    from tools import record_fixtures

    client = _RecordingClient()
    monkeypatch.setattr(record_fixtures, "RateLimitedClient", lambda *a, **k: client)
    monkeypatch.setattr(record_fixtures, "wait_for_chain_complete", lambda c: (True, {"ok": True}))
    monkeypatch.setattr(record_fixtures, "wait_for_stable_verify", lambda c, **k: (True, {"ok": 1}))
    monkeypatch.setattr(
        record_fixtures, "capture_half", lambda c, half, out, write: ({}, {})
    )
    record_fixtures.main(argv)
    return client


def test_A3_the_DEFAULT_run_does_NOT_truncate_the_ledger(tmp_path, monkeypatch, capsys):
    """RED before this change: POST /api/demo/reset was unconditional, so the default run
    TRUNCATEd whatever ledger BASE_URL pointed at - it destroyed a live 8-posting ledger on
    2026-09-22. Authorised behaviour change, owner, 2026-09-22 (separate from the first pass)."""
    client = _run_recorder(tmp_path, monkeypatch, ["--out", str(tmp_path / "as-found")])
    out = capsys.readouterr().out
    paths = [path for _method, path in client.calls]
    assert "/api/demo/reset" not in paths, client.calls
    assert "/api/demo/tamper" not in paths, client.calls
    assert "reset: SKIPPED" in out
    assert "destructive: False" in out


def test_A3_the_FLAG_really_does_truncate_and_tamper(tmp_path, monkeypatch, capsys):
    """The paired must-fire: the destructive recipe is still available, unchanged, on request."""
    client = _run_recorder(
        tmp_path,
        monkeypatch,
        ["--out", str(tmp_path / "canned"), "--destructive-reset-and-tamper"],
    )
    out = capsys.readouterr().out
    paths = [path for _method, path in client.calls]
    assert "/api/demo/reset" in paths, client.calls
    assert "/api/demo/tamper" in paths, client.calls
    assert "TRUNCATEd" in out


def test_A3_a_non_destructive_run_refuses_to_overwrite_the_shipped_corpus(tmp_path, monkeypatch):
    """A clean-half-only capture must never silently replace the two-half ground truth.

    Since 2026-09-24 (gate residual R3) the "shipped corpus" is a BYTE COPY of tests/fixtures
    installed as the recorder's protected roots: with the guard broken, this test itself
    overwrote the real recorded/_corpus.json. main()'s --out default follows RECORDED_ROOT, so
    the default run now targets the copy; the real corpus is asserted untouched as well."""
    from tools import record_fixtures

    fixtures_root = tmp_path / "repo" / "tests" / "fixtures"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures", fixtures_root)
    monkeypatch.setattr(record_fixtures, "FIXTURES_ROOT", fixtures_root)
    monkeypatch.setattr(record_fixtures, "RECORDED_ROOT", fixtures_root / "recorded")
    real_corpus = REPO_ROOT / "tests" / "fixtures" / "recorded" / "_corpus.json"
    real_bytes = real_corpus.read_bytes()

    with pytest.raises(record_fixtures.RecorderError) as excinfo:
        _run_recorder(tmp_path, monkeypatch, [])  # --out defaults to the shipped corpus
    assert "REFUSING TO WRITE" in str(excinfo.value)
    assert "--destructive-reset-and-tamper" in str(excinfo.value)
    assert real_corpus.read_bytes() == real_bytes, "the real shipped corpus is untouched"


def test_A3_the_corpus_metadata_declares_which_mode_produced_it(tmp_path, monkeypatch):
    """A clean-half-only corpus that claimed AC-0.2 eligibility would be a false green."""
    from tools import record_fixtures

    out = tmp_path / "as-found"
    _run_recorder(tmp_path, monkeypatch, ["--out", str(out)])
    meta = json.loads((out / "_corpus.json").read_text(encoding="utf-8"))
    assert meta["capture_mode"] == "as-found-read-only"
    assert meta["ac_0_2_eligible"] is False
    assert "NOT ELIGIBLE" in meta["ac_0_2_reason"]


def test_A3_the_recorder_declares_at_the_call_site_that_it_TRUNCATES_the_live_ledger():
    """A3: `POST /api/demo/reset` truncates the ledger. It destroyed a live 8-posting ledger
    during the 2026-09-22 run. Behaviour unchanged on purpose (that is a recommendation, not
    a coder's call); what changes is that the call site says so."""
    text = (REPO_ROOT / "tools" / "record_fixtures.py").read_text(encoding="utf-8")
    normalised = " ".join(text.split())
    assert "DESTRUCTIVE" in normalised
    assert "TRUNCATE" in normalised.upper()
    assert "/api/demo/reset" in normalised


# --------------------------------------------------------------------------- #
# items 3 and 6 - the documents
# --------------------------------------------------------------------------- #
def test_item3_the_README_correction_block_calls_the_audit_equivalence_PARTIAL():
    """RED at 996de69: the README claimed the H4 gate is 'the same rule as LedgerMind's own
    audit()' with nothing narrowing it, while the gate provably cannot catch an attacker who
    re-signs the checkpoint with their own key."""
    text = README.read_text(encoding="utf-8")
    assert "PARTIAL" in text
    lowered = text.lower()
    assert "re-sign" in lowered or "resign" in lowered or "their own key" in lowered
    assert "anchor" in lowered


def test_item3_SILENT_the_existing_key_substitution_disclosure_is_NOT_weakened():
    """The correction may only ADD. These are the exact sentences the 2026-09-20 verifier
    found and confirmed as an honest disclosure."""
    evidence = " ".join(EVIDENCE_DOC.read_text(encoding="utf-8").split())
    assert "MESSAGE INTEGRITY, not signer authenticity" in evidence
    assert "The public key travels with the row" in evidence
    assert "anchored outside the database" in evidence


def test_item6_the_README_test_count_is_the_one_a_real_collection_produces():
    """RED at 996de69: README.md:41 said 194 while the suite collected 210. A number in a
    document rots; this test is what stops it rotting again."""
    text = README.read_text(encoding="utf-8")
    claimed = [int(n) for n in re.findall(r"#\s*(\d+)\s+tests,\s*no network", text)]
    assert claimed, "README no longer states a test count in the pinned shape"

    completed = subprocess.run(
        # -o addopts= clears the repo's own "-q" so the COLLECTED TOTAL is printed; collection
        # executes no test, so this cannot recurse into itself.
        [
            sys.executable, "-m", "pytest", "--collect-only", "-q",
            "-o", "addopts=", "-p", "no:cacheprovider",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    collected = re.search(r"(\d+)\s+tests? collected", completed.stdout)
    assert collected, completed.stdout[-500:]
    assert claimed == [int(collected.group(1))], (claimed, collected.group(1))
