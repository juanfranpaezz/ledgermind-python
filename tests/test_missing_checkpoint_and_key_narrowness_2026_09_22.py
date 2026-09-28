"""The three residuals left open by the fresh-context adversarial verification of 2026-09-22.

Source: the verifier report of 2026-09-22 (PASS, confidence 88, residuals A1 / A2 / A3). Every
test here is named for the direction it proves, and every gate in this file was run BOTH ways
before it was trusted.

A1  REMOVING the evidence must not be cheaper than forging it. Every forgery path already exits
    1, 2 or 3, but DELETING journal_checkpoint.json from a RECORDED corpus exited 0 with a
    NO-CHECKPOINT note - the same "a check that cannot go red" shape as the defect this whole
    pass was about, reached by removal instead of forgery. It is now INCOMPLETE (exit 2) for
    --corpus recorded and STILL exit 0 for --corpus adversarial, whose fixtures legitimately
    carry no checkpoint at all.
A2  The narrowness guard "key_algorithm_oid is not None" in verify_checkpoint was the one mutant
    of 17 that survived the verifier sweep: deleting it left all 261 tests green. It decides
    whether a valid signature under a key the in-repo DER reader cannot parse is reported as
    "we could not check the key algorithm" or as "this is forged" - opposite claims about the
    same bytes, in a report an auditor reads.
A3  The recorder write refusal was keyed to RECORDED_ROOT only, so a capture could be written
    inside tests/fixtures/derived_from_source. It now covers the whole shipped fixture tree.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import shutil
from pathlib import Path

import pytest

from ledger_verification_agent.checkpoint_signature import verify_checkpoint
from ledger_verification_agent.deterministic_verifier import check_all
from ledger_verification_agent.ledger_snapshot import load_recorded
from ledger_verification_agent.mldsa_openssl_backend import OpensslCliMlDsaBackend
from ledger_verification_agent.verdict import (
    SIGNATURE_ABSENT,
    SIGNATURE_INVALID,
    SIGNATURE_UNVERIFIED,
    SIGNATURE_VERIFIED,
    VERDICT_OK,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDED_CORPUS = REPO_ROOT / "tests" / "fixtures" / "recorded"
ADVERSARIAL_CORPUS = REPO_ROOT / "tests" / "fixtures" / "derived_from_source" / "adversarial"
SIGNATURE_GATE = "checkpoint_signature_invalid"


# --------------------------------------------------------------------------- #
# A1 - a DELETED checkpoint, and the corpus split that keeps the fix usable
# --------------------------------------------------------------------------- #
def _recorded_copy(tmp_path: Path, name: str) -> Path:
    dest = tmp_path / name
    shutil.copytree(RECORDED_CORPUS, dest)
    return dest


def _without_checkpoint(tmp_path: Path, half: str = "clean") -> Path:
    """The cheap attack: do not forge the signature, delete the file that carries it."""
    dest = _recorded_copy(tmp_path, "stripped-" + half)
    (dest / half / "journal_checkpoint.json").unlink()
    return dest


def _forged_signature(tmp_path: Path) -> Path:
    dest = _recorded_copy(tmp_path, "forged")
    path = dest / "clean" / "journal_checkpoint.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    signature = raw["signature"]
    raw["signature"] = ("B" if signature[0] != "B" else "C") + signature[1:]
    path.write_text(json.dumps(raw), encoding="utf-8")
    return dest


def test_A1res_FIRES_a_RECORDED_corpus_whose_checkpoint_was_DELETED_is_INCOMPLETE(
    tmp_path, capsys
):
    """RED before this change: exit 0, "verdict: OK", NO-CHECKPOINT. The recorder always
    captures /api/journal/checkpoint, so a recorded corpus without one is a stripped or broken
    capture: the evidence is gone, and gone is not fine."""
    from tools import verify_report

    root = _without_checkpoint(tmp_path)
    code = verify_report.main(
        ["--corpus", "recorded", "--half", "clean", "--corpus-root", str(root)]
    )
    captured = capsys.readouterr()
    assert code == verify_report.EXIT_INCOMPLETE, (code, captured.out)
    assert "INCOMPLETE" in captured.err
    assert "journal_checkpoint.json is absent" in captured.err
    # the VERDICT object is NOT re-labelled: absence is not evidence of tamper
    assert "verdict: OK" in captured.out
    assert SIGNATURE_ABSENT in captured.out


def test_A1res_SILENT_the_SAME_corpus_with_its_checkpoint_present_still_exits_0(
    tmp_path, capsys
):
    """The paired must-not-fire on the same bytes: only the deletion moves the exit code."""
    from tools import verify_report

    intact = _recorded_copy(tmp_path, "intact")
    code = verify_report.main(
        ["--corpus", "recorded", "--half", "clean", "--corpus-root", str(intact)]
    )
    out = capsys.readouterr().out
    assert code == verify_report.EXIT_OK, out
    assert (intact / "clean" / "journal_checkpoint.json").exists()


def test_A1res_the_THREE_recorded_states_get_THREE_different_exit_codes(tmp_path, capsys):
    """present+good -> 0, present+forged -> 1, absent -> 2. Collapsing any two of these hides
    either a forgery or a stripped capture behind the meaning of the other."""
    from tools import verify_report

    def run(root):
        code = verify_report.main(
            ["--corpus", "recorded", "--half", "clean", "--corpus-root", str(root)]
        )
        capsys.readouterr()
        return code

    good = run(_recorded_copy(tmp_path, "good"))
    absent = run(_without_checkpoint(tmp_path))
    forged = run(_forged_signature(tmp_path))

    assert good == verify_report.EXIT_OK
    assert absent == verify_report.EXIT_INCOMPLETE
    if OpensslCliMlDsaBackend().available():
        assert forged == verify_report.EXIT_TAMPERED
    else:  # pragma: no cover - only on a machine with no openssl >= 3.5
        assert forged == verify_report.EXIT_INCOMPLETE
    assert forged != good and absent != good


def test_A1res_SILENT_an_ADVERSARIAL_case_without_a_checkpoint_still_exits_0(tmp_path, capsys):
    """THE half of A1 that must not regress. Derived fixtures carry no checkpoint by
    construction (load_adversarial hard-codes checkpoint=None), so making that INCOMPLETE would
    turn the entire adversarial suite red - worse than the hole it closes."""
    from tools import verify_report

    assert verify_report.main(["--corpus", "adversarial", "--case", "clean_must_not_fire"]) == 0
    capsys.readouterr()

    outside = tmp_path / "derived"
    outside.mkdir()
    shutil.copy2(ADVERSARIAL_CORPUS / "clean_must_not_fire.json", outside)
    code = verify_report.main(
        ["--corpus", "adversarial", "--case", "clean_must_not_fire", "--corpus-root", str(outside)]
    )
    out = capsys.readouterr().out
    assert code == verify_report.EXIT_OK, out
    assert SIGNATURE_ABSENT in out, "the note is still printed; only the exit code differs"


def test_A1res_a_PROVEN_break_with_NO_checkpoint_keeps_exit_1(tmp_path, capsys):
    """Over-firing guard on the new path: a corpus that already proved tamper stays TAMPERED,
    never softened into "could not check" because the checkpoint is missing as well."""
    from tools import verify_report

    root = _without_checkpoint(tmp_path, half="tampered")
    code = verify_report.main(
        ["--corpus", "recorded", "--half", "tampered", "--corpus-root", str(root)]
    )
    out = capsys.readouterr().out
    assert code == verify_report.EXIT_TAMPERED, out


def test_A1res_every_shipped_adversarial_case_keeps_the_exit_code_it_had(capsys):
    """The regression net for the split: 7 shipped fixtures, not one of which has a
    checkpoint. If the new gate ever leaks onto this corpus, every row here moves at once."""
    from tools import verify_report

    expected = {
        "chain_link_posting_deleted": 1,
        "chain_prev_hash_rewritten": 1,
        "clean_must_not_fire": 0,
        "counters_debit_leg_only_drift": 1,
        "counters_disagree_with_postings": 1,
        "overdraft_account": 1,
        "unbalanced_posting": 1,
    }
    assert sorted(p.stem for p in ADVERSARIAL_CORPUS.glob("*.json")) == sorted(expected)
    for case, code in expected.items():
        assert verify_report.main(["--corpus", "adversarial", "--case", case]) == code, case
        capsys.readouterr()


# --------------------------------------------------------------------------- #
# A2 - the narrowness guard: the one mutant that survived the verifier sweep
# --------------------------------------------------------------------------- #
class _AlwaysValidBackend:
    """A backend that verifies successfully - i.e. the real OpenSSL on a checkpoint whose
    signature genuinely closes over the message, which is the only situation in which the
    narrowness guard is reached at all."""

    name = "stub-always-valid"

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return True


# valid base64, NOT a DER SubjectPublicKeyInfo: placeholder key material, which is the exact
# case the guard comment in checkpoint_signature names as the over-firing danger.
PLACEHOLDER_KEY = base64.b64encode(b"PLACEHOLDER-PUBLIC-KEY-NOT-DER" * 8).decode("ascii")


def _checkpoint_with_key(public_key_base64: str):
    snapshot = load_recorded("clean")
    return dataclasses.replace(snapshot.checkpoint, public_key_base64=public_key_base64)


def _truncated_der_key() -> str:
    """A real SPKI cut in half: the mini reader runs off the end of the buffer."""
    snapshot = load_recorded("clean")
    raw = base64.b64decode(snapshot.checkpoint.public_key_base64, validate=True)
    return base64.b64encode(raw[: len(raw) // 2]).decode("ascii")


@pytest.mark.parametrize("kind", ["placeholder", "truncated-der"])
def test_A2res_FIRES_a_key_the_DER_reader_cannot_parse_is_never_called_INVALID(kind):
    """THE MUTANT THIS KILLS: dropping "findings.key_algorithm_oid is not None" from
    verify_checkpoint (verifier sweep M6, which survived 261 green tests). Without that term,
    key_algorithm_matches_declared is False for every key that fails to parse, so a signature
    that really does close over the message is reported INVALID - "we could not read this key"
    silently becomes "this checkpoint is forged". Opposite claims about the same bytes."""
    key = PLACEHOLDER_KEY if kind == "placeholder" else _truncated_der_key()
    checkpoint = _checkpoint_with_key(key)

    report = verify_checkpoint(checkpoint, backend=_AlwaysValidBackend())

    assert report.structural["key_algorithm_oid"] is None, "precondition: the key must not parse"
    assert any("does not parse" in p for p in report.structural["problems"]), report.structural
    assert report.status != SIGNATURE_INVALID, (
        "an unreadable key is not evidence of forgery, status was " + str(report.status)
    )
    # CHANGED 2026-09-22 (R3, fail-closed decision), LOUDLY: this line read
    #     assert report.status == SIGNATURE_VERIFIED
    # and that assertion pinned the defect in place. With a permissive backend the run
    # reported VERIFIED over key bytes this checker never managed to parse, and the declared
    # algorithm went unchecked because the only term that checks it needs the OID the parse
    # failed to produce. UNVERIFIED is STRICTLY STRONGER than the "!= INVALID" claim above,
    # so this test keeps its whole original point - an unreadable key is still not evidence of
    # forgery - and adds the half that was missing: it is not a pass either.
    assert report.status == SIGNATURE_UNVERIFIED
    assert "does NOT close" not in report.reason
    assert "does NOT parse" in report.reason, "the report must say plainly WHY it stopped"


def test_A2res_FIRES_the_unreadable_key_does_not_gate_the_VERDICT_either():
    """The same mutant where it would actually hurt: the verdict an auditor reads. With the
    guard deleted this snapshot becomes TAMPERED, carrying a checkpoint_signature_invalid
    violation, over a signature that verified."""
    snapshot = load_recorded("clean")
    snapshot = dataclasses.replace(snapshot, checkpoint=_checkpoint_with_key(PLACEHOLDER_KEY))

    result = check_all(snapshot, signature_backend=_AlwaysValidBackend())

    codes = [v.code for check in result.checks for v in check.violations]
    assert SIGNATURE_GATE not in codes, codes
    assert result.verdict == VERDICT_OK, result.verdict


def test_A2res_SILENT_the_guard_does_NOT_disarm_the_algorithm_gate_on_a_PARSEABLE_key():
    """The other outcome of the same instrument, without which the tests above would only
    prove the term is dead: when the key DOES parse and its OID disagrees with the declared
    algorithm, a valid signature is still INVALID (LedgerMind folds algorithmMatches into
    signatureValid, JournalCheckpointService.java:149-150 of its working tree)."""
    snapshot = load_recorded("clean")
    relabelled = dataclasses.replace(snapshot.checkpoint, algorithm="ML-DSA-87")

    report = verify_checkpoint(relabelled, backend=_AlwaysValidBackend())

    assert report.structural["key_algorithm_oid"] is not None, "this key DOES parse"
    assert report.status == SIGNATURE_INVALID
    assert "DECLARED algorithm" in report.reason


def test_A2res_SILENT_an_untouched_checkpoint_under_a_parseable_key_still_VERIFIES():
    """The must-not-fire floor: neither term may turn the shipped corpus red."""
    snapshot = load_recorded("clean")
    report = verify_checkpoint(snapshot.checkpoint, backend=_AlwaysValidBackend())
    assert report.status == SIGNATURE_VERIFIED
    assert report.structural["key_algorithm_matches_declared"] is True


# --------------------------------------------------------------------------- #
# A3 - the write refusal covers the WHOLE shipped fixture tree
# --------------------------------------------------------------------------- #
class _RecordingClient:
    """Stands in for RateLimitedClient and records every request the recorder issues. When the
    guard lands where it must, this stays EMPTY: a mis-invocation may not reach the ledger at
    all, let alone TRUNCATE it."""

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


def _stub_network(monkeypatch):
    from tools import record_fixtures

    client = _RecordingClient()
    monkeypatch.setattr(record_fixtures, "RateLimitedClient", lambda *a, **k: client)
    monkeypatch.setattr(record_fixtures, "wait_for_chain_complete", lambda c: (True, {"ok": True}))
    monkeypatch.setattr(record_fixtures, "wait_for_stable_verify", lambda c, **k: (True, {"ok": 1}))
    monkeypatch.setattr(record_fixtures, "capture_half", lambda c, half, out, write: ({}, {}))
    return client


def _tree_listing(root: Path):
    return sorted((p.relative_to(root).as_posix(), p.stat().st_size) for p in root.rglob("*"))


def _relocated_repo(tmp_path, monkeypatch):
    """S54 (d), 2026-09-24: a byte copy of tests/fixtures under tmp_path, installed as the
    recorder's protected roots, so a regressed guard can only ever write into the COPY (the
    gate's mutants did overwrite _corpus.json when these tests ran on the real tree). The
    real constants are pinned first, without writing, so the move hides nothing about which
    tree the shipped recorder protects."""
    from tools import record_fixtures

    assert record_fixtures.FIXTURES_ROOT == REPO_ROOT / "tests" / "fixtures"
    assert record_fixtures.RECORDED_ROOT == RECORDED_CORPUS
    fake_repo = tmp_path / "relocated_repo"
    shutil.copytree(REPO_ROOT / "tests" / "fixtures", fake_repo / "tests" / "fixtures")
    (fake_repo / "tools").mkdir()
    monkeypatch.setattr(record_fixtures, "FIXTURES_ROOT", fake_repo / "tests" / "fixtures")
    monkeypatch.setattr(
        record_fixtures, "RECORDED_ROOT", fake_repo / "tests" / "fixtures" / "recorded"
    )
    return fake_repo


@pytest.mark.parametrize("extra", [[], ["--destructive-reset-and-tamper"]])
def test_A3res_FIRES_a_capture_into_the_SHIPPED_derived_corpus_is_REFUSED(
    monkeypatch, tmp_path, extra
):
    """RED before this change: the guard compared --out against RECORDED_ROOT only, so
    --out <repo>/tests/fixtures/derived_from_source was accepted and a clean/ half would have
    been written INSIDE the shipped derived corpus. Runs against a RELOCATED byte copy of the
    shipped tree since S54 (d), 2026-09-24 - it used to run on the real one."""
    from tools import record_fixtures

    fake_repo = _relocated_repo(tmp_path, monkeypatch)
    target = fake_repo / "tests" / "fixtures" / "derived_from_source"
    before = _tree_listing(target)
    client = _stub_network(monkeypatch)

    with pytest.raises(record_fixtures.RecorderError) as excinfo:
        record_fixtures.main(["--out", str(target)] + extra)

    assert "REFUSING TO WRITE" in str(excinfo.value)
    assert "shipped fixture tree" in str(excinfo.value)
    assert client.calls == [], "the refusal must land BEFORE any HTTP call"
    assert _tree_listing(target) == before, "not one byte of the shipped corpus may change"


def test_A3res_FIRES_a_fresh_SUBDIRECTORY_of_the_fixture_tree_is_refused_too(
    monkeypatch, tmp_path
):
    """The guard is containment, not equality: a path that does not exist yet, under the
    fixture tree, is still inside the ground truth. (Relocated tree since S54 (d).)"""
    from tools import record_fixtures

    fixtures = _relocated_repo(tmp_path, monkeypatch) / "tests" / "fixtures"
    target = fixtures / "capture-2026-09-22"
    before = _tree_listing(fixtures)
    _stub_network(monkeypatch)

    with pytest.raises(record_fixtures.RecorderError) as excinfo:
        record_fixtures.main(["--out", str(target)])

    assert "REFUSING TO WRITE" in str(excinfo.value)
    # asserted as "this call added nothing", not as "the path does not exist": if the guard
    # ever regresses, the write lands in the fixture tree and would otherwise make the NEXT
    # run of this test pass over its own wreckage.
    assert _tree_listing(fixtures) == before


def test_A3res_FIRES_a_path_that_WALKS_into_the_fixture_tree_is_refused(monkeypatch, tmp_path):
    """--out is resolved before the comparison, so a .. segment cannot get in sideways.
    (Relocated tree since S54 (d).)"""
    from tools import record_fixtures

    _stub_network(monkeypatch)
    fake_repo = _relocated_repo(tmp_path, monkeypatch)
    fixtures = fake_repo / "tests" / "fixtures"
    sideways = fake_repo / "tools" / ".." / "tests" / "fixtures" / "recorded" / "clean"
    before = _tree_listing(fixtures)

    with pytest.raises(record_fixtures.RecorderError) as excinfo:
        record_fixtures.main(["--out", str(sideways)])

    assert "REFUSING TO WRITE" in str(excinfo.value)
    # measured with the guard narrowed back to RECORDED_ROOT equality: this exact call drops
    # a _corpus.json INSIDE tests/fixtures/recorded/clean/, next to the shipped ground truth.
    assert _tree_listing(fixtures) == before


def test_A3res_SILENT_a_directory_OUTSIDE_the_fixture_tree_still_captures(monkeypatch, tmp_path):
    """The paired must-not-fire: capturing a live ledger into a scratch directory is the
    normal documented use and has to keep working."""
    from tools import record_fixtures

    _stub_network(monkeypatch)
    out = tmp_path / "live-capture"

    record_fixtures.main(["--out", str(out)])

    # no RecorderError, and a corpus really was written where it was asked for
    meta = json.loads((out / "_corpus.json").read_text(encoding="utf-8"))
    assert meta["capture_mode"] == "as-found-read-only"
    # limit, stated rather than hidden: capture_half and the waits are stubbed, so this
    # exercises the shipped main() control flow around the guard, not a live capture.


def test_A3res_SILENT_the_canned_two_half_regeneration_is_still_allowed(monkeypatch, tmp_path):
    """The one write into the fixture tree that stays legal. Exercised against a RELOCATED
    fixture root so that this test cannot overwrite the very corpus it protects - the
    relocation is the only thing stubbed; the guard being exercised is the shipped one."""
    from tools import record_fixtures

    fake_fixtures = tmp_path / "tests" / "fixtures"
    fake_recorded = fake_fixtures / "recorded"
    fake_recorded.mkdir(parents=True)
    monkeypatch.setattr(record_fixtures, "FIXTURES_ROOT", fake_fixtures)
    monkeypatch.setattr(record_fixtures, "RECORDED_ROOT", fake_recorded)
    client = _stub_network(monkeypatch)

    # default --out (= the relocated RECORDED_ROOT) WITH the destructive flag: allowed
    record_fixtures.main(["--destructive-reset-and-tamper"])
    assert (fake_recorded / "_corpus.json").exists()
    assert ("POST", "/api/demo/reset") in client.calls

    # the same directory WITHOUT the flag is still refused
    with pytest.raises(record_fixtures.RecorderError):
        record_fixtures.main([])

    # and a sibling inside the relocated fixture tree is refused even WITH the flag
    with pytest.raises(record_fixtures.RecorderError):
        record_fixtures.main(
            ["--out", str(fake_fixtures / "derived_from_source"), "--destructive-reset-and-tamper"]
        )
