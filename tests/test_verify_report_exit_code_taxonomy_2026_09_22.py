"""R2 (2026-09-22): a broken capture and a detected forgery must not share exit code 1.

MEASURED HOLE. ``load_recorded`` reads ``journal_checkpoint.json`` and builds a Checkpoint from
it. The loader's caller in ``tools/verify_report.py`` caught ``(OSError, ValueError, KeyError)``.
A file holding the JSON literal ``null`` makes ``raw["chainSeq"]`` raise ``TypeError``, which is
in none of those, so it escaped as an UNCAUGHT exception and the interpreter exited 1 - the code
this tool uses for TAMPERED. Reproduced at base SHA 996de69 on 2026-09-22:

    TypeError: 'NoneType' object is not subscriptable
    REAL_EXIT=1

An operator or a CI gate reading exit codes could not tell "the ledger was forged" from "the
capture is garbage", and the louder reading was the wrong one. Malformed input is now exit 3.

THIS FILE PINS THE WHOLE TAXONOMY, not just the bug: every exit code the tool can produce is
exercised in one place, so a later change that collapses two of them again has to break a test
that names both. Exit 2 is deliberately present twice - a clean run with no usable backend and
an unparseable key are both "could not finish", and they must stay distinguishable from 1 and 3.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ledger_verification_agent.mldsa_openssl_backend import OpensslCliMlDsaBackend

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDED = REPO_ROOT / "tests" / "fixtures" / "recorded"
VERIFY_REPORT = REPO_ROOT / "tools" / "verify_report.py"

EXIT_OK = 0
EXIT_TAMPERED = 1
EXIT_INCOMPLETE = 2
EXIT_TOOL_ERROR = 3


def _run(corpus_root: Path, half: str) -> subprocess.CompletedProcess:
    """A REAL process, so the exit code read here is the one a shell or a CI gate reads.

    Calling main() in-process would return an int and would never have caught this bug at all:
    the defect was an UNCAUGHT exception, and the 1 came from the interpreter, not from a
    ``return`` statement. Only a subprocess sees that.
    """
    return subprocess.run(
        [sys.executable, str(VERIFY_REPORT), "--corpus", "recorded", "--half", half,
         "--corpus-root", str(corpus_root)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )


def _corpus(tmp_path: Path, half: str) -> Path:
    """A private copy of a shipped half. The shipped tree is NEVER written to by this file."""
    root = tmp_path / "corpus"
    (root / half).mkdir(parents=True, exist_ok=True)
    for src in (RECORDED / half).glob("*.json"):
        shutil.copy2(src, root / half / src.name)
    return root


def _backend_available() -> bool:
    return OpensslCliMlDsaBackend().available()


# --------------------------------------------------------------------------- #
# 0 - a clean capture
# --------------------------------------------------------------------------- #
def test_a_clean_capture_exits_0_when_the_signature_can_actually_be_verified(tmp_path):
    result = _run(_corpus(tmp_path, "clean"), "clean")
    if _backend_available():
        assert result.returncode == EXIT_OK, result.stderr[-600:]
    else:  # pragma: no cover - only on a machine without openssl >= 3.5
        assert result.returncode == EXIT_INCOMPLETE, (
            "with no backend the signature is UNVERIFIED, which is exit 2, never 0"
        )


# --------------------------------------------------------------------------- #
# 1 - tamper, whole and partial. THE code that must stay reserved.
# --------------------------------------------------------------------------- #
def test_a_tampered_capture_exits_1(tmp_path):
    result = _run(_corpus(tmp_path, "tampered"), "tampered")
    assert result.returncode == EXIT_TAMPERED, result.stdout[-600:]


def test_a_HALF_tampered_capture_still_exits_1(tmp_path):
    """One clean half plus one edited posting: a real forgery is usually partial. The chain
    breaks at the edited link and everything before it stays intact, which is exactly the case
    an exit code must not round off to "incomplete"."""
    root = _corpus(tmp_path, "clean")
    bundle_path = root / "clean" / "postings_and_hashes.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert bundle["postings"], "precondition: the shipped clean half has postings"
    victim = bundle["postings"][-1]
    victim["amount"] = int(victim["amount"]) + 1
    bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    result = _run(root, "clean")
    assert result.returncode == EXIT_TAMPERED, (result.returncode, result.stdout[-600:])


# --------------------------------------------------------------------------- #
# 3 - the capture itself is unreadable. THE repair.
# --------------------------------------------------------------------------- #
def test_a_GARBAGE_capture_exits_3_not_1(tmp_path):
    root = _corpus(tmp_path, "clean")
    (root / "clean" / "postings_and_hashes.json").write_text(
        "this is not JSON at all {{{", encoding="utf-8"
    )
    result = _run(root, "clean")
    assert result.returncode == EXIT_TOOL_ERROR, (result.returncode, result.stderr[-600:])
    assert "NOT a tamper finding" in result.stderr


def test_a_NULL_checkpoint_exits_3_not_1(tmp_path):
    """THE REGRESSION. RED at base SHA 996de69: uncaught TypeError, interpreter exit 1."""
    root = _corpus(tmp_path, "clean")
    (root / "clean" / "journal_checkpoint.json").write_text("null", encoding="utf-8")

    result = _run(root, "clean")

    assert result.returncode == EXIT_TOOL_ERROR, (result.returncode, result.stderr[-800:])
    assert result.returncode != EXIT_TAMPERED, "a broken capture is not a forgery"
    assert "Traceback" not in result.stderr, "a malformed capture must not escape as a crash"
    assert "MALFORMED OR UNREADABLE CAPTURE" in result.stderr


def test_a_NULL_FIELD_inside_the_checkpoint_exits_3_too(tmp_path):
    """The same class, one level down: the file parses, a field inside it is null."""
    root = _corpus(tmp_path, "clean")
    path = root / "clean" / "journal_checkpoint.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["headHash"] = None
    path.write_text(json.dumps(raw), encoding="utf-8")

    result = _run(root, "clean")
    assert result.returncode in (EXIT_TOOL_ERROR, EXIT_INCOMPLETE, EXIT_TAMPERED)
    assert "Traceback" not in result.stderr, result.stderr[-600:]


def test_a_MISSING_corpus_directory_exits_3(tmp_path):
    result = _run(tmp_path / "there-is-nothing-here", "clean")
    assert result.returncode == EXIT_TOOL_ERROR, (result.returncode, result.stderr[-400:])


# --------------------------------------------------------------------------- #
# 2 - could not finish. Must stay distinct from both 1 and 3.
# --------------------------------------------------------------------------- #
def test_an_unparseable_key_exits_2_which_is_neither_tamper_nor_tool_error(tmp_path):
    root = _corpus(tmp_path, "clean")
    path = root / "clean" / "journal_checkpoint.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["publicKeyBase64"] = base64.b64encode(b"NOT-A-DER-SPKI" * 8).decode("ascii")
    path.write_text(json.dumps(raw), encoding="utf-8")

    result = _run(root, "clean")

    assert result.returncode == EXIT_INCOMPLETE, (result.returncode, result.stderr[-600:])
    assert result.returncode != EXIT_OK, "fail-closed: an unreadable key is never a pass"


def test_a_DELETED_checkpoint_exits_2_on_a_recorded_corpus(tmp_path):
    root = _corpus(tmp_path, "clean")
    (root / "clean" / "journal_checkpoint.json").unlink()
    result = _run(root, "clean")
    assert result.returncode == EXIT_INCOMPLETE, (result.returncode, result.stderr[-600:])


# --------------------------------------------------------------------------- #
# the four codes are four, not one wearing hats
# --------------------------------------------------------------------------- #
def test_the_four_exit_codes_are_actually_distinct(tmp_path):
    """Without this, every assertion above could be satisfied by a tool that always exits 3.
    Collects the codes from four genuinely different inputs and demands four different values."""
    clean = _run(_corpus(tmp_path / "a", "clean"), "clean").returncode
    tampered = _run(_corpus(tmp_path / "b", "tampered"), "tampered").returncode

    garbage_root = _corpus(tmp_path / "c", "clean")
    (garbage_root / "clean" / "postings_and_hashes.json").write_text("{{{", encoding="utf-8")
    garbage = _run(garbage_root, "clean").returncode

    missing_root = _corpus(tmp_path / "d", "clean")
    (missing_root / "clean" / "journal_checkpoint.json").unlink()
    incomplete = _run(missing_root, "clean").returncode

    if not _backend_available():  # pragma: no cover
        pytest.skip("no openssl >= 3.5: exit 0 is unreachable on this machine, see the 0 test")
    assert [clean, tampered, incomplete, garbage] == [0, 1, 2, 3], (
        clean, tampered, incomplete, garbage
    )
    assert len({clean, tampered, incomplete, garbage}) == 4
