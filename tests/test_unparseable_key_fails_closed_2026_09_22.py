"""R3 (2026-09-22): a public key this checker cannot parse can never end in VERIFIED.

MEASURED HOLE. ``structural_findings`` leaves ``key_algorithm_oid`` at None when the public key
does not parse as a DER SubjectPublicKeyInfo. The algorithm term in ``verify_checkpoint`` is
guarded on that field being non-None - correctly, because "we could not read this key" is not
evidence of forgery. But execution then fell through to the backend, and a permissive backend
answering True produced ``status=VERIFIED``: a pass over key bytes the checker never read, with
the declared algorithm unchecked, because the only term that checks the algorithm needs the OID
the parse failed to produce. Two things were claimed that had not been proven.

THE DECISION IS FAIL-CLOSED. An unparseable key makes the report UNVERIFIED and says plainly
why. UNVERIFIED, not INVALID: unreadable must not become "forged", which is the opposite
over-firing mistake and is the one the narrow guard was built to prevent. Only INVALID gates the
verdict (H4), so this cannot manufacture a TAMPERED finding; what it does is refuse to say pass,
and on the CLI that is exit 2 instead of exit 0.

BOTH OUTCOMES ARE PINNED HERE. Every fires-case below sits next to a does-not-fire case on the
genuine shipped key, so "return UNVERIFIED always" would fail this file just as loudly as the
defect did. No key, signature or credential VALUE is printed by these tests or by the code they
exercise - the report carries an OID, two byte-counts and a reason string.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ledger_verification_agent.checkpoint_signature import verify_checkpoint
from ledger_verification_agent.deterministic_verifier import check_all
from ledger_verification_agent.ledger_snapshot import load_recorded
from ledger_verification_agent.verdict import (
    SIGNATURE_INVALID,
    SIGNATURE_UNVERIFIED,
    SIGNATURE_VERIFIED,
    VERDICT_OK,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDED = REPO_ROOT / "tests" / "fixtures" / "recorded"
VERIFY_REPORT = REPO_ROOT / "tools" / "verify_report.py"
SIGNATURE_GATE = "checkpoint_signature_invalid"


class _AlwaysValidBackend:
    """The permissive backend that made the hole reachable: it says True for anything, which is
    what any backend does when it is handed material it is not actually checking."""

    name = "stub-always-valid"

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return True


def _clean_checkpoint():
    return load_recorded("clean").checkpoint


def _with_key(public_key_base64: str):
    return dataclasses.replace(_clean_checkpoint(), public_key_base64=public_key_base64)


def _unparseable_keys():
    """Three ways a key fails to parse, all of them valid inputs to the loader."""
    genuine = base64.b64decode(_clean_checkpoint().public_key_base64, validate=True)
    return {
        # valid base64, not DER at all
        "placeholder": base64.b64encode(b"PLACEHOLDER-PUBLIC-KEY-NOT-DER" * 8).decode("ascii"),
        # a real SPKI cut in half: the mini reader runs off the end of the buffer
        "truncated-der": base64.b64encode(genuine[: len(genuine) // 2]).decode("ascii"),
        # not even base64
        "not-base64": "this is not base64 %%%",
    }


# --------------------------------------------------------------------------- #
# FIRES: an unreadable key is never a pass
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("kind", sorted(_unparseable_keys()))
def test_FIRES_an_unparseable_key_is_never_VERIFIED_even_on_a_permissive_backend(kind):
    report = verify_checkpoint(_with_key(_unparseable_keys()[kind]), backend=_AlwaysValidBackend())

    assert report.structural["key_algorithm_oid"] is None, "precondition: the key must not parse"
    assert report.status != SIGNATURE_VERIFIED, "fail-closed: this is the whole repair"
    assert report.status == SIGNATURE_UNVERIFIED
    assert report.is_cryptographically_verified is False


@pytest.mark.parametrize("kind", sorted(_unparseable_keys()))
def test_FIRES_and_it_is_NOT_called_forged_either(kind):
    """The over-firing direction, which is just as wrong: unreadable is not INVALID."""
    report = verify_checkpoint(_with_key(_unparseable_keys()[kind]), backend=_AlwaysValidBackend())
    assert report.status != SIGNATURE_INVALID
    assert "does NOT close" not in report.reason


@pytest.mark.parametrize("kind", sorted(_unparseable_keys()))
def test_FIRES_and_the_report_says_plainly_WHY(kind):
    """A refusal an operator cannot act on is only half a repair."""
    report = verify_checkpoint(_with_key(_unparseable_keys()[kind]), backend=_AlwaysValidBackend())
    assert "does NOT parse" in report.reason
    assert "NOT a pass" in report.reason
    assert any("does not parse" in p for p in report.structural["problems"]), report.structural


def test_FIRES_the_declared_algorithm_cannot_be_laundered_behind_an_unreadable_key():
    """The attack the fail-closed default actually blocks: rewrite the algorithm column AND
    make the key unreadable, and before this change the algorithm term went quiet and the run
    reported VERIFIED. Now it reports UNVERIFIED and names the unread key as the reason."""
    broken = dataclasses.replace(
        _with_key(_unparseable_keys()["placeholder"]), algorithm="ML-DSA-87"
    )
    report = verify_checkpoint(broken, backend=_AlwaysValidBackend())
    assert report.status == SIGNATURE_UNVERIFIED
    assert report.status != SIGNATURE_VERIFIED
    assert "ML-DSA-87" in report.reason, "the unchecked declared name must be quoted back"


# --------------------------------------------------------------------------- #
# DOES NOT FIRE: the genuine key still verifies, and the verdict is untouched
# --------------------------------------------------------------------------- #
def test_SILENT_the_genuine_shipped_key_still_VERIFIES():
    """Without this leg, "always return UNVERIFIED" would pass every test above."""
    report = verify_checkpoint(_clean_checkpoint(), backend=_AlwaysValidBackend())
    assert report.status == SIGNATURE_VERIFIED
    assert report.structural["key_algorithm_matches_declared"] is True
    assert report.structural["problems"] == []


def test_SILENT_an_unreadable_key_still_does_not_make_the_VERDICT_tampered():
    """Fail-closed changes what the tool CLAIMS, not what it ACCUSES. The verdict object stays
    OK with no signature violation; the exit code is where the refusal lands."""
    snapshot = load_recorded("clean")
    snapshot = dataclasses.replace(
        snapshot, checkpoint=_with_key(_unparseable_keys()["placeholder"])
    )

    result = check_all(snapshot, signature_backend=_AlwaysValidBackend())

    codes = [v.code for check in result.checks for v in check.violations]
    assert SIGNATURE_GATE not in codes, codes
    assert result.verdict == VERDICT_OK, result.verdict
    assert result.signature.status == SIGNATURE_UNVERIFIED


# --------------------------------------------------------------------------- #
# end to end: the exit code an operator reads
# --------------------------------------------------------------------------- #
def _corpus_with_key(tmp_path: Path, public_key_base64: str | None) -> Path:
    root = tmp_path / "corpus"
    (root / "clean").mkdir(parents=True, exist_ok=True)
    for src in (RECORDED / "clean").glob("*.json"):
        shutil.copy2(src, root / "clean" / src.name)
    if public_key_base64 is not None:
        path = root / "clean" / "journal_checkpoint.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["publicKeyBase64"] = public_key_base64
        path.write_text(json.dumps(raw), encoding="utf-8")
    return root


def _run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFY_REPORT), "--corpus", "recorded", "--half", "clean",
         "--corpus-root", str(root)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )


def test_FIRES_the_CLI_refuses_to_exit_0_on_an_unparseable_key(tmp_path):
    result = _run(_corpus_with_key(tmp_path, _unparseable_keys()["placeholder"]))
    assert result.returncode != 0, "fail-closed: an unread key must never leave a green exit"
    assert result.returncode == 2, (result.returncode, result.stderr[-600:])
    assert "NOT cryptographically verified" in result.stderr


def test_SILENT_the_CLI_on_the_untouched_shipped_corpus_is_not_dragged_red(tmp_path):
    from ledger_verification_agent.mldsa_openssl_backend import OpensslCliMlDsaBackend

    result = _run(_corpus_with_key(tmp_path, None))
    expected = 0 if OpensslCliMlDsaBackend().available() else 2
    assert result.returncode == expected, (result.returncode, result.stderr[-600:])
