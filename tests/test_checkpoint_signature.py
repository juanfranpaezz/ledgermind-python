"""The checkpoint plane: canonical message, key structure, and the signature status.

The distinction this file exists to protect: **"could not verify" is not "invalid"**.
LedgerMind's own ``MlDsaJournalSigner.verify`` javadoc says a structural failure that
gets dressed up as a bad signature makes ``audit()`` shout a false "MANIPULACION
DETECTADA". The Python side must not reintroduce that, so a backend that is missing,
or that blows up, yields ``UNVERIFIED-SIGNATURE`` and never ``INVALID``.

Every status the report can emit is driven here by an injected backend, so all four
are exercised on this machine regardless of what crypto library happens to exist.
"""

from __future__ import annotations

import base64
import dataclasses
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from ledger_verification_agent.checkpoint_signature import (  # noqa: E402
    ML_DSA_65_OID,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    canonical_checkpoint_message,
    default_backend,
    parse_spki,
    structural_findings,
    verify_checkpoint,
)
from ledger_verification_agent.ledger_snapshot import load_recorded  # noqa: E402
from ledger_verification_agent.mldsa_openssl_backend import OpensslCliMlDsaBackend  # noqa: E402
from ledger_verification_agent.verdict import (  # noqa: E402
    SIGNATURE_ABSENT,
    SIGNATURE_INVALID,
    SIGNATURE_UNVERIFIED,
    SIGNATURE_VERIFIED,
)


@pytest.fixture()
def checkpoint():
    cp = load_recorded("clean").checkpoint
    assert cp is not None
    return cp


# --------------------------------------------------------------------------- #
# the canonical message - the byte string the Java actually signs
# --------------------------------------------------------------------------- #
def test_the_canonical_message_is_byte_for_byte_the_java_format():
    assert canonical_checkpoint_message(5, "abc") == "ledgermind:journal-checkpoint:v1:5:abc"


def test_the_recorded_checkpoint_carries_exactly_that_message(checkpoint):
    assert checkpoint.signed_message == canonical_checkpoint_message(
        checkpoint.chain_seq, checkpoint.head_hash
    )


def test_FIRES_when_the_signed_message_was_rewritten(checkpoint):
    forged = dataclasses.replace(checkpoint, signed_message="ledgermind:journal-checkpoint:v1:9:x")
    problems = structural_findings(forged).problems
    assert any("signedMessage is not the canonical string" in problem for problem in problems)


# --------------------------------------------------------------------------- #
# the key - parsed with no dependency at all
# --------------------------------------------------------------------------- #
def test_the_public_key_parses_as_an_ML_DSA_65_SubjectPublicKeyInfo(checkpoint):
    oid, raw = parse_spki(base64.b64decode(checkpoint.public_key_base64))
    assert oid == ML_DSA_65_OID
    assert len(raw) == ML_DSA_65_PUBLIC_KEY_BYTES
    assert len(base64.b64decode(checkpoint.signature_base64)) == ML_DSA_65_SIGNATURE_BYTES


def test_SILENT_the_shipped_checkpoint_is_structurally_sound_on_both_halves():
    for half in ("clean", "tampered"):
        cp = load_recorded(half).checkpoint
        findings = structural_findings(cp)
        assert findings.problems == ()
        assert findings.key_algorithm_matches_declared is True
        assert findings.canonical_message_matches is True


def test_FIRES_when_the_declared_algorithm_disagrees_with_the_key_itself(checkpoint):
    """A DB writer that rewrites only the algorithm column must not slip through."""
    relabelled = dataclasses.replace(checkpoint, algorithm="Ed25519")
    problems = structural_findings(relabelled).problems
    assert any("does not agree with the key" in problem for problem in problems)


def test_FIRES_on_a_truncated_public_key(checkpoint):
    raw = base64.b64decode(checkpoint.public_key_base64)
    truncated = dataclasses.replace(
        checkpoint, public_key_base64=base64.b64encode(raw[:200]).decode("ascii")
    )
    assert structural_findings(truncated).problems


def test_FIRES_on_a_signature_of_the_wrong_length(checkpoint):
    short = dataclasses.replace(checkpoint, signature_base64=base64.b64encode(b"x" * 10).decode())
    assert any("ML-DSA-65 signatures are" in p for p in structural_findings(short).problems)


def test_parse_spki_refuses_junk():
    with pytest.raises(ValueError):
        parse_spki(b"\x01\x02\x03")


# --------------------------------------------------------------------------- #
# the four statuses, each driven by an injected backend
# --------------------------------------------------------------------------- #
class _Backend:
    def __init__(self, answer):
        self.name = "test-double"
        self._answer = answer

    def verify(self, message, signature, public_key_der):
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


def test_VERIFIED_when_the_backend_says_the_signature_closes(checkpoint):
    report = verify_checkpoint(checkpoint, backend=_Backend(True))
    assert report.status == SIGNATURE_VERIFIED
    assert report.is_cryptographically_verified is True
    assert "NOT signer authenticity" in report.reason


def test_INVALID_when_the_backend_says_it_does_not_close(checkpoint):
    report = verify_checkpoint(checkpoint, backend=_Backend(False))
    assert report.status == SIGNATURE_INVALID
    assert report.is_cryptographically_verified is False


def test_a_BROKEN_backend_is_UNVERIFIED_and_never_INVALID(checkpoint):
    """The load-bearing distinction: a structural failure is not evidence of tamper."""
    report = verify_checkpoint(checkpoint, backend=_Backend(RuntimeError("provider missing")))
    assert report.status == SIGNATURE_UNVERIFIED
    assert "not evidence" in report.reason


def test_NO_CHECKPOINT_when_the_snapshot_carries_none():
    assert verify_checkpoint(None).status == SIGNATURE_ABSENT


def test_the_DEFAULT_path_never_claims_more_than_it_proved(checkpoint):
    report = verify_checkpoint(checkpoint)
    if default_backend() is None:
        assert report.status == SIGNATURE_UNVERIFIED
        assert report.backend == "none"
        assert "no in-process ML-DSA library is importable" in report.reason
    else:  # pragma: no cover - only on a machine that ships one
        assert report.status in (SIGNATURE_VERIFIED, SIGNATURE_INVALID)
    # either way the structural plane was still checked and is reported
    assert report.structural["key_algorithm_oid"] == ML_DSA_65_OID
    assert report.structural["problems"] == []
    assert report.citations


# --------------------------------------------------------------------------- #
# the opt-in OpenSSL backend, against the REAL post-quantum signature
# --------------------------------------------------------------------------- #
def test_the_optin_openssl_backend_on_the_real_checkpoint_both_ways(checkpoint):
    backend = OpensslCliMlDsaBackend()
    if not backend.available():
        # No openssl >= 3.5 here: the documented contract is a loud refusal, never a
        # quiet False that would read as "the signature is bad".
        with pytest.raises(RuntimeError):
            backend.verify(b"message", b"signature", b"key")
        return

    report = verify_checkpoint(checkpoint, backend=backend)
    assert report.status == SIGNATURE_VERIFIED
    assert report.backend == "openssl-cli"

    flipped = dataclasses.replace(checkpoint, head_hash="f" * 64)
    assert backend.verify(
        canonical_checkpoint_message(flipped.chain_seq, flipped.head_hash).encode("utf-8"),
        base64.b64decode(checkpoint.signature_base64),
        base64.b64decode(checkpoint.public_key_base64),
    ) is False


def test_an_absent_binary_makes_the_backend_unavailable_rather_than_wrong():
    backend = OpensslCliMlDsaBackend(binary="definitely-not-openssl-on-this-machine")
    assert backend.version() is None
    assert backend.available() is False
    with pytest.raises(RuntimeError):
        backend.verify(b"m", b"s", b"k")
