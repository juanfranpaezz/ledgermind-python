"""The checkpoint plane: the canonical signed message, the key's structure, and the signature.

RE-DERIVED FROM PRIMARY SOURCE (read-only, 2026-09-17), from
``<ledgermind-checkout>/src/main/java/com/ledgermind/ledger/JournalCheckpointService.java``
at commit 872505f::

    public static String checkpointMessageString(long chainSeq, String headHash) {
        return "ledgermind:journal-checkpoint:v1:" + chainSeq + ":" + headHash;
    }

and from ``MlDsaJournalSigner.java``: ML-DSA-65 (FIPS 204) via BouncyCastle, key
published as base64 of ``getEncoded()`` i.e. an X.509 SubjectPublicKeyInfo, signature
as base64 of the raw ML-DSA signature.

WHAT IS DETERMINISTIC WITHOUT ANY CRYPTO LIBRARY, and is therefore always checked:

1. the checkpoint's ``signedMessage`` is byte-for-byte the canonical string the Java
   builds from its own ``chainSeq`` and ``headHash`` (catches a rewritten message);
2. the public key parses as a DER SubjectPublicKeyInfo whose algorithm OID is
   ``2.16.840.1.101.3.4.3.18`` = id-ml-dsa-65, and that OID AGREES with the declared
   ``algorithm`` string. LedgerMind's own ``signalsFor`` has this guard because a DB
   writer that rewrites only the ``algorithm`` column would otherwise print a false
   scheme; checking the OID inside the key is the stronger form of the same guard;
3. the raw key and signature have the ML-DSA-65 sizes (1952 / 3309 bytes).

WHAT NEEDS A LIBRARY. Actually verifying the ML-DSA signature. This package has ZERO
runtime dependencies by design, so the default backend resolution only looks for an
IN-PROCESS library; if none is importable the status is the explicit string
``UNVERIFIED-SIGNATURE`` with the reason attached. It is never silently reported as
valid, and it is never reported as INVALID either - "could not verify" is not
evidence of tamper, which is exactly the distinction ``MlDsaJournalSigner.verify``
makes in its own javadoc.

A backend may be passed in explicitly. ``mldsa_openssl_backend`` ships one that
shells out to an OpenSSL >= 3.5 CLI; it is deliberately NOT imported here, so the
verifier's own import closure stays free of ``subprocess`` and the default verdict
stays environment-independent.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Protocol

from .ledger_snapshot import Checkpoint
from .verdict import (
    SIGNATURE_ABSENT,
    SIGNATURE_INVALID,
    SIGNATURE_UNVERIFIED,
    SIGNATURE_VERIFIED,
    Citation,
    SignatureReport,
)

ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309

CHECKPOINT_MESSAGE_PREFIX = "ledgermind:journal-checkpoint:v1:"

UPSTREAM = "com.ledgermind.ledger.JournalCheckpointService @ 872505f"


def canonical_checkpoint_message(chain_seq: int, head_hash: str) -> str:
    """``JournalCheckpointService.checkpointMessageString`` - the exact signed string."""
    return CHECKPOINT_MESSAGE_PREFIX + str(chain_seq) + ":" + head_hash


class MlDsaBackend(Protocol):
    """A thing that can verify an ML-DSA signature. Injected, never auto-discovered."""

    name: str

    def verify(self, message: bytes, signature: bytes, public_key_der: bytes) -> bool:
        ...


# --- a minimal DER reader, so the key can be inspected with no dependency -----


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Return (tag, content, next_offset) for one DER TLV. Raises ValueError on junk."""
    if offset >= len(data):
        raise ValueError("truncated DER: no tag at offset " + str(offset))
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER: no length byte")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length form: " + hex(first))
        if offset + count > len(data):
            raise ValueError("truncated DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise ValueError("truncated DER content")
    return tag, data[offset : offset + length], offset + length


def _decode_oid(content: bytes) -> str:
    if not content:
        raise ValueError("empty OID")
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def parse_spki(der: bytes) -> tuple[str, bytes]:
    """Return (algorithm_oid, raw_public_key_bytes) from an X.509 SubjectPublicKeyInfo."""
    tag, content, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("SubjectPublicKeyInfo is not a SEQUENCE (tag " + hex(tag) + ")")
    alg_tag, alg_content, offset = _read_tlv(content, 0)
    if alg_tag != 0x30:
        raise ValueError("AlgorithmIdentifier is not a SEQUENCE (tag " + hex(alg_tag) + ")")
    oid_tag, oid_content, _ = _read_tlv(alg_content, 0)
    if oid_tag != 0x06:
        raise ValueError("AlgorithmIdentifier does not start with an OID")
    bit_tag, bit_content, _ = _read_tlv(content, offset)
    if bit_tag != 0x03:
        raise ValueError("subjectPublicKey is not a BIT STRING (tag " + hex(bit_tag) + ")")
    if not bit_content or bit_content[0] != 0:
        raise ValueError("subjectPublicKey has unused bits, which ML-DSA keys never do")
    return _decode_oid(oid_content), bit_content[1:]


@dataclass(frozen=True)
class StructuralFindings:
    """The library-free plane. ``problems`` empty == structurally sound."""

    canonical_message_matches: bool
    declared_algorithm: str
    key_algorithm_oid: str | None
    key_algorithm_matches_declared: bool
    public_key_bytes: int | None
    signature_bytes: int | None
    problems: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "canonical_message_matches": self.canonical_message_matches,
            "declared_algorithm": self.declared_algorithm,
            "key_algorithm_oid": self.key_algorithm_oid,
            "key_algorithm_matches_declared": self.key_algorithm_matches_declared,
            "public_key_bytes": self.public_key_bytes,
            "signature_bytes": self.signature_bytes,
            "problems": list(self.problems),
        }


def structural_findings(checkpoint: Checkpoint) -> StructuralFindings:
    """Everything that can be proven about the checkpoint with no crypto library."""
    problems: list[str] = []

    expected_message = canonical_checkpoint_message(checkpoint.chain_seq, checkpoint.head_hash)
    message_matches = checkpoint.signed_message == expected_message
    if not message_matches:
        problems.append(
            "signedMessage is not the canonical string for (chainSeq="
            + str(checkpoint.chain_seq)
            + ", headHash="
            + checkpoint.head_hash
            + "): stored="
            + repr(checkpoint.signed_message)
            + " expected="
            + repr(expected_message)
        )

    key_oid: str | None = None
    key_bytes: int | None = None
    try:
        key_oid, raw_key = parse_spki(base64.b64decode(checkpoint.public_key_base64, validate=True))
        key_bytes = len(raw_key)
    except ValueError as exc:  # binascii.Error (bad base64) is a ValueError subclass
        problems.append("public key does not parse as a DER SubjectPublicKeyInfo: " + str(exc))

    declared = checkpoint.algorithm
    oid_matches = key_oid == ML_DSA_65_OID and declared == "ML-DSA-65"
    if key_oid is not None and not oid_matches:
        problems.append(
            "declared algorithm " + repr(declared) + " does not agree with the key's OID "
            + repr(key_oid) + " (id-ml-dsa-65 is " + ML_DSA_65_OID + ")"
        )
    if key_bytes is not None and key_bytes != ML_DSA_65_PUBLIC_KEY_BYTES:
        problems.append(
            "public key is " + str(key_bytes) + " bytes, ML-DSA-65 keys are "
            + str(ML_DSA_65_PUBLIC_KEY_BYTES)
        )

    signature_bytes: int | None = None
    try:
        signature_bytes = len(base64.b64decode(checkpoint.signature_base64, validate=True))
    except ValueError as exc:  # binascii.Error again
        problems.append("signature is not valid base64: " + str(exc))
    if signature_bytes is not None and signature_bytes != ML_DSA_65_SIGNATURE_BYTES:
        problems.append(
            "signature is " + str(signature_bytes) + " bytes, ML-DSA-65 signatures are "
            + str(ML_DSA_65_SIGNATURE_BYTES)
        )

    return StructuralFindings(
        canonical_message_matches=message_matches,
        declared_algorithm=declared,
        key_algorithm_oid=key_oid,
        key_algorithm_matches_declared=oid_matches,
        public_key_bytes=key_bytes,
        signature_bytes=signature_bytes,
        problems=tuple(problems),
    )


def default_backend() -> MlDsaBackend | None:
    """In-process libraries ONLY. Returns None when none is importable.

    Deliberately does NOT reach for a CLI: the default verdict must not change
    depending on what happens to be installed on the box running it. Probed on this
    machine 2026-09-17: cryptography 46.0.5 exposes no ``mldsa`` module, so this
    returns None here and the status is ``UNVERIFIED-SIGNATURE``.
    """
    try:  # pragma: no cover - exercised only where the library exists
        from cryptography.hazmat.primitives.asymmetric import mldsa  # type: ignore
        from cryptography.hazmat.primitives.serialization import load_der_public_key  # type: ignore
    except ImportError:
        return None

    class _CryptographyBackend:  # pragma: no cover - see above
        name = "cryptography.mldsa"

        def verify(self, message: bytes, signature: bytes, public_key_der: bytes) -> bool:
            key = load_der_public_key(public_key_der)
            if not isinstance(key, mldsa.MLDSAPublicKey):
                raise TypeError("loaded key is not an ML-DSA public key")
            try:
                key.verify(signature, message)
            except Exception:
                return False
            return True

    return _CryptographyBackend()


def verify_checkpoint(
    checkpoint: Checkpoint | None,
    backend: MlDsaBackend | None = None,
    source: str = "journal_checkpoint.json",
) -> SignatureReport:
    """Report the checkpoint plane. Never conflates "could not verify" with "invalid"."""
    if checkpoint is None:
        return SignatureReport(
            status=SIGNATURE_ABSENT,
            reason="the snapshot carries no signed checkpoint",
        )

    findings = structural_findings(checkpoint)
    citation = Citation(
        kind="checkpoint",
        ref="checkpoint:chainSeq=" + str(checkpoint.chain_seq),
        source=source,
        detail="algorithm=" + checkpoint.algorithm + " headHash=" + checkpoint.head_hash,
    )

    # FAIL-CLOSED ON A KEY THIS CHECKER CANNOT READ (decision taken 2026-09-22).
    # The algorithm term further down is narrow on purpose: it fires only when the key PARSED
    # and its OID disagrees with the declared name, because "we could not read this key" is not
    # evidence of forgery. That narrowness is right and it stays. What was wrong was what
    # happened next: execution fell through to the backend, and a permissive backend answering
    # True produced status=VERIFIED over key bytes this checker never managed to parse - with
    # the declared algorithm unchecked, because the only term that checks it needs the OID the
    # parse failed to produce. A checker that cannot read the key has not verified anything, and
    # saying VERIFIED there claims more than was proven. So: UNVERIFIED, stated plainly, before
    # any backend runs. UNVERIFIED and never INVALID - "unreadable" must not become "forged",
    # which is the opposite over-firing mistake. Only INVALID gates the verdict
    # (deterministic_verifier.check_checkpoint_signature, H4), so this cannot manufacture a
    # TAMPERED finding; what it does is stop the run from reporting a pass, and on the CLI
    # verify_report turns OK + UNVERIFIED into exit 2 (INCOMPLETE) instead of exit 0.
    if findings.key_algorithm_oid is None:
        return SignatureReport(
            status=SIGNATURE_UNVERIFIED,
            algorithm=checkpoint.algorithm,
            chain_seq=checkpoint.chain_seq,
            head_hash=checkpoint.head_hash,
            backend="none",
            reason=(
                "the public key carried by the checkpoint row does NOT parse as a DER "
                "SubjectPublicKeyInfo, so this checker could not read the key the signature "
                "would have to close under. Nothing was cryptographically verified, and the "
                "declared algorithm (" + checkpoint.algorithm + ") could not be checked against "
                "the key's own OID because there is no OID to check it against. This is NOT "
                "evidence of tamper and it is NOT a pass: a checker that cannot read the key has "
                "verified nothing. The parse failure is named in the structural problems below."
            ),
            structural=findings.as_dict(),
            citations=(citation,),
        )

    resolved = backend if backend is not None else default_backend()
    if resolved is None:
        return SignatureReport(
            status=SIGNATURE_UNVERIFIED,
            algorithm=checkpoint.algorithm,
            chain_seq=checkpoint.chain_seq,
            head_hash=checkpoint.head_hash,
            backend="none",
            reason=(
                "no in-process ML-DSA library is importable, so the post-quantum signature was "
                "NOT cryptographically verified. This is not evidence of tamper. The structural "
                "plane below WAS checked. Pass a backend (see mldsa_openssl_backend) to verify."
            ),
            structural=findings.as_dict(),
            citations=(citation,),
        )

    try:
        valid = resolved.verify(
            canonical_checkpoint_message(checkpoint.chain_seq, checkpoint.head_hash).encode("utf-8"),
            base64.b64decode(checkpoint.signature_base64, validate=True),
            base64.b64decode(checkpoint.public_key_base64, validate=True),
        )
    except Exception as exc:  # noqa: BLE001 - structural failure, NOT a tamper verdict
        return SignatureReport(
            status=SIGNATURE_UNVERIFIED,
            algorithm=checkpoint.algorithm,
            chain_seq=checkpoint.chain_seq,
            head_hash=checkpoint.head_hash,
            backend=getattr(resolved, "name", type(resolved).__name__),
            reason=(
                "the backend could not complete the verification (structural cause, not evidence "
                "of tamper): " + type(exc).__name__ + ": " + str(exc)
            ),
            structural=findings.as_dict(),
            citations=(citation,),
        )

    # THE ALGORITHM COLUMN IS INSIDE THE VERIFICATION LOOP, not a label beside it (open list
    # 2026-09-20, item 4). LedgerMind folds exactly this term into signatureValid:
    #     JournalCheckpointService.signalsFor, lines 149-150 of the Java working tree
    #     boolean algorithmMatches = signer.algorithm().equals(cp.getAlgorithm());
    #     boolean signatureValid   = algorithmMatches && signer.verify(msg, sig, key);
    # and audit() (line 134) makes !signatureValid a TAMPERED verdict. Before this fold the
    # Python reported the disagreement as a structural note and returned VERIFIED / OK, i.e.
    # it passed a checkpoint its own subject calls tampered: an UNDER-firing divergence.
    # NARROW ON PURPOSE - it fires only when the key PARSED and its OID disagrees with the
    # declared name, so a corpus with placeholder key material cannot be flipped to INVALID by
    # this term (that would be the over-firing direction). Since 2026-09-22 a key that does not
    # parse never reaches this line at all: the fail-closed gate above returns UNVERIFIED before
    # any backend runs, because leaving an unreadable key to "the structural plane" still let a
    # permissive backend report VERIFIED with this term silently inert.
    algorithm_disagrees = (
        findings.key_algorithm_oid is not None and not findings.key_algorithm_matches_declared
    )
    if valid and algorithm_disagrees:
        reason = (
            "the ML-DSA signature closes over the message, but the DECLARED algorithm does not "
            "agree with the key's own OID. LedgerMind folds algorithmMatches into signatureValid "
            "(JournalCheckpointService.java:149-150), so its own audit() calls this tampered and "
            "so does this verifier: a rewritten algorithm column would otherwise print a false "
            "scheme over a real signature."
        )
    elif valid:
        reason = (
            "the signature closes under the key the checkpoint itself carries: message INTEGRITY, "
            "NOT signer authenticity - proving WHO signed needs a key anchored outside the DB"
        )
    else:
        reason = "the signature does NOT close under the key the checkpoint carries"

    return SignatureReport(
        status=SIGNATURE_VERIFIED if (valid and not algorithm_disagrees) else SIGNATURE_INVALID,
        algorithm=checkpoint.algorithm,
        chain_seq=checkpoint.chain_seq,
        head_hash=checkpoint.head_hash,
        backend=getattr(resolved, "name", type(resolved).__name__),
        reason=reason,
        structural=findings.as_dict(),
        citations=(citation,),
    )
