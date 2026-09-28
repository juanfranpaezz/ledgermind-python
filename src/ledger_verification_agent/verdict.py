"""The structured verdict object the deterministic verifier returns.

PHASE 1. This is the object the Phase-2 FastAPI endpoint will serialise as the
``verdict`` and ``citations[]`` half of ``POST /ask``. It is defined here, in the
deterministic layer, on purpose: **the model never produces a verdict**, it only
narrates one that this layer already decided.

Design rules that are load-bearing, not decoration:

* **Every violation carries citations.** A verdict that says "something is wrong"
  without naming the journal entry or the account is not usable by a reviewer and
  is not usable by an agent either. ``Violation.citations`` is never empty.
* **A check that could not run is NOT ``OK``.** ``CheckStatus.NO_DATA`` exists so a
  missing input cannot be silently read as a pass. A checker whose absent input
  returns green is the exact shape of an inert instrument.
* **The top-level vocabulary is frozen by the plan.** Manifest AC-1.1 requires
  ``verdict == "OK"`` on the clean corpus and AC-1.2 requires ``verdict ==
  "TAMPERED"`` on the tampered one. ``INCOMPLETE`` is the third value and is only
  reachable when a check had no data AND nothing was violated; it can never mask a
  violation, because violations are tested first.
* **No enum-by-string-comparison in the callers.** The counts they need
  (``violation_count``, ``conservation_violations``) are properties here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

# --- check names, frozen so tests and the Phase-2 API agree on the spelling ----
MONEY_CONSERVATION = "money_conservation"
NO_OVERDRAFT = "no_overdraft"
HASH_CHAIN_CONTINUITY = "hash_chain_continuity"

CHECK_NAMES: tuple[str, ...] = (MONEY_CONSERVATION, NO_OVERDRAFT, HASH_CHAIN_CONTINUITY)

# --- statuses -----------------------------------------------------------------
OK = "OK"
VIOLATION = "VIOLATION"
NO_DATA = "NO_DATA"

# --- top-level verdicts (AC-1.1 / AC-1.2 vocabulary) --------------------------
VERDICT_OK = "OK"
VERDICT_TAMPERED = "TAMPERED"
VERDICT_INCOMPLETE = "INCOMPLETE"

# --- signature statuses -------------------------------------------------------
SIGNATURE_VERIFIED = "VERIFIED"
SIGNATURE_INVALID = "INVALID"
SIGNATURE_UNVERIFIED = "UNVERIFIED-SIGNATURE"
SIGNATURE_ABSENT = "NO-CHECKPOINT"


@dataclass(frozen=True)
class Citation:
    """Where a finding comes from. The unit of evidence in the verdict."""

    kind: str       # "posting" | "account" | "chain_link" | "checkpoint" | "corpus"
    ref: str        # "posting:5" | "account:wallet:ana" | "chain_link:seq=5"
    source: str     # the fixture-relative file the value was read from
    detail: str = ""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "ref": self.ref, "source": self.source, "detail": self.detail}


@dataclass(frozen=True)
class Violation:
    """One proven breach of one invariant, with the evidence attached."""

    check: str
    code: str
    message: str
    citations: tuple[Citation, ...]

    def __post_init__(self) -> None:
        if not self.citations:
            raise ValueError(
                "a Violation without citations is not reportable: " + self.check + "/" + self.code
            )

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "code": self.code,
            "message": self.message,
            "citations": [c.as_dict() for c in self.citations],
        }


@dataclass(frozen=True)
class CheckVerdict:
    """The result of ONE invariant check over one snapshot."""

    check: str
    status: str
    violations: tuple[Violation, ...] = ()
    examined: Mapping[str, object] = field(default_factory=dict)
    citations: tuple[Citation, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "status": self.status,
            "violation_count": self.violation_count,
            "violations": [v.as_dict() for v in self.violations],
            "examined": dict(self.examined),
            "citations": [c.as_dict() for c in self.citations],
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class SignatureReport:
    """The checkpoint signature plane, reported SEPARATELY from the chain plane.

    LedgerMind's own javadoc (JournalCheckpointService.audit) is explicit that these
    are different planes and that conflating them destroys security information:
    ``signatureValid`` is message integrity against an accompanying key, NOT signer
    authenticity, and the tamper-evidence of the CONTENT comes from the SHA-256
    chain, not from the signature. This object keeps them apart.
    """

    status: str
    algorithm: str | None = None
    chain_seq: int | None = None
    head_hash: str | None = None
    backend: str = "none"
    reason: str = ""
    structural: Mapping[str, object] = field(default_factory=dict)
    citations: tuple[Citation, ...] = ()

    @property
    def is_cryptographically_verified(self) -> bool:
        return self.status == SIGNATURE_VERIFIED

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "algorithm": self.algorithm,
            "chain_seq": self.chain_seq,
            "head_hash": self.head_hash,
            "backend": self.backend,
            "reason": self.reason,
            "structural": dict(self.structural),
            "citations": [c.as_dict() for c in self.citations],
        }


@dataclass(frozen=True)
class LedgerVerdict:
    """What the Phase-2 endpoint returns. Produced HERE, never by a model."""

    verdict: str
    subject: str
    checks: tuple[CheckVerdict, ...]
    signature: SignatureReport

    @property
    def violations(self) -> tuple[Violation, ...]:
        out: list[Violation] = []
        for check in self.checks:
            out.extend(check.violations)
        return tuple(out)

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    def violations_of(self, check: str) -> tuple[Violation, ...]:
        return tuple(v for v in self.violations if v.check == check)

    @property
    def conservation_violations(self) -> int:
        """AC-1.3 names this quantity by name."""
        return len(self.violations_of(MONEY_CONSERVATION))

    @property
    def overdraft_violations(self) -> int:
        return len(self.violations_of(NO_OVERDRAFT))

    @property
    def chain_violations(self) -> int:
        return len(self.violations_of(HASH_CHAIN_CONTINUITY))

    def check(self, name: str) -> CheckVerdict:
        for candidate in self.checks:
            if candidate.check == name:
                return candidate
        raise KeyError("no such check in this verdict: " + name)

    @property
    def citations(self) -> tuple[Citation, ...]:
        out: list[Citation] = []
        for check in self.checks:
            out.extend(check.citations)
            for violation in check.violations:
                out.extend(violation.citations)
        out.extend(self.signature.citations)
        return tuple(out)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "subject": self.subject,
            "violation_count": self.violation_count,
            "conservation_violations": self.conservation_violations,
            "overdraft_violations": self.overdraft_violations,
            "chain_violations": self.chain_violations,
            "checks": [c.as_dict() for c in self.checks],
            "signature": self.signature.as_dict(),
        }


def decide(checks: tuple[CheckVerdict, ...]) -> str:
    """The top-level verdict. Violations dominate; NO_DATA can never mask one."""
    if any(check.violations for check in checks):
        return VERDICT_TAMPERED
    if any(check.status == NO_DATA for check in checks):
        return VERDICT_INCOMPLETE
    return VERDICT_OK
