"""Interpret the Java ledger's own audit report (plan v2 section 3.2) and compare it with the Python
verdict (the differential ``agree``). Standard library only; nothing here calls Java or recomputes
anything: the input is the JSON of ``JournalCheckpointService.JournalIntegrityReport`` as the Java
MCP tool ``verify_journal_integrity`` / the audit endpoint returns it.

Java record (LedgerMind ``JournalCheckpointService.java:528-538``, read 2026-09-26 at f9a0956):
``tamperDetected, verdict, coverageDegraded, coverageReason, chainIntact, chainedCount, brokenAtSeq,
checkpointPresent, signatureAlgorithm, signedChainSeq, signedHeadHash, signatureValid,
signedHeadStillInChain, signedHeadIsLatest, signedAt, balancesConsistent, accountsChecked,
balanceMismatches, unchainedPostings, staleUnchainedPostings, unchainedGraceMs``.
``enum CoverageReason { ATRASADO, DETENIDO, SIN_CHECKPOINT }`` (same file, :319).
Its Javadoc (:522-526): ``tamperDetected`` = ONLY confirmed evidence; coverage states are NOT tamper.
Captures made before 2026-09-24 have no ``coverageDegraded``: those map on the ``legacy`` basis.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

JAVA_BACKEND = "java-ledger-audit"


def holds_non_finite(value: Any) -> bool:
    """True when a parsed JSON value holds NaN or an infinity anywhere (``json.loads`` turns ``NaN``,
    ``Infinity`` and an overflow such as ``1e999`` into those floats). Parity gate r2 A3 (2026-09-27):
    the service refuses such an audit with 422 instead of echoing it in ``native`` as null, which would
    silently change the uploaded report. Iterative, so depth never raises."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, float) and not math.isfinite(item):
            return True
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False
REQUIRED_BOOLEANS = ("tamperDetected", "chainIntact", "checkpointPresent")
COVERAGE_INCOMPLETE = frozenset({"SIN_CHECKPOINT"})
COVERAGE_DEGRADED_REASONS = frozenset({"ATRASADO", "DETENIDO"})

# Java's own blind-spot list (LedgerMcpTools.java:59-100, "NO DETECTA"), condensed.
JAVA_DOES_NOT_DETECT = (
    "VERIFIED means no evidence of what the Java audit detects, not 'journal intact'.",
    "The audit is whatever JSON was uploaded: it is not fetched from the live ledger and its provenance "
    "is not authenticated.",
    "Not detected when the same database writer also adjusts the balance counters: inserting a posting "
    "(inside the grace window, or any date once the chainer has passed), editing or deleting a posting "
    "not yet chained.",
    "Not detected: editing or deleting a posting in the chained tail AFTER the last signed checkpoint when "
    "the links are recomputed (the next checkpoint signs the forged version), or truncating that tail.",
    "Not detected: an actor with full write access who rewrites postings, chain and checkpoint consistently.",
    "signatureValid is message integrity under the key the checkpoint itself stores, not signer "
    "authenticity: proving WHO signed needs a key anchored outside the database.",
    "Coverage states (ATRASADO, DETENIDO, SIN_CHECKPOINT) mean 'cannot confirm now'; they are not tamper "
    "and not a clean result.",
)


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def java_status(audit: Mapping[str, Any]) -> tuple[str, str, str | None]:
    """Return ``(status, mapping_basis, error_code)`` for a Java audit report, per plan v2 section 3.2.

    Worst wins: ``tamperDetected=true`` is TAMPER_SUSPECTED whatever coverage says. A shape this
    mapping does not know is ERROR ``unknown_shape``, never a guess.
    """
    missing = [name for name in REQUIRED_BOOLEANS if not _is_bool(audit.get(name))]
    if missing:
        basis = "field" if "coverageDegraded" in audit else "legacy"
        return "ERROR", basis, "unknown_shape"
    if "coverageDegraded" in audit:
        # Rule 1 comes before the coverage type check (plan v2 section 3.2, pinned 2026-09-28, F2): a
        # coverageDegraded that is not a boolean must never hide a tamper signal.
        if audit["tamperDetected"]:
            return "TAMPER_SUSPECTED", "field", None
        degraded = audit["coverageDegraded"]
        if not _is_bool(degraded):
            return "ERROR", "field", "unknown_shape"
        if degraded:
            reason = audit.get("coverageReason")
            if not isinstance(reason, str):  # null, array, object, number: unknown (an array or object is unhashable)
                return "ERROR", "field", "unknown_shape"
            if reason in COVERAGE_INCOMPLETE:
                return "INCOMPLETE", "field", None
            if reason in COVERAGE_DEGRADED_REASONS:
                return "COVERAGE_DEGRADED", "field", None
            return "ERROR", "field", "unknown_shape"
        if not audit["checkpointPresent"]:
            return "INCOMPLETE", "field", None
        return "VERIFIED", "field", None
    if audit["tamperDetected"]:
        return "TAMPER_SUSPECTED", "legacy", None
    if audit["checkpointPresent"]:
        return "VERIFIED", "legacy", None
    return "INCOMPLETE", "legacy", None


def java_tamper_proven(audit: Mapping[str, Any]) -> bool:
    """``tamperDetected AND (!chainIntact OR (checkpointPresent AND (!signatureValid OR
    !signedHeadStillInChain)))``. A field that is absent or not a boolean proves nothing (only an
    explicit ``false`` counts); ``balancesConsistent=false`` alone is not proven."""
    if audit.get("tamperDetected") is not True:
        return False
    if audit.get("chainIntact") is False:
        return True
    if audit.get("checkpointPresent") is True:
        return audit.get("signatureValid") is False or audit.get("signedHeadStillInChain") is False
    return False


def _check(name: str, value: Any, detail: str) -> dict[str, Any]:
    result = "pass" if value is True else "fail" if value is False else "no_data"
    return {"name": name, "result": result, "violations": 1 if value is False else 0, "detail": detail}


def _signature(audit: Mapping[str, Any]) -> dict[str, Any]:
    if audit.get("checkpointPresent") is not True:
        status = "absent"
    elif audit.get("signatureValid") is True:
        status = "verified"
    elif audit.get("signatureValid") is False:
        status = "invalid"
    else:
        status = "unknown"
    algorithm = audit.get("signatureAlgorithm")
    return {"status": status, "algorithm": algorithm if isinstance(algorithm, str) else None}


def map_java(audit: Mapping[str, Any], subject: str) -> dict[str, Any]:
    """The Java audit report as a UniformVerdict (without request_id / duration_ms). ``native`` is the
    uploaded report, unmodified."""
    status, basis, error_code = java_status(audit)
    notes = []
    if error_code is not None:
        shape = (error_code + ": the audit report does not have the shape this mapping knows "
                              "(required booleans tamperDetected, chainIntact, checkpointPresent; "
                              "coverageReason in ATRASADO, DETENIDO, SIN_CHECKPOINT when coverage is degraded). ")
        if audit.get("tamperDetected") is True:  # pinned 2026-09-28 (F2): never "not a tamper finding" here
            notes.append(shape + "Nothing was concluded from the report's shape, but the upload says "
                                 "tamperDetected=true: read it as a possible tamper, never as a clean result.")
        elif "tamperDetected" in audit and audit["tamperDetected"] is not False:
            # Present but not the JSON boolean false (e.g. the string "true"): the upload may be claiming a
            # tamper, so this is not a clean result either (pinned 2026-09-28, pre-publish).
            notes.append(shape + "Nothing was concluded, and tamperDetected is present but is not the JSON "
                                 "boolean false, so the tamper question is unanswered: never read this as a "
                                 "clean result.")
        else:
            notes.append(shape + "Nothing was concluded; this is not a tamper finding.")
    if status == "TAMPER_SUSPECTED" and "coverageDegraded" in audit and not _is_bool(audit["coverageDegraded"]):
        notes.append("coverageDegraded is not a boolean; it was not read, because tamperDetected=true wins "
                     "(worst wins)")
    if basis == "legacy":
        notes.append("legacy shape: no coverageDegraded field (a capture made before the coverage fields existed)")
    if audit.get("coverageDegraded") is True and isinstance(audit.get("coverageReason"), str):
        notes.append("coverageReason: " + audit["coverageReason"])
    verdict_text = audit.get("verdict")
    if isinstance(verdict_text, str) and verdict_text:
        notes.append("java verdict text: " + verdict_text[:500])
    signed_at = audit.get("signedAt")
    return {
        "schema_version": "1",
        "backend": JAVA_BACKEND,
        "status": status,
        "tamper_proven": status == "TAMPER_SUSPECTED" and java_tamper_proven(audit),
        "coverage_degraded": audit.get("coverageDegraded") is True,
        "frozen_accounts": None,
        "checks": [
            _check("hash_chain", audit.get("chainIntact"), "chainIntact"),
            _check("checkpoint_signature", audit.get("signatureValid") if audit.get("checkpointPresent") is True
                   else None, "signatureValid (only when checkpointPresent)"),
            _check("signed_head_in_chain", audit.get("signedHeadStillInChain")
                   if audit.get("checkpointPresent") is True else None, "signedHeadStillInChain"),
            _check("balances", audit.get("balancesConsistent"), "balancesConsistent (absent in legacy captures)"),
        ],
        "signature": _signature(audit),
        "subject": subject,
        "evidence_time": signed_at if isinstance(signed_at, str) else None,
        "does_not_detect": list(JAVA_DOES_NOT_DETECT),
        "mapping_basis": basis,
        "exit_code": None,
        "native": dict(audit),
        "notes": notes,
    }


NOT_COMPARABLE_PYTHON = frozenset({"INCOMPLETE", "ERROR"})
NOT_COMPARABLE_JAVA = frozenset({"COVERAGE_DEGRADED", "INCOMPLETE", "ERROR"})


def agree(java: str, python: str | None) -> str | None:
    """Differential (plan v2 section 3.2): None without a Python side; NOT_COMPARABLE when either side
    could not reach a verdict; else YES iff both say TAMPER_SUSPECTED or both do not. It compares two
    readings of whatever was uploaded; it does not authenticate either input."""
    if python is None:
        return None
    if python in NOT_COMPARABLE_PYTHON or java in NOT_COMPARABLE_JAVA:
        return "NOT_COMPARABLE"
    return "YES" if (python == "TAMPER_SUSPECTED") == (java == "TAMPER_SUSPECTED") else "NO"
