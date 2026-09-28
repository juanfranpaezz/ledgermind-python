"""CLI over the Phase-1 deterministic verifier. Prints the verdict a reviewer can re-derive.

Usage::

    py -m tools.verify_report --corpus recorded --half clean
    py -m tools.verify_report --corpus recorded --half tampered --json
    py -m tools.verify_report --corpus adversarial --case overdraft_account
    py -m tools.verify_report --corpus recorded --half clean --mldsa-openssl

Exit codes, chosen so the tool is usable as a gate:

* ``0`` - verdict OK: every check ran and nothing was violated.
* ``1`` - verdict TAMPERED: at least one invariant was proven broken. This is the
  CORRECT and expected exit for the tampered fixture.
* ``2`` - verdict INCOMPLETE: a check had no data. Never treated as a pass.
* ``3`` - the tool itself could not run (bad arguments, missing corpus).

THE SIGNATURE LEG CAN NEVER EXIT 0 UNVERIFIED (fixed 2026-09-22, live-ledger finding A1).
Until that date the ML-DSA backend was opt-in behind ``--mldsa-openssl`` and the flagless
command printed ``UNVERIFIED-SIGNATURE`` while still exiting ``0``. Measured on a real
Docker LedgerMind with ONE byte of the signature flipped: the shipped flagless command
said ``OK, EXIT=0`` on a machine that HAD a working OpenSSL 3.5.5 verifier installed. A
detector that is structurally unable to go red is worse than no detector, because it
produces confident green over forged data. Two changes close it:

1. the OpenSSL backend is AUTO-SELECTED when ``openssl >= 3.5`` is on PATH, so the
   default command verifies the signature for real. ``--mldsa-openssl`` still exists and
   now means "REQUIRE it": if openssl is missing the tool errors instead of degrading.
2. when no backend can be resolved at all and the snapshot DOES carry a checkpoint, the
   run exits ``2`` (INCOMPLETE), never ``0``. "Could not verify" is still not evidence of
   tamper - the VERDICT object is untouched and keeps reporting OK/UNVERIFIED-SIGNATURE -
   but the CLI's exit code, which is what a gate reads, refuses to say "pass".

REMOVING THE EVIDENCE IS NOT CHEAPER THAN FORGING IT (2026-09-22, residual A1 of the
adversarial verification). Forging the signature in any way - a flipped byte, an empty or
truncated value, a rewritten algorithm, a signature over other content - exits 1 or 2. But
DELETING ``journal_checkpoint.json`` from a recorded corpus used to exit ``0`` with a
``NO-CHECKPOINT`` note: the same "a check that cannot go red" shape as the defect above,
reached by removal instead of forgery. The exit code now splits on WHERE THE CORPUS COMES
FROM, because the absence means opposite things on the two corpora:

* ``--corpus recorded``: the recorder ALWAYS fetches and saves ``/api/journal/checkpoint``
  (record_fixtures.capture_half), so a recorded snapshot without one is a broken or a
  stripped capture - evidence that should be there is gone. That is INCOMPLETE, exit ``2``.
* ``--corpus adversarial``: the derived fixtures legitimately carry no checkpoint at all
  (``load_adversarial`` hard-codes ``checkpoint=None``), so there is nothing missing and
  nothing to forge. Exit ``0`` is kept, unchanged - treating it as a failure would make the
  whole adversarial suite unusable, which would be worse than the hole it closes.

As with the UNVERIFIED gate, the VERDICT object is NOT re-labelled: absence of a checkpoint
is not evidence of tamper, and a corpus that already PROVED tamper keeps exit ``1``.

``--corpus-root`` (2026-09-22, live-ledger finding A2) points the tool at a corpus
OUTSIDE the repo, so verifying a fresh live capture no longer requires copying the repo.
For ``--corpus recorded`` it is the directory that CONTAINS ``clean/`` and ``tampered/``;
for ``--corpus adversarial`` it is the directory that contains the ``<case>.json`` files.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# src-layout bootstrap: the package is not installed in Phase 1 (pyproject ships zero
# runtime dependencies and nobody pip-installs it to run a checker). pytest gets this
# from [tool.pytest.ini_options] pythonpath; a bare `py -m tools.verify_report` does not.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ledger_verification_agent.deterministic_verifier import check_all  # noqa: E402
from ledger_verification_agent.ledger_snapshot import load_adversarial, load_recorded  # noqa: E402
from ledger_verification_agent.verdict import (  # noqa: E402
    SIGNATURE_ABSENT,
    SIGNATURE_UNVERIFIED,
    VERDICT_INCOMPLETE,
    VERDICT_OK,
    VERDICT_TAMPERED,
    LedgerVerdict,
)

EXIT_OK = 0
EXIT_TAMPERED = 1
EXIT_INCOMPLETE = 2
EXIT_TOOL_ERROR = 3


def render(result: LedgerVerdict) -> str:
    lines = [
        "LEDGER VERIFICATION - deterministic checker (no model involved)",
        "subject: " + result.subject,
        "verdict: " + result.verdict,
        "violations: " + str(result.violation_count),
        "",
    ]
    for check in result.checks:
        lines.append(check.check + ": " + check.status + " (" + str(check.violation_count) + " violations)")
        lines.append("    examined: " + json.dumps(dict(check.examined), default=str))
        for note in check.notes:
            lines.append("    note: " + note)
        for violation in check.violations:
            lines.append("    VIOLATION [" + violation.code + "] " + violation.message)
            for citation in violation.citations:
                lines.append("        cite " + citation.ref + " <- " + citation.source
                             + (" (" + citation.detail + ")" if citation.detail else ""))
        lines.append("")
    signature = result.signature
    lines.append("checkpoint signature: " + signature.status
                 + " (backend " + signature.backend + ")")
    if signature.reason:
        lines.append("    " + signature.reason)
    if signature.structural:
        lines.append("    structural: " + json.dumps(dict(signature.structural), default=str))
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Phase-1 deterministic ledger verifier")
    parser.add_argument("--corpus", choices=("recorded", "adversarial"), default="recorded")
    parser.add_argument("--half", choices=("clean", "tampered"), default="clean")
    parser.add_argument("--case", default=None, help="adversarial fixture name, without .json")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--mldsa-openssl",
        action="store_true",
        help=(
            "REQUIRE the OpenSSL >= 3.5 CLI backend for the ML-DSA signature. It is now "
            "auto-selected when present; this flag makes its absence an error instead of a "
            "degraded run."
        ),
    )
    parser.add_argument(
        "--corpus-root",
        default=None,
        help=(
            "verify a corpus OUTSIDE the repo. For --corpus recorded: the directory holding "
            "clean/ and tampered/. For --corpus adversarial: the directory holding <case>.json."
        ),
    )
    args = parser.parse_args(argv)

    from ledger_verification_agent.mldsa_openssl_backend import OpensslCliMlDsaBackend

    # A1: auto-select. The signature leg must be able to go RED on the default command.
    candidate = OpensslCliMlDsaBackend()
    backend = candidate if candidate.available() else None
    if args.mldsa_openssl and backend is None:
        print(
            "ERROR: --mldsa-openssl was requested but no openssl >= 3.5 is on PATH",
            file=sys.stderr,
        )
        return EXIT_TOOL_ERROR

    corpus_root = Path(args.corpus_root) if args.corpus_root else None
    try:
        if args.corpus == "recorded":
            snapshot = load_recorded(args.half, root=corpus_root)
        else:
            if not args.case:
                print("ERROR: --corpus adversarial needs --case", file=sys.stderr)
                return EXIT_TOOL_ERROR
            snapshot = load_adversarial(args.case, root=corpus_root)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError) as exc:
        # OverflowError added 2026-09-27 (parity gate r1): 1e999 parses as inf and int(inf) overflows;
        # uncaught, that too left the process with exit 1 = TAMPERED.
        # A BROKEN CAPTURE AND A DETECTED FORGERY ARE NOT THE SAME EVENT (fixed 2026-09-22).
        # TypeError and AttributeError were missing from this tuple, so a `journal_checkpoint.json`
        # holding `null` - or any field that is null where a scalar is expected - escaped as an
        # UNCAUGHT exception. An uncaught exception leaves the interpreter with exit status 1,
        # which in this tool's taxonomy means TAMPERED. An operator, or a CI gate, reading exit
        # codes could not tell "the ledger was forged" from "the capture is garbage", and the
        # louder of the two readings is the wrong one. Malformed or unreadable input is a TOOL
        # ERROR: exit 3. Exit 1 is reserved for a verdict this tool actually reached.
        print(
            "ERROR: the corpus could not be READ, so NOTHING was verified ("
            + type(exc).__name__
            + ": "
            + str(exc)
            + "). This is a MALFORMED OR UNREADABLE CAPTURE - a missing file, unparseable JSON, "
            "a missing field, or a null where a value belongs. It is NOT a tamper finding: this "
            "tool never got far enough to have an opinion about the ledger. Exit 3 (tool error), "
            "never exit 1, which in this tool means TAMPERED.",
            file=sys.stderr,
        )
        return EXIT_TOOL_ERROR

    # Parity gate r2 A2 (2026-09-27): check_all and its print sat OUTSIDE any handler, so an input that
    # loads but crashes a check (measured: a lone surrogate like 'ORD-\ud800' in a hashed field raises
    # UnicodeEncodeError) left the interpreter with exit 1 = TAMPERED and no verdict. A crash while
    # checking is not a finding about the ledger: exit 3. The report text is built in full before the
    # print, so a crash never leaves half a verdict on stdout.
    try:
        result = check_all(snapshot, signature_backend=backend)
        report = json.dumps(result.as_dict(), indent=2, default=str) if args.as_json else render(result)
        print(report)
    except Exception as exc:  # noqa: BLE001 - any crash here is a tool error, never a verdict
        print(
            "ERROR: the checks CRASHED on this input, so NOTHING was verified ("
            + type(exc).__name__
            + "). The capture loaded but a value in it could not be processed. It is NOT a tamper "
            "finding. Exit 3 (tool error), never exit 1, which in this tool means TAMPERED.",
            file=sys.stderr,
        )
        return EXIT_TOOL_ERROR

    # A1, the load-bearing half: a checkpoint that exists and was NOT cryptographically
    # verified can never leave this tool with a success exit code.
    # Only when nothing else already proved tamper: a PROVEN break must keep exit 1 and
    # must never be softened into "incomplete".
    if (
        result.verdict == VERDICT_OK
        and result.signature is not None
        and result.signature.status == SIGNATURE_UNVERIFIED
    ):
        print(
            "INCOMPLETE: the snapshot carries a signed checkpoint that was NOT "
            "cryptographically verified (" + result.signature.reason + "). This is NOT "
            "evidence of tamper, and it is NOT a pass either: a forged signature is "
            "indistinguishable from a real one here, so the exit code refuses to say OK. "
            "Install openssl >= 3.5 (or pass --mldsa-openssl to make this an error).",
            file=sys.stderr,
        )
        return EXIT_INCOMPLETE

    # A1, the removal half: on a RECORDED corpus the checkpoint is never optional. The
    # recorder always captures /api/journal/checkpoint, so a recorded snapshot that carries
    # none is a stripped or broken capture and the evidence the signature plane rests on is
    # simply gone. Exiting 0 there would let an attacker skip the forgery entirely and just
    # DELETE the file. Adversarial fixtures are excluded on purpose: they never have a
    # checkpoint by construction, so for them absence is the normal case, not a loss.
    if (
        result.verdict == VERDICT_OK
        and args.corpus == "recorded"
        and result.signature is not None
        and result.signature.status == SIGNATURE_ABSENT
    ):
        print(
            "INCOMPLETE: this RECORDED snapshot carries NO signed checkpoint "
            "(journal_checkpoint.json is absent), so the chain head is anchored by nothing "
            "and there is no signature to check. The recorder always captures "
            "/api/journal/checkpoint, so a recorded corpus without one is a broken or a "
            "stripped capture. This is NOT evidence of tamper, and it is NOT a pass either: "
            "deleting the evidence must not be an easier way to a green exit than forging "
            "it. (Adversarial fixtures legitimately have no checkpoint and still exit 0.)",
            file=sys.stderr,
        )
        return EXIT_INCOMPLETE

    if result.verdict == VERDICT_OK:
        return EXIT_OK
    if result.verdict == VERDICT_TAMPERED:
        return EXIT_TAMPERED
    if result.verdict == VERDICT_INCOMPLETE:
        return EXIT_INCOMPLETE
    return EXIT_TOOL_ERROR


if __name__ == "__main__":
    sys.exit(main())
