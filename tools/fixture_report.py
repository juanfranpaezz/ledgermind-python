"""AC-0.2's checker: count fixture files and distinct verdicts in a corpus.

Plan reference: manifest v1 AC-0.2 - "fixture_files >= 6 AND distinct_verdicts >= 2",
checked by ``py -m tools.fixture_report``. Section 2.6 adds the binding constraint
that makes this checker non-trivial: the tampered half of the corpus must come from
a real ``POST /api/demo/tamper`` against a running LedgerMind, NOT from a hand-built
file, because "a hand-edited fixture proves the test, not the instrument".

That constraint is enforced HERE, in the checker, rather than left to a reader's
good faith: a corpus whose ``_corpus.json`` says ``ac_0_2_eligible: false`` can never
make this tool exit 0, no matter how many files it holds or how many distinct
verdicts it contains. The source-derived corpus this repository ships today is
marked ineligible on purpose. Without that rule the tool would happily certify
AC-0.2 against fixtures that were computed rather than captured, which is precisely
the failure mode AC-0.2 exists to prevent.

Usage::

    py -m tools.fixture_report                      # the recorded corpus (AC-0.2's real subject)
    py -m tools.fixture_report --corpus derived     # the source-derived corpus
    py -m tools.fixture_report --corpus <path>      # any corpus directory

Exit code 0 means AC-0.2 is MET for that corpus. Any other outcome exits 1.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures"
CORPUS_ALIASES = {
    "recorded": FIXTURE_ROOT / "recorded",
    "derived": FIXTURE_ROOT / "derived_from_source",
}

MIN_FIXTURE_FILES = 6
MIN_DISTINCT_VERDICTS = 2
VERDICT_KEY = "verdict"
CORPUS_METADATA_FILE = "_corpus.json"


def _iter_fixture_files(root: Path):
    """Every JSON fixture in the corpus, excluding the corpus metadata sidecar."""
    for path in sorted(root.rglob("*.json")):
        if path.name == CORPUS_METADATA_FILE:
            continue
        yield path


def _verdicts(paths):
    """Distinct values of the ledger's own ``verdict`` field across the corpus."""
    found = set()
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get(VERDICT_KEY), str):
            found.add(payload[VERDICT_KEY])
    return found


def _eligibility(root: Path):
    """(eligible, reason) read from the corpus metadata sidecar. Absent metadata is not eligible."""
    meta_path = root / CORPUS_METADATA_FILE
    if not meta_path.exists():
        return False, "no " + CORPUS_METADATA_FILE + " in the corpus; provenance unknown"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return False, CORPUS_METADATA_FILE + " unreadable: " + str(exc)
    eligible = bool(meta.get("ac_0_2_eligible", False))
    reason = meta.get("ac_0_2_reason", "no reason recorded")
    return eligible, reason


def report(root: Path) -> int:
    print("CORPUS_PATH: " + str(root))
    if not root.exists():
        print("CORPUS_KIND: absent")
        print("fixture_files: 0")
        print("distinct_verdicts: 0")
        print("AC_0_2_ELIGIBLE: no  (corpus directory does not exist)")
        print("AC_0_2: NOT MET")
        return 1

    eligible, reason = _eligibility(root)
    meta_path = root / CORPUS_METADATA_FILE
    kind = "unknown"
    if meta_path.exists():
        try:
            kind = json.loads(meta_path.read_text(encoding="utf-8")).get("corpus_kind", "unknown")
        except (json.JSONDecodeError, OSError):
            kind = "unknown"

    paths = list(_iter_fixture_files(root))
    verdicts = _verdicts(paths)

    print("CORPUS_KIND: " + str(kind))
    print("fixture_files: " + str(len(paths)))
    print("distinct_verdicts: " + str(len(verdicts)))
    for v in sorted(verdicts):
        print("  verdict: " + v[:80])
    print("AC_0_2_ELIGIBLE: " + ("yes" if eligible else "no") + "  (" + reason[:160] + ")")

    failures = []
    if not eligible:
        failures.append("corpus is not AC-0.2 eligible (not recorded from a running stack)")
    if len(paths) < MIN_FIXTURE_FILES:
        failures.append("fixture_files " + str(len(paths)) + " < " + str(MIN_FIXTURE_FILES))
    if len(verdicts) < MIN_DISTINCT_VERDICTS:
        failures.append("distinct_verdicts " + str(len(verdicts)) + " < " + str(MIN_DISTINCT_VERDICTS))

    if failures:
        print("AC_0_2: NOT MET")
        for f in failures:
            print("  reason: " + f)
        return 1
    print("AC_0_2: MET")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AC-0.2 fixture corpus report")
    parser.add_argument(
        "--corpus",
        default="recorded",
        help="recorded | derived | an explicit corpus directory path",
    )
    args = parser.parse_args(argv)
    root = CORPUS_ALIASES.get(args.corpus, Path(args.corpus))
    return report(root)


if __name__ == "__main__":
    sys.exit(main())
