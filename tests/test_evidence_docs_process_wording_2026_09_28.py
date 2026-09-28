"""Run A delta gate A6 (2026-09-28): the two evidence documents that still named the project's
internal process role (``CEO``) use neutral wording. RED at 5801b5c: phase0-blocked-items.md:6, :17,
:104 and preflight.txt:66. The meaning of each sentence is unchanged (the decision belongs to the
project owner)."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRUBBED = ("docs/evidence/phase0-blocked-items.md", "docs/evidence/preflight.txt")
PROCESS_WORDING_RE = re.compile(r"\bCEO\b|checkpoint CP-\d", re.I)


def process_wording_hits(named_texts: list[tuple[str, str]]) -> list[str]:
    return [name + ":" + str(number) for name, text in named_texts
            for number, line in enumerate(text.splitlines(), start=1) if PROCESS_WORDING_RE.search(line)]


def test_positive_control_the_checker_fires_on_planted_process_wording():
    assert process_wording_hits([("x", "fine\ngated behind the CEO's D-1.1")]) == ["x:2"]
    assert process_wording_hits([("x", "gated behind the project owner's D-1.1")]) == []


def test_A6_the_scrubbed_evidence_documents_carry_no_process_wording():
    texts = [(name, (REPO_ROOT / name).read_text(encoding="utf-8")) for name in SCRUBBED]
    assert all(text for _, text in texts)
    hits = process_wording_hits(texts)
    print("process-wording hits:", hits)
    assert hits == []
