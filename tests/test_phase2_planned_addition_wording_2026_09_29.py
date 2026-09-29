"""Guard: Phase 2 is described as a planned addition, not as blocked on an open decision (2026-09-29).

The scope is settled: the deterministic verifier and the optional FastAPI service are the complete
product, and Phase 2 (agent loop, evals, CI) is a planned addition after 2026-10-28, on a simulated
model at zero cost. The earlier text said Phase 2 waited on an undecided design question and that
the project was incomplete until an agent loop existed. This guard keeps both claims from returning
and keeps the settled scope stated in the README.

Stdlib only, so it runs in the zero-dependency core suite. Matching is done on whitespace-flattened
text, so a line wrap in the middle of a phrase cannot hide it. The two real-surface tests were shown
RED on the previous text of README.md, pyproject.toml, src/ledger_verification_agent/__init__.py and
tool_registry.py before being kept.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Wording that presents Phase 2 as blocked, or the project as incomplete without an agent loop.
STALE_PHASE2_PATTERNS = (
    re.compile(r"pending\s+design\s+decision", re.I),
    re.compile(r"Phase\s+2,\s+still\s+gated", re.I),
    re.compile(r"not\s+at\s+100\s*%\s+until\s+an\s+agent\s+loop", re.I),
)

# The settled scope, as the README must state it (flattened, case-sensitive).
DECIDED_SCOPE_PHRASES = (
    "Phase 2 (agent loop, evals, CI) is a planned addition after 2026-10-28",
    "on a simulated model at zero cost",
    "the verifier and the FastAPI service are complete",
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def wording_surfaces() -> list[Path]:
    files = [REPO / "README.md", REPO / "pyproject.toml"]
    files += sorted((REPO / "src").rglob("*.py"))
    files += sorted((REPO / "ledgermind_api").glob("*.py"))
    return files


def stale_phase2_hits(named_texts: list[tuple[str, str]]) -> list[str]:
    """Every stale Phase-2 phrase, as ``name: phrase`` (empty = none)."""
    hits = []
    for name, text in named_texts:
        flat = _flat(text)
        hits += [name + ": " + m.group(0) for pattern in STALE_PHASE2_PATTERNS for m in pattern.finditer(flat)]
    return hits


def missing_scope_phrases(readme: str) -> list[str]:
    flat = _flat(readme)
    return [phrase for phrase in DECIDED_SCOPE_PHRASES if phrase not in flat]


# ---- the checkers can fire (positive controls on planted text) ------------------------------

def test_positive_control_each_checker_fires_on_planted_text_and_passes_the_decided_text():
    assert stale_phase2_hits([("x", "those are\nPhase 2, which is gated behind a pending design\ndecision.")]) == [
        "x: pending design decision"
    ]
    assert stale_phase2_hits([("x", "any model transport are Phase 2,\nstill gated.")]) != []
    assert stale_phase2_hits([("x", '"LedgerMind Python" is not at\n100% until an agent loop exists.')]) != []
    decided = ("Phase 2 (agent loop, evals, CI) is a planned addition after\n2026-10-28, on a simulated model"
               " at zero cost; the verifier and the FastAPI service are complete.")
    assert stale_phase2_hits([("x", decided)]) == []
    assert missing_scope_phrases(decided) == []
    assert missing_scope_phrases("Phase 2 is not started.") == list(DECIDED_SCOPE_PHRASES)


def test_positive_control_the_surface_list_is_not_empty():
    names = {p.name for p in wording_surfaces()}
    assert {"README.md", "pyproject.toml", "__init__.py", "tool_registry.py"} <= names


# ---- the guards ------------------------------------------------------------------------------

def test_published_surfaces_do_not_present_phase2_as_blocked_or_the_project_as_incomplete():
    surfaces = wording_surfaces()
    hits = stale_phase2_hits([(str(p.relative_to(REPO)), p.read_text(encoding="utf-8")) for p in surfaces])
    print("surfaces scanned:", len(surfaces), "hits:", hits)
    assert hits == []


def test_readme_states_the_settled_scope():
    missing = missing_scope_phrases((REPO / "README.md").read_text(encoding="utf-8"))
    print("missing scope phrases:", missing)
    assert missing == []
