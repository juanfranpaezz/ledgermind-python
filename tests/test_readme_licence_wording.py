"""Guards for the repository's own wording (gate fixes A1-A3, A7 of the Run A delta gate, 2026-09-26).

These are text checks, stdlib only, so they run in the zero-dependency core suite:
- A1: while the optional FastAPI service exists (``ledgermind_api/app.py``), the README must not deny it.
- A2: the licence is Apache-2.0 everywhere it is declared, and ``MIT`` appears nowhere it could be read as the licence.
- A3: process wording (``CEO``, ``checkpoint CP-<n>``) stays out of the published text surfaces.
- A7: pyproject.toml must not say FastAPI "arrives in Phase 2" while it ships as the ``api`` extra.

Each check was shown RED on the historical text it guards against (da66afd README; 3d0f5ec README,
pyproject.toml, src/ledger_verification_agent/__init__.py, tool_registry.py) before being kept.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# A1: phrases that deny the FastAPI service. Matched on the whitespace-flattened README, so a line
# wrap in the middle of a phrase cannot hide it.
FASTAPI_DENIALS = (
    re.compile(r"no FastAPI service", re.I),
    re.compile(r"no HTTP client and no FastAPI", re.I),
    re.compile(r"no `POST /ask` and no FastAPI", re.I),
)
# A table row that names FastAPI and says it has not started.
FASTAPI_NOT_STARTED_ROW = re.compile(r"^\|[^\n]*FastAPI[^\n]*\|\s*\**\s*not started", re.I | re.M)

MIT_RE = re.compile(r"\bMIT\b")
PROCESS_WORDING_RE = re.compile(r"\bCEO\b|checkpoint CP-\d", re.I)
STALE_PYPROJECT_RE = re.compile(r"FastAPI.{0,80}arrive in Phase 2", re.I)


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def fastapi_denials(readme: str) -> list[str]:
    """Every README phrase that denies the FastAPI service (empty = none)."""
    flat = _flat(readme)
    hits = [m.group(0) for pattern in FASTAPI_DENIALS for m in pattern.finditer(flat)]
    hits += [m.group(0) for m in FASTAPI_NOT_STARTED_ROW.finditer(readme)]
    return hits


def licence_violations(readme: str, pyproject: str, licence_file: str) -> list[str]:
    problems = []
    if 'license = { text = "Apache-2.0" }' not in pyproject.splitlines():
        problems.append("pyproject.toml: no line `license = { text = \"Apache-2.0\" }`")
    if "Apache-2.0" not in readme:
        problems.append("README.md: does not name Apache-2.0")
    for name, text in (("README.md", readme), ("pyproject.toml", pyproject)):
        problems += [name + ": MIT at offset " + str(m.start()) for m in MIT_RE.finditer(text)]
    if "Apache License" not in licence_file:
        problems.append("LICENSE: not the Apache License text")
    return problems


def wording_surfaces() -> list[Path]:
    files = [REPO / "README.md", REPO / "pyproject.toml"]
    files += sorted((REPO / "src").rglob("*.py"))
    files += sorted((REPO / "ledgermind_api").glob("*.py"))
    return files


def process_wording_hits(named_texts: list[tuple[str, str]]) -> list[str]:
    hits = []
    for name, text in named_texts:
        for number, line in enumerate(text.splitlines(), 1):
            if PROCESS_WORDING_RE.search(line):
                hits.append(name + ":" + str(number))
    return hits


# ---- the checkers can fire (positive controls on planted text) ------------------------------

def test_positive_control_each_checker_fires_on_planted_text():
    assert fastapi_denials("There is no FastAPI\nservice yet.") == ["no FastAPI service"]
    assert fastapi_denials("| API | FastAPI layer | **not started** |\n") != []
    assert licence_violations("MIT licence", 'license = { text = "MIT" }', "MIT") != []
    assert process_wording_hits([("x", "ok\nthe CEO said so")]) == ["x:2"]
    assert process_wording_hits([("x", "see checkpoint CP-1")]) == ["x:1"]
    assert STALE_PYPROJECT_RE.search(_flat("# FastAPI, httpx and the\n# Anthropic transport arrive in Phase 2"))


def test_positive_control_the_surface_list_is_not_empty():
    names = {p.name for p in wording_surfaces()}
    assert {"README.md", "pyproject.toml", "__init__.py", "app.py", "tool_registry.py"} <= names


# ---- the guards ------------------------------------------------------------------------------

def test_A1_readme_does_not_deny_the_fastapi_service_while_it_exists():
    assert (REPO / "ledgermind_api" / "app.py").is_file(), "the premise: the service exists"
    hits = fastapi_denials(_read("README.md"))
    print("README FastAPI-denial hits:", hits)
    assert hits == []


def test_A2_licence_is_apache_2_0_and_mit_appears_nowhere():
    problems = licence_violations(_read("README.md"), _read("pyproject.toml"), _read("LICENSE"))
    print("licence problems:", problems)
    assert problems == []


def test_A3_no_process_wording_in_published_text_surfaces():
    surfaces = wording_surfaces()
    hits = process_wording_hits([(str(p.relative_to(REPO)), p.read_text(encoding="utf-8")) for p in surfaces])
    print("surfaces scanned:", len(surfaces), "hits:", hits)
    assert hits == []


def test_A7_pyproject_does_not_say_fastapi_arrives_later():
    assert STALE_PYPROJECT_RE.search(_flat(_read("pyproject.toml"))) is None
