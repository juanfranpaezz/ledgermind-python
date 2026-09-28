"""Pre-publish guard (2026-09-28): no local absolute path of a personal machine, and no internal process
wording, anywhere in the published text of the repository.

Generic on purpose: it names no person, company or machine. It flags the SHAPE of a personal path:
- a drive-letter path whose first directory is not a system one (Windows, Program Files, ProgramData),
- a drive-letter path into a named user's home (``<drive>:/Users/<name>``; a ``*`` glob is fine),
- a Git-Bash drive path (``/<drive>/<dir>/``) and a POSIX home (``/home/<name>``, ``/Users/<name>``).
Process wording (``CEO``, a bare ``CP-<n>`` checkpoint label, a ``D-<n>.<n>`` decision code) is flagged in
every file outside the guard tests, which must spell the banned pattern to test it.

RED at 7108d37 on both legs (the evidence documents carried local paths and process wording); the planted
controls below show each pattern can fire.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".txt", ".json", ".toml", ".yml", ".yaml", ".cfg", ".ini", ".http", ".sh"}
TEXT_NAMES = {"Dockerfile", ".dockerignore", ".gitignore", "LICENSE"}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "build", "dist"}
# The guard tests that must spell the banned process pattern to test it.
PROCESS_GUARD_FILES = {"test_readme_licence_wording.py", "test_evidence_docs_process_wording_2026_09_28.py",
                       "test_prepublish_scrub_guard_2026_09_28.py"}

SYSTEM_TOP_DIRS = {"windows", "program", "programdata"}  # "Program Files" stops at the space
DRIVE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]):[\\/]{1,2}([^\\/\s\"'`<>|*?:;,()\[\]{}]+)([\\/]{1,2}[^\\/\s\"'`<>|]*)?")
GIT_BASH_DRIVE_RE = re.compile(r"(?<![\w.:/~-])/[a-zA-Z]/(?!\*)[\w .-]+/")
POSIX_HOME_RE = re.compile(r"(?<![\w.~-])/(?:home|Users)/(?!\*)[\w.-]+")
PROCESS_WORDING_RE = re.compile(r"\bCEO\b|\bCP-\d|\bD-\d+\.\d+", re.I)


def published_files() -> list[Path]:
    files = []
    for path in REPO.rglob("*"):
        parts = path.relative_to(REPO).parts
        if any(part in SKIP_DIRS or part.startswith(".venv") or part.endswith(".egg-info") for part in parts):
            continue
        if path.is_file() and (path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES):
            files.append(path)
    return sorted(files)


def personal_path_hits(line: str) -> list[str]:
    hits = []
    for match in DRIVE_PATH_RE.finditer(line):
        top, rest = match.group(2).lower(), match.group(3) or ""
        if set(top) == {"."} or (len(top) == 1 and not rest.strip("\\/")):
            continue  # an elided path (C:\...\x) or a lone one-letter synthetic test input (C:\x)
        if top not in SYSTEM_TOP_DIRS and top != "users":
            hits.append(match.group(0))
        elif top == "users" and rest.strip("\\/") and not rest.strip("\\/").startswith("*"):
            hits.append(match.group(0))
    hits += [m.group(0) for m in GIT_BASH_DRIVE_RE.finditer(line)]
    hits += [m.group(0) for m in POSIX_HOME_RE.finditer(line)]
    return hits


def scan(named_texts: list[tuple[str, str]], process: bool) -> list[str]:
    found = []
    for name, text in named_texts:
        for number, line in enumerate(text.splitlines(), start=1):
            if personal_path_hits(line) or (process and PROCESS_WORDING_RE.search(line)):
                found.append(name + ":" + str(number))
    return found


def _read_all() -> list[tuple[Path, str]]:
    return [(p, p.read_text(encoding="utf-8", errors="replace")) for p in published_files()]


# ---- the checker can fire (planted text, built by concatenation so this file never matches itself) ----

def test_positive_control_each_pattern_fires_on_planted_text():
    drive = "D" + ":"
    assert personal_path_hits(drive + "/work/project") == [drive + "/work/project"]
    assert personal_path_hits('cd "' + drive + '\\Users\\someone\\x"') != []
    assert personal_path_hits("cd /" + "d/work/repo") != []
    assert personal_path_hits("see /" + "home/someone/repo") != []
    assert scan([("x", "fine\nthe " + "C" + "EO decided")], process=True) == ["x:2"]


def test_positive_control_bare_checkpoint_label_and_decision_code_fire_and_neutral_text_does_not():
    # A bare checkpoint label and an internal decision code, not only "checkpoint CP-<n>".
    assert scan([("x", "per the " + "C" + "P-1 design call")], process=True) == ["x:1"]
    assert scan([("x", "fine\nthe owner's " + "D" + "-1.1 at review")], process=True) == ["x:2"]
    # The neutral replacements used in this repository stay silent.
    assert scan([("x", "per the Phase 0 design decision")], process=True) == []
    assert scan([("x", "the Phase 1 go decision at the end-of-Phase-0 review")], process=True) == []


def test_negative_control_system_paths_urls_and_globs_do_not_fire():
    drive = "C" + ":"
    assert personal_path_hits(drive + "\\Windows\\System32\\taskkill.exe") == []
    assert personal_path_hits(drive + "\\Program Files\\Git\\mingw64\\bin\\openssl.EXE") == []
    assert personal_path_hits('Path("' + drive + '/Users").glob("*/.vscode/extensions")') == []
    assert personal_path_hits("http://127.0.0.1:8088/v1/health and https://github.com/a/b") == []
    assert personal_path_hits("<ledgermind-checkout>/src/main/java and $HOME/.ledgermind-api") == []
    assert personal_path_hits(drive + "\\...\\tests\\fixtures and the input " + drive + "\\x") == []


def test_positive_control_the_file_list_covers_code_docs_and_fixtures():
    names = {str(p.relative_to(REPO)).replace("\\", "/") for p in published_files()}
    assert {"README.md", "docs/evidence/preflight.txt", "docs/evidence/phase1-verifier.md",
            "tools/record_fixtures.py", "tests/fixtures/recorded/_corpus.json"} <= names
    assert len(names) > 100


def test_no_personal_local_path_anywhere_in_the_published_tree():
    hits = scan([(str(p.relative_to(REPO)), text) for p, text in _read_all()], process=False)
    print("personal-path hits:", hits)
    assert hits == []


def test_no_process_wording_outside_the_guard_tests():
    texts = [(str(p.relative_to(REPO)), text) for p, text in _read_all() if p.name not in PROCESS_GUARD_FILES]
    hits = scan(texts, process=True)
    print("process-wording or path hits:", hits)
    assert hits == []
