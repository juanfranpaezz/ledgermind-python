"""Run B documents and container, static checks (no Docker needed; the live container checks are in
docs/RUNBOOK-ledgermind-api.md and the Run B coder note).

AC-B.5 docs/openapi.json has no drift from the live app; AC-B.9 exactly 3 Mermaid diagrams in the
README; AC-B.8 the README's FastAPI section carries its load-bearing statements (the prose itself
is a human check); AC-B.6 (static half) the Dockerfile never copies a keys file and never runs as root.
"""

from __future__ import annotations

import json
import re

from conftest import REPO_ROOT

from ledgermind_api.app import create_app
from ledgermind_api.openapi_export import render

README = REPO_ROOT / "README.md"
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
OPENAPI = REPO_ROOT / "docs" / "openapi.json"
RUNBOOK = REPO_ROOT / "docs" / "RUNBOOK-ledgermind-api.md"


def _flat(text: str) -> str:
    return " ".join(text.split())


def _leaf_diffs(a, b, path: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            out += _leaf_diffs(a.get(key, "<absent>"), b.get(key, "<absent>"), path + "/" + str(key))
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in _leaf_diffs(x, y, path + "/" + str(i))]
    return [] if a == b else [path]


# ---- AC-B.5 ----------------------------------------------------------------------------------

def test_positive_control_the_drift_counter_sees_one_changed_leaf():
    live = json.loads(render())
    planted = json.loads(render())
    planted["info"]["version"] = "planted"
    assert _leaf_diffs(live, planted) == ["/info/version"]


def test_AC_B5_committed_openapi_has_no_drift_from_the_live_app(settings):
    committed = json.loads(OPENAPI.read_text(encoding="utf-8"))
    live = json.loads(json.dumps(create_app(settings).openapi()))
    diffs = _leaf_diffs(committed, live)
    print("openapi drift leaves:", len(diffs), diffs[:5])
    assert diffs == [], "regenerate with: py -m ledgermind_api.openapi_export"


def test_AC_B5_verdict_enum_and_api_key_scheme():
    spec = json.loads(OPENAPI.read_text(encoding="utf-8"))
    assert set(spec["components"]["schemas"]["VerdictStatus"]["enum"]) == {
        "VERIFIED", "COVERAGE_DEGRADED", "TAMPER_SUSPECTED", "INCOMPLETE", "ERROR"}
    schemes = [s for s in spec["components"]["securitySchemes"].values()
               if s.get("type") == "apiKey" and s.get("in") == "header" and s.get("name") == "X-API-Key"]
    assert len(schemes) == 1
    assert "/v1/java/audit" in spec["paths"]


# ---- AC-B.9 / AC-B.8 -------------------------------------------------------------------------

MERMAID_FENCE = re.compile(r"^```mermaid\s*$", re.M)


def test_AC_B9_readme_has_exactly_three_mermaid_diagrams():
    count = len(MERMAID_FENCE.findall(README.read_text(encoding="utf-8")))
    print("mermaid blocks:", count)
    assert count == 3


def test_AC_B8_readme_fastapi_section_states_install_auth_limits_and_honest_limits():
    text = README.read_text(encoding="utf-8")
    assert re.search(r"^## FastAPI service \(optional\)\s*$", text, re.M)
    section = _flat(text.split("## FastAPI service (optional)", 1)[1].split("\n## ", 1)[0])
    required = ("[api]", "X-API-Key", "413", "127.0.0.1", "not the live ledger", "VERIFIED is not",
                "not authenticated", "no TLS", "no AI model", "/v1/java/audit", "RUNBOOK-ledgermind-api.md")
    missing = [phrase for phrase in required if phrase not in section]
    print("missing README phrases:", missing)
    assert missing == []


# ---- AC-B.6 static half ----------------------------------------------------------------------

def dockerfile_problems(text: str) -> list[str]:
    problems = []
    instructions = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    copies = [line for line in instructions if re.match(r"(?i)^(COPY|ADD)\b", line)]
    problems += ["copies keys: " + line for line in copies if re.search(r"(?i)keys?", line)]
    problems += ["copies the whole context: " + line for line in copies if re.match(r"(?i)^(COPY|ADD)\s+\.\s", line)]
    users = [line.split(None, 1)[1].strip() if len(line.split()) > 1 else "" for line in instructions
             if re.match(r"(?i)^USER\b", line)]
    if not users or users[-1] in ("root", "0", "0:0"):
        problems.append("final USER is root or missing")
    return problems


def test_positive_control_the_dockerfile_checker_fires_on_planted_defects():
    assert dockerfile_problems("FROM x\nCOPY api-keys.txt /k\nUSER 10001\n") == ["copies keys: COPY api-keys.txt /k"]
    assert dockerfile_problems("FROM x\nCOPY src ./src\n") == ["final USER is root or missing"]
    assert dockerfile_problems("FROM x\nCOPY . .\nUSER 10001\n") != []


def test_AC_B6_static_dockerfile_never_copies_keys_and_does_not_run_as_root():
    problems = dockerfile_problems(DOCKERFILE.read_text(encoding="utf-8"))
    print("Dockerfile problems:", problems)
    assert problems == []
    ignored = DOCKERIGNORE.read_text(encoding="utf-8").split()
    assert "*.key" in ignored and "*keys*" in ignored


def test_the_runbook_exists_and_names_every_route():
    text = RUNBOOK.read_text(encoding="utf-8")
    for path in ("/v1/health", "/v1/verify/corpus", "/v1/verify/snapshot", "/v1/java/audit", "/v1/tools"):
        assert path in text
