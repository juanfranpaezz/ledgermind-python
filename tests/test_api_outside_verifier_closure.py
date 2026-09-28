"""The optional FastAPI service stays OUTSIDE the verifier (plan v2 AC-A.14, AC-A.15, AC-A.16 leg).

Zero-dependency on purpose: this file runs in the main suite, with or without FastAPI installed.
- AC-A.14: an AST scan of ledgermind_api/**/*.py finds no import of a network client or of the
  verifier package, and the SAME scanner reports a planted import (positive control).
- AC-A.15: the verifier's runtime import closure contains neither fastapi nor ledgermind_api.
- the key generator's closure contains no web framework (it must run without FastAPI).
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
API_DIR = REPO_ROOT / "ledgermind_api"
FORBIDDEN_TOP_LEVEL = ("httpx", "requests", "mcp", "anthropic", "openai", "ledger_verification_agent")
WEB_STACK = ("fastapi", "starlette", "pydantic", "uvicorn", "anyio")


def forbidden_imports(py_files) -> list[tuple[str, int, str]]:
    hits = []
    for path in py_files:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            elif (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
                  and isinstance(node.args[0].value, str)
                  and ((isinstance(node.func, ast.Name) and node.func.id == "__import__")
                       or (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"))):
                names = [node.args[0].value]
            for name in names:
                if name.split(".")[0] in FORBIDDEN_TOP_LEVEL:
                    hits.append((Path(path).name, node.lineno, name))
    return hits


def _closure_of(module: str) -> set[str]:
    proc = subprocess.run(
        [sys.executable, "-c",
         "import importlib,sys,json;importlib.import_module('" + module + "');"
         "print(json.dumps(sorted({n.split('.')[0] for n in sys.modules})))"],
        cwd=str(REPO_ROOT), env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return set(json.loads(proc.stdout.strip().splitlines()[-1]))


def test_the_scan_target_is_not_empty():
    files = sorted(API_DIR.rglob("*.py"))
    assert len(files) >= 5, files


def test_AC_A14_no_network_client_and_no_verifier_import_in_the_api_package():
    assert forbidden_imports(sorted(API_DIR.rglob("*.py"))) == []


def test_AC_A14_positive_control_the_same_scanner_reports_planted_imports(tmp_path):
    planted = {
        "a.py": "import httpx\n",
        "b.py": "from ledger_verification_agent.verdict import VERDICT_OK\n",
        "c.py": "import importlib\nimportlib.import_module('openai')\n",
    }
    for name, source in planted.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
        assert len(forbidden_imports([tmp_path / name])) == 1, name


def test_AC_A15_the_verifier_closure_has_no_web_stack_and_no_api_package():
    closure = _closure_of("ledger_verification_agent.deterministic_verifier")
    assert "ledger_verification_agent" in closure
    assert "ledgermind_api" not in closure
    assert [name for name in WEB_STACK if name in closure] == []


def test_the_closure_probe_can_see_the_api_package_positive_control():
    assert "ledgermind_api" in _closure_of("ledgermind_api.config")


def test_the_key_generator_imports_no_web_stack():
    closure = _closure_of("ledgermind_api.keygen")
    assert "ledgermind_api" in closure
    assert [name for name in WEB_STACK if name in closure] == []


def test_the_core_still_declares_zero_runtime_dependencies():
    lines = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines()
    assert lines.count("dependencies = []") == 1
