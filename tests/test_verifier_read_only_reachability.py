"""The read-only guarantee, proven mechanically rather than promised in a docstring.

Manifest AC-1.4 plus the Phase-1 brief's item 3: *the verifier must use only the
read-only tools from the phase-0 registry; no write-capable call is reachable from
the verifier module*.

FOUR INDEPENDENT LEGS, because each one alone has a hole:

1. **Registry leg** - every tool ``ledger_snapshot.DATASET_SOURCES`` names is a real
   ``ToolSpec`` on ``READ_ONLY_SURFACE`` and on none of ``MUTATING_ENDPOINTS``.
   Hole: a module could bypass the registry entirely.
2. **Static leg (AST)** - the verifier's own sources import nothing outside a pure
   stdlib allow-list, call nothing on a write/network denylist, and contain no
   mutating endpoint path as a literal. Hole: a dynamic ``__import__`` or getattr.
3. **Runtime-closure leg** - a FRESH interpreter imports the verifier and its whole
   ``sys.modules`` closure is inspected. This is the leg that catches a transitive
   import the AST cannot see, and it is where ``anthropic`` would surface.
4. **Dynamic leg** - ``check_all`` is run for real with ``socket.socket``, every
   write-mode ``open`` and the delete syscalls replaced by raisers. Nothing is
   mocked away, so if a write were reachable it would fire.

Each detector is also shown FIRING on a planted positive, because a scanner that
only ever returns "clean" proves nothing at all.
"""

from __future__ import annotations

import ast
import builtins
import io
import os
import socket
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(REPO_ROOT))

from ledger_verification_agent import tool_registry  # noqa: E402
from ledger_verification_agent.deterministic_verifier import check_all  # noqa: E402
from ledger_verification_agent.ledger_snapshot import (  # noqa: E402
    DATASET_SOURCES,
    DB_READ_ONLY,
    load_recorded,
)
from ledger_verification_agent.verdict import VERDICT_OK  # noqa: E402

#: The modules that ARE the verifier. The opt-in openssl backend is deliberately not
#: here and is asserted below to stay out of the closure.
VERIFIER_MODULES = (
    "verdict.py",
    "journal_chain.py",
    "ledger_snapshot.py",
    "checkpoint_signature.py",
    "deterministic_verifier.py",
)

#: Pure, offline, no-side-effect stdlib only.
ALLOWED_IMPORTS = frozenset(
    {
        "__future__",
        "base64",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "typing",
        "collections",
        "enum",
        "re",
    }
)

#: Outside packages the verifier may REACH FOR but must never REQUIRE. Each one has
#: to be imported inside a ``try`` that catches ``ImportError``, so the package keeps
#: its zero-runtime-dependency promise and the absence of the library degrades the
#: report (``UNVERIFIED-SIGNATURE``) instead of breaking the import.
OPTIONAL_GUARDED_IMPORTS = frozenset({"cryptography"})

#: Names that can write, delete, spawn or reach the network.
FORBIDDEN_CALL_NAMES = frozenset(
    {
        "write",
        "write_text",
        "write_bytes",
        "writelines",
        "unlink",
        "rmdir",
        "rmtree",
        "remove",
        "mkdir",
        "makedirs",
        "rename",
        "replace_file",
        "truncate",
        "system",
        "popen",
        "run",
        "Popen",
        "check_output",
        "check_call",
        "call",
        "urlopen",
        "Request",
        "post",
        "put",
        "patch",
        "delete",
        "request",
        "connect",
        "sendall",
        "socket",
        "create_connection",
    }
)


def _sources() -> dict[str, str]:
    return {name: (SRC / "ledger_verification_agent" / name).read_text("utf-8") for name in VERIFIER_MODULES}


# --------------------------------------------------------------------------- #
# the two detectors, written once so the planted-positive tests drive the SAME code
# --------------------------------------------------------------------------- #
def imported_top_level_modules(source: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # a relative import: inside this package, not an outside dep
                continue
            if node.module:
                found.add(node.module.split(".")[0])
    return found


def hard_required_modules(source: str) -> set[str]:
    """Top-level imports only: the ones that MUST resolve for the module to import.

    An import nested inside a ``try`` whose handler catches ``ImportError`` is an
    optional reach, not a dependency, and is reported separately.
    """
    tree = ast.parse(source)
    guarded: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(
            isinstance(handler.type, ast.Name) and handler.type.id == "ImportError"
            for handler in node.handlers
        ):
            for child in ast.walk(node):
                guarded.add(child)
    found: set[str] = set()
    for node in ast.walk(tree):
        if node in guarded:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            found.add(node.module.split(".")[0])
    return found


ENDPOINT_TOKEN = re.compile(r"/(?:api|mcp)[A-Za-z0-9_{}/-]*")


def mutating_paths_mentioned(source: str, mutating: frozenset) -> set[str]:
    """Endpoint paths that appear in a STRING LITERAL and are exactly a mutating path.

    Exact token comparison on purpose: a naive substring test reports
    ``GET /api/accounts/{address}`` (read-only) as the mutating ``POST /api/accounts``,
    which is a false positive that would train a reader to ignore the check.
    """
    paths = {path for _method, path in mutating}
    hits: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for token in ENDPOINT_TOKEN.findall(node.value):
                if token in paths:
                    hits.add(token)
    return hits


def forbidden_calls(source: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = None
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        if name in FORBIDDEN_CALL_NAMES:
            found.add(name)
    return found


# --------------------------------------------------------------------------- #
# 1. registry leg
# --------------------------------------------------------------------------- #
def test_every_dataset_the_verifier_reads_names_a_READ_ONLY_registry_tool():
    declared = {spec.name: spec for spec in tool_registry.DECLARED_TOOLS}
    for source in DATASET_SOURCES:
        if source.tool is None:
            assert source.access == DB_READ_ONLY, source.dataset
            assert "read_only" in source.justification or "read-only" in source.justification
            continue
        assert source.tool in declared, source.dataset + " names a tool that is not in the registry"
        spec = declared[source.tool]
        assert (spec.method, spec.path) in tool_registry.READ_ONLY_SURFACE
        assert (spec.method, spec.path) not in tool_registry.MUTATING_ENDPOINTS


def test_the_registry_the_verifier_would_be_handed_contains_no_mutating_endpoint():
    assert tool_registry.mutating_endpoints_in(tool_registry.TOOL_REGISTRY) == ()
    assert tool_registry.endpoints_outside_read_only_surface(tool_registry.TOOL_REGISTRY) == ()


def test_FIRES_the_registry_check_rejects_a_mutating_tool():
    """Planted positive: a registry with POST /api/transfers must be caught."""
    hostile = tool_registry.DECLARED_TOOLS + (
        tool_registry.ToolSpec(
            name="transfer",
            transport="rest",
            method="POST",
            path="/api/transfers",
            upstream="planted",
            requires_mcp=False,
            description="planted mutating tool",
        ),
    )
    assert tool_registry.mutating_endpoints_in(hostile) == (("POST", "/api/transfers"),)


# --------------------------------------------------------------------------- #
# 2. static leg
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("module_name", VERIFIER_MODULES)
def test_the_verifier_REQUIRES_only_pure_offline_stdlib(module_name):
    required = hard_required_modules(_sources()[module_name])
    assert required <= ALLOWED_IMPORTS, (
        module_name + " hard-requires " + str(sorted(required - ALLOWED_IMPORTS))
    )


@pytest.mark.parametrize("module_name", VERIFIER_MODULES)
def test_any_outside_package_the_verifier_reaches_for_is_optional_and_declared(module_name):
    source = _sources()[module_name]
    every = imported_top_level_modules(source)
    required = hard_required_modules(source)
    optional = every - required
    assert optional <= OPTIONAL_GUARDED_IMPORTS, (
        module_name + " reaches for undeclared outside packages: "
        + str(sorted(optional - OPTIONAL_GUARDED_IMPORTS))
    )
    assert (every - ALLOWED_IMPORTS) <= OPTIONAL_GUARDED_IMPORTS, module_name


def test_FIRES_the_optional_import_rule_catches_an_UNGUARDED_outside_dependency():
    """Planted positive: the same module imported at top level must be caught."""
    guarded = (
        "try:\n"
        "    from cryptography.hazmat.primitives.asymmetric import mldsa\n"
        "except ImportError:\n"
        "    mldsa = None\n"
    )
    unguarded = "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
    assert hard_required_modules(guarded) == set()
    assert hard_required_modules(unguarded) == {"cryptography"}


@pytest.mark.parametrize("module_name", VERIFIER_MODULES)
def test_no_write_capable_or_network_call_appears_in_the_verifier(module_name):
    assert forbidden_calls(_sources()[module_name]) == set(), module_name


@pytest.mark.parametrize("module_name", VERIFIER_MODULES)
def test_no_mutating_endpoint_path_appears_as_a_literal_in_the_verifier(module_name):
    hits = mutating_paths_mentioned(_sources()[module_name], tool_registry.MUTATING_ENDPOINTS)
    assert hits == set(), module_name + " mentions mutating paths " + str(sorted(hits))


def test_FIRES_the_static_scanners_catch_a_planted_write_and_a_planted_client():
    planted = (
        "import httpx\n"
        "import subprocess\n"
        "from pathlib import Path\n"
        "def go():\n"
        "    httpx.post('http://localhost:8080/api/transfers', json={})\n"
        "    Path('x').write_text('y')\n"
        "    subprocess.run(['rm', '-rf', '/'])\n"
    )
    assert imported_top_level_modules(planted) - ALLOWED_IMPORTS == {"httpx", "subprocess"}
    assert {"post", "write_text", "run"} <= forbidden_calls(planted)
    assert mutating_paths_mentioned(planted, tool_registry.MUTATING_ENDPOINTS) == {"/api/transfers"}


def test_SILENT_the_endpoint_scanner_does_not_confuse_a_read_path_with_its_mutating_prefix():
    """GET /api/accounts/{address} is read-only; POST /api/accounts is not. Same prefix."""
    read_only = "PATH = '/api/accounts/{address}'\n"
    mutating = "PATH = '/api/accounts'\n"
    assert mutating_paths_mentioned(read_only, tool_registry.MUTATING_ENDPOINTS) == set()
    assert mutating_paths_mentioned(mutating, tool_registry.MUTATING_ENDPOINTS) == {"/api/accounts"}


def test_SILENT_the_static_scanners_clear_a_clean_planted_module():
    """The paired negative: the same scanners must NOT fire on pure computation."""
    clean = (
        "import hashlib\n"
        "from dataclasses import dataclass\n"
        "def go(value):\n"
        "    return hashlib.sha256(value.encode('utf-8')).hexdigest()\n"
    )
    assert imported_top_level_modules(clean) <= ALLOWED_IMPORTS
    assert forbidden_calls(clean) == set()


# --------------------------------------------------------------------------- #
# 3. runtime-closure leg  (AC-1.4: the import graph excludes `anthropic`)
# --------------------------------------------------------------------------- #
FORBIDDEN_IN_CLOSURE = (
    "anthropic",
    "openai",
    "httpx",
    "requests",
    "urllib",
    "http",
    "socket",
    "ssl",
    "subprocess",
    "asyncio",
    "fastapi",
)


def _closure_of(module: str) -> set[str]:
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import importlib,sys,json;importlib.import_module('" + module + "');"
            "print(json.dumps(sorted({name.split('.')[0] for name in sys.modules})))",
        ],
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(SRC)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return set(__import__("json").loads(proc.stdout.strip().splitlines()[-1]))


def test_AC_1_4_the_verifiers_runtime_import_closure_has_no_model_client_and_no_network():
    closure = _closure_of("ledger_verification_agent.deterministic_verifier")
    assert "ledger_verification_agent" in closure  # the probe really imported it
    offenders = sorted(name for name in FORBIDDEN_IN_CLOSURE if name in closure)
    assert offenders == [], "reachable from the verifier: " + str(offenders)


def test_the_optin_openssl_backend_is_NOT_reachable_from_the_verifier():
    closure = _closure_of("ledger_verification_agent.deterministic_verifier")
    assert "ledger_verification_agent" in closure
    module_file = SRC / "ledger_verification_agent" / "mldsa_openssl_backend.py"
    assert module_file.exists()  # it ships...
    for source in _sources().values():  # ...and no core module imports it
        assert "mldsa_openssl_backend" not in source or "see mldsa_openssl_backend" in source


def test_FIRES_the_closure_probe_would_catch_a_module_that_does_reach_the_network():
    """Planted positive for leg 3: the same probe on a module that imports urllib."""
    closure = _closure_of("urllib.request")
    assert "urllib" in closure
    assert [name for name in FORBIDDEN_IN_CLOSURE if name in closure] != []


# --------------------------------------------------------------------------- #
# 4. dynamic leg
# --------------------------------------------------------------------------- #
class _Blocked(RuntimeError):
    pass


def _install_write_and_network_blockers(monkeypatch):
    real_open = builtins.open

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            raise _Blocked("write-mode open is blocked: " + str(file) + " mode=" + mode)
        return real_open(file, mode, *args, **kwargs)

    def blocked(*args, **kwargs):
        raise _Blocked("blocked syscall")

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)
    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(os, "remove", blocked)
    monkeypatch.setattr(os, "unlink", blocked)
    monkeypatch.setattr(os, "rmdir", blocked)


def test_the_blocking_harness_itself_FIRES(monkeypatch, tmp_path):
    """Positive control. Without this, leg 4 proves only that nothing was patched."""
    _install_write_and_network_blockers(monkeypatch)
    with pytest.raises(_Blocked):
        open(tmp_path / "nope.txt", "w")
    with pytest.raises(_Blocked):
        (tmp_path / "nope2.txt").write_text("x")
    with pytest.raises(_Blocked):
        socket.socket()
    with pytest.raises(_Blocked):
        os.remove(tmp_path / "whatever")


def test_check_all_runs_GREEN_with_every_write_and_socket_blocked(monkeypatch):
    _install_write_and_network_blockers(monkeypatch)
    result = check_all(load_recorded("clean"))
    assert result.verdict == VERDICT_OK
    assert result.violation_count == 0
    tampered = check_all(load_recorded("tampered"))
    assert tampered.verdict == "TAMPERED"


def test_reading_a_fixture_still_works_under_the_harness(monkeypatch):
    """Guards the guard: if reads were blocked too, leg 4 would pass for the wrong reason."""
    _install_write_and_network_blockers(monkeypatch)
    snapshot = load_recorded("clean")
    assert len(snapshot.postings) == 5
