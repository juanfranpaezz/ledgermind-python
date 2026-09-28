"""Run ``tools.verify_report`` in a child process, stage uploads, map the result. Standard library only.

WRAPPED, NEVER REIMPLEMENTED. The verdict is the CLI's EXIT CODE plus its stdout JSON; an
in-process ``check_all`` call would lose the CLI's OK -> INCOMPLETE escalations (unverified
signature, recorded snapshot without a checkpoint), so the service runs the CLI itself.

Child environment: PATH (load-bearing: the CLI auto-selects ``openssl >= 3.5`` from PATH to verify
the ML-DSA signature; without it every clean run silently degrades to INCOMPLETE), SYSTEMROOT
(Windows needs it to start a process), TEMP/TMP/TMPDIR (the CLI's OpenSSL backend stages files with
``tempfile``; with no temp variable Python falls back to the CURRENT DIRECTORY, i.e. the repo),
and PYTHONPATH=<repo>/src. Nothing else - in particular no LEDGERMIND_API_* variable.

On timeout the WHOLE process tree is killed: the CLI spawns ``openssl``, and killing only the
direct child would leave a grandchild holding the output pipes open.

Uploads: request models carry CONTENT, never a path. Only allowlisted file names are written,
each with an exclusive create, and only inside ``tempfile.TemporaryDirectory(prefix="lm-api-")``,
deleted when the CLI run returns. A recorded half is staged as ``<tmp>/<label>/<name>`` so the
CLI's own relative source labels (``recorded/<label>/...``) match a direct run; an adversarial
document as ``<tmp>/<case_label>.json``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

CLI_MODULE = "tools.verify_report"
STDERR_LIMIT = 2048
PASSTHROUGH_ENV = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR")

STAGE_PREFIX = "lm-api-"
REQUIRED_NAME = "postings_and_hashes.json"
RECORDED_FIXED_NAMES = frozenset(
    {"postings_and_hashes.json", "journal_checkpoint.json", "journal_verify.json", "journal_audit.json"}
)
# Finalised against tests/fixtures/recorded/clean/ (account_external_funding.json,
# account_wallet_ana.json, account_wallet_beto.json). ':' is excluded: illegal in Windows file names.
# \Z, not $: in Python re, $ also matches just before a trailing newline, so "account_x.json\n" passed
# and reached open() -> uncaught OSError -> 500 (security gate r1 F3, 2026-09-27).
ACCOUNT_NAME_RE = re.compile(r"^account_[a-z0-9_-]{1,64}\.json\Z")
LABELS = ("clean", "tampered")
CASE_LABEL_PATTERN = r"^[a-z0-9_]{1,64}$"
CASE_LABEL_RE = re.compile(CASE_LABEL_PATTERN)

PY_BACKEND = "python-verifier"
PY_DOES_NOT_DETECT = (
    "The verdict is about the supplied SNAPSHOT at capture time, never the live ledger.",
    "The snapshot's provenance is not authenticated: the service verifies whatever JSON it was given.",
    "VERIFIED means no evidence of what the checks detect (money conservation, no overdraft, hash-chain "
    "continuity, checkpoint signature), not 'ledger intact'.",
    "A verified signature is message integrity under the key the checkpoint itself carries, not signer "
    "authenticity: proving WHO signed needs a key anchored outside the ledger database.",
)
STATUS_BY_EXIT = {0: "VERIFIED", 1: "TAMPER_SUSPECTED", 2: "INCOMPLETE"}
NATIVE_VERDICTS_BY_EXIT = {0: {"OK"}, 1: {"TAMPERED"}, 2: {"OK", "INCOMPLETE"}}
CHECK_RESULT = {"OK": "pass", "VIOLATION": "fail", "NO_DATA": "no_data"}
SIGNATURE_STATUS = {
    "VERIFIED": "verified",
    "INVALID": "invalid",
    "UNVERIFIED-SIGNATURE": "unverified",
    "NO-CHECKPOINT": "absent",
}


class ApiProblem(Exception):
    """An error the service answers with an RFC 9457 problem document."""

    def __init__(self, status: int, code: str, title: str, detail: str, **extra: Any) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.extra = extra


@dataclass(frozen=True)
class CliRun:
    exit_code: int | None  # None when the run timed out or could not start
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


def child_env(repo_root: Path, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environ is None else environ
    env = {name: source[name] for name in PASSTHROUGH_ENV if source.get(name)}
    env["PYTHONPATH"] = str(repo_root / "src")
    return env


def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
        try:
            subprocess.run(
                [str(taskkill), "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        import signal

        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        proc.kill()
    except OSError:
        pass


def run_cli(py_exe: str, repo_root: Path, args: Sequence[str], timeout_s: float) -> CliRun:
    cmd = [py_exe, "-m", CLI_MODULE, *args, "--json"]
    started = time.monotonic()
    kwargs: dict[str, Any] = {
        "cwd": str(repo_root),
        "env": child_env(repo_root),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
    }
    if os.name != "nt":
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(cmd, **kwargs)
    except OSError as exc:
        return CliRun(None, "", "could not start the verifier process (" + type(exc).__name__ + ")", False,
                      int((time.monotonic() - started) * 1000))
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        out, err = proc.communicate()
    return CliRun(
        exit_code=None if timed_out else proc.returncode,
        stdout=out.decode("utf-8", errors="replace"),
        stderr=err.decode("utf-8", errors="replace")[:STDERR_LIMIT],
        timed_out=timed_out,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def recorded_name_allowed(name: str) -> bool:
    return name in RECORDED_FIXED_NAMES or ACCOUNT_NAME_RE.match(name) is not None


def _write_json(directory: Path, name: str, value: Any) -> None:
    target = directory / name
    if target.parent != directory or target.name != name:
        raise ValueError("refusing a staged name outside the stage directory")
    try:
        handle = open(target, "x", encoding="utf-8")
    except (OSError, ValueError) as exc:
        # Security gate r1 F3 (2026-09-27): a name the file system refuses (too long, a control character,
        # a NUL) is the client's input, so it is a 422 problem, never an uncaught 500. The exception text
        # is not echoed: it carries the stage path.
        raise ApiProblem(422, "validation_error", "File name refused",
                         "the file system refused a staged file name (" + type(exc).__name__ + ")") from None
    with handle:
        try:
            json.dump(value, handle)
        except RecursionError:
            # Security gate r2 (2026-09-27): json.dump recurses in pure Python, so a document nested
            # past the interpreter's recursion limit raised RecursionError here -> 500. The depth guard
            # should stop such a body first; this is the second line, and it is the client's input: 422.
            raise ApiProblem(422, "validation_error", "JSON nested too deeply",
                             "the uploaded JSON nests too deeply to be staged for the verifier") from None


def verify_recorded_upload(py_exe: str, repo_root: Path, label: str, files: Mapping[str, Any],
                           timeout_s: float) -> CliRun:
    if label not in LABELS:
        raise ValueError("label must be clean or tampered")
    if REQUIRED_NAME not in files or not all(recorded_name_allowed(name) for name in files):
        raise ValueError("file names must be allowlisted and include " + REQUIRED_NAME)
    with tempfile.TemporaryDirectory(prefix=STAGE_PREFIX) as tmp:
        root = Path(tmp)
        half_dir = root / label
        half_dir.mkdir()
        for name, value in files.items():
            _write_json(half_dir, name, value)
        return run_cli(py_exe, repo_root, ["--corpus", "recorded", "--half", label, "--corpus-root", str(root)],
                       timeout_s)


def verify_adversarial_upload(py_exe: str, repo_root: Path, case_label: str, document: Any,
                              timeout_s: float) -> CliRun:
    # fullmatch, not match (security gate r1 A4, 2026-09-27): CASE_LABEL_PATTERN ends in $, which in Python re
    # also matches before a trailing newline. The pattern string itself stays: pydantic compiles it with Rust
    # regex, where $ is end of text, and a \Z there makes the schema fail to build (probed: pydantic 2.13.5
    # raises SchemaError).
    if not CASE_LABEL_RE.fullmatch(case_label):
        raise ValueError("case_label must match " + CASE_LABEL_PATTERN)
    with tempfile.TemporaryDirectory(prefix=STAGE_PREFIX) as tmp:
        root = Path(tmp)
        _write_json(root, case_label + ".json", document)
        return run_cli(py_exe, repo_root, ["--corpus", "adversarial", "--case", case_label, "--corpus-root", str(root)],
                       timeout_s)


def map_python(run: CliRun, subject: str) -> dict[str, Any]:
    """Python mapping (plan v2 section 3.1). The EXIT CODE is authoritative; ``native`` is unmodified."""
    if run.timed_out:
        raise ApiProblem(504, "backend_timeout", "Verifier timed out",
                         "the verifier CLI did not finish within the configured timeout; nothing was verified")
    if run.exit_code not in STATUS_BY_EXIT:
        raise ApiProblem(502, "backend_tool_error", "Verifier could not run",
                         "the verifier CLI exited " + str(run.exit_code) + ": the input could not be read, so "
                         "NOTHING was verified. This is not a tamper finding.",
                         backend=PY_BACKEND, backend_exit_code=run.exit_code, backend_stderr=run.stderr)
    try:
        native = json.loads(run.stdout)
    except ValueError:
        raise ApiProblem(502, "backend_tool_error", "Verifier output was not JSON",
                         "the verifier CLI printed no JSON verdict; nothing was verified",
                         backend=PY_BACKEND, backend_exit_code=run.exit_code, backend_stderr=run.stderr) from None
    if not isinstance(native, dict) or native.get("verdict") not in NATIVE_VERDICTS_BY_EXIT[run.exit_code]:
        raise ApiProblem(502, "verdict_exit_mismatch", "Verifier exit code and verdict disagree",
                         "exit " + str(run.exit_code) + " with a JSON verdict that does not belong to it",
                         backend=PY_BACKEND, backend_exit_code=run.exit_code)
    checks = []
    for check in native.get("checks") or []:
        checks.append({
            "name": str(check.get("check")),
            "result": CHECK_RESULT.get(check.get("status"), "unknown"),
            "violations": int(check.get("violation_count") or 0),
            "detail": "; ".join(str(note) for note in (check.get("notes") or []))[:500],
        })
    signature = native.get("signature") or {}
    return {
        "schema_version": "1",
        "backend": PY_BACKEND,
        "status": STATUS_BY_EXIT[run.exit_code],
        "tamper_proven": run.exit_code == 1,
        "coverage_degraded": False,
        "frozen_accounts": None,
        "checks": checks,
        "signature": {
            "status": SIGNATURE_STATUS.get(signature.get("status"), "not_applicable" if not signature else "unknown"),
            "algorithm": signature.get("algorithm"),
        },
        "subject": subject,
        "evidence_time": None,
        "does_not_detect": list(PY_DOES_NOT_DETECT),
        "mapping_basis": "exit_code",
        "exit_code": run.exit_code,
        "native": native,
        "notes": [line for line in run.stderr.splitlines() if line.strip()],
    }
