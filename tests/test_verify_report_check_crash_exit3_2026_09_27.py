"""Amend round 2 (2026-09-27), parity gate r2 A2: a crash WHILE CHECKING must exit 3, never 1.

``check_all`` and its print sat outside the tool-error handling, so a capture that loads but crashes a
check (here: a lone surrogate in a posting's idempotencyKey, written as the legal JSON escape ``\\ud800``)
left the interpreter with an uncaught exception, i.e. exit 1, the code that means TAMPERED.
The control run edits the same field to an ordinary string and must still reach a verdict.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLEAN = REPO / "tests" / "fixtures" / "recorded" / "clean"


def _run_with_idempotency_key(tmp_path: Path, key: str) -> subprocess.CompletedProcess:
    root = tmp_path / "corpus"
    shutil.copytree(CLEAN, root / "clean")
    bundle_path = root / "clean" / "postings_and_hashes.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["postings"][0]["idempotencyKey"] = key
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")  # ensure_ascii: the surrogate stays an escape
    return subprocess.run(
        [sys.executable, "-m", "tools.verify_report", "--corpus", "recorded", "--half", "clean",
         "--corpus-root", str(root), "--json"],
        cwd=REPO, capture_output=True, text=True, check=False, timeout=120)


def test_A2_a_lone_surrogate_idempotency_key_exits_3_with_no_verdict_on_stdout(tmp_path):
    proc = _run_with_idempotency_key(tmp_path, "ORD-\ud800")
    print("rc", proc.returncode, "stdout", proc.stdout[:200], "stderr", proc.stderr[-400:])
    assert proc.returncode == 3
    assert proc.stdout.strip() == ""
    assert "NOTHING was verified" in proc.stderr


def test_A2_control_an_ordinary_key_in_the_same_field_still_reaches_a_verdict(tmp_path):
    proc = _run_with_idempotency_key(tmp_path, "ORD-control-1")
    print("rc", proc.returncode, proc.stderr[-300:])
    assert proc.returncode in (0, 1, 2)
    assert json.loads(proc.stdout)["verdict"] in ("OK", "TAMPERED", "INCOMPLETE")
