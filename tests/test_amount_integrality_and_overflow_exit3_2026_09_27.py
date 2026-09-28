"""Amend round 1 (2026-09-27), parity gate r1 findings in the CLI (outside Run B).

P4: an amount (or any integer field) of ``1e999`` parses as ``float('inf')``; ``int(inf)`` raises
OverflowError, which the CLI's tool-error tuple did not catch, so the process died with exit 1 -
the code that means TAMPERED. A number the tool cannot read is a TOOL ERROR: exit 3.
P5: an amount of ``<n>.9`` was truncated by ``int()`` to ``<n>`` and verified as if nothing were wrong.
Ledger amounts are whole minor units: a fractional amount is a malformed capture, exit 3. The same
number written as an integral float (``<n>.0``) is still that number and keeps the clean exit code.

Each case runs the CLI in a subprocess on a copy of the recorded clean half with ONE literal edited in
postings_and_hashes.json (the literal is written as text, so ``1e999`` reaches the parser as written).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLEAN = REPO / "tests" / "fixtures" / "recorded" / "clean"
SENTINEL = "__AMEND_R1_LITERAL__"


def _run_with_literal(tmp_path: Path, field: str, literal: str | None) -> subprocess.CompletedProcess:
    root = tmp_path / "corpus"
    shutil.copytree(CLEAN, root / "clean")
    bundle_path = root / "clean" / "postings_and_hashes.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    original = bundle["postings"][0][field]
    assert isinstance(original, int) and not isinstance(original, bool)
    if literal is not None:
        bundle["postings"][0][field] = SENTINEL
        text = json.dumps(bundle).replace('"' + SENTINEL + '"', literal.replace("<n>", str(original)))
        bundle_path.write_text(text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "tools.verify_report", "--corpus", "recorded", "--half", "clean",
         "--corpus-root", str(root), "--json"],
        cwd=REPO, capture_output=True, text=True, check=False, timeout=120)


def test_P4_an_amount_of_1e999_exits_3_not_1(tmp_path):
    proc = _run_with_literal(tmp_path, "amount", "1e999")
    print("rc", proc.returncode, proc.stderr[-300:])
    assert proc.returncode == 3
    assert "NOTHING was verified" in proc.stderr


def test_P4_an_integer_id_of_1e999_exits_3_not_1(tmp_path):
    proc = _run_with_literal(tmp_path, "id", "1e999")
    print("rc", proc.returncode, proc.stderr[-300:])
    assert proc.returncode == 3
    assert "OverflowError" in proc.stderr


def test_P5_a_fractional_amount_is_refused_with_exit_3_not_truncated(tmp_path):
    proc = _run_with_literal(tmp_path, "amount", "<n>.9")
    print("rc", proc.returncode, proc.stderr[-300:])
    assert proc.returncode == 3
    assert "whole number of minor units" in proc.stderr


def test_P5_an_integral_float_amount_keeps_the_clean_exit_code(tmp_path):
    clean = _run_with_literal(tmp_path / "control", "amount", None)
    integral = _run_with_literal(tmp_path / "integral", "amount", "<n>.0")
    print("clean rc", clean.returncode, "integral-float rc", integral.returncode)
    assert clean.returncode in (0, 2)
    assert integral.returncode == clean.returncode
