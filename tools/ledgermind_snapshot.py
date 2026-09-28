"""The no-write guard over the LedgerMind Java checkout.

Plan reference: manifest v2 section A4, as NARROWED by v2.1 section B4.

WHY THIS EXISTS AT ALL. The Global Definition of Done originally enforced "we never
wrote under LedgerMind" with a before/after commit count. A commit count cannot see
an uncommitted edit, and the LedgerMind tree is already dirty, so a stray write would
have blended into pre-existing noise. The guard was sized for the wrong object.

WHAT A SNAPSHOT IS (v2.1 B4, governing):

1. ``git status --porcelain -- . ':(exclude)target'`` - verbatim, with ``target/``
   and everything under it excluded. The exclusion is narrow and named: ``target/``
   is Maven build output, it is not source, and writing it is an unavoidable
   consequence of running the app (AC-0.1's fallback path runs ``./mvnw
   spring-boot:run``). Without the exclusion the plan's own stand-up step would
   break the plan's own no-write gate, and the first reflex would be to weaken the
   guard under pressure - the worst possible moment to edit a guard.
2. SHA-256 per tracked file under ``src/``, plus ``pom.xml``, ``docker-compose.yml``,
   ``docker-compose.observability.yml`` and ``Dockerfile``. None of these live under
   ``target/``.

Everything the invariant actually protects - source, build manifest, both compose
files, the Dockerfile - stays covered, and an untracked NEW file anywhere outside
``target/`` still trips the gate through the porcelain leg.

Usage::

    py tools/ledgermind_snapshot.py --repo <ledgermind-checkout> \\
        --out docs/evidence/ledgermind-snapshot-before.txt
    py tools/ledgermind_snapshot.py --compare before.txt after.txt

``--compare`` exits 0 when the two snapshots are identical (``diff_lines == 0``) and
1 otherwise, printing the differing lines.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

# The LedgerMind checkout: $LEDGERMIND_REPO, else a sibling directory named ledgermind.
DEFAULT_REPO = Path(os.environ.get("LEDGERMIND_REPO", str(Path(__file__).resolve().parents[2] / "ledgermind")))

# Everything the invariant protects. Directories are walked; files are hashed directly.
HASHED_DIRS = ("src",)
HASHED_FILES = ("pom.xml", "docker-compose.yml", "docker-compose.observability.yml", "Dockerfile")

EXCLUDED_PREFIX = "target/"


def _git(repo: Path, args):
    proc = subprocess.run(
        ["git"] + list(args),
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("git " + " ".join(args) + " failed: " + proc.stderr.strip())
    return proc.stdout


def porcelain(repo: Path) -> list[str]:
    """git status --porcelain with target/ excluded, exactly as v2.1 B4 specifies."""
    raw = _git(repo, ["status", "--porcelain", "--", ".", ":(exclude)target"])
    return [line for line in raw.splitlines() if line.strip()]


def tracked_files(repo: Path) -> list[str]:
    raw = _git(repo, ["ls-files"])
    return [line for line in raw.splitlines() if line.strip()]


def _is_protected(rel_path: str) -> bool:
    if rel_path.startswith(EXCLUDED_PREFIX):
        return False
    if rel_path in HASHED_FILES:
        return True
    return any(rel_path == d or rel_path.startswith(d + "/") for d in HASHED_DIRS)


def file_hashes(repo: Path):
    """SHA-256 of every protected tracked file, as it sits on disk right now."""
    out = []
    for rel in sorted(tracked_files(repo)):
        if not _is_protected(rel):
            continue
        path = repo / rel
        if not path.exists():
            out.append((rel, "MISSING-FROM-WORKING-TREE"))
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        out.append((rel, digest))
    return out


def build_snapshot(repo: Path) -> str:
    head = _git(repo, ["rev-parse", "HEAD"]).strip()
    status = porcelain(repo)
    hashes = file_hashes(repo)
    lines = []
    lines.append("# LedgerMind no-write snapshot (manifest v2 A4, narrowed by v2.1 B4)")
    lines.append("# repo: " + str(repo))
    lines.append("# HEAD: " + head)
    lines.append("# porcelain command: git status --porcelain -- . ':(exclude)target'")
    lines.append("# protected set: src/**, " + ", ".join(HASHED_FILES))
    lines.append("# NOTE: HEAD and timestamps are informational; the comparison is over")
    lines.append("#       the PORCELAIN and SHA256 sections below.")
    lines.append("")
    lines.append("[PORCELAIN] entries=" + str(len(status)))
    for line in status:
        lines.append(line)
    lines.append("")
    lines.append("[SHA256] files=" + str(len(hashes)))
    for rel, digest in hashes:
        lines.append(digest + "  " + rel)
    lines.append("")
    return "\n".join(lines)


def _comparable(text: str) -> list[str]:
    """The lines the comparison is defined over: everything except '#' commentary."""
    return [line for line in text.splitlines() if not line.startswith("#")]


def compare(before: Path, after: Path) -> int:
    a = _comparable(before.read_text(encoding="utf-8"))
    b = _comparable(after.read_text(encoding="utf-8"))
    only_before = [line for line in a if line not in b]
    only_after = [line for line in b if line not in a]
    diff_lines = len(only_before) + len(only_after)
    print("before: " + str(before))
    print("after:  " + str(after))
    print("diff_lines: " + str(diff_lines))
    for line in only_before:
        print("  -" + line)
    for line in only_after:
        print("  +" + line)
    if diff_lines == 0:
        print("NO_WRITE_GUARD: PASS (snapshots identical)")
        return 0
    print("NO_WRITE_GUARD: FAIL (the LedgerMind tree changed outside target/)")
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="LedgerMind no-write snapshot / compare")
    parser.add_argument("--repo", default=str(DEFAULT_REPO))
    parser.add_argument("--out", default=None, help="write the snapshot here instead of stdout")
    parser.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args(argv)

    if args.compare:
        return compare(Path(args.compare[0]), Path(args.compare[1]))

    repo = Path(args.repo)
    if not (repo / ".git").exists():
        print("ERROR: not a git checkout: " + str(repo), file=sys.stderr)
        return 2
    snapshot = build_snapshot(repo)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(snapshot, encoding="utf-8")
        print("snapshot written: " + str(out))
        print("porcelain entries + hashed files recorded.")
    else:
        print(snapshot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
