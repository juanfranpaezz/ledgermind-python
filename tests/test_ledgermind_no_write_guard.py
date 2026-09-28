"""The no-write guard over LedgerMind, proven to return both of its outcomes.

Plan reference: manifest v2 A4, narrowed by v2.1 B4. The guard replaced a before/after
commit count, which cannot see an uncommitted edit - the decorative-safeguard class
this project has been burned by before.

Every test here builds a THROWAWAY git repository in pytest's tmp_path with the same
protected layout the real LedgerMind has (``src/``, ``pom.xml``, both compose files,
``Dockerfile``, plus a ``target/`` build-output directory) and drives the real snapshot
code against it. Nothing here touches the actual LedgerMind checkout, which is
read-only for this project: planting a defect inside it to prove a guard would be the
very thing the guard exists to forbid.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools import ledgermind_snapshot as snap


def _git(repo: Path, *args):
    subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True, text=True)


@pytest.fixture()
def fake_ledger(tmp_path):
    repo = tmp_path / "fakeledger"
    (repo / "src" / "main" / "java" / "com" / "ledgermind" / "ledger").mkdir(parents=True)
    (repo / "target" / "classes").mkdir(parents=True)
    (repo / "src" / "main" / "java" / "com" / "ledgermind" / "ledger" / "Account.java").write_text(
        "class Account {}\n", encoding="utf-8"
    )
    (repo / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (repo / "Dockerfile").write_text("FROM eclipse-temurin:21-jre\n", encoding="utf-8")
    (repo / "docker-compose.yml").write_text("services:\n  postgres:\n", encoding="utf-8")
    (repo / "docker-compose.observability.yml").write_text("services:\n  app:\n", encoding="utf-8")
    (repo / "target" / "classes" / "Account.class").write_text("compiled\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "proof@local")
    _git(repo, "config", "user.name", "proof")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    return repo


def _snapshot(repo: Path, out: Path) -> Path:
    out.write_text(snap.build_snapshot(repo), encoding="utf-8")
    return out


def test_guard_PASSES_when_nothing_changed(fake_ledger, tmp_path):
    before = _snapshot(fake_ledger, tmp_path / "before.txt")
    after = _snapshot(fake_ledger, tmp_path / "after.txt")
    assert snap.compare(before, after) == 0


def test_guard_PASSES_when_only_target_was_written(fake_ledger, tmp_path):
    """v2.1 B4's named exclusion. Running the app writes target/; that is not a breach."""
    before = _snapshot(fake_ledger, tmp_path / "before.txt")
    (fake_ledger / "target" / "classes" / "Account.class").write_text("recompiled\n", encoding="utf-8")
    (fake_ledger / "target" / "ledgermind.jar").write_text("new artifact\n", encoding="utf-8")
    after = _snapshot(fake_ledger, tmp_path / "after.txt")
    assert snap.compare(before, after) == 0


def test_guard_FAILS_on_an_uncommitted_source_edit(fake_ledger, tmp_path):
    """The exact write the old commit-count guard could not see."""
    before = _snapshot(fake_ledger, tmp_path / "before.txt")
    (fake_ledger / "src" / "main" / "java" / "com" / "ledgermind" / "ledger" / "Account.java").write_text(
        "class Account { long balance; }\n", encoding="utf-8"
    )
    after = _snapshot(fake_ledger, tmp_path / "after.txt")
    assert snap.compare(before, after) == 1


def test_guard_FAILS_on_a_new_untracked_file_outside_target(fake_ledger, tmp_path):
    before = _snapshot(fake_ledger, tmp_path / "before.txt")
    (fake_ledger / "src" / "main" / "java" / "com" / "ledgermind" / "ledger" / "Stray.java").write_text(
        "stray\n", encoding="utf-8"
    )
    after = _snapshot(fake_ledger, tmp_path / "after.txt")
    assert snap.compare(before, after) == 1


def test_guard_FAILS_when_a_compose_file_is_edited(fake_ledger, tmp_path):
    """Authoring a compose service inside LedgerMind is cut by v2 A1; the guard enforces it."""
    before = _snapshot(fake_ledger, tmp_path / "before.txt")
    (fake_ledger / "docker-compose.observability.yml").write_text(
        "services:\n  app:\n  newthing:\n", encoding="utf-8"
    )
    after = _snapshot(fake_ledger, tmp_path / "after.txt")
    assert snap.compare(before, after) == 1


def test_guard_FAILS_when_a_protected_file_is_deleted(fake_ledger, tmp_path):
    before = _snapshot(fake_ledger, tmp_path / "before.txt")
    (fake_ledger / "Dockerfile").unlink()
    after = _snapshot(fake_ledger, tmp_path / "after.txt")
    assert snap.compare(before, after) == 1


def test_the_protected_set_actually_covers_the_real_checkout():
    """A snapshot that hashes nothing would pass forever. Pin the real coverage.

    COVERAGE HOLE, named by an independent verifier 2026-09-13 and closed by the
    PRE-DIRTY tests below: this test reads a STATIC committed file and never executes
    _is_protected or file_hashes, so it cannot notice the protected set collapsing.
    """
    evidence = Path(__file__).resolve().parents[1] / "docs" / "evidence" / "ledgermind-snapshot-before.txt"
    assert evidence.exists(), "the P0.0 before-snapshot is missing"
    text = evidence.read_text(encoding="utf-8")
    hashed = [line for line in text.splitlines() if len(line) > 66 and line[64:66] == "  "]
    assert len(hashed) >= 50, "protected set collapsed: " + str(len(hashed)) + " files hashed"
    assert "pom.xml" in text
    assert "docker-compose.observability.yml" in text
    assert "Dockerfile" in text


# ---------------------------------------------------------------------------
# THE PRE-DIRTY CASES - the SHA-256 leg, exercised on the tree shape that actually
# exists.
#
# Why these had to be added. All seven tests above start from a CLEAN committed fake
# repo, where any stray write also produces a NEW porcelain entry - so the porcelain
# leg alone catches every one of them, and collapsing _is_protected to always-False
# left all seven green (mutation M2 in the verifier's break-the-implementation run).
# The REAL LedgerMind checkout is already dirty: 6 modified files and 2 untracked ones
# at the before-snapshot. An edit to a file that is ALREADY modified leaves
# git status BYTE-IDENTICAL, so only the hash leg can see it - and that is the precise
# reason manifest v2 A4 replaced the old commit-count guard with a hashing one.
# ---------------------------------------------------------------------------

SRC_ACCOUNT = ("src", "main", "java", "com", "ledgermind", "ledger", "Account.java")
UNPROTECTED_DIRTY = ("observability", "grafana", "dashboards", "ledgermind.json")


@pytest.fixture()
def pre_dirty_ledger(fake_ledger):
    """The same fake repo, then made dirty the way the real checkout is dirty.

    Three kinds of pre-existing noise, all present BEFORE the before-snapshot:
    a modified protected source file, a modified protected build manifest, and a
    modified file OUTSIDE the protected set (the real tree has exactly one of those,
    observability/grafana/dashboards/ledgermind.json).
    """
    (fake_ledger / "observability" / "grafana" / "dashboards").mkdir(parents=True)
    (fake_ledger / Path(*UNPROTECTED_DIRTY)).write_text("{\"panels\": []}\n", encoding="utf-8")
    _git(fake_ledger, "add", "-A")
    _git(fake_ledger, "commit", "-qm", "dashboard")
    # now dirty it, and leave it dirty - this is the pre-existing state
    (fake_ledger / Path(*SRC_ACCOUNT)).write_text("class Account { /* wip */ }\n", encoding="utf-8")
    (fake_ledger / "pom.xml").write_text("<project><!-- wip --></project>\n", encoding="utf-8")
    (fake_ledger / Path(*UNPROTECTED_DIRTY)).write_text("{\"panels\": [1]}\n", encoding="utf-8")
    return fake_ledger


def test_the_pre_dirty_fixture_really_is_dirty_before_anything_is_measured(pre_dirty_ledger):
    """Guard the guard's test: if the fixture were clean, the tests below would prove
    nothing, because the porcelain leg would be doing all the work again."""
    entries = snap.porcelain(pre_dirty_ledger)
    assert len(entries) == 3, entries
    assert all(entry.lstrip().startswith("M") for entry in entries), entries


def test_guard_PASSES_on_a_PRE_DIRTY_tree_when_nothing_new_is_written(pre_dirty_ledger, tmp_path):
    """A pre-existing dirty entry on its own must NOT trip the gate."""
    before = _snapshot(pre_dirty_ledger, tmp_path / "before.txt")
    after = _snapshot(pre_dirty_ledger, tmp_path / "after.txt")
    assert "[PORCELAIN] entries=3" in before.read_text(encoding="utf-8")
    assert snap.compare(before, after) == 0


def test_guard_FAILS_when_an_ALREADY_MODIFIED_protected_file_is_edited_AGAIN(pre_dirty_ledger, tmp_path):
    """The load-bearing case on the real tree, and the one M2 sailed through."""
    before = _snapshot(pre_dirty_ledger, tmp_path / "before.txt")
    porcelain_before = snap.porcelain(pre_dirty_ledger)

    (pre_dirty_ledger / Path(*SRC_ACCOUNT)).write_text(
        "class Account { long stolenBalance; }\n", encoding="utf-8"
    )

    porcelain_after = snap.porcelain(pre_dirty_ledger)
    assert porcelain_after == porcelain_before, (
        "precondition of this test: git status must be BLIND to this edit; "
        "if it is not, the test is no longer exercising the hash leg"
    )
    after = _snapshot(pre_dirty_ledger, tmp_path / "after.txt")
    assert snap.compare(before, after) == 1


def test_the_SHA256_leg_is_what_catches_it_not_the_porcelain_leg(pre_dirty_ledger):
    """Same scenario, asserted directly on the two legs so the attribution is explicit."""
    porcelain_before = snap.porcelain(pre_dirty_ledger)
    hashes_before = snap.file_hashes(pre_dirty_ledger)

    (pre_dirty_ledger / "pom.xml").write_text("<project><!-- tampered --></project>\n", encoding="utf-8")

    assert snap.porcelain(pre_dirty_ledger) == porcelain_before
    hashes_after = snap.file_hashes(pre_dirty_ledger)
    assert hashes_after != hashes_before
    changed = [rel for (rel, a), (_, b) in zip(hashes_before, hashes_after) if a != b]
    assert changed == ["pom.xml"], changed


def test_file_hashes_covers_every_protected_kind_and_nothing_under_target(pre_dirty_ledger):
    """Executes _is_protected for real, instead of reading a static evidence file.

    Collapse _is_protected to always-False and this assertion is the first to die.
    """
    hashed = dict(snap.file_hashes(pre_dirty_ledger))
    assert "pom.xml" in hashed
    assert "Dockerfile" in hashed
    assert "docker-compose.yml" in hashed
    assert "docker-compose.observability.yml" in hashed
    assert "src/main/java/com/ledgermind/ledger/Account.java" in hashed
    assert hashed, "the protected set collapsed to zero files"
    assert not [rel for rel in hashed if rel.startswith("target/")]
    assert "/".join(UNPROTECTED_DIRTY) not in hashed


def test_KNOWN_BLIND_SPOT_an_already_dirty_file_OUTSIDE_the_protected_set(pre_dirty_ledger, tmp_path):
    """Documented limitation, demonstrated rather than asserted.

    A file that is already modified AND outside the protected set is invisible to both
    legs: porcelain already lists it, and it is never hashed. The real checkout has
    exactly one such file, observability/grafana/dashboards/ledgermind.json. This is the
    PLAN's protected-set scoping (v2 A4 names src/, pom.xml, both compose files,
    Dockerfile), not coder drift - but it should be named here rather than discovered
    later. If this test ever FAILS, the blind spot was closed: widen the protected set
    in the plan and delete this test.
    """
    before = _snapshot(pre_dirty_ledger, tmp_path / "before.txt")
    (pre_dirty_ledger / Path(*UNPROTECTED_DIRTY)).write_text("{\"panels\": [1,2,3]}\n", encoding="utf-8")
    after = _snapshot(pre_dirty_ledger, tmp_path / "after.txt")
    assert snap.compare(before, after) == 0
