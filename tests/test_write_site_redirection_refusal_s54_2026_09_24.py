"""S54 (2026-09-24): the recorder's WRITES, not just its --out, must stay out of the fixture tree.

The --out guard (``_is_inside``) decides once, on --out and its ancestors, before a network
phase of up to ~90 s. The recorder then writes DESCENDANTS of --out (``clean/``, ``tampered/``,
``_corpus.json``). Measured by the 2026-09-24 gate, identically before and after the UNC fix:

- (a1) a JUNCTION below --out (``<out>/clean`` -> tests/fixtures/recorded/clean) lands the half
  in the protected tree;
- (a2) a HARDLINK below --out (``<out>/_corpus.json`` sharing its file id with the shipped
  ``_corpus.json``) - ``write_text`` truncates the SHARED file, so the shipped bytes change;
- (b)  a junction planted at --out DURING the network phase lands the whole capture;
- (c)  the two fail-closed branches of the guard (realpath raises; an existing ancestor cannot
  be stat'ed) were exercised by no test, so a mutant weakening either survived all 348.

Every test here runs against a RELOCATED copy of tests/fixtures under ``tmp_path``: a guard
regression can only ever damage that copy, never the shipped tree. The junctions and hardlinks
are made by the OS's own ``mklink`` (no admin right needed for /J or /H), so the file ids are the
real ones. Windows only: junctions and ``mklink`` do not exist elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tools import record_fixtures
from tools.record_fixtures import RecorderError

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="junctions and mklink /J /H are Windows-only; the vectors are NTFS ones"
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_FIXTURES = REPO_ROOT / "tests" / "fixtures"
HALF_FILES = sorted(
    [name for name, _ in record_fixtures.HTTP_READS]
    + ["reconciliation.json", "postings_and_hashes.json"]
)


def _mklink(kind: str, link: Path, target: Path) -> None:
    proc = subprocess.run(
        ["cmd", "/c", "mklink", kind, str(link), str(target)], capture_output=True, text=True
    )
    assert proc.returncode == 0, "mklink " + kind + " failed: " + proc.stdout + proc.stderr


def _fingerprint(root: Path):
    """Every directory and every file's bytes under ``root`` - a change anywhere shows."""
    rows = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        rows.append(("dir", rel))
        for name in filenames:
            data = Path(dirpath, name).read_bytes()
            rows.append((os.path.join(rel, name), hashlib.sha256(data).hexdigest()))
    return sorted(rows)


class _Client:
    def __init__(self):
        self.calls = []
        self.http_log = []
        self.retries_after_429 = 0

    def post_json(self, path, body=None):
        self.calls.append(("POST", path))
        return {}

    def get_json(self, path):
        self.calls.append(("GET", path))
        return {}

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        return 200, {"captured_from": path}


@pytest.fixture
def relocated(tmp_path, monkeypatch):
    """A byte copy of the shipped fixture tree, installed as the recorder's protected roots.

    The network, the chain wait and the DB read are stubbed; ``capture_half`` is the SHIPPED
    one, so the real write sites are exercised."""
    fixtures = tmp_path / "repo" / "tests" / "fixtures"
    shutil.copytree(REAL_FIXTURES, fixtures)
    monkeypatch.setattr(record_fixtures, "FIXTURES_ROOT", fixtures)
    monkeypatch.setattr(record_fixtures, "RECORDED_ROOT", fixtures / "recorded")
    client = _Client()
    monkeypatch.setattr(record_fixtures, "RateLimitedClient", lambda *a, **k: client)
    monkeypatch.setattr(record_fixtures, "wait_for_chain_complete", lambda c: (True, {"ok": True}))
    monkeypatch.setattr(record_fixtures, "wait_for_stable_verify", lambda c, **k: (True, {"ok": 1}))
    monkeypatch.setattr(record_fixtures, "capture_db", lambda: ([], [], []))
    outside = tmp_path / "outside"
    outside.mkdir()
    return fixtures, outside


# ---------------------------------------------------------------- (a1) junction below --out


@pytest.mark.parametrize("half", ["clean", "tampered"])
def test_FIRES_a_JUNCTION_below_out_cannot_carry_a_half_into_the_tree(relocated, half):
    """RED at base 325fcf5: rc 0 and the half's nine files overwrite recorded/<half>."""
    fixtures, outside = relocated
    out = outside / "capture"
    out.mkdir()
    _mklink("/J", out / half, fixtures / "recorded" / half)
    before = _fingerprint(fixtures)
    argv = ["--out", str(out)] + (["--destructive-reset-and-tamper"] if half == "tampered" else [])

    with pytest.raises(RecorderError) as excinfo:
        record_fixtures.main(argv)

    assert "REFUSING TO WRITE" in str(excinfo.value)
    assert _fingerprint(fixtures) == before, "not one byte of the protected tree may change"


# ---------------------------------------------------------------- (a2) hardlink below --out


@pytest.mark.parametrize(
    "rel", ["_corpus.json", "clean/journal_checkpoint_verify.json"], ids=["corpus", "half-file"]
)
def test_FIRES_a_HARDLINK_below_out_cannot_rewrite_the_shipped_bytes(relocated, rel):
    """RED at base 325fcf5: write_text opens the existing name and TRUNCATES the file id it
    shares with the shipped file. The capture itself is legitimate and must still succeed."""
    fixtures, outside = relocated
    out = outside / "capture"
    (out / "clean").mkdir(parents=True)
    shipped = fixtures / "recorded" / rel
    _mklink("/H", out / rel, shipped)
    assert os.stat(shipped).st_nlink == 2  # premise: the two names really share one file
    before = _fingerprint(fixtures)

    assert record_fixtures.main(["--out", str(out)]) == 0

    assert _fingerprint(fixtures) == before, "the shipped file's bytes were rewritten"
    assert os.stat(shipped).st_nlink == 1, "the capture must now be its own file"
    assert os.stat(out / rel).st_nlink == 1
    assert (out / rel).read_bytes() != shipped.read_bytes()


# ---------------------------------------------------------------- (b) junction planted mid-run


@pytest.mark.parametrize(
    "into",
    ["derived_from_source", "recorded", "derived_from_source/adversarial"],
    ids=["derived", "recorded", "dir-without-a-half-subdir"],
)
def test_FIRES_a_junction_planted_DURING_the_network_phase_does_not_land(
    relocated, monkeypatch, into
):
    """RED at base 325fcf5. --out does not exist when the guard runs (it passes); the junction
    appears while the recorder waits for the chain. ``recorded`` is the sharper case: a write
    INTO RECORDED_ROOT is legal for the destructive regeneration, so the write site must bind
    to what the guard APPROVED, not re-derive permission from where the path points now.
    ``adversarial`` has no ``clean/`` inside, so it also pins the check BEFORE mkdir: without
    it, mkdir would create an empty ``clean/`` in the tree before anything else refuses."""
    fixtures, outside = relocated
    out = outside / "late"

    def chain_wait_with_a_plant(client):
        _mklink("/J", out, fixtures / into)
        return True, {"ok": True}

    monkeypatch.setattr(record_fixtures, "wait_for_chain_complete", chain_wait_with_a_plant)
    before = _fingerprint(fixtures)

    with pytest.raises(RecorderError) as excinfo:
        record_fixtures.main(["--out", str(out)])

    assert "REFUSING TO WRITE" in str(excinfo.value)
    assert out.is_junction(), "premise: the plant really happened"
    assert _fingerprint(fixtures) == before


def test_FIRES_a_directory_swapped_for_a_junction_AFTER_the_first_check_does_not_land(
    relocated, monkeypatch
):
    """Pins the temp-file leg of the write site: the directory passes its check and is created,
    then - right before the temp file is made - it is renamed away and a junction into the tree
    takes its name. The bytes are written inside the tree for an instant; the check of the
    temp file's own resolved location must refuse and remove it before any shipped name is
    touched. (At base there is no temp file, so this test cannot run there.)"""
    fixtures, outside = relocated
    out = outside / "capture"
    real_mkstemp = record_fixtures.tempfile.mkstemp
    swapped = []

    def mkstemp_after_a_swap(*args, dir=None, **kwargs):
        directory = Path(dir)
        if directory.name == "clean" and not swapped:
            directory.rename(directory.with_name("clean_moved_away"))
            _mklink("/J", directory, fixtures / "recorded" / "clean")
            swapped.append(directory)
        return real_mkstemp(*args, dir=dir, **kwargs)

    monkeypatch.setattr(
        record_fixtures, "tempfile", type("T", (), {"mkstemp": staticmethod(mkstemp_after_a_swap)})
    )
    before = _fingerprint(fixtures)

    with pytest.raises(RecorderError) as excinfo:
        record_fixtures.main(["--out", str(out)])

    assert swapped, "premise: the swap really happened"
    assert "redirects the write" in str(excinfo.value)
    assert _fingerprint(fixtures) == before, "no temp file and no shipped byte may remain changed"


# ---------------------------------------------------------------- write-site identity leg


def test_FIRES_the_write_site_refuses_a_plain_target_inside_the_tree_outside_RECORDED_ROOT(
    relocated,
):
    """The identity leg of the write site on its own: no redirection anywhere, the target is
    simply inside the protected tree and not under RECORDED_ROOT. Only a broken --out guard
    could hand it such a path, which is why it exists. (At base this helper does not exist.)"""
    fixtures, _ = relocated
    before = _fingerprint(fixtures)

    with pytest.raises(RecorderError) as excinfo:
        record_fixtures._write_text_where_approved(
            fixtures / "derived_from_source" / "planted.json", "{}\n"
        )

    assert "inside the shipped fixture tree" in str(excinfo.value)
    assert _fingerprint(fixtures) == before


# ---------------------------------------------------------------- (c) fail-closed branches


def test_FIRES_a_path_realpath_cannot_resolve_is_refused_not_passed_through(
    relocated, monkeypatch
):
    """Kills the gate's surviving mutant M3 (realpath error -> use the raw path)."""
    fixtures, outside = relocated

    def broken_realpath(path, *args, **kwargs):
        raise OSError(5, "planted: the filesystem refused to resolve this path")

    monkeypatch.setattr(record_fixtures.os.path, "realpath", broken_realpath)
    with pytest.raises(RecorderError) as excinfo:
        record_fixtures._is_inside(outside / "new", fixtures)

    assert "could not be resolved through the filesystem" in str(excinfo.value)


def test_FIRES_an_existing_ancestor_that_cannot_be_stated_is_refused_not_skipped(
    relocated, monkeypatch
):
    """Kills the gate's surviving mutant M5 (ancestor stat OSError -> treat it as missing and
    keep walking up, which ends in 'outside' for any path under a readable drive root)."""
    fixtures, outside = relocated
    locked = outside / "locked"
    locked.mkdir()
    real_stat = os.stat
    locked_key = os.path.normcase(str(locked))

    def stat_denied_on_locked(path, *args, **kwargs):
        if os.path.normcase(os.fspath(path)) == locked_key:
            raise PermissionError(13, "planted: access denied", os.fspath(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(record_fixtures.os, "stat", stat_denied_on_locked)
    with pytest.raises(RecorderError) as excinfo:
        record_fixtures._is_inside(locked / "new", fixtures)

    assert "exists but cannot be stat'ed" in str(excinfo.value)


# ---------------------------------------------------------------- legitimate writes still work


def _expected_bytes(tmp_path: Path, text: str) -> bytes:
    control = tmp_path / "write_text_control.json"
    control.write_text(text, encoding="utf-8")
    return control.read_bytes()


def test_SILENT_a_plain_outside_out_gets_every_file_with_write_text_bytes(relocated, tmp_path):
    fixtures, outside = relocated
    out = outside / "capture"
    before = _fingerprint(fixtures)

    assert record_fixtures.main(["--out", str(out)]) == 0

    assert sorted(p.name for p in (out / "clean").iterdir()) == HALF_FILES
    sample = json.dumps({"captured_from": "/api/journal/verify"}, indent=2, ensure_ascii=False)
    assert (out / "clean" / "journal_verify.json").read_bytes() == _expected_bytes(
        tmp_path, sample + "\n"
    )
    meta = json.loads((out / "_corpus.json").read_text(encoding="utf-8"))
    assert meta["capture_mode"] == "as-found-read-only"
    assert not list(out.rglob("*.tmp")), "no temp file may be left behind"
    assert _fingerprint(fixtures) == before


def test_SILENT_an_out_spelled_THROUGH_a_junction_to_an_outside_dir_still_captures(relocated):
    """A junction in --out ITSELF is resolved when the guard runs, so it is not a redirection
    at write time; the files land in the real directory it names."""
    fixtures, outside = relocated
    real_dir = outside / "real_target"
    real_dir.mkdir()
    _mklink("/J", outside / "alias", real_dir)

    assert record_fixtures.main(["--out", str(outside / "alias" / "capture")]) == 0

    assert sorted(p.name for p in (real_dir / "capture" / "clean").iterdir()) == HALF_FILES
    assert (real_dir / "capture" / "_corpus.json").is_file()


def test_SILENT_an_extended_length_prefixed_outside_out_still_captures(relocated):
    fixtures, outside = relocated
    out = outside / "prefixed"

    assert record_fixtures.main(["--out", "\\\\?\\" + str(out)]) == 0

    assert sorted(p.name for p in (out / "clean").iterdir()) == HALF_FILES
    assert (out / "_corpus.json").is_file()


def test_SILENT_the_canned_regeneration_still_rewrites_both_halves_in_RECORDED_ROOT(relocated):
    """The one legal write into the tree, with the SHIPPED capture_half: both halves and the
    corpus metadata are rewritten in place; nothing else in the tree changes."""
    fixtures, _ = relocated
    derived_before = _fingerprint(fixtures / "derived_from_source")
    recorded = fixtures / "recorded"
    corpus_before = (recorded / "_corpus.json").read_bytes()

    assert record_fixtures.main(["--destructive-reset-and-tamper"]) == 0

    for half in ("clean", "tampered"):
        assert sorted(p.name for p in (recorded / half).iterdir()) == HALF_FILES
        body = json.loads((recorded / half / "journal_verify.json").read_text(encoding="utf-8"))
        assert body == {"captured_from": "/api/journal/verify"}
    assert (recorded / "_corpus.json").read_bytes() != corpus_before
    assert json.loads((recorded / "_corpus.json").read_text(encoding="utf-8"))["ac_0_2_eligible"]
    assert not list(recorded.rglob("*.tmp"))
    assert _fingerprint(fixtures / "derived_from_source") == derived_before
