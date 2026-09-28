"""R1/R2 (2026-09-24): the last two windows of the recorder's write site, closed.

The S54 gate (an independent review kept in private project notes, not in this repository)
measured two residuals in ``_write_text_where_approved`` (tools/record_fixtures.py):

- R1: a parent directory MOVED AWAY before the post-write temp check still passed it, because a
  non-strict ``os.path.realpath`` hands a missing path back unchanged. An attacker then plants a
  junction into the protected tree at the old name and moves the temp file in, and ``os.replace``
  lands the capture there. The window was the whole temp check (median 3.9 ms, p95 14 ms), not
  the "microseconds" the docstring claimed.
- R2: nothing checked that the TEMP NAME still named the file this process wrote. A hardlink to a
  shipped file put at the temp name was renamed into place: no error, and the capture silently
  became the shipped file's bytes.

Every test drives the SHIPPED helper against a byte copy of tests/fixtures under ``tmp_path``,
installed as the recorder's protected roots, so a regression can only ever damage the copy. The
swaps are made deterministically from inside the check the helper runs on its temp file (a wrapper
around ``_refuse_if_redirected_or_protected``) - the exact points the gate's attacker process raced
for. Windows only: junctions are NTFS objects.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import shutil
import stat
import struct
import tempfile
from pathlib import Path

import pytest

from tools import record_fixtures
from tools.record_fixtures import RecorderError

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="junctions are NTFS objects; these vectors are Windows ones"
)

if os.name == "nt":
    import _winapi

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_FIXTURES = REPO_ROOT / "tests" / "fixtures"
CAPTURE = '{"captured": "by this run, not shipped"}\n'


def _fingerprint(root: Path):
    """Every directory, every file's bytes and link count under ``root``."""
    rows = []
    for dirpath, _dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        rows.append(("dir", rel, "", 0))
        for name in filenames:
            path = Path(dirpath, name)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            rows.append(("file", os.path.join(rel, name), digest, os.stat(path).st_nlink))
    return sorted(rows)


@pytest.fixture
def relocated(tmp_path, monkeypatch):
    """A byte copy of the shipped fixture tree as the protected roots, plus an approved
    capture directory OUTSIDE it (``<tmp>/outside/capture/clean``), already created."""
    fixtures = tmp_path / "repo" / "tests" / "fixtures"
    shutil.copytree(REAL_FIXTURES, fixtures)
    monkeypatch.setattr(record_fixtures, "FIXTURES_ROOT", fixtures)
    monkeypatch.setattr(record_fixtures, "RECORDED_ROOT", fixtures / "recorded")
    out_dir = tmp_path / "outside" / "capture" / "clean"
    out_dir.mkdir(parents=True)
    return fixtures, out_dir


def _hook_the_temp_check(monkeypatch, before=None, after=None):
    """Run ``before`` / ``after`` around the helper's check of its TEMP file, and only that one."""
    real_check = record_fixtures._refuse_if_redirected_or_protected
    seen = []

    def wrapped(path, *args, **kwargs):
        is_temp = str(path).endswith(".tmp")
        if is_temp:
            seen.append(Path(path))
            if before is not None:
                before(Path(path))
        real_check(path, *args, **kwargs)
        if is_temp and after is not None:
            after(Path(path))

    monkeypatch.setattr(record_fixtures, "_refuse_if_redirected_or_protected", wrapped)
    return seen


def _write_and_catch(target: Path):
    try:
        record_fixtures._write_text_where_approved(target, CAPTURE)
    except RecorderError as exc:
        return exc
    return None


def _is_junction(path: Path) -> bool:
    """``Path.is_junction`` is Python 3.12+; the project declares 3.11+. The entry's own reparse
    tag (``lstat``, available since 3.8) says the same thing on every supported version."""
    return os.lstat(path).st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT


def _turn_the_existing_empty_directory_into_a_junction(directory: Path, target: Path) -> None:
    """FSCTL_SET_REPARSE_POINT on a directory that ALREADY exists (``_winapi.CreateJunction`` only
    makes a new one). Same entry, same file id, so ``lstat`` still matches; following it now
    leads to ``target``. No privilege is needed, as for any junction the user owns."""
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    substitute = ("\\??\\" + os.path.abspath(target)).encode("utf-16-le")
    printed = os.path.abspath(target).encode("utf-16-le")
    data = struct.pack("<HHHH", 0, len(substitute), len(substitute) + 2, len(printed))
    data += substitute + b"\0\0" + printed + b"\0\0"
    raw = struct.pack("<IHH", stat.IO_REPARSE_TAG_MOUNT_POINT, len(data), 0) + data
    buffer = ctypes.create_string_buffer(raw, len(raw))
    generic_write, open_existing = 0x40000000, 3
    backup_semantics, open_reparse_point = 0x02000000, 0x00200000
    handle = kernel32.CreateFileW(
        os.fspath(directory), generic_write, 0, None, open_existing,
        backup_semantics | open_reparse_point, None,
    )
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        returned = wintypes.DWORD()
        fsctl_set_reparse_point = 0x000900A4
        if not kernel32.DeviceIoControl(
            handle, fsctl_set_reparse_point, buffer, len(raw), None, 0, ctypes.byref(returned), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(handle)


# ---------------------------------------------------------------- R1, strict leg


def test_FIRES_R1_a_parent_moved_away_BEFORE_the_temp_check_is_refused(relocated, monkeypatch):
    """The gate's attack, made deterministic. RED at 6ab1906: the temp check passed the missing
    path, the junction was planted, and the capture replaced the relocated shipped
    recorded/clean/journal_verify.json with no error."""
    fixtures, out_dir = relocated
    shipped = fixtures / "recorded" / "clean" / "journal_verify.json"
    away = out_dir.with_name("clean_moved_away")

    def move_the_parent_away(temp):
        out_dir.rename(away)  # the temp file travels with its directory

    def plant_a_junction_and_move_the_temp_in(temp):
        _winapi.CreateJunction(str(shipped.parent), str(out_dir))
        os.rename(away / temp.name, shipped.parent / temp.name)

    seen = _hook_the_temp_check(
        monkeypatch, before=move_the_parent_away, after=plant_a_junction_and_move_the_temp_in
    )
    before = _fingerprint(fixtures)

    raised = _write_and_catch(out_dir / "journal_verify.json")

    assert seen, "premise: the helper checked a temp file, and the parent was moved away first"
    assert shipped.read_text(encoding="utf-8") != CAPTURE, "the capture LANDED in the tree"
    assert _fingerprint(fixtures) == before, "no shipped byte and no stray temp may remain"
    assert raised is not None, "a missing parent at the temp check must be refused, not passed"
    assert "could not be resolved through the filesystem" in str(raised)


# ---------------------------------------------------------------- R1, final identity leg


def test_FIRES_R1_a_swap_AFTER_the_temp_check_passes_is_refused_before_os_replace(
    relocated, monkeypatch
):
    """The swap lands after every path check has passed: rename the directory away, plant a
    junction into the tree at its name, move the temp in. Only the identity re-check right
    before ``os.replace`` can see it. RED at 6ab1906: the capture landed, no error."""
    fixtures, out_dir = relocated
    shipped = fixtures / "recorded" / "clean" / "journal_verify.json"
    away = out_dir.with_name("clean_moved_away")

    def swap_after_the_check(temp):
        out_dir.rename(away)
        _winapi.CreateJunction(str(shipped.parent), str(out_dir))
        os.rename(away / temp.name, shipped.parent / temp.name)

    seen = _hook_the_temp_check(monkeypatch, after=swap_after_the_check)
    before = _fingerprint(fixtures)

    raised = _write_and_catch(out_dir / "journal_verify.json")

    assert seen, "premise: the swap ran after the helper's temp check"
    assert _is_junction(out_dir), "premise: the capture directory really is a junction now"
    assert shipped.read_text(encoding="utf-8") != CAPTURE, "the capture LANDED in the tree"
    assert _fingerprint(fixtures) == before, "no shipped byte and no stray temp may remain"
    assert raised is not None and type(raised).__name__ == "WriteSiteSwapError", repr(raised)
    assert "no longer the directory" in str(raised)


# ---------------------------------------------------------------- R1, final LOCATION leg (AMEND A1)


def test_FIRES_R1_an_ANCESTOR_moved_INTO_the_tree_behind_a_junction_AFTER_the_temp_check_is_refused(
    relocated, monkeypatch
):
    """The final-residuals gate's V1 (2026-09-24): after the temp check, the capture directory's
    PARENT is moved into the protected tree and a junction is left at its old name. The capture
    directory moves with it, so its lstat and stat ids still match, and the temp keeps its id and
    link count 1: identity cannot see it. RED at f7fff205 (the R1/R2 build): no error, and the
    capture landed at fixtures/derived_from_source/capture_moved/clean/journal_verify.json."""
    fixtures, out_dir = relocated
    ancestor = out_dir.parent
    moved = fixtures / "derived_from_source" / "capture_moved"
    landed = moved / "clean" / "journal_verify.json"

    def move_the_ancestor_into_the_tree(temp):
        os.rename(ancestor, moved)
        _winapi.CreateJunction(str(moved), str(ancestor))

    seen = _hook_the_temp_check(monkeypatch, after=move_the_ancestor_into_the_tree)
    before = _fingerprint(fixtures)

    raised = _write_and_catch(out_dir / "journal_verify.json")

    assert seen and _is_junction(ancestor), "premise: the ancestor was moved and a junction left"
    assert not landed.exists(), "the capture LANDED in the tree"
    assert raised is not None and type(raised).__name__ == "WriteSiteSwapError", repr(raised)
    assert "now resolves to" in str(raised)
    assert sorted(moved.rglob("*")) == [moved / "clean"], "the refused temp was left in the tree"
    moved_rel = os.path.join("derived_from_source", "capture_moved")
    assert [row for row in _fingerprint(fixtures) if not row[1].startswith(moved_rel)] == before
    assert not getattr(raised, "__notes__", None), "cleanup reached the temp: nothing to report"


# ---------------------------------------------------------------- R1, each identity leg alone (AMEND A3)


def test_FIRES_R1_lstat_leg_a_junction_at_the_name_back_to_the_MOVED_original_is_refused_by_identity(
    relocated, monkeypatch
):
    """The directory is renamed away and a junction to the ORIGINAL (now moved) directory is put
    at its name. ``stat`` follows the junction to the original, so its id still matches; only
    ``lstat`` (the junction's own id) sees it. The location leg would refuse this input too, so
    the identity message is what pins the lstat leg: the final-residuals gate removed it and every
    test stayed green (b6). Without any check the capture would land in the moved directory."""
    fixtures, out_dir = relocated
    away = out_dir.with_name("clean_moved_away")

    def junction_back_to_the_moved_original(temp):
        out_dir.rename(away)
        _winapi.CreateJunction(str(away), str(out_dir))

    seen = _hook_the_temp_check(monkeypatch, after=junction_back_to_the_moved_original)
    before = _fingerprint(fixtures)

    raised = _write_and_catch(out_dir / "journal_verify.json")

    assert seen and _is_junction(out_dir), "premise: a junction now sits at the directory's name"
    assert os.path.samestat(os.stat(out_dir), os.lstat(away)), "premise: stat reaches the original"
    assert not (away / "journal_verify.json").exists(), "the capture was renamed into place"
    assert raised is not None and type(raised).__name__ == "WriteSiteSwapError", repr(raised)
    assert "no longer the directory" in str(raised)
    assert sorted(away.iterdir()) == [], "the refused temp was left behind"
    assert _fingerprint(fixtures) == before


def test_FIRES_R1_stat_leg_the_original_directory_turned_into_a_junction_IN_PLACE_is_refused_by_identity(
    relocated, monkeypatch
):
    """The temp is parked outside, the capture directory ITSELF is made a junction into the tree
    (same entry, same file id - ``lstat`` still matches), and the temp is moved to the junction's
    target. Only ``stat`` (every component followed) sees it. The location leg would refuse this
    input too, so the identity message is what pins the stat leg: the final-residuals gate removed
    it and every test stayed green (b7). Without any check the capture would replace the
    relocated shipped recorded/clean/journal_verify.json."""
    fixtures, out_dir = relocated
    shipped = fixtures / "recorded" / "clean" / "journal_verify.json"
    original = os.lstat(out_dir)

    def junction_in_place_into_the_tree(temp):
        parked = out_dir.parent / temp.name
        os.rename(temp, parked)  # a junction can only be set on an EMPTY directory
        _turn_the_existing_empty_directory_into_a_junction(out_dir, shipped.parent)
        os.rename(parked, shipped.parent / temp.name)

    seen = _hook_the_temp_check(monkeypatch, after=junction_in_place_into_the_tree)
    before = _fingerprint(fixtures)

    raised = _write_and_catch(out_dir / "journal_verify.json")

    assert seen and _is_junction(out_dir), "premise: the directory itself is a junction now"
    assert os.path.samestat(os.lstat(out_dir), original), "premise: lstat still sees the original"
    assert shipped.read_text(encoding="utf-8") != CAPTURE, "the capture LANDED in the tree"
    assert raised is not None and type(raised).__name__ == "WriteSiteSwapError", repr(raised)
    assert "no longer the directory" in str(raised)
    assert _fingerprint(fixtures) == before, "no shipped byte and no stray temp may remain"


# ---------------------------------------------------------------- the identity PAIR, behaviorally (Round 3 A2)


def test_FIRES_R1_a_REAL_protected_directory_renamed_onto_the_approved_name_is_refused_by_identity(
    relocated, monkeypatch
):
    """The re-gate's real-directory swap (2026-09-25), made complete BEFORE step 5: the approved
    directory is renamed away, the protected ``derived_from_source/clean`` is renamed onto its
    name, the temp is moved in, and after the call the protected directory is renamed back. A
    REAL directory sits at the literal name, so the location leg passes, and the temp keeps its id
    and link count 1; only the directory-identity pair (lstat + stat) can see it. With both legs
    removed the capture replaced the protected journal_verify.json - a shipped byte changed - so
    this test fails on BYTES, not on a message."""
    fixtures, out_dir = relocated
    protected = fixtures / "derived_from_source" / "clean"
    shipped = protected / "journal_verify.json"
    shipped_bytes = shipped.read_bytes()
    away = out_dir.with_name("clean_moved_away")

    def rename_a_real_protected_directory_onto_the_approved_name(temp):
        out_dir.rename(away)
        protected.rename(out_dir)
        os.rename(away / temp.name, out_dir / temp.name)

    seen = _hook_the_temp_check(
        monkeypatch, after=rename_a_real_protected_directory_onto_the_approved_name
    )
    before = _fingerprint(fixtures)

    raised = _write_and_catch(out_dir / "journal_verify.json")
    swapped = seen and not protected.exists() and not _is_junction(out_dir)
    out_dir.rename(protected)  # the racer's move-back

    assert swapped, "premise: a real protected directory sat at the approved name"
    assert shipped.read_bytes() == shipped_bytes, "the capture REPLACED a shipped file"
    assert _fingerprint(fixtures) == before, "no shipped byte and no stray temp may remain"
    assert raised is not None and type(raised).__name__ == "WriteSiteSwapError", repr(raised)


# ---------------------------------------------------------------- the orphaned temp (AMEND A7)


def test_R1_a_refusal_whose_temp_moved_away_with_its_parent_names_the_orphan_in_a_note(
    relocated, monkeypatch
):
    """The parent is moved away before the temp check (R1, strict leg). Cleanup unlinks by the old
    path, which no longer reaches the temp, so the capture bytes stay in the moved directory. The
    helper cannot find them by name safely; the refusal must SAY where they are instead."""
    fixtures, out_dir = relocated
    away = out_dir.with_name("clean_moved_away")

    seen = _hook_the_temp_check(monkeypatch, before=lambda temp: out_dir.rename(away))

    raised = _write_and_catch(out_dir / "journal_verify.json")

    assert seen and raised is not None, repr(raised)
    orphan = away / seen[0].name
    assert orphan.read_text(encoding="utf-8") == CAPTURE, "premise: the temp really is orphaned"
    notes = getattr(raised, "__notes__", [])
    assert any(str(seen[0]) in note and "moved" in note for note in notes), notes


# ---------------------------------------------------------------- R2, the temp name's identity


def test_FIRES_R2_a_hardlink_to_a_shipped_file_at_the_TEMP_name_is_refused(relocated, monkeypatch):
    """RED at 6ab1906: the hardlink was renamed into place - the helper returned normally and
    the 'capture' was the shipped file's bytes (nlink 2)."""
    fixtures, out_dir = relocated
    shipped = fixtures / "recorded" / "_corpus.json"
    shipped_bytes = shipped.read_bytes()
    target = out_dir / "_corpus.json"

    def replace_the_temp_with_a_hardlink(temp):
        os.unlink(temp)
        os.link(shipped, temp)

    seen = _hook_the_temp_check(monkeypatch, before=replace_the_temp_with_a_hardlink)
    before = _fingerprint(fixtures)

    raised = _write_and_catch(target)

    assert seen, "premise: the hardlink was planted at the temp name"
    assert shipped.read_bytes() == shipped_bytes
    assert not (target.exists() and target.read_bytes() == shipped_bytes), (
        "SILENT: the capture was replaced by the shipped file's bytes"
    )
    assert raised is not None and type(raised).__name__ == "WriteSiteSwapError", repr(raised)
    assert os.stat(shipped).st_nlink == 1, "the planted extra name must not be left behind"
    assert _fingerprint(fixtures) == before


def test_FIRES_R2_another_file_put_at_the_TEMP_name_is_refused_by_the_file_id_alone(
    relocated, monkeypatch
):
    """The file-id leg on its own: the temp file is replaced by a FRESH file (link count 1)
    holding someone else's bytes. Only the id captured from the writing descriptor tells them
    apart; renaming it would publish those bytes as the capture."""
    fixtures, out_dir = relocated
    target = out_dir / "journal_verify.json"
    foreign = b'{"written": "by another process"}\n'

    def replace_the_temp_with_a_fresh_file(temp):
        os.unlink(temp)
        temp.write_bytes(foreign)

    seen = _hook_the_temp_check(monkeypatch, before=replace_the_temp_with_a_fresh_file)

    raised = _write_and_catch(target)

    assert seen, "premise: a fresh foreign file was put at the temp name"
    assert not (target.exists() and target.read_bytes() == foreign), "foreign bytes published"
    assert raised is not None and type(raised).__name__ == "WriteSiteSwapError", repr(raised)
    assert "file id changed" in str(raised)


def test_FIRES_R2_an_extra_hardlink_to_the_temp_file_is_refused_by_the_link_count_alone(
    relocated, monkeypatch
):
    """The link-count leg on its own: the temp name still names the file this process wrote
    (same id), but a second name for it was made elsewhere, so the published capture would stay
    writable through a name outside the approved --out."""
    fixtures, out_dir = relocated
    target = out_dir / "journal_verify.json"
    extra = out_dir.parent / "second_name_for_the_temp.json"

    def add_a_second_name(temp):
        os.link(temp, extra)

    seen = _hook_the_temp_check(monkeypatch, before=add_a_second_name)

    raised = _write_and_catch(target)

    assert seen and extra.exists(), "premise: the temp file really had a second name"
    assert not target.exists(), "nothing may be renamed into place"
    assert raised is not None and type(raised).__name__ == "WriteSiteSwapError", repr(raised)
    assert "link count 2" in str(raised)


def test_SILENT_R2_an_existing_file_at_the_candidate_temp_name_is_never_opened(
    relocated, monkeypatch
):
    """The temp file is created with O_CREAT|O_EXCL (``tempfile.mkstemp``), so a name that
    already exists - here a hardlink to a shipped file, pre-placed at the first candidate - is
    skipped, never opened or truncated. Green at 6ab1906 too: a regression guard for the day
    someone swaps mkstemp for a plain open()."""
    fixtures, out_dir = relocated
    shipped = fixtures / "recorded" / "_corpus.json"
    shipped_bytes = shipped.read_bytes()
    target = out_dir / "_corpus.json"
    planted = out_dir / ("." + target.name + ".planted.tmp")
    os.link(shipped, planted)
    assert hasattr(tempfile, "_get_candidate_names"), "premise: CPython's mkstemp name source"
    candidates = iter(["planted", "fresh"])
    monkeypatch.setattr(tempfile, "_get_candidate_names", lambda: candidates)

    record_fixtures._write_text_where_approved(target, CAPTURE)

    assert target.read_text(encoding="utf-8") == CAPTURE
    assert shipped.read_bytes() == shipped_bytes
    assert planted.read_bytes() == shipped_bytes, "the pre-existing name was opened"
    assert os.stat(shipped).st_nlink == 2, "the planted name is untouched, the shipped id intact"
    assert os.stat(target).st_nlink == 1
