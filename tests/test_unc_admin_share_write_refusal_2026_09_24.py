r"""R1b (2026-09-24): the fixture-tree write refusal survives SHARE and VOLUME spellings.

MEASURED HOLE (independent verification 2026-09-23, re-derived and widened 2026-09-24). The
2026-09-22 guard rewrote path prefixes as strings. Against an os.path.samefile oracle over 31
spellings of tests/fixtures, 13 passed the guard while naming the same directory, and a write
through each landed at the plain path (proven in a TEMP tree): the admin share via localhost,
127.0.0.1, the machine's own hostname and the IPv6 loopback literal; \?\UNC\ and \.\UNC\ forms;
\?\Volume{guid}\ and \.\Volume{guid}\; and \?\GLOBALROOT\Device\HarddiskVolumeN\.

The guard now asks the FILESYSTEM: realpath, then refuse anything that is not on a local drive
letter, then compare file identity (st_dev, st_ino) of the existing ancestors with the root.

WIRING. The end-to-end legs run main() against a RELOCATED fixture root under tmp_path, so a
regression of this guard writes into a temp directory, never into the shipped corpus. The
direct-guard legs use the REAL fixture root, read-only.
"""

from __future__ import annotations

import ctypes
import os
import socket
from pathlib import Path

import pytest

from tools import record_fixtures
from tools.record_fixtures import FIXTURES_ROOT, RECORDED_ROOT, RecorderError, _is_inside

BS = chr(92)
NEW_SUBDIR = "capture-2026-09-24-not-created"

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows share and volume namespaces")


def _drive_and_tail(path: Path):
    text = str(path)
    assert text[1:3] == ":" + BS, "these spellings are built from a plain drive-letter path"
    return text[0], text[3:]


def _volume_guid(drive):
    buf = ctypes.create_unicode_buffer(260)
    ok = ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(drive + ":" + BS, buf, 260)
    return buf.value.rstrip(BS) if ok else None


def _nt_device(drive):
    buf = ctypes.create_unicode_buffer(1024)
    ok = ctypes.windll.kernel32.QueryDosDeviceW(drive + ":", buf, 1024)
    return buf.value if ok else None


def _share_spellings(path: Path):
    """Every spelling of `path` that the 2026-09-22 guard let through. Built, not copied."""
    d, tail = _drive_and_tail(path)
    host = socket.gethostname()
    rows = {
        "admin share via localhost": BS * 2 + "localhost" + BS + d + "$" + BS + tail,
        "admin share via 127.0.0.1": BS * 2 + "127.0.0.1" + BS + d + "$" + BS + tail,
        "admin share via own hostname": BS * 2 + host + BS + d + "$" + BS + tail,
        "admin share, forward slashes": "//localhost/" + d + "$/" + tail.replace(BS, "/"),
        "admin share, IPv6 loopback literal": BS * 2 + "0--1.ipv6-literal.net" + BS + d + "$" + BS + tail,
        "extended-length UNC": BS * 2 + "?" + BS + "UNC" + BS + "localhost" + BS + d + "$" + BS + tail,
        "device-namespace UNC": BS * 2 + "." + BS + "UNC" + BS + "localhost" + BS + d + "$" + BS + tail,
    }
    guid = _volume_guid(d)
    if guid:
        rows["volume GUID, extended-length"] = guid + BS + tail
        rows["volume GUID, device namespace"] = BS * 2 + "." + guid[3:] + BS + tail
    dev = _nt_device(d)
    if dev:
        rows["GLOBALROOT device path"] = BS * 2 + "?" + BS + "GLOBALROOT" + dev + BS + tail
    return rows


_LABELS = sorted(_share_spellings(FIXTURES_ROOT)) if os.name == "nt" else []


def _refused(spelling, root) -> bool:
    try:
        return _is_inside(Path(spelling), root) is True
    except RecorderError:
        return True


def _share_reachable(path: Path) -> bool:
    try:
        return os.path.samefile(_share_spellings(path)["admin share via localhost"], path)
    except OSError:
        return False


def _tree_listing(root: Path):
    return sorted((p.relative_to(root).as_posix(), p.stat().st_size) for p in root.rglob("*"))


# --------------------------------------------------------------------------- #
# the premise, re-derived here: these spellings really are the same directory
# --------------------------------------------------------------------------- #
def test_PREMISE_a_write_through_each_share_or_volume_spelling_lands_at_the_plain_path(tmp_path):
    if not _share_reachable(tmp_path):
        pytest.skip("the local admin share is not reachable on this machine; premise unprovable")
    landed = []
    for label, spelling in _share_spellings(tmp_path).items():
        name = "landed-" + str(abs(hash(label))) + ".txt"
        sep = "/" if spelling.startswith("//") else BS
        with open(spelling + sep + name, "w", encoding="utf-8") as fh:
            fh.write(label)
        landed.append((label, (tmp_path / name).is_file()))
    assert all(ok for _label, ok in landed), landed


# --------------------------------------------------------------------------- #
# FIRES: every share / volume spelling of the REAL fixture tree is refused
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("label", _LABELS)
def test_FIRES_the_guard_refuses_a_share_or_volume_spelling_of_the_fixture_root(label):
    assert _refused(_share_spellings(FIXTURES_ROOT)[label], FIXTURES_ROOT), label


@pytest.mark.parametrize("label", _LABELS)
def test_FIRES_the_guard_refuses_the_same_spelling_of_a_NOT_YET_CREATED_subdirectory(label):
    spelling = _share_spellings(FIXTURES_ROOT / NEW_SUBDIR)[label]
    assert not (FIXTURES_ROOT / NEW_SUBDIR).exists()
    assert _refused(spelling, FIXTURES_ROOT), label


def _stub_network(monkeypatch):
    class _Client:
        def __init__(self, *a, **k):
            self.calls, self.http_log, self.retries_after_429 = [], [], 0

        def post_json(self, path, body=None):
            self.calls.append(("POST", path))
            return {}

        def get_json(self, path):
            self.calls.append(("GET", path))
            return {}

        def request(self, method, path, body=None):
            self.calls.append((method, path))
            return 200, {}

    client = _Client()
    monkeypatch.setattr(record_fixtures, "RateLimitedClient", lambda *a, **k: client)
    monkeypatch.setattr(record_fixtures, "wait_for_chain_complete", lambda c: (True, {"ok": True}))
    monkeypatch.setattr(record_fixtures, "wait_for_stable_verify", lambda c, **k: (True, {"ok": 1}))
    monkeypatch.setattr(record_fixtures, "capture_half", lambda c, half, out, write: ({}, {}))
    return client


@pytest.mark.parametrize(
    "label", ["admin share via localhost", "extended-length UNC", "volume GUID, extended-length"]
)
@pytest.mark.parametrize("extra", [[], ["--destructive-reset-and-tamper"]])
def test_FIRES_main_REFUSES_a_share_spelled_out_and_writes_nothing(monkeypatch, tmp_path, label, extra):
    """End to end against a RELOCATED fixture root: RED before the fix, main() accepted these,
    and a write through them lands in the fixture tree (see the PREMISE leg)."""
    fake_fixtures = tmp_path / "tests" / "fixtures"
    fake_recorded = fake_fixtures / "recorded"
    fake_recorded.mkdir(parents=True)
    (fake_recorded / "shipped.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(record_fixtures, "FIXTURES_ROOT", fake_fixtures)
    monkeypatch.setattr(record_fixtures, "RECORDED_ROOT", fake_recorded)
    client = _stub_network(monkeypatch)
    spelling = _share_spellings(fake_recorded).get(label)
    if spelling is None:
        pytest.skip(label + " cannot be built on this machine")
    before = _tree_listing(fake_fixtures)

    with pytest.raises(RecorderError) as excinfo:
        record_fixtures.main(["--out", spelling] + extra)

    assert "REFUSING TO WRITE" in str(excinfo.value)
    assert client.calls == [], "the refusal must land BEFORE any HTTP call"
    assert _tree_listing(fake_fixtures) == before, "not one byte of the fixture tree may change"


def test_FIRES_a_share_path_OUTSIDE_the_tree_is_refused_too(tmp_path):
    """The share rule is load-bearing on its own: a share cannot be placed, so it is refused
    even where file identity alone would have said 'outside'."""
    with pytest.raises(RecorderError) as excinfo:
        _is_inside(Path(_share_spellings(tmp_path)["admin share via localhost"]), FIXTURES_ROOT)
    assert "network-share or device path" in str(excinfo.value)


def test_FIRES_fail_closed_when_nothing_of_the_path_exists_or_the_root_cannot_be_stated(tmp_path):
    free = next(
        (c for c in "QRSTUVWXYZ" if not os.path.exists(c + ":" + BS)), None
    )
    if free is not None:
        with pytest.raises(RecorderError, match="no part of"):
            _is_inside(Path(free + ":" + BS + "capture"), FIXTURES_ROOT)
    with pytest.raises(RecorderError, match="cannot be stat'ed"):
        _is_inside(tmp_path / "capture", tmp_path / "root-that-does-not-exist")


# --------------------------------------------------------------------------- #
# DOES NOT FIRE: legitimate writes still go through
# --------------------------------------------------------------------------- #
def test_SILENT_a_sibling_temp_directory_is_outside_in_plain_extended_and_volume_spelling(tmp_path):
    """Without this leg, 'refuse everything with a prefix' would pass every FIRES test."""
    sibling = tmp_path / "sibling-capture"
    assert _is_inside(sibling, FIXTURES_ROOT) is False
    assert _is_inside(Path(BS * 2 + "?" + BS + str(sibling)), FIXTURES_ROOT) is False
    guid_spelling = _share_spellings(sibling).get("volume GUID, extended-length")
    if guid_spelling is not None:
        assert _is_inside(Path(guid_spelling), FIXTURES_ROOT) is False


def test_SILENT_main_writes_a_capture_into_a_plain_temp_directory(monkeypatch, tmp_path):
    _stub_network(monkeypatch)
    out = tmp_path / "live-capture"
    assert record_fixtures.main(["--out", str(out)]) == 0
    assert (out / "_corpus.json").is_file()


def test_SILENT_the_canned_regeneration_into_the_REAL_recorded_root_gets_past_the_guard(monkeypatch):
    """The one legal write into the REAL fixture tree, under its plain path, is still allowed.
    Proven WITHOUT writing: the first HTTP call after the guard raises a sentinel, and the
    shipped tree is compared byte-listing for byte-listing."""

    class _PastTheGuard(Exception):
        pass

    client = _stub_network(monkeypatch)

    def _stop(path, body=None):
        raise _PastTheGuard(path)

    client.post_json = _stop
    before = _tree_listing(FIXTURES_ROOT)

    with pytest.raises(_PastTheGuard) as excinfo:
        record_fixtures.main(["--destructive-reset-and-tamper", "--out", str(RECORDED_ROOT)])

    assert str(excinfo.value) == "/api/demo/reset"
    assert _tree_listing(FIXTURES_ROOT) == before
