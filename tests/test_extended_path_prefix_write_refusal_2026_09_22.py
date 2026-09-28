r"""R1 (2026-09-22): the fixture-tree write refusal survives the Windows path-parser prefixes.

MEASURED HOLE. `_is_inside` resolved both sides and compared them, which stopped fourteen of
fifteen spellings of "inside the fixture tree" - including an NTFS junction. It did not stop
the extended-length prefix. `Path.resolve()` KEEPS `\?\`, so `\?\C:\...\tests\fixtures` and
`C:\...\tests\fixtures` compared UNEQUAL while naming the same bytes: the guard returned "not
inside", the recorder accepted the path, and the write LANDED IN THE REAL FIXTURE TREE,
because the prefix only switches the path PARSER off - it does not name another place.
Probed on this machine 2026-09-22: writing through the prefixed form of a directory creates
the file at the plain form of that directory.

WHY THESE CASES TOGETHER. The fix normalises both sides instead of special-casing one prefix,
so this file pins the whole family (`\?\`, `\?\UNC\`, `\.\`) NEXT TO three spellings that
were already blocked (a relative --out, a `..` segment, a lower-case drive letter). A future
refactor that reaches for "just strip the one prefix we saw" has to keep all of them green,
and the must-not-fire legs at the bottom stop anyone from buying that by making the guard
answer True for everything.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from tools import record_fixtures
from tools.record_fixtures import FIXTURES_ROOT, RECORDED_ROOT, REPO_ROOT, _is_inside

EXT = chr(92) * 2 + "?" + chr(92)      # the extended-length prefix, four characters
DEVICE = chr(92) * 2 + "." + chr(92)   # the device-namespace prefix, same family


def _tree_listing(root: Path):
    return sorted((p.relative_to(root).as_posix(), p.stat().st_size) for p in root.rglob("*"))


# --------------------------------------------------------------------------- #
# the premise, re-derived here rather than asserted from the bug report
# --------------------------------------------------------------------------- #
def test_PREMISE_the_prefixed_spelling_really_is_the_same_directory(tmp_path):
    """If this ever stops holding, the hole below is not a hole and the rest is theatre."""
    prefixed = Path(EXT + str(tmp_path))
    assert prefixed.exists() and prefixed.is_dir()
    (prefixed / "landed.txt").write_text("x", encoding="utf-8")
    assert (tmp_path / "landed.txt").exists(), "the prefixed write must land at the plain path"


# --------------------------------------------------------------------------- #
# FIRES: every spelling of "inside the shipped fixture tree" is refused
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "spelling,label",
    [
        (lambda: Path(EXT + str(FIXTURES_ROOT)), "extended-length prefix on the fixture root"),
        (lambda: Path(EXT + str(RECORDED_ROOT)), "extended-length prefix on the recorded corpus"),
        (
            lambda: Path(EXT + str(FIXTURES_ROOT / "capture-2026-09-22")),
            "extended-length prefix on a subdirectory that does not exist yet",
        ),
        (lambda: Path(DEVICE + str(RECORDED_ROOT)), "device-namespace prefix, same family"),
        # --- the three that were ALREADY blocked: regression guards, not new coverage ---
        (lambda: Path("tests") / "fixtures" / "recorded", "a relative --out from the repo root"),
        (
            lambda: FIXTURES_ROOT / "derived_from_source" / ".." / "recorded",
            "a .. segment walking in sideways",
        ),
        (lambda: Path(str(RECORDED_ROOT)[0].lower() + str(RECORDED_ROOT)[1:]), "lower-case drive"),
    ],
)
def test_FIRES_the_guard_calls_every_spelling_of_the_fixture_tree_INSIDE(spelling, label, monkeypatch):
    monkeypatch.chdir(REPO_ROOT)  # the relative case is only meaningful from the repo root
    assert _is_inside(spelling(), FIXTURES_ROOT) is True, label


# --------------------------------------------------------------------------- #
# DOES NOT FIRE: the guard must still let a legitimate outside capture through
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("prefix", ["", EXT])
def test_SILENT_a_directory_outside_the_fixture_tree_is_still_allowed(tmp_path, prefix):
    """Without this leg, `return True` would pass every test above."""
    assert _is_inside(Path(prefix + str(tmp_path)), FIXTURES_ROOT) is False


def test_SILENT_a_sibling_whose_name_merely_starts_with_the_root_is_not_inside(tmp_path):
    """Containment is by path component, not by string prefix: `fixtures-backup` is outside."""
    lookalike = Path(str(FIXTURES_ROOT) + "-backup")
    assert _is_inside(lookalike, FIXTURES_ROOT) is False
    assert _is_inside(Path(EXT + str(lookalike)), FIXTURES_ROOT) is False


# --------------------------------------------------------------------------- #
# end to end, through main(), against the REAL shipped tree - the thing that broke
# --------------------------------------------------------------------------- #
class _RecordingClient:
    def __init__(self, base_url=None):
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
        return 200, {}


@pytest.mark.parametrize("prefix", [EXT, DEVICE])
def test_FIRES_main_REFUSES_a_prefixed_out_and_writes_nothing(monkeypatch, prefix, tmp_path):
    """RED before the fix: this call returned 0, wrote clean/ and tampered/ halves into the
    REAL tests/fixtures/recorded, and the listing assertion below caught the damage.

    Since 2026-09-24 (gate residual R3) it runs on a BYTE COPY of tests/fixtures installed as
    the recorder's protected roots: with the guard broken, this test itself overwrote the real
    recorded/_corpus.json. A regression now damages only the copy; the real tree is asserted
    untouched as well."""
    fixtures_root = tmp_path / "repo" / "tests" / "fixtures"
    shutil.copytree(FIXTURES_ROOT, fixtures_root)
    recorded_root = fixtures_root / "recorded"
    monkeypatch.setattr(record_fixtures, "FIXTURES_ROOT", fixtures_root)
    monkeypatch.setattr(record_fixtures, "RECORDED_ROOT", recorded_root)
    client = _RecordingClient()
    monkeypatch.setattr(record_fixtures, "RateLimitedClient", lambda *a, **k: client)
    monkeypatch.setattr(record_fixtures, "wait_for_chain_complete", lambda c: (True, {"ok": True}))
    monkeypatch.setattr(record_fixtures, "wait_for_stable_verify", lambda c, **k: (True, {"ok": 1}))
    monkeypatch.setattr(record_fixtures, "capture_half", lambda c, half, out, write: ({}, {}))

    before = _tree_listing(fixtures_root)
    real_before = _tree_listing(FIXTURES_ROOT)

    with pytest.raises(record_fixtures.RecorderError) as excinfo:
        record_fixtures.main(["--out", prefix + str(recorded_root)])

    assert "REFUSING TO WRITE" in str(excinfo.value)
    assert client.calls == [], "the refusal must land BEFORE any HTTP call"
    assert _tree_listing(fixtures_root) == before, "not one byte of the shipped corpus may change"
    assert _tree_listing(FIXTURES_ROOT) == real_before, "the real shipped tree is untouched"


def test_SILENT_main_still_ACCEPTS_a_capture_directory_outside_the_repo(monkeypatch, tmp_path):
    """The other outcome of the same instrument: the guard is not simply refusing everything."""
    client = _RecordingClient()
    monkeypatch.setattr(record_fixtures, "RateLimitedClient", lambda *a, **k: client)
    monkeypatch.setattr(record_fixtures, "wait_for_chain_complete", lambda c: (True, {"ok": True}))
    monkeypatch.setattr(record_fixtures, "wait_for_stable_verify", lambda c, **k: (True, {"ok": 1}))
    monkeypatch.setattr(record_fixtures, "capture_half", lambda c, half, out, write: ({}, {}))

    target = tmp_path / "capture"
    rc = record_fixtures.main(["--out", str(target)])

    assert rc == 0, "a capture outside the fixture tree must still be allowed to run"
    assert not _is_inside(target, FIXTURES_ROOT)
