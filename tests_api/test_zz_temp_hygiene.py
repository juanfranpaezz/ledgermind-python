"""AC-A.12 temp hygiene. Named test_zz_ so it runs LAST in the tests_api session: after every
upload of the run, no ``lm-api-*`` staging directory created during the run may remain."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from conftest import PRE_EXISTING_STAGE_DIRS, STAGE_GLOB


def _stage_dirs() -> set[str]:
    return {p.name for p in Path(tempfile.gettempdir()).glob(STAGE_GLOB)}


def test_positive_control_the_glob_sees_a_live_staging_directory():
    with tempfile.TemporaryDirectory(prefix="lm-api-") as live:
        assert Path(live).name in _stage_dirs()
    assert Path(live).name not in _stage_dirs()


# A second tests_api run in another process shares %TEMP%; its in-flight staging directory is deleted
# when its CLI call returns (the CLI timeout defaults to 60 s). A real leak never disappears.
CONCURRENT_RUN_GRACE_S = 90.0


def test_AC_A12_no_staging_directory_created_during_the_run_remains():
    flagged = _stage_dirs() - PRE_EXISTING_STAGE_DIRS
    first_seen = len(flagged)
    deadline = time.monotonic() + CONCURRENT_RUN_GRACE_S
    # Re-check ONLY the names flagged now: a directory another run creates later is not counted,
    # and a flagged one still present at the deadline is a leak.
    while flagged and time.monotonic() < deadline:
        time.sleep(0.5)
        flagged &= _stage_dirs()
    leaked = sorted(flagged)
    print("lm-api-* dirs flagged:", first_seen, "still present after the grace:", len(leaked))
    assert leaked == []
