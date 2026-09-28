"""Cross-source tests: the derived corpus against the JAVA, not against itself.

Why this file exists. A fixture generator whose only tests read its own output pins
the drift in place: change the generator, regenerate, and every test still passes.
Two mutations demonstrated exactly that on 2026-09-13 - dropping the ``pendingDebits``
term from the balance formula, and flipping the seeded asset from ARS to USD - and
BOTH survived the whole suite with 80 passing tests.

Every expected value below is read out of the LedgerMind Java source at read time, or
is a constant quoted from it with the file and symbol named. Where the checkout is
absent the cross-source tests SKIP rather than fail, so the suite still runs on a
machine that only has this repo - a skip is an honest "not checked here", not a pass.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from tools import derive_fixtures as df

# The LedgerMind checkout: $LEDGERMIND_REPO, else a sibling directory named ledgermind.
LEDGERMIND = Path(os.environ.get("LEDGERMIND_REPO", str(Path(__file__).resolve().parents[2] / "ledgermind")))
DEMO_CONTROLLER = LEDGERMIND / "src/main/java/com/ledgermind/ledger/web/DemoSupportController.java"
ACCOUNT_ENTITY = LEDGERMIND / "src/main/java/com/ledgermind/ledger/Account.java"
FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "derived_from_source"


def _java(path: Path) -> str:
    if not path.exists():
        pytest.skip("LedgerMind checkout not present: " + str(path))
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# The seeded asset (DemoSupportController.reset -> ledger.createAccount(..., "ARS", ...))
# ---------------------------------------------------------------------------


def test_the_asset_is_the_one_the_JAVA_demo_seeds():
    java = _java(DEMO_CONTROLLER)
    seeded = set(re.findall(r'createAccount\(\s*"[^"]+"\s*,\s*"([^"]+)"', java))
    assert seeded == {"ARS"}, "the Java seeds " + str(sorted(seeded))
    assert df.ASSET in seeded, "generator asset " + df.ASSET + " is not what the demo seeds"


def test_every_derived_account_fixture_carries_that_asset():
    java = _java(DEMO_CONTROLLER)
    seeded = set(re.findall(r'createAccount\(\s*"[^"]+"\s*,\s*"([^"]+)"', java))
    for state in ("clean", "tampered"):
        for path in sorted((FIXTURES / state).glob("account_*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            assert data["asset"] in seeded, path.name + " carries asset " + str(data["asset"])


def test_every_derived_posting_carries_that_asset():
    java = _java(DEMO_CONTROLLER)
    seeded = set(re.findall(r'createAccount\(\s*"[^"]+"\s*,\s*"([^"]+)"', java))
    data = json.loads((FIXTURES / "clean" / "postings_and_hashes.json").read_text(encoding="utf-8"))
    postings = data["postings"] if isinstance(data, dict) and "postings" in data else data
    assert postings
    for posting in postings:
        assert posting["asset"] in seeded


# ---------------------------------------------------------------------------
# The transfers (DemoSupportController.reset -> ledger.transfer(...))
# ---------------------------------------------------------------------------


def test_the_transfers_are_the_ones_the_JAVA_seeds():
    java = _java(DEMO_CONTROLLER)
    seeded = re.findall(
        r'transfer\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*([0-9_]+)\s*,\s*"([^"]+)"\s*\)', java
    )
    assert len(seeded) == 5, seeded
    java_pairs = [(int(amount.replace("_", "")), key) for _src, _dst, amount, key in seeded]
    ours = [(amount, key) for _id, _dr, _cr, amount, key, _created in df.TRANSFERS]
    assert ours == java_pairs


# ---------------------------------------------------------------------------
# The three-term balance formula (Account.availableBalance)
# ---------------------------------------------------------------------------


def test_the_java_balance_formula_still_has_three_terms():
    java = _java(ACCOUNT_ENTITY)
    assert "postedCredits - postedDebits - pendingDebits" in java, (
        "Account.availableBalance changed shape in the Java; re-read it before trusting "
        "any balance in this corpus"
    )


def test_account_views_subtracts_pendingDebits():
    """Drives account_views with a NON-ZERO pendingDebits, which the demo corpus never
    has - which is exactly why dropping the term was invisible to every other test."""
    counters = {}
    for aid, _address, _asset, _allow in df.ACCOUNTS:
        counters[aid] = {
            "postedDebits": 0,
            "postedCredits": 1_000,
            "pendingDebits": 250,
            "pendingCredits": 0,
            "updates": 1,
        }
    views = df.account_views(counters)
    for view in views.values():
        assert view["balance"] == 750, (
            "balance must be postedCredits - postedDebits - pendingDebits (1000 - 0 - 250)"
        )


def test_the_demo_balances_and_money_conservation():
    """The arithmetic the Java seeding implies, spelled out rather than read back."""
    counters = df.account_counters(df.build_postings())
    views = df.account_views(counters)
    assert views["external:funding"]["balance"] == -158_000
    assert views["wallet:ana"]["balance"] == 107_500
    assert views["wallet:beto"]["balance"] == 50_500
    assert sum(v["balance"] for v in views.values()) == 0, "money is not conserved"
