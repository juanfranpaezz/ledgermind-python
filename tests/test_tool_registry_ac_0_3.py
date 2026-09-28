"""AC-0.3's tool-count check, plus the both-ways proof the plan demands of it.

Plan reference: AC-0.3 (manifest v1), checker replaced by v2 A8, expression FIXED by
v2.1 B1. The v2 wording was ``len(TOOL_REGISTRY) == 4 if MCP_ENABLED else 3``, which
Python parses as ``(len(TOOL_REGISTRY) == 4) if MCP_ENABLED else 3``. On the
MCP-disabled branch - the branch this repository is actually on - that expression
evaluates to the integer 3, which is truthy for a registry of ANY size, including
zero. v2.1 B1 requires the parenthesised form AND a demonstration that the check
FAILS on a deliberately mis-sized registry on EACH branch before the check is
trusted. Those demonstrations are the last four tests in this file; they are kept as
permanent regression guards, not run once and discarded.

A SECOND, UNASKED-FOR GUARD, and why it is here. ``TOOL_REGISTRY`` is built by
filtering ``DECLARED_TOOLS`` with the same flag the assertion compares against, so
``test_tool_count_matches_spike`` alone is close to tautological on the shipped path:
it cannot fail unless the filter itself breaks. The assertions on ``DECLARED_TOOLS``
are what actually bite - adding a fifth tool, deleting one, or flipping a tool's gate
breaks them - and they are the reason a count check here is worth anything at all.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from ledger_verification_agent import tool_registry as tr


# --- AC-0.3 on the shipped registry -------------------------------------------

def test_tool_count_matches_spike():
    """AC-0.3's named checker: pytest -k test_tool_count_matches_spike."""
    assert tr.tool_count_matches(tr.TOOL_REGISTRY, tr.MCP_ENABLED)
    assert len(tr.TOOL_REGISTRY) == (4 if tr.MCP_ENABLED else 3)


def test_declared_surface_is_exactly_four_tools_one_of_them_gated():
    """The non-tautological half: a fifth tool, or a lost one, breaks this."""
    assert len(tr.DECLARED_TOOLS) == 4
    gated = [t for t in tr.DECLARED_TOOLS if t.requires_mcp]
    rest = [t for t in tr.DECLARED_TOOLS if not t.requires_mcp]
    assert len(rest) == 3
    assert len(gated) == 1
    # CHANGED 2026-09-13, flagged loudly rather than done quietly: this literal used to
    # read "list_entries_by_account", which was OUR invented name. The name a client
    # sends over MCP is the Java @Tool name, and LedgerMcpTools.java:47 declares
    # "list_transactions". The assertion is not weakened - it is corrected to the
    # primary source, and the cross-source test below now re-derives it from the Java
    # rather than trusting any literal typed here.
    assert gated[0].name == "list_transactions"
    assert {t.name for t in rest} == {"get_balance", "verify_journal", "reconcile_against_feed"}


# The LedgerMind checkout: $LEDGERMIND_REPO, else a sibling directory named ledgermind.
LEDGERMIND_MCP_TOOLS = Path(os.environ.get("LEDGERMIND_REPO", str(Path(__file__).resolve().parents[2] / "ledgermind"))) / (
    "src/main/java/com/ledgermind/ledger/mcp/LedgerMcpTools.java"
)


def test_the_gated_tool_name_is_the_one_the_JAVA_declares():
    """A cross-source oracle instead of a literal we typed ourselves.

    Read-only on the LedgerMind checkout. Skips rather than fails where that checkout is
    absent, so the suite stays runnable on a machine that only has this repo.
    """
    if not LEDGERMIND_MCP_TOOLS.exists():
        pytest.skip("LedgerMind checkout not present; cross-source check not run")
    java = LEDGERMIND_MCP_TOOLS.read_text(encoding="utf-8", errors="replace")
    declared = set(re.findall(r'@Tool\(name\s*=\s*"([^"]+)"', java))
    assert declared, "no @Tool(name=...) found; the Java layout changed, re-read it"
    gated = [t for t in tr.DECLARED_TOOLS if t.requires_mcp]
    assert gated[0].name in declared, (
        "registry MCP tool name " + gated[0].name + " is not declared by the Java: " + str(sorted(declared))
    )
    assert "list_entries_by_account" not in declared


def test_the_mutating_denylist_is_documented_as_a_CLIENT_side_control():
    """The security wording, pinned. McpServerSecurityConfig leaves /api permitAll and
    the Java has no ledger.write scope, so this registry is the only thing enforcing
    read-only on REST. If that sentence disappears from the module, this fails."""
    doc = tr.__doc__ or ""
    assert "CLIENT-SIDE CONTROL" in doc
    assert "permitAll" in doc
    assert "ledger.write" in doc


def test_mcp_enabled_is_derived_from_the_evidence_file_not_set_by_hand():
    """v2.1 B1: MCP_ENABLED must come from the spike evidence, with a stated reason."""
    assert tr.MCP_ENABLED == tr.SPIKE_STATE.mcp_enabled
    assert tr.SPIKE_STATE.reason


# --- Read-only surface. Partial early coverage of AC-2.1 (v2), which is scored at P2.
# The registry is metadata-only in Phase 0, so this proves the DECLARED surface, not a
# running client. AC-2.1 is NOT claimed met by this file.

def test_no_registered_tool_touches_a_mutating_endpoint():
    assert tr.mutating_endpoints_in(tr.DECLARED_TOOLS) == ()
    assert tr.mutating_endpoints_in(tr.TOOL_REGISTRY) == ()


def test_every_registered_tool_is_on_the_read_only_surface():
    assert tr.endpoints_outside_read_only_surface(tr.DECLARED_TOOLS) == ()


def test_the_mutating_denylist_is_not_empty_so_the_check_can_fail():
    """A denylist that is empty makes the two checks above vacuous. Guard the guard."""
    assert len(tr.MUTATING_ENDPOINTS) >= 5
    assert ("POST", "/api/transfers") in tr.MUTATING_ENDPOINTS


def test_mutating_endpoint_is_detected_when_one_is_planted():
    """The read-only check fires on a realistic defect: someone adds the transfer tool."""
    planted = tr.DECLARED_TOOLS + (
        tr.ToolSpec(
            name="make_transfer",
            transport="rest",
            method="POST",
            path="/api/transfers",
            upstream="LedgerController.transfer @ 872505f",
            requires_mcp=False,
            description="PLANTED DEFECT for the both-ways proof. Never shipped.",
        ),
    )
    assert tr.mutating_endpoints_in(planted) == (("POST", "/api/transfers"),)
    assert tr.endpoints_outside_read_only_surface(planted) == (("POST", "/api/transfers"),)


# --- v2.1 B1's mandated both-ways proof of the count check ---------------------

def _fake_registry(n):
    """n placeholder specs. Only the LENGTH matters to the count check."""
    return tuple(
        tr.ToolSpec(
            name="fake_" + str(i),
            transport="rest",
            method="GET",
            path="/api/journal/audit",
            upstream="fixture",
            requires_mcp=False,
            description="mis-sizing fixture",
        )
        for i in range(n)
    )


@pytest.mark.parametrize("size", [0, 1, 2, 3, 5, 7])
def test_count_check_FAILS_on_a_mis_sized_registry_when_mcp_enabled(size):
    """MCP-PASS branch: anything other than 4 must be rejected."""
    assert tr.tool_count_matches(_fake_registry(size), True) is False


@pytest.mark.parametrize("size", [0, 1, 2, 4, 5, 7])
def test_count_check_FAILS_on_a_mis_sized_registry_when_mcp_disabled(size):
    """MCP-FAIL / UNRESOLVED branch: anything other than 3 must be rejected.

    This is the branch the broken v2 expression could not fail on. A 0-tool and a
    7-tool registry both pass through it here to make that concrete.
    """
    assert tr.tool_count_matches(_fake_registry(size), False) is False


def test_count_check_PASSES_on_the_right_size_on_each_branch():
    assert tr.tool_count_matches(_fake_registry(4), True) is True
    assert tr.tool_count_matches(_fake_registry(3), False) is True


def test_the_broken_v2_expression_would_have_passed_a_seven_tool_registry():
    """Pins the defect v2.1 B1 fixed, so nobody re-introduces the unparenthesised form.

    This asserts the behaviour of the BROKEN expression on purpose: it is the
    regression guard for the fix, and it is the reason the fix was needed.
    """
    seven = _fake_registry(7)
    broken = (len(seven) == 4) if False else 3          # what v2's wording parsed to
    assert bool(broken) is True                          # truthy: asserts nothing
    assert tr.tool_count_matches(seven, False) is False  # the fixed form rejects it
