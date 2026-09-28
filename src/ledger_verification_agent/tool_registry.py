"""Declarative, read-only tool registry over LedgerMind.

PHASE 0 SCOPE. This module declares WHICH tools exist and WHAT surface each one
reaches. It deliberately contains no HTTP client, no transport and no callable
tool body: those are Phase 2 deliverables, gated behind a pending design decision.
Declaring the surface now is what lets the AC-0.3 tool-count check and the
read-only allow-list check exist and be proven to fire both ways before any code
that can actually talk to the ledger is written.

Every endpoint below was re-derived today from the LedgerMind Java source at
commit 872505f (read-only):

* ``GET  /api/accounts/{address}``  - LedgerController.getAccount
* ``GET  /api/journal/audit``       - LedgerController.auditJournal
* ``POST /api/reconciliation``      - LedgerController.reconcile, javadoc "Solo lectura";
                                      it takes a settlement feed as the request body and
                                      writes nothing.
* ``POST /mcp``                     - Streamable-HTTP JSON-RPC transport; the underlying
                                      tool is LedgerMcpTools.listTransactions, registered
                                      as ``list_transactions`` and guarded server-side by
                                      scope ``ledger.read``. GATED on the AC-0.3 spike.

The mutating endpoints below are the denylist. They exist on the service and are
explicitly NOT reachable from this agent.

THE DENYLIST IS A CLIENT-SIDE CONTROL, NOT A SERVER-ENFORCED SCOPE. Corrected
2026-09-13 after re-reading the Java; the earlier wording implied more than is true.

* ``McpServerSecurityConfig.defaultSecurityFilterChain`` (@Order(2)) applies
  ``auth.anyRequest().permitAll()`` to everything that is not ``/mcp``. The whole REST
  ``/api`` surface - including ``POST /api/transfers`` and ``POST /api/demo/tamper`` -
  is UNAUTHENTICATED. Nothing on the server would refuse this agent a write.
* The only scope that exists in the Java is ``ledger.read``
  (DemoAuthorizationServerConfig:63; ``@PreAuthorize("hasAuthority('SCOPE_ledger.read')")``
  on all four MCP tools). There is NO ``ledger.write`` scope to be denied.
* Therefore the read-only guarantee for the REST surface rests entirely on THIS
  registry plus the AC-2.1 tests. It is a property of our client, not of the server.
  That is a finding about the Java LedgerMind repository; we do
  not change LedgerMind.
* ``POST /api/demo/reconcile`` stays on the denylist even though
  ``ReconciliationService.reconcileDemoFeed`` is annotated
  ``@Transactional(readOnly = true)`` (ReconciliationService.java:37) and writes
  nothing. Keeping a harmless endpoint denied is a fail-SAFE default; the annotation is
  recorded here so the denial is a deliberate choice rather than a misreading.
"""

from __future__ import annotations

from dataclasses import dataclass

from .spike_state import read_spike_state


@dataclass(frozen=True)
class ToolSpec:
    """One tool the agent is allowed to call. Metadata only in Phase 0."""

    name: str
    transport: str          # "rest" | "mcp"
    method: str             # HTTP method actually used on the wire
    path: str               # HTTP path actually used on the wire
    upstream: str           # the Java symbol that serves it
    requires_mcp: bool
    description: str


# --- The complete DECLARED surface. Four specs, one of them gated. -------------
# This tuple is a LITERAL declaration, not a function of the spike flag, so that a
# fifth tool (or a deleted one) breaks the count assertions rather than sliding
# through them.
DECLARED_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="get_balance",
        transport="rest",
        method="GET",
        path="/api/accounts/{address}",
        upstream="LedgerController.getAccount @ 872505f",
        requires_mcp=False,
        description="Balance and posted counters for one account address.",
    ),
    ToolSpec(
        name="verify_journal",
        transport="rest",
        method="GET",
        path="/api/journal/audit",
        upstream="LedgerController.auditJournal @ 872505f",
        requires_mcp=False,
        description="Consolidated journal integrity report: hash chain plus ML-DSA checkpoint.",
    ),
    ToolSpec(
        name="reconcile_against_feed",
        transport="rest",
        method="POST",
        path="/api/reconciliation",
        upstream="LedgerController.reconcile @ 872505f (non-mutating by contract)",
        requires_mcp=False,
        description="Classify discrepancies between a settlement feed and the ledger.",
    ),
    ToolSpec(
        # RENAMED 2026-09-13 from "list_entries_by_account". The name a client sends
        # over MCP is the Java @Tool name, and LedgerMcpTools.java:47 declares
        # @Tool(name = "list_transactions"). The old name was ours, not the server's,
        # and would have failed the call. "LedgerEntry" in the Java means something
        # else entirely - the reconciliation projection (ref, amount) - so reusing it
        # here was doubly wrong.
        name="list_transactions",
        transport="mcp",
        method="POST",
        path="/mcp",
        upstream="LedgerMcpTools.listTransactions @ 872505f, @Tool(name=\"list_transactions\"), @PreAuthorize SCOPE_ledger.read",
        requires_mcp=True,
        description="Postings in which one account participates. Only reachable over MCP.",
    ),
)

# --- The read-only allow-list and the mutating denylist (AC-2.1 v2) ------------
READ_ONLY_SURFACE: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/api/accounts/{address}"),
        ("GET", "/api/journal/audit"),
        ("GET", "/api/journal/verify"),
        ("GET", "/api/journal/checkpoint"),
        ("GET", "/api/journal/checkpoint/verify"),
        ("POST", "/api/reconciliation"),
        ("POST", "/mcp"),
    }
)

MUTATING_ENDPOINTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/accounts"),
        ("POST", "/api/transfers"),
        ("POST", "/api/demo/reset"),
        ("POST", "/api/demo/reconcile"),
        ("POST", "/api/demo/tamper"),
    }
)


def active_tools(mcp_enabled: bool) -> tuple[ToolSpec, ...]:
    """The registry the agent would actually be given, for a spike outcome."""
    return tuple(t for t in DECLARED_TOOLS if mcp_enabled or not t.requires_mcp)


def expected_tool_count(mcp_enabled: bool) -> int:
    """AC-0.3's frozen count. Parenthesised on purpose - see manifest v2.1 B1."""
    return 4 if mcp_enabled else 3


def tool_count_matches(registry: "tuple[ToolSpec, ...] | list[ToolSpec]", mcp_enabled: bool) -> bool:
    """AC-0.3's assertion, as a PURE function so it can be driven both ways.

    Manifest v2.1 B1 governs the shape: the comparison is against the conditional
    VALUE ``(4 if mcp_enabled else 3)``, never the conditional applied to the
    comparison, which on the MCP-disabled branch evaluated to the truthy literal 3
    and asserted nothing at all.
    """
    return len(registry) == (4 if mcp_enabled else 3)


def mutating_endpoints_in(registry: "tuple[ToolSpec, ...] | list[ToolSpec]") -> tuple[tuple[str, str], ...]:
    """Every (method, path) in the registry that is on the mutating denylist."""
    return tuple((t.method, t.path) for t in registry if (t.method, t.path) in MUTATING_ENDPOINTS)


def endpoints_outside_read_only_surface(
    registry: "tuple[ToolSpec, ...] | list[ToolSpec]",
) -> tuple[tuple[str, str], ...]:
    """Every (method, path) in the registry that is not on the read-only allow-list."""
    return tuple((t.method, t.path) for t in registry if (t.method, t.path) not in READ_ONLY_SURFACE)


# --- What the repository ships right now, derived from the spike evidence -----
SPIKE_STATE = read_spike_state()
MCP_ENABLED: bool = SPIKE_STATE.mcp_enabled
TOOL_REGISTRY: tuple[ToolSpec, ...] = active_tools(MCP_ENABLED)
