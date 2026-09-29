"""Read-only verification agent over the LedgerMind double-entry ledger.

Phase 0 and Phase 1: the MCP-spike state reader, the declarative read-only
tool registry and the deterministic verifier. The optional FastAPI service
lives outside this package, in ``ledgermind_api/``. Phase 2 (agent loop,
evals, CI) is a planned addition after 2026-10-28, on a simulated model at
zero cost; the verifier and the FastAPI service are complete.
"""

__version__ = "0.0.1"
