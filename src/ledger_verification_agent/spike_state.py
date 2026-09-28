"""Reads the AC-0.3 MCP-spike verdict from its evidence file.

Plan reference: manifest v1 AC-0.3, as amended by v2 section A8 and v2.1 section B1.
The rule the plan freezes is that ``MCP_ENABLED`` is DERIVED FROM THE EVIDENCE FILE
and never set by hand, so that the tool count and the spike verdict cannot drift
apart silently.

Three states, not two. The plan names two verdict tokens; a third state exists in
reality and pretending otherwise is how a guard becomes decorative:

* ``PASS``       - the evidence file carries the pass token. MCP tool is enabled.
* ``FAIL``       - the evidence file carries the fail token. MCP tool is disabled.
* ``UNRESOLVED`` - the spike has not been run (or the file carries neither token,
                   or carries both). MCP tool is disabled: FAIL CLOSED.

UNRESOLVED is the state the repository is in until a running LedgerMind exists,
because the spike needs one. It deliberately resolves to ``MCP_ENABLED == False``
so the shipped registry is the 3-tool REST-only registry, which is also the
manifest's own R7 cut-list fallback.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# The two frozen tokens from AC-0.3. They are matched as whole words so that a
# sentence *describing* the tokens (for example "MCP-{PASS,FAIL}") does not count
# as a verdict. Only a bare token does.
_PASS_TOKEN = "MCP-PASS"
_FAIL_TOKEN = "MCP-FAIL"

_PASS_RE = re.compile(r"(?<![A-Za-z0-9_{,-])" + re.escape(_PASS_TOKEN) + r"(?![A-Za-z0-9_},-])")
_FAIL_RE = re.compile(r"(?<![A-Za-z0-9_{,-])" + re.escape(_FAIL_TOKEN) + r"(?![A-Za-z0-9_},-])")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SPIKE_EVIDENCE = REPO_ROOT / "docs" / "evidence" / "mcp-spike.md"

PASS = "PASS"
FAIL = "FAIL"
UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class SpikeState:
    """The spike verdict plus the reason it is what it is."""

    state: str
    reason: str

    @property
    def mcp_enabled(self) -> bool:
        return self.state == PASS

    @property
    def expected_tool_count(self) -> int:
        """AC-0.3: the registry is frozen at 4 tools on PASS, 3 otherwise."""
        return 4 if self.mcp_enabled else 3


def read_spike_state(path: Path | None = None) -> SpikeState:
    """Derive the spike state from the evidence file. Never trusts a caller flag."""
    target = Path(path) if path is not None else DEFAULT_SPIKE_EVIDENCE
    if not target.exists():
        return SpikeState(UNRESOLVED, f"evidence file absent: {target}")
    text = target.read_text(encoding="utf-8", errors="replace")
    has_pass = bool(_PASS_RE.search(text))
    has_fail = bool(_FAIL_RE.search(text))
    if has_pass and has_fail:
        return SpikeState(UNRESOLVED, f"both verdict tokens present in {target.name}; ambiguous")
    if has_pass:
        return SpikeState(PASS, f"pass token found in {target.name}")
    if has_fail:
        return SpikeState(FAIL, f"fail token found in {target.name}")
    return SpikeState(UNRESOLVED, f"neither verdict token present in {target.name}")
