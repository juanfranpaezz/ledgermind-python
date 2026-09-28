"""The MCP-spike state reader must return every one of its outcomes on a real file.

Plan reference: AC-0.3 (manifest v1), as amended by v2 A8 and v2.1 B1. The binding
rule is that ``MCP_ENABLED`` is derived from the evidence file and never set by hand.
A reader that can only ever return one state would silently pin the tool count, which
is the inert-instrument failure this project keeps finding in its own machinery, so
each state is exercised here against a file on disk rather than a mock.
"""

from __future__ import annotations

from ledger_verification_agent import spike_state


def _write(tmp_path, body):
    path = tmp_path / "mcp-spike.md"
    path.write_text(body, encoding="utf-8")
    return path


def test_pass_token_yields_pass_and_four_tools(tmp_path):
    path = _write(tmp_path, "# spike\n\nOutcome: MCP-PASS\nlist_transactions returned a payload.\n")
    state = spike_state.read_spike_state(path)
    assert state.state == spike_state.PASS
    assert state.mcp_enabled is True
    assert state.expected_tool_count == 4


def test_fail_token_yields_fail_and_three_tools(tmp_path):
    path = _write(tmp_path, "# spike\n\nOutcome: MCP-FAIL\n401 from the token endpoint.\n")
    state = spike_state.read_spike_state(path)
    assert state.state == spike_state.FAIL
    assert state.mcp_enabled is False
    assert state.expected_tool_count == 3


def test_no_token_yields_unresolved_and_fails_closed(tmp_path):
    path = _write(tmp_path, "# spike\n\nBLOCKED: the Docker daemon is down, the spike did not run.\n")
    state = spike_state.read_spike_state(path)
    assert state.state == spike_state.UNRESOLVED
    assert state.mcp_enabled is False
    assert state.expected_tool_count == 3


def test_both_tokens_yield_unresolved_not_a_coin_flip(tmp_path):
    path = _write(tmp_path, "MCP-PASS on the first try, then MCP-FAIL after the token expired.\n")
    state = spike_state.read_spike_state(path)
    assert state.state == spike_state.UNRESOLVED
    assert state.mcp_enabled is False


def test_missing_file_yields_unresolved(tmp_path):
    state = spike_state.read_spike_state(tmp_path / "absent.md")
    assert state.state == spike_state.UNRESOLVED
    assert state.mcp_enabled is False


def test_a_sentence_describing_the_tokens_is_not_a_verdict(tmp_path):
    """The evidence file this repo ships names the tokens without claiming one.

    If that prose counted as a verdict, the blocked repository would report a spike
    outcome it never ran. The reader matches bare tokens only.
    """
    path = _write(
        tmp_path,
        "This file deliberately carries NEITHER frozen token. They are written here as\n"
        "MCP-{PASS,FAIL} so that naming them cannot be mistaken for recording one.\n",
    )
    state = spike_state.read_spike_state(path)
    assert state.state == spike_state.UNRESOLVED
