# AC-0.3 MCP spike - RUN 2026-09-14. Verdict below.

MCP-PASS

**What that token means, exactly:** a `tools/call` for `list_transactions` over the live
`/mcp` Streamable-HTTP endpoint, authenticated with a `client_credentials` bearer from the
demo authorization server, returned a payload. AC-0.3 therefore freezes the v1 tool count at
**4**, and `src/ledger_verification_agent/spike_state.py` derives `MCP_ENABLED = True` from
this file rather than from anybody's say-so.

## The run of record

Executed 2026-09-14 against the stack stood up in `docs/evidence/standup.txt`
(`docker compose -f docker-compose.observability.yml up --build -d postgres app`).
Well inside the 45-minute timebox: the whole sequence, token included, took under a minute.

| step | result |
|------|--------|
| `POST /oauth2/token`, `client_credentials`, scope `ledger.read`, HTTP Basic in a HEADER | `200`, `token_type=Bearer`, `expires_in=299`, `scope=ledger.read` |
| token claims that matter | `iss=http://localhost:8080`, `aud=ledgermind-mcp`, `scope=["ledger.read"]`, `sub=mcp-client` |
| `POST /mcp` `initialize`, dual `Accept: application/json, text/event-stream` | `200`, `protocolVersion 2025-06-18`, `serverInfo {"name":"ledgermind-mcp","version":"0.0.1"}` |
| `Mcp-Session-Id` present on the initialize RESPONSE headers | yes |
| `POST /mcp` `notifications/initialized` with the session id | `202` |
| `POST /mcp` `tools/list` | `200`, tools = `["list_transactions","get_balance","explain_reconciliation_discrepancy","verify_journal_integrity"]` |
| `POST /mcp` `tools/call` `list_transactions {"address":"wallet:ana"}` | `200`, `isError: false`, 4 postings returned |

The returned payload, verbatim (demo ledger data, not credentials):

```
[{"id":4,"debitAccountId":2,"creditAccountId":3,"amount":12500,"asset":"ARS","createdAt":1789401735.147314000},
 {"id":3,"debitAccountId":2,"creditAccountId":3,"amount":30000,"asset":"ARS","createdAt":1789401735.118061000},
 {"id":2,"debitAccountId":1,"creditAccountId":2,"amount":50000,"asset":"ARS","createdAt":1789401735.087582000},
 {"id":1,"debitAccountId":1,"creditAccountId":2,"amount":100000,"asset":"ARS","createdAt":1789401735.037738000}]
```

### Three things this run SETTLED that were previously reasoned-not-measured

1. **The rewritten step 3 is correct.** The dual `Accept` header plus `initialize` ->
   `Mcp-Session-Id` -> `tools/call` sequence works on the first attempt. The earlier single
   bare POST, copied from the Java README, could not have worked. The header requirements had
   been re-derived from the jar's own error strings; they are now confirmed by execution.
2. **`TransactionInfo` really does omit `idempotencyKey`** - the payload above carries `id`,
   `debitAccountId`, `creditAccountId`, `amount`, `asset` and `createdAt`, and nothing else.
   That is the live confirmation of the premise of the DB-level capture decision: the canonical string the hash
   chain signs is NOT recomputable over any wire surface, MCP included, which is why the
   recorder takes a read-only Postgres SELECT.
3. **`createdAt` comes over MCP as a float epoch** (`1789401735.147314000`), not as the
   `Instant.toString()` text the chain signs. A checker that fed the MCP rendering into the
   canonical string would compute a wrong hash and blame the server.

### What this run did NOT settle

* The 400/404 status codes for the two header rejections. The happy path was taken on the
  first try, so neither rejection was provoked and neither code was observed. They remain the
  docs-vs-code review's claim, not a measurement here.
* Whether `tools/call` works WITHOUT the preceding `notifications/initialized`. It was sent,
  so its necessity is untested.
* Protocol-version negotiation. `2025-06-18` was accepted first, so no fallback was exercised.

### How it was run, and what was never written down

The secret is a literal in the demo's own Java config on this machine. It was read into
memory by name, sent as an HTTP Basic **header** (never in argv, never in a URL), and never
printed, logged or written to any file. The access token likewise never touched disk; only
its non-secret claims (`iss`, `aud`, `scope`, `sub`) are quoted above. The runner script was
kept in the session scratchpad and deliberately NOT added to this repository, because this
repository is intended to be public and a helper that knows how to extract a client secret
from a source file has no business shipping in it.

## Exact commands, staged and ready to run

The spike is a 45-minute hard-capped timebox. It has one job: get a
`list_transactions` payload back over MCP, or record the error text.

1. Stand the stack up first (see `docs/evidence/standup.txt`).

2. Get a token from the demo authorization server. It is a `client_credentials`
   client registered in `DemoAuthorizationServerConfig` with scope `ledger.read`.
   **The client secret is a literal in that Java config. Read it by name at
   runtime; never copy it into this repo, a log, a command line or a message.**
   Put it in an environment variable before the call and reference the variable:

   ```
   # the value is injected into the environment by the operator, never typed here
   curl -s -u "mcp-client:$LEDGERMIND_MCP_CLIENT_SECRET" \
     -d "grant_type=client_credentials&scope=ledger.read" \
     http://localhost:8080/oauth2/token
   ```

3. Call the tool over Streamable HTTP JSON-RPC. **REWRITTEN 2026-09-13** - the previous
   version of this step was a single bare authenticated POST to `/mcp`, copied from the
   Java README, and it CANNOT work. A docs-vs-code review caught it and the claim was
   then re-derived from the primary artifact rather than from the review: the transport
   is `WebMvcStreamableServerTransportProvider` (application.yml:37 `protocol:
   STREAMABLE`; `spring-ai-starter-mcp-server-webmvc`, spring-ai 1.1.7, which resolves
   `io.modelcontextprotocol.sdk:mcp-spring-webmvc:0.18.2` in the local Maven cache), and
   disassembling that class shows these literals:

       "Invalid Accept headers. Expected TEXT_EVENT_STREAM and APPLICATION_JSON"
       "Invalid Accept header. Expected TEXT_EVENT_STREAM"
       "Session ID required in mcp-session-id header"
       "Mcp-Session-Id"

   So every request needs the DUAL Accept header, and everything after `initialize`
   needs the session id the server hands back. (The review reports the two rejections as
   HTTP 400 and 404 respectively; the status codes are its claim, the header
   requirements are confirmed above. Record whatever actually comes back.)

   3a. INITIALIZE - this is the only call that may omit the session id:

   ```
   curl -i -X POST http://localhost:8080/mcp \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2025-06-18",
                    "capabilities":{},
                    "clientInfo":{"name":"ledger-verification-agent-spike","version":"0.0.1"}}}'
   ```

   Read `Mcp-Session-Id` off the RESPONSE HEADERS (that is why `curl -i` is used) and
   export it. The protocol versions the provider advertises are 2024-11-05, 2025-03-26,
   2025-06-18 and 2025-11-25; if `initialize` is rejected on version grounds, try the
   next one down and record which one was accepted.

   3b. TOOLS/CALL - same dual Accept header, plus the session id:

   ```
   curl -i -X POST http://localhost:8080/mcp \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Mcp-Session-Id: $MCP_SESSION_ID" \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
          "params":{"name":"list_transactions",
                    "arguments":{"address":"wallet:ana"}}}'
   ```

   A `notifications/initialized` notification between 3a and 3b is what a real client
   sends; if 3b is refused for a missing initialized notification, send it with the same
   headers and record that too - it is exactly the kind of finding this spike exists for.

## How to record the outcome

Replace this file's status section with exactly one of the two frozen tokens,
written bare, plus the evidence:

* **Pass token** - paste the returned payload (redacting nothing; it is demo
  ledger data, not credentials). The registry then ships 4 tools.
* **Fail token** - paste the verbatim error text and the HTTP status. The registry
  stays at 3 tools.

Either way, do not edit `MCP_ENABLED` by hand: it is derived from this file, and
`test_mcp_enabled_is_derived_from_the_evidence_file_not_set_by_hand` checks that.

## Why this tool is worth the timebox

`list_transactions` (renamed 2026-09-13 from our invented `list_entries_by_account`;
the wire name is the Java `@Tool(name = ...)` at LedgerMcpTools.java:47) is the only
one of the analyzer's four specified tools
that is serveable at all and is not already on REST (manifest v2 A6), and MCP
appears in 17 of 37 job descriptions in the corpus the lane analysis was built on.
On the pass branch it is also the more strongly guarded surface of the two, because
the server enforces `SCOPE_ledger.read` per tool.


---

## SUPERSEDED - the BLOCKED-ON-DOCKER status section, 2026-09-13, kept verbatim

Nothing below is current. It is preserved because the state it describes is what the
staged commands were written against, and deleting superseded evidence is how a record
stops being auditable.

# AC-0.3 MCP spike - NOT RUN. BLOCKED ON DOCKER.

**STATUS: BLOCKED-ON-DOCKER as of 2026-09-13.** The spike calls a running
LedgerMind MCP endpoint. The Docker daemon is down on this machine (see
`docs/evidence/preflight.txt`, LEG 1, exit code 1), so the spike did not run and
has no outcome.

## This file deliberately carries NEITHER frozen verdict token

AC-0.3 freezes two tokens, and `src/ledger_verification_agent/spike_state.py`
derives `MCP_ENABLED` from whichever one appears here. Writing either token into a
placeholder would manufacture a spike result out of nothing. They are named below
only in the escaped form `MCP-{PASS,FAIL}`, which the reader does not match, and
the test `test_a_sentence_describing_the_tokens_is_not_a_verdict` pins that
behaviour so this exact prose cannot start counting as a verdict later.

With neither token present the reader returns **UNRESOLVED**, which fails closed:
`MCP_ENABLED = False`, the shipped registry is the 3-tool REST-only registry, and
that is also the manifest's own R7 cut-list fallback (v2.1 B2 item 2). Nothing
about the current state is a decision to drop MCP; it is an unrun probe.
