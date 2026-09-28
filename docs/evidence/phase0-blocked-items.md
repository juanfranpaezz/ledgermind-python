> **RESOLVED 2026-09-14.** Docker came up and every item below was executed. AC-0.1 MET
> (`docs/evidence/standup.txt`, `HTTP/1.1 200`, 320 s). AC-0.2 MET
> (`tests/fixtures/recorded/`, 18 files, 2 verdicts, eligible). AC-0.3 recorded as
> **MCP-PASS** (`docs/evidence/mcp-spike.md`), so the registry ships 4 tools. Item 5's
> after-snapshot was taken and compares clean. Item 4 (the section 2.6 instrument-fitness
> leg for the Phase-1 checker) remains Phase-1 work and is still gated behind the project owner's
> Phase 1 go decision. **The text below is the 2026-09-13 staging record and is kept verbatim; read it
> for the commands, not for the status.**

# Phase 0 - what is BLOCKED ON DOCKER, with the exact commands staged

Date: 2026-09-13. Everything below needs a running LedgerMind. The Docker daemon is
down on this machine (`docs/evidence/preflight.txt`, LEG 1, exit code 1) and the
manifest's named ABORT action forbids improvising a workaround, so none of it was
attempted. Each item names the criterion, the command, and what flips it to MET.

The project owner's action is one line, at the end-of-Phase-0 review: **start Docker Desktop and say go, or take
the fallback.** Nothing here needs anything else from him.

---

## 1. AC-0.1 - one-command stand-up transcript

**Blocked because:** the stack cannot start without the daemon.
**Evidence file:** `docs/evidence/standup.txt` (staged, deliberately without the
status literal so the checker cannot report a false MET).

```
cd "<ledgermind-checkout>"
docker compose -f docker-compose.observability.yml up --build -d postgres app
curl -i http://localhost:8080/api/journal/audit
```

Fallback, only on a failure of the primary (this path writes under `target/`, which
is why the no-write guard excludes `target/` by name):

```
cd "<ledgermind-checkout>"
docker compose up -d
./mvnw spring-boot:run -Dspring-boot.run.profiles=demo
curl -i http://localhost:8080/api/journal/audit
```

**Flips to MET when:** the successful status line and the exact command are pasted
into `standup.txt`, plus `elapsed_to_healthy_seconds` as a number, under 600.
**Timebox:** 60 minutes hard cap. The cap guards build time (Maven runs inside the
image, so a cold cache is slow and needs network), not design uncertainty.

---

## 2. AC-0.2 - recorded fixture corpus, clean and tampered

**Blocked because:** manifest section 2.6 requires the tampered half to come from a
real `POST /api/demo/tamper` against a running stack. A computed fixture proves the
test, not the instrument.
**Evidence dir:** `tests/fixtures/recorded/` (empty; its README carries the full
recording sequence).

```
py -m tools.fixture_report          # today: exits 1, corpus empty
```

**Flips to MET when:** the recorded corpus exists with `_corpus.json` carrying
`ac_0_2_eligible: true`, at least 6 fixture files, and at least 2 distinct `verdict`
values. The reporter is already proven to return both outcomes - see
`tests/test_derived_fixture_corpus.py`.

**What is ready now instead:** a source-derived corpus under
`tests/fixtures/derived_from_source/`, computed from the Java source with the real
SHA-256 chain, marked ineligible for AC-0.2 on purpose. It is an exact
expected-value oracle: if the recorded clean corpus later disagrees with it, either
the demo seeding changed or our reading of the Java source is wrong, and both are
worth knowing before the checker is written.

---

## 3. AC-0.3 - the MCP spike verdict (the CHECK is done; the SPIKE is not)

**Blocked because:** the spike calls a live `/mcp` endpoint behind OAuth2.1.
**Evidence file:** `docs/evidence/mcp-spike.md` (staged, deliberately carrying
neither frozen token).

Two halves, and only one of them is blocked:

* **The checker: DONE and proven both ways.** `pytest -k test_tool_count_matches_spike`
  exists, uses the parenthesised expression v2.1 B1 mandates, and is demonstrated to
  FAIL on a deliberately mis-sized registry on each branch (registry sizes 0, 1, 2,
  3, 5, 7 against the MCP-enabled branch; 0, 1, 2, 4, 5, 7 against the disabled one).
  A regression test also pins the behaviour of the BROKEN v2 expression so nobody
  reintroduces it.
* **The spike: NOT RUN.** Commands are in `mcp-spike.md`. The client secret is read
  from the environment by name and never written into this repo, a log, a command
  line or a message.

**Current state:** UNRESOLVED, failing closed to `MCP_ENABLED = False` and a 3-tool
REST-only registry - which is also the manifest's own R7 cut-list fallback. That is
an unrun probe, not a decision to drop MCP.

---

## 4. The section 2.6 instrument-fitness leg for the Phase-1 checker

**Blocked because:** it requires the deployment-realistic tampered corpus from item 2.
Phase 1 is in any case gated behind the project owner's Phase 1 go decision at the end-of-Phase-0 review and was not started.

---

## 5. The A4 / B4 no-write guard's SECOND snapshot

The before-snapshot is taken and committed: `docs/evidence/ledgermind-snapshot-before.txt`
(HEAD 872505f, 8 pre-existing porcelain entries, 62 protected files hashed). The
after-snapshot is a P6 task. The comparator itself is already proven to return both
outcomes, including the `target/`-only case that must NOT trip it:

```
py tools/ledgermind_snapshot.py --repo "<ledgermind-checkout>" \
    --out docs/evidence/ledgermind-snapshot-after.txt
py tools/ledgermind_snapshot.py --compare \
    docs/evidence/ledgermind-snapshot-before.txt \
    docs/evidence/ledgermind-snapshot-after.txt
```
