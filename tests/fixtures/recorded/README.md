# Recorded fixture corpus - CAPTURED 2026-09-14. AC-0.2 is MET.

`py -m tools.fixture_report` exits 0: `fixture_files: 18`, `distinct_verdicts: 2`,
`AC_0_2_ELIGIBLE: yes`, `AC_0_2: MET`. The tampered half came from a real
`POST /api/demo/tamper` against the stack stood up in `docs/evidence/standup.txt`.

The recorder is `tools/record_fixtures.py`. It implements the three requirements below -
they were written as requirements on 2026-09-13, before it existed, and all three were
exercised for real on 2026-09-14:

* rate limit: 21 requests, paced at one per ~0.56 s, `http_429_encountered: 0`;
* chain completeness: `{"postings": 5, "posting_hash_rows": 5, "chainedCount": 5, "intact": true}`
  asserted BEFORE the clean half was written;
* DB capture: three read-only SELECTs under `default_transaction_read_only=on`, which is
  enforced by PostgreSQL itself - a probe of the same session refused
  `UPDATE posting SET amount = amount WHERE 1=0` with
  `ERROR: cannot execute UPDATE in a read-only transaction`.

One thing the run revealed that no amount of reading would have: the compose file mounts a
NAMED VOLUME, so the demo came up holding 34 postings from a June run. `POST /api/demo/reset`
is what makes the corpus the 5-transfer scenario, and without it the capture would have
silently inherited stale data that still looked perfectly well-formed.

---

## ORIGINAL STAGING NOTE, 2026-09-13, kept verbatim

# Recorded fixture corpus - EMPTY, blocked on Docker

This directory is where AC-0.2's corpus belongs: fixtures **captured from a running
LedgerMind**, not computed. It is empty as of 2026-09-13 because the Docker daemon is
down (see `docs/evidence/preflight.txt`).

## Why the derived corpus cannot stand in for this one

`tests/fixtures/derived_from_source/` holds a corpus computed from the Java source.
It is arithmetically exact and it is useful - it is a correct expected-value oracle
for the Phase-1 checker - but it does **not** satisfy AC-0.2, and manifest section
2.6 says why in one line: *the tampered corpus must come from a real
`POST /api/demo/tamper` against a running LedgerMind, NOT from a hand-edited JSON
file. A hand-edited fixture proves the test, not the instrument.*

That rule is enforced mechanically, not by good faith. `_corpus.json` in the derived
corpus carries `ac_0_2_eligible: false`, and `tools/fixture_report.py` refuses any
corpus that is not eligible, no matter how many files or distinct verdicts it holds.
Run it and see:

    py -m tools.fixture_report --corpus derived     # exits 1, AC_0_2: NOT MET
    py -m tools.fixture_report                      # exits 1, this corpus is empty

## The recording sequence, staged and ready

Run it once the stack is up (`docs/evidence/standup.txt`). It is the manifest's P0.2
sequence: reset, read everything, tamper, read everything again.

    BASE=http://localhost:8080

    curl -s -X POST  $BASE/api/demo/reset
    curl -s          $BASE/api/accounts/external:funding
    curl -s          $BASE/api/accounts/wallet:ana
    curl -s          $BASE/api/accounts/wallet:beto
    curl -s          $BASE/api/journal/verify
    curl -s          $BASE/api/journal/audit
    curl -s          $BASE/api/journal/checkpoint
    curl -s          $BASE/api/journal/checkpoint/verify
    curl -s -X POST  $BASE/api/demo/reconcile

    curl -s -X POST  $BASE/api/demo/tamper

    # then every read above again, into the tampered half

Save each response body as its own `.json` file, and write a `_corpus.json` next to
them with `corpus_kind: "recorded"` and `ac_0_2_eligible: true`. AC-0.2 then needs
`fixture_files >= 6` and `distinct_verdicts >= 2`; the two `verdict` strings out of
`/api/journal/audit`, before and after the tamper, supply the second.

## THREE THINGS THE LOOP ABOVE WILL GET WRONG IF WRITTEN NAIVELY

Added 2026-09-13 from the Java, before the recorder exists, so they are requirements
rather than post-mortems. Each was re-derived from the source named beside it.

### 1. The rate limit will bite this exact loop

`web/RateLimitFilter.java:20-21,30` - a GLOBAL fixed-window limiter of **30 requests
per 10 000 ms** over `/api/demo/**` **and** `/api/journal/**`, which is precisely the
set of paths this sequence hammers. One reset + tamper cycle already spends 4 demo
calls and 8 journal calls, and any retry loop or a second pass inside the same window
crosses it. Over the limit the filter returns:

    HTTP 429, body: {"detail":"Rate limit: demasiadas solicitudes, intenta de nuevo en unos segundos."}

Two consequences for the recorder:

* That body is **NOT** a ProblemDetail - no `type`, `title` or `status` fields, just
  `detail`. A recorder that blindly saves response bodies will happily write that
  object into `journal_audit.json` and produce a corrupt corpus that still has the
  right file count. **Check the status code before saving, never just the body.**
* Handle 429 with a **backoff and retry** (the window is 10 s, so sleeping ~11 s and
  retrying once is enough), and throttle the whole sequence to stay under 30 per 10 s.
  The limiter is a global counter, not per-client, so anything else touching the demo
  at the same time counts against the same budget.

### 2. Chaining is ASYNCHRONOUS - assert completeness before recording

`JournalChainer.java:39` chains on `@Scheduled(fixedDelayString = "${ledgermind.journal.chain-delay-ms:5000}")`
and `JournalCheckpointService.java:44` checkpoints every 10 s by default.
`DemoSupportController.reset` (:54) chains and signs synchronously "AHORA" so the
normal reset path should already be complete - but the recorder must not depend on
that, and after `POST /api/demo/tamper` the verdict the audit reports is a function of
what the background job has processed so far.

So: before writing ANY corpus, the recorder must assert **chain completeness** -
`chainedCount` covers every posting it expects - and if it does not, wait and re-read
rather than record. A half-built chain recorded as ground truth is worse than no
corpus, because every later comparison inherits it silently.

### 3. `posting_hash` and `idempotencyKey` are not on any HTTP surface

No REST endpoint and no MCP tool exposes `posting_hash` rows, and `TransactionInfo`
(LedgerMcpTools.java:87-88) omits `idempotencyKey`, which is a REQUIRED field of the
canonical string `JournalChainer.entryHash` signs. So an HTTP-only recorder can capture
the ledger's **verdict** on its own hash chain but never the material needed to
**recompute** it - which would leave the deterministic checker trusting the thing it is
supposed to check.

Per the Phase 0 design decisions the recorder therefore also captures `posting_hash` and
`idempotencyKey` from a **read-only SELECT against the demo Postgres**, using a
read-only role or a plainly SELECT-only connection. Never a write, never a DDL, never
an `UPDATE` - the tamper is performed through the app's own `/api/demo/tamper`
endpoint, exactly as a user would, and never by touching the database directly.
