PHASE 1 - DETERMINISTIC VERIFIER: EVIDENCE
==========================================
Date: 2026-09-17, 21:20-22:10 local. Operator: coder agent, Phase-1 build.
Base commit: 7b19b04 (phase 0 foundations). Nothing was committed by this pass.
Zero spend: no model call of any kind, no network, no paid API. The LedgerMind Java
repo was READ ONLY and is proven unwritten at the bottom of this file.

Every number below came from a command run on this machine in this session. Where a
claim could not be executed it is marked UNVERIFIED and says why.


THE CRITERIA THIS PASS WAS SCORED AGAINST
-----------------------------------------
Consumed verbatim from the Phase 0 plan, section 2, "Phase 1 - Deterministic
checker" (the plan itself is kept in private project notes):

  AC-1.1  clean corpus      -> violations == 0 and verdict == "OK"
  AC-1.2  tampered corpus   -> violations >= 1, the report names the exact broken seq,
                               verdict == "TAMPERED"
  AC-1.3  unbalanced posting -> conservation_violations == 1
  AC-1.4  the checker imports no model client and makes no network call

Reading declared, not hidden: AC-1.1/AC-1.2 write "violations" where a COUNT is meant.
The verdict object exposes `violations` as the tuple of Violation objects and
`violation_count` as the integer; the tests assert the integer.


1. THE THREE CHECKS AGAINST THE FIXTURES
----------------------------------------
Command, per row:  py -m tools.verify_report --corpus <corpus> [--half H | --case C]

  recorded / clean        verdict OK        0 violations   exit 0
      money_conservation     OK    5 postings, 3 accounts, debit legs 200500 == credit legs 200500
      no_overdraft           OK    3 accounts, 2 with a floor, 5 replay steps
      hash_chain_continuity  OK    5/5 links recomputed from GENESIS, intact, checkpoint anchored

  recorded / tampered     verdict TAMPERED  3 violations   exit 1
      hash_chain_continuity  VIOLATION [entry_hash_mismatch] breaks at seq=5 after 4 intact links
          stored   entryHash d6ba614f5f60beb4b6b69227c68c9fc0e310c58bd497599728f2f7083080159d
          recomputed        678bd7071fbdddda1fd4778d399685b20a8e2609de4ccf09a48ff8d13d1064e1
      money_conservation     VIOLATION x2 [counters_disagree_with_postings]
          external:funding reports postedDebits 158000, the replay gives 158001
          wallet:beto      reports postedCredits 50500, the replay gives 50501

      NOT A FALSE POSITIVE, and worth reading twice: POST /api/demo/tamper edits the
      posting row and does NOT touch the account counters, so after the tamper the
      counters genuinely disagree with the journal. The ledger's own hash chain cannot
      see that plane at all - it protects postings, not counters. Two independent
      detections of one tamper.

  adversarial / unbalanced_posting              conservation 1 violation  (AC-1.3, exactly 1)
      posting id=3 (ORD-1003) debits 30000 but credits 29500
  adversarial / overdraft_account               no_overdraft VIOLATION, cites wallet:ana at -92500
  adversarial / counters_disagree_with_postings conservation VIOLATION, system net = 1, not 0
  adversarial / chain_prev_hash_rewritten       chain breaks at seq=4  (fixture declares 4)
  adversarial / chain_link_posting_deleted      chain breaks at seq=3  (fixture declares 3)
  adversarial / clean_must_not_fire             verdict OK, 0 violations - the negative control


2. THE MODEL-FREE LEG: AN INDEPENDENT RECOMPUTATION
---------------------------------------------------
tests/test_deterministic_verifier_phase1.py re-types JournalChainer.entryHash from the
Java INSIDE THE TEST and never imports journal_chain for it. It reproduces all five of
the Java's own entry_hash values on the clean corpus, and on the tampered corpus it
shows the single mismatch is explained to the byte: restoring amount 8001 -> 8000
reproduces the original stored hash exactly. If journal_chain and the test ever agreed
only because they are the same code, this leg would be worthless.


3. MUTATION TESTING - 6 PLANTED DEFECTS, 6 KILLED
--------------------------------------------------
Run on a throwaway copy of the repo in the scratchpad; the shipped tree was never
mutated. Control green before and after.

  CONTROL                                                        exit 0, 0 failed
  M1 entry_hash drops the prev_hash prefix                        KILLED, 10 tests red
  M2 availableBalance drops the pendingDebits term                KILLED,  1 test red
  M3 conservation compares the debit leg with itself              KILLED,  3 tests red
  M4 verify_chain stops comparing prevHash to the running head    KILLED,  1 test red
  M5 no_overdraft flags every negative balance (over-fires)       KILLED,  7 tests red
  M6 a backend that blows up is reported VERIFIED                 KILLED,  1 test red
  FINAL CONTROL (all reverted)                                    exit 0, 0 failed
  KILL COUNT: 6/6

M5 is the one worth naming: it is the OVER-firing mutant, and it is killed by the
clean corpus and by clean_must_not_fire. An over-firing checker is as useless as an
inert one, and only a negative control catches it.


4. READ-ONLY GUARANTEE - FOUR LEGS, EACH SHOWN FIRING
------------------------------------------------------
tests/test_verifier_read_only_reachability.py, 33 tests.

  registry leg  every dataset the verifier reads names a ToolSpec on READ_ONLY_SURFACE
                and on none of MUTATING_ENDPOINTS. Planted positive: a registry with
                POST /api/transfers is caught.
  static leg    AST over the five verifier modules: hard-required imports are pure
                offline stdlib only; no write/network/spawn call name appears; no
                mutating endpoint path appears in any string literal. All three
                scanners are shown firing on a planted module and silent on a clean one.
  closure leg   a FRESH interpreter imports deterministic_verifier and its whole
                sys.modules closure is checked: anthropic, openai, httpx, requests,
                urllib, http, socket, ssl, subprocess, asyncio and fastapi are all
                ABSENT. Planted positive: the same probe on urllib.request fires.
  dynamic leg   check_all() is run for real with socket.socket, every write-mode open
                (builtins AND io, because pathlib calls io.open directly) and the
                delete syscalls replaced by raisers. It completes and returns the same
                verdicts. A positive control proves the harness itself fires, and a
                fourth test proves reads still work - otherwise the leg would pass for
                the wrong reason.

ONE SOURCE HAS NO TOOL AND IT IS DISCLOSED. posting_hash rows (seq/prevHash/entryHash)
are exposed by no REST endpoint and no MCP tool; they come from a PostgreSQL session
pinned read-only by the server (PGOPTIONS=-c default_transaction_read_only=on), which
is a stronger guard than a client-side allow-list. The honest sentence is: every data
source is read-only, and every source that HAS an HTTP surface is a read-only registry
tool.


5. THE ML-DSA-65 CHECKPOINT SIGNATURE
--------------------------------------
DEFAULT STATUS: UNVERIFIED-SIGNATURE, with the reason attached.

Probed on this machine 2026-09-17:
  cryptography 46.0.5 is installed; `from cryptography.hazmat.primitives.asymmetric
  import mldsa` -> ImportError. No oqs, no dilithium_py, no pqcrypto. So no in-process
  library can verify ML-DSA here, and the report says so rather than implying validity.

WHAT IS PROVEN WITH NO LIBRARY AT ALL, on both halves of the recorded corpus:
  signedMessage == "ledgermind:journal-checkpoint:v1:5:<headHash>"   byte-for-byte
  public key parses as an X.509 SPKI, OID 2.16.840.1.101.3.4.3.18 = id-ml-dsa-65
  the OID agrees with the declared algorithm string "ML-DSA-65"
  public key 1952 bytes, signature 3309 bytes - the ML-DSA-65 sizes
  problems: []

OPT-IN BACKEND, PROBED BOTH WAYS. OpenSSL 3.5.5 is on PATH here
(C:\Program Files\Git\mingw64\bin\openssl.EXE) and does support ML-DSA:

  py -m tools.verify_report --corpus recorded --half clean --mldsa-openssl
      checkpoint signature: VERIFIED (backend openssl-cli)

  the same signature against a message with one byte changed
      "Signature Verification Failure", exit 1

It is OFF by default on purpose: a deterministic verifier whose verdict depends on
what is installed on the box is not deterministic.

A PROPERTY THAT LOOKS WRONG AND IS NOT. On the TAMPERED corpus the signature still
verifies while the chain is broken. That is LedgerMind's own documented behaviour
(JournalCheckpointService javadoc): the signature anchors the head in time, the
SHA-256 chain is what betrays the edit. Reporting them as one field would destroy
security information, so they are two planes here and the signature does not gate the
verdict.

WHAT THIS DOES NOT PROVE, restated because it is easy to oversell: signature validity
here is MESSAGE INTEGRITY, not signer authenticity. The public key travels with the
row, so anyone who can rewrite the row can substitute their own (key, signature) pair.
Real non-repudiation needs a key anchored outside the database.


6. THE FULL SUITE
-----------------
  before this pass:  py -m pytest -> 110 passed, exit 0        (base commit 7b19b04)
  after  this pass:  py -m pytest -> 194 passed, exit 0, 0 skipped
  added: 35 + 33 + 16 = 84 tests. No pre-existing test was modified, skipped, deleted
  or re-thresholded; `git status` shows the three new test files as untracked additions.


7. THE LEDGERMIND JAVA REPO WAS NOT WRITTEN TO
-----------------------------------------------
  HEAD before and after: 872505f03605e60168288ef056eed58794e9a1fc
  git status --porcelain: the same 8 pre-existing entries before and after
  py tools/ledgermind_snapshot.py --compare docs/evidence/ledgermind-snapshot-before.txt <fresh>
      diff_lines: 0
      NO_WRITE_GUARD: PASS (snapshots identical)
      exit 0


8. WHAT THIS PASS DID NOT VERIFY
---------------------------------
* No live LedgerMind. Everything runs against the recorded corpus; the verifier has
  never talked to a running ledger, because it has no HTTP client yet (by design).
* The replay legs assume a ZERO opening state. That is true of this corpus because the
  recorder drove POST /api/demo/reset first, and the counters-vs-replay leg would fire
  if it were false - but a corpus captured mid-life would need an opening snapshot.
* pendingDebits is 0 everywhere in this corpus, so the third term of the balance is
  exercised only by a hand-built test case, not by recorded data.
* The adversarial fixtures carry no account ids, so the counters-vs-replay and
  replay-overdraft legs are SKIPPED BY NAME on them and were exercised on the recorded
  corpus and on hand-built snapshots instead.
* Signer authenticity, per section 5. And the ML-DSA key is ephemeral per boot, so this
  signature cannot be re-verified against a future run of the stack.
* Nothing here is an independent verdict. This file is evidence produced by the author
  of the code; a fresh-context verifier has not re-derived it.

## Correction 2026-09-19 - open-list fixes (fresh-context verification of 2026-09-17, O1/O2/O3/O5)

APPENDED, nothing above edited. Two sentences above are now FALSE and are corrected here:

* "the signature does not gate the verdict" (section on the two planes) - SUPERSEDED. A
  cryptographically INVALID checkpoint signature is now a `hash_chain_continuity` violation
  (`checkpoint_signature_invalid`, leg H4) and the verdict is TAMPERED / CLI exit 1, mirroring
  `JournalCheckpointService.audit()` (`tampered = !intact || !signatureValid || !signedHeadStillInChain`).
  UNVERIFIED-SIGNATURE still never gates: "could not verify" is not evidence of tamper. The two
  planes are still reported separately; H4 is the one place they meet.
* "replayed in chain order" - was replayed in POSTING-ID order (O1, a real false positive when a
  posting commits late with a lower id and a higher seq, the case `JournalChainer`'s own comment
  names). Now walked by `posting_hash.seq` (ties on posting id; unchained postings follow in id
  order, named; no links at all -> id order, named in `legs_skipped`). `examined["replay_order"]`
  says which order ran.
* `load_recorded` no longer guesses a floor when `allowNegative` is JSON null or absent (O2):
  three-state `None`, reported by name; every-floor-null -> NO_DATA.
* O5: today's `pendingDebits` applied at every replay step is now DECLARED in `legs_skipped`.

Regression guards: `tests/test_verifier_open_list_o1_o5_2026_09_19.py` (16 tests, 13 RED at
88db264, all GREEN after). O4 (honesty-sweep allowlist evidence unenforced) is NOT fixed here.
Evidence and both-outcome runs are kept in private project notes
(not part of this repository). This is builder evidence, not an independent verdict.

## Correction 2026-09-22 - revised open list items 1-7, plus the live-ledger findings A1/A2/A3

APPENDED, nothing above edited. One sentence above is now narrowed and none is withdrawn.

* THE `audit()` EQUIVALENCE IS PARTIAL, and the README now says so. H4 provably cannot catch an
  attacker who rewrites the postings, re-chains them and RE-SIGNS the head with their own key: the
  public key travels in the row and is anchored nowhere. That limit was already disclosed in
  section 5 above and at runtime on every verdict; what was missing was the tension with the new
  "same rule as audit()" claim. The disclosure above stands unweakened (open list item 3).
* THE ALGORITHM COLUMN IS NOW INSIDE THE VERIFICATION LOOP (item 4). LedgerMind computes
  `signatureValid = algorithmMatches && signer.verify(...)` (JournalCheckpointService.java:149-150,
  confirmed by reading the Java, working tree over 872505f - the fold is an uncommitted change
  there). A rewritten `algorithm` column with signature and key intact used to give VERIFIED / OK
  here while the Java said TAMPERED. It now gives INVALID / TAMPERED, naming the algorithm as the
  cause. Narrow on purpose: it fires only when the key PARSES and its OID disagrees with the
  declared name, so placeholder key material cannot be flipped to INVALID by it.
* `allowNegative` IS THREE-STATE IN BOTH LOADERS, and a NON-BOOLEAN IS A NAMED REFUSAL (items 1-2).
  `load_adversarial` still did `bool(v)`, so a JSON null became a floor of 0 on a live verdict path;
  and in BOTH loaders a non-boolean coerced silently while `floor_is_declared` still read True - the
  JSON string "false" deleted the account's floor outright. The refusal (not "undeclared") is taken
  from the Java: `allow_negative` is `BOOLEAN NOT NULL` (V1__create_ledger_core.sql:39) read into a
  primitive `boolean` (Account.java:48-49), so a non-boolean is a corrupt or rewritten snapshot, not
  a state the ledger can hold. The shipped CLI fails closed on it (exit 3, named cause).
* THE L2 DEBIT LEG HAS A FIXTURE (item 5): `adversarial/counters_debit_leg_only_drift.json`. Two
  postedDebits counters moved 1000 in opposite directions, so L1, L3 and the no-overdraft floor all
  stay silent and only the debit half of the counters-vs-replay comparison can catch it. The 2026-09-20
  survivor mutant M1d (delete that half) now dies on 3 tests; before, the whole suite stayed green.
* THE HONESTY-SWEEP ALLOWLIST NOW ENFORCES ITS EVIDENCE FIELD (item 7 / O4 - previously open). An
  entry of a CLEARING class with blank, missing or placeholder evidence no longer clears: it is
  reported UNCLASSIFIED with the reason and the run fails. HONEST LIMIT: this proves evidence was
  WRITTEN, not that it is true - the text is not machine-checked against the artifact it cites.
  (Public-repository note: the honesty-sweep tool, its allowlist and its tests scanned private
  project notes, so they are not part of this public repository.)
* THE SIGNATURE LEG COULD NOT GO RED ON THE DEFAULT COMMAND (live-ledger finding A1). Measured
  2026-09-22 on a real Docker LedgerMind and reproduced here at 996de69: with one byte of the
  signature flipped, `py -m tools.verify_report --corpus recorded --half clean` printed `verdict: OK`
  and exited 0 on a machine with a working OpenSSL 3.5.5. The backend is now AUTO-SELECTED when
  present, and when it genuinely is not the CLI exits 2 (INCOMPLETE), never 0. The verdict OBJECT is
  unchanged: UNVERIFIED-SIGNATURE still never gates, because "could not verify" is not tamper.
* `--corpus-root` VERIFIES A CORPUS OUTSIDE THE REPO (A2), so a live capture no longer needs a copy
  of the repository around it.
* `tools/record_fixtures.py` NOW DECLARES AT THE CALL SITE THAT `POST /api/demo/reset` TRUNCATES THE
  TARGET LEDGER (A3). It destroyed a live 8-posting ledger on 2026-09-22 and it is why the recorder
  can only ever capture the canned demo. `--dry-run` does NOT protect against it. Making it opt-in is
  a behaviour change and was RECOMMENDED, not applied.

Regression guards: `tests/test_open_list_close_2026_09_22.py` (47 tests, 33 RED at 996de69 before the
fixes, all GREEN after; the 7 that were already green at 996de69 are the paired must-not-fire controls).
Suite: 210 passed before this pass, 257 passed after, exit 0 both times, 0 skipped. No pre-existing test
was modified, skipped, deleted or weakened. Evidence and both-outcome runs are kept in
private project notes (not part of this repository). Open list item 8
(an end-to-end run against a live LedgerMind) was handled by a separate agent, not here.
This is builder evidence, not an independent verdict.
