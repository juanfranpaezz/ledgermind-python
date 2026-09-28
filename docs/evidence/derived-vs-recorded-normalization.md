# Derived-vs-recorded diff: the normalization rule and the expected diff classes

**Written 2026-09-14, BEFORE the recorder ran and BEFORE any comparison was executed.**
This file exists because of the correlated-derivation risk: three agents read the same Java and agree, so a
shared misreading is invisible to all three. The recorded capture is the ONLY model-free
leg available, and the predictable way to destroy it is to run the diff first, see a wall
of timestamp noise, and "just normalize it". So the rule and the expected classes are
frozen here first, and the comparator refuses to widen them.

## The ONE normalization rule

**`createdAt` PRECISION only.** The derived corpus fabricated whole-second timestamps
(`2026-09-13T17:00:01Z`); a real Postgres `TIMESTAMPTZ` carries microseconds and Java's
`Instant.toString()` renders 0, 3, 6 or 9 fractional digits depending on the value. The
comparator therefore compares `createdAt` for SHAPE (a valid ISO-8601 instant in UTC, and
strictly increasing across the five postings) and NEVER for equality.

Nothing else is normalized. In particular the comparator does NOT normalize away:
amounts, account ids, idempotency keys, assets, counters, verdict booleans, chain
`seq`/`prevHash` linkage, `chainedCount`, `brokenAtSeq`, reconciliation figures or
discrepancy sets.

## The expected diff classes, frozen before the run

| # | class | why it is expected | verdict if seen |
|---|-------|--------------------|-----------------|
| E1 | `createdAt` values differ | the derived corpus invented them | EXPECTED |
| E2 | every `entryHash` and every non-genesis `prevHash` differs | `createdAt` is part of the canonical string the chain signs, so a hash equality can NEVER hold across the two corpora | EXPECTED |
| E3 | `signedAt`, `publicKeyBase64`, `signature`, `signedHeadHash` differ | the demo key is ephemeral and the derived corpus carries named placeholders, never invented key material | EXPECTED |
| E4 | the audit `verdict` PROSE differs in its embedded timestamp and head hash | same two causes as E1/E3 | EXPECTED |
| E5 | reconciliation discrepancy ORDER differs | the Java iterates two HashMaps; order is not reproducible | EXPECTED (compare as a set) |
| X1 | any difference in an amount, a counter, an id, an idempotency key, an asset, a boolean, a count, `brokenAtSeq`, or the discrepancy SET | nothing in the mechanism explains it | **HALTS Phase 1 and goes to a fresh-context verifier** |

## The independent check this makes possible

Inside the RECORDED corpus alone, with no derived corpus involved:
recompute `SHA-256(prevHash + id|dr|cr|amount|asset|idempotencyKey|createdAt)` over the
rows captured from Postgres and compare against the `entry_hash` column the Java wrote.
That is model-free: if our reading of `JournalChainer.entryHash` (including the exact
`Instant.toString()` precision) is wrong, it fails, and no amount of agreement between
readers can hide it. The comparator reports this as `SELF_CHAIN` and it is the leg that
must never be normalized away.
