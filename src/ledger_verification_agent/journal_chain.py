"""The SHA-256 journal hash chain, re-implemented in Python from the Java source.

RE-DERIVED FROM PRIMARY SOURCE, not from any other Python file in this repo. Read
2026-09-17 (read-only) from
``<ledgermind-checkout>/src/main/java/com/ledgermind/ledger/JournalChainer.java``
at commit 872505f:

* ``JournalChainer:27``   ``GENESIS = "0".repeat(64)``
* ``JournalChainer:93-98``::

      static String entryHash(String prevHash, Posting p) {
          String canonical = p.getId() + "|" + p.getDebitAccountId() + "|" + p.getCreditAccountId()
                  + "|" + p.getAmount() + "|" + p.getAsset() + "|" + p.getIdempotencyKey()
                  + "|" + p.getCreatedAt();
          return sha256Hex(prevHash + canonical);
      }

* ``JournalChainer:62-91`` ``verify()``: walk ``posting_hash`` by ascending ``seq``;
  a missing posting row, a ``prevHash`` that does not equal the running hash, or a
  recomputed ``entryHash`` that does not equal the stored one all return
  ``(intact=false, chainedCount=<links verified BEFORE the break>, brokenAtSeq=<this seq>)``.

``createdAt`` is a ``java.time.Instant`` concatenated into a String, i.e.
``Instant.toString()`` / ISO-8601 with 0, 3, 6 or 9 fractional digits. The fixtures
store that rendering verbatim, so this module hashes the stored string as-is and
never re-formats it. Re-formatting it is the one mistake that silently breaks every
hash (see ``tests/fixtures/*/\\_corpus.json`` ``known_shape_gaps``).

THIS MODULE IS PURE. No I/O, no network, no clock, no randomness.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping, Sequence

GENESIS = "0" * 64

#: The Java symbol this module re-implements, carried so a reader can re-derive it.
UPSTREAM = "com.ledgermind.ledger.JournalChainer @ 872505f"


@dataclass(frozen=True)
class Posting:
    """One journal entry, exactly the seven fields the canonical string signs."""

    id: int
    debit_account_id: int
    credit_account_id: int
    amount: int
    asset: str
    idempotency_key: str
    created_at: str
    #: Present ONLY on hand-built / corrupted-feed inputs. LedgerMind's schema has a
    #: single amount column serving both legs, so a differing credit leg cannot be
    #: represented by the ledger - which is exactly why the checker must not assume it.
    credit_amount: int | None = None

    @property
    def debit_leg(self) -> int:
        return self.amount

    @property
    def credit_leg(self) -> int:
        return self.amount if self.credit_amount is None else self.credit_amount


@dataclass(frozen=True)
class ChainLink:
    """One row of ``posting_hash``."""

    posting_id: int
    seq: int
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class ChainResult:
    """The same three fields ``JournalChainer.VerifyResult`` carries, plus a reason."""

    intact: bool
    chained_count: int
    broken_at_seq: int | None
    broken_reason: str | None = None
    broken_detail: str = ""


def canonical_string(posting: Posting) -> str:
    """``JournalChainer:94-96``, field order and separator included."""
    return (
        str(posting.id)
        + "|"
        + str(posting.debit_account_id)
        + "|"
        + str(posting.credit_account_id)
        + "|"
        + str(posting.amount)
        + "|"
        + posting.asset
        + "|"
        + posting.idempotency_key
        + "|"
        + posting.created_at
    )


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def entry_hash(prev_hash: str, posting: Posting) -> str:
    """``JournalChainer:93-98``: ``sha256Hex(prevHash + canonical(posting))``."""
    return sha256_hex(prev_hash + canonical_string(posting))


def verify_chain(postings: Mapping[int, Posting], links: Sequence[ChainLink]) -> ChainResult:
    """``JournalChainer.verify()`` re-implemented. Stops at the FIRST break, as Java does.

    ``chained_count`` counts the links verified BEFORE the break, which is what the
    Java returns and what the ledger's own ``/api/journal/verify`` reports.
    """
    prev = GENESIS
    checked = 0
    for link in sorted(links, key=lambda item: item.seq):
        posting = postings.get(link.posting_id)
        if posting is None:
            return ChainResult(
                False,
                checked,
                link.seq,
                "posting_row_absent",
                "chain link seq=" + str(link.seq) + " points at posting id="
                + str(link.posting_id) + ", which is not in the journal",
            )
        if prev != link.prev_hash:
            return ChainResult(
                False,
                checked,
                link.seq,
                "prev_hash_mismatch",
                "link seq=" + str(link.seq) + " declares prevHash=" + link.prev_hash
                + " but the running chain head is " + prev,
            )
        recomputed = entry_hash(prev, posting)
        if recomputed != link.entry_hash:
            return ChainResult(
                False,
                checked,
                link.seq,
                "entry_hash_mismatch",
                "link seq=" + str(link.seq) + " stores entryHash=" + link.entry_hash
                + " but posting id=" + str(posting.id) + " as it stands now hashes to "
                + recomputed,
            )
        prev = link.entry_hash
        checked += 1
    return ChainResult(True, checked, None, None, "")


def head_hash(links: Sequence[ChainLink]) -> str:
    """The stored entry hash of the highest seq, or GENESIS on an empty chain."""
    if not links:
        return GENESIS
    return max(links, key=lambda item: item.seq).entry_hash


def link_at_seq(links: Sequence[ChainLink], seq: int) -> ChainLink | None:
    for link in links:
        if link.seq == seq:
            return link
    return None
