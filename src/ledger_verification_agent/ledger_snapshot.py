"""Loads a ledger snapshot out of a fixture corpus, and declares where each datum came from.

PHASE 1 SCOPE, stated precisely so nothing here overclaims. In Phase 1 **every byte
is read from a fixture file on local disk**; there is no HTTP client in this
repository yet. What this module additionally declares, per dataset, is the
phase-0 registry tool that WOULD serve that dataset in Phase 2
(``ledger_verification_agent.tool_registry``), so the read-only property is checked
now, mechanically, before any code that can actually talk to the ledger exists.

``DATASET_SOURCES`` is the load-bearing declaration and
``tests/test_verifier_read_only_reachability.py`` is what makes it more than a
comment: it asserts every named tool is on ``READ_ONLY_SURFACE``, that none is on
``MUTATING_ENDPOINTS``, and that no write-capable call is reachable from this
package at all.

ONE SOURCE HAS NO TOOL, AND THAT IS DISCLOSED RATHER THAN PAPERED OVER. The
``posting_hash`` rows (seq / prevHash / entryHash) are exposed by NO REST endpoint
and NO MCP tool - ``tests/fixtures/recorded/clean/postings_and_hashes.json`` records
this and so does the recorded corpus metadata. They were captured through a
PostgreSQL session pinned read-only by the server
(``PGOPTIONS=-c default_transaction_read_only=on``), which is a stronger guard than
a client-side allow-list, not a weaker one. The honest sentence is therefore: every
data source is read-only, and every source that has an HTTP surface is a read-only
tool from the phase-0 registry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .journal_chain import ChainLink, Posting

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures"
RECORDED_CORPUS = FIXTURE_ROOT / "recorded"
DERIVED_CORPUS = FIXTURE_ROOT / "derived_from_source"
ADVERSARIAL_DIR = DERIVED_CORPUS / "adversarial"

#: A read-only access mode that is NOT an HTTP tool. Named, not hidden.
DB_READ_ONLY = "db-select-read-only"


class MalformedSnapshotError(ValueError):
    """The corpus carries a value the LIVE ledger cannot represent, so no verdict is computed.

    A ``ValueError`` subclass on purpose: ``tools/verify_report.py`` already catches
    ``ValueError`` around the load and turns it into ``EXIT_TOOL_ERROR``, so the shipped CLI
    fails CLOSED with a named cause instead of printing a verdict.
    """


def _allow_negative_state(
    raw: Mapping[str, object] | dict,
    key: str,
    address: str,
    source: str,
) -> bool | None:
    """THREE states, and a fourth outcome that is a REFUSAL rather than a fourth state.

    * the key is absent, or its value is JSON ``null`` -> ``None`` = UNDECLARED. This is a
      real transport state: the derived corpus genuinely does not carry the column for some
      addresses, and guessing ``False`` invents a floor of 0 on a legally-negative account.
    * a JSON boolean -> that boolean.
    * ANYTHING ELSE -> ``MalformedSnapshotError``, by name, naming the address and the type.

    WHY A REFUSAL AND NOT "UNDECLARED" (the judgment call, taken from the Java, not from
    convenience). In the live system the field is ``allow_negative BOOLEAN NOT NULL DEFAULT
    FALSE`` (V1__create_ledger_core.sql:39), read into a PRIMITIVE ``boolean``
    (Account.java:48-49, ``updatable = false``), and used verbatim inside the DB's own
    no-overdraft CHECK (V1__create_ledger_core.sql:57-59). There is NO representable
    non-boolean value: a string, a number, a list or an object cannot come out of that column
    through any capture path. So a non-boolean does not mean "the corpus is silent about the
    floor" - it means the snapshot is corrupt or was rewritten, which is exactly the event
    this verifier exists to detect. Mapping it to UNDECLARED would let an attacker DOWNGRADE
    the no-overdraft leg to a soft "no data" note by changing a type; mapping it to a boolean
    (the old ``bool(v)``) let the JSON string ``"false"`` delete the account's floor outright
    while the loader still reported ``floor_is_declared=True``. Only a hard refusal cannot be
    used to disarm the checker quietly.
    """
    if key not in raw:
        return None
    value = raw[key]
    if value is None:
        return None
    # bool BEFORE int: in Python ``isinstance(True, int)`` is True, so the order is load-bearing.
    if isinstance(value, bool):
        return value
    raise MalformedSnapshotError(
        "REFUSED: account " + repr(address) + " declares " + key + " as a "
        + type(value).__name__ + " (" + repr(value) + "), and the ledger cannot represent "
        "that: allow_negative is BOOLEAN NOT NULL (V1__create_ledger_core.sql:39) read into a "
        "primitive boolean (Account.java:48-49). A non-boolean is a corrupt or rewritten "
        "snapshot, not a ledger state - coercing it would silently arm or disarm the "
        "no-overdraft floor. Source: " + source
    )


@dataclass(frozen=True)
class DatasetSource:
    """Where one dataset comes from, and what would serve it over the wire."""

    dataset: str
    tool: str | None          # a ToolSpec.name from the phase-0 registry, or None
    access: str               # "http-read" | DB_READ_ONLY
    justification: str


#: Every dataset the deterministic verifier consumes. The read-only test reads THIS.
DATASET_SOURCES: tuple[DatasetSource, ...] = (
    DatasetSource(
        dataset="accounts",
        tool="get_balance",
        access="http-read",
        justification="GET /api/accounts/{address} - LedgerController.getAccount, read-only by method.",
    ),
    DatasetSource(
        dataset="postings",
        tool="list_transactions",
        access="http-read",
        justification=(
            "LedgerMcpTools.listTransactions over MCP, @PreAuthorize SCOPE_ledger.read. "
            "POST /mcp is a JSON-RPC transport, not a mutation; it is on READ_ONLY_SURFACE."
        ),
    ),
    DatasetSource(
        dataset="journal_verify",
        tool="verify_journal",
        access="http-read",
        justification="GET /api/journal/audit - LedgerController.auditJournal, read-only by method.",
    ),
    DatasetSource(
        dataset="journal_checkpoint",
        tool="verify_journal",
        access="http-read",
        justification=(
            "GET /api/journal/checkpoint and /checkpoint/verify are on READ_ONLY_SURFACE; the "
            "consolidated audit tool already carries the same checkpoint fields."
        ),
    ),
    DatasetSource(
        dataset="posting_hashes",
        tool=None,
        access=DB_READ_ONLY,
        justification=(
            "posting_hash rows have NO REST and NO MCP surface (recorded corpus _note). Captured "
            "through psql with PGOPTIONS=-c default_transaction_read_only=on, i.e. read-only "
            "enforced by PostgreSQL itself, which is stronger than a client-side allow-list."
        ),
    ),
)


@dataclass(frozen=True)
class AccountRow:
    """One account. ``balance`` is DERIVED from counters, never stored (Account.java:83-86)."""

    address: str
    asset: str
    posted_debits: int
    posted_credits: int
    pending_debits: int
    #: THREE states, not two. ``True`` = no floor (``external:funding`` legally sits at
    #: -158000). ``False`` = the floor is 0. ``None`` = the corpus does not say, and
    #: guessing ``False`` would flag a legally-negative account - exactly the
    #: over-firing that ``clean_must_not_fire.json`` exists to forbid. An undeclared
    #: floor is reported by name and never silently assumed either way.
    allow_negative: bool | None
    #: The ledger's numeric account id. Postings reference accounts by id, so without
    #: it the posting-replay legs cannot map an entry onto an account and say so
    #: instead of guessing. Absent in the derived adversarial fixtures by design.
    account_id: int | None = None
    #: What the ledger's own AccountView reported, when the corpus carries it. Used as a
    #: cross-check, never as the source of truth for the invariants.
    reported_balance: int | None = None
    #: True when pendingDebits was NOT in the corpus and was assumed 0. Recorded so a
    #: degraded computation can never pass as a full one.
    pending_debits_assumed: bool = False

    @property
    def available_balance(self) -> int:
        """``Account.availableBalance()`` - postedCredits - postedDebits - pendingDebits."""
        return self.posted_credits - self.posted_debits - self.pending_debits

    @property
    def floor_is_declared(self) -> bool:
        return self.allow_negative is not None

    @property
    def has_floor(self) -> bool:
        """True only when the corpus SAYS the account may not go negative."""
        return self.allow_negative is False

    @property
    def floor_description(self) -> str:
        if self.allow_negative is None:
            return "unknown (allowNegative is not declared in this corpus)"
        return "none (allowNegative)" if self.allow_negative else "0"


@dataclass(frozen=True)
class Checkpoint:
    """The signed tree head. Field names mirror JournalCheckpoint / the REST payload."""

    chain_seq: int
    head_hash: str
    algorithm: str
    signed_message: str
    public_key_base64: str
    signature_base64: str
    signed_at: str


@dataclass(frozen=True)
class LedgerSnapshot:
    """Everything one verification pass reads. Immutable; the verifier never writes."""

    subject: str
    postings: tuple[Posting, ...] = ()
    links: tuple[ChainLink, ...] = ()
    accounts: tuple[AccountRow, ...] = ()
    checkpoint: Checkpoint | None = None
    #: LedgerMind's OWN /api/journal/verify answer, kept for the cross-oracle leg.
    #: NEVER used as the verifier's own result - that would make the checker a mirror.
    reported_verify: Mapping[str, object] | None = None
    sources: Mapping[str, str] = field(default_factory=dict)

    @property
    def postings_by_id(self) -> dict[int, Posting]:
        return {posting.id: posting for posting in self.postings}

    def source_of(self, dataset: str) -> str:
        return self.sources.get(dataset, self.subject)

    def account(self, address: str) -> AccountRow | None:
        for row in self.accounts:
            if row.address == address:
                return row
        return None


def _whole_minor_units(value: object) -> int:
    """A ledger amount is a whole number of minor units. ``int()`` alone TRUNCATED ``100000.9`` to
    ``100000`` and the snapshot then verified as if nothing were wrong (parity gate r1, 2026-09-27).
    A fractional or non-finite number is refused with ValueError, which the CLI reports as a tool
    error (exit 3). ``100000.0`` is the same number as ``100000`` and is accepted."""
    if isinstance(value, float) and not value.is_integer():
        raise ValueError("a ledger amount must be a whole number of minor units, got " + repr(value))
    return int(value)


def _posting_from(raw: Mapping[str, object]) -> Posting:
    return Posting(
        id=int(raw["id"]),
        debit_account_id=int(raw["debitAccountId"]),
        credit_account_id=int(raw["creditAccountId"]),
        amount=_whole_minor_units(raw["amount"]),
        asset=str(raw["asset"]),
        idempotency_key=str(raw["idempotencyKey"]),
        created_at=str(raw["createdAt"]),
        credit_amount=None if raw.get("creditAmount") is None else _whole_minor_units(raw["creditAmount"]),
    )


def _link_from(raw: Mapping[str, object]) -> ChainLink:
    return ChainLink(
        posting_id=int(raw["postingId"]),
        seq=int(raw["seq"]),
        prev_hash=str(raw["prevHash"]),
        entry_hash=str(raw["entryHash"]),
    )


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_recorded(half: str, root: Path | None = None) -> LedgerSnapshot:
    """The RECORDED corpus (captured from a running LedgerMind). ``half`` is clean|tampered."""
    if half not in ("clean", "tampered"):
        raise ValueError("half must be 'clean' or 'tampered', got: " + repr(half))
    base = (root or RECORDED_CORPUS) / half
    bundle = _read_json(base / "postings_and_hashes.json")

    postings = tuple(_posting_from(item) for item in bundle.get("postings", []))
    links = tuple(_link_from(item) for item in bundle.get("postingHashes", []))

    account_views: dict[str, int] = {}
    for view_path in sorted(base.glob("account_*.json")):
        view = _read_json(view_path)
        account_views[str(view["address"])] = int(view["balance"])

    accounts = tuple(
        AccountRow(
            address=str(row["address"]),
            asset=str(row["asset"]),
            posted_debits=int(row["postedDebits"]),
            posted_credits=int(row["postedCredits"]),
            pending_debits=int(row.get("pendingDebits", 0)),
            # THREE-STATE, never guessed (open-list finding O2, 2026-09-17): a JSON null or a
            # missing key is "undeclared" (None), not a floor of 0. bool(None) was the guess.
            # A NON-BOOLEAN is refused by name (open list 2026-09-20, item 2): bool("false")
            # was True, which deleted the account's floor while still reporting it declared.
            allow_negative=_allow_negative_state(
                row,
                "allowNegative",
                str(row["address"]),
                "recorded/" + half + "/postings_and_hashes.json",
            ),
            reported_balance=account_views.get(str(row["address"])),
            pending_debits_assumed="pendingDebits" not in row,
            account_id=None if row.get("id") is None else int(row["id"]),
        )
        for row in bundle.get("accounts", [])
    )

    checkpoint = None
    checkpoint_path = base / "journal_checkpoint.json"
    if checkpoint_path.exists():
        raw = _read_json(checkpoint_path)
        checkpoint = Checkpoint(
            chain_seq=int(raw["chainSeq"]),
            head_hash=str(raw["headHash"]),
            algorithm=str(raw["algorithm"]),
            signed_message=str(raw["signedMessage"]),
            public_key_base64=str(raw["publicKeyBase64"]),
            signature_base64=str(raw["signature"]),
            signed_at=str(raw["signedAt"]),
        )

    reported_verify = None
    verify_path = base / "journal_verify.json"
    if verify_path.exists():
        reported_verify = _read_json(verify_path)

    prefix = "recorded/" + half + "/"
    return LedgerSnapshot(
        subject="recorded:" + half,
        postings=postings,
        links=links,
        accounts=accounts,
        checkpoint=checkpoint,
        reported_verify=reported_verify,
        sources={
            "postings": prefix + "postings_and_hashes.json",
            "posting_hashes": prefix + "postings_and_hashes.json",
            "accounts": prefix + "postings_and_hashes.json",
            "journal_checkpoint": prefix + "journal_checkpoint.json",
            "journal_verify": prefix + "journal_verify.json",
        },
    )


def load_adversarial(case: str, root: Path | None = None) -> LedgerSnapshot:
    """One planted-defect fixture from ``derived_from_source/adversarial``.

    These carry whichever datasets the case is about. A dataset the file does not
    carry stays EMPTY, and the checks report ``NO_DATA`` for it rather than green.
    """
    path = (root or ADVERSARIAL_DIR) / (case + ".json")
    raw = _read_json(path)
    rel = "derived_from_source/adversarial/" + path.name

    postings = tuple(_posting_from(item) for item in raw.get("postings", []))
    links = tuple(_link_from(item) for item in raw.get("postingHashes", []))

    # SAME three-state rule as load_recorded, and the same named refusal. Until 2026-09-22 this
    # line was a bare ``bool(v)``: a JSON null became False here, i.e. an INVENTED floor of 0 on
    # `py -m tools.verify_report --corpus adversarial --case X`, which is a live verdict path.
    declared = raw.get("allow_negative_by_address", {})
    allow_negative = {
        str(k): _allow_negative_state(declared, k, str(k), rel) for k in declared
    }
    account_ids = {str(k): int(v) for k, v in raw.get("account_id_by_address", {}).items()}
    accounts: list[AccountRow] = []
    for address, row in raw.get("accounts", {}).items():
        accounts.append(
            AccountRow(
                address=str(row.get("address", address)),
                asset=str(row.get("asset", "")),
                posted_debits=int(row["postedDebits"]),
                posted_credits=int(row["postedCredits"]),
                pending_debits=int(row.get("pendingDebits", 0)),
                allow_negative=allow_negative.get(str(address)),
                reported_balance=None if row.get("balance") is None else int(row["balance"]),
                pending_debits_assumed="pendingDebits" not in row,
                account_id=account_ids.get(str(address), row.get("id")),
            )
        )

    return LedgerSnapshot(
        subject="adversarial:" + case,
        postings=postings,
        links=links,
        accounts=tuple(accounts),
        checkpoint=None,
        reported_verify=None,
        sources={
            "postings": rel,
            "posting_hashes": rel,
            "accounts": rel,
        },
    )
