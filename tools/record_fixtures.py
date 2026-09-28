"""AC-0.2's RECORDER: capture the fixture corpus from a RUNNING LedgerMind.

Why this exists at all
----------------------
Manifest section 2.6: the tampered half of the corpus must come from a real
``POST /api/demo/tamper`` against a running stack, NOT from a hand-built file, because
"a hand-edited fixture proves the test, not the instrument". ``tools/derive_fixtures.py``
computes a corpus from the Java source; it is an expected-value oracle and it is marked
``ac_0_2_eligible: false`` on purpose. THIS tool produces the eligible one.

Three things the naive loop gets wrong, each handled here and each anchored to the Java
line that implies it (Phase 0 design decisions, sections 3 and 7):

1. **A GLOBAL rate limit of 30 requests / 10 000 ms** over ``/api/demo/**`` AND
   ``/api/journal/**`` (``web/RateLimitFilter.java:20-21,30``). Over the limit the filter
   answers 429 with a bare ``{"detail": ...}`` body that is NOT an RFC 7807 ProblemDetail,
   so a recorder that saves bodies blindly writes a corrupt fixture that still has the
   right file count. This recorder paces itself below the limit, checks the STATUS of
   every response before saving anything, and backs off a full window on a 429 and
   retries. A non-200 can never reach the corpus: the capture raises instead of writing.

2. **Chaining is ASYNCHRONOUS** (``JournalChainer.java:39``, every 5 s;
   ``JournalCheckpointService.java:44``, every 10 s). A read taken straight after a write
   can capture a half-built chain. Before writing the clean half, this recorder asserts
   ``chainedCount == len(postings)`` and re-reads until it holds or the timeout expires.
   A half-built chain recorded as ground truth is worse than no corpus, because every
   later comparison inherits it silently.

3. **``posting_hash`` rows and ``idempotencyKey`` are on NO HTTP surface.** No REST
   endpoint and no MCP tool exposes them, and ``TransactionInfo``
   (``LedgerMcpTools.java:87-88``) omits ``idempotencyKey``, which is a REQUIRED field of
   the canonical string ``JournalChainer.entryHash`` signs. So an HTTP-only recorder can
   capture the ledger's VERDICT on its own chain but never the material to RECOMPUTE it.
   Per the DB-level capture decision the recorder therefore also takes a **read-only SELECT**
   against the demo Postgres. The read-only-ness is enforced by the SERVER, not by good
   intentions: the session runs under ``PGOPTIONS=-c default_transaction_read_only=on``,
   so any INSERT/UPDATE/DELETE/DDL is refused by PostgreSQL itself. A client-side prefix
   check is layered on top, and it is declared here as the WEAKER of the two.

   The tamper is performed through the app's own ``/api/demo/tamper`` endpoint, exactly as
   a user would, and NEVER by touching the database directly.

The ``createdAt`` precision, which is load-bearing
--------------------------------------------------
``JournalChainer.entryHash`` concatenates ``p.getCreatedAt()``, i.e. ``Instant.toString()``,
which emits 0, 3, 6 or 9 fractional digits depending on the value - never a fixed width.
Postgres ``TIMESTAMPTZ`` holds microseconds. ``java_instant_string`` below reproduces that
rendering exactly; get it wrong and every recomputed hash is wrong for a reason that looks
like a server bug.

Usage::

    py -m tools.record_fixtures --out <dir>           # READ-ONLY: capture the ledger as found
    py -m tools.record_fixtures --dry-run             # probe the stack, write nothing
    py -m tools.record_fixtures --destructive-reset-and-tamper
                                                      # TRUNCATEs the target ledger, re-seeds the
                                                      # canned demo, tampers it, writes both halves

DEFAULT BEHAVIOUR CHANGED 2026-09-22, on the owner's explicit authorisation. Until that date
this tool ALWAYS opened with ``POST /api/demo/reset``, which TRUNCATEs the ledger; it silently
destroyed a live 8-posting ledger during the first end-to-end run, and it is why a "recorded"
corpus could only ever contain the canned 5-transfer demo and never real traffic. The two
mutating calls (``/api/demo/reset`` and ``/api/demo/tamper``) are now BOTH behind
``--destructive-reset-and-tamper``, default OFF. The default run mutates nothing and captures
whatever is on the ledger, which is what makes real activity recordable at all; it produces a
CLEAN half only, marks the corpus ``ac_0_2_eligible: false``, and refuses to write into the
shipped corpus directory so a half capture can never replace the two-half ground truth.

THE WRITE REFUSAL COVERS THE WHOLE FIXTURE TREE (widened 2026-09-22, residual A3). It is not
keyed to ``tests/fixtures/recorded`` any more: NO run writes anywhere under
``tests/fixtures/`` - not into ``derived_from_source``, not into a fresh subdirectory - with
exactly one exception, ``--destructive-reset-and-tamper`` with the default ``--out``, which
is the documented way the canned two-half corpus is regenerated. The refusal is raised before
any HTTP call, so a mis-invocation cannot touch the ledger either.

Exit 0 means a corpus was written and every pre-write assertion held.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDED_ROOT = REPO_ROOT / "tests" / "fixtures" / "recorded"
# EVERY shipped fixture, not just the recorded corpus. The write refusal below used to be
# keyed to RECORDED_ROOT alone, so `--out <repo>/tests/fixtures/derived_from_source` would
# have dropped a captured half INSIDE the shipped derived corpus (2026-09-22 adversarial
# verification, residual A3). A capture is live data from whatever BASE_URL points at; a
# fixture is ground truth that tests assert against. Live data must never land on top of
# ground truth, in ANY subdirectory of it.
FIXTURES_ROOT = REPO_ROOT / "tests" / "fixtures"

BASE_URL = "http://localhost:8080"
# The LedgerMind checkout: $LEDGERMIND_REPO, else a sibling directory named ledgermind.
LEDGERMIND_REPO = os.environ.get("LEDGERMIND_REPO", str(REPO_ROOT.parent / "ledgermind"))
LEDGERMIND_UPSTREAM = "github.com/juanfranpaezz/ledgermind"
COMPOSE_FILE = "docker-compose.observability.yml"
PG_SERVICE = "postgres"
PG_USER = "ledgermind"
PG_DB = "ledgermind"

# RateLimitFilter.java:20-21 -> 30 requests per 10 000 ms, GLOBAL (not per client).
RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW_S = 10.0
# Stay well under it: the limiter is a global counter and anything else touching the demo
# spends from the same budget.
SAFE_REQUESTS_PER_WINDOW = 18
MIN_SECONDS_BETWEEN_REQUESTS = RATE_LIMIT_WINDOW_S / SAFE_REQUESTS_PER_WINDOW
BACKOFF_ON_429_S = 11.0
MAX_429_RETRIES = 3

CHAIN_COMPLETE_TIMEOUT_S = 90.0
CHAIN_POLL_INTERVAL_S = 3.0

GENESIS = "0" * 64


class RecorderError(RuntimeError):
    """Raised instead of writing. Never downgraded to a warning."""


class WriteSiteSwapError(RecorderError):
    """A name the write site is about to rename no longer names what this process created and
    checked: the directory was renamed or replaced by a junction, or the temp name now points at
    another file (a hardlink). Raised by ``_refuse_if_swapped``; nothing is renamed into place."""


# --------------------------------------------------------------------------------------
# createdAt rendering - Instant.toString(), reproduced
# --------------------------------------------------------------------------------------
def java_instant_string(micro_text):
    """Render a Postgres ``YYYY-MM-DDTHH:MM:SS.US`` UTC value the way Java prints it.

    ``Instant.toString()`` (ISO_INSTANT) emits NO fractional part when the nanosecond
    field is zero, 3 digits when it is a whole millisecond, 6 when it is a whole
    microsecond, and 9 otherwise. Postgres carries microseconds, so the 9-digit branch is
    unreachable from this data source, but the rule - not the data - is what is being
    reproduced, so the branch stays.
    """
    if "." in micro_text:
        base, frac = micro_text.split(".", 1)
    else:
        base, frac = micro_text, "0"
    micros = int((frac + "000000")[:6])
    nanos = micros * 1000
    if nanos == 0:
        return base + "Z"
    if nanos % 1000000 == 0:
        return base + "." + "{:03d}".format(nanos // 1000000) + "Z"
    if nanos % 1000 == 0:
        return base + "." + "{:06d}".format(nanos // 1000) + "Z"
    return base + "." + "{:09d}".format(nanos) + "Z"


# --------------------------------------------------------------------------------------
# HTTP, rate-limit aware
# --------------------------------------------------------------------------------------
class RateLimitedClient:
    """Paces itself under the global limiter, and never hands back a non-200 as data."""

    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self._last_request_at = 0.0
        self.http_log = []
        self.retries_after_429 = 0

    def _pace(self):
        gap = time.monotonic() - self._last_request_at
        if gap < MIN_SECONDS_BETWEEN_REQUESTS:
            time.sleep(MIN_SECONDS_BETWEEN_REQUESTS - gap)

    def request(self, method, path, body=None):
        """Return (status, parsed_json_or_text). Retries a 429 after a full window."""
        url = self.base_url + path
        attempt = 0
        while True:
            attempt += 1
            self._pace()
            data = None
            headers = {"Accept": "application/json"}
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    status = resp.status
                    raw = resp.read().decode("utf-8")
            except urllib.error.HTTPError as exc:
                status = exc.code
                raw = exc.read().decode("utf-8", errors="replace")
            except urllib.error.URLError as exc:
                status = 0
                raw = "URLError: " + str(exc.reason)
            self._last_request_at = time.monotonic()

            self.http_log.append(
                {"method": method, "path": path, "status": status, "attempt": attempt}
            )

            if status == 429 and attempt <= MAX_429_RETRIES:
                # RateLimitFilter's body is a bare {"detail": ...}, NOT a ProblemDetail.
                # Check the STATUS, never the body shape.
                self.retries_after_429 += 1
                time.sleep(BACKOFF_ON_429_S)
                continue

            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {"_raw": raw}
            return status, payload

    def get_json(self, path):
        status, payload = self.request("GET", path)
        if status != 200:
            raise RecorderError(
                "GET " + path + " returned " + str(status) + ", not 200: " + json.dumps(payload)[:300]
            )
        return payload

    def post_json(self, path, body=None):
        status, payload = self.request("POST", path, body=body)
        if status != 200:
            raise RecorderError(
                "POST " + path + " returned " + str(status) + ", not 200: " + json.dumps(payload)[:300]
            )
        return payload


# --------------------------------------------------------------------------------------
# Read-only Postgres capture
# --------------------------------------------------------------------------------------
_SELECT_ONLY = re.compile(r"^\s*SELECT\b", re.IGNORECASE)

READ_ONLY_PGOPTIONS = "PGOPTIONS=-c default_transaction_read_only=on"


def _psql_cmd(sql):
    return [
        "docker", "compose", "-f", COMPOSE_FILE, "exec", "-T",
        "-e", READ_ONLY_PGOPTIONS,
        PG_SERVICE,
        "psql", "-U", PG_USER, "-d", PG_DB,
        "-v", "ON_ERROR_STOP=1", "-A", "-t", "-F", "|", "-c", sql,
    ]


def db_select(sql, timeout=90):
    """Run ONE read-only SELECT inside the postgres container and return parsed rows.

    Two independent guards, and the weaker one is named as such:
      * SERVER-SIDE (the real one): ``default_transaction_read_only=on``. PostgreSQL
        itself refuses any INSERT/UPDATE/DELETE/DDL in that session, so a bug in this
        file cannot turn into a write.
      * CLIENT-SIDE (the weaker one): the statement must start with SELECT. This catches
        a typo early; it is NOT what makes the capture safe.
    """
    if not _SELECT_ONLY.match(sql):
        raise RecorderError("refused: only SELECT statements may be sent to the demo database")
    proc = subprocess.run(
        _psql_cmd(sql), cwd=LEDGERMIND_REPO, capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        raise RecorderError("psql failed (" + str(proc.returncode) + "): " + (proc.stderr or "")[:500])
    rows = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        rows.append(line.split("|"))
    return rows


POSTINGS_SQL = (
    "SELECT p.id, p.debit_account_id, p.credit_account_id, p.amount, p.asset, "
    "p.idempotency_key, to_char(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') "
    "FROM posting p ORDER BY p.id"
)
POSTING_HASH_SQL = (
    "SELECT h.posting_id, h.seq, h.prev_hash, h.entry_hash FROM posting_hash h ORDER BY h.seq"
)
ACCOUNTS_SQL = (
    "SELECT a.id, a.address, a.asset, a.posted_debits, a.posted_credits, a.pending_debits, "
    "a.pending_credits, a.allow_negative, a.version FROM account a ORDER BY a.id"
)


def capture_db():
    """The three read-only SELECTs. Returns (postings, posting_hashes, accounts)."""
    postings = []
    for r in db_select(POSTINGS_SQL):
        postings.append({
            "id": int(r[0]),
            "debitAccountId": int(r[1]),
            "creditAccountId": int(r[2]),
            "amount": int(r[3]),
            "asset": r[4],
            "idempotencyKey": r[5],
            "createdAt": java_instant_string(r[6]),
        })
    hashes = []
    for r in db_select(POSTING_HASH_SQL):
        hashes.append({
            "postingId": int(r[0]),
            "seq": int(r[1]),
            "prevHash": r[2],
            "entryHash": r[3],
        })
    accounts = []
    for r in db_select(ACCOUNTS_SQL):
        accounts.append({
            "id": int(r[0]),
            "address": r[1],
            "asset": r[2],
            "postedDebits": int(r[3]),
            "postedCredits": int(r[4]),
            "pendingDebits": int(r[5]),
            "pendingCredits": int(r[6]),
            "allowNegative": r[7] == "t",
            "version": int(r[8]),
        })
    return postings, hashes, accounts


# --------------------------------------------------------------------------------------
# The pre-write assertions
# --------------------------------------------------------------------------------------
def wait_for_chain_complete(client):
    """Block until ``chainedCount == len(postings)``. Never record a half-built chain."""
    deadline = time.monotonic() + CHAIN_COMPLETE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        postings, hashes, _ = capture_db()
        verify = client.get_json("/api/journal/verify")
        last = {
            "postings": len(postings),
            "posting_hash_rows": len(hashes),
            "chainedCount": verify.get("chainedCount"),
            "intact": verify.get("intact"),
        }
        if (
            len(postings) > 0
            and len(hashes) == len(postings)
            and verify.get("chainedCount") == len(postings)
            and verify.get("intact") is True
        ):
            return True, last
        time.sleep(CHAIN_POLL_INTERVAL_S)
    return False, last


def wait_for_stable_verify(client, required_identical_reads=2):
    """For the TAMPERED half: the chain is broken by design, so completeness cannot hold.

    What must hold instead is that the async chainer has stopped changing the answer: two
    consecutive identical ``/api/journal/verify`` responses, a full chain cycle apart.
    """
    previous = None
    identical = 1
    deadline = time.monotonic() + CHAIN_COMPLETE_TIMEOUT_S
    while time.monotonic() < deadline:
        current = client.get_json("/api/journal/verify")
        if previous is not None and current == previous:
            identical += 1
            if identical >= required_identical_reads:
                return True, current
        else:
            identical = 1
        previous = current
        time.sleep(6.0)  # a full 5 s chain cycle plus slack
    return False, previous


# --------------------------------------------------------------------------------------
# Capture one half
# --------------------------------------------------------------------------------------
HTTP_READS = [
    ("account_external_funding.json", "/api/accounts/external:funding"),
    ("account_wallet_ana.json", "/api/accounts/wallet:ana"),
    ("account_wallet_beto.json", "/api/accounts/wallet:beto"),
    ("journal_verify.json", "/api/journal/verify"),
    ("journal_audit.json", "/api/journal/audit"),
    ("journal_checkpoint.json", "/api/journal/checkpoint"),
    ("journal_checkpoint_verify.json", "/api/journal/checkpoint/verify"),
]


def capture_half(client, half, out_root, write):
    """Read everything for one half of the corpus. Returns (files, statuses)."""
    files = {}
    statuses = {}
    for name, path in HTTP_READS:
        status, payload = client.request("GET", path)
        statuses[name] = status
        if status != 200:
            raise RecorderError(
                "REFUSING TO WRITE: GET " + path + " returned " + str(status)
                + " (body " + json.dumps(payload)[:200] + "). A non-200 body must never reach "
                "the corpus - RateLimitFilter's 429 carries a bare {\"detail\":...} that would "
                "sit in the fixture looking like data."
            )
        files[name] = payload

    status, payload = client.request("POST", "/api/demo/reconcile")
    statuses["reconciliation.json"] = status
    if status != 200:
        raise RecorderError("REFUSING TO WRITE: POST /api/demo/reconcile returned " + str(status))
    files["reconciliation.json"] = payload

    postings, hashes, accounts = capture_db()
    files["postings_and_hashes.json"] = {
        "postings": postings,
        "postingHashes": hashes,
        "accounts": accounts,
        "_note": (
            "DB-LEVEL capture through a READ-ONLY psql session "
            "(default_transaction_read_only=on). No REST endpoint and no MCP tool exposes "
            "posting_hash rows, and TransactionInfo omits idempotencyKey, so an independent "
            "recomputation of the chain is impossible over any wire surface. createdAt is "
            "rendered the way Instant.toString() renders it (0/3/6/9 fractional digits), "
            "because it is part of the canonical string entryHash signs."
        ),
    }
    statuses["postings_and_hashes.json"] = "db-select-read-only"

    if write:
        half_dir = out_root / half
        for name, payload in files.items():
            _write_text_where_approved(
                half_dir / name, json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
            )
    return files, statuses


# A resolved Windows path is accepted only on a LOCAL DRIVE LETTER: "C:" or its
# extended-length form "\\?\C:". Everything else - "\\server\share", "\\?\UNC\...",
# "\\.\..." - is refused outright, never rewritten into something comparable.
_LOCAL_DRIVE = re.compile(r"(?:\\\\\?\\)?[A-Za-z]:")


def _canonical(path: Path, *, strict: bool = False) -> Path:
    """Resolve ``path`` THROUGH THE FILESYSTEM, and refuse anything not provably local.

    The 2026-09-22 version rewrote prefixes as strings and then compared strings. That was
    decorative for the whole share family: measured 2026-09-24 on this machine, 13 of 31
    spellings that ``os.path.samefile`` says ARE the fixture root passed the guard -
    ``\\\\localhost\\C$\\...``, ``\\\\127.0.0.1\\C$\\...``, the machine's own hostname, the
    IPv6 loopback literal, ``\\\\?\\UNC\\...``, ``\\\\.\\UNC\\...``, ``\\\\?\\Volume{guid}\\...``
    and ``\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeN\\...`` - and a write through each landed at
    the plain path. No string rule can enumerate every name the OS has for one directory.

    So the location is asked of the OS: ``os.path.realpath`` opens the deepest existing
    component and reads its final path back (junctions, symlinks, 8.3 names, case, volume
    GUIDs and device paths all collapse to the drive-letter form). A share spelling does NOT
    collapse - realpath hands back ``\\\\server\\share`` or ``\\\\?\\UNC\\...`` - and a path the
    guard cannot place on a local drive is REFUSED, whether or not it points into the tree.

    ``strict=True`` is for a path that MUST exist (the write site's directory after mkdir, and
    its temp file). Non-strict realpath hands a missing path back unchanged, which let a temp
    file whose parent had been moved away pass as "not redirected" (R1, 2026-09-24). Strict, a
    missing component raises, and the raise is a refusal.
    """
    try:
        if strict:
            resolved = os.path.realpath(os.fspath(path), strict=True)
        else:
            resolved = os.path.realpath(os.fspath(path))
    except (OSError, ValueError) as exc:
        raise RecorderError(
            "REFUSING TO WRITE: " + str(path) + " could not be resolved through the "
            "filesystem (" + repr(exc) + "), so it cannot be proven outside the fixture tree."
        ) from exc
    if os.name == "nt" and not _LOCAL_DRIVE.fullmatch(os.path.splitdrive(resolved)[0]):
        raise RecorderError(
            "REFUSING TO WRITE: " + str(path) + " resolves to " + resolved + ", which is a "
            "network-share or device path, not a local drive-letter path. A share can be the "
            "same disk as the shipped fixtures under another name (\\\\localhost\\C$ is), so "
            "the fixture guard refuses every such path. Pass a local drive-letter --out."
        )
    return Path(resolved)


def _is_inside(path: Path, root: Path, *, strict: bool = False) -> bool:
    """True when ``path`` IS ``root`` or lives anywhere under it - decided by FILE IDENTITY.

    ``path`` usually does not exist yet (the recorder creates it), so it cannot itself be
    ``samefile``-d. The decision is taken on its existing ancestors instead: every component
    below the deepest existing one will be created fresh by ``mkdir(parents=True)``, so the
    path is inside ``root`` exactly when one of its EXISTING ancestors (or the path itself)
    is the same directory as ``root`` - same volume and same file id (``st_dev``/``st_ino``),
    which is what ``os.path.samefile`` compares. No spelling of ``root`` can change its id.

    FAIL CLOSED, by raising ``RecorderError``, whenever the answer cannot be proven: the
    path or the root resolves to a share or device (``_canonical``), the root cannot be
    stat'ed, an ancestor exists but cannot be stat'ed, or no ancestor exists at all. A false
    refusal costs a re-run with another ``--out``; a false accept overwrote a tracked fixture
    in the first red run of this guard. ``strict`` is handed to ``_canonical`` for ``path``: a
    path that must exist and does not is refused.
    """
    resolved = _canonical(path, strict=strict)
    root_resolved = _canonical(root)
    try:
        root_stat = os.stat(root_resolved)
    except OSError as exc:
        raise RecorderError(
            "REFUSING TO WRITE: the protected fixture root " + str(root) + " cannot be "
            "stat'ed (" + repr(exc) + "), so no --out can be proven outside it."
        ) from exc
    root_id = (root_stat.st_dev, root_stat.st_ino)

    probe = os.fspath(resolved)
    found_existing = False
    while True:
        try:
            probe_stat = os.stat(probe)
        except (FileNotFoundError, NotADirectoryError):
            pass  # not created yet: it will be created UNDER the next existing ancestor
        except OSError as exc:
            raise RecorderError(
                "REFUSING TO WRITE: " + probe + " (an ancestor of --out " + str(path) + ") "
                "exists but cannot be stat'ed (" + repr(exc) + "), so --out cannot be "
                "proven outside the fixture tree."
            ) from exc
        else:
            found_existing = True
            if (probe_stat.st_dev, probe_stat.st_ino) == root_id:
                return True
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    if not found_existing:
        raise RecorderError(
            "REFUSING TO WRITE: no part of " + str(path) + " exists on disk, so it cannot be "
            "placed relative to the fixture tree."
        )
    return False


def _refuse_if_redirected_or_protected(path: Path, *, strict: bool = False) -> None:
    """Refuse a write location that is not where ``main()``'s --out guard approved.

    ``main()`` hands the write sites paths under the RESOLVED --out, so nothing in them
    redirects when the guard runs. Two legs, both FAIL CLOSED with ``RecorderError``:

    - REDIRECTION: ``realpath`` of ``path`` must equal its literal absolute path. A junction
      or symlink anywhere in the chain - one that pre-existed BELOW --out (``<out>/clean`` ->
      tests/fixtures/recorded/clean) or one planted at --out during the network phase - makes
      them differ. This leg binds the write to the APPROVED location, which the identity leg
      alone cannot do: a write into RECORDED_ROOT is legal for the canned regeneration, so a
      junction planted to RECORDED_ROOT in a non-destructive run would pass identity.
    - IDENTITY: ``path`` must not be inside FIXTURES_ROOT unless it is inside RECORDED_ROOT
      (``_is_inside``: file ids of the resolved path and every existing ancestor). Reached only
      if the --out guard itself is broken; kept as the backstop for exactly that.

    ``strict=True`` (the path must exist) resolves both legs strictly - see ``_canonical``.
    """
    literal = os.path.abspath(os.fspath(path))
    resolved = os.fspath(_canonical(path, strict=strict))
    if os.path.normcase(resolved) != os.path.normcase(literal):
        raise RecorderError(
            "REFUSING TO WRITE: " + literal + " resolves to " + resolved + " - a junction, "
            "symlink or mount point in its chain redirects the write away from the --out that "
            "was checked (it may have been planted below --out, or after the check). Remove "
            "the redirection or pass a --out that contains none."
        )
    if _is_inside(path, FIXTURES_ROOT, strict=strict) and not _is_inside(
        path, RECORDED_ROOT, strict=strict
    ):
        raise RecorderError(
            "REFUSING TO WRITE: " + literal + " is inside the shipped fixture tree ("
            + str(FIXTURES_ROOT) + ") and not under " + str(RECORDED_ROOT) + ", the only "
            "place a regeneration may write."
        )


def _file_id(stat_result) -> tuple:
    """(volume, file id), what ``os.path.samestat`` compares: one pair, one file."""
    return (stat_result.st_dev, stat_result.st_ino)


def _refuse_if_swapped(
    directory: Path, directory_id: tuple, temp_name: str, temp_id: tuple
) -> None:
    """The LAST check before ``os.replace``: the names about to be used still name the objects
    this process created and checked. FAIL CLOSED with ``WriteSiteSwapError``.

    - DIRECTORY: ``lstat`` (the entry itself - a junction or symlink put at the name has its own
      file id) and ``stat`` (every component followed) must both give the id captured right after
      mkdir. A directory renamed away and replaced by a junction, or an ancestor swapped so the
      path reaches another directory, changes at least one of them (R1, 2026-09-24). ``lstat``
      alone catches a junction left at the name that leads back to the moved original; ``stat``
      alone catches the original directory itself turned into a junction (same entry, same id).
    - LOCATION: strict ``realpath`` of the directory must equal its literal absolute path, the
      same comparison ``_refuse_if_redirected_or_protected`` makes. Identity cannot see an
      ANCESTOR moved elsewhere - into the fixture tree, say - with a junction left at its old
      name: the directory object moves with it, so both ids still match, and the capture landed
      in ``tests/fixtures/derived_from_source/...`` with no error (reproduced by the 2026-09-24
      verifier). Checked after identity, so an identity swap keeps its own message.
    - TEMP FILE: ``lstat`` of the temp name must give the id ``fstat`` read from the descriptor
      this process wrote through, with ``st_nlink == 1``. A hardlink to a shipped file put at the
      temp name carries the shipped file's id and a link count of 2 (R2, 2026-09-24).
    """
    literal = os.path.abspath(os.fspath(directory))
    try:
        directory_entry = os.lstat(directory)
        directory_followed = os.stat(directory)
        temp_entry = os.lstat(temp_name)
        # read LAST: a junction or a moved ancestor changes the location, so those swaps get the
        # narrowest window. A REAL protected directory renamed onto the approved name does NOT
        # change it; only the identity reads above see that, and their window is WIDER and can
        # replace a shipped file (measured by the verifier, see _write_text_where_approved).
        directory_resolved = os.path.realpath(literal, strict=True)
    except OSError as exc:
        raise WriteSiteSwapError(
            "REFUSING TO WRITE: the write site " + str(directory) + " or its temp file "
            + temp_name + " can no longer be stat'ed (" + repr(exc) + ") - something moved "
            "between the checks and the rename."
        ) from exc
    if _file_id(directory_entry) != directory_id or _file_id(directory_followed) != directory_id:
        raise WriteSiteSwapError(
            "REFUSING TO WRITE: " + str(directory) + " is no longer the directory that was "
            "checked and created - it was renamed, or replaced by a junction, symlink or mount "
            "point, after the checks. Nothing was renamed into place."
        )
    if os.path.normcase(directory_resolved) != os.path.normcase(literal):
        raise WriteSiteSwapError(
            "REFUSING TO WRITE: " + literal + " now resolves to " + directory_resolved + " - a "
            "folder on its path was moved, or replaced by a junction, symlink or mount point, "
            "after the checks, so the write would land away from the approved --out. Nothing was "
            "renamed into place."
        )
    if _file_id(temp_entry) != temp_id or temp_entry.st_nlink != 1:
        raise WriteSiteSwapError(
            "REFUSING TO WRITE: the temp name " + temp_name + " no longer names the file this "
            "process wrote (file id changed, or link count " + str(temp_entry.st_nlink)
            + " is not 1): a hardlink or another file was put at it, and renaming it into place "
            "would publish someone else's bytes as the capture."
        )


def _write_text_where_approved(target: Path, text: str) -> None:
    """Write ``text`` to ``target`` so the bytes can only land where the --out guard approved.

    S54, measured 2026-09-24: the guard decides once, on --out and its ancestors, before a
    network phase of up to ~90 s, and the recorder then writes DESCENDANTS of --out. Three ways
    a capture landed in the shipped tree anyway, identically before and after the UNC fix:
    a junction below --out; a HARDLINK below --out (``Path.write_text`` opens the existing name
    and truncates the file id it shares with a shipped file); a junction planted at --out during
    the network phase. So every write re-checks at the write site, in this order:

    1. ``_refuse_if_redirected_or_protected`` on the directory BEFORE mkdir, so no directory is
       ever created in the tree;
    2. right after mkdir, the directory's file id is captured (``lstat``: the entry itself);
    3. a FRESH temp file is created by ``tempfile.mkstemp``, which opens with O_CREAT|O_EXCL: a
       name that already exists (say a hardlink someone pre-placed) is skipped, never opened;
       the temp file's id is read from the descriptor that writes the bytes;
    4. the temp file's own resolved location is checked STRICTLY: a directory swapped for a
       junction shows as a redirection, and a parent moved away is now a refusal - non-strict
       realpath used to pass it (R1, 2026-09-24);
    5. LAST, right before ``os.replace``, ``_refuse_if_swapped`` re-reads the directory's id
       (entry and followed path), the directory's LOCATION (strict realpath == literal path),
       and the temp name's id and link count (R1 and R2).

    ``os.replace`` then swaps the NAME. The existing file is never opened, so a hardlink's
    other names keep their bytes. Text mode, like write_text.

    What is refused: a swap that is COMPLETE before step 5 reads what it changes - the directory
    renamed away and replaced by a junction (into the tree or back to the moved original) or by
    another REAL directory (a protected one included), the
    directory itself turned into a junction, an ANCESTOR moved anywhere (into the fixture tree
    included) with a junction left at its old name, a parent missing at step 4, and any other
    file or extra hardlink at the temp name.

    What is NOT refused, stated with its measurement: a swap that completes after step 5 has
    read what it checks and before ``os.replace`` runs. Each property has its own window, from
    the moment step 5 last reads it to ``os.replace``:

    - BEFORE the location leg (measured by the 2026-09-24 verifier, 2000 writes, this machine):
      the ancestor move had the whole stretch from the end of step 4 to ``os.replace`` -
      median 362 us, p95 2.0 ms, max 40 ms - and landed the capture in the tree with no error.
      The gap from the end of step 5 to ``os.replace`` was median 2.7 us, p95 5.0 us, max
      1.9 ms (the R1/R2 builder's run: p95 4.6 us, max 13 ms). The 2.7 us figure is that
      narrow gap ONLY; it never bounded the ancestor move.
    - NOW, read order directory lstat, directory stat, temp lstat, directory realpath (measured
      by the verifier 25-09-2026, 2 runs of 2000 writes, this machine, Python-wrapper
      timestamps, from the end of each read to the start of ``os.replace``):
      - LOCATION (realpath, read last): median 21-23 us, p95 34-41 us, max 2.8-4.0 ms. Every
        junction or moved-ancestor redirection must complete inside this window.
      - TEMP-name identity (R2): median 0.45-0.49 ms, p95 0.8-1.6 ms, max 11-39 ms. A swap in it
        publishes someone else's bytes, or a second name of a shipped file, at the APPROVED
        place only.
      - DIRECTORY identity (lstat and stat): median 0.56-0.71 ms (stat p95 1.0-2.1 ms, max
        19-40 ms). A swap in it CAN REPLACE A SHIPPED FILE: the racer renames the approved
        directory away, renames a REAL protected directory (``tests/fixtures/derived_from_source/
        clean``, or ``recorded/clean``) onto the approved name, moves the temp in, and renames
        the directory back after ``os.replace``. A real directory at the literal name passes the
        location leg, the temp keeps its id and link count 1, and the capture overwrites the
        protected ``journal_verify.json`` with no error and no note - reproduced
        deterministically by the verifier on 3.13 and 3.11. The same swap made BEFORE step 5 is
        refused by the identity pair (a test pins that behaviorally).
      No order makes every window small here: one realpath costs about 0.43 ms and each stat
      about 0.1 ms. Location last is a choice: the location-class swaps need 2 operations and
      one was raced for real by an earlier gate, while the real-directory swap needs 3 renames
      plus a move-back; reading realpath first would widen the location window to about 0.35
      ms (verifier, same date).

    Closing these windows entirely needs a directory handle held without FILE_SHARE_DELETE
    (Windows) or ``os.replace`` with ``src_dir_fd``/``dst_dir_fd`` (POSIX); neither is done here.

    After ANY refusal the temp file is unlinked by its path. When its directory was moved away
    (not into a junction the path still follows), that path no longer reaches it: the temp
    file - this run's capture bytes, never a shipped file's - stays in the moved directory. It
    cannot be found by name safely, so it is not hunted for; the raised exception carries a
    note naming it instead.
    """
    directory = target.parent
    _refuse_if_redirected_or_protected(directory)  # before mkdir: create nothing in the tree
    directory.mkdir(parents=True, exist_ok=True)
    directory_id = _file_id(os.lstat(directory))  # the entry itself, before any byte is written
    # O_CREAT|O_EXCL (mkstemp): an existing name is skipped, never opened or truncated.
    fd, temp_name = tempfile.mkstemp(prefix="." + target.name + ".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            temp_id = _file_id(os.fstat(handle.fileno()))
            handle.write(text)
        _refuse_if_redirected_or_protected(Path(temp_name), strict=True)  # where the bytes are
        _refuse_if_swapped(directory, directory_id, temp_name, temp_id)  # last, then at once:
        os.replace(temp_name, target)
    except BaseException as exc:
        try:
            os.unlink(temp_name)  # our own temp file only - never the target
        except FileNotFoundError:
            exc.add_note(
                "the temp file " + temp_name + " was not found at that path during cleanup: if "
                "its directory was moved, it (this run's capture bytes only) is still inside the "
                "moved directory and must be removed by hand."
            )
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="AC-0.2 recorder: capture the corpus from a running LedgerMind"
    )
    parser.add_argument("--dry-run", action="store_true", help="probe the stack and write nothing")
    parser.add_argument("--out", default=str(RECORDED_ROOT), help="corpus output directory")
    parser.add_argument(
        "--destructive-reset-and-tamper",
        action="store_true",
        dest="destructive",
        help=(
            "DESTROYS DATA ON THE TARGET LEDGER. Runs POST /api/demo/reset, which TRUNCATEs the "
            "ledger tables and re-seeds the canned 5-transfer demo, and then POST /api/demo/tamper, "
            "which edits a posting. This is the only way to produce the two-half AC-0.2 corpus. "
            "Without it the recorder captures the ledger AS IT FINDS IT and never mutates it."
        ),
    )
    args = parser.parse_args(argv)

    out_root = Path(args.out)
    write = not args.dry_run
    destructive = args.destructive
    client = RateLimitedClient()

    print("BASE_URL: " + BASE_URL)
    print("write: " + str(write))
    print("destructive: " + str(destructive))

    # A capture must never land on top of a SHIPPED FIXTURE. Two distinct dangers, one guard:
    #  (a) the default corpus root in a non-destructive run: there IS no tampered half, so a
    #      write would leave tests/fixtures/recorded/tampered/ stale beside a fresh clean/
    #      half - two halves of two different ledgers, which is worse than either alone;
    #  (b) ANY other path under tests/fixtures/: those files are the ground truth the suite
    #      asserts against, and a capture is live data from whatever BASE_URL points at.
    # (b) is the 2026-09-22 residual A3: the guard used to compare against RECORDED_ROOT only,
    # so --out <repo>/tests/fixtures/derived_from_source was accepted. Exactly ONE write into
    # tests/fixtures/ stays legal - regenerating the canned two-half corpus in its own
    # directory with the destructive flag, which is the documented way that corpus is made.
    if write and _is_inside(out_root, FIXTURES_ROOT):
        regenerating_the_canned_corpus = (
            destructive and out_root.resolve() == RECORDED_ROOT.resolve()
        )
        if not regenerating_the_canned_corpus:
            detail = (
                "the default output directory (" + str(RECORDED_ROOT) + ") holds the shipped "
                "two-half corpus and a non-destructive run captures the CLEAN half only"
                if out_root.resolve() == RECORDED_ROOT.resolve()
                else str(out_root) + " is inside the shipped fixture tree ("
                + str(FIXTURES_ROOT) + "), whose files are the ground truth the test suite "
                "asserts against"
            )
            raise RecorderError(
                "REFUSING TO WRITE: " + detail + ". Pass --out <a directory outside "
                + str(FIXTURES_ROOT) + "> to capture this ledger, or "
                "--destructive-reset-and-tamper with the default --out to regenerate the full "
                "canned corpus (that TRUNCATEs the target ledger)."
            )
    if write:
        # Every write site gets the RESOLVED --out the guard just approved: from here on any
        # redirection in the chain (below --out, or planted during the network phase) is
        # refused where the bytes are written - see _write_text_where_approved.
        out_root = _canonical(out_root)

    # 1. Reset to the clean demo scenario, through the app's own endpoint.
    #
    # *** DESTRUCTIVE. THIS TRUNCATES THE LIVE LEDGER. ***
    # POST /api/demo/reset does not "reset the recorder": it TRUNCATEs the ledger tables of
    # whatever LedgerMind BASE_URL points at and re-seeds the canned 5-transfer demo. Two
    # consequences, both measured on 2026-09-22 during the first end-to-end run against a
    # real Docker LedgerMind:
    #   (a) it SILENTLY DESTROYED a live 8-posting ledger that had just been built by hand;
    #   (b) it means this recorder can only ever capture the canned demo scenario - real
    #       activity on the target ledger is wiped before a single byte is read, so a
    #       "recorded" corpus can never contain concurrent or interleaved traffic (which is
    #       exactly the condition the O1 chain-order fix was written for).
    # --dry-run does NOT protect you: it only suppresses WRITING THE FIXTURE FILES; this
    # call runs either way. NEVER point BASE_URL at a ledger whose contents matter.
    # SINCE 2026-09-22 IT IS OPT-IN, behind --destructive-reset-and-tamper, default OFF. The
    # behaviour change was authorised by the owner after it was recommended and NOT applied in
    # the first pass; see the coder handoff of 2026-09-22. The warning above stays exactly
    # where it is, because someone will pass the flag without understanding it.
    if destructive:
        client.post_json("/api/demo/reset")
        print("reset: 200 (DESTRUCTIVE: the target ledger was TRUNCATEd and re-seeded)")
    else:
        print(
            "reset: SKIPPED (non-destructive default) - POST /api/demo/reset was NOT sent and "
            "the target ledger was NOT truncated. Capturing it as found."
        )

    # 2. Chain completeness BEFORE anything is written.
    complete, detail = wait_for_chain_complete(client)
    print("chain_complete: " + str(complete) + "  " + json.dumps(detail))
    if not complete:
        raise RecorderError(
            "REFUSING TO WRITE: chain completeness never held (" + json.dumps(detail) + "). "
            "A half-built chain recorded as ground truth poisons every later comparison."
        )

    clean_files, clean_status = capture_half(client, "clean", out_root, write)
    print("clean half captured: " + str(len(clean_files)) + " files")

    # 3. The planted defect comes from HIS code, not from us. ALSO DESTRUCTIVE: /api/demo/tamper
    # edits a posting on the target ledger, so a run that promises not to destroy anything
    # cannot send it either. Gated on the same flag, so ONE flag means "this run may mutate the
    # ledger" and its absence means "this run only reads".
    tampered_files, tampered_status, verify_after = {}, {}, None
    if destructive:
        client.post_json("/api/demo/tamper")
        print("tamper: 200")

        stable, verify_after = wait_for_stable_verify(client)
        print("tampered_verify_stable: " + str(stable) + "  " + json.dumps(verify_after))
        if not stable:
            raise RecorderError("REFUSING TO WRITE: the tampered verify response never stabilised")

        tampered_files, tampered_status = capture_half(client, "tampered", out_root, write)
        print("tampered half captured: " + str(len(tampered_files)) + " files")
    else:
        print(
            "tamper: SKIPPED (non-destructive default) - POST /api/demo/tamper was NOT sent, so "
            "this corpus has a CLEAN half only and is NOT AC-0.2 eligible."
        )

    # 4. Zero-429 assertion over everything that was saved.
    saved_statuses = {}
    saved_statuses.update({"clean/" + k: v for k, v in clean_status.items()})
    saved_statuses.update({"tampered/" + k: v for k, v in tampered_status.items()})
    non_200 = {
        k: v for k, v in saved_statuses.items() if v != 200 and v != "db-select-read-only"
    }
    if non_200:
        raise RecorderError(
            "REFUSING TO WRITE: non-200 responses reached the corpus: " + json.dumps(non_200)
        )
    rate_limited = [e for e in client.http_log if e["status"] == 429]
    print("http_requests: " + str(len(client.http_log)))
    print("http_429_encountered: " + str(len(rate_limited)))
    print("saved_429_in_corpus: 0")

    meta = {
        "corpus_kind": "recorded",
        # The corpus declares WHICH mode produced it. A clean-half-only capture that claimed
        # AC-0.2 eligibility would be exactly the kind of false green this repo exists to stop.
        "capture_mode": "destructive-reset-and-tamper" if destructive else "as-found-read-only",
        "ac_0_2_eligible": bool(destructive),
        "ac_0_2_reason": (
            (
                "Captured from a RUNNING LedgerMind demo stack. The tampered half comes from a "
                "real POST /api/demo/tamper against that stack, exactly as manifest section 2.6 "
                "requires; nothing here was computed or hand-edited."
            )
            if destructive
            else (
                "NOT ELIGIBLE. This run captured the ledger AS FOUND and mutated nothing: no "
                "POST /api/demo/reset and no POST /api/demo/tamper were sent, so there is a "
                "CLEAN half only and no second verdict. Re-run with "
                "--destructive-reset-and-tamper to produce an AC-0.2 corpus (it TRUNCATEs the "
                "target ledger)."
            )
        ),
        "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "base_url": BASE_URL,
        "ledgermind_repo": LEDGERMIND_UPSTREAM,
        "http_requests": len(client.http_log),
        "http_429_encountered": len(rate_limited),
        "http_429_retries": client.retries_after_429,
        "saved_response_statuses": saved_statuses,
        "chain_completeness_at_clean_capture": detail,
        "tampered_verify_after_stabilising": verify_after,
        "db_capture": {
            "how": "docker compose exec -T -e " + READ_ONLY_PGOPTIONS + " postgres psql",
            "read_only_enforced_by": (
                "PostgreSQL itself (default_transaction_read_only=on). A client-side "
                "SELECT-prefix check is layered on top and is the WEAKER guard."
            ),
            "statements": [POSTINGS_SQL, POSTING_HASH_SQL, ACCOUNTS_SQL],
            "writes_issued": 0,
        },
        "known_shape_gaps": [
            "The checkpoint public key and signature are real but EPHEMERAL: the demo generates a "
            "fresh ML-DSA key per boot, so they differ across runs and must never be compared "
            "across corpora.",
            "createdAt carries real Postgres microseconds rendered as Instant.toString() renders "
            "them; the derived corpus fabricated whole seconds, so no entryHash can ever match "
            "across the two corpora. See docs/evidence/derived-vs-recorded-normalization.md.",
            "Discrepancy ORDER in the reconciliation report follows two Java HashMaps and is not "
            "reproducible; compare discrepancies as a set.",
        ],
        "regenerate_with": "py -m tools.record_fixtures",
    }
    if write:
        _write_text_where_approved(
            out_root / "_corpus.json", json.dumps(meta, indent=2, ensure_ascii=False) + "\n"
        )
        print("wrote: " + str(out_root / "_corpus.json"))
    else:
        print("DRY RUN - nothing written")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RecorderError as exc:
        print("RECORDER_ERROR: " + str(exc), file=sys.stderr)
        for note in getattr(exc, "__notes__", ()):  # e.g. where a refused write's temp was left
            print("RECORDER_NOTE: " + note, file=sys.stderr)
        sys.exit(1)
