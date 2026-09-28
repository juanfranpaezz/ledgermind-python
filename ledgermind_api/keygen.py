"""Create one API key. Standard library only (runs without FastAPI).

    py -m ledgermind_api.keygen --id <key_id> [--keys-file PATH] [--out-dir DIR]

The PLAINTEXT key goes to ``<out-dir>/<key_id>.key`` (default ``<home>/.ledgermind-api``), created
exclusively. Only ``<key_id> sha256:<hex>`` is appended to the keys file the server reads
(``--keys-file`` or ``$LEDGERMIND_API_KEYS_FILE``). This program prints ONLY the key_id and file
PATHS - never the key value - so no log or agent transcript ever carries it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
from pathlib import Path

from .config import ENV_KEYS_FILE, KEY_ID_RE, KEY_LINE_RE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="py -m ledgermind_api.keygen", description="Create one LedgerMind API key.")
    parser.add_argument("--id", required=True, dest="key_id")
    parser.add_argument("--keys-file", default=None, help="hash file to append to (default: $" + ENV_KEYS_FILE + ")")
    parser.add_argument("--out-dir", default=None, help="directory for the plaintext key file")
    args = parser.parse_args(argv)

    if not KEY_ID_RE.match(args.key_id):
        print("ERROR: --id must match ^[A-Za-z0-9_.-]{1,64}$", file=sys.stderr)
        return 2
    keys_file = args.keys_file or os.environ.get(ENV_KEYS_FILE)
    if not keys_file:
        print("ERROR: pass --keys-file or set " + ENV_KEYS_FILE, file=sys.stderr)
        return 2
    keys_path = Path(keys_file)
    existing = keys_path.read_text(encoding="utf-8") if keys_path.exists() else ""
    for line in existing.splitlines():
        match = KEY_LINE_RE.match(line.strip())
        if match and match["key_id"] == args.key_id:
            print("ERROR: key_id '" + args.key_id + "' already exists in the keys file", file=sys.stderr)
            return 2

    out_dir = Path(args.out_dir) if args.out_dir else Path.home() / ".ledgermind-api"
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / (args.key_id + ".key")
    key = secrets.token_urlsafe(32)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print("ERROR: the key file already exists; refusing to overwrite it: " + str(key_path), file=sys.stderr)
        return 2
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(key + "\n")
    keys_path.parent.mkdir(parents=True, exist_ok=True)
    with keys_path.open("a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write(args.key_id + " sha256:" + digest + "\n")
    print("key_id: " + args.key_id)
    print("plaintext key file (send its content as the X-API-Key header; never paste it anywhere): " + str(key_path))
    print("hash line appended to: " + str(keys_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
