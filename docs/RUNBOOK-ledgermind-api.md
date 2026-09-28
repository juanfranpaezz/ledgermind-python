# Runbook - LedgerMind API (the optional FastAPI service)

Every command below runs from the repository root in Git Bash (Windows) or any POSIX shell. On
Linux/macOS replace `.venv/Scripts/python` with `.venv/bin/python`. On Windows use `py` to
create the venv; bare `python`/`python3` may be the Microsoft Store stub. Expected results are given
after each block as `-> ...`.

The API key is a secret: it is written to a file by `keygen`, and the commands below only ever read it
from a file. Never paste it into a command line, a URL or a chat.

## 1. Install (a fresh venv (`.venv`, ignored by git), the `api` and `api-test` extras)

```
py -m venv .venv
.venv/Scripts/python -m pip install -q -e ".[api,api-test]"
.venv/Scripts/python -c "import fastapi, uvicorn; print('ok')"
```
-> `ok`. The verifier core stays dependency-free: a venv with only `.[dev]` cannot `import fastapi`.

## 2. Create a key (hash file + plaintext key file, both in your user profile)

```
mkdir -p "$HOME/.ledgermind-api"
export LEDGERMIND_API_KEYS_FILE="$HOME/.ledgermind-api/api-keys.txt"
.venv/Scripts/python -m ledgermind_api.keygen --id local-dev --out-dir "$HOME/.ledgermind-api"
printf 'X-API-Key: %s\n' "$(cat "$HOME/.ledgermind-api/local-dev.key")" > "$HOME/.ledgermind-api/local-dev.header"
chmod 600 "$HOME/.ledgermind-api/local-dev.header"
```
-> keygen prints the key id and the PATH of the plaintext key file, never the key; exit 0. `--out-dir` is
given so the key lands where the next commands read it: on Windows Python's home is `%USERPROFILE%`,
which can differ from the shell's `$HOME`.
`api-keys.txt` holds one line `local-dev sha256:<64 hex>`. The `.header` file lets curl send the key
without it appearing on any command line (`curl -H @file`). Running keygen twice with the same id
exits non-zero and changes nothing.

## 3. Start the service (127.0.0.1:8088)

```
.venv/Scripts/python -m ledgermind_api > "$HOME/.ledgermind-api/server.log" 2>&1 &
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8088/v1/health && break; sleep 1; done
```
-> listening on `127.0.0.1:8088` only. With `LEDGERMIND_API_KEYS_FILE` unset, pointing at a missing
or empty file, or at a file with a malformed line, the service refuses to start: exit 2 and the
variable NAME (never a value) on stderr. The loop waits for the first HTTP answer (any status; at most
30 s) instead of a fixed sleep. A request body that has not arrived in full within
`LEDGERMIND_API_BODY_TIMEOUT_S` seconds (default 10) is answered 408 and the connection closes; a client
that never finishes its headers, and connection-count exhaustion, are not bounded by the service: beyond
localhost, put a reverse proxy with its own timeouts in front.

## 4. Call it

```
H="$HOME/.ledgermind-api/local-dev.header"
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8088/v1/health
curl -s -H @"$H" http://127.0.0.1:8088/v1/health
curl -s -H @"$H" -H "Content-Type: application/json" -d '{"corpus_id":"repo-recorded","half":"tampered"}' http://127.0.0.1:8088/v1/verify/corpus | .venv/Scripts/python -c "import json,sys; b=json.load(sys.stdin); print(b['status'], b['exit_code'], b['tamper_proven'])"
curl -s -H @"$H" http://127.0.0.1:8088/v1/tools | .venv/Scripts/python -c "import json,sys; print(sorted(t['name'] for t in json.load(sys.stdin)))"
```
-> `401`; `{"status":"ok"}`; `TAMPER_SUSPECTED 1 True` (with `"half":"clean"`: `VERIFIED 0 False`
when `openssl >= 3.5` is on PATH, else `INCOMPLETE 2 False`, exactly what the CLI says);
`['interpret_java_audit', 'verify_corpus', 'verify_snapshot']`.

Upload a snapshot and interpret the Java ledger's own audit report (body files built from the
recorded fixtures):

```
.venv/Scripts/python - "$HOME/.ledgermind-api" <<'EOF'
import json, pathlib, sys
d = pathlib.Path("tests/fixtures/recorded/tampered")
names = ["postings_and_hashes.json", "journal_checkpoint.json", "journal_verify.json", "journal_audit.json"]
names += sorted(p.name for p in d.glob("account_*.json"))
snap = {"kind": "recorded", "label": "tampered", "files": {n: json.loads((d / n).read_text()) for n in names}}
audit = json.loads((d / "journal_audit.json").read_text())
out = pathlib.Path(sys.argv[1])
(out / "snapshot-tampered.json").write_text(json.dumps(snap))
(out / "java-audit-tampered.json").write_text(json.dumps({"audit": audit, "snapshot": snap}))
EOF
curl -s -H @"$H" -H "Content-Type: application/json" --data-binary @"$HOME/.ledgermind-api/snapshot-tampered.json" http://127.0.0.1:8088/v1/verify/snapshot | .venv/Scripts/python -c "import json,sys; b=json.load(sys.stdin); print(b['status'], b['exit_code'])"
curl -s -H @"$H" -H "Content-Type: application/json" --data-binary @"$HOME/.ledgermind-api/java-audit-tampered.json" http://127.0.0.1:8088/v1/java/audit | .venv/Scripts/python -c "import json,sys; b=json.load(sys.stdin); print(b['java']['status'], b['java']['mapping_basis'], b['python']['status'], b['agree'])"
```
-> `TAMPER_SUSPECTED 1`; `TAMPER_SUSPECTED legacy TAMPER_SUSPECTED YES`. The recorded audits predate
the Java `coverageDegraded` field, so they map on the `legacy` basis.

Stop the service: `kill %1` (the background job started in step 3).

## 5. Tests and the committed OpenAPI document

```
.venv/Scripts/python -m pytest tests_api -q
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m ledgermind_api.openapi_export
git diff --stat -- docs/openapi.json
```
-> both suites 0 failed, 0 skipped; after the export, `git diff` shows nothing unless a route or model
changed (the drift test fails until the file is regenerated and committed).

## 6. Docker (local only)

```
docker build -t ledgermind-api .
docker run --rm ledgermind-api; echo "exit=$?"
docker run -d --rm --name lm-api -p 127.0.0.1:8088:8088 --mount "type=bind,source=$LEDGERMIND_API_KEYS_FILE,target=/run/secrets/ledgermind-api-keys,readonly" ledgermind-api
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8088/v1/health && break; sleep 1; done
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8088/v1/health
curl -s -H @"$H" http://127.0.0.1:8088/v1/health
docker exec lm-api id -u
docker exec lm-api python -m tools.verify_report --corpus recorded --half tampered --json > /dev/null; echo "cli exit=$?"
docker stop lm-api
```
-> build exit 0; without the keys mount the container exits `2` and names `LEDGERMIND_API_KEYS_FILE`;
with it: `401`, `{"status":"ok"}`, `10001` (not root), `cli exit=1`. Stop the local service from
step 3 first, or publish another host port (`-p 127.0.0.1:8098:8088`). The image carries no key: the
hash file is mounted read-only at run time, and `.dockerignore` keeps `*.key` / `*keys*` out of the
build context. There is no TLS: never publish the port on a public interface.
