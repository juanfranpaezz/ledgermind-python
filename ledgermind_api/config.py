"""Configuration from environment variables only (never argv). Standard library only.

FAIL-CLOSED: any missing or malformed setting raises ``ConfigError`` and the service refuses to
start. Messages name the VARIABLE and never echo a value (a malformed keys-file line may hold a
plaintext key, so it is never repeated back).
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]

ENV_KEYS_FILE = "LEDGERMIND_API_KEYS_FILE"
ENV_PY_EXE = "LEDGERMIND_PY_EXE"
ENV_PY_REPO = "LEDGERMIND_PY_REPO"
ENV_CORPORA = "LEDGERMIND_PY_CORPORA"
ENV_TIMEOUT = "LEDGERMIND_PY_TIMEOUT_S"
ENV_BODY_TIMEOUT = "LEDGERMIND_API_BODY_TIMEOUT_S"
ENV_MAX_BODY = "LEDGERMIND_API_MAX_BODY_BYTES"
ENV_MAX_CONCURRENT = "LEDGERMIND_API_MAX_CONCURRENT_VERIFIES"
ENV_HOST = "LEDGERMIND_API_HOST"
ENV_PORT = "LEDGERMIND_API_PORT"

# 1 MiB. Probe U3 (2026-09-25): the largest recorded half, as an upload body, is 11,606 bytes,
# so the plan's floor (>= 4x) is 46,424 bytes. 1 MiB leaves room for real captures and still
# bounds the memory one request can take.
DEFAULT_MAX_BODY_BYTES = 1_048_576
DEFAULT_TIMEOUT_S = 60.0
# A request body must arrive in full within this many seconds, else 408 (security gate r1 A5).
DEFAULT_BODY_TIMEOUT_S = 10.0
DEFAULT_MAX_CONCURRENT = 2
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8088
MAX_JSON_DEPTH = 64
MAX_UPLOAD_FILES = 64

ID_PATTERN = r"^[a-z0-9_-]{1,64}$"
ID_RE = re.compile(ID_PATTERN)
KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
KEY_LINE_RE = re.compile(r"^(?P<key_id>[A-Za-z0-9_.-]{1,64}) sha256:(?P<hex>[0-9a-f]{64})$")

RECORDED_SUBDIR = Path("tests") / "fixtures" / "recorded"
ADVERSARIAL_SUBDIR = Path("tests") / "fixtures" / "derived_from_source" / "adversarial"


class ConfigError(Exception):
    """The service refuses to start. The message names a variable, never a value."""


@dataclass(frozen=True)
class CorpusEntry:
    kind: str  # "recorded" | "adversarial"
    root: Path | None  # None = the CLI's built-in repo corpus (no --corpus-root is passed)


DEFAULT_CORPORA: dict[str, CorpusEntry] = {
    "repo-recorded": CorpusEntry("recorded", None),
    "repo-adversarial": CorpusEntry("adversarial", None),
}


@dataclass(frozen=True)
class Settings:
    key_hashes: tuple[tuple[str, bytes], ...]
    repo_root: Path = REPO_ROOT
    py_exe: str = sys.executable
    corpora: Mapping[str, CorpusEntry] = field(default_factory=lambda: dict(DEFAULT_CORPORA))
    timeout_s: float = DEFAULT_TIMEOUT_S
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_concurrent: int = DEFAULT_MAX_CONCURRENT
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    max_json_depth: int = MAX_JSON_DEPTH
    body_timeout_s: float = DEFAULT_BODY_TIMEOUT_S
    max_upload_files: int = MAX_UPLOAD_FILES


def corpus_dir(settings: Settings, entry: CorpusEntry) -> Path:
    """The directory the CLI will read for this registered corpus."""
    if entry.root is not None:
        return entry.root
    return settings.repo_root / (RECORDED_SUBDIR if entry.kind == "recorded" else ADVERSARIAL_SUBDIR)


def load_key_hashes(environ: Mapping[str, str]) -> tuple[tuple[str, bytes], ...]:
    raw = environ.get(ENV_KEYS_FILE)
    if not raw:
        raise ConfigError(ENV_KEYS_FILE + " is not set; the API refuses to start without API keys (fail-closed).")
    try:
        text = Path(raw).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(ENV_KEYS_FILE + " points at a file that does not exist (fail-closed).") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(ENV_KEYS_FILE + " could not be read (" + type(exc).__name__ + "; fail-closed).") from None
    entries: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = KEY_LINE_RE.match(stripped)
        if match is None:
            raise ConfigError(
                ENV_KEYS_FILE + ": line " + str(number) + " is not '<key_id> sha256:<64 lowercase hex>'. "
                "The line is not echoed because it may hold a plaintext key (fail-closed)."
            )
        if match["key_id"] in seen:
            raise ConfigError(ENV_KEYS_FILE + ": line " + str(number) + " repeats a key_id (fail-closed).")
        seen.add(match["key_id"])
        entries.append((match["key_id"], bytes.fromhex(match["hex"])))
    if not entries:
        raise ConfigError(
            ENV_KEYS_FILE + " holds no key lines; an empty key set would reject every request (fail-closed)."
        )
    return tuple(entries)


def _int_env(environ: Mapping[str, str], name: str, default: int, minimum: int, maximum: int | None = None) -> int:
    raw = environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(name + " must be an integer.") from None
    if value < minimum or (maximum is not None and value > maximum):
        raise ConfigError(name + " is out of range.")
    return value


def _float_env(environ: Mapping[str, str], name: str, default: float) -> float:
    raw = environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(name + " must be a number of seconds.") from None
    if not value > 0:
        raise ConfigError(name + " must be > 0.")
    return value


def load_corpora(environ: Mapping[str, str]) -> dict[str, CorpusEntry]:
    raw = environ.get(ENV_CORPORA)
    if raw is None or raw.strip() == "":
        return dict(DEFAULT_CORPORA)
    try:
        data = json.loads(raw)
    except ValueError:
        raise ConfigError(ENV_CORPORA + " is not valid JSON.") from None
    if not isinstance(data, dict) or not data:
        raise ConfigError(ENV_CORPORA + " must be a non-empty JSON object {corpus_id: {kind, root}}.")
    out: dict[str, CorpusEntry] = {}
    for corpus_id, spec in data.items():
        if not isinstance(corpus_id, str) or not ID_RE.match(corpus_id):
            raise ConfigError(ENV_CORPORA + ": a corpus id does not match " + ID_PATTERN + ".")
        if not isinstance(spec, dict) or spec.get("kind") not in ("recorded", "adversarial"):
            raise ConfigError(ENV_CORPORA + ": corpus '" + corpus_id + "' needs kind recorded|adversarial.")
        root = spec.get("root")
        if root is None:
            out[corpus_id] = CorpusEntry(spec["kind"], None)
            continue
        if not isinstance(root, str) or not Path(root).is_dir():
            raise ConfigError(ENV_CORPORA + ": corpus '" + corpus_id + "' root is not an existing directory.")
        out[corpus_id] = CorpusEntry(spec["kind"], Path(root).resolve())
    return out


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    key_hashes = load_key_hashes(env)
    repo_root = Path(env.get(ENV_PY_REPO) or REPO_ROOT).resolve()
    if not (repo_root / "tools" / "verify_report.py").is_file():
        raise ConfigError(ENV_PY_REPO + " does not contain tools/verify_report.py.")
    py_exe = env.get(ENV_PY_EXE) or sys.executable
    if not Path(py_exe).is_file():
        raise ConfigError(ENV_PY_EXE + " is not an existing file.")
    return Settings(
        key_hashes=key_hashes,
        repo_root=repo_root,
        py_exe=py_exe,
        corpora=load_corpora(env),
        timeout_s=_float_env(env, ENV_TIMEOUT, DEFAULT_TIMEOUT_S),
        body_timeout_s=_float_env(env, ENV_BODY_TIMEOUT, DEFAULT_BODY_TIMEOUT_S),
        max_body_bytes=_int_env(env, ENV_MAX_BODY, DEFAULT_MAX_BODY_BYTES, 1024),
        max_concurrent=_int_env(env, ENV_MAX_CONCURRENT, DEFAULT_MAX_CONCURRENT, 1, 64),
        host=env.get(ENV_HOST) or DEFAULT_HOST,
        port=_int_env(env, ENV_PORT, DEFAULT_PORT, 0, 65535),
    )
