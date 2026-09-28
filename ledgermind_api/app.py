"""The FastAPI application: request models, the two pure-ASGI guards, and the routes.

Order on every request (plan v2 D-3/D-4): API key -> body size + body deadline (408) + JSON depth -> routing.
Both guards are pure ASGI and wrap the WHOLE app, so FastAPI's automatic routes (/openapi.json,
/docs, /redoc), unknown paths and every method (HEAD, OPTIONS) are behind the key, and an
unauthenticated caller never gets its body read (401 beats 413).

The service never imports the verifier. ``runner`` runs the CLI in a child process; see there.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import time
import uuid
from enum import Enum
from itertools import accumulate
from typing import Annotated, Any, Callable, Literal, Union

import anyio
from fastapi import FastAPI, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator, model_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import DEFAULT_BODY_TIMEOUT_S, ENV_KEYS_FILE, ID_PATTERN, MAX_UPLOAD_FILES, ConfigError, Settings, corpus_dir, load_settings
from .java_audit import agree, holds_non_finite, map_java
from .runner import (
    CASE_LABEL_PATTERN,
    REQUIRED_NAME,
    ApiProblem,
    CliRun,
    map_python,
    recorded_name_allowed,
    run_cli,
    verify_adversarial_upload,
    verify_recorded_upload,
)

API_KEY_HEADER_NAME = "X-API-Key"
PROBLEM_MEDIA_TYPE = "application/problem+json"
API_KEY_SCHEME = APIKeyHeader(
    name=API_KEY_HEADER_NAME,
    auto_error=False,
    description="Every route, including /openapi.json and /docs, requires this header.",
)


# ---------------------------------------------------------------------------------------------
# Problem documents (RFC 9457)
# ---------------------------------------------------------------------------------------------

def problem_body(status: int, code: str, title: str, detail: str, request_id: str, **extra: Any) -> dict[str, Any]:
    body = {
        "type": "urn:ledgermind-api:problem:" + code,
        "title": title,
        "status": status,
        "detail": detail,
        "code": code,
        "request_id": request_id,
    }
    body.update(extra)
    return body


class AsciiJSONResponse(JSONResponse):
    """Every JSON answer of the service (parity gate r2 A1, 2026-09-27). A lone-surrogate escape such as
    ``"\\udc00x"`` is legal JSON; echoed in ``native`` it made FastAPI's default path (pydantic writing
    UTF-8) and Starlette's JSONResponse (``ensure_ascii=False`` then ``.encode("utf-8")``) raise, i.e.
    HTTP 500 text/plain where the CLI gives a verdict. ASCII-escaped output carries any code point.
    Setting this as ``default_response_class`` also turns off FastAPI's pydantic ``dump_json`` fast path;
    pydantic's json-mode conversion still runs first, so NaN/inf keep arriving here as null and
    ``allow_nan=False`` never has to refuse one. Known limit (measured 2026-09-27): that json-mode
    conversion replaces a lone surrogate inside a dict KEY with U+FFFD; values keep it."""

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=True, allow_nan=False, indent=None,
                          separators=(",", ":")).encode("ascii")


def _request_id(scope: dict) -> str:
    return str((scope.get("state") or {}).get("request_id", ""))


async def _send_problem(send: Callable, status: int, code: str, title: str, detail: str, request_id: str,
                        headers: tuple = ()) -> None:
    payload = json.dumps(problem_body(status, code, title, detail, request_id)).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", PROBLEM_MEDIA_TYPE.encode("ascii")),
            (b"content-length", str(len(payload)).encode("ascii")),
            # A guard may answer while the body is still arriving (401, 408); without this a client that
            # keeps sending bytes holds the connection open indefinitely (security gate r3, S1).
            (b"connection", b"close"),
            *headers,
        ],
    })
    await send({"type": "http.response.body", "body": payload})


# ---------------------------------------------------------------------------------------------
# Guards (pure ASGI)
# ---------------------------------------------------------------------------------------------

class ApiKeyAuthMiddleware:
    """OUTERMOST guard. Compares sha256(presented key) against EVERY stored hash with
    ``hmac.compare_digest`` (no early exit). An empty key set rejects everything."""

    def __init__(self, app: Callable, key_hashes: tuple[tuple[str, bytes], ...]) -> None:
        self.app = app
        self._hashes = tuple(key_hashes)

    def _match(self, presented: bytes) -> str | None:
        digest = hashlib.sha256(presented).digest()
        matched = None
        for key_id, stored in self._hashes:
            if hmac.compare_digest(digest, stored) and matched is None:
                matched = key_id
        return matched

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        state = scope.setdefault("state", {})
        state["request_id"] = uuid.uuid4().hex
        presented = None
        for name, value in scope.get("headers") or []:
            if name == b"x-api-key":
                presented = value
                break
        challenge = ((b"www-authenticate", b'ApiKey header="X-API-Key"'),)
        if not presented:
            await _send_problem(send, 401, "auth_missing", "API key required",
                                "send the key in the X-API-Key header", state["request_id"], challenge)
            return
        key_id = self._match(presented)
        if key_id is None:
            await _send_problem(send, 401, "auth_invalid", "API key not accepted",
                                "the X-API-Key header does not match any configured key", state["request_id"],
                                challenge)
            return
        state["key_id"] = key_id
        await self.app(scope, receive, send)


# Security gate r1 F1 (2026-09-27): the old string pattern needed a CLOSING quote, so on an unterminated
# string every later '"' restarted a scan to the end of the body - quadratic time, inside the event loop
# (measured: 80 KB took 114 s). Here a string runs to its closing quote OR to the end of the body, which is
# what a JSON parser does with a string that never closes, so every byte is consumed once.
_JSON_STRING_RE = re.compile(rb'"(?:[^"\\]++|\\.)*+"?', re.S)
_NON_BRACKET_BYTES = bytes(b for b in range(256) if b not in b"[]{}")
_BRACKET_STEP = [1 if b in b"[{" else -1 if b in b"]}" else 0 for b in range(256)]


def json_depth_exceeds(body: bytes, limit: int) -> bool:
    """True when the body nests arrays/objects deeper than ``limit`` (strings are ignored).
    Runs BEFORE any JSON parser so a deep document is a 422, never a RecursionError 500.
    Linear time: one regex pass that never re-scans, one translate, one running sum (all C-level).

    Security gate r2 (2026-09-27): the scan used to read the RAW bytes, but ``json.loads`` on bytes
    auto-detects UTF-8/16/32. In UTF-16LE the character U+2200 is the bytes 00 22, which a byte scan
    reads as a quote, so every bracket after it was hidden (measured by the gate: depth 2000 reached
    json.dump and pydantic, HTTP 500). The body is now decoded the way the parser picks its encoding
    (``json.detect_encoding``), strictly, and the scan runs on its UTF-8 form, where an ASCII byte is
    always an ASCII character. Raises UnicodeDecodeError (a ValueError) when the body is not text in
    that encoding; the caller answers it with a 400 problem."""
    utf8 = body.decode(json.detect_encoding(body)).encode("utf-8")
    brackets = _JSON_STRING_RE.sub(b"", utf8).translate(None, _NON_BRACKET_BYTES)
    return max(accumulate(map(_BRACKET_STEP.__getitem__, brackets)), default=0) > limit


class BodyLimitMiddleware:
    """Second guard. 413 when Content-Length exceeds the limit (body never read), 413 when the
    bytes actually received exceed it (chunked bodies carry no Content-Length), 422 when the JSON
    nests deeper than the limit. The buffered body is then replayed to the app."""

    def __init__(self, app: Callable, max_body_bytes: int, max_json_depth: int,
                 body_timeout_s: float = DEFAULT_BODY_TIMEOUT_S) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.max_json_depth = max_json_depth
        self.body_timeout_s = body_timeout_s

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = _request_id(scope)
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await _send_problem(send, 400, "bad_request", "Bad Content-Length",
                                        "the Content-Length header is not an integer", request_id)
                    return
                if declared > self.max_body_bytes:
                    await _send_problem(send, 413, "body_too_large", "Request body too large",
                                        "the body exceeds " + str(self.max_body_bytes) + " bytes", request_id)
                    return
        chunks: list[bytes] = []
        total = 0
        too_large = False
        # Security gate r1 A5 (2026-09-27): uvicorn does not bound a request body that trickles in, so the
        # WHOLE body gets one deadline (a per-chunk timeout would be defeated by a one-byte drip).
        try:
            with anyio.fail_after(self.body_timeout_s):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    if message["type"] != "http.request":
                        continue
                    chunk = message.get("body", b"")
                    total += len(chunk)
                    if total > self.max_body_bytes:
                        too_large = True
                        break
                    chunks.append(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await _send_problem(send, 408, "body_timeout", "Request body too slow",
                                "the body did not arrive in full within " + str(self.body_timeout_s) + " s",
                                request_id)
            return
        if too_large:
            await _send_problem(send, 413, "body_too_large", "Request body too large",
                                "the body exceeds " + str(self.max_body_bytes) + " bytes", request_id)
            return
        body = b"".join(chunks)
        try:
            too_deep = bool(body) and json_depth_exceeds(body, self.max_json_depth)
        except UnicodeDecodeError as exc:
            await _send_problem(send, 400, "bad_request", "Body is not JSON text",
                                "the body is not valid " + exc.encoding + " text (the encoding JSON detection "
                                "picks from its first bytes)", request_id)
            return
        if too_deep:
            await _send_problem(send, 422, "validation_error", "JSON nested too deeply",
                                "the JSON nests deeper than " + str(self.max_json_depth) + " levels", request_id)
            return
        replayed = False

        async def replay() -> dict:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


# ---------------------------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------------------------

class VerdictStatus(str, Enum):
    VERIFIED = "VERIFIED"
    COVERAGE_DEGRADED = "COVERAGE_DEGRADED"
    TAMPER_SUSPECTED = "TAMPER_SUSPECTED"
    INCOMPLETE = "INCOMPLETE"
    ERROR = "ERROR"


class VerifyCorpusRequest(BaseModel):
    """Verify a corpus registered on the server (no paths: ids only)."""

    model_config = ConfigDict(extra="forbid")
    corpus_id: Annotated[str, Field(pattern=ID_PATTERN, description="a registered corpus id")]
    half: Literal["clean", "tampered"] | None = Field(default=None, description="recorded corpora; default clean")
    case: Annotated[str, Field(pattern=ID_PATTERN)] | None = Field(default=None, description="adversarial corpora")

    @model_validator(mode="after")
    def _half_or_case(self) -> "VerifyCorpusRequest":
        if self.half is not None and self.case is not None:
            raise ValueError("give half OR case, not both")
        return self


class RecordedSnapshot(BaseModel):
    """A recorded half uploaded as content: {file name: parsed JSON content}."""

    model_config = ConfigDict(extra="forbid")
    kind: Literal["recorded"]
    label: Literal["clean", "tampered"] = Field(default="clean", description="cosmetic: never changes the verdict")
    files: dict[str, Any] = Field(description="postings_and_hashes.json (required), journal_checkpoint.json, "
                                              "journal_verify.json, journal_audit.json, account_<name>.json")

    @field_validator("files")
    @classmethod
    def _allowlisted(cls, files: dict[str, Any]) -> dict[str, Any]:
        if len(files) > MAX_UPLOAD_FILES:
            raise ValueError("at most " + str(MAX_UPLOAD_FILES) + " files")
        refused = sorted(name for name in files if not recorded_name_allowed(name))
        if refused:
            raise ValueError("file names not in the allowlist: " + ", ".join(repr(n[:80]) for n in refused[:5]))
        if REQUIRED_NAME not in files:
            raise ValueError(REQUIRED_NAME + " is required")
        return files


class AdversarialSnapshot(BaseModel):
    """One adversarial-format document uploaded as content."""

    model_config = ConfigDict(extra="forbid")
    kind: Literal["adversarial"]
    case_label: Annotated[str, Field(pattern=CASE_LABEL_PATTERN)] = "upload"
    document: dict[str, Any]


class VerifySnapshotRequest(RootModel[Annotated[Union[RecordedSnapshot, AdversarialSnapshot],
                                                Field(discriminator="kind")]]):
    """An uploaded snapshot: kind=recorded (a recorded half) or kind=adversarial (one document)."""


class VerdictCheck(BaseModel):
    name: str
    result: str
    violations: int
    detail: str


class VerdictSignature(BaseModel):
    status: str
    algorithm: str | None


class UniformVerdict(BaseModel):
    schema_version: Literal["1"]
    backend: str
    status: VerdictStatus
    tamper_proven: bool
    coverage_degraded: bool
    frozen_accounts: list[dict[str, Any]] | None
    checks: list[VerdictCheck]
    signature: VerdictSignature
    subject: str
    evidence_time: str | None
    does_not_detect: list[str]
    mapping_basis: Literal["exit_code", "field", "legacy"]
    exit_code: int | None
    native: dict[str, Any]
    notes: list[str]
    request_id: str
    duration_ms: int


class JavaAuditRequest(BaseModel):
    """The Java ledger's own audit report, optionally with a recorded snapshot for the differential."""

    model_config = ConfigDict(extra="forbid")
    audit: dict[str, Any] = Field(description="the JSON of Java's JournalIntegrityReport, as the MCP tool "
                                              "verify_journal_integrity returns it; interpreted, never recomputed")
    snapshot: RecordedSnapshot | None = Field(default=None, description="optional: a recorded half (same body as "
                                                                        "/v1/verify/snapshot kind=recorded); when "
                                                                        "given, the Python verifier runs on it and "
                                                                        "agree compares the two verdicts")

    @field_validator("audit")
    @classmethod
    def _finite_numbers_only(cls, audit: dict[str, Any]) -> dict[str, Any]:
        # Parity gate r2 A3 (2026-09-27): refuse, never echo a changed report (NaN/inf would come back null).
        if holds_non_finite(audit):
            raise ValueError("the audit holds a non-finite number (NaN, Infinity or an overflow such as 1e999); "
                             "a Java JournalIntegrityReport never does")
        return audit


class JavaAuditResponse(BaseModel):
    java: UniformVerdict
    python: UniformVerdict | None
    agree: Literal["YES", "NO", "NOT_COMPARABLE"] | None


class Health(BaseModel):
    status: Literal["ok"]


class ToolHttp(BaseModel):
    method: str
    path: str


class ToolSpec(BaseModel):
    name: str
    description: str
    read_only: bool
    http: ToolHttp
    input_schema: dict[str, Any]


# ---------------------------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------------------------

def build_tool_catalog(app: FastAPI) -> list[dict[str, Any]]:
    """One tool per POST route under /v1/; input_schema = that route's OpenAPI request component."""
    spec = app.openapi()
    components = spec.get("components", {}).get("schemas", {})
    tools = []
    for route in app.routes:
        if not (isinstance(route, APIRoute) and "POST" in route.methods and route.path.startswith("/v1/")):
            continue
        schema = spec["paths"][route.path]["post"]["requestBody"]["content"]["application/json"]["schema"]
        if "$ref" in schema:
            schema = components[schema["$ref"].rsplit("/", 1)[1]]
        tools.append({
            "name": route.name,
            "description": route.description or route.summary or "",
            "read_only": True,
            "http": {"method": "POST", "path": route.path},
            "input_schema": schema,
        })
    return tools


def create_app(settings: Settings | None = None, *, environ: dict[str, str] | None = None) -> FastAPI:
    if settings is None:
        settings = load_settings(environ)
    if not settings.key_hashes:
        raise ConfigError(ENV_KEYS_FILE + " holds no key lines (fail-closed).")

    app = FastAPI(
        title="LedgerMind API",
        version="0.1.0",
        description=(
            "Local verification service over the LedgerMind double-entry ledger. Verdicts come from the "
            "deterministic Python checker (tools.verify_report) run in a child process; no model is involved. "
            "POST /v1/java/audit interprets the Java ledger's own audit report uploaded as JSON (the service "
            "never calls Java). Every route requires the X-API-Key header."
        ),
        dependencies=[Security(API_KEY_SCHEME)],
        default_response_class=AsciiJSONResponse,
    )
    app.state.settings = settings
    # add_middleware: the LAST added is the OUTERMOST, so auth wraps the size guard.
    app.add_middleware(BodyLimitMiddleware, max_body_bytes=settings.max_body_bytes,
                       max_json_depth=settings.max_json_depth, body_timeout_s=settings.body_timeout_s)
    app.add_middleware(ApiKeyAuthMiddleware, key_hashes=settings.key_hashes)

    def problem_response(request: Request, status: int, code: str, title: str, detail: str,
                         **extra: Any) -> JSONResponse:
        return JSONResponse(problem_body(status, code, title, detail, _request_id(request.scope), **extra),
                            status_code=status, media_type=PROBLEM_MEDIA_TYPE)

    @app.exception_handler(ApiProblem)
    async def _api_problem(request: Request, exc: ApiProblem) -> JSONResponse:
        return problem_response(request, exc.status, exc.code, exc.title, exc.detail, **exc.extra)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"type": e.get("type"), "loc": list(e.get("loc", ())), "msg": e.get("msg")} for e in exc.errors()]
        return problem_response(request, 422, "validation_error", "Request validation failed",
                                "the request body does not match the schema", errors=errors)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {404: "not_found", 405: "method_not_allowed"}
        return problem_response(request, exc.status_code, codes.get(exc.status_code, "http_error"),
                                str(exc.detail), str(exc.detail))

    async def run_limited(request: Request, job: Callable[[], CliRun]) -> CliRun:
        loop = asyncio.get_running_loop()
        holder = getattr(request.app.state, "limiter_holder", None)
        if holder is None or holder[0] is not loop:
            holder = (loop, anyio.CapacityLimiter(settings.max_concurrent))
            request.app.state.limiter_holder = holder
        return await anyio.to_thread.run_sync(job, limiter=holder[1])

    def verdict(request: Request, run: CliRun, subject: str, started: float) -> dict[str, Any]:
        result = map_python(run, subject)
        result["request_id"] = _request_id(request.scope)
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result

    @app.get("/v1/health", response_model=Health, summary="Liveness (authenticated)")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/verify/corpus",
        response_model=UniformVerdict,
        name="verify_corpus",
        summary="Verify a registered corpus",
        description=(
            "Run the deterministic Python verifier on a corpus registered on the server (by id, never a path). "
            "Recorded corpora take half=clean|tampered; adversarial corpora take case=<name>. Any verdict, "
            "including TAMPER_SUSPECTED, is HTTP 200: the verdict is data. Read-only."
        ),
    )
    async def verify_corpus(body: VerifyCorpusRequest, request: Request) -> dict[str, Any]:
        entry = settings.corpora.get(body.corpus_id)
        if entry is None:
            raise ApiProblem(404, "not_found", "Unknown corpus", "no corpus is registered under that corpus_id")
        if entry.kind == "recorded":
            if body.case is not None:
                raise ApiProblem(422, "validation_error", "Wrong selector", "a recorded corpus takes half, not case")
            half = body.half or "clean"
            args = ["--corpus", "recorded", "--half", half]
            subject = "corpus:" + body.corpus_id + "/" + half
        else:
            if body.case is None or body.half is not None:
                raise ApiProblem(422, "validation_error", "Wrong selector", "an adversarial corpus takes case")
            if not (corpus_dir(settings, entry) / (body.case + ".json")).is_file():
                raise ApiProblem(404, "not_found", "Unknown case", "the corpus has no such case")
            args = ["--corpus", "adversarial", "--case", body.case]
            subject = "corpus:" + body.corpus_id + "/" + body.case
        if entry.root is not None:
            args += ["--corpus-root", str(entry.root)]
        started = time.monotonic()
        run = await run_limited(request, lambda: run_cli(settings.py_exe, settings.repo_root, args, settings.timeout_s))
        return verdict(request, run, subject, started)

    @app.post(
        "/v1/verify/snapshot",
        response_model=UniformVerdict,
        name="verify_snapshot",
        summary="Verify an uploaded snapshot",
        description=(
            "Upload a snapshot as JSON CONTENT (never a path) and run the deterministic Python verifier on it. "
            "kind=recorded: files={name: content} with postings_and_hashes.json required; kind=adversarial: one "
            "document. The verdict is byte-identical to the CLI's on the same files. The snapshot's provenance "
            "is not authenticated. Read-only."
        ),
    )
    async def verify_snapshot(body: VerifySnapshotRequest, request: Request) -> dict[str, Any]:
        snapshot = body.root
        started = time.monotonic()
        if isinstance(snapshot, RecordedSnapshot):
            subject = "upload:recorded/" + snapshot.label
            run = await run_limited(request, lambda: verify_recorded_upload(
                settings.py_exe, settings.repo_root, snapshot.label, snapshot.files, settings.timeout_s))
        else:
            subject = "upload:adversarial/" + snapshot.case_label
            run = await run_limited(request, lambda: verify_adversarial_upload(
                settings.py_exe, settings.repo_root, snapshot.case_label, snapshot.document, settings.timeout_s))
        return verdict(request, run, subject, started)

    @app.post(
        "/v1/java/audit",
        response_model=JavaAuditResponse,
        name="interpret_java_audit",
        summary="Interpret the Java ledger's own audit report",
        description=(
            "Map the Java ledger's JournalIntegrityReport (uploaded as JSON; the service never calls Java) to the "
            "uniform verdict: tamperDetected wins, coverage states are COVERAGE_DEGRADED or INCOMPLETE, an "
            "unknown shape is ERROR. With an optional recorded snapshot the Python verifier also runs and agree "
            "is YES, NO or NOT_COMPARABLE. agree compares two readings of whatever was uploaded; neither "
            "input's provenance is authenticated. Any verdict is HTTP 200. Read-only."
        ),
    )
    async def interpret_java_audit(body: JavaAuditRequest, request: Request) -> dict[str, Any]:
        started = time.monotonic()
        java = map_java(body.audit, "upload:java-audit")
        java["request_id"] = _request_id(request.scope)
        python = None
        snapshot = body.snapshot
        if snapshot is not None:
            run = await run_limited(request, lambda: verify_recorded_upload(
                settings.py_exe, settings.repo_root, snapshot.label, snapshot.files, settings.timeout_s))
            python = verdict(request, run, "upload:recorded/" + snapshot.label, started)
        java["duration_ms"] = int((time.monotonic() - started) * 1000)
        return {"java": java, "python": python,
                "agree": agree(java["status"], None if python is None else python["status"])}

    @app.get("/v1/tools", response_model=list[ToolSpec], summary="Agent-callable tool catalog")
    async def tools() -> list[dict[str, Any]]:
        return build_tool_catalog(app)

    return app
