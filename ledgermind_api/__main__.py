"""``py -m ledgermind_api`` - start the service on 127.0.0.1:8088 (LEDGERMIND_API_HOST/PORT override).

Fail-closed: a configuration error prints the VARIABLE name (never a value) and exits 2.

Slow clients (security gate r1 A5, 2026-09-27): uvicorn's own timeouts do not bound a request body that
trickles in (measured before the fix: a body dripping 1 byte every 0.4 s got no answer in 8 s). The app
gives every request body LEDGERMIND_API_BODY_TIMEOUT_S (default 10 s) to arrive in full, else 408 and the
connection closes. NOT bounded here and not tested: a client that never finishes its HEADERS, and
connection-count exhaustion. Beyond 127.0.0.1, put a reverse proxy with its own header/body timeouts in front.
"""

from __future__ import annotations

import sys

from .config import DEFAULT_HOST, ConfigError, load_settings


def main() -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        print("ledgermind_api: refusing to start (fail-closed): " + str(exc), file=sys.stderr)
        return 2
    try:
        import uvicorn

        from .app import create_app
    except ImportError:
        print("ledgermind_api: FastAPI/uvicorn are not installed; install the optional extra: "
              "pip install -e .[api]", file=sys.stderr)
        return 3
    try:
        app = create_app(settings)
    except ConfigError as exc:
        print("ledgermind_api: refusing to start (fail-closed): " + str(exc), file=sys.stderr)
        return 2
    if settings.host != DEFAULT_HOST:
        print("ledgermind_api: WARNING binding " + settings.host + " - there is no TLS; keep it on a private "
              "network or behind a TLS proxy", file=sys.stderr)
    uvicorn.run(app, host=settings.host, port=settings.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
