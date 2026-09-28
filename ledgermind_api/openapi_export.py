"""Write the committed OpenAPI document: ``py -m ledgermind_api.openapi_export [path]`` (default
``docs/openapi.json``). The drift test in tests_api compares that file with the live app's schema.

The schema does not depend on any key, so the app is built with a throwaway in-memory key hash
that matches no real key; no keys file is read and nothing secret is written.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .config import REPO_ROOT, Settings

DEFAULT_PATH = REPO_ROOT / "docs" / "openapi.json"


def render() -> str:
    from .app import create_app  # imported here so the module help works without FastAPI

    app = create_app(Settings(key_hashes=(("openapi-export", bytes(32)),)))
    return json.dumps(app.openapi(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    target = Path(args[0]) if args else DEFAULT_PATH
    target.write_text(render(), encoding="utf-8", newline="\n")
    print("wrote " + str(target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
