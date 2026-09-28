"""LedgerMind API: an OPTIONAL, local, API-key-authenticated FastAPI service over the
zero-dependency verifier CLI (``tools.verify_report``).

This package lives OUTSIDE ``src/ledger_verification_agent`` on purpose. It never imports the
verifier: every verdict comes from the CLI run in a CHILD PROCESS, and the CLI's exit code plus
its stdout JSON are passed through unchanged as ``native``. So the verifier's import closure stays
free of FastAPI and of any network client (guarded by tests/test_api_outside_verifier_closure.py).

This ``__init__`` imports nothing, so ``py -m ledgermind_api.keygen`` runs without FastAPI.
Install the service's dependencies with the optional extra: ``pip install -e .[api]``.
"""
