"""OPT-IN ML-DSA verification backend that shells out to an OpenSSL >= 3.5 CLI.

WHY THIS IS A SEPARATE MODULE AND IS NEVER IMPORTED BY THE VERIFIER.

1. **The default verdict must not depend on what is installed on the box.** A
   deterministic verifier whose answer changes between two machines is not
   deterministic. The core resolves only IN-PROCESS libraries and otherwise says
   ``UNVERIFIED-SIGNATURE``; using this backend is an explicit act by the caller.
2. **The verifier's import closure stays free of ``subprocess``.** The read-only
   reachability test walks that closure and would (correctly) fail if the core could
   spawn a process. Keeping this out of the closure is what lets that test stay
   strict instead of carrying an exception.

WHAT IT PROVES AND WHAT IT DOES NOT. It proves the ML-DSA-65 signature closes under
the public key the checkpoint itself carries: message INTEGRITY. It does NOT prove
who signed - the key travels with the row, so whoever can rewrite the row can swap
in their own (key, signature) pair. LedgerMind's own javadoc says exactly this. Real
signer authenticity needs a key anchored outside the database.

PROBED ON THIS MACHINE 2026-09-17 (Windows 11, Git Bash), both outcomes::

    openssl version                    -> OpenSSL 3.5.5 27 Jan 2026
    verify, canonical message          -> "Signature Verified Successfully", exit 0
    verify, one byte flipped           -> "Signature Verification Failure",  exit 1

It writes three files into a private temporary directory because ``openssl pkeyutl``
takes its key, message and signature as paths; the directory is created and removed
by ``tempfile.TemporaryDirectory`` and nothing else is touched.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

#: OpenSSL gained ML-DSA (FIPS 204) in 3.5. Below that the CLI cannot do this at all.
MINIMUM_OPENSSL = (3, 5)


class OpensslCliMlDsaBackend:
    """Verifies an ML-DSA signature with the ``openssl`` binary on PATH."""

    name = "openssl-cli"

    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or shutil.which("openssl") or "openssl"

    # -- capability, so a caller can fail closed instead of guessing ---------- #
    def version(self) -> tuple[int, ...] | None:
        try:
            proc = subprocess.run(
                [self.binary, "version"], capture_output=True, text=True, check=False
            )
        except OSError:
            return None
        if proc.returncode != 0:
            return None
        parts = proc.stdout.split()
        if len(parts) < 2:
            return None
        numbers = []
        for chunk in parts[1].split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            if not digits:
                break
            numbers.append(int(digits))
        return tuple(numbers) if numbers else None

    def available(self) -> bool:
        version = self.version()
        return version is not None and version[:2] >= MINIMUM_OPENSSL

    # -- the MlDsaBackend protocol -------------------------------------------- #
    def verify(self, message: bytes, signature: bytes, public_key_der: bytes) -> bool:
        if not self.available():
            raise RuntimeError(
                "openssl >= 3.5 is required for ML-DSA and is not available as " + self.binary
            )
        with tempfile.TemporaryDirectory(prefix="lva-mldsa-") as workdir:
            base = Path(workdir)
            key_path = base / "pub.der"
            msg_path = base / "msg.bin"
            sig_path = base / "sig.bin"
            key_path.write_bytes(public_key_der)
            msg_path.write_bytes(message)
            sig_path.write_bytes(signature)
            proc = subprocess.run(
                [
                    self.binary,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    str(key_path),
                    "-rawin",
                    "-in",
                    str(msg_path),
                    "-sigfile",
                    str(sig_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        if proc.returncode == 0 and "Verified Successfully" in proc.stdout:
            return True
        if "Verification Failure" in proc.stdout or "Verification Failure" in proc.stderr:
            return False
        raise RuntimeError(
            "openssl could not complete the verification (structural cause, NOT evidence of "
            "tamper): exit " + str(proc.returncode) + " stdout=" + proc.stdout.strip()
            + " stderr=" + proc.stderr.strip()
        )
