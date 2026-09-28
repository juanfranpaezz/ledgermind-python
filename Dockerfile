# LedgerMind API (optional FastAPI service) - local container image.
# Keys are NEVER baked in: mount the hash-only keys file read-only at run time, e.g.
#   docker run --rm -p 127.0.0.1:8088:8088 \
#     -v "$HOME/.ledgermind-api/api-keys.txt:/run/secrets/ledgermind-api-keys:ro" ledgermind-api
# Without the mount the service refuses to start (fail-closed, exit non-zero).
# Publish on 127.0.0.1 only: there is no TLS.
FROM python:3.13-slim

# openssl on PATH lets the verifier CLI check the ML-DSA-65 checkpoint signature (needs >= 3.5);
# with an older openssl the clean half is INCOMPLETE, which the API reports identically to the CLI.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin ledgermind

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tools ./tools
COPY ledgermind_api ./ledgermind_api
COPY tests/fixtures ./tests/fixtures
RUN pip install --no-cache-dir ".[api]"

ENV LEDGERMIND_API_HOST=0.0.0.0 \
    LEDGERMIND_API_PORT=8088 \
    LEDGERMIND_API_KEYS_FILE=/run/secrets/ledgermind-api-keys \
    PYTHONDONTWRITEBYTECODE=1

USER 10001
EXPOSE 8088
CMD ["python", "-m", "ledgermind_api"]
