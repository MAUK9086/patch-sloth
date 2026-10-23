# Patch Sloth API + web page for DigitalOcean App Platform (deploy/do-app.yaml). Build context: this project folder.
#   docker build -f deploy/Dockerfile -t patchsloth .
#   docker run -p 8080:8080 --env-file .env patchsloth
# At start-up the app downloads the newest feed-* GitHub release (feed parquet + HGB fallback model) in the
# background; /health reports which release it serves. osv-scanner and its npm/PyPI offline DB are baked in at build
# time, so lockfile contents never leave the container (scan.run_osv uses --offline).
FROM python:3.11-slim

ARG OSV_VERSION=2.7.0
# sha256 of osv-scanner_linux_amd64 v2.7.0 (GitHub release asset digest, 2026-10-24)
ARG OSV_SHA256=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATCHSLOTH_ROOT=/app \
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db \
    PORT=8080

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /usr/local/bin/osv-scanner \
       "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
    && echo "${OSV_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c - \
    && chmod +x /usr/local/bin/osv-scanner

WORKDIR /app
COPY requirements-app.txt .
RUN pip install --no-cache-dir -r requirements-app.txt

# Pre-download the npm and PyPI vulnerability DBs by scanning the fixture lockfiles once (exit code 1 = "found
# vulnerabilities", which is expected). The DB is as fresh as the image: redeploy to refresh it.
COPY tests/fixtures/package-lock.json tests/fixtures/requirements.txt /tmp/osv-warm/
RUN osv-scanner scan source --offline-vulnerabilities --download-offline-databases --format json \
       -L /tmp/osv-warm/package-lock.json -L /tmp/osv-warm/requirements.txt > /dev/null; \
    rc=$?; [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ] \
    && rm -rf /tmp/osv-warm && ls /opt/osv-db

COPY patchsloth/ patchsloth/
COPY web/ web/
COPY results/thresholds.json results/data_as_of.txt results/

RUN useradd --create-home --uid 10001 app \
    && mkdir -p /app/feed /app/data/models \
    && chown -R app:app /app/feed /app/data /opt/osv-db
USER app

EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn patchsloth.api:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
