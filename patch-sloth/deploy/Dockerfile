# Patch Sloth API + web page for DigitalOcean App Platform (deploy/do-app.yaml). Build context: this project folder.
#   docker build -f deploy/Dockerfile -t patchsloth .
#   docker run -p 8080:8080 --env-file .env patchsloth
# Everything the app needs at start-up is baked in, so a GitHub API rate limit at boot cannot leave it empty:
#   - the GHSA advisory index (scanner used by the deployed app, PATCHSLOTH_SCAN_ENGINE=fallback; built below)
#   - the feed release FEED_TAG (parquet, CSV, meta, HGB fallback model). At start-up the app still checks for a
#     newer feed-* release and downloads it if there is one; otherwise it serves the baked feed.
#   - osv-scanner + its npm/PyPI offline DB (opt-in with PATCHSLOTH_SCAN_ENGINE=osv; ~30 s and ~0.6 GB per scan)

# ---- stage 1: GitHub Advisory DB (github-reviewed) -> compact npm/PyPI index (patchsloth.scan.build_index)
FROM python:3.11-slim AS advisories
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir packaging==26.3 semver==3.1.0
WORKDIR /build
COPY patchsloth/ patchsloth/
RUN git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database.git /tmp/adb \
    && git -C /tmp/adb sparse-checkout set advisories/github-reviewed \
    && mkdir -p /out \
    && git -C /tmp/adb log -1 --format='%H %cI' > /out/advisory_db_commit.txt \
    && python -c "from pathlib import Path; from patchsloth.scan import build_index; \
build_index(Path('/tmp/adb/advisories/github-reviewed'), Path('/out/advisory_index.json.gz'))" \
    && ls -la /out && rm -rf /tmp/adb

# ---- stage 2: the app
FROM python:3.11-slim

ARG OSV_VERSION=2.7.0
# sha256 of osv-scanner_linux_amd64 v2.7.0 (GitHub release asset digest, checked 2026-10-24)
ARG OSV_SHA256=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG FEED_REPO=MAUK9086/patch-sloth
ARG FEED_TAG=feed-2026-10-23

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATCHSLOTH_ROOT=/app \
    PATCHSLOTH_SCAN_ENGINE=fallback \
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

# osv-scanner's npm + PyPI offline DBs (~245 MB): scan the fixture lockfiles once. Exit code 1 means "found
# vulnerabilities", which is expected; anything else fails the build.
COPY tests/fixtures/package-lock.json tests/fixtures/requirements.txt /tmp/osv-warm/
RUN rc=0; osv-scanner scan source --offline-vulnerabilities --download-offline-databases --format json \
       -L /tmp/osv-warm/package-lock.json -L /tmp/osv-warm/requirements.txt > /dev/null || rc=$?; \
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then echo "osv-scanner warm-up failed: $rc"; exit 1; fi; \
    rm -rf /tmp/osv-warm && du -sh /opt/osv-db

# the feed release (public GitHub release assets; not the API, so no rate limit)
RUN mkdir -p /app/feed /app/data/models \
    && for f in second_opinion.parquet latest.csv meta.json; do \
         curl -fsSL -o "/app/feed/$f" "https://github.com/${FEED_REPO}/releases/download/${FEED_TAG}/$f"; done \
    && curl -fsSL -o /app/data/models/bump_hgb.joblib \
         "https://github.com/${FEED_REPO}/releases/download/${FEED_TAG}/bump_hgb.joblib" \
    && echo "${FEED_TAG}" > /app/feed/release_tag.txt \
    && ls -la /app/feed /app/data/models

COPY --from=advisories /out/advisory_index.json.gz /out/advisory_db_commit.txt /app/data/
COPY patchsloth/ patchsloth/
COPY web/ web/
COPY results/thresholds.json results/data_as_of.txt results/

RUN useradd --create-home --uid 10001 app \
    && chown -R app:app /app/feed /app/data /opt/osv-db
USER app

EXPOSE 8080
# --proxy-headers: the per-IP rate limit sees the client IP behind App Platform's proxy (spoofable; demo only)
CMD ["sh", "-c", "exec uvicorn patchsloth.api:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
