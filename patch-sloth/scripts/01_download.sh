#!/usr/bin/env bash
# Downloads all raw data. Run from repo root. ~60 MB compressed.
set -euo pipefail
mkdir -p data/raw && cd data/raw
for y in 2021 2022 2023 2024 2025 2026; do
  curl -sL -o CVE-$y.json.xz https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-$y.json.xz
done
curl -sL -o kev.json https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
# GitHub Advisory Database (what Dependabot uses) – npm + PyPI reviewed advisories, with CVE aliases
[ -d advisory-database ] || git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database.git
(cd advisory-database && git sparse-checkout set advisories/github-reviewed)
# EPSS: today's scores (history: https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz)
curl -sL -o epss_current.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz || echo "EPSS download failed (optional)"
echo done
