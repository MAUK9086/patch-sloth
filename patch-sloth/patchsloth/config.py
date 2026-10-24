"""Paths, thresholds, model names and prices. Secrets and overrides come from the environment (.env)."""
import json
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # dotenv is optional for the data scripts
    pass

ROOT = Path(os.environ.get("PATCHSLOTH_ROOT", Path(__file__).resolve().parents[1]))
DATA = ROOT / "data"
RAW = DATA / "raw"
MODELS = DATA / "models"
RESULTS = ROOT / "results"
FEED = ROOT / "feed"
WEB = ROOT / "web"
CVES_PARQUET = DATA / "cves.parquet"
ADVISORY_DB = RAW / "advisory-database" / "advisories" / "github-reviewed"

CISA_ADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"

# time-based splits (SPEC §8.3)
VAL_START = "2025-07-01"
TEST_START = "2026-01-01"
LABELED_STATUSES = ("Analyzed", "Modified")
UNANALYSED_STATUSES = ("Deferred", "Awaiting Analysis", "Received", "Undergoing Analysis")

# Task B thresholds (SPEC §9.2, §11.3). Tuned on val by scripts/07 and written to results/thresholds.json.
THRESHOLDS_FILE = RESULTS / "thresholds.json"
# the published feed: GitHub releases tagged feed-YYYY-MM-DD; the app downloads the newest at start-up
FEED_REPO = os.environ.get("PATCHSLOTH_FEED_REPO", "MAUK9086/patch-sloth")
FEED_DOWNLOAD = os.environ.get("PATCHSLOTH_FEED_DOWNLOAD", "1").strip().lower() not in ("0", "false", "no", "off")
FEED_ASSETS = ("second_opinion.parquet", "latest.csv", "meta.json", "bump_hgb.joblib")
# scanner: auto (osv-scanner if installed, else the GHSA index) | osv | fallback. The deployed app uses fallback:
# an offline osv-scanner run reloads its npm DB per request (~30 s, ~0.6 GB measured; DECISIONS.md 2026-10-25)
SCAN_ENGINE = os.environ.get("PATCHSLOTH_SCAN_ENGINE", "auto").strip().lower() or "auto"


def thresholds() -> dict:
    """tau / tau_high for the bump classifier; falls back to 0.5 / 0.8 if 07 has not been run."""
    if THRESHOLDS_FILE.exists():
        return json.loads(THRESHOLDS_FILE.read_text())
    return {"tau": 0.5, "tau_high": 0.8, "source": "default"}


EPSS_P0 = 0.10

# LLM (SPEC §9.1, §11.4, §11.7)
BASE_MODEL = "Qwen/Qwen3-8B"
# tinker_cookbook renderer for Qwen3 with thinking disabled (VERIFIED 2026-10-23 against get_renderer docs);
# serving must render the same way (chat template with enable_thinking=False)
TINKER_RENDERER = "qwen3_disable_thinking"
# USD per 1M tokens for Qwen/Qwen3-8B (tinker-docs models_and_pricing, VERIFIED 2026-10-23)
TINKER_PRICE = {"train": 0.44, "prefill": 0.195, "prefill_cached": 0.039, "sample": 0.60}
TINKER_BUDGET_USD = 9.0  # abort above this (promo credit is $10)
LLM_BACKEND = os.environ.get("PATCHSLOTH_LLM_BACKEND", "null")
VLLM_BASE_URL = os.environ.get("VLLM_BASE_URL", "")
VLLM_API_KEY = os.environ.get("VLLM_API_KEY", "")
VLLM_MODEL = "patchsloth"

ULTRAMARINE_BASE_URL = os.environ.get("PAPERINSTRUMENTS_BASE_URL", "https://api.paperinstruments.com/v1")
ULTRAMARINE_MODEL = os.environ.get("PAPERINSTRUMENTS_MODEL", "ultramarine-1-flash")
PAPERINSTRUMENTS_API_KEY = os.environ.get("PAPERINSTRUMENTS_API_KEY", "")
# USD per 1M tokens (SPEC §11.4, as of 2026-10-15)
ULTRAMARINE_PRICE = {"input": 0.15, "cached_input": 0.03, "output": 0.50}

OSV_DB_DIR = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "")

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
RATE_LIMIT_PER_MIN = int(os.environ.get("PATCHSLOTH_RATE_LIMIT_PER_MIN", "20"))
