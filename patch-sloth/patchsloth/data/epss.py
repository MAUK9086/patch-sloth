"""EPSS scores (FIRST / Empirical Security). Report field only, never a model feature.
Daily file: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz (history: epss_scores-YYYY-MM-DD.csv.gz).
The CSV starts with a '#model_version:...,score_date:...' comment line, then cve,epss,percentile."""
import gzip
import urllib.request
from pathlib import Path

import pandas as pd

from ..config import RAW

BASE = "https://epss.empiricalsecurity.com"


def url(date: str | None = None) -> str:
    return f"{BASE}/epss_scores-{date or 'current'}.csv.gz"


def download(date: str | None = None, out_dir: Path = RAW) -> Path:
    out = Path(out_dir) / ("epss_current.csv.gz" if date is None else f"epss_{date}.csv.gz")
    out.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url(date), out)
    return out


def load(path: Path = RAW / "epss_current.csv.gz") -> tuple[dict, str | None]:
    """Returns ({cve: epss}, score_date). Empty dict if the file is missing."""
    path = Path(path)
    if not path.exists():
        return {}, None
    with gzip.open(path, "rt") as f:
        header = f.readline()
    score_date = next((p.split(":", 1)[1][:10] for p in header.lstrip("#").strip().split(",")
                       if p.startswith("score_date")), None)
    df = pd.read_csv(path, comment="#")
    return dict(zip(df.cve, df.epss.astype(float))), score_date
