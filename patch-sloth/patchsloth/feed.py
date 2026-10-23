"""Nightly feed (SPEC §5, §9.2): second opinions for every unanalysed CVE, plus the lookup table the
serve path uses for every scanned CVE.

feed/second_opinion.parquet  one row per CVE in the dataset:
  source = "model"  Deferred / Awaiting Analysis / Received with a CNA vector: p_bump + predicted_vector, plus
                    bump_band (likely / possible / unlikely: what users see), p_bump_cal (isotonic) and bump_high
  source = "nvd"    NVD analysed it: predicted_vector = the NVD-final vector (label rule), no p_bump
  source = "none"   no CNA v3.1 vector to second-guess
feed/latest.csv              the open data feed: source == "model" rows only, without descriptions; it carries
                             the band and the calibrated probability, not the raw score
CVEs missing from the feed are scored on demand by the CPU fallback model (HGB), never by the GPU feed model.
"""
import json
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

from . import config
from .cvss import base_score, parse, severity
from .data import epss as epss_mod
from .data.nvd import label_vector, parse_record
from .llm.backends import get_backend
from .tabular import BumpModel

FEED_FILE = config.FEED / "second_opinion.parquet"
CSV_FILE = config.FEED / "latest.csv"
META_FILE = config.FEED / "meta.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
COLUMNS = ["cve", "published", "status", "cna", "cna_cwe", "score_source", "description", "cna_vector",
           "predicted_vector", "p_bump", "source", "llm_backend", "epss", "kev_date", "n_refs", "ref_github",
           "ref_exploitdb", "has_v40", "p_bump_cal", "bump_band", "bump_high", "bump_model"]
BAND_COLUMNS = ["p_bump_cal", "bump_band", "bump_high", "bump_model"]


def _sev(v):
    return severity(base_score(parse(v))) if isinstance(v, str) else None


def score_rows(df: pd.DataFrame, model: BumpModel | None, backend=None) -> pd.DataFrame:
    """Adds predicted_vector, p_bump, source to rows shaped like cves.parquet (or parse_record output)."""
    df = df.copy()
    backend = backend or get_backend("null")
    unanalysed = df.status.isin(config.UNANALYSED_STATUSES) & df.cna_vector.map(lambda v: isinstance(v, str))
    nvd = df["nvd_vector"] if "nvd_vector" in df else pd.Series(None, index=df.index, dtype=object)
    labels = [label_vector(s, c, n) for s, c, n in zip(df.status, df.cna_vector, nvd)]
    df["predicted_vector"] = labels
    df["p_bump"] = np.nan
    df["source"] = np.where(pd.Series(labels, index=df.index).notna(), "nvd", "none")
    if unanalysed.any():
        u = df[unanalysed]
        df.loc[unanalysed, "predicted_vector"] = backend.predict_vectors(list(u.itertuples()))
        if model is not None:
            p = model.predict(u)
            df.loc[unanalysed, "p_bump"] = p
            df.loc[unanalysed, "bump_model"] = model.name
            bands = getattr(model, "bands", None)  # models saved before scripts/15 have none
            if bands is not None:
                df.loc[unanalysed, "p_bump_cal"] = bands.calibrate(p)
                df.loc[unanalysed, "bump_band"] = bands.band(p)
                df.loc[unanalysed, "bump_high"] = p >= bands.tau_high
        df.loc[unanalysed, "source"] = "model"
    for c in BAND_COLUMNS:
        if c not in df:
            df[c] = None
    df["llm_backend"] = np.where(df.source == "model", backend.name, None)
    return df


def build(since: str | None = None, model_name: str = "hgb", no_llm: bool = True,
          dataset: Path = config.CVES_PARQUET, out_dir: Path = config.FEED, fallback_model: str = "hgb") -> dict:
    """Score the dataset and write the feed. `since` limits the CSV to CVEs published on/after a date."""
    df = pd.read_parquet(dataset)
    model = BumpModel.load(name=model_name)
    backend = get_backend("null" if no_llm else None)
    scores, score_date = epss_mod.load()
    df["epss"] = df.cve.map(scores)
    df = score_rows(df, model, backend)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    df[COLUMNS].to_parquet(out_dir / FEED_FILE.name, index=False)
    pub = df[df.source == "model"]
    if since:
        pub = pub[pub.published >= since]
    pub = pub.assign(cna_severity=pub.cna_vector.map(_sev), predicted_severity=pub.predicted_vector.map(_sev))
    pub = pub.sort_values("p_bump", ascending=False)
    pub = pub.rename(columns={"p_bump_cal": "p_bump_calibrated"})
    pub[["cve", "published", "status", "cna", "cna_vector", "cna_severity", "predicted_vector",
         "predicted_severity", "bump_band", "p_bump_calibrated", "bump_model", "llm_backend", "epss", "kev_date"]] \
        .to_csv(out_dir / CSV_FILE.name, index=False, float_format="%.4f")
    # serving data date (scripts/01 stamps it); results/data_as_of.txt is the frozen evaluation snapshot
    as_of = config.DATA / "data_as_of.txt"
    fb = BumpModel.load(name=fallback_model)
    meta = dict(data_as_of=as_of.read_text().strip() if as_of.exists() else None, epss_date=score_date,
                model=model_name, fallback_model=fallback_model, llm_backend=backend.name,
                bands={m.name: m.bands.as_dict() for m in (model, fb) if getattr(m, "bands", None) is not None},
                n_rows=len(df), n_model=int((df.source == "model").sum()), n_csv=len(pub))
    (out_dir / META_FILE.name).write_text(json.dumps(meta, indent=1, default=float))
    return meta


class Feed:
    """Serve-time lookups. Loads the feed once; CVEs missing from it can be fetched from the NVD API."""

    def __init__(self, path: Path = FEED_FILE):
        self.path = Path(path)
        self.df = pd.read_parquet(self.path).set_index("cve") if self.path.exists() else None
        meta = self.path.parent / META_FILE.name
        self.meta = json.loads(meta.read_text()) if meta.exists() else {}
        self._model = None

    @property
    def data_as_of(self) -> str | None:
        return self.meta.get("data_as_of")

    def model(self) -> BumpModel | None:
        if self._model is None:
            try:
                # on-demand rows use the CPU fallback (the feed model may need a GPU)
                self._model = BumpModel.load(name=self.meta.get("fallback_model", "hgb"))
            except FileNotFoundError:
                return None
        return self._model

    def get(self, cve: str) -> dict | None:
        if self.df is None or cve not in self.df.index:
            return None
        r = self.df.loc[cve]
        return {"cve": cve, **{k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in r.items()}}

    def on_demand(self, cve: str, backend=None, fetch: bool = True, timeout: float = 10) -> dict | None:
        """CVE newer than the feed: fetch its NVD record, then LLM second opinion + HGB fallback."""
        if not fetch:
            return None
        try:
            with urllib.request.urlopen(NVD_API.format(cve), timeout=timeout) as resp:
                vulns = json.load(resp).get("vulnerabilities", [])
        except Exception:
            return None
        if not vulns:
            return None
        rec = parse_record(vulns[0]["cve"], kev={})
        if rec is None:
            return None
        row = score_rows(pd.DataFrame([rec]), self.model(), backend).iloc[0].to_dict()
        row["source"] = row["source"] + "-on-demand"
        return {k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in row.items()}
