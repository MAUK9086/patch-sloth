"""NVD yearly feeds -> one row per CVE, the label rule (SPEC §8.2) and time-based splits (§8.3).

Label rule: for CVEs NVD has Analyzed/Modified that carry a CNA v3.1 vector,
label = NVD Primary vector if NVD wrote one, else the CNA vector (NVD reviewed and kept it).
Always test with isinstance(x, str): NaN is truthy, and a truthiness check once mislabelled ~40% of rows.
"""
import glob
import json
import lzma
from pathlib import Path

import pandas as pd

from ..config import CISA_ADP, LABELED_STATUSES, TEST_START, VAL_START
from ..cvss import base_score, parse, sev_rank


def load_kev(raw_dir: Path) -> dict:
    """CVE ID -> date added to CISA KEV."""
    with open(Path(raw_dir) / "kev.json", encoding="utf-8") as f:
        return {v["cveID"]: v["dateAdded"] for v in json.load(f)["vulnerabilities"]}


def parse_record(c: dict, kev: dict) -> dict | None:
    """One NVD JSON 2.0 CVE item -> one dataset row (None for Rejected CVEs)."""
    status = c.get("vulnStatus")
    if status == "Rejected":
        return None
    m = c.get("metrics", {}).get("cvssMetricV31", [])
    prim = [x for x in m if x["type"] == "Primary"]
    sec = [x for x in m if x["type"] == "Secondary"]
    cna_src = c.get("sourceIdentifier", "")
    sec_cna = [x for x in sec if x["source"] == cna_src] or [x for x in sec if x["source"] == CISA_ADP] or sec
    cna_vec = sec_cna[0]["cvssData"]["vectorString"] if sec_cna else None
    nvd_vec = prim[0]["cvssData"]["vectorString"] if prim else None
    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    cna_cwes = sorted({d["value"] for w in c.get("weaknesses", []) if w.get("type") == "Secondary"
                       for d in w["description"] if d["value"].startswith("CWE-")})
    refs = [r["url"] for r in c.get("references", [])]
    if not sec_cna:
        score_source = None
    elif sec_cna[0]["source"] == cna_src:
        score_source = "CNA"
    elif sec_cna[0]["source"] == CISA_ADP:
        score_source = "CISA-ADP"
    else:
        score_source = "other"
    return dict(
        cve=c["id"], published=c["published"][:10], status=status, cna=cna_src, score_source=score_source,
        description=desc, cna_vector=cna_vec, nvd_vector=nvd_vec, cna_cwe=";".join(cna_cwes),
        n_refs=len(refs), ref_github=any("github.com" in u for u in refs),
        ref_exploitdb=any("exploit-db" in u or "packetstorm" in u for u in refs),
        has_v40=bool(c.get("metrics", {}).get("cvssMetricV40")), has_cpe=bool(c.get("configurations")),
        kev_date=kev.get(c["id"]),
    )


def label_vector(status, cna_vector, nvd_vector) -> str | None:
    """SPEC §8.2. Returns the label vector or None. Never use truthiness here (NaN is truthy)."""
    if status in LABELED_STATUSES and isinstance(cna_vector, str):
        return nvd_vector if isinstance(nvd_vector, str) else cna_vector
    return None


def add_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Adds label_vector, {cna,label}_{score,sev}, bump_up, vector_changed, nvd_own."""
    df["label_vector"] = [label_vector(s, c, n) for s, c, n in zip(df.status, df.cna_vector, df.nvd_vector)]
    for col in ["cna", "label"]:
        v = df[f"{col}_vector"]
        df[f"{col}_score"] = v.map(lambda s: base_score(parse(s)) if isinstance(s, str) else None)
        df[f"{col}_sev"] = df[f"{col}_score"].map(lambda s: sev_rank(s) if pd.notna(s) else None)
    df["bump_up"] = (df.label_sev > df.cna_sev).where(df.label_vector.notna())
    df["vector_changed"] = pd.Series([parse(a) != parse(b) if isinstance(a, str) else None
                                      for a, b in zip(df.label_vector, df.cna_vector)], index=df.index)
    df["nvd_own"] = df.nvd_vector.notna()
    return df


def assign_splits(df: pd.DataFrame) -> pd.DataFrame:
    """train < VAL_START <= val < TEST_START <= test; Deferred with a CNA vector -> deferred_unlabeled."""
    p = pd.to_datetime(df.published)
    df["split"] = None
    lab = df.label_vector.notna()
    df.loc[lab & (p < VAL_START), "split"] = "train"
    df.loc[lab & (p >= VAL_START) & (p < TEST_START), "split"] = "val"
    df.loc[lab & (p >= TEST_START), "split"] = "test"
    df.loc[(df.status == "Deferred") & df.cna_vector.notna(), "split"] = "deferred_unlabeled"
    return df


def build_dataset(raw_dir: Path) -> pd.DataFrame:
    """Parse every data/raw/CVE-*.json.xz feed into the cves.parquet table (SPEC §8.1)."""
    kev = load_kev(raw_dir)
    rows = []
    for f in sorted(glob.glob(str(Path(raw_dir) / "CVE-*.json.xz"))):
        with lzma.open(f) as fh:
            for c in json.load(fh)["cve_items"]:
                r = parse_record(c, kev)
                if r is not None:
                    rows.append(r)
    return assign_splits(add_labels(pd.DataFrame(rows)))
