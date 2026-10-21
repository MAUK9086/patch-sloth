"""Parse NVD yearly feeds into one table: one row per CVE with the CNA's CVSS 3.1 vector,
NVD's own vector (if any), the training label, and serve-time-safe features.

Label rule (Task A): for CVEs NVD has Analyzed/Modified and that carry a CNA v3.1 score:
  label = NVD Primary vector if NVD added one, else the CNA vector (NVD reviewed and kept it).
Evidence for the rule: since mid-2025, when NVD adds its own score it differs from the CNA 80-95%
of the time, i.e. NVD mostly writes its own score only when it disagrees (see results/label_check.txt).
"""
import glob, json, lzma, sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.cvss import parse, base_score, sev_rank

RAW = Path("data/raw")
CISA_ADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
kev = {v["cveID"]: v["dateAdded"] for v in json.load(open(RAW / "kev.json"))["vulnerabilities"]}

rows = []
for f in sorted(glob.glob(str(RAW / "CVE-*.json.xz"))):
    for c in json.load(lzma.open(f))["cve_items"]:
        status = c.get("vulnStatus")
        if status == "Rejected":
            continue
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
        rows.append(dict(
            cve=c["id"], published=c["published"][:10], status=status, cna=cna_src,
            score_source=("CNA" if sec_cna and sec_cna[0]["source"] == cna_src else "CISA-ADP" if sec_cna and sec_cna[0]["source"] == CISA_ADP else ("other" if sec_cna else None)),
            description=desc, cna_vector=cna_vec, nvd_vector=nvd_vec, cna_cwe=";".join(cna_cwes),
            n_refs=len(refs), ref_github=any("github.com" in u for u in refs),
            ref_exploitdb=any("exploit-db" in u or "packetstorm" in u for u in refs),
            has_v40=bool(c.get("metrics", {}).get("cvssMetricV40")), has_cpe=bool(c.get("configurations")),
            kev_date=kev.get(c["id"]),
        ))
df = pd.DataFrame(rows)

def label(r):
    if r.status in ("Analyzed", "Modified") and isinstance(r.cna_vector, str):
        return r.nvd_vector if isinstance(r.nvd_vector, str) else r.cna_vector
    return None
df["label_vector"] = df.apply(label, axis=1)
for col in ["cna", "label"]:
    v = df[f"{col}_vector"]
    df[f"{col}_score"] = v.map(lambda s: base_score(parse(s)) if isinstance(s, str) else None)
    df[f"{col}_sev"] = df[f"{col}_score"].map(lambda s: sev_rank(s) if pd.notna(s) else None)
df["bump_up"] = (df.label_sev > df.cna_sev).where(df.label_vector.notna())
df["vector_changed"] = pd.Series([parse(a) != parse(b) if isinstance(a, str) else None
                                  for a, b in zip(df.label_vector, df.cna_vector)], index=df.index)
df["nvd_own"] = df.nvd_vector.notna()

# time-based split for Task A
p = pd.to_datetime(df.published)
df["split"] = None
lab = df.label_vector.notna()
df.loc[lab & (p < "2025-07-01"), "split"] = "train"
df.loc[lab & (p >= "2025-07-01") & (p < "2026-01-01"), "split"] = "val"
df.loc[lab & (p >= "2026-01-01"), "split"] = "test"
df.loc[(df.status == "Deferred") & df.cna_vector.notna(), "split"] = "deferred_unlabeled"
Path("data").mkdir(exist_ok=True)
df.to_parquet("data/cves.parquet", index=False)

print("rows", len(df))
print(df.split.value_counts(dropna=False).to_string())
s = df[df.split.isin(["train", "val", "test"])]
print("\nper split: n, NVD wrote own score, vector changed, severity bumped UP, bumped DOWN")
for k, g in s.groupby("split"):
    print(k, len(g), round(g.nvd_own.mean(), 3), round(g.vector_changed.astype(float).mean(), 3), round(g.bump_up.astype(float).mean(), 3), round((g.label_sev < g.cna_sev).mean(), 3))
