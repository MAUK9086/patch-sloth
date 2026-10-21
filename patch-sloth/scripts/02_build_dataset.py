"""Parse NVD yearly feeds into one table: one row per CVE with the CNA's CVSS 3.1 vector,
NVD's own vector (if any), the training label, and serve-time-safe features.
Logic lives in patchsloth/data/nvd.py (label rule: SPEC §8.2).
Evidence for the rule: since mid-2025, when NVD adds its own score it differs from the CNA 80-95%
of the time, i.e. NVD mostly writes its own score only when it disagrees.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.data.nvd import build_dataset  # noqa: E402

df = build_dataset(Path("data/raw"))
Path("data").mkdir(exist_ok=True)
df.to_parquet("data/cves.parquet", index=False)

print("rows", len(df))
print(df.split.value_counts(dropna=False).to_string())
s = df[df.split.isin(["train", "val", "test"])]
print("\nper split: n, NVD wrote own score, vector changed, severity bumped UP, bumped DOWN")
for k, g in s.groupby("split"):
    print(k, len(g), round(g.nvd_own.mean(), 3), round(g.vector_changed.astype(float).mean(), 3),
          round(g.bump_up.astype(float).mean(), 3), round((g.label_sev < g.cna_sev).mean(), 3))
