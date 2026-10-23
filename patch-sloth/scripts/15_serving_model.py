"""Build a serve-time bump model with its Bands (label-free cut-offs + isotonic calibration) and save it to
data/models/bump_<name>.joblib, for `patchsloth feed build --model <name>`.
  hgb     all train rows, CPU: the fallback for CVEs not in the feed (and the CPU-only feed)
  tabpfn  TabPFN-3.5 on a 50k train subsample (seed 0), GPU: the feed model
Cut-offs are quantiles of the model's own p_bump over deferred_unlabeled (no labels): likely >= q90 (tau),
possible >= q75, tau_high = q95. Isotonic is fitted on the most recent 3 months of val (labels from 2025, never test).
Test rows are used only to REPORT the observed bump rate per band (results/serving_<name>.json).
Usage: python scripts/15_serving_model.py --model hgb|tabpfn"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import brier_score_loss

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import tabular  # noqa: E402
from patchsloth.features import FeatureBuilder  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--model", required=True, choices=["hgb", "tabpfn"])
a = ap.parse_args()
N_TRAIN = {"hgb": None, "tabpfn": 50000}[a.model]

df = pd.read_parquet("data/cves.parquet")
df = df[df.split.isin(["train", "val", "test", "deferred_unlabeled"])].copy()
fb = FeatureBuilder().fit(df[df.split == "train"])
X, y = fb.transform(df), df.bump_up
tr = df[df.split == "train"]
idx = tr.sample(n=N_TRAIN, random_state=0).index if N_TRAIN else tr.index
clf = tabular.fit(a.model, X.loc[idx], y.loc[idx], seed=0)

m_def = (df.split == "deferred_unlabeled").to_numpy()
val = df.split == "val"
start = str((pd.Timestamp(df.published[val].max()) - pd.DateOffset(months=3)).date())
m_rec = (val & (df.published >= start)).to_numpy()
m_test = (df.split == "test").to_numpy()
p_def = tabular.predict_proba(clf, X[m_def])
p_rec = tabular.predict_proba(clf, X[m_rec])
bands = tabular.Bands(p_def, p_rec, y[m_rec].astype(int), val_window=f"val published >= {start} (n={int(m_rec.sum())})")
model = tabular.BumpModel(fb, clf, a.model, bands)
print("saved", model.save())

# evidence: what each band means on 2026 test rows (reported, never used to choose anything)
p_test = tabular.predict_proba(clf, X[m_test])
yt = y[m_test].astype(int).to_numpy()
b = bands.band(p_test)
llm_rows = set(json.loads(Path("results/llm_vectors_ft_test.json").read_text()))
in_eval = df.cve[m_test].isin(llm_rows).to_numpy()


def per_band(mask):
    return {k: dict(share=float((b[mask] == k).mean()), observed_bump_rate=float(yt[mask][b[mask] == k].mean()),
                    n=int((b[mask] == k).sum())) for k in tabular.BANDS}


hi = p_test >= bands.tau_high
out = dict(model=a.model, n_train=len(idx), data_note="trained/scored on the serving data (data/data_as_of.txt)",
           **bands.as_dict(),
           deferred_band_share={k: float((bands.band(p_def) == k).mean()) for k in tabular.BANDS},
           test_all=dict(n=int(m_test.sum()), base_rate=float(yt.mean()), bands=per_band(np.ones(len(yt), bool)),
                         at_tau_high=dict(flag_rate=float(hi.mean()), precision=float(yt[hi].mean()),
                                          recall=float(yt[hi].sum() / yt.sum())),
                         brier_raw=float(brier_score_loss(yt, p_test)),
                         brier_calibrated=float(brier_score_loss(yt, bands.calibrate(p_test)))),
           test_eval_rows=dict(n=int(in_eval.sum()), bands=per_band(in_eval)))
Path(f"results/serving_{a.model}.json").write_text(json.dumps(out, indent=1))
if a.model == "hgb":  # the priority default for rows without a band (thresholds.json predates bands)
    Path("results/thresholds.json").write_text(json.dumps(dict(**bands.as_dict(), model="hgb (all train)"), indent=1))
print(json.dumps({k: out[k] for k in ["tau", "tau_high", "tau_possible"]}),
      json.dumps(out["test_all"]["bands"]), json.dumps(out["test_all"]["at_tau_high"]))
