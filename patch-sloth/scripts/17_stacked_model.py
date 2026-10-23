"""Serve-time stacked model: TabPFN-3.5 + fine-tuned-LLM features, trained on the 10k out-of-SFT stack_train rows
(seed 0), with Bands and the gate threshold. Saved to data/models/bump_stack.joblib for
`patchsloth feed build --model stack --llm --backend precomputed`.
- Gate t: chosen in M4 on the last 3 months of val (results/gated_override.json, seed 0). Verified here: this model's
  val/test predictions equal the M4 seed-0 stack's, so t applies unchanged.
- Bands: label-free quantiles of this model's p_bump over the Deferred CVEs that have an LLM vector (scripts/16).
  Isotonic on the last 3 months of val (rows with LLM predictions).
Usage: python scripts/17_stacked_model.py   (after scripts/16)"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import tabular  # noqa: E402
from patchsloth.features import LLM_INPUT, FeatureBuilder  # noqa: E402

R = Path("results")
df = pd.read_parquet("data/cves.parquet")
df = df[df.split.isin(["train", "val", "test", "deferred_unlabeled"])].copy()
v = {}
for s in ["stack_train", "val", "test", "unanalysed"]:
    v.update(json.loads((R / f"llm_vectors_ft_{s}.json").read_text()))
df[LLM_INPUT] = df.cve.map(v)
has = df[LLM_INPUT].notna()
train = df.split == "train"
fb = FeatureBuilder(with_llm=True).fit(df[df.split.isin(["train", "val", "test"]) & train])
X, y = fb.transform(df), df.bump_up
idx = df[train & has].index
clf = tabular.fit("tabpfn", X.loc[idx], y.loc[idx], seed=0)

m_eval = (df.split.isin(["val", "test"]) & has).to_numpy()
p_eval = pd.Series(tabular.predict_proba(clf, X[m_eval]), index=df.cve[m_eval])
ref = pd.read_parquet("data/m4/tabpfn_llm_stack_s0.parquet").set_index("cve").p
diff = float(np.abs(p_eval.loc[ref.index].to_numpy() - ref.to_numpy()).max())
print("max |p - M4 seed-0 stack| =", diff)
assert diff < 1e-3, "model differs from the M4 stack: the gate threshold would not apply"

m_def = (df.split == "deferred_unlabeled").to_numpy() & has.to_numpy()
val = df.split == "val"
start = str((pd.Timestamp(df.published[val].max()) - pd.DateOffset(months=3)).date())
m_rec = (val & has & (df.published >= start)).to_numpy()
p_def = tabular.predict_proba(clf, X[m_def])
bands = tabular.Bands(p_def, tabular.predict_proba(clf, X[m_rec]), y[m_rec].astype(int),
                      val_window=f"val with LLM predictions, published >= {start} (n={int(m_rec.sum())})")
model = tabular.BumpModel(fb, clf, "stack", bands)
gate = json.loads((R / "gated_override.json").read_text())["seeds"]["0"]["chosen_on_val_last3m"]
model.gate_t = float(gate["t"])
print("saved", model.save())

# evidence on the 8k eval test rows (reported only)
m_t = (df.split == "test").to_numpy() & has.to_numpy()
pt = tabular.predict_proba(clf, X[m_t])
yt = y[m_t].astype(int).to_numpy()
b = bands.band(pt)
hi = pt >= bands.tau_high
out = dict(model="stack (TabPFN-3.5 + LLM features, 10k stack_train, seed 0)", gate_t=model.gate_t,
           gate_rule="chosen on the last 3 months of val (M4, seed 0)", max_abs_diff_vs_m4=diff, **bands.as_dict(),
           n_deferred_with_llm=int(m_def.sum()), n_deferred_all=int((df.split == "deferred_unlabeled").sum()),
           test_eval_rows=dict(n=int(m_t.sum()), base_rate=float(yt.mean()),
                               bands={k: dict(share=float((b == k).mean()), n=int((b == k).sum()),
                                              observed_bump_rate=float(yt[b == k].mean())) for k in tabular.BANDS},
                               at_tau_high=dict(flag_rate=float(hi.mean()), precision=float(yt[hi].mean()),
                                                recall=float(yt[hi].sum() / yt.sum())),
                               gated_override=gate["test"], gated_vs_copy_cna=gate["test_vs_copy_cna"]))
(R / "serving_stack.json").write_text(json.dumps(out, indent=1))
print(json.dumps({k: out[k] for k in ["gate_t", "tau", "tau_high", "tau_possible", "n_deferred_with_llm"]}),
      json.dumps(out["test_eval_rows"]["bands"]))
