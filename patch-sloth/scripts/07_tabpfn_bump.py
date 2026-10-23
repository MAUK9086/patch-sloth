"""TabPFN decision layer: P(independent reviewer would raise the CNA's severity band).
Features are all available at serve time for Deferred CVEs (patchsloth/features.py). Optionally stacks
the fine-tuned LLM's predicted vector as features (--with_llm). Compares TabPFN vs logistic regression vs HistGBT.
Usage: python scripts/07_tabpfn_bump.py --model tabpfn --n_train 10000 [--with_llm]
With --model hgb it also saves data/models/bump_hgb.joblib (serve-time fallback) and results/thresholds.json."""
import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import tabular  # noqa: E402
from patchsloth.features import LLM_INPUT, FeatureBuilder  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="tabpfn", choices=["tabpfn", "hgb", "logreg"])
ap.add_argument("--n_train", type=int, default=10000)
ap.add_argument("--with_llm", action="store_true")
a = ap.parse_args()

df = pd.read_parquet("data/cves.parquet")
df = df[df.split.isin(["train", "val", "test", "deferred_unlabeled"])].copy()
if a.with_llm:  # out-of-SFT LLM predictions only (stack_train for training rows), SPEC §9.2
    v = {}
    for split in ["stack_train", "val", "test"]:
        p = Path(f"results/llm_vectors_ft_{split}.json")
        if p.exists():
            v.update(json.loads(p.read_text()))
    df[LLM_INPUT] = df.cve.map(v)
    if not Path("results/llm_vectors_ft_stack_train.json").exists():
        print("NOTE: --with_llm needs results/llm_vectors_ft_stack_train.json (out-of-SFT train predictions)")

fb = FeatureBuilder(with_llm=a.with_llm).fit(df[df.split == "train"])
X = fb.transform(df)
y = df.bump_up
tr = df.split == "train"
if a.with_llm:  # train only on rows that have an out-of-SFT LLM prediction
    tr &= df[LLM_INPUT].notna()
idx = df[tr].sample(n=min(a.n_train, int(tr.sum())), random_state=0).index
clf = tabular.fit(a.model, X.loc[idx], y.loc[idx])
tag = a.model + ("_llm" if a.with_llm else "")
if a.model == "tabpfn":  # one result file per context size (scaling curve, SPEC §9.2)
    tag += f"_n{len(idx)}"


def predict(mask):
    return tabular.predict_proba(clf, X[mask])


def at(yy, p, t):
    """Flag rate, precision and recall of the flagged set p >= t (labels only used for reporting)."""
    flag = p >= t
    return dict(threshold=float(t), flag_rate=float(flag.mean()),
                precision=float(yy[flag].mean()) if flag.any() else 0.0,
                recall=float(yy[flag].sum() / max(yy.sum(), 1)))


# tau: top 10% of the population the product actually scores (Deferred, no labels), the same cutoff
# serve time applies. No test (or val) labels are used to choose it.
m_def = (df.split == "deferred_unlabeled").to_numpy()
p_def = predict(m_def)
tau = float(np.quantile(p_def, 0.90))
out = {}
rng = np.random.default_rng(0)
preds = {}
for split in ["val", "test"]:
    m = (df.split == split).to_numpy()
    p = predict(m)
    yy = y[m].astype(int).to_numpy()
    k = max(1, int(0.1 * len(p)))
    top = np.argsort(-p)[:k]
    boots = [average_precision_score(yy[i], p[i]) for i in (rng.integers(0, len(p), len(p)) for _ in range(500))]
    out[split] = dict(n=int(m.sum()), base_rate=yy.mean(), pr_auc=average_precision_score(yy, p),
                      pr_auc_ci95=(np.percentile(boots, 2.5), np.percentile(boots, 97.5)),
                      roc_auc=roc_auc_score(yy, p), brier=brier_score_loss(yy, p),
                      precision_at_top10pct=yy[top].mean())
    if split == "val":
        # SPEC §9.2 rule on the most recent 3 months of val. Kept for tau_high, and tau_val is kept as the
        # drift finding (it is NOT the serving tau: on 2026 its precision collapses)
        pub = df.published[m].to_numpy()
        recent = pub >= str((pd.Timestamp(df.published[m].max()) - pd.DateOffset(months=3)).date())
        tau_val = tabular.choose_tau(yy[recent], p[recent], min_precision=0.5)
        tau_high = max(tau, tabular.choose_tau(yy[recent], p[recent], min_precision=0.75))
        thr = dict(tau=tau, tau_rule=f"90th percentile of p_bump over deferred_unlabeled (n={int(m_def.sum())}); "
                                     "no labels", tau_high=tau_high,
                   tau_high_rule=f"val published >= {pub[recent].min()}: largest flag set with precision >= 0.75, "
                                 "floored at tau", model=tag, n_tune=int(recent.sum()),
                   base_rate_tune=float(yy[recent].mean()))
    out[split].update(at_tau=at(yy, p, tau), at_tau_high=at(yy, p, tau_high), at_tau_val=at(yy, p, tau_val))
    preds[split] = pd.DataFrame({"cve": df.cve[m].to_numpy(), "published": df.published[m].to_numpy(),
                                 "y": yy, "p": p})
    print(split, {k_: (np.round(v_, 3) if isinstance(v_, float) else v_) for k_, v_ in out[split].items()})
out["thresholds"] = thr
out["drift_finding"] = dict(
    tau_val=tau_val, rule="SPEC §9.2 literal: precision >= 0.5 on the last 3 months of val",
    val_recent_base_rate=thr["base_rate_tune"], test_base_rate=float(out["test"]["base_rate"]),
    test_at_tau_val=out["test"]["at_tau_val"],
    note="val-tuned threshold transfers badly to 2026: the bump base rate halved, so precision at tau_val drops")
print("thresholds", thr)
print("drift", out["drift_finding"])
# score the real target population: Deferred CVEs nobody independently checked
pd.DataFrame({"cve": df.cve[m_def], "cna": df.cna[m_def], "cna_vector": df.cna_vector[m_def], "p_bump": p_def}) \
  .sort_values("p_bump", ascending=False).to_csv(f"results/deferred_scored_{tag}.csv", index=False)
out["model"] = dict(name=a.model, n_train=len(idx), n_features=X.shape[1],
                    tabpfn_version=os.environ.get("PATCHSLOTH_TABPFN_VERSION", "v3.5") if a.model == "tabpfn" else None)
json.dump(out, open(f"results/bump_{tag}.json", "w"), indent=1, default=float)
# per-row val/test predictions for the calibration and scaling plots (scripts/11_tabpfn_plots.py)
Path("data/preds").mkdir(parents=True, exist_ok=True)
pd.concat([d.assign(split=k) for k, d in preds.items()]).to_parquet(f"data/preds/bump_{tag}.parquet", index=False)
if a.model == "hgb" and not a.with_llm:  # the CPU serve-time fallback
    print("saved", tabular.BumpModel(fb, clf, "hgb").save())
    Path("results/thresholds.json").write_text(json.dumps(thr, indent=1))
    Path("results/tau_drift.json").write_text(json.dumps(out["drift_finding"], indent=1, default=float))
