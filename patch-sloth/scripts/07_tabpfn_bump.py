"""TabPFN decision layer: P(independent reviewer would raise the CNA's severity band).
Features are all available at serve time for Deferred CVEs (patchsloth/features.py). Optionally stacks
the fine-tuned LLM's predicted vector as features (--with_llm). Compares TabPFN vs logistic regression vs HistGBT.
Usage: python scripts/07_tabpfn_bump.py --model tabpfn --n_train 10000 [--with_llm]
With --model hgb it also saves data/models/bump_hgb.joblib (serve-time fallback) and results/thresholds.json."""
import argparse
import json
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


def predict(mask):
    return tabular.predict_proba(clf, X[mask])


out = {}
rng = np.random.default_rng(0)
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
        # thresholds on the most recent 3 months of val, closest to the 2026 base rate (SPEC §9.2)
        pub = df.published[m].to_numpy()
        recent = pub >= str((pd.Timestamp(df.published[m].max()) - pd.DateOffset(months=3)).date())
        tau = tabular.choose_tau(yy[recent], p[recent], min_precision=0.5)
        tau_high = max(tau, tabular.choose_tau(yy[recent], p[recent], min_precision=0.75))
        thr = dict(tau=tau, tau_high=tau_high, model=tag, tuned_on=f"val published >= {pub[recent].min()}",
                   n_tune=int(recent.sum()), base_rate_tune=float(yy[recent].mean()))
    else:
        flag = p >= thr["tau"]
        out[split]["recall_at_tau"] = float(yy[flag].sum() / max(yy.sum(), 1))
        out[split]["precision_at_tau"] = float(yy[flag].mean()) if flag.any() else 0.0
    print(split, {k_: (np.round(v_, 3) if not isinstance(v_, tuple) else tuple(np.round(v_, 3)))
                  for k_, v_ in out[split].items()})
out["thresholds"] = thr
print("thresholds", thr)
# score the real target population: Deferred CVEs nobody independently checked
m = (df.split == "deferred_unlabeled").to_numpy()
pd.DataFrame({"cve": df.cve[m], "cna": df.cna[m], "cna_vector": df.cna_vector[m], "p_bump": predict(m)}) \
  .sort_values("p_bump", ascending=False).to_csv(f"results/deferred_scored_{tag}.csv", index=False)
json.dump(out, open(f"results/bump_{tag}.json", "w"), indent=1, default=float)
if a.model == "hgb" and not a.with_llm:  # the CPU serve-time fallback
    print("saved", tabular.BumpModel(fb, clf, "hgb").save())
    Path("results/thresholds.json").write_text(json.dumps(thr, indent=1))
