"""M4 experiments: fit every Task-B configuration with 3 seeds and save per-row val/test predictions.
Analysis (paired bootstrap, tables) is in scripts/13_final_table.py.

Training rows per config (seed s draws the subsample AND seeds the model):
  *_full      all train rows (80,098)            *_50k / *_30k  random train subsample
  *_recent    train rows published >= 2024-01-01 (TabPFN: subsample to 50k if larger)
  *_stack     the 10k out-of-SFT stack_train rows (the only train rows with LLM predictions)
  *_llm_stack the same rows, plus the fine-tuned LLM's features (SPEC §9.2 stacking)
  hgb_noes_*  HGB with early stopping off (diagnostic for the 30k-vs-80k anomaly)
Tabular configs are scored on all val/test rows; LLM configs only on rows with LLM predictions (the M3 eval rows).
Resumable: existing data/m4/<config>_s<seed>.parquet files are skipped. Progress: data/m4/progress.log.
Usage: python scripts/12_m4_experiments.py [--only tabpfn_50k,hgb_full] [--seeds 0,1,2]"""
import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import tabular  # noqa: E402
from patchsloth.features import LLM_INPUT, FeatureBuilder  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--only", default="")
ap.add_argument("--seeds", default="0,1,2")
a = ap.parse_args()
OUT = Path("data/m4")
OUT.mkdir(parents=True, exist_ok=True)
LOG = OUT / "progress.log"

# (name, model, train rows, n cap or None, with LLM features, early stopping)
CONFIGS = [
    ("lr_full", "logreg", "train", None, False),
    ("hgb_full", "hgb", "train", None, False),
    ("hgb_50k", "hgb", "train", 50000, False),
    ("hgb_30k", "hgb", "train", 30000, False),
    ("hgb_recent", "hgb", "recent", None, False),
    ("hgb_noes_full", "hgb_noes", "train", None, False),
    ("hgb_noes_30k", "hgb_noes", "train", 30000, False),
    ("hgb_stack", "hgb", "stack", None, False),
    ("hgb_llm_stack", "hgb", "stack", None, True),
    ("tabpfn_stack", "tabpfn", "stack", None, False),
    ("tabpfn_llm_stack", "tabpfn", "stack", None, True),
    ("tabpfn_50k", "tabpfn", "train", 50000, False),
    ("tabpfn_recent", "tabpfn", "recent", 50000, False),
]
only = set(filter(None, a.only.split(",")))
seeds = [int(s) for s in a.seeds.split(",")]

df = pd.read_parquet("data/cves.parquet")
df = df[df.split.isin(["train", "val", "test"])].copy()
llm = {}
for split in ["stack_train", "val", "test"]:
    llm.update(json.loads(Path(f"results/llm_vectors_ft_{split}.json").read_text()))
df[LLM_INPUT] = df.cve.map(llm)
has_llm = df[LLM_INPUT].notna()
train = df.split == "train"
pools = {"train": train, "recent": train & (df.published >= "2024-01-01"), "stack": train & has_llm}
fb_tab = FeatureBuilder().fit(df[train])
fb_llm = FeatureBuilder(with_llm=True).fit(df[train])
X_tab, X_llm = fb_tab.transform(df), fb_llm.transform(df)
y = df.bump_up.astype(int)


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


todo = [(c, s) for c in CONFIGS for s in seeds if (not only or c[0] in only)
        and not (OUT / f"{c[0]}_s{s}.parquet").exists()]
log(f"start: {len(todo)} runs to do")
for i, ((name, model, pool, cap, with_llm), seed) in enumerate(todo, 1):
    if model == "logreg" and seed != seeds[0] and cap is None:
        continue  # deterministic on the full pool: one run is enough
    t0 = time.time()
    rows = df[pools[pool]]
    idx = rows.sample(n=min(cap, len(rows)), random_state=seed).index if cap else rows.index
    X = X_llm if with_llm else X_tab
    if model == "hgb_noes":
        from sklearn.ensemble import HistGradientBoostingClassifier
        clf = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, early_stopping=False,
                                             random_state=seed).fit(X.loc[idx].fillna(0).values, y.loc[idx].values)
    else:
        clf = tabular.fit(model, X.loc[idx], y.loc[idx], seed=seed)
    score = df.split.isin(["val", "test"]) & (has_llm if with_llm else True)
    p = tabular.predict_proba(clf, X[score])
    pd.DataFrame({"cve": df.cve[score].to_numpy(), "split": df.split[score].to_numpy(),
                  "published": df.published[score].to_numpy(), "y": y[score].to_numpy(), "p": p}) \
        .to_parquet(OUT / f"{name}_s{seed}.parquet", index=False)
    log(f"[{i}/{len(todo)}] {name} seed {seed}: n_train {len(idx)}, scored {int(score.sum())}, "
        f"{time.time() - t0:.0f}s")
log("done")
