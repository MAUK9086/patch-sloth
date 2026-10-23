"""Task A baselines: copy-CNA, per-metric logistic regression on TF-IDF + CNA fields,
and a direct 'bump-up' classifier. Writes results/baselines_<split>.json."""
import json
import sys
from pathlib import Path

import pandas as pd
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.cvss import METRICS, parse, to_vector
from patchsloth.metrics import evaluate, mcnemar

df = pd.read_parquet("data/cves.parquet")
df = df[df.split.isin(["train", "val", "test"])].copy()
for k in METRICS:
    df[f"cna_{k}"] = df.cna_vector.map(lambda v, k=k: parse(v)[k])
    df[f"lab_{k}"] = df.label_vector.map(lambda v, k=k: parse(v)[k])
df["cwe1"] = df.cna_cwe.fillna("").str.split(";").str[0]
tr = df[df.split == "train"]

tfidf = TfidfVectorizer(min_df=3, max_features=50000, ngram_range=(1, 2), sublinear_tf=True)
ohe = OneHotEncoder(handle_unknown="ignore", min_frequency=20)
cat_cols = [f"cna_{k}" for k in METRICS] + ["cna", "cwe1", "score_source"]
def feats(d, fit=False):
    t = tfidf.fit_transform(d.description) if fit else tfidf.transform(d.description)
    c = ohe.fit_transform(d[cat_cols].astype(str)) if fit else ohe.transform(d[cat_cols].astype(str))
    return hstack([t, c]).tocsr()
Xtr = feats(tr, fit=True)

clfs = {k: LogisticRegression(max_iter=2000, C=4.0).fit(Xtr, tr[f"lab_{k}"]) for k in METRICS}
bump_clf = LogisticRegression(max_iter=2000, C=2.0, class_weight="balanced").fit(Xtr, tr.bump_up.astype(int))

Path("results").mkdir(exist_ok=True)
for split in ["val", "test"]:
    d = df[df.split == split]
    X = feats(d)
    res = {}
    res["copy_cna"], ok_copy = evaluate(d, list(d.cna_vector))
    preds = {k: clfs[k].predict(X) for k in METRICS}
    vecs = [to_vector({k: preds[k][i] for k in METRICS}) for i in range(len(d))]
    proba = bump_clf.predict_proba(X)[:, 1]
    res["tfidf_logreg"], ok_lr = evaluate(d, vecs, bump_proba=proba)
    res["tfidf_logreg"]["mcnemar_vs_copy_cna_severity"] = mcnemar(ok_lr, ok_copy)
    json.dump(res, open(f"results/baselines_{split}.json", "w"), indent=1, default=float)
    # per-row vectors and bump probabilities, so every model can be rescored on the same rows (scripts/13)
    Path("data/preds").mkdir(parents=True, exist_ok=True)
    json.dump({c: [v, float(q)] for c, v, q in zip(d.cve, vecs, proba)}, open(f"data/preds/tfidf_lr_{split}.json", "w"))
    print(f"== {split} (n={len(d)}) ==")
    print(pd.DataFrame(res).T[["severity_acc", "exact_vector", "score_mae", "bump_precision", "bump_recall", "bump_f1"]].round(3).to_string())
    print("bump PR-AUC (direct classifier):", round(res["tfidf_logreg"]["bump_pr_auc"], 3), "base rate", round(res["copy_cna"]["bump_base_rate"], 3))
    print("per-metric acc copy vs LR:", {k: (round(res['copy_cna'][f'acc_{k}'], 3), round(res['tfidf_logreg'][f'acc_{k}'], 3)) for k in METRICS})
    print("McNemar:", res["tfidf_logreg"]["mcnemar_vs_copy_cna_severity"])
