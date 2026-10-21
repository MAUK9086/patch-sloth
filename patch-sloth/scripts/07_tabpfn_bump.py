"""TabPFN decision layer: P(independent reviewer would raise the CNA's severity band).
Features are all available at serve time for Deferred CVEs. Optionally stacks the fine-tuned LLM's
predicted vector as features (--with_llm). Compares TabPFN vs logistic regression vs HistGBT.
Usage: python scripts/07_tabpfn_bump.py --model tabpfn --n_train 10000 [--with_llm]"""
import argparse, json, sys
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.cvss import METRICS, VALUES, parse, base_score

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="tabpfn", choices=["tabpfn", "hgb", "logreg"])
ap.add_argument("--n_train", type=int, default=10000)
ap.add_argument("--with_llm", action="store_true")
a = ap.parse_args()

df = pd.read_parquet("data/cves.parquet")
df = df[df.split.isin(["train", "val", "test", "deferred_unlabeled"])].copy()
top_cna = df[df.split == "train"].cna.value_counts().index[:40]
top_cwe = df[df.split == "train"].cna_cwe.str.split(";").str[0].value_counts().index[:40]
X = pd.DataFrame(index=df.index)
for k in METRICS:
    X[f"cna_{k}"] = df.cna_vector.map(lambda v: VALUES[k].index(parse(v)[k]))
X["cna_score"] = df.cna_score
X["cna_id"] = pd.Categorical(df.cna.where(df.cna.isin(top_cna), "other")).codes
X["cwe"] = pd.Categorical(df.cna_cwe.str.split(";").str[0].where(lambda s: s.isin(top_cwe), "other")).codes
X["adp_scored"] = (df.score_source == "CISA-ADP").astype(int)
X["n_refs"] = df.n_refs; X["ref_github"] = df.ref_github.astype(int); X["ref_exploitdb"] = df.ref_exploitdb.astype(int)
X["desc_len"] = df.description.str.len(); X["has_v40"] = df.has_v40.astype(int)
tf = TfidfVectorizer(min_df=5, max_features=30000, sublinear_tf=True).fit(df[df.split == "train"].description)
svd = TruncatedSVD(32, random_state=0).fit(tf.transform(df[df.split == "train"].description))
emb = svd.transform(tf.transform(df.description))
for i in range(emb.shape[1]): X[f"txt{i}"] = emb[:, i]
if a.with_llm:  # predicted NVD vector from the fine-tuned LLM (val/test only unless you also predict train via CV)
    for split in ["val", "test"]:
        p = Path(f"results/llm_vectors_ft_{split}.json")
        if p.exists():
            v = json.loads(p.read_text()); m = df.cve.isin(v.keys())
            X.loc[m, "llm_score_delta"] = [base_score(parse(v[c])) - s for c, s in zip(df.cve[m], df.cna_score[m])]
    print("NOTE: --with_llm needs LLM predictions on a train subset too; see PLAN.md day 3")

y = df.bump_up
tr = df.split == "train"
idx = df[tr].sample(n=min(a.n_train, tr.sum()), random_state=0).index
if a.model == "tabpfn":
    from tabpfn import TabPFNClassifier
    clf = TabPFNClassifier(device="cuda")
elif a.model == "hgb":
    from sklearn.ensemble import HistGradientBoostingClassifier
    clf = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05)
else:
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline; from sklearn.preprocessing import StandardScaler
    clf = make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000))
clf.fit(X.loc[idx].fillna(0).values, y.loc[idx].astype(int).values)

def predict(mask):
    Xs = X[mask].fillna(0).values
    return np.concatenate([clf.predict_proba(Xs[i:i + 5000])[:, 1] for i in range(0, len(Xs), 5000)])

out = {}
rng = np.random.default_rng(0)
for split in ["val", "test"]:
    m = (df.split == split).to_numpy(); p = predict(m); yy = y[m].astype(int).to_numpy()
    k = max(1, int(0.1 * len(p))); top = np.argsort(-p)[:k]
    boots = [average_precision_score(yy[i], p[i]) for i in (rng.integers(0, len(p), len(p)) for _ in range(500))]
    out[split] = dict(n=int(m.sum()), base_rate=yy.mean(), pr_auc=average_precision_score(yy, p),
                      pr_auc_ci95=(np.percentile(boots, 2.5), np.percentile(boots, 97.5)),
                      roc_auc=roc_auc_score(yy, p), brier=brier_score_loss(yy, p),
                      precision_at_top10pct=yy[top].mean())
    print(split, {k_: (np.round(v, 3) if not isinstance(v, tuple) else tuple(np.round(v, 3))) for k_, v in out[split].items()})
# score the real target population: Deferred CVEs nobody independently checked
m = (df.split == "deferred_unlabeled").to_numpy()
pd.DataFrame({"cve": df.cve[m], "cna": df.cna[m], "cna_vector": df.cna_vector[m], "p_bump": predict(m)}) \
  .sort_values("p_bump", ascending=False).to_csv(f"results/deferred_scored_{a.model}.csv", index=False)
json.dump(out, open(f"results/bump_{a.model}.json", "w"), indent=1, default=float)
