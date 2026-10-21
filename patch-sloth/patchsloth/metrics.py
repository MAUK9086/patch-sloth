"""Shared evaluation for every Task A model, so all baselines are scored identically."""
import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_fscore_support

from .cvss import METRICS, base_score, parse, sev_rank


def evaluate(df, pred_vectors, bump_proba=None, n_boot=1000, seed=0):
    """df needs label_vector, cna_vector, cna_sev, bump_up. pred_vectors: list of CVSS strings."""
    lab = [parse(v) for v in df.label_vector]
    pred = [parse(v) for v in pred_vectors]
    out = {f"acc_{k}": np.mean([p[k] == l[k] for p, l in zip(pred, lab)]) for k in METRICS}
    out["exact_vector"] = np.mean([p == l for p, l in zip(pred, lab)])
    ps = np.array([base_score(p) for p in pred]); ls = df.label_score.to_numpy()
    out["score_mae"] = np.abs(ps - ls).mean()
    psev = np.array([sev_rank(s) for s in ps]); lsev = df.label_sev.to_numpy()
    sev_ok = psev == lsev
    out["severity_acc"] = sev_ok.mean()
    y = df.bump_up.astype(bool).to_numpy()
    yhat = psev > df.cna_sev.to_numpy()
    p, r, f, _ = precision_recall_fscore_support(y, yhat, average="binary", zero_division=0)
    out.update(bump_precision=p, bump_recall=r, bump_f1=f, bump_base_rate=y.mean())
    rng = np.random.default_rng(seed); n = len(y)
    boots = {"severity_acc": [], "bump_f1": [], "bump_pr_auc": []}
    for _ in range(n_boot):
        i = rng.integers(0, n, n)
        boots["severity_acc"].append(sev_ok[i].mean())
        boots["bump_f1"].append(precision_recall_fscore_support(y[i], yhat[i], average="binary", zero_division=0)[2])
        if bump_proba is not None:
            boots["bump_pr_auc"].append(average_precision_score(y[i], bump_proba[i]))
    if bump_proba is not None:
        out["bump_pr_auc"] = average_precision_score(y, bump_proba)
    for k, v in boots.items():
        if v:
            out[f"{k}_ci95"] = (float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5)))
    return out, sev_ok


def mcnemar(ok_a, ok_b):
    """Exact-ish McNemar (chi2 with continuity) on paired correctness arrays."""
    from scipy.stats import chi2
    b = int((ok_a & ~ok_b).sum()); c = int((~ok_a & ok_b).sum())
    stat = (abs(b - c) - 1) ** 2 / max(b + c, 1)
    return dict(a_only=b, b_only=c, p_value=float(chi2.sf(stat, 1)))
