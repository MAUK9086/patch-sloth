"""M2 evidence for Task B: TabPFN scaling curve and calibration (SPEC §9.2, §10).
Reads results/bump_tabpfn_n*.json and the per-row predictions 07 saves in data/preds/. HGB and logistic regression
are refitted here on the same n_train subsamples (same sampling as 07), so the curves compare like with like.
Calibration (TabPFN at the largest n vs the 10k HGB from 07): Brier + reliability on test; isotonic fitted on the first half of val (by publication date) and
reported on the second half of val and on test.
Usage: python scripts/11_tabpfn_plots.py   (after 07 --model hgb and 07 --model tabpfn at each n_train)
Writes results/tabpfn_scaling.{json,png} and results/tabpfn_calibration.{json,png}."""
import json
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, brier_score_loss

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import tabular  # noqa: E402
from patchsloth.features import FeatureBuilder  # noqa: E402

R = Path("results")
# M2 ran on the serving data (all test rows), not on the frozen evaluation snapshot in results/data_as_of.txt
as_of = Path("data/data_as_of.txt").read_text().strip()


def pr_auc_ci(y, p, n_boot=500):
    rng = np.random.default_rng(0)
    b = [average_precision_score(y[i], p[i]) for i in (rng.integers(0, len(p), len(p)) for _ in range(n_boot))]
    return float(average_precision_score(y, p)), [float(np.percentile(b, 2.5)), float(np.percentile(b, 97.5))]


# ---- scaling: TabPFN results from 07, CPU baselines refitted on the same subsamples
runs = sorted((int(re.search(r"_n(\d+)\.json$", f.name).group(1)), f) for f in R.glob("bump_tabpfn_n*.json"))
if not runs:
    sys.exit("no results/bump_tabpfn_n*.json: run 07 --model tabpfn first")
df = pd.read_parquet("data/cves.parquet")
df = df[df.split.isin(["train", "val", "test", "deferred_unlabeled"])].copy()
fb = FeatureBuilder().fit(df[df.split == "train"])
X, y = fb.transform(df), df.bump_up
tr = df.split == "train"
scaling = {"data_as_of": as_of, "tabpfn": [], "hgb": [], "logreg": []}
for n, f in runs:
    r = json.loads(f.read_text())
    scaling["tabpfn"].append(dict(n_train=n, **{s: dict(pr_auc=r[s]["pr_auc"], pr_auc_ci95=r[s]["pr_auc_ci95"])
                                                for s in ["val", "test"]}))
    idx = df[tr].sample(n=min(n, int(tr.sum())), random_state=0).index  # same rows as 07
    for name in ["hgb", "logreg"]:
        clf = tabular.fit(name, X.loc[idx], y.loc[idx])
        row = dict(n_train=n)
        for s in ["val", "test"]:
            m = (df.split == s).to_numpy()
            v, ci = pr_auc_ci(y[m].astype(int).to_numpy(), tabular.predict_proba(clf, X[m]))
            row[s] = dict(pr_auc=v, pr_auc_ci95=ci)
        scaling[name].append(row)
    print("n", n, {k: round(scaling[k][-1]["test"]["pr_auc"], 3) for k in ["tabpfn", "hgb", "logreg"]})
# HGB on ALL train rows (results/bump_hgb.json is a 10k model: 07's default --n_train)
clf = tabular.fit("hgb", X[tr], y[tr])
m_t = (df.split == "test").to_numpy()
v, ci = pr_auc_ci(y[m_t].astype(int).to_numpy(), tabular.predict_proba(clf, X[m_t]))
scaling["hgb_full_train"] = dict(n_train=int(tr.sum()), test=dict(pr_auc=v, pr_auc_ci95=ci))
scaling["test_base_rate"] = float(y[m_t].mean())
(R / "tabpfn_scaling.json").write_text(json.dumps(scaling, indent=1))

fig, ax = plt.subplots(figsize=(6.4, 4.2))
for name, label, c in [("tabpfn", "TabPFN-3.5", "C0"), ("hgb", "HistGBT", "C1"), ("logreg", "Logistic reg.", "C2")]:
    ns = [r["n_train"] for r in scaling[name]]
    v = np.array([r["test"]["pr_auc"] for r in scaling[name]])
    lo, hi = np.array([r["test"]["pr_auc_ci95"] for r in scaling[name]]).T
    ax.plot(ns, v, "o-", color=c, label=label)
    ax.fill_between(ns, lo, hi, color=c, alpha=0.15)
h = scaling["hgb_full_train"]
ax.errorbar([h["n_train"]], [h["test"]["pr_auc"]], yerr=[[h["test"]["pr_auc"] - h["test"]["pr_auc_ci95"][0]],
            [h["test"]["pr_auc_ci95"][1] - h["test"]["pr_auc"]]], fmt="s", color="C1", mfc="white",
            label=f"HistGBT, all {h['n_train']:,} train rows")
ax.axhline(scaling["test_base_rate"], color="grey", ls=":", label="base rate (random ranking)")
ax.set_xscale("log")
ticks = [r["n_train"] for r in scaling["tabpfn"]] + [h["n_train"]]
ax.set_xticks(ticks, [f"{t // 1000}k" for t in ticks])
ax.minorticks_off()
ax.set_xlabel("training rows (n_train)")
ax.set_ylabel("PR-AUC on 2026 test CVEs")
ax.set_title("Bump-up classifier: scaling with training size", fontsize=11)
ax.legend(fontsize=8, loc="lower right", bbox_to_anchor=(1, 0.12))
ax.grid(alpha=0.3)
fig.text(0.01, 0.01, f"95% bootstrap CIs. Data as of {as_of}.", fontsize=7, color="grey")
fig.tight_layout()
fig.savefig(R / "tabpfn_scaling.png", dpi=150)

# ---- calibration: largest TabPFN run vs full-train HGB
n_max = runs[-1][0]
cal = {"data_as_of": as_of}
fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
for tag, label, c in [(f"tabpfn_n{n_max}", f"TabPFN-3.5 (n={n_max:,})", "C0"), ("hgb", "HistGBT (n=10,000)", "C1")]:
    p_path = Path(f"data/preds/bump_{tag}.parquet")
    if not p_path.exists():
        print("skip calibration for", tag, "(no", p_path, ")")
        continue
    pr = pd.read_parquet(p_path)
    val = pr[pr.split == "val"].sort_values("published")
    test = pr[pr.split == "test"]
    half = len(val) // 2
    v1, v2 = val.iloc[:half], val.iloc[half:]
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(v1.p, v1.y)
    res = dict(test_brier=brier_score_loss(test.y, test.p), test_mean_p=float(test.p.mean()),
               test_base_rate=float(test.y.mean()),
               val2_brier=brier_score_loss(v2.y, v2.p), val2_brier_isotonic=brier_score_loss(v2.y, iso.predict(v2.p)),
               test_brier_isotonic=brier_score_loss(test.y, iso.predict(test.p)),
               val_split_date=str(v2.published.iloc[0]), n_val1=len(v1), n_val2=len(v2))
    for ax, (name, d, pp) in zip(axes, [("test", test, test.p), ("test, isotonic (fit on val H1)", test,
                                                                    iso.predict(test.p))]):
        fy, fx = calibration_curve(d.y, pp, n_bins=10, strategy="quantile")
        ax.plot(fx, fy, "o-", color=c, label=f"{label}  Brier {brier_score_loss(d.y, pp):.4f}")
        ax.set_title(f"Reliability on 2026 {name}", fontsize=10)
        res.setdefault("reliability", {})[name] = dict(mean_pred=fx.tolist(), frac_pos=fy.tolist())
    cal[tag] = res
    print("calibration", tag, {k: round(v, 4) for k, v in res.items() if isinstance(v, float)})
for ax in axes:
    ax.plot([0, 1], [0, 1], ls=":", color="grey")
    ax.set_xlabel("predicted P(bump up)")
    ax.set_ylabel("observed bump-up rate")
    ax.legend(fontsize=8, loc="upper left")
    ax.grid(alpha=0.3)
fig.text(0.01, 0.01, f"10 quantile bins. Val H1 = val published before {cal.get(f'tabpfn_n{n_max}', {}).get('val_split_date', '?')}."
         f" Data as of {as_of}.", fontsize=7, color="grey")
fig.tight_layout()
fig.savefig(R / "tabpfn_calibration.png", dpi=150)
(R / "tabpfn_calibration.json").write_text(json.dumps(cal, indent=1))
print("wrote results/tabpfn_scaling.{json,png}, results/tabpfn_calibration.{json,png}")
