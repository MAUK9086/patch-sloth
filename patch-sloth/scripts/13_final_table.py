"""M4 analysis: every model on the SAME rows, paired bootstrap of PR-AUC differences, 3 training seeds.
Evaluation rows = val/test CVEs that have a fine-tuned LLM prediction (the M3 eval_n rows, data snapshot in
results/data_as_of.txt). Reads data/m4/*.parquet (scripts/12) and results/llm_vectors_ft_*.json.
Rule: "A beats B" only if the 95% CI of PR-AUC(A) - PR-AUC(B) excludes 0 for every seed.
Writes results/m4_comparison.json and results/m4_tables.md."""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.cvss import base_score, parse, sev_rank  # noqa: E402

M4 = Path("data/m4")
R = Path("results")
N_BOOT = 1000
SEEDS = [0, 1, 2]

df = pd.read_parquet("data/cves.parquet").set_index("cve")
llm = {s: json.loads((R / f"llm_vectors_ft_{s}.json").read_text()) for s in ["val", "test"]}


def load(name):
    """{seed: Series p indexed by cve} for a config; deterministic configs have only seed 0."""
    out = {}
    for s in SEEDS:
        f = M4 / f"{name}_s{s}.parquet"
        if f.exists():
            d = pd.read_parquet(f)
            out[s] = d.set_index("cve").p
    return out


def llm_score(split):
    """Fine-tuned LLM alone: predicted base score minus CNA base score (bump if > 0 after banding)."""
    v = llm[split]
    d = df.loc[list(v)]
    return pd.Series([base_score(parse(v[c])) - base_score(parse(cv)) for c, cv in zip(d.index, d.cna_vector)],
                     index=d.index)


def llm_bump(split):
    v = llm[split]
    d = df.loc[list(v)]
    return pd.Series([float(sev_rank(base_score(parse(v[c]))) > sev_rank(base_score(parse(cv))))
                      for c, cv in zip(d.index, d.cna_vector)], index=d.index)


def metrics(y, p):
    k = max(1, int(0.1 * len(p)))
    top = np.argsort(-p, kind="stable")[:k]
    constant = np.ptp(p) == 0
    return dict(pr_auc=float(average_precision_score(y, p)), roc_auc=None if constant else float(roc_auc_score(y, p)),
                brier=float(brier_score_loss(y, np.clip(p, 0, 1))) if p.min() >= 0 and p.max() <= 1 else None,
                precision_top10=float(y[top].mean()))


def boot_idx(n, seed=0):
    rng = np.random.default_rng(seed)
    return [rng.integers(0, n, n) for _ in range(N_BOOT)]


def pr_ci(y, p, idx):
    b = [average_precision_score(y[i], p[i]) for i in idx]
    return [float(np.percentile(b, 2.5)), float(np.percentile(b, 97.5))]


def paired(y, pa, pb, idx):
    d = [average_precision_score(y[i], pa[i]) - average_precision_score(y[i], pb[i]) for i in idx]
    return dict(diff=float(average_precision_score(y, pa) - average_precision_score(y, pb)),
                ci95=[float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))])


def evaluate(rows, split, configs, extra=None):
    """Model table on a fixed row set. Returns {name: {per_seed: [...], mean, sd, ci95 (seed 0)}}."""
    y = df.loc[rows].bump_up.astype(int).to_numpy()
    idx = boot_idx(len(rows))
    out = {}
    scores = {}
    for name in configs:
        seeds = load(name)
        if not seeds:
            continue
        scores[name] = {s: p.loc[rows].to_numpy() for s, p in seeds.items()}
    for name, p in (extra or {}).items():
        scores[name] = {0: p.loc[rows].to_numpy()}
    for name, by_seed in scores.items():
        per = {s: metrics(y, p) for s, p in by_seed.items()}
        pr = [m["pr_auc"] for m in per.values()]
        first = min(by_seed)
        out[name] = dict(seeds=sorted(by_seed), pr_auc_mean=float(np.mean(pr)), pr_auc_sd=float(np.std(pr)),
                         pr_auc_ci95_seed0=pr_ci(y, by_seed[first], idx),
                         **{k: float(np.mean([m[k] for m in per.values()])) if per[first][k] is not None else None
                            for k in ["roc_auc", "brier", "precision_top10"]},
                         per_seed_pr_auc=pr)
    return dict(split=split, n=len(rows), base_rate=float(y.mean()), models=out), scores, y, idx


def compare(scores, y, idx, a, b):
    """Paired bootstrap per seed (seed s of A vs seed s of B; a deterministic side reuses its only run)."""
    sa, sb = scores[a], scores[b]
    seeds = sorted(set(sa) | set(sb))
    res = []
    for s in seeds:
        pa, pb = sa.get(s, sa[min(sa)]), sb.get(s, sb[min(sb)])
        res.append(dict(seed=s, **paired(y, pa, pb, idx)))
    lo_all = all(r["ci95"][0] > 0 for r in res)
    hi_all = all(r["ci95"][1] < 0 for r in res)
    verdict = f"{a} better" if lo_all else f"{b} better" if hi_all else "no significant difference"
    return dict(a=a, b=b, per_seed=res, mean_diff=float(np.mean([r["diff"] for r in res])), verdict=verdict)


TAB = ["lr_full", "hgb_full", "hgb_50k", "hgb_30k", "hgb_stack", "tabpfn_stack", "tabpfn_50k", "hgb_llm_stack",
       "tabpfn_llm_stack"]
result = {"data_as_of": (R / "data_as_of.txt").read_text().strip(), "n_boot": N_BOOT,
          "rule": "A beats B only if the paired-bootstrap 95% CI of the PR-AUC difference excludes 0 for every seed"}
for split in ["test", "val"]:
    rows = list(llm[split])
    copy = pd.Series(0.0, index=rows)  # copy-CNA never predicts a bump: constant score
    table, scores, y, idx = evaluate(rows, split, TAB, extra={"copy_cna": copy, "llm_ft_alone": llm_score(split)})
    lb = llm_bump(split).loc[rows].to_numpy()
    table["llm_ft_alone_binary"] = dict(precision=float(y[lb == 1].mean()), recall=float(lb[y == 1].mean()),
                                        flag_rate=float(lb.mean()))
    comps = [("tabpfn_50k", "hgb_50k"), ("tabpfn_50k", "hgb_full"), ("tabpfn_llm_stack", "tabpfn_stack"),
             ("tabpfn_llm_stack", "tabpfn_50k"), ("tabpfn_llm_stack", "llm_ft_alone"),
             ("hgb_llm_stack", "hgb_stack")]
    table["comparisons"] = [compare(scores, y, idx, a, b) for a, b in comps if a in scores and b in scores]
    result[f"eval_rows_{split}"] = table
    print(split, "eval rows", len(rows))

# step 4: the HGB anomaly and recency, on ALL test rows (the anomaly was measured there)
rows = list(df.index[df.split == "test"])
ANOM = ["hgb_full", "hgb_30k", "hgb_50k", "hgb_noes_full", "hgb_noes_30k", "hgb_recent", "tabpfn_50k", "tabpfn_recent"]
table, scores, y, idx = evaluate(rows, "test_all", ANOM)
comps = [("hgb_30k", "hgb_full"), ("hgb_noes_full", "hgb_full"), ("hgb_noes_30k", "hgb_noes_full"),
         ("hgb_recent", "hgb_full"), ("tabpfn_recent", "tabpfn_50k"), ("tabpfn_50k", "hgb_full")]
table["comparisons"] = [compare(scores, y, idx, a, b) for a, b in comps if a in scores and b in scores]
result["anomaly_test_all"] = table
# sample efficiency: learning curves on the 8k eval test rows, and TabPFN at n vs HGB on all 80k rows
CURVE = {"tabpfn": [("tabpfn_5k", 5000), ("tabpfn_10k", 10000), ("tabpfn_30k", 30000), ("tabpfn_50k", 50000)],
         "hgb": [("hgb_5k", 5000), ("hgb_10k", 10000), ("hgb_30k", 30000), ("hgb_full", 80098)]}
rows = list(llm["test"])
table, scores, y, idx = evaluate(rows, "test_eval_curve", [c for v in CURVE.values() for c, _ in v])
comps = [(t, "hgb_full") for t in ["tabpfn_5k", "tabpfn_10k", "tabpfn_30k", "tabpfn_50k"]] + \
        [("tabpfn_5k", "hgb_5k"), ("tabpfn_10k", "hgb_10k"), ("tabpfn_30k", "hgb_30k")]
table["comparisons"] = [compare(scores, y, idx, a, b) for a, b in comps if a in scores and b in scores]
table["curve"] = {m: [dict(config=c, n_train=n, **{k: table["models"][c][k] for k in
                                                     ["pr_auc_mean", "pr_auc_sd", "pr_auc_ci95_seed0", "per_seed_pr_auc"]})
                      for c, n in v if c in table["models"]] for m, v in CURVE.items()}
result["sample_efficiency"] = table
(R / "m4_comparison.json").write_text(json.dumps(result, indent=1))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

fig, ax = plt.subplots(figsize=(6.4, 4.2))
for m, label, c in [("tabpfn", "TabPFN-3.5", "C0"), ("hgb", "HistGBT", "C1")]:
    pts = table["curve"][m]
    ns = [q["n_train"] for q in pts]
    ax.plot(ns, [q["pr_auc_mean"] for q in pts], "o-", color=c, label=f"{label} (mean of 3 seeds)")
    lo, hi = np.array([q["pr_auc_ci95_seed0"] for q in pts]).T
    ax.fill_between(ns, lo, hi, color=c, alpha=0.15)
    for q in pts:
        ax.scatter([q["n_train"]] * len(q["per_seed_pr_auc"]), q["per_seed_pr_auc"], color=c, s=8, alpha=0.6)
ax.axhline(table["base_rate"], color="grey", ls=":", label="base rate")
ticks = sorted({q["n_train"] for v in table["curve"].values() for q in v})
ax.set_xscale("log")
ax.set_xticks(ticks, [f"{t // 1000}k" for t in ticks])
ax.minorticks_off()
ax.set_xlabel("training rows (n_train)")
ax.set_ylabel("PR-AUC on 2026 test (8,000 eval rows)")
ax.set_title("Sample efficiency: TabPFN-3.5 vs HistGBT", fontsize=11)
ax.legend(fontsize=8, loc="lower right")
ax.grid(alpha=0.3)
fig.text(0.01, 0.01, f"Bands: 95% bootstrap CI (seed 0); dots: seeds. Data as of {result['data_as_of']}.",
         fontsize=7, color="grey")
fig.tight_layout()
fig.savefig(R / "learning_curve.png", dpi=150)

# markdown tables
NAMES = {"copy_cna": "copy-CNA (never flags)", "lr_full": "Logistic regression (all train)",
         "hgb_full": "HistGBT (all 80k train)", "hgb_50k": "HistGBT (50k subsample)", "hgb_30k": "HistGBT (30k)",
         "hgb_stack": "HistGBT (10k stack_train)", "hgb_llm_stack": "HistGBT + LLM features (10k stack_train)",
         "tabpfn_stack": "TabPFN-3.5 (10k stack_train)", "tabpfn_50k": "TabPFN-3.5 (50k subsample)",
         "tabpfn_llm_stack": "**TabPFN-3.5 + LLM features (10k stack_train)**",
         "llm_ft_alone": "Fine-tuned Qwen3-8B alone (score delta)", "hgb_noes_full": "HistGBT, no early stopping (80k)",
         "hgb_noes_30k": "HistGBT, no early stopping (30k)", "hgb_recent": "HistGBT, train 2024+ only",
         "tabpfn_recent": "TabPFN-3.5, train 2024+ only (50k)",
         "hgb_5k": "HistGBT (5k)", "hgb_10k": "HistGBT (10k)", "tabpfn_5k": "TabPFN-3.5 (5k)",
         "tabpfn_10k": "TabPFN-3.5 (10k)", "tabpfn_30k": "TabPFN-3.5 (30k)"}


def fmt(x, nd=3):
    return "—" if x is None else f"{x:.{nd}f}"


def model_table(t):
    lines = [f"n = {t['n']:,}, base rate {t['base_rate']:.3f}", "",
             "| Model | PR-AUC (mean of seeds) | 95% CI (seed 0) | seed sd | ROC-AUC | Brier | Precision top 10% |",
             "|---|---|---|---|---|---|---|"]
    for name, m in sorted(t["models"].items(), key=lambda kv: kv[1]["pr_auc_mean"]):
        sd = fmt(m["pr_auc_sd"]) if len(m["seeds"]) > 1 else "—"
        lines.append(f"| {NAMES.get(name, name)} | {m['pr_auc_mean']:.3f} | {m['pr_auc_ci95_seed0'][0]:.3f}–"
                     f"{m['pr_auc_ci95_seed0'][1]:.3f} | {sd} | {fmt(m['roc_auc'])} | {fmt(m['brier'], 4)} | "
                     f"{fmt(m['precision_top10'])} |")
    return lines


def comp_table(t):
    lines = ["| A vs B | ΔPR-AUC per seed [95% CI] | Verdict |", "|---|---|---|"]
    for c in t["comparisons"]:
        per = "; ".join(f"s{r['seed']}: {r['diff']:+.3f} [{r['ci95'][0]:+.3f}, {r['ci95'][1]:+.3f}]"
                        for r in c["per_seed"])
        lines.append(f"| {NAMES.get(c['a'], c['a'])} vs {NAMES.get(c['b'], c['b'])} | {per} | {c['verdict']} |")
    return lines


md = [f"# M4 tables (generated by scripts/13_final_table.py; evaluation snapshot {result['data_as_of']})", ""]
for split in ["test", "val"]:
    t = result[f"eval_rows_{split}"]
    md += [f"## {split}: rows with a fine-tuned LLM prediction", ""] + model_table(t) + [""]
    b = t["llm_ft_alone_binary"]
    md += [f"Fine-tuned LLM as a yes/no bump flag: precision {b['precision']:.3f}, recall {b['recall']:.3f}, "
           f"flags {b['flag_rate']:.1%} of rows.", ""] + comp_table(t) + [""]
t = result["anomaly_test_all"]
md += ["## HGB anomaly and recency (all test rows)", ""] + model_table(t) + [""] + comp_table(t) + [""]
t = result["sample_efficiency"]
md += ["## Sample efficiency (8k eval test rows)", ""] + model_table(t) + [""] + comp_table(t) + [""]
(R / "m4_tables.md").write_text("\n".join(md))
print("\n".join(md))
