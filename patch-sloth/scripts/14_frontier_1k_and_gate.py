"""M4 add-ons.
(1) Every model on the SAME 1,000 test rows Ultramarine was scored on (results/frontier_subsample.json):
    Task A (vectors) for copy-CNA, TF-IDF+LR, base Qwen, fine-tuned Qwen, Ultramarine; Task B (bump ranking) for
    the tabular/stacked models. Plus cost per 1k CVEs from results/costs.jsonl.
(2) Gated override: final vector = fine-tuned LLM vector if stacked p_bump >= t, else the CNA vector. t is swept
    and chosen on val only (max severity accuracy); test (2026) is reported at that t with a paired bootstrap of
    severity accuracy vs copy-CNA.
Needs scripts/03 (data/preds/tfidf_lr_*.json) and scripts/12 (data/m4/*). Writes results/frontier_1k.json,
results/gated_override.{json,png}."""
import json
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.cvss import base_score, parse, sev_rank  # noqa: E402
from patchsloth.metrics import evaluate, mcnemar  # noqa: E402

R, M4 = Path("results"), Path("data/m4")
N_BOOT, SEEDS = 1000, [0, 1, 2]
as_of = (R / "data_as_of.txt").read_text().strip()
df = pd.read_parquet("data/cves.parquet").set_index("cve")


def vecs(name, split):
    if name == "tfidf_lr":
        return {c: v for c, (v, _) in json.loads(Path(f"data/preds/tfidf_lr_{split}.json").read_text()).items()}
    return json.loads((R / f"llm_vectors_{name}_{split}.json").read_text())


def m4(name, seed):
    return pd.read_parquet(M4 / f"{name}_s{seed}.parquet").set_index("cve").p


# ---------------------------------------------------------------- (1) same 1k rows + cost
sub = json.loads((R / "frontier_subsample.json").read_text())["cves"]
d = df.loc[sub]
task_a = {}
copy_res, ok_copy = evaluate(d, list(d.cna_vector), n_boot=N_BOOT)
task_a["copy_cna"] = copy_res
for name in ["tfidf_lr", "base", "ft", "ultramarine"]:
    v = vecs(name, "test")
    missing = [c for c in sub if c not in v]
    assert not missing, f"{name}: {len(missing)} of the 1k rows have no prediction"
    res, ok = evaluate(d, [v[c] for c in sub], n_boot=N_BOOT)
    res["mcnemar_vs_copy_cna_severity"] = mcnemar(ok, ok_copy)
    task_a[name] = res
y1k = d.bump_up.astype(int).to_numpy()
task_b = {"copy_cna": dict(pr_auc=float(y1k.mean()), note="constant score: PR-AUC = base rate")}
for name in ["hgb_full", "tabpfn_50k", "tabpfn_stack", "tabpfn_llm_stack"]:
    pr = [average_precision_score(y1k, m4(name, s).loc[sub].to_numpy()) for s in SEEDS
          if (M4 / f"{name}_s{s}.parquet").exists()]
    task_b[name] = dict(pr_auc_mean=float(np.mean(pr)), pr_auc_per_seed=pr)

# cost per 1k CVEs (inference only), from the logged calls
agg = defaultdict(lambda: dict(usd=0.0, n=0, latency_s=0.0))
for line in open(R / "costs.jsonl"):
    r = json.loads(line)
    a = agg[(r["service"], r.get("task"))]
    a["usd"] += r.get("usd") or 0
    a["n"] += r.get("n") or 1
    a["latency_s"] += r.get("latency_s") or 0


def per_1k(*keys):
    usd = sum(agg[k]["usd"] for k in keys)
    n = sum(agg[k]["n"] for k in keys)
    return dict(usd_per_1k=1000 * usd / n, n_calls=n, usd_total=usd, source=[f"{s}/{t}" for s, t in keys])


cost = {"ft": per_1k(("tinker", "sample_ft_val"), ("tinker", "sample_ft_test")),
        "base": per_1k(("tinker", "sample_base_val"), ("tinker", "sample_base_test")),
        "ultramarine": per_1k(("ultramarine", "frontier_baseline"), ("ultramarine", "frontier_baseline_pilot")),
        "ft_one_off_training_usd": agg[("tinker", "sft")]["usd"],
        "copy_cna": dict(usd_per_1k=0.0), "tfidf_lr": dict(usd_per_1k=0.0, note="CPU, local"),
        "hgb": dict(usd_per_1k=0.0, note="CPU, local"),
        "tabpfn": dict(usd_per_1k=0.0, note="local 24 GB GPU; no metered cost (see wall times in m2_tabpfn.md)")}
(R / "frontier_1k.json").write_text(json.dumps(dict(data_as_of=as_of, n=len(sub), rows="results/frontier_subsample.json",
                                                    task_a=task_a, task_b=task_b, cost=cost), indent=1, default=float))
print("1k:", {k: round(v["severity_acc"], 3) for k, v in task_a.items()})
print("cost per 1k:", {k: round(v["usd_per_1k"], 4) for k, v in cost.items() if isinstance(v, dict)})


# ---------------------------------------------------------------- (2) gated override
def sev(v):
    return sev_rank(base_score(parse(v)))


def frame(split, seed):
    v = vecs("ft", split)
    rows = list(v)
    dd = df.loc[rows]
    return pd.DataFrame({"p": m4("tabpfn_llm_stack", seed).loc[rows].to_numpy(),
                         "llm_sev": [sev(v[c]) for c in rows], "cna_sev": dd.cna_sev.to_numpy(),
                         "lab_sev": dd.label_sev.to_numpy(), "y": dd.bump_up.astype(bool).to_numpy(),
                         "published": dd.published.to_numpy()}, index=rows)


def gate(f, t):
    over = f.p.to_numpy() >= t
    fsev = np.where(over, f.llm_sev, f.cna_sev)
    ok = fsev == f.lab_sev.to_numpy()
    yhat = fsev > f.cna_sev.to_numpy()
    y = f.y.to_numpy()
    tp = (yhat & y).sum()
    return dict(t=float(t), override_rate=float(over.mean()), severity_acc=float(ok.mean()),
                bump_precision=float(tp / max(yhat.sum(), 1)), bump_recall=float(tp / max(y.sum(), 1))), ok


def sweep(f):
    ts = np.unique(np.concatenate([[np.inf], np.quantile(f.p, np.linspace(0, 1, 201))]))
    return [gate(f, t)[0] for t in ts]


def paired_acc(ok_a, ok_b, seed=0):
    rng = np.random.default_rng(seed)
    n = len(ok_a)
    diffs = [(ok_a[i].mean() - ok_b[i].mean()) for i in (rng.integers(0, n, n) for _ in range(N_BOOT))]
    return dict(diff=float(ok_a.mean() - ok_b.mean()), ci95=[float(np.percentile(diffs, 2.5)),
                                                              float(np.percentile(diffs, 97.5))])


gated = {"data_as_of": as_of, "rule": "t maximises severity accuracy on val (or on the last 3 months of val); "
         "test is never used to choose t", "seeds": {}}
for seed in SEEDS:
    fv, ft_ = frame("val", seed), frame("test", seed)
    recent = fv.published >= str((pd.Timestamp(fv.published.max()) - pd.DateOffset(months=3)).date())
    sv, st, svr = sweep(fv), sweep(ft_), sweep(fv[recent])
    out = {"sweep_val": sv, "sweep_test": st}
    for rule, sw in [("val", sv), ("val_last3m", svr)]:
        best = max(sw, key=lambda r: (r["severity_acc"], -r["override_rate"]))
        m, ok = gate(ft_, best["t"])
        _, ok_copy = gate(ft_, np.inf)
        out[f"chosen_on_{rule}"] = dict(t=best["t"], val=best, test=m, test_vs_copy_cna=paired_acc(ok, ok_copy))
    # exploratory only (uses test labels to pick t): the best any threshold could do on 2026
    bt = max(st, key=lambda r: r["severity_acc"])
    ok_bt, ok_copy = gate(ft_, bt["t"])[1], gate(ft_, np.inf)[1]
    out["best_on_test_exploratory"] = dict(**bt, vs_copy_cna=paired_acc(ok_bt, ok_copy),
                                           note="t picked on test labels: optimistic, not a valid result")
    gated["seeds"][seed] = out
    c = out["chosen_on_val"]
    print(f"seed {seed}: t={c['t']:.3f} val acc {c['val']['severity_acc']:.4f} override {c['val']['override_rate']:.3f}"
          f" | test acc {c['test']['severity_acc']:.4f} override {c['test']['override_rate']:.3f} vs copy "
          f"{c['test_vs_copy_cna']['diff']:+.4f} {np.round(c['test_vs_copy_cna']['ci95'], 4)}"
          f" | last3m t={out['chosen_on_val_last3m']['t']:.3f} test vs copy "
          f"{out['chosen_on_val_last3m']['test_vs_copy_cna']['diff']:+.4f} "
          f"{np.round(out['chosen_on_val_last3m']['test_vs_copy_cna']['ci95'], 4)}"
          f" | best-on-test {bt['severity_acc']:.4f} vs copy {out['best_on_test_exploratory']['vs_copy_cna']['diff']:+.4f}")
(R / "gated_override.json").write_text(json.dumps(gated, indent=1))

s0 = gated["seeds"][0]
fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), sharey=True)
for ax, split in zip(axes, ["val", "test"]):
    sw = pd.DataFrame(s0[f"sweep_{split}"]).sort_values("override_rate")
    ax.plot(sw.override_rate, sw.severity_acc, color="C0", label="severity accuracy")
    ax.plot(sw.override_rate, sw.bump_precision, color="C1", label="bump precision")
    ax.plot(sw.override_rate, sw.bump_recall, color="C2", label="bump recall")
    ax.axhline(sw.severity_acc.iloc[0], color="C0", ls=":", label="copy-CNA severity accuracy")
    for rule, label, col in [("chosen_on_val", "all val", "grey"), ("chosen_on_val_last3m", "last 3 months of val", "C3")]:
        c = s0[rule]
        ax.axvline(c[split]["override_rate"], color=col, ls="--", label=f"t chosen on {label} = {c['t']:.2f}")
    ax.set_title(f"{'Val (2025-H2)' if split == 'val' else 'Test (2026)'}: LLM vector used when stacked p >= t",
                 fontsize=10)
    ax.set_xlabel("override rate (share of CVEs given the LLM vector)")
    ax.grid(alpha=0.3)
axes[0].set_ylabel("metric")
axes[1].legend(fontsize=8, loc="lower right")
fig.text(0.01, 0.01, f"Stacked TabPFN-3.5 + LLM features, seed 0; rows with an LLM prediction (n=8,000 each). "
         f"Data as of {as_of}.", fontsize=7, color="grey")
fig.tight_layout()
fig.savefig(R / "gated_override.png", dpi=150)
print("wrote results/frontier_1k.json, results/gated_override.{json,png}")
