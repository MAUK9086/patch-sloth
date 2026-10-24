"""Error analysis (SPEC §10): 20 false-positive "likely" flags and 20 false negatives on the 2026 evaluation test rows
(the 8,000 test CVEs with a fine-tuned-LLM prediction, frozen snapshot results/data_as_of.txt). Writes
results/error_sample.md for the human to tag [HUMAN].

Two sources (--model):
  hgb_llm_stack  (default, CPU) HistGBT + fine-tuned-LLM features trained on the 10k out-of-SFT stack_train rows,
                 seed 0: the M4 config `hgb_llm_stack` (scripts/12), refitted here from committed LLM predictions.
                 Bands and the gate are re-derived for THIS model with the served model's rules: likely >= q90 and
                 possible >= q75 of its p_bump over the Deferred CVEs with an LLM vector (label-free); gate t
                 maximises severity accuracy on the last 3 months of val (scripts/14's rule).
  served         the served stack (TabPFN-3.5 + LLM features, seed 0) from data/m4/tabpfn_llm_stack_s0.parquet
                 (scripts/12, GPU) with serving_stack.json's bands and gate; band counts are checked against it.

  false positive  band "likely" and NVD did NOT raise the band
  false negative  NVD raised the band, but the band is not "likely" (shown: "possible" or "unlikely")
"Ours" = what the product would serve: the LLM vector if p >= gate t, else the CNA vector. The raw LLM vector is
shown too. Usage: python scripts/10_error_analysis.py [--model hgb_llm_stack|served] [--n 20]"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.cvss import base_score, parse, sev_rank, severity  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--model", choices=["hgb_llm_stack", "served"], default="hgb_llm_stack")
ap.add_argument("--preds", default="data/m4/tabpfn_llm_stack_s0.parquet", help="per-row predictions (--model served)")
ap.add_argument("--n", type=int, default=20)
ap.add_argument("--out", default="results/error_sample.md")
a = ap.parse_args()

R = Path("results")
AS_OF = (R / "data_as_of.txt").read_text().strip()
llm = {}
for s in ["stack_train", "val", "test", "unanalysed"]:
    llm.update(json.loads((R / f"llm_vectors_ft_{s}.json").read_text()))
df = pd.read_parquet("data/cves.parquet")


def vsev(v):
    return sev_rank(base_score(parse(v))) if isinstance(v, str) else np.nan


if a.model == "served":
    if not Path(a.preds).exists():
        sys.exit(f"{a.preds} not found: it is written by scripts/12_m4_experiments.py (config tabpfn_llm_stack, "
                 "seed 0) on a GPU. See deploy/RUNBOOK.md.")
    serving = json.loads((R / "serving_stack.json").read_text())
    tau, tau_possible, gate_t = serving["tau"], serving["tau_possible"], serving["gate_t"]
    pr = pd.read_parquet(a.preds)
    pr = pr[pr.split == "test"]
    p_test = pd.Series(pr.p.to_numpy(), index=pr.cve)
    model_desc = f"{serving['model']} (the served model's configuration), from `{a.preds}`"
    rules = "bands and gate from `results/serving_stack.json`"
    check_bands = {b: v["n"] for b, v in serving["test_eval_rows"]["bands"].items()}
    yt = df.set_index("cve").loc[p_test.index].bump_up.astype(int).to_numpy()
    extra = dict(pr_auc_test=float(average_precision_score(yt, p_test.to_numpy())),
                 pr_auc_test_m4_seed0=json.loads((R / "m4_comparison.json").read_text())
                 ["eval_rows_test"]["models"]["tabpfn_llm_stack"]["per_seed_pr_auc"][0])
else:
    from patchsloth import tabular
    from patchsloth.features import LLM_INPUT, FeatureBuilder
    d0 = df[df.split.isin(["train", "val", "test", "deferred_unlabeled"])].copy()
    d0[LLM_INPUT] = d0.cve.map(llm)
    has = d0[LLM_INPUT].notna()
    train = d0.split == "train"
    # as scripts/12: vocabularies/TF-IDF fitted on all train rows, model on the train rows with an LLM vector
    fb = FeatureBuilder(with_llm=True).fit(d0[train])
    X, y = fb.transform(d0), d0.bump_up
    idx = d0[train & has].index
    clf = tabular.fit("hgb", X.loc[idx], y.loc[idx].astype(int), seed=0)

    def score(mask):
        m = mask.to_numpy()
        return pd.Series(tabular.predict_proba(clf, X[m]), index=d0.cve[m].to_numpy())

    p_test = score((d0.split == "test") & has)
    p_val = score((d0.split == "val") & has)
    p_def = score((d0.split == "deferred_unlabeled") & has)
    tau, tau_possible, tau_high = (float(np.quantile(p_def, q)) for q in (0.90, 0.75, 0.95))
    # gate: scripts/14's rule on the last 3 months of val (labels of val only)
    v = df.set_index("cve").loc[p_val.index]
    recent = v.published >= str((pd.Timestamp(v.published.max()) - pd.DateOffset(months=3)).date())
    fv = pd.DataFrame({"p": p_val, "llm_sev": [vsev(llm[c]) for c in p_val.index], "cna_sev": v.cna_sev,
                       "lab_sev": v.label_sev})[recent.to_numpy()]
    ts = np.unique(np.concatenate([[np.inf], np.quantile(fv.p, np.linspace(0, 1, 201))]))

    def acc(t):
        s = np.where(fv.p >= t, fv.llm_sev, fv.cna_sev)
        return float((s == fv.lab_sev).mean()), -float((fv.p >= t).mean())

    gate_t = float(max(ts, key=acc))
    yt = df.set_index("cve").loc[p_test.index].bump_up.astype(int).to_numpy()
    extra = dict(pr_auc_test=float(average_precision_score(yt, p_test.to_numpy())),
                 pr_auc_test_m4_seed0=json.loads((R / "m4_comparison.json").read_text())
                 ["eval_rows_test"]["models"]["hgb_llm_stack"]["per_seed_pr_auc"][0],
                 n_deferred_scored=int(len(p_def)), n_train=int(len(idx)), tau_high=tau_high,
                 gate_val_last3m=dict(n=int(len(fv)), severity_acc=acc(gate_t)[0], copy_cna_acc=acc(np.inf)[0]))
    model_desc = ("HistGBT + fine-tuned-LLM features, trained on the 10k out-of-SFT `stack_train` rows (seed 0; M4 "
                  "config `hgb_llm_stack`), refitted on CPU from the committed LLM predictions")
    rules = (f"bands re-derived for this model with the served rules (label-free quantiles of its p_bump over "
             f"{len(p_def):,} Deferred CVEs with an LLM vector); gate t chosen on the last 3 months of val")
    check_bands = None

d = df.set_index("cve").loc[p_test.index].copy()
d["p"] = p_test.to_numpy()
assert len(d) == 8000, f"expected the 8,000 2026 evaluation rows, got {len(d)}"
d["band"] = np.where(d.p >= tau, "likely", np.where(d.p >= tau_possible, "possible", "unlikely"))
if check_bands:
    # predictions rebuilt on other hardware/data are close to, not bit-identical with, the served model's: report
    # the match, and stop only if it is clearly a different model
    extra["band_counts_vs_serving_stack"] = {b: dict(now=int((d.band == b).sum()), served=n)
                                             for b, n in check_bands.items()}
    gap = abs(extra["pr_auc_test"] - extra["pr_auc_test_m4_seed0"])
    print("band counts (now vs serving_stack.json):", extra["band_counts_vs_serving_stack"], f"PR-AUC gap {gap:.4f}")
    assert gap < 0.01, f"PR-AUC {extra['pr_auc_test']:.4f} vs M4 seed 0 {extra['pr_auc_test_m4_seed0']:.4f}"
d["llm_vector"] = [llm.get(c) for c in d.index]
d["our_vector"] = np.where(d.p >= gate_t, d.llm_vector, d.cna_vector)
y = d.bump_up.astype(bool)
bands = {b: dict(n=int((d.band == b).sum()), observed_bump_rate=float(y[d.band == b].mean())) for b in
         ["likely", "possible", "unlikely"]}

fp_pool = d[(d.band == "likely") & ~y]
fn_pool = d[y & (d.band != "likely")]
rng = np.random.default_rng(0)
fp = fp_pool.loc[rng.choice(fp_pool.index, size=min(a.n, len(fp_pool)), replace=False)].sort_values("p", ascending=False)
fn = fn_pool.loc[rng.choice(fn_pool.index, size=min(a.n, len(fn_pool)), replace=False)].sort_values("p", ascending=False)


def sev(v):
    if not isinstance(v, str):
        return "—"
    s = base_score(parse(v))
    return f"{severity(s)} {s}"


def case(i, cve, r):
    desc = " ".join(str(r.description).split())
    nvd = r.nvd_vector if isinstance(r.nvd_vector, str) else None
    return "\n".join([
        f"### {i}. {cve}",
        "",
        f"- Published {r.published} · scorer `{r.cna}` ({r.score_source}) · CNA CWE {r.cna_cwe or '—'}",
        f"- Band **{r.band}** (p_bump {r.p:.3f}; likely ≥ {tau:.3f}, gate ≥ {gate_t:.3f})",
        "",
        "| | Vector | Severity |",
        "|---|---|---|",
        f"| CNA | `{r.cna_vector}` | {sev(r.cna_vector)} |",
        f"| NVD | `{nvd}` | {sev(nvd)} |" if nvd else
        "| NVD | — (kept the CNA vector; label = CNA) | — |",
        f"| Ours (served rule) | `{r.our_vector}` | {sev(r.our_vector)} |",
        f"| Fine-tuned LLM (raw) | `{r.llm_vector}` | {sev(r.llm_vector)} |",
        "",
        f"> {desc}",
        "",
        "Tag: ",
        "",
    ])


note = []
if a.model == "hgb_llm_stack":
    note = ["> **Sample drawn from the HGB + LLM stack** (test PR-AUC 0.609 [0.573–0.643] vs 0.621 [0.584–0.655] for "
            "the served TabPFN stack: the 95% CIs overlap, but no paired test between the two was run; see "
            "`results/final_table.md` §2 and `results/m4_comparison.json`). The served model's per-row predictions "
            "were unavailable after access to the GPU workstation ended. `deploy/RUNBOOK.md` regenerates this file "
            "from the served model.", ""]
lines = [
    "# Error analysis sample (2026 evaluation rows)",
    "",
    *note,
    f"Evaluation snapshot: NVD data as of {AS_OF}. Model: {model_desc}. Rules: {rules}. Rows: the {len(d):,} 2026 "
    f"test CVEs with a fine-tuned-LLM prediction (base rate {y.mean():.3f}). Generated by "
    f"`scripts/10_error_analysis.py --model {a.model}` (random sample, seed 0; each section sorted by p_bump).",
    "",
    f"- Cut-offs: likely ≥ {tau:.3f}, possible ≥ {tau_possible:.3f}, gate t = {gate_t:.3f}.",
    "- Bands on these rows: " + "; ".join(f"{b} {v['n']} (observed bump rate {v['observed_bump_rate']:.3f})"
                                         for b, v in bands.items()) + ".",
    f"- **False positives:** band \"likely\" but NVD did not raise the band: {len(fp_pool)} of "
    f"{bands['likely']['n']} \"likely\" rows; {len(fp)} sampled.",
    f"- **False negatives:** NVD raised the band but the band is not \"likely\": {len(fn_pool)} of {int(y.sum())} "
    f"raised rows ({int((fn_pool.band == 'possible').sum())} \"possible\", "
    f"{int((fn_pool.band == 'unlikely').sum())} \"unlikely\"); {len(fn)} sampled "
    f"({int((fn.band == 'possible').sum())} \"possible\", {int((fn.band == 'unlikely').sum())} \"unlikely\").",
    "- **Ours (served rule)** = the fine-tuned LLM vector if p ≥ the gate t, otherwise the CNA vector.",
    "",
    "**Tag each case [HUMAN]** with one of: `model wrong` / `NVD worst-casing` / `ambiguous description` / "
    "`label noise`.",
    "",
    "## False positives (flagged \"likely\", NVD did not raise)",
    "",
]
lines += [case(i, c, r) for i, (c, r) in enumerate(fp.iterrows(), 1)]
lines += ["## False negatives (NVD raised, not flagged \"likely\")", ""]
lines += [case(i, c, r) for i, (c, r) in enumerate(fn.iterrows(), len(fp) + 1)]
Path(a.out).write_text("\n".join(lines), encoding="utf-8")
summary = dict(model=a.model, data_as_of=AS_OF, n=len(d), tau=tau, tau_possible=tau_possible, gate_t=gate_t,
               bands=bands, fp_pool=len(fp_pool), fn_pool=len(fn_pool), sampled_fp=list(fp.index),
               sampled_fn=list(fn.index), **extra)
Path(a.out).with_suffix(".json").write_text(json.dumps(summary, indent=1))
print(json.dumps({k: v for k, v in summary.items() if not k.startswith("sampled")}, indent=1))
