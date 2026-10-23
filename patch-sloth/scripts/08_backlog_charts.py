"""M7 evidence charts (SPEC §15 M7, §17) on the frozen evaluation snapshot (results/data_as_of.txt, 2026-10-21).

Writes results/charts/*.png (blog width: 8 x 4.5 in at 160 dpi = 1280 px) and results/charts/charts_data.json with
every number plotted, so each chart is backed by a file.
  01_deferred_per_month      CVEs with status Deferred, by publication month
  02_nvd_own_score_rate      share of analysed, CNA-scored CVEs where NVD wrote its own v3.1 vector, by month
  03_field_disagreement      CNA vs NVD disagreement per CVSS field (rows where both scored), by year
  04_bump_rate_by_scorer     NVD raised the severity band: rate for the 15 biggest scorers of labelled CVEs
  05_drift_2026              (a) bump rate by month, val vs test; (b) precision of a val-tuned vs a label-free tau
The TabPFN vs HGB learning curve already exists (results/learning_curve.png, scripts/11 + 13) and is not redrawn.
Panel 05b refits HGB on all train rows (seed 0, CPU, ~1 min) because per-row predictions are not in results/.
Usage: python scripts/08_backlog_charts.py [--no_hgb]"""
import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import tabular  # noqa: E402
from patchsloth.cvss import METRICS as FIELDS  # noqa: E402
from patchsloth.cvss import parse  # noqa: E402
from patchsloth.features import FeatureBuilder  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--no_hgb", action="store_true", help="skip the HGB refit (panel 05b reuses charts_data.json)")
a = ap.parse_args()

R = Path("results")
OUT = R / "charts"
OUT.mkdir(parents=True, exist_ok=True)
AS_OF = (R / "data_as_of.txt").read_text().strip()
SOURCE = f"Source: NVD JSON 2.0 (fkie-cad mirror), data as of {AS_OF}. Patch Sloth"

# reference palette (dataviz skill, light mode): slots 1-3 validate all-pairs
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, MUTED, GRID = "#0b0b0b", "#52514e", "#8a8984", "#e6e5e0"
plt.rcParams.update({
    "font.size": 11, "axes.titlesize": 14, "axes.titleweight": "bold", "axes.titlelocation": "left",
    "axes.edgecolor": MUTED, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "axes.grid.axis": "y",
    "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True, "figure.facecolor": "white",
    "legend.frameon": False,
})
data = {"data_as_of": AS_OF}


def finish(fig, name, caption, subtitle=None):
    """Figure-level title (taken from the first axes) and subtitle, so they never collide; caption at the bottom."""
    ax = fig.axes[0]
    fig.text(0.01, 0.975, ax.get_title(loc="left"), fontsize=14, fontweight="bold", color=INK, va="top")
    ax.set_title("", loc="left")
    if subtitle:
        fig.text(0.01, 0.915, subtitle, color=INK2, fontsize=10.5, va="top")
    fig.text(0.01, 0.01, caption, color=MUTED, fontsize=8.5, ha="left", va="bottom", wrap=True)
    fig.savefig(OUT / f"{name}.png", dpi=160)
    plt.close(fig)
    print("wrote", OUT / f"{name}.png")


def month_axis(ax, months, every=3):
    ax.set_xticks(range(0, len(months), every))
    ax.set_xticklabels([pd.Timestamp(m).strftime("%b\n%Y") if m.endswith("-01") or i == 0 else
                        pd.Timestamp(m).strftime("%b") for i, m in list(enumerate(months))[::every]])
    ax.set_xlim(-0.7, len(months) - 0.3)


df = pd.read_parquet("data/cves.parquet")
df["month"] = df.published.str[:7]
last_day = df.published.max()
partial = f"{last_day[:7]} is partial (to {last_day})"
months = [str(p) for p in pd.period_range("2024-01", last_day[:7], freq="M")]
april = months.index("2026-04")

# ---------------------------------------------------------------- 01 Deferred per month
dfr = df[df.status == "Deferred"].groupby("month").size().reindex(months, fill_value=0)
data["deferred_per_month"] = dfr.to_dict()
fig, ax = plt.subplots(figsize=(8, 4.5))
fig.subplots_adjust(left=0.09, right=0.98, top=0.84, bottom=0.2)
ax.bar(range(len(months)), dfr.values, width=0.72, color=BLUE)
ax.axvline(april - 0.5, color=INK2, lw=1, ls="--")
ax.text(april - 0.7, dfr.max() * 0.97, "Apr 2026: NVD stops\nanalysing every CVE", ha="right", va="top",
        color=INK2, fontsize=9.5)
for m in ["2026-03", "2026-09"]:
    i = months.index(m)
    ax.text(i, dfr[m] + dfr.max() * 0.015, f"{dfr[m]:,}", ha="center", va="bottom", fontsize=9, color=INK,
            bbox=dict(fc="white", ec="none", pad=1))
month_axis(ax, months)
ax.set_ylabel("CVEs marked Deferred")
ax.set_title("Deferred CVEs per month")
finish(fig, "01_deferred_per_month",
       f"{SOURCE}. CVEs with NVD status 'Deferred', by publication month (non-rejected). {partial}.",
       "Deferred = NVD will not add its own score; only the reporter's (CNA's) score exists")

# ---------------------------------------------------------------- 02 NVD own-score rate
an = df[df.cna_vector.notna() & df.status.isin(["Analyzed", "Modified"])]
own = an.groupby("month").nvd_own.agg(["mean", "size"]).reindex(months)
data["nvd_own_score_rate"] = {m: dict(rate=float(r["mean"]), n=int(r["size"])) for m, r in own.iterrows()}
fig, ax = plt.subplots(figsize=(8, 4.5))
fig.subplots_adjust(left=0.09, right=0.98, top=0.84, bottom=0.2)
x = np.arange(len(months))
ax.plot(x, own["mean"] * 100, color=BLUE, lw=2, marker="o", ms=4)
ax.axvline(april - 0.5, color=INK2, lw=1, ls="--")
for m in ["2024-01", "2025-01", "2026-01", months[-2]]:
    i = months.index(m)
    ax.annotate(f"{own.loc[m, 'mean']:.0%}", (i, own.loc[m, "mean"] * 100), textcoords="offset points",
                xytext=(0, 8), ha="center", fontsize=9.5, color=INK)
month_axis(ax, months)
ax.set_ylim(0, 100)
ax.set_ylabel("% where NVD wrote its own score")
ax.set_title("How often NVD still writes its own score")
finish(fig, "02_nvd_own_score_rate",
       f"{SOURCE}. Denominator: CVEs with a CNA CVSS v3.1 vector that NVD analysed (status Analyzed or Modified),"
       f" by publication month. {partial}.",
       "Share of analysed, CNA-scored CVEs where NVD wrote its own CVSS v3.1 vector")

# ---------------------------------------------------------------- 03 disagreement by field
both = df[df.nvd_own & df.cna_vector.notna() & df.nvd_vector.notna()].copy()
both["year"] = both.published.str[:4]
years = ["2024", "2025", "2026"]
dis = {}
for yr in years:
    b = both[both.year == yr]
    pc, pn = [parse(v) for v in b.cna_vector], [parse(v) for v in b.nvd_vector]
    dis[yr] = dict(n=len(b), **{f: float(np.mean([c[f] != n[f] for c, n in zip(pc, pn)])) for f in FIELDS})
data["field_disagreement"] = dis
fig, ax = plt.subplots(figsize=(8, 4.5))
fig.subplots_adjust(left=0.09, right=0.98, top=0.84, bottom=0.2)
w = 0.26
for k, (yr, col) in enumerate(zip(years, [BLUE, ORANGE, AQUA])):
    ax.bar(np.arange(len(FIELDS)) + (k - 1) * w, [dis[yr][f] * 100 for f in FIELDS], width=w - 0.03, color=col,
           label=f"{yr} (n={dis[yr]['n']:,})")
for i, f in enumerate(FIELDS):
    ax.text(i, dis["2025"][f] * 100 + 1.5, f"{dis['2025'][f]:.0%}", ha="center", fontsize=8.5, color=INK)
names = {"AV": "Attack\nvector", "AC": "Attack\ncomplexity", "PR": "Privileges\nrequired", "UI": "User\ninteraction",
         "S": "Scope", "C": "Confidentiality", "I": "Integrity", "A": "Availability"}
ax.set_xticks(range(len(FIELDS)))
ax.set_xticklabels([names[f] for f in FIELDS], fontsize=9)
ax.grid(axis="x", visible=False)
ax.set_ylabel("% of pairs where NVD ≠ CNA")
ax.legend(loc="upper left", ncol=3, fontsize=9.5)
ax.set_ylim(0, max(dis[y][f] for y in years for f in FIELDS) * 100 * 1.25)
ax.set_title("Where NVD and the CNA disagree")
finish(fig, "03_field_disagreement",
       f"{SOURCE}. CVEs where both the CNA and NVD wrote a CVSS v3.1 vector, by publication year; labels show 2025.",
       "Share of CVEs where NVD's value for a CVSS field differs from the CNA's")

# ---------------------------------------------------------------- 04 bump rate by scorer
lab = df[df.split.isin(["train", "val", "test"])].copy()
lab["scorer"] = np.where(lab.score_source == "CISA-ADP", "CISA-ADP (Vulnrichment)", lab.cna)
short = {"416baaa9-dc9f-4396-8d5f-8c081fb06d67": "Linux kernel", "cna@vuldb.com": "VulDB",
         "security-advisories@github.com": "GitHub", "secure@microsoft.com": "Microsoft",
         "audit@patchstack.com": "Patchstack", "secalert_us@oracle.com": "Oracle", "security@wordfence.com": "Wordfence",
         "chrome-cve-admin@google.com": "Google Chrome", "psirt@adobe.com": "Adobe", "psirt@us.ibm.com": "IBM",
         "product-security@apple.com": "Apple", "contact@wpscan.com": "WPScan", "psirt@cisco.com": "Cisco",
         "disclosure@vulncheck.com": "VulnCheck", "security_alert@emc.com": "Dell", "security@apache.org": "Apache",
         "product-security@qualcomm.com": "Qualcomm", "cve@mitre.org": "MITRE", "security@huntr.dev": "huntr",
         "zdi-disclosures@trendmicro.com": "ZDI", "secalert@redhat.com": "Red Hat", "psirt@huawei.com": "Huawei",
         "security@android.com": "Android", "productcert@siemens.com": "Siemens", "psirt@fortinet.com": "Fortinet"}
y = lab.bump_up.astype(bool)
top = lab.scorer.value_counts().head(15).index
g = lab.groupby("scorer").bump_up.agg(lambda s: s.astype(bool).mean()).loc[top]
n = lab.scorer.value_counts().loc[top]
z = 1.96
lo = (g + z * z / (2 * n) - z * np.sqrt(g * (1 - g) / n + z * z / (4 * n * n))) / (1 + z * z / n)
hi = (g + z * z / (2 * n) + z * np.sqrt(g * (1 - g) / n + z * z / (4 * n * n))) / (1 + z * z / n)
order = g.sort_values().index
base = float(y.mean())
data["bump_rate_by_scorer"] = dict(base_rate=base, n_labelled=int(len(lab)), rows={
    short.get(s, s): dict(id=s, n=int(n[s]), rate=float(g[s]), ci95=[float(lo[s]), float(hi[s])]) for s in top})
fig, ax = plt.subplots(figsize=(8, 6))
fig.subplots_adjust(left=0.36, right=0.96, top=0.86, bottom=0.17)
yy = np.arange(len(order))
ax.barh(yy, g[order] * 100, height=0.66, color=BLUE)
ax.errorbar(g[order] * 100, yy, xerr=[(g - lo)[order] * 100, (hi - g)[order] * 100], fmt="none", ecolor=INK2,
            elinewidth=1, capsize=0)
ax.axvline(base * 100, color=ORANGE, lw=1.5, ls="--")
ax.text(base * 100 + 0.6, len(order) - 0.4, f"all labelled CVEs {base:.0%}", color=INK2, fontsize=9, va="center")
ax.set_yticks(yy)
ax.set_yticklabels([f"{short.get(s, s)}  (n={n[s]:,})" for s in order], fontsize=9.5)
for i, s in enumerate(order):
    ax.text(hi[s] * 100 + 0.8, i, f"{g[s]:.0%}", va="center", fontsize=9, color=INK)
ax.grid(axis="y", visible=False)
ax.grid(axis="x", visible=True)
ax.set_xlabel("% of CVEs where NVD raised the severity band")
ax.set_xlim(0, float(hi.max()) * 100 * 1.15)
ax.set_title("How often NVD raised each scorer's severity")
finish(fig, "04_bump_rate_by_scorer",
       f"{SOURCE}. Labelled CVEs 2021-2026 (train+val+test, SPEC §8.2 label rule), 15 biggest scorers. Scorer = the CNA,"
       " or CISA-ADP when the vector came from Vulnrichment. Bars: 95% Wilson intervals.",
       "Share of each scorer's CVEs that NVD put in a higher severity band")

# ---------------------------------------------------------------- 05 drift
labm = lab[lab.month.isin(months)]
br = labm.groupby("month").bump_up.agg(lambda s: s.astype(bool).mean()).reindex(months)
split_of = labm.groupby("month").split.first().reindex(months)
data["bump_rate_by_month"] = {m: dict(rate=None if np.isnan(br[m]) else float(br[m]), split=split_of[m])
                              for m in months}
split_rates = {s: float(lab[lab.split == s].bump_up.astype(bool).mean()) for s in ["train", "val", "test"]}
data["bump_rate_by_split"] = split_rates

if not a.no_hgb:
    train = df.split == "train"
    fb = FeatureBuilder().fit(df[train])
    X = fb.transform(df)
    clf = tabular.fit("hgb", X[train], df.bump_up[train].astype(int), seed=0)

    def pp(mask):
        return tabular.predict_proba(clf, X[mask.to_numpy()]), df.bump_up[mask].astype(int).to_numpy()

    p_val, y_val = pp(df.split == "val")
    p_test, y_test = pp(df.split == "test")
    p_def = tabular.predict_proba(clf, X[(df.split == "deferred_unlabeled").to_numpy()])
    pub = df.published[df.split == "val"].to_numpy()
    recent = pub >= str((pd.Timestamp(pub.max()) - pd.DateOffset(months=3)).date())
    tau_val = tabular.choose_tau(y_val[recent], p_val[recent], min_precision=0.5)
    tau_def = float(np.quantile(p_def, 0.90))

    def at(yv, p, t):
        f = p >= t
        return dict(threshold=float(t), flag_rate=float(f.mean()), precision=float(yv[f].mean()),
                    recall=float(yv[f].sum() / yv.sum()))

    data["tau_drift_hgb_all_train"] = dict(
        model="HGB, all 80,098 train rows, seed 0", tau_val_rule="precision >= 0.5 on the last 3 months of val",
        tau_label_free_rule="90th percentile of p_bump over deferred_unlabeled",
        val_recent=at(y_val[recent], p_val[recent], tau_val), val_recent_base_rate=float(y_val[recent].mean()),
        test_base_rate=float(y_test.mean()), test_at_tau_val=at(y_test, p_test, tau_val),
        test_at_tau_label_free=at(y_test, p_test, tau_def))
else:
    data["tau_drift_hgb_all_train"] = json.loads((OUT / "charts_data.json").read_text())["tau_drift_hgb_all_train"]
td = data["tau_drift_hgb_all_train"]
gate = json.loads((R / "gated_override.json").read_text())["seeds"]["0"]
data["gated_override_seed0"] = dict(all_val=gate["chosen_on_val"]["test_vs_copy_cna"],
                                    last3m_val=gate["chosen_on_val_last3m"]["test_vs_copy_cna"])

fig, (a1, a2) = plt.subplots(1, 2, figsize=(8, 4.5), gridspec_kw=dict(width_ratios=[1.7, 1]))
fig.subplots_adjust(left=0.08, right=0.98, top=0.8, bottom=0.2, wspace=0.32)
x = np.arange(len(months))
for s, col, lbl in [("train", MUTED, "train"), ("val", BLUE, "val (2025-H2)"), ("test", ORANGE, "test (2026)")]:
    m = (split_of == s).to_numpy()
    a1.bar(x[m], br.to_numpy()[m] * 100, width=0.72, color=col, label=f"{lbl}: {split_rates[s]:.0%}")
month_axis(a1, months, every=6)
a1.set_ylabel("% where NVD raised the band")
a1.set_title("Bump rate by month", fontsize=12)
a1.legend(loc="upper right", fontsize=8.5)
bars = [("Val-tuned τ\n(last 3 months\nof val)", td["test_at_tau_val"]["precision"], MUTED),
        ("Label-free τ\n(top 10% of\nDeferred)", td["test_at_tau_label_free"]["precision"], BLUE)]
a2.bar(range(2), [b[1] * 100 for b in bars], width=0.6, color=[b[2] for b in bars])
a2.axhline(td["val_recent"]["precision"] * 100, color=INK2, lw=1, ls="--", label="target set on val")
a2.axhline(td["test_base_rate"] * 100, color=ORANGE, lw=1.5, ls=":", label="2026 base rate")
a2.legend(loc="upper left", fontsize=8.5)
for i, b in enumerate(bars):
    a2.text(i, b[1] * 100 + 1.5, f"{b[1]:.0%}", ha="center", fontsize=10, color=INK, fontweight="bold")
a2.set_xticks(range(2))
a2.set_xticklabels([b[0] for b in bars], fontsize=8.5)
a2.grid(axis="x", visible=False)
a2.set_ylim(0, 110)
a2.set_yticks(range(0, 101, 20))
a2.set_ylabel("2026 precision of flags (%)")
a2.set_title("Precision on 2026", fontsize=12)
fig.suptitle("2026 drift: NVD raises far fewer scores", x=0.01, ha="left", fontsize=14, fontweight="bold")
fig.text(0.01, 0.885, "A threshold tuned on 2025 decisions over-flags on 2026", color=INK2, fontsize=10.5)
fig.text(0.01, 0.01,
         f"{SOURCE}. Left: labelled CVEs by publication month. Right: HGB on all train rows (seed 0); val-tuned τ ="
         f" {td['test_at_tau_val']['threshold']:.3f}, label-free τ = {td['test_at_tau_label_free']['threshold']:.3f};"
         f" all {len(df[df.split == 'test']):,} test rows. {partial}.", color=MUTED, fontsize=8.5, wrap=True)
fig.savefig(OUT / "05_drift_2026.png", dpi=160)
plt.close(fig)
print("wrote", OUT / "05_drift_2026.png")

(OUT / "charts_data.json").write_text(json.dumps(data, indent=1, default=float))
print(json.dumps({k: data[k] for k in ["bump_rate_by_split", "tau_drift_hgb_all_train"]}, indent=1, default=float))
