<!--
Post draft (SPEC §17). The technical sections are written as plain factual prose. Every number comes from a file in
results/, named in [brackets]; delete the brackets before publishing, or keep them as links. Ahmad's parts are
[AHMAD: ...] placeholders. Image paths are relative to this file; upload the images to DEV before publishing.
Evaluation snapshot: NVD data as of 2026-10-21T14:41Z unless a sentence says otherwise. The live feed is release
feed-2026-10-23 (data as of 2026-10-23).
-->

# [AHMAD: title]

[AHMAD: cover image; tags: hf26challenge + partner tags]

## 1. Hook

[AHMAD: hook, in your words. SPEC line to riff on: "NIST stopped checking. Here's what that costs you."]

![Deferred CVEs per month](../results/charts/01_deferred_per_month.png)

In March 2026, 1,465 newly published CVEs were marked Deferred. In September it was 5,768. From April to 20
October 2026, the total was 26,809. [`results/charts/charts_data.json` → `deferred_per_month`]

## 2. The problem, with evidence

A Deferred CVE is one NIST's National Vulnerability Database (NVD) will not analyse. Its only severity score is the
one from the CNA, the organisation that reported it (often the vendor itself). [SPEC §1]

NVD's own review is also shrinking for the CVEs it does analyse. In January 2024, NVD wrote its own CVSS v3.1
vector for 94% of the analysed CVEs that had a CNA score. By January 2025 it was 49%, by January 2026 38%, and in
September 2026 12%. [`charts_data.json` → `nvd_own_score_rate`]

![NVD own-score rate](../results/charts/02_nvd_own_score_rate.png)

When both scored, they often disagreed. Among 2025 CVEs where NVD and the CNA both wrote a vector (11,697 CVEs),
they disagreed on Confidentiality 49% of the time, Integrity 43% and Availability 40%. Attack Vector, by contrast,
differed only 6% of the time. [`charts_data.json` → `field_disagreement`]

![Field disagreement](../results/charts/03_field_disagreement.png)

Across all 122,459 labelled CVEs from 2021 to 2026, NVD's label put 16.4% in a higher severity band than the scorer
had. The rate depends heavily on who scored the CVE. [`charts_data.json` → `bump_rate_by_scorer`]

![Bump rate by scorer](../results/charts/04_bump_rate_by_scorer.png)

- VulDB: 77% of 11,421 CVEs raised. Most of these are one pattern: VulDB scores C/I/A as Low/Low/Low and NVD as
  High/High/High (5,850 of the 8,747 raised VulDB CVEs; two thirds of those 5,850 carry CWE-89, SQL injection).
  VulDB's rate has fallen over time, to 57.9% in 2026. [`results/vuldb_check.md`]
- Oracle (4,711) and the Linux kernel (3,810): 0.1%. CISA-ADP (Vulnrichment, 33,672): 1.9%.
  [`charts_data.json`]

[AHMAD: the policy change and the backlog-exploitation angle. SPEC §17 sources, read before quoting:
[Help Net Security](https://www.helpnetsecurity.com/?p=366659),
[CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/),
[VulnCheck](https://us-gov-east-1.vulncheck.com/blog/nvd-backlog-exploitation-lurking).]

NVD is not ground truth either. It tends to score the worst case, and Daniel Stenberg of curl has argued that it
inflates severity ([blog post](https://daniel.haxx.se/blog/2023/03/06/nvd-makes-up-vulnerability-severity-levels/)).
So Patch Sloth never says "the vendor is wrong". It says that an independent NVD-style reviewer would likely rate a
CVE higher. Every output is an estimate for triage, not an official score.

## 3. Who it's for

[AHMAD: personal: the lazy-but-responsible maintainer who ignores Dependabot because of alert fatigue]

## 4. Why it rewards laziness

[AHMAD: nobody re-scores 5,000 CVEs a month by hand, so the sloth does]

The feed re-scores every unanalysed CVE in one batch. Release `feed-2026-10-23` covers 58,457 CVEs: 49,272
Deferred, 6,604 Awaiting Analysis, 1,902 Received and 679 Undergoing Analysis. [`results/final_table.md` §6]

## 5. What I built

[AHMAD: architecture diagram, demo GIF, live URL]

You give Patch Sloth a `package-lock.json` or a `requirements.txt`, and it works in four steps:
1. It finds the vulnerable packages and their CVE IDs.
2. It looks each CVE up in the precomputed feed.
3. It sorts the CVEs into P0 "patch now", P1 "this month" and P2 "ignore for now", using fixed rules: CISA KEV,
   EPSS ≥ 0.10, and the predicted severity when the model is confident.
4. Ultramarine 1 Flash writes a short report. A guardrail checks that every CVE ID and number in the report appears
   in the input; if not, the report is retried once and then replaced by a template. [SPEC §11]

There is a CLI, a web page and an API. For CVEs that NIST has already reviewed, the report shows the CNA and NVD
severities side by side and makes no prediction. [DECISIONS.md, 2026-10-23]

I scanned the current lockfiles of three popular npm projects without opening any issues. Their lockfiles include
dev, test and example dependencies, so a finding does not mean the published package is affected.
[`results/demo/README.md`]

| Project | Dependencies | CVEs | Deferred CVEs | Report cost | Guardrail |
|---|---|---|---|---|---|
| markedjs/marked | 625 | 14 | 8 | $0.0012 | pass |
| mochajs/mocha | 715 | 36 | 11 | $0.0024 | pass |
| socketio/socket.io | 1,212 | 112 | 22 | $0.0077 | pass |

[AHMAD: screenshot of a report on the web page]

## 6. Data and methods

**Data.** The dataset covers 239,058 non-rejected CVEs from 2021 to 2026, taken from NVD's JSON feeds (fkie-cad
mirror). It is split by publication date, never randomly. Train is before July 2025 (80,098 CVEs), validation is
2025-H2 (11,655) and test is 2026 (30,706). The 48,979 Deferred CVEs with a CNA score are the population the
product scores. [`results/dataset_summary.txt`]

**Label.** For a CVE that NVD analysed and the CNA scored, the label is NVD's vector if NVD wrote one. Otherwise
the label is the CNA's vector, because NVD reviewed it and kept it. A "bump" means the label's severity band is
higher than the CNA's. The bump rate is 18.2% in train, 22.7% in validation and 9.3% in test.
[SPEC §8.2, `results/dataset_summary.txt`]

**No leakage.** The features use only what is known about a Deferred CVE on the day it is published: the CNA's
vector, CWE and identity, the description, references and a CVSS v4 flag. NVD status, NVD's vector and CWE, CPE
configurations and KEV dates are never features. Text features are fitted on train only. [SPEC §8.4,
`tests/test_features.py`]

**Task A, predict NVD's vector.** Qwen3-8B, fine-tuned with LoRA (rank 32, learning rate 2e-4, batch 64, one
epoch) on 30,000 training CVEs on Tinker, with thinking turned off. The model sees the CNA, its CWE, its vector
and the description, and answers with eight CVSS fields as JSON. Training took 469 steps, and the logged loss fell
from 2.97 at step 10 to 0.97 at the last step. [`results/tinker_run.json`, `results/tinker_train_log.jsonl`]

**Task B, rank CVEs NVD would raise.** These models are binary classifiers for "NVD raised the band", scored by
PR-AUC on the same 8,000 2026 test CVEs:
- TabPFN-3.5, HistGBT and logistic regression on tabular features;
- a stacked model: TabPFN with the fine-tuned LLM's predictions as extra features, trained on 10,000 training CVEs
  that were held out from fine-tuning.

"Better" means the 95% paired-bootstrap interval of the difference excludes zero in each of 3 seeds.
[`results/final_table.md` §2]

**What users see.** Users get a band, not a probability. The cut-offs are quantiles of the model's own scores over
the Deferred CVEs, so no labels are used to choose them: "likely" is the top 10%, "possible" the next 15%.
[`results/serving_stack.json`]

## 7. Results

### Headline

When the served model said "likely under-rated", NIST had raised the band 75% of the time (281 of 376 CVEs). The
base rate on the same 8,000 2026 test CVEs is 9.5%. The "possible" band was confirmed 29% of the time and
"unlikely" 3.8%. [`results/serving_stack.json`, `final_table.md` §7]

### Predicting NVD's vector

Severity accuracy is the share of CVEs where the predicted vector falls in the same severity band as NVD's label.
[`final_table.md` §1]

| Split | Copy the CNA | Base Qwen3-8B | Fine-tuned Qwen3-8B |
|---|---|---|---|
| Validation (2025-H2) | 0.722 | 0.710 | **0.869** [0.861–0.876] |
| Test (2026) | **0.880** | 0.865 | 0.859 [0.851–0.866] |

On 2025-H2 the fine-tuned model beats copying the CNA clearly (McNemar p = 2e-143). On 2026 it does not: copying
the CNA is better (p = 2e-6), because in 2026 NVD changes far fewer CNA vectors.

The fine-tuned model is much better than the base model at spotting raises: bump F1 0.830 vs 0.033 on validation,
and 0.559 vs 0.108 on test. It produced valid JSON for 100% of CVEs. [`final_table.md` §1]

The fine-tune helps most on the fields CNAs and NVD dispute. On validation, accuracy on Confidentiality went from
0.749 (base) to 0.933, Integrity from 0.788 to 0.934 and Availability from 0.804 to 0.936.
[`results/llm_val.json`]

**Use the LLM only when the stack is confident.** The served vector is the LLM's when the stacked model's
probability is at least t, and the CNA's otherwise. With t tuned on the last three months of validation, this
changes 6% of 2026 CVEs. Severity accuracy is then 0.899, against 0.880 for copying the CNA: +2.0 points
[1.5, 2.5], in all 3 seeds. [`final_table.md` §4]

![Gated override](../results/gated_override.png)

### Ranking CVEs NVD would raise

PR-AUC on the 8,000 2026 test CVEs (base rate 0.095; mean of 3 seeds). [`final_table.md` §2]

| Model (training CVEs) | PR-AUC |
|---|---|
| Copy the CNA (never flags) | 0.095 |
| Fine-tuned Qwen3-8B alone | 0.404 |
| TF-IDF + logistic regression (all train) | 0.426 |
| TabPFN-3.5 + LLM features (10k) | 0.621 |
| HistGBT (all 80,098) | 0.627 |
| TabPFN-3.5 (50k) | 0.631 |

- TabPFN-3.5 on 50k CVEs and HistGBT on all 80k are not significantly different.
- The stacked model is far better at ranking than the LLM alone (+0.22).
- Adding the LLM's features helps HistGBT significantly (+0.035), but not TabPFN.

### TabPFN is about sample efficiency

![Learning curve](../results/learning_curve.png)

At 5,000 and 10,000 training CVEs, TabPFN beats HistGBT trained on the same CVEs by 0.05 to 0.08 PR-AUC, in every
seed. TabPFN on 5,000 CVEs reaches 0.602, against 0.627 for HistGBT on all 80,098. That is 96% of the way with
1/16 of the labels and no tuning, though the gap is still significant in 2 of 3 seeds. From 30,000 CVEs up, the
two are level. [`final_table.md` §8]

### The 2026 drift

![2026 drift](../results/charts/05_drift_2026.png)

NVD raised 18% of training-period CVEs, 23% in 2025-H2 and 9% in 2026. [`charts_data.json` →
`bump_rate_by_split`]

That shift breaks thresholds tuned on the past. One HistGBT model (all training CVEs) was given two thresholds:
- tuned on the last three months of validation to reach 50% precision: 28% precision on 2026, flagging 30% of
  CVEs;
- the label-free cut-off (top 10% of Deferred scores): 74% precision on 2026, flagging 4.4% of CVEs.

[`charts_data.json` → `tau_drift_hgb_all_train`]

The gate shows the same pattern. Tuned on all of 2025-H2 validation, it is 2.1 points worse than copying the CNA on
2026; tuned on the last three months, it is 2.0 points better. [`final_table.md` §4]

### Frontier zero-shot comparison

The same 1,000 test CVEs, scored by every model. [`final_table.md` §3, `results/frontier_1k.json`]

| Model | Severity accuracy | Cost per 1,000 CVEs |
|---|---|---|
| Copy the CNA | 0.874 | $0 |
| Base Qwen3-8B | 0.865 | $0.063 |
| Fine-tuned Qwen3-8B | 0.861 | $0.045 (+ $3.37 one-off training) |
| Ultramarine 1 Flash, zero-shot | 0.795 | $0.092 |

Zero-shot Ultramarine changes CNA vectors too often: it is significantly worse than copying the CNA (McNemar
p = 7e-11). On these 1,000 rows, the fine-tuned model and copy-the-CNA are not significantly different (p = 0.32).

### Error analysis

[TODO after tagging: counts per tag from `results/error_sample.md`.] The 40 cases come from the HistGBT + LLM
stack, because the served model's per-row predictions were not available after access to the GPU workstation
ended. Its test PR-AUC is 0.609 [0.573–0.643], against 0.621 [0.584–0.655] for the served stack; no paired test
between the two was run. [`results/error_sample.md`, `final_table.md` §2]

### Per-CNA results

[TODO: model results by CNA (SPEC §10) are not computed; only the data view (chart 04) exists.]

## 8. Why open matters

[AHMAD: your argument]

Facts to draw on:
- The model is an open-weight 8B model (Qwen3-8B) with a LoRA adapter, trained on 30,000 public NVD decisions for
  $3.37. [`results/costs.jsonl`]
- [PENDING: export running] The adapter is downloaded from Tinker and converted to the standard PEFT format that
  vLLM serves [`results/peft_export.json`]. The prompt that vLLM's chat template builds is token-for-token the same as the
  training prompt (200 of 200 CVEs checked). [DECISIONS.md, 2026-10-24]
- End-to-end vLLM parity with Tinker's outputs: [TODO: `results/vllm_parity.json` from the GPU window. If the window
  doesn't happen: "Weights exported in PEFT format, servable with vLLM (template parity 200/200 checked);
  end-to-end parity not measured due to time."]
- Scoring the whole unanalysed backlog of 58,457 CVEs cost $2.57 on Tinker. [`final_table.md` §6]
- The feed is open: `latest.csv` and `second_opinion.parquet` are assets of a public GitHub release.

## 9. What went wrong

**The baseline that was smaller than its name.** For three milestones, the "HistGBT, all training data" baseline
was actually trained on 10,000 rows: a command-line default meant for TabPFN applied to every model. Retrained on
all 80,098 rows, HistGBT scores 0.627, which removed most of TabPFN's accuracy lead. That is why the TabPFN result
is about sample efficiency, not accuracy. It was caught by an "anomaly" in which HistGBT on 30k rows beat HistGBT
on "all" rows. [`final_table.md` §9]

**The NaN label bug.** The label rule was first written as `nvd_vector or cna_vector`. In pandas a missing string
is NaN, and NaN counts as true. So every CVE that NVD had accepted unchanged lost its label, and the labelled set
held only CVEs NVD had rescored. The fix uses explicit string checks and added 7,367 labels (115,092 → 122,459).
A regression test covers None, NaN and `pd.NA`. [`final_table.md` §9, `tests/test_label_rule.py`]

**A test that only failed on Linux.** The advisory scanner read files in filesystem order, which is alphabetical
on Windows and hash order on Linux, so a test picked a different "fixed" version on each. The index is now built
from a sorted list. [`final_table.md` §9]

**An unfair comparison, fixed.** Ultramarine was first scored on 1,000 CVEs and compared with Qwen on 8,000. Every
model is now scored on the same 1,000. [`final_table.md` §3]

**Thresholds that don't survive 2026.** See the drift section. This turned from a bug into a finding.

[AHMAD: anything personal about these]

## 10. Limitations

- Every score is an estimate for triage, not an official CVSS score.
- The label is NVD's decision, and NVD tends to score the worst case.
- In 2026 NVD writes its own vector for far fewer CVEs (12% in September). Some "kept the CNA's score" labels may
  reflect less review rather than agreement.
- On 2026 CVEs, the fine-tuned model alone is less accurate than copying the CNA (0.859 vs 0.880). Only the gated
  version beats it.
- CVSS v3.1 only. npm and PyPI only. No affected-product (CPE) lists. EPSS is an input, and the product does not
  predict exploitation.
- The headline numbers use 8,000 of the 30,706 test CVEs: those with a fine-tuned prediction.
  [`final_table.md` intro]

## 11. Partner technology

**Tinker (Thinking Machines).** LoRA fine-tuning of Qwen3-8B: 469 steps on 30,000 CVEs for $3.37. Tinker also ran
all sampling: base and fine-tuned predictions for validation, test and the stacking set, and the 58,457-CVE
backlog. Logged Tinker spend was $8.16 in total (training $3.38 including the dry run, evaluation sampling $2.20,
backlog $2.57), plus at most about $0.10 for an interrupted run that was not logged. [`results/costs.jsonl`,
DECISIONS.md] [AHMAD: one or two sentences of your own]

**TabPFN (Prior Labs).** TabPFN-3.5 is the classifier inside the served stacked model. It is also the sample-
efficiency result: 96% of the full HistGBT's PR-AUC from 5,000 labelled CVEs. It ran on a local 24 GB GPU, with no
metered cost. [`final_table.md` §2, §8] [AHMAD]

**DigitalOcean.** App Platform hosts the API and web page (`apps-s-1vcpu-2gb`, $25/month). [TODO after deploy: live
URL, hours, cost. GPU Droplet: an L40S is $1.57/hour; if the GPU window runs, quote `results/vllm_latency.json`,
`results/vllm_parity.json` and `results/do_gpu_session.jsonl`.] [`deploy/`] [AHMAD]

**Ultramarine 1 Flash (Paper Instruments).** It writes the reports: the three demo reports cost $0.0012 to
$0.0077 each, and all passed the guardrail. It was also the frontier zero-shot baseline: $0.092 for 1,000 CVEs,
and less accurate than copying the CNA. Logged Ultramarine spend was $0.11 in total. [`results/demo/README.md`,
`final_table.md` §3, `results/costs.jsonl`] [AHMAD]

**Entire.** Every Claude Code session that built this repo is stored as `refs/entire/checkpoints/*` in the public
repo. [AHMAD: links to sessions]

## 12. Costs

| Item | Cost | Source |
|---|---|---|
| Tinker: LoRA training (incl. dry run) | $3.38 | `results/costs.jsonl` |
| Tinker: evaluation sampling (val, test, stacking set, dry runs) | $2.20 | `results/costs.jsonl` |
| Tinker: 58,457 unanalysed CVEs | $2.57 | `results/costs.jsonl` |
| Ultramarine: frontier baseline (1,000 + 10 pilot calls) | $0.09 | `results/costs.jsonl` |
| Ultramarine: reports (6 so far) | $0.015 | `results/costs.jsonl` |
| DigitalOcean App Platform | [TODO] | console billing |
| DigitalOcean GPU Droplet | [TODO, or "not used"] | `results/do_gpu_session.jsonl` |

## 13. Credits

- Data: NVD JSON 2.0 via the fkie-cad mirror (public domain); CISA KEV (public domain); EPSS (FIRST/Empirical);
  GitHub Advisory Database (CC-BY 4.0); OSV and osv-scanner (Apache-2.0).
- Prior work: CISA Vulnrichment; VulnCheck; "Can LLMs Classify CVEs?" (arXiv 2504.10713).
- The initial scaffold was produced in a Claude chat session before Entire was enabled.
- [AHMAD: Entire session links, DevRelay embed]
