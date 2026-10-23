# Final results (M3 + M4)

**Evaluation snapshot: NVD data as of 2026-10-21T14:41Z** (`results/data_as_of.txt`). Every headline comparison uses
the same rows: the val (2025-H2) and test (2026) CVEs that have a fine-tuned LLM prediction, 8,000 each (the M3
`eval_n` rows). The workstation's data is from 2026-10-23, and all 75 M3 metrics reproduce exactly on it, so these
rows' labels are unchanged (DECISIONS.md). Newer data is used for serving only. All CIs are 95% bootstrap intervals;
"better" means the paired-bootstrap CI of the difference (1,000 resamples) excludes 0 **for every one of 3 seeds**.
Generated tables: `results/m4_tables.md` (from `scripts/13_final_table.py`), `results/frontier_1k.json`,
`results/gated_override.json`.

## 1. Task A (M3): base vs fine-tuned Qwen3-8B (`results/llm_{val,test}.json`, n = 8,000 each)

| Split | Model | JSON valid | Severity acc [95% CI] | Bump precision | Bump recall | Bump F1 | McNemar vs copy-CNA (model-only / copy-only correct, p) |
|---|---|---|---|---|---|---|---|
| val | copy-CNA | — | 0.722 | 0 | 0 | 0 | — |
| val | base zero-shot | 1.000 | 0.710 [0.699–0.719] | 0.189 | 0.018 | 0.033 | 28 / 129, p = 1e-15 (copy-CNA better) |
| val | **fine-tuned** | 1.000 | **0.869 [0.861–0.876]** | 0.818 | 0.842 | 0.830 | 1,642 / 469, p = 2e-143 (**fine-tune better**) |
| test | copy-CNA | — | **0.880** | 0 | 0 | 0 | — |
| test | base zero-shot | 0.9998 | 0.865 [0.857–0.872] | 0.252 | 0.069 | 0.108 | 47 / 166, p = 6e-16 (copy-CNA better) |
| test | fine-tuned | 1.000 | 0.859 [0.851–0.866] | 0.519 | 0.604 | 0.559 | 520 / 688, p = 2e-6 (**copy-CNA better**) |

Cost (Tinker, `results/costs.jsonl`): SFT $3.37 one-off; inference $0.045 per 1k CVEs (fine-tuned) and $0.063 per 1k
(base, longer answers). Total for the full run: $5.53, plus $0.055 for the dry run.

## 2. Task B: bump classifier, all models on the same 8,000 test rows (base rate 0.095)

| Model (training rows) | PR-AUC, mean of 3 seeds | 95% CI (seed 0) | ROC-AUC | Precision top 10% |
|---|---|---|---|---|
| copy-CNA (never flags) | 0.095 | — | — | — |
| Fine-tuned Qwen3-8B alone (score delta as the ranking) | 0.404 | 0.366–0.444 | 0.783 | 0.506 |
| TF-IDF + logistic regression (all train) | 0.426 | 0.391–0.470 | 0.848 | 0.432 |
| HistGBT (10k stack_train) | 0.574 | 0.536–0.609 | 0.891 | 0.514 |
| TabPFN-3.5 (10k stack_train) | 0.609 | 0.574–0.645 | 0.901 | 0.543 |
| HistGBT + LLM features (10k stack_train) | 0.609 | 0.573–0.643 | 0.894 | 0.541 |
| TabPFN-3.5 + LLM features (10k stack_train) | 0.621 | 0.584–0.655 | 0.901 | 0.552 |
| HistGBT (all 80,098 train) | 0.627 | 0.596–0.664 | 0.910 | 0.574 |
| TabPFN-3.5 (50k train subsample) | **0.631** | 0.592–0.662 | 0.911 | 0.558 |

As a yes/no flag, the fine-tuned LLM has precision 0.519 and recall 0.604, flagging 11.0% of rows. Val numbers are in
`m4_tables.md`; there every model except the LLM alone and LR scores 0.91–0.93.

**Paired comparisons (test rows, ΔPR-AUC per seed [95% CI])**

| A vs B | Seed 0 | Seed 1 | Seed 2 | Verdict |
|---|---|---|---|---|
| TabPFN (50k) vs HGB (same 50k) | +0.023 [+0.008, +0.038] | +0.014 [−0.001, +0.029] | +0.018 [+0.002, +0.032] | no significant difference |
| TabPFN (50k) vs HGB (all 80k) | −0.003 [−0.016, +0.011] | +0.007 [−0.008, +0.021] | +0.009 [−0.008, +0.024] | no significant difference |
| Stacked vs TabPFN, same 10k rows | +0.011 [−0.003, +0.024] | +0.014 [+0.002, +0.027] | +0.012 [−0.001, +0.026] | no significant difference |
| Stacked vs TabPFN (50k) | −0.007 [−0.025, +0.010] | −0.012 [−0.029, +0.005] | −0.011 [−0.028, +0.007] | no significant difference |
| Stacked vs fine-tuned LLM alone | +0.216 [+0.189, +0.243] | +0.218 [+0.191, +0.243] | +0.218 [+0.190, +0.243] | **stacked better** |
| HGB + LLM vs HGB, same 10k rows | +0.035 [+0.017, +0.053] | +0.035 [+0.017, +0.053] | +0.035 [+0.017, +0.053] | **HGB + LLM better** |

What this supports:
- On the 8k evaluation rows, **TabPFN-3.5 is not significantly better than a well-trained HGB**. It is ahead of HGB on
  the same 50k rows in 2 of 3 seeds, and level with HGB on all 80k rows.
  Secondary (all 31,198 test rows of the serving data, `m4_tables.md`): TabPFN-50k beats HGB-80k in all 3 seeds,
  by +0.008 to +0.014. That set is newer data and is not the headline.
- **LLM features help HGB significantly (+0.035), but not TabPFN** (+0.011 to +0.014; significant in 1 of 3 seeds).
  The stack trains on only 10k rows, because those are the only out-of-SFT train rows with LLM predictions.
- The stack is much better than the fine-tuned LLM on its own at ranking likely bumps (+0.22).
- The SPEC §9.2 "HistGBT 0.58" bar was a **10k-row** HGB (07's default `--n_train`). Every model trained on 30k+ rows
  beats it.

## 3. Same 1,000 test rows as Ultramarine (`results/frontier_1k.json`, base rate 0.102)

The Ultramarine subsample is a subset of the 8k eval rows. Before this, `llm_test.json` compared Ultramarine on 1k rows
with Qwen on 8k rows; here every model is scored on the same 1,000.

| Model | Severity acc [95% CI] | Exact vector | Score MAE | Bump P / R / F1 | McNemar vs copy-CNA | $ per 1k CVEs |
|---|---|---|---|---|---|---|
| copy-CNA | **0.874 [0.853–0.897]** | 0.801 | 0.344 | 0 / 0 / 0 | — | 0 |
| base Qwen3-8B zero-shot | 0.865 [0.844–0.887] | 0.774 | 0.358 | 0.30 / 0.07 / 0.11 | 7 / 16, p = 0.10 | 0.063 (Tinker) |
| fine-tuned Qwen3-8B | 0.861 [0.839–0.883] | 0.776 | 0.353 | 0.56 / 0.54 / 0.55 | 65 / 78, p = 0.32 | 0.045 (Tinker) + $3.37 training |
| TF-IDF + LR | 0.833 [0.810–0.855] | 0.702 | 0.429 | 0.47 / 0.63 / 0.54 | 69 / 110, p = 0.003 | 0 (CPU) |
| Ultramarine 1 Flash zero-shot | 0.795 [0.771–0.822] | 0.650 | 0.525 | 0.29 / 0.28 / 0.29 | 32 / 111, p = 7e-11 | 0.092 |

Bump ranking on the same 1k rows (PR-AUC, mean of 3 seeds): TabPFN-50k 0.659, HGB-80k 0.658, TabPFN (10k stack_train)
0.640, stacked 0.623. With n = 1,000 these do not separate. TabPFN and HGB run locally (GPU / CPU) with no metered
cost; TabPFN-50k takes about 6 min per 43k rows scored on the RTX PRO 4000.

## 4. Gated override: use the LLM vector only when the stack is confident (`results/gated_override.{json,png}`)

Final vector = fine-tuned LLM vector if stacked p_bump ≥ t, else the CNA vector. t is swept and chosen on val labels
only (max severity accuracy). Two val rules were coded before the run: all of val, and the last 3 months of val (the
window SPEC §9.2 uses for τ). Test is reported at the chosen t, with a paired bootstrap of severity accuracy vs
copy-CNA (0.8795 on these rows).

| t chosen on | Seed | t | Test override rate | Test severity acc | Δ vs copy-CNA [95% CI] | Test bump P / R |
|---|---|---|---|---|---|---|
| all val | 0 / 1 / 2 | ≈ 0 (override ~all) | 99.7% | 0.859 | −0.021 [−0.030, −0.013] | 0.52 / 0.60 |
| last 3 months of val | 0 | 0.668 | 6.0% | **0.899** | **+0.020 [+0.015, +0.025]** | 0.71 / 0.44 |
| last 3 months of val | 1 | 0.685 | 5.4% | **0.900** | **+0.020 [+0.015, +0.025]** | 0.73 / 0.41 |
| last 3 months of val | 2 | 0.666 | 5.9% | **0.899** | **+0.019 [+0.014, +0.024]** | 0.71 / 0.43 |
| *(exploratory: t picked on test labels)* | 0 | — | — | 0.900 | +0.020 | — |

- **Yes, an operating point beats copy-CNA on 2026**, with the CI excluding 0 in all 3 seeds: override about 6% of
  CVEs (the stack's most confident ones) and keep the CNA vector for the rest. The gain is +2.0 points of severity
  accuracy, and it almost matches the best threshold chosen with hindsight on test.
- **Caveat: it depends on the tuning window.** Tuned on all of val, where the bump rate is 0.23, the rule overrides
  almost everything and is significantly *worse* than copy-CNA on 2026 (base rate 0.095). This is the same drift as
  the τ finding in M1. Both rules are reported, and only val labels were used for either.
- It is not in the product yet. It needs LLM predictions for the CVEs being scored. Deferred CVEs have none, so getting
  them is a paid Tinker or vLLM job (about $0.045 per 1k CVEs, roughly $2.6 for the 58k unanalysed CVEs): **[HUMAN]
  approval**.

## 5. HGB "anomaly" and recency (all 31,198 test rows, serving data)

| Model | PR-AUC, mean of 3 seeds | 95% CI (seed 0) | seed sd |
|---|---|---|---|
| HGB, 30k subsample | 0.617 | 0.600–0.634 | 0.003 |
| HGB, 50k subsample | 0.618 | 0.594–0.630 | 0.004 |
| HGB, all 80k | 0.626 | 0.610–0.644 | 0.001 |
| HGB, all 80k, no early stopping | 0.631 | 0.613–0.647 | 0.000 |
| HGB, train 2024+ only (40,204 rows) | 0.609 | 0.590–0.626 | 0.003 |
| TabPFN, 50k subsample | 0.637 | 0.617–0.652 | 0.001 |
| TabPFN, train 2024+ only (40,204 rows) | 0.631 | 0.616–0.649 | 0.002 |

- **The anomaly was a mislabel, not recency.** M2's "HGB all train" (0.579) was a 10k-row model. HGB on all 80k rows
  scores 0.626, and 30k is not better than 80k: 30k − 80k is −0.005 to −0.013, with the CI below 0 in 2 of 3 seeds.
- **Recency does not help.** Training only on 2024+ is significantly worse for HGB (−0.012 to −0.020, all seeds), and
  no better for TabPFN (−0.002 to −0.008).
- Turning HGB's early stopping off adds +0.003 to +0.006 (significant in 2 of 3 seeds), which is not enough to call.

## 6. Serving (`results/serving_{tabpfn,hgb}.json`, feed in `feed/`, data as of 2026-10-23)

**Feed model: TabPFN-3.5 on a 50k train subsample** (`15_serving_model.py --model tabpfn`). **Fallback for CVEs not in
the feed: HGB on all 80k train rows** (CPU), with its own bands. Why TabPFN: it has the highest point estimate on the
eval rows (0.631 vs 0.627; not significant) and beats HGB-80k in all 3 seeds on the full, newer test set. The stack is
not served, because Deferred CVEs have no LLM predictions (that is the paid [HUMAN] step in §4), and it is not
significantly better anyway.

Users see a **band**, never a raw probability. The cut-offs are label-free quantiles of each model's own p_bump over
the 49,272 Deferred CVEs. Isotonic calibration (stored as `p_bump_calibrated`) is fitted on the last 3 months of val.

| Band | Rule (TabPFN cut-off) | Share of Deferred | Share of 2026 test | Observed bump rate, 2026 test (all / eval rows) |
|---|---|---|---|---|
| likely | p ≥ τ = 0.722 (top 10%) | 10.0% | 4.3% | **0.752** / **0.777** |
| possible | p ≥ 0.350 (top 25%) | 15.0% | 8.7% | 0.367 / 0.349 |
| unlikely | the rest | 75.0% | 87.0% | 0.032 / 0.035 |

- τ_high = top 5% of Deferred = 0.847: on 2026 test it flags 2.3% of rows, with precision 0.883 and recall 0.221.
  The P0 rule for under-rated CVEs needs band "likely", p ≥ τ_high, eff_sev ≥ HIGH and a fix.
- HGB fallback: τ 0.703, τ_high 0.845. Its bands behave the same way (likely 0.742, possible 0.368, unlikely 0.034).
- Calibration: Brier on 2026 goes from 0.0552 to 0.0519 with isotonic (HGB: 0.0553 to 0.0528). Caveat: isotonic maps
  the top scores to about 1.0, but the observed 2026 rate in "likely" is about 0.75. The band is the honest summary;
  the calibrated number overstates the top on 2026 (drift).
- Feed: 58,457 unanalysed CVEs (Deferred 49,272, Awaiting Analysis 6,604, Received 1,902, Undergoing Analysis 679),
  scored in about 6 min on the GPU. `feed/` is gitignored; publishing it as a release asset is a separate step.

## 7. Headline claim (filled with measured numbers)

> "On 2026 CVEs, Patch Sloth's *likely under-rated* flags were confirmed by NVD **78% of the time** (254 of 327) vs a
> **9.5% base rate**, flagging 4.1% of CVEs."

That is TabPFN-3.5's "likely" band (label-free cut-off: top 10% of Deferred scores) on the 8,000 evaluation test rows.
If instead the top 10% of 2026 test CVEs are flagged, precision is 0.558 (TabPFN-50k) to 0.574 (HGB-80k). Rating CNA
vectors, the fine-tuned LLM alone does **not** beat copying the CNA on 2026 (0.859 vs 0.880). The gated override
(§4) does (+2.0 points), but only with the threshold tuned on the most recent 3 months of val.
