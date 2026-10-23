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
- On the 8k evaluation rows, **TabPFN-3.5 is not significantly better than a well-trained HGB**; its advantage is
  sample efficiency (§8). It is ahead of HGB on
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

**The drift lesson.** Both rules were specified before the run, and both use only val labels:

- **Stale calibration loses.** Tuned on all of 2025-H2 val (bump rate 0.23), the gate learns "trust the LLM almost
  always". On 2026 (bump rate 0.095) that is significantly **worse** than copying the CNA: −2.1 points
  [−3.0, −1.3], in all 3 seeds.
- **A recent window wins.** Tuned on the last 3 months of val, the gate overrides only the ~6% of CVEs the stack is
  most confident about. On 2026 that **beats copy-CNA by +2.0 points [1.5, 2.5]** of severity accuracy in all
  3 seeds, almost matching the best threshold picked with hindsight on test.
- Same model, same features; only the tuning window differs. NVD's behaviour moved in 2026 (it changes far fewer CNA
  vectors), so a threshold tuned on older decisions over-corrects. This is the same drift as the τ finding in M1.
- In the product since M4 sign-off: the feed uses this gate (t = 0.668) on Tinker vectors for every unanalysed CVE
  (§6).

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

## 6. Serving (`results/serving_{stack,tabpfn,hgb}.json`, release `feed-2026-10-23`, data as of 2026-10-23)

**Feed model: the stacked/gated system** (`17_stacked_model.py`). The stack is TabPFN-3.5 with fine-tuned-LLM features,
trained on the 10k out-of-SFT `stack_train` rows (seed 0). Its predictions are identical to the M4 seed-0 stack
(max |Δp| = 0.0), so the gate threshold t = 0.668 from §4 applies unchanged. **Fallbacks:** TabPFN-3.5 (50k,
tabular only) for unanalysed CVEs without an LLM vector (none in this build), and HGB on all 80k train rows (CPU) for
CVEs not in the feed. Each fallback has its own bands. The stack is not significantly better than TabPFN at ranking
(§2). It is served because the gate needs it, and the gate is the part that beats copy-CNA (§4).

**LLM vectors for the unanalysed CVEs** (`16_tinker_unanalysed.py`, approved ~$2.6 with a hard stop at $3.5):
58,457 CVEs, fine-tuned Qwen3-8B on Tinker, greedy decoding, same prompt and renderer as M3. **Spend $2.571** ($0.003
smoke test + $2.568 main run, 59% of prefill tokens cached), logged in `results/costs.jsonl`. The hard stop was not
hit, and json_valid is 1.000. That is $0.044 per 1k CVEs, in line with §3.

Users see a **band**, never a raw probability. The cut-offs are label-free quantiles of the stack's p_bump over the
49,272 Deferred CVEs. Isotonic calibration (`p_bump_calibrated`) is fitted on the last 3 months of val (rows with
LLM predictions, n = 3,878).

| Band | Rule (stack cut-off) | Share of Deferred | Share of 2026 eval test | Observed bump rate, 2026 eval test |
|---|---|---|---|---|
| likely | p ≥ τ = 0.725 (top 10%) | 10.0% | 4.7% | **0.747** (281/376) |
| possible | p ≥ 0.333 (top 25%) | 15.0% | 9.3% | 0.294 |
| unlikely | the rest | 75.0% | 86.0% | 0.038 |

- τ_high = top 5% of Deferred = 0.868. On the 2026 eval rows it flags 2.4%, with precision 0.916 and recall 0.230.
- Gate: the predicted vector is the LLM vector only when p ≥ 0.668, otherwise the CNA vector. On 2026 eval test this
  overrides 6.0% of rows, with severity accuracy 0.899 vs copy-CNA 0.880 (+2.0 [1.5, 2.5]). In the feed it overrides
  **11.5%** of unanalysed CVEs (6,732; severity changes for 6,718). Deferred CVEs score higher than 2026 test, as
  the 10% vs 4.7% "likely" shares show. That is the same population shift seen in M1.
- Feed: 58,457 unanalysed CVEs (Deferred 49,272, Awaiting Analysis 6,604, Received 1,902, Undergoing Analysis 679),
  all scored by the stack. Bands: likely 5,179, possible 8,105, unlikely 45,173. Isotonic maps the top 102 rows to
  1.0; the band is the honest summary (observed ~0.75 in "likely" on 2026).
- TabPFN-only (`serving_tabpfn.json`; τ 0.722, τ_high 0.847, likely 254/327 = 0.777) and HGB fallback (τ 0.703,
  τ_high 0.845) numbers are unchanged.
- **Distribution:** `feed/` is gitignored. The feed (`second_opinion.parquet`, `latest.csv`, `meta.json`) and the HGB
  fallback model (`bump_hgb.joblib`) are assets of the GitHub release `feed-2026-10-23`. At start-up the API
  downloads the newest `feed-*` release (`PATCHSLOTH_FEED_DOWNLOAD=0` turns this off). It skips the download if
  the tag is already local, and if GitHub is unreachable it serves the local feed.

## 7. Headline claims (approved wording, 2026-10-23)

> "When Patch Sloth said 'likely under-rated', NIST had raised the score 78% of the time (254/327) vs a 9.5% base
> rate."

Source: TabPFN-3.5 (tabular, 50k) "likely" band (label-free cut-off: top 10% of Deferred scores) on the 8,000 2026
evaluation test rows (`results/serving_tabpfn.json`, `test_eval_rows`). It flags 4.1% of those rows.
**Note:** the served model is now the stack (§6). Its "likely" band is confirmed 281/376 = 75% on the same rows.
The approved wording quotes the TabPFN-only model; [HUMAN] keep it, or switch it to the served stack's number.

> Gated override: with a threshold tuned on all of 2025-H2, letting the LLM rewrite CNA vectors is **worse** than
> copying the CNA on 2026 (−2.1 points). Tuned on the most recent 3 months, it is **better**: +2.0 points
> [1.5, 2.5]. The model was the same; the lesson is drift.

For context: if instead the top 10% of 2026 test CVEs are flagged, precision is 0.558 (TabPFN-50k) to 0.574 (HGB-80k).
The fine-tuned LLM alone does not beat copying the CNA on 2026 (0.859 vs 0.880).

## 8. TabPFN is about sample efficiency, not accuracy (`results/learning_curve.png`, `m4_tables.md`)

Same 8,000 eval test rows; 3 seeds (the seed draws the training subsample and seeds the model).

| n_train | TabPFN-3.5 PR-AUC (mean, seed sd) | HistGBT PR-AUC (mean, seed sd) | TabPFN − HGB at equal n, per seed [95% CI] |
|---|---|---|---|
| 5k | 0.602 (0.008) | 0.534 (0.019) | +0.073 [+0.052, +0.093]; +0.080 [+0.056, +0.103]; +0.052 [+0.034, +0.068]: **TabPFN better** |
| 10k | 0.614 (0.002) | 0.564 (0.005) | +0.047 [+0.029, +0.065]; +0.054 [+0.032, +0.074]; +0.051 [+0.032, +0.071]: **TabPFN better** |
| 30k | 0.625 (0.002) | 0.612 (0.004) | +0.013 [−0.002, +0.027]; +0.017 [+0.001, +0.031]; +0.009 [−0.006, +0.022]: no significant difference |
| 50k / 80k | 0.631 (50k) | 0.627 (all 80,098) | see below |

**TabPFN at n vs HGB on all 80k rows (paired, per seed):**

| TabPFN at | Seed 0 | Seed 1 | Seed 2 | Verdict |
|---|---|---|---|---|
| 5k | −0.024 [−0.042, −0.008] | −0.036 [−0.054, −0.019] | −0.015 [−0.033, +0.001] | no significant difference under the every-seed rule, but significantly **lower** in 2 of 3 seeds |
| 10k | −0.014 [−0.029, −0.000] | −0.015 [−0.032, −0.001] | −0.009 [−0.025, +0.006] | no significant difference (lower in 2 of 3 seeds) |
| 30k | −0.004 [−0.018, +0.010] | −0.004 [−0.018, +0.010] | +0.001 [−0.015, +0.015] | no significant difference |
| 50k | −0.003 [−0.016, +0.011] | +0.007 [−0.008, +0.021] | +0.009 [−0.008, +0.024] | no significant difference |

What the post can say:
- **With little data, TabPFN wins clearly.** At 5k and 10k training rows it beats HGB trained on the same rows by
  +0.05 to +0.08 PR-AUC, significant in every seed.
- **TabPFN on 5k rows gets 96% of the way to HGB on 80k rows** (0.602 vs 0.627), with 1/16 of the labelled data and
  no tuning. It is not *equal*: the gap is significant in 2 of 3 seeds. From 30k rows on, the two are level.
- With all the data, HGB catches up. TabPFN is not more accurate here; it gets there with far fewer labels.

## 9. What went wrong

**1. The "HistGBT" baseline was trained on 10k rows, and nobody noticed for three milestones.**
`scripts/07_tabpfn_bump.py` has `--n_train` (default 10,000) so that TabPFN's context size can be set. The same default
silently applied to `--model hgb`, and the README ran `07 --model hgb` without the flag. As a result, the SPEC §9.2
bar ("HistGBT 0.58"), the M1 reproduction, M2's "TabPFN beats full-train HGB, CIs don't overlap" and the served
fallback model were all a 10k-row HGB.
*How it was caught:* M2 had flagged an "anomaly": HGB refitted on a 30k subsample (0.618) beat "HGB on all 80k rows"
(0.579). M4 re-ran the anomaly check with 3 seeds and an explicit config table. `hgb_full` on all 80,098 rows scored
0.626, not 0.579, and the gap traced straight to the default. With the real baseline, TabPFN's accuracy edge mostly
disappears (§2). The project's TabPFN story became sample efficiency (§8), not accuracy.
*Fixes:* the M2 write-up is corrected in place with a note; `07` documents the default; serve-time models are built by
`15`, which has no subsample default; every M4 config states its training rows.

**2. The NaN label bug (scaffold, before this repo's sessions).** The label rule (SPEC §8.2: NVD's vector if NVD wrote
one, else the CNA's) was first written with truthiness checks (`if nvd_vector:`). In pandas, a missing value is a
float NaN, and NaN is truthy, so missing NVD vectors were taken as present. That silently mislabelled about 40% of
rows.
*How it was caught:* not recorded in this repo. It was found and fixed in the chat session that produced the
scaffold, before Entire was enabled; SPEC §8.2 only notes that it happened. **[HUMAN]: add how you spotted it.**
*Fix:* `label_vector` uses `isinstance(x, str)` and lives in `patchsloth/data/nvd.py` as a pure function.
`tests/test_label_rule.py` checks that None, NaN, `np.nan` and `pd.NA` never produce a label, both directly and
through a DataFrame, because pandas 3.0 turns missing strings into NaN.

**3. A test that passed on Windows and failed on Linux.** `tests/test_scan.py` failed on the GPU workstation with a
different "fixed" version for brace-expansion (1.1.12 vs 1.1.20). I first blamed the fresh advisory-database clone
and logged it that way. That was wrong: the fixtures use a pinned advisory snapshot.
*Real cause:* `scan.build_index` walked the advisories with `rglob`, whose order is the filesystem's (alphabetical on
NTFS, hash order on ext4). The test then kept the *last* finding per package, and a package can match several
advisories with different fixes.
*Fix:* the index is built from `sorted(rglob(...))`, and the test checks that the expected fix is among the package's
fixes. The product was never wrong (each CVE row keeps its own advisory's fix), but its output order depended on the
OS.

**Also:** the Ultramarine frontier baseline was first compared on 1k rows against Qwen on 8k rows (§3 fixes it); and a
threshold tuned on older val months does not transfer to 2026 (M1 τ, §4), which is now a finding rather than a bug.
