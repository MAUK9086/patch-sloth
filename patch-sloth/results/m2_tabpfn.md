# M2: TabPFN bump classifier (GPU, 2026-10-23)

> **Correction (M4, 2026-10-23).** The HGB rows labelled "all train" below came from `07 --model hgb`, whose
> `--n_train` defaults to 10,000; they are a **10k-row HGB** (the same model as the SPEC §9.2 / M1 bar of 0.58).
> HGB on all 80,098 train rows scores **0.628 [0.609–0.645]** on test, so TabPFN-3.5 at 50k (0.636) does **not** beat
> it: the CIs overlap. The paired-bootstrap comparison with 3 seeds is in `results/final_table.md`. The tables
> below are corrected in place; the 30k-vs-80k "anomaly" was this mislabel.

Run on the GPU workstation: Ubuntu 24.04 on WSL2, NVIDIA RTX PRO 4000 Blackwell (24 GB), Python 3.11 (uv venv),
torch 2.14.1+cu130, tabpfn 9.2.0 with **TabPFN-3.5** weights (`tabpfn-v3.5-20260909.safetensors`). Data downloaded
2026-10-23 (`results/data_as_of.txt`).

## Data refresh vs M1

`01` pulls the latest fkie-cad release, so the data is two days newer than M1's.

| | M1 (2026-10-21) | Now | Δ |
|---|---|---|---|
| Non-rejected CVEs | 239,058 | 240,071 | +0.4% |
| train / val / test | 80,098 / 11,655 / 30,706 | 80,098 / 11,654 / 30,706 → 31,198 | test +1.6% |
| deferred_unlabeled | 48,979 | 49,272 | +0.6% |
| Bump-up rate test | 0.093 | 0.092 | |

Train is unchanged (it is frozen by publication date), so the Tinker SFT and `stack_train` rows are unaffected.

## Reproduction of `03` and `07 --model hgb` (within ±2%)

| | M1 | Now |
|---|---|---|
| copy-CNA severity acc, test | 0.882 | 0.883 |
| TF-IDF + LR severity acc, test | 0.836 | 0.837 |
| TF-IDF + LR bump PR-AUC, test | 0.517 | 0.513 |
| HGB (10k rows) PR-AUC, test | 0.580 [0.561–0.599] | 0.579 [0.560–0.598] |
| HGB precision top 10%, test | 0.529 | 0.534 |
| HGB τ (90th pct of Deferred p_bump) | 0.738 | 0.738 |
| HGB test at τ: precision / recall | 0.707 / 0.338 | 0.718 / 0.347 |

## TabPFN-3.5 scaling (`results/bump_tabpfn_n*.json`, `results/tabpfn_scaling.{json,png}`)

The context set is a random `train` subsample (seed 0). HGB and LR are refitted on the **same** subsample for the curve.
Test = 2026 CVEs (n = 31,198, base rate 0.092). 95% CIs are 500-sample bootstraps.

| n_train | TabPFN PR-AUC test | HGB (same rows) | LR (same rows) | TabPFN ROC-AUC | TabPFN prec. top 10% | Wall time |
|---|---|---|---|---|---|---|
| 5k | 0.615 [0.597–0.634] | 0.544 | 0.439 | 0.913 | 0.566 | 1.3 min |
| 10k | 0.623 [0.602–0.641] | 0.579 | 0.448 | 0.913 | 0.566 | 2.0 min |
| 30k | 0.637 [0.617–0.656] | 0.618 | 0.448 | 0.919 | 0.567 | 6.8 min |
| 50k | **0.636 [0.617–0.654]** | 0.613 | 0.445 | 0.921 | 0.564 | 13.7 min |
| HGB, all 80,098 rows | — | 0.628 [0.609–0.645] | — | — | — | — |

Wall time covers predicting val, test and the 49,272 Deferred CVEs (about 92k rows), not just fitting.

- TabPFN beats the SPEC §9.2 bar (0.58, a 10k-row HGB) at every size. It does **not** beat HGB trained on all 80k
  rows (0.628; CIs overlap).
- The gain is largest at small n. TabPFN at 5k beats HGB at 5k by 0.07; at 30k–50k the gap shrinks to about 0.02,
  and the CIs overlap.
- TabPFN plateaus after 30k (0.637 → 0.636).
- ~~Unexplained: HGB on a 30k/50k subsample beats HGB on all 80k rows.~~ Resolved in M4: the "80k" HGB was a 10k
  model. HGB scales normally (10k 0.579 → 30k 0.618 → 80k 0.628).

## Threshold at τ (same rule as serving: 90th percentile of the model's own Deferred p_bump, no labels)

| Model | τ | Test flagged | Test precision | Test recall |
|---|---|---|---|---|
| HGB (10k rows) | 0.738 | 4.4% | 0.718 | 0.347 |
| TabPFN n=50k | 0.722 | 4.3% | 0.752 | 0.352 |

The serving τ in `results/thresholds.json` is still the HGB one. TabPFN is not wired into serving or the feed yet.

## Calibration (`results/tabpfn_calibration.{json,png}`)

| | Test Brier | Test mean p (base rate 0.092) | Val H2 Brier → isotonic | Test Brier, isotonic |
|---|---|---|---|---|
| TabPFN n=50k | 0.0552 | 0.125 | 0.0603 → 0.0565 | 0.0521 |
| HGB (10k rows) | 0.0586 | 0.110 | 0.0637 → 0.0628 | 0.0563 |

Both models over-predict on 2026: train/val bump rates (0.18–0.23) are about twice the 2026 rate. As SPEC §9.2
asks, isotonic regression is fitted on val H1 (published before 2025-09-25, n = 5,827) and reported on val H2 and on
test. For TabPFN it lowers Brier on both. Isotonic is monotone, so PR-AUC and the top-k ranking are unchanged.
It is not applied to any served score yet.

## Deferred population scored

`results/deferred_scored_tabpfn_n50000.csv` holds p_bump for all 49,272 Deferred CVEs with a CNA v3.1 vector.
The per-size CSVs for 5k/10k/30k were not kept, since `07` regenerates them.

## Reproduce
```
python scripts/07_tabpfn_bump.py --model hgb
for n in 5000 10000 30000 50000; do python scripts/07_tabpfn_bump.py --model tabpfn --n_train $n; done
python scripts/11_tabpfn_plots.py
```
