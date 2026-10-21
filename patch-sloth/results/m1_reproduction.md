# M1 reproduction (CPU, 2026-10-21)

The refactored pipeline (`01_download.py` → `02` → `03` → `07 --model hgb|logreg`) was re-run on a Windows laptop with
conda, Python 3.11 and pandas 3.0. The data was downloaded on 2026-10-21 (`results/data_as_of.txt`). Reference
values come from SPEC §2/§8.3/§9.2 and the committed scaffold results.

## Dataset (`02`, `results/dataset_summary.txt`)

| Quantity | Reference | Now | Δ |
|---|---|---|---|
| Non-rejected CVEs | 239,058 | 239,058 | 0 |
| train / val / test | 80,098 / 11,655 / 30,706 | 80,098 / 11,655 / 30,706 | 0 |
| deferred_unlabeled | 48,979 | 48,979 | 0 |
| Bump-up rate train / val / test | 0.182 / 0.227 / 0.093 | 0.182 / 0.227 / 0.093 | 0 |

The output is identical: today's fkie-cad release matches the snapshot the scaffold was built from, and the
refactored label rule and splits reproduce it exactly.

## Task A baselines (`03`, `results/baselines_{val,test}.json`)

| Split | Model | Severity acc (ref → now) | Exact vector | Bump F1 | Bump PR-AUC |
|---|---|---|---|---|---|
| val | copy-CNA | 0.721 → 0.721 | 0.627 → 0.627 | 0 → 0 | — |
| val | TF-IDF + LR | 0.822 → 0.822 | 0.708 → 0.708 | 0.793 → 0.793 | 0.884 → 0.885 |
| test | copy-CNA | 0.882 → 0.882 | 0.809 → 0.809 | 0 → 0 | — |
| test | TF-IDF + LR | 0.836 → 0.836 | 0.709 → 0.708 | 0.562 → 0.559 | 0.517 → 0.517 |

McNemar vs copy-CNA (severity): val p = 7e-88 (LR better), test p = 8e-85 (copy-CNA better). Same direction as before.
The differences are ≤ 0.003 (solver/library versions).

## Task B bump classifier (`07`, `results/bump_{hgb,logreg}.json`)

| Model | Split | PR-AUC (ref → now) | 95% CI (now) | Precision top 10% (ref → now) | ROC-AUC | Brier |
|---|---|---|---|---|---|---|
| HistGBT | val | 0.898 → 0.898 | 0.889–0.908 | 0.967 → 0.967 | 0.960 | 0.061 |
| HistGBT | **test** | **0.580 → 0.580** | 0.561–0.599 | **0.529 → 0.529** | 0.903 | 0.059 |
| LogReg | test | 0.45 → 0.449 | 0.428–0.470 | — → 0.457 | 0.866 | 0.069 |

All the §9.2 bars are reproduced within ±2%. The HGB model is now seeded (`random_state=0`), and the FeatureBuilder
refactor (train-fitted vocabularies) did not move the numbers.

## Thresholds (new, `results/thresholds.json`)

τ is chosen as SPEC §9.2 says: the largest flagged set with precision ≥ 0.5 on the most recent 3 months of val
(published ≥ 2025-09-30, n = 5,614, base rate 0.191). τ_high uses precision ≥ 0.75 on the same window.

| | τ | τ_high |
|---|---|---|
| HGB | 0.072 | 0.442 |

**Finding (needs a human decision):** on test (2026), HGB at τ = 0.072 has **precision 0.287 and recall 0.864**. That
falls short of the 0.5 target, because the 2026 base rate (0.093) is half that of the tuning window (0.191). The
threshold was not tuned on test. The options are recorded in DECISIONS.md.
