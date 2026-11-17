# Patch Sloth

NIST no longer analyses every CVE. Since April 2026, many CVEs are marked **Deferred**, and the only severity score they carry comes from the CNA, the organisation that reported the vulnerability (often the vendor itself). In the years when NIST still reviewed those scores, it changed about 4 in 10 of them, and it raised them more often than it lowered them.

Patch Sloth reads your lockfile and finds the vulnerabilities NIST never checked. For each one it says whether an independent reviewer would likely rate it higher, and it writes you a one-minute patch list.

**Status:** working prototype, built for the DEV Hacktoberfest 2026 Open-Source AI Challenge (week 3) and not submitted. The models, evaluation, CLI, web page and second-opinion feed are complete; 113 tests pass. It runs locally and is not hosted. The full technical write-up is [`docs/WRITEUP.md`](docs/WRITEUP.md); `post/` holds the unfinished DEV post drafts.

## Results
Evaluated on 8,000 CVEs from 2026, split by date from the training data (`results/final_table.md`):
- When Patch Sloth said "likely under-rated", NIST had raised the score **75% of the time (281 of 376)**, against a 9.5% base rate. The cut-off is label-free (top 10% of scores over Deferred CVEs).
- Ranking the CVEs NVD would raise: PR-AUC **0.621** for the TabPFN-3.5 + LLM stack, against 0.095 for copying the CNA. HistGBT on all 80,098 training rows (0.627) and TabPFN-3.5 alone on 50k rows (0.631) are not significantly different; TabPFN's advantage is sample efficiency.
- A fine-tuned Qwen3-8B predicts NVD's vector better than copying the CNA on 2025 data (severity accuracy 0.869 vs 0.722) but not on 2026 data (0.859 vs 0.880). A gate tuned on late 2025 makes the system 2.0 points more accurate than copying the CNA on 2026.
- The whole unanalysed backlog (58,457 CVEs) is scored in the open feed, release [`feed-2026-10-23`](https://github.com/MAUK9086/patch-sloth/releases/tag/feed-2026-10-23). Total metered cost of the project: about $8.26.

## Stack
- **Tinker:** fine-tunes Qwen3-8B (LoRA) to produce the "second opinion" CVSS vector.
- **TabPFN:** predicts the probability that the severity band gets bumped up (HistGBT is the CPU fallback).
- **Ultramarine 1 Flash:** writes the report, behind a guardrail that checks every CVE ID and number.
- **Deployment configs** (`deploy/`): Dockerfile, DigitalOcean App Platform spec and a vLLM runbook. These were prepared but not deployed.

## Reproduce
CPU-only, works on Windows, macOS and Linux. Run everything from this folder.
```
conda create -n patchsloth python=3.11 && conda activate patchsloth
pip install -r requirements.txt && pip install -e .     # GPU box: also requirements-gpu.txt
python scripts/01_download.py        # or: bash scripts/01_download.sh
python scripts/02_build_dataset.py
python scripts/03_baselines.py
python scripts/07_tabpfn_bump.py --model hgb      # or --model tabpfn (GPU); note --n_train defaults to 10k
python scripts/15_serving_model.py --model hgb    # CPU fallback model with its bands (all train rows)
patchsloth feed build                # HGB-only second-opinion feed -> feed/
pytest -q
```
GPU box (M2/M4): `07 --model tabpfn --n_train N`, `11_tabpfn_plots.py`, `12_m4_experiments.py` (all Task-B configs × 3
seeds), `13_final_table.py` (paired bootstrap), `14_frontier_1k_and_gate.py` (Ultramarine 1k rows, gated override),
`15_serving_model.py --model tabpfn` then `patchsloth feed build --model tabpfn`.

Two dates: `results/data_as_of.txt` is the frozen **evaluation** snapshot (the rows the LLM was scored on);
`data/data_as_of.txt` is the **serving** data date that `01` stamps and the feed reports.
The M1 numbers are in `results/m1_reproduction.md`, the final comparison in `results/final_table.md`. Decisions and
their reasons are in `DECISIONS.md`.

## Use
```
patchsloth scan path/to/package-lock.json --no-llm   # or requirements.txt, or a project directory
patchsloth cve CVE-2025-5889
patchsloth serve                                     # web page + API on http://127.0.0.1:8080
patchsloth costs
```
`--no-llm` makes no paid calls: the bump probability comes from HistGBT and the report from a template. When
`PAPERINSTRUMENTS_API_KEY` is set in `.env`, Ultramarine 1 Flash writes the report. A guardrail checks every CVE
ID and number in its report against the input, and falls back to the template if the check fails.
If [osv-scanner](https://github.com/google/osv-scanner) is installed and `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` points
to its offline DB, it is used for matching; otherwise a built-in matcher runs over the GitHub Advisory Database.

See `PLAN.md` for the full build plan.

## Data and licences
- **NVD**, via the [fkie-cad mirror](https://github.com/fkie-cad/nvd-json-data-feeds): public domain.
- **CISA KEV:** public domain.
- **GitHub Advisory Database:** CC-BY 4.0.
- **EPSS:** FIRST.org.
- **TabPFN 2.5:** non-commercial licence. This project is used for research and hackathon purposes only.

Predictions are estimates for triage. They are not official scores.
