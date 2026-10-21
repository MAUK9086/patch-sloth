# Patch Sloth: build plan (Wed Oct 21 to Sun Oct 25, 2026)

**Deadline:** Oct 25, 11:59 PM PDT, which is **Mon Oct 26, 12:29 PM IST**. Aim to submit by Sunday night IST so there is a buffer.

**One-line pitch:** For a third of new CVEs, the only severity rating now comes from the CNA (the reporter, often the vendor). When NIST still checked, it overruled 4 in 10 of those ratings, usually upward. Patch Sloth gives you the second opinion NIST stopped giving, for the CVEs in your own lockfile.

---

## Established so far (Wed, done)

### 1. Data
These scripts run end to end.
- `01_download.sh` downloads the inputs:
  - the NVD mirror (fkie-cad), 2021–2026
  - CISA KEV
  - the GitHub Advisory DB (the source Dependabot uses)
  - EPSS
- `02_build_dataset.py` builds `data/cves.parquet`: 239k CVEs, of which 48,979 are Deferred and carry a CNA score.

### 2. Label rule check
Label = NVD's own vector if it wrote one; otherwise the CNA's vector, because NVD analysed the CVE and kept it.

The evidence for this rule: from mid-2025, when NVD did write its own vector, that vector differed from the CNA's in 80–95% of cases. In other words, NVD mostly writes one only when it disagrees.

**Caveat:** in 2026, NVD's own-score rate fell from 40% to 11%. Some of the "kept" cases may be rubber stamps rather than agreement. This goes in the write-up as a stated limitation.

### 3. Splits
Splits are by time.

| Split | Period | CVEs | Bump-up rate* |
|---|---|---|---|
| train | up to Jun 2025 | 80,098 | 18% |
| val | Jul–Dec 2025 | 11,655 | 23% |
| test | 2026, after the policy change | 30,706 | 9% |

\*Bump-up rate = how often NVD raised the CNA's severity band.

### 4. First baselines
Tables are in `results/`.

**Severity accuracy, copy-CNA vs TF-IDF + logistic regression**

| Split | Copy-CNA | TF-IDF + LR | McNemar p |
|---|---|---|---|
| val | 0.72 | **0.82** | 1e-87 |
| test | **0.88** | 0.84 | — |

On test, the model loses. It over-flags because NVD's behaviour shifted in 2026.

**Bump-up detection (PR-AUC)**

| Model | val | test |
|---|---|---|
| HistGBT, tabular | 0.90 | 0.58 |
| logistic regression | 0.80 | 0.45 |
| base rate | 0.23 | 0.09 |

On test, HistGBT is 6× the base rate. The top 10% of its flags are 53% correct, against a 9% base rate.

**What follows from this:**
- The headline metric is **ranking quality for bump-ups**: PR-AUC and precision of the top-k flags. The product is a "look at these first" ranker.
- Raw severity accuracy will not be the headline, because copy-CNA wins it whenever reviewers mostly agree.
- The 2026 shift is a finding in its own right, not something to hide.

---

## Thu Oct 22: models

### Morning (on your machine)
- `pip install pandas pyarrow scikit-learn scipy tinker tinker-cookbook tabpfn`
- Run `bash scripts/01_download.sh`, then `python scripts/02_build_dataset.py`.
  - The result should match `results/dataset_summary.txt`. Numbers will be slightly higher because the data is newer.
- Accept the TabPFN 2.5 licence on Hugging Face (non-commercial use is fine for a hackathon).
- Run `python scripts/07_tabpfn_bump.py --model tabpfn --n_train 10000` on the 24 GB GPU.
  - Then rerun with `--n_train 30000` and `50000`. That gives a scaling curve, which is good material for the post.

### Afternoon: Tinker
- Run `python scripts/04_make_tinker_data.py --n_train 30000`. That is about 7.3M tokens, roughly $3.2 per epoch on Qwen3-8B.
- Run `python scripts/05_tinker_train.py --dry_run` first.
  - The API names should be checked against the Tinker docs, then fixed if anything is off.
- Full run: `--epochs 1 --eval_n 8000`. Evaluation costs about $2 of prefill.
  - Total Tinker spend should be roughly $6 of the $10 credit.
- Run `python scripts/06_eval_llm.py`. It reports, for base zero-shot vs fine-tuned:
  - JSON validity
  - severity accuracy
  - bump-up precision and recall
  - McNemar's test against copy-CNA

### Evening: stacking
- Get LLM predictions on 10k train examples, held out from the SFT subset. This costs about $0.6.
- Then `07_tabpfn_bump.py --with_llm`. The question it answers: does the LLM's reading of the text add signal on top of tabular TabPFN?

## Fri Oct 23: product

- **`patchsloth scan <lockfile>`** (CLI):
  1. Parse `package-lock.json` or `requirements.txt`.
  2. Match against the local GitHub Advisory DB clone. The API alternative is OSV `querybatch`.
  3. Map each match to its CVEs and look them up in the parquet file.
  4. For CVEs that are Deferred or unanalysed, run the LLM's second opinion, the TabPFN bump probability and the EPSS score.
- **Report:** Ultramarine 1 Flash turns the structured results into a one-minute report: patch now, patch this month, or ignore, each with a one-line reason.
  - Log tokens and cost per report.
  - Guardrail: the prompt receives only computed facts, and the report must not invent scores.
- **DigitalOcean:**
  - App Platform: a small web page (paste a lockfile, get the report) plus the API.
  - GPU Droplet with vLLM: serves the merged LoRA. Switch it on only for the demo and evaluation window to keep cost to a few dollars. First check whether Tinker lets you download the LoRA weights. If it does not, serve through Tinker sampling and keep DigitalOcean for the app and jobs, and say so honestly in the post.
  - A weekly scheduled job that re-scans a sample repo and reports only what changed.
- **Demo repos:** two real, popular open-source projects with at least one Deferred CVE in their dependency trees. Find them by joining the GitHub Advisory DB to the Deferred CVEs.

## Sat Oct 24: evidence and polish

- **Part 0: "state of the backlog" charts** (`08_backlog_charts.py`)
  - deferrals per month
  - NVD own-score rate over time
  - disagreement by CVSS question (C, I and A are disputed most)
  - bump-up rate by CNA (which reporters get raised most often)
- **Error analysis:** 20 wrong flags read by hand. For each, decide whether the model was wrong or NVD was worst-casing.
  - Cite Daniel Stenberg's (curl) critique that NVD inflates scores. This keeps the framing honest: the tool says "an independent reviewer would likely rate this higher", not "the vendor lied".
- **Final results table:** every model, val and test, with 95% CIs.
- **Demo:** a 2-minute screen recording plus GIFs. Run a fresh clone and follow the README to make sure it works.

## Sun Oct 25: write the post (most heavily weighted criterion)

Post structure, following the pattern of past winners:
1. **Hook:** "NIST stopped checking. Here's what that costs you." One chart.
2. **The problem, with evidence:**
   - the April 2026 policy
   - 41,907 unanalysed 2026 CVEs
   - the 4-in-10 override rate
   - links to Help Net Security, CSA and VulnCheck
3. **Who it's for:** a lazy-but-responsible maintainer, with a concrete persona.
4. **What I built:** architecture diagram and demo GIF.
5. **How I know it works:**
   - baselines ladder: copy-CNA, TF-IDF + LR, HistGBT, TabPFN, base LLM, fine-tuned LLM, stacked
   - time split
   - confidence intervals and McNemar's test
   - the 2026 shift
6. **What went wrong:** the NaN label bug, test-set drift, and anything else that comes up.
7. **Limitations:** estimates not official scores; the label caveat; no CPE generation (future work).
8. **Prize categories:** Tinker, TabPFN, DigitalOcean and Ultramarine, one paragraph each with the evidence.
9. **Cost table:** Tinker spend, Ultramarine cost per report, DigitalOcean hours.

Submit Sunday night IST. Use Monday morning only as a buffer.

---

## Budget (verify before spending)

| Item | Estimate | Credit |
|---|---|---|
| Tinker Qwen3-8B, 1 epoch at 30k plus evaluation | ~$6 | $10 promo |
| Ultramarine reports | <$0.50 | $5 promo |
| DigitalOcean GPU Droplet, a few hours, plus App Platform | ~$5–10 | none, so check pricing |
| TabPFN | $0 (local GPU) | — |

## Open risks
- The Tinker API names in `05` need checking against the docs (use `--dry_run`).
- LoRA export for serving on DigitalOcean is unconfirmed; the fallback is described above.
- The 2026 test drift: present it as a finding and recalibrate the threshold on recent validation months.
- EPSS is used only as a feature and report field. We do not try to beat it, because published time-matched evaluations put EPSS at MCC around 0.9.
