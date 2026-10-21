# Patch Sloth: Build Specification

> **For Claude Code.** This is the single source of truth for the project.
> - Read the whole document before writing code.
> - Work milestone by milestone (§15), and check each milestone's acceptance criteria before moving on.
> - Stop and ask the human whenever you reach a step tagged **[HUMAN]** (full list in §16).
> - Do not invent third-party API names. Where this spec says **VERIFY**, read the linked docs (or `--help`) first, then write the code.
> - Keep every decision you make in `DECISIONS.md`, one line each, with the date and the reason. The write-up depends on it.

---

## 1. One-paragraph summary

Since April 2026, NIST's National Vulnerability Database (NVD) no longer analyses every CVE. Many CVEs are marked **Deferred**. For those, the only severity score is the one supplied by the **CNA**, the organisation that reported the vulnerability (often the vendor itself). In the years when NVD still reviewed CNA scores, it changed the CNA's CVSS vector about 4 in 10 times. When it changed the severity band, it raised it about 3 times more often than it lowered it.

**Patch Sloth** gives a maintainer the missing second opinion for the CVEs in *their own* lockfile:
- It predicts what an independent NVD-style reviewer would likely have scored.
- It flags CVEs that are probably under-rated.
- It writes a one-minute "patch now / this month / ignore" report.

It is built for the DEV Hacktoberfest 2026 Open-Source AI Challenge, Week 3 ("Slow and Steady": build something with open-source AI that rewards laziness). The due date is **Oct 25, 2026, 11:59 PM PDT**, which is Mon Oct 26, 12:29 PM IST.

## 2. Evidence already measured (cite these; recompute in M1)

These numbers come from NVD records 2021–2026, taken from the fkie-cad mirror on 2026-10-21.

| Fact | Value |
|---|---|
| 2026 CVE IDs so far | 78,297 |
| Deferred | 28,518 (36%) |
| Deferred, Awaiting Analysis or Received (no NVD analysis) | 41,907 (54%) |
| Deferred per month (2026 IDs) | Mar 1,382 → Aug 5,196 → Sep 5,629 |
| Deferred CVEs with some CVSS score | 99.4% (almost all supplied by the CNA) |
| Deferred CVEs with an NVD score | 1.5% |
| Deferred CVEs with CPE configurations | 0 |
| 2024: NVD wrote its own vector on CNA-scored CVEs | 16,741 of 26,465. It changed the CNA vector in 11,252 (43% of all) and changed the severity band in 6,489. |
| 2025: when NVD changed the score, the score went up vs down | 6,419 vs 2,009 |
| Most disputed CVSS fields (2025) | C/I/A, disputed in 48–56% of the pairs where both NVD and the CNA scored. AV is disputed in only about 6%. |
| Biggest scorers of Deferred CVEs | VulDB, Patchstack, CISA-ADP (Vulnrichment), VulnCheck, GitHub, Wordfence |
| NVD writes its own score, share by month | 2024: 47–91% → 2026-H2: 11–13%. When it does, it differs from the CNA 80–95% of the time. |
| Total labelled dataset | 239,058 non-rejected CVEs. Splits: train 80,098 / val 11,655 / test 30,706. Deferred and unlabelled: 48,979. |

**Honesty framing (required in all copy):**
- NVD is not ground truth. NVD tends to score the worst case. Daniel Stenberg of curl has argued that NVD inflates severity ([source](https://daniel.haxx.se/blog/2023/03/06/nvd-makes-up-vulnerability-severity-levels/)).
- The product therefore says *"an independent NVD-style reviewer would likely rate this higher"*. It must never say *"the vendor is wrong"*.
- All outputs are **estimates for triage, not official scores**.

## 3. Goals and non-goals

**Goals**
1. A reproducible dataset and evaluation that judges can trust: time-based splits, baselines, confidence intervals and significance tests.
2. A Task-A model: a Tinker LoRA fine-tune of an open-weight model that predicts the NVD-style CVSS v3.1 vector.
3. A Task-B model: TabPFN, predicting P(NVD would raise the CNA's severity band). It also stacks the LLM's output with tabular features.
4. A product: a CLI, a web page and an API. Input is a lockfile; output is a report written by Ultramarine.
5. Deployment on DigitalOcean.
6. A daily open data feed: a second-opinion CSV covering every Deferred CVE.
7. A DEV post that explains the work, with charts and honest limits.

**Non-goals (say so in the post)**
- Generating CPE (affected-product lists). This is future work.
- Beating EPSS at predicting exploitation. EPSS is used only as an input field.
- CVSS v4.0. We target v3.1 only, because that is what most CNAs and NVD provide.
- Ecosystems beyond npm and PyPI.

## 4. Partner technology mapping

| Partner | Role in Patch Sloth | Evidence to show in the post |
|---|---|---|
| **Tinker** (Thinking Machines) | LoRA SFT of `Qwen/Qwen3-8B` for Task A, using about 30k examples for 1 epoch. Also hosts base-model zero-shot sampling. | Base vs fine-tuned: JSON validity, per-field accuracy, bump-up recall and precision, McNemar against copy-CNA. Training loss curve. Cost. |
| **TabPFN** (Prior Labs) | Task B classifier, plus the stacking "decision layer" inside the triage agent. Prior Labs favours TabPFN inside a wider prediction agent. | PR-AUC with CIs against logistic regression and HistGBT. A scaling curve over `n_train`. Calibration plot. |
| **DigitalOcean** | App Platform hosts the FastAPI app and UI. A GPU Droplet runs vLLM with the LoRA adapter, for on-demand second opinions and the nightly feed job. | Architecture diagram, latency, hourly cost, screenshots. |
| **Ultramarine 1 Flash** (Paper Instruments) | Report writer, with tool calling if supported. Also a frontier-style zero-shot baseline on 1k test CVEs. | Cost per report (tokens × price), guardrail pass rate, baseline comparison. |
| **Entire** | Records every Claude Code session that builds this repo, on the `entire/checkpoints/v1` branch. | Link to the sessions in the post, and use `entire checkpoint explain` to show why key code exists. |
| *(optional)* **DevRelay** | Saves an agent transcript to DEV and embeds it in the post. The submission template asks for this. | An embedded transcript in the post. |

Do not add more partners, for example simply to inflate the count. Four done well, plus Entire, is the strategy.

## 5. Architecture

```
                         ┌───────────── offline / nightly (GPU) ─────────────┐
 NVD mirror (fkie-cad) ──►  build_dataset ─► cves.parquet ─► Task A (Tinker LoRA, vLLM)
 CISA KEV  ─────────────►                         │            Task B (TabPFN)
 EPSS (daily CSV) ──────►                         ▼                    │
                                       feed/second_opinion.parquet ◄───┘
                                       (every Deferred/unanalysed CVE:
                                        cna_vector, predicted_vector, p_bump, epss, kev)
                         └───────────────────────────────────────────────────┘
                                                  │ (uploaded nightly)
 user lockfile ─► osv-scanner (offline DB) ─► CVE IDs ─► lookup in feed ──► priority rules
                                                  │  (not in feed? → on-demand:
                                                  │   vLLM second opinion + HGB fallback)
                                                  ▼
                                     Ultramarine report agent ─► report.md / JSON / web page
```

**Key design decision:**
- TabPFN is too slow to refit on a CPU web server for each request.
- So **all bump probabilities are precomputed nightly** for every Deferred, Awaiting Analysis and Received CVE, and stored in the feed.
- The web app only looks values up.
- CVEs newer than the last feed get an on-demand LLM second opinion plus the fast HistGBT fallback, and are labelled as such.

## 6. Repository layout (target)

```
patch-sloth/
  SPEC.md  PLAN.md  DECISIONS.md  README.md  CLAUDE.md  requirements.txt  .env.example
  patchsloth/
    __init__.py
    cvss.py            # EXISTS: parse/to_vector/base_score/severity (tested vs known vectors)
    metrics.py         # EXISTS: evaluate(), mcnemar()
    config.py          # paths, thresholds, model names, prices (read from env)
    data/nvd.py        # loading feeds, label rule, splits (refactor of scripts/02)
    data/epss.py       # download + time-matched lookup
    features.py        # tabular features shared by train and serve (single source!)
    llm/prompt.py      # SYSTEM prompt + prompt(row) + parse_output()  (shared by train/serve)
    llm/backends.py    # VLLMBackend (OpenAI-compatible), TinkerBackend, NullBackend
    tabular.py         # train/predict TabPFN, HGB fallback, calibration, threshold
    scan.py            # osv-scanner wrapper + fallback GHSA matcher
    priority.py        # deterministic priority rules (§11.3)
    report.py          # Ultramarine agent + guardrail + template fallback
    costs.py           # token/latency/cost logging -> results/costs.jsonl
    feed.py            # nightly feed build
    api.py             # FastAPI app
    cli.py             # `patchsloth` entry point (Typer)
  scripts/             # EXISTS 01–07; add 08_backlog_charts.py, 09_frontier_baseline.py, 10_error_analysis.py
  web/index.html       # single page: paste/upload lockfile -> report
  tests/               # pytest; fixtures/ with small lockfiles and NVD records
  deploy/              # Dockerfile, do-app.yaml, vllm-droplet.sh
  .github/workflows/feed.yml   # optional nightly feed refresh
  results/             # metrics JSON, charts PNG, costs.jsonl (committed)
  data/                # gitignored
```

**What already exists:**
- `patchsloth/cvss.py` and `patchsloth/metrics.py`
- `scripts/01_download.sh` to `07_tabpfn_bump.py`
- `PLAN.md` and `README.md`

Scripts 01–04 and 07 (in `hgb`/`logreg` mode) have been run successfully. Scripts 05 and 06 were written but not yet run, because they need Tinker credentials. Refactor shared logic into the package, but keep the scripts as thin entry points.

## 7. Data sources

| Source | URL | Licence | Use |
|---|---|---|---|
| NVD JSON 2.0, yearly | `https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-<YEAR>.json.xz` (2021–2026) | public domain | everything |
| CISA KEV | `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json` | public domain | report field and feature |
| EPSS | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`; history at `epss_scores-YYYY-MM-DD.csv.gz` (**VERIFY**: the host moved from epss.cyentia.com in 2025) | FIRST/Empirical | report field only |
| GitHub Advisory DB | `git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database` then `sparse-checkout set advisories/github-reviewed` | CC-BY 4.0 | fallback matcher |
| OSV via osv-scanner | `osv-scanner` v2 binary with an offline DB cache | Apache-2.0 | lockfile → vulns |

The NVD record fields used are the same as in `scripts/02_build_dataset.py`:
- `vulnStatus`, `published`, `sourceIdentifier`, `descriptions[lang=en]`
- `metrics.cvssMetricV31[type=Primary|Secondary]`
- `weaknesses[type=Secondary]` (only the CNA's CWE: NVD's own CWE is not available at serve time)
- `references[].url`, `configurations`, `metrics.cvssMetricV40`

The CISA-ADP source UUID is `134c704f-9b21-4f2e-91b3-4a467353bcc0`.

## 8. Dataset, label rule, splits, leakage rules

### 8.1 `data/cves.parquet` schema

| Column | Description |
|---|---|
| `cve`, `published` | CVE ID and publication date (`YYYY-MM-DD`) |
| `status` | NVD `vulnStatus` |
| `cna` | `sourceIdentifier` |
| `score_source` | `CNA`, `CISA-ADP` or `other` |
| `description` | English description |
| `cna_vector` | Secondary v3.1 vector. Prefer the CNA's own; fall back to ADP. |
| `nvd_vector` | Primary vector |
| `cna_cwe` | `;`-joined |
| `n_refs`, `ref_github`, `ref_exploitdb` | Reference count and flags |
| `has_v40`, `has_cpe` | Booleans |
| `kev_date` | Date added to KEV, if any |
| `label_vector`, `label_score`, `label_sev` | Label (§8.2), its base score and severity rank |
| `cna_score`, `cna_sev` | CNA base score and severity rank |
| `bump_up` | `label_sev > cna_sev` |
| `vector_changed`, `nvd_own` | Booleans |
| `split` | §8.3 |

### 8.2 Label rule (Task A and Task B)

For a CVE with status Analyzed or Modified **and** a CNA v3.1 vector:
- the label is the NVD Primary vector if NVD wrote one;
- otherwise the label is the CNA vector, because NVD reviewed it and kept it.

**Use `isinstance(x, str)` checks, not truthiness.** A NaN-is-truthy bug already happened once and silently mislabelled about 40% of rows. Keep the regression test in §14.

**Known caveat** (put it in the post): in 2026, NVD writes its own score much less often. Some "kept" labels may reflect lower review effort rather than agreement. Mitigation: report val (2025-H2) and test (2026) separately, and add a sensitivity analysis on Jan–Feb 2024, when NVD wrote its own score for about 91% of CVEs.

### 8.3 Splits (time-based, never random)

| Split | Rule |
|---|---|
| `train` | published before 2025-07-01 |
| `val` | 2025-07-01 to 2025-12-31 |
| `test` | 2026-01-01 onwards |
| `deferred_unlabeled` | status Deferred with a CNA vector. This is the population the product scores. |

Bump-up base rates: train 18%, val 23%, test 9%.

### 8.4 Leakage rules (enforce in `features.py`, test in `tests/test_features.py`)

Never use any of the following as features:
- `status`, because NVD prioritises KEV CVEs
- `nvd_vector`
- NVD's CWE (`weaknesses[type=Primary]`)
- NVD reference tags (NVD adds these during analysis)
- `configurations` / `has_cpe`
- `kev_date` (it is a report field only)

Features must be computable for a Deferred CVE on the day it was published. Fit TF-IDF and SVD vocabularies on `train` only.

## 9. Models: what is trained and what is not

| Component | Trained? | Where | Notes |
|---|---|---|---|
| Copy-CNA baseline | no | — | Predict `cna_vector`. This is the bar to beat. |
| TF-IDF + logistic regression (per field) | yes, CPU | local | EXISTS `03_baselines.py` |
| HistGBT bump classifier | yes, CPU | local | EXISTS `07 --model hgb`. Also the serve-time fallback. |
| Base Qwen3-8B zero-shot | no | Tinker sampling | same prompt as the fine-tune |
| **Qwen3-8B LoRA (Task A)** | **yes** | **Tinker** | §9.1 |
| **TabPFN bump classifier (Task B)** | **in-context, no gradient training** | local 24 GB GPU | §9.2 |
| Ultramarine zero-shot vectors (frontier baseline) | no | Paper Instruments API | 1,000 test CVEs, §10 |
| Ultramarine report writer | no | Paper Instruments API | §11.4 |
| Priority rules | no (thresholds tuned on val) | — | §11.3 |

### 9.1 Task A: Tinker LoRA SFT

**Base model.**
- Use `Qwen/Qwen3-8B`: $0.44/M training tokens, $0.195/M prefill and $0.60/M sampling per the Tinker pricing page on 2026-10-19.
- Fallback: `Qwen/Qwen3.5-4B`.
- Renderer: `qwen3` from `tinker_cookbook.renderers`. **VERIFY** the renderer name for the chosen model, and turn thinking off if the renderer exposes that option.

**Data.**
- Produced by `scripts/04_make_tinker_data.py`.
- Train is 30k examples, oversampled towards 2024+. That is about 7.3M tokens, about $3.2 per epoch.
- **Reserve 10k extra `train` rows outside the SFT set as `stack_train`.** These are needed for honest stacking in §9.2.

**Prompt.** `llm/prompt.py` holds the single shared definition for training and serving. Keep the `SYSTEM` prompt as written in `04`. The user turn contains:
- the CNA ID
- the CNA's CWE
- the CNA vector
- the description, truncated to 1,200 characters

**Target.** Compact JSON `{"AV":..,"AC":..,"PR":..,"UI":..,"S":..,"C":..,"I":..,"A":..}`.

**Hyperparameters.**
- LoRA rank 32, learning rate 2e-4 with linear decay, batch 64, 1 epoch.
- Log the loss every 10 steps to `results/tinker_train_log.jsonl`.

**API.**
- `scripts/05_tinker_train.py` uses `ServiceClient`, `create_lora_training_client`, `forward_backward(..., "cross_entropy")`, `optim_step(AdamParams)`, `save_weights_and_get_sampling_client` and `create_sampling_client`.
- **VERIFY every name against https://tinker-docs.thinkingmachines.ai before running.**
- Run `--dry_run` (128 examples) first. **[HUMAN]** supplies `TINKER_API_KEY`.

**Evaluation sampling.**
- Greedy, `max_tokens=48`.
- `eval_n=8000` each for val and test, which costs about $2 in prefill.
- Also predict `stack_train` (10k).
- Parse failures fall back to the CNA vector and are counted in `json_valid`.

**Export for serving.**
1. `tinker_cookbook.weights.download(tinker_path="tinker://<run_id>/sampler_weights/final", output_dir="./adapter")`
2. `weights.build_lora_adapter(base_model=..., adapter_path=..., output_path="./peft_adapter")`
3. `vllm serve Qwen/Qwen3-8B --enable-lora --lora-modules patchsloth=./peft_adapter --max-model-len 2048`

Source: https://tinker-docs.thinkingmachines.ai/tutorials/deployment/lora-adapter/

**Budget guard.** Abort if the estimated spend is above $9 (Tinker promo credit is $10). Log the estimated cost before every paid call.

### 9.2 Task B: TabPFN bump classifier and stacking

**Package.**
- Use the latest `tabpfn`. Prior Labs recommends **TabPFN-3.5**: open-weight and free after signing the non-commercial licence at platform.priorlabs.ai **[HUMAN]**.
- **VERIFY** how to select 3.5 weights and what their sample and feature limits are. Fallback is TabPFN-2.5 (Hugging Face `Prior-Labs/tabpfn_2_5`, which is tested up to 50k samples and 2k features).
- Run on the local GPU.

**Features.** `features.py` is shared by training and serving:
- CNA vector fields as ordinal integers
- `cna_score`
- top-40 CNA codes and top-40 CWE codes
- `adp_scored`, `n_refs`, `ref_github`, `ref_exploitdb`, `desc_len`, `has_v40`
- 32-dimensional TF-IDF → SVD text embedding

**Stacked features** (`--with_llm`):
- the fine-tuned LLM's predicted score minus the CNA score
- per-field "LLM changed this field" flags

These must come from **out-of-SFT** predictions (`stack_train`) at training time, never from SFT training rows.

**Training sizes.** Run `n_train` = 5k, 10k, 30k and 50k (within the limits). Plot PR-AUC against `n_train` as the scaling curve.

**Calibration.** Report the Brier score and a reliability plot. If the model is miscalibrated, fit isotonic calibration on the first half of val and report on the second half.

**Threshold τ.**
- Choose it on the **most recent 3 months of val** to match the 2026 base rate. Target: precision ≥ 0.5 in the top-flag set.
- Store τ in `config.py`.

**Output.** `feed/second_opinion.parquet` with `p_bump` for every Deferred, Awaiting Analysis and Received CVE.

**Bars to beat (test, 2026, base rate 0.093):**

| Model | PR-AUC | 95% CI | Precision in top 10% |
|---|---|---|---|
| HistGBT | 0.58 | 0.56–0.60 | 0.53 |
| Logistic regression | 0.45 | — | — |

## 10. Evaluation protocol (results must be reproducible from `results/`)

**Models on the same test rows** (val and test):
- copy-CNA
- TF-IDF + LR
- HistGBT
- TabPFN
- base Qwen zero-shot
- fine-tuned Qwen
- fine-tuned Qwen + TabPFN stack
- Ultramarine zero-shot (1,000-row random test subsample; compare every model on that same subsample too)

**Task A metrics:**
- per-field accuracy
- exact-vector match
- severity accuracy
- score MAE
- `json_valid`
- bump-up precision, recall and F1

**Task B metrics:**
- PR-AUC (**headline**)
- ROC-AUC
- Brier score
- precision@top-10%
- recall at τ

**Uncertainty and significance:**
- 1,000-sample bootstrap 95% CIs for severity accuracy, bump F1 and PR-AUC
- McNemar's test against copy-CNA on severity correctness

**Breakdowns:**
- by CNA (top 15 by volume)
- by CVSS field
- by month of 2026 (shows the drift)

**Error analysis** (`10_error_analysis.py`):
- Sample 20 false-positive bump flags and 20 false negatives. Write them to `results/error_sample.md`, showing the description, CNA vector, NVD vector and our vector.
- **[HUMAN]** reads them and tags each one: *model wrong*, *NVD worst-casing*, *ambiguous description*, or *label noise*.

**Cost table:**
- Tinker training and sampling dollars
- Ultramarine dollars per report and per 1k baseline calls
- DigitalOcean dollars per hour and in total

The headline claim template (fill it in with real numbers; do not oversell):
> "On 2026 CVEs, Patch Sloth's top-10% flags were confirmed by NVD X% of the time vs a 9% base rate."

## 11. Product

### 11.1 CLI (`patchsloth`, built with Typer)

| Command | What it does |
|---|---|
| `scan PATH [--format md\|json] [--no-llm] [--no-report]` | Scan a lockfile or a project directory |
| `cve CVE-ID` | Single-CVE second opinion |
| `feed build [--since DATE]` | Nightly job: rebuild the dataset delta, score unanalysed CVEs, write the feed |
| `serve` | Run the FastAPI app locally |
| `costs` | Summarise `results/costs.jsonl` |

### 11.2 Scanning (`scan.py`)

**Primary path:**

```
osv-scanner scan source --offline --format=json --output-file=<tmp> <dir>
```

- Use the offline DB cache, set by `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`. Download it once with `--offline-vulnerabilities --download-offline-databases`.
- For a single lockfile, **VERIFY** the current flag (v2 uses `-L/--lockfile`).
- Parse the vulnerability IDs and `aliases`, and keep `CVE-*` IDs.
- Keep the package name, installed version and fixed version (if any).

**Fallback** (if osv-scanner is not installed):
- A pure-Python matcher over the local GitHub Advisory DB clone.
- Parse `package-lock.json` (v2/v3 `packages`) and `requirements.txt` with `==` pins.
- Evaluate OSV `ranges[].events` (introduced/fixed/last_affected), using `packaging.version` for PyPI and the `semver` package for npm.

**Fixtures:** in `tests/fixtures/`, include one npm lockfile and one requirements.txt with known-vulnerable pins. At least one of them must include a currently Deferred CVE; find one by joining the GitHub Advisory DB to `deferred_unlabeled`.

### 11.3 Priority rules (`priority.py`, deterministic, explained in the report)

For each CVE, compute `eff_sev = max(cna_sev, predicted_sev if p_bump ≥ τ else cna_sev)`. Then assign the first matching bucket:

| Bucket | Rule |
|---|---|
| **P0 "Patch now"** | in KEV; **or** EPSS ≥ 0.10; **or** (eff_sev ≥ HIGH **and** p_bump ≥ τ_high **and** a fixed version exists) |
| **P1 "This month"** | eff_sev ≥ HIGH; **or** p_bump ≥ τ |
| **P2 "Ignore for now"** | everything else |

Every row carries a machine-generated `reason` list, for example `["CISA KEV", "likely under-rated: CNA MEDIUM → predicted HIGH (p=0.82)", "fix: 4.17.21"]`. Tune τ_high on val and record it in `DECISIONS.md`.

### 11.4 Report agent (`report.py`, Ultramarine 1 Flash)

**Client.**
- OpenAI SDK with `base_url="https://api.paperinstruments.com/v1"` and `model="ultramarine-1-flash"`.
- API key in `PAPERINSTRUMENTS_API_KEY` **[HUMAN]**.
- Prices: $0.15/M input, $0.03/M cached input, $0.50/M output (as of 2026-10-15; **VERIFY**).

**Agent shape.**
- The model receives the structured scan JSON. Rows are already prioritised; the model never sets priorities.
- Tools, if the endpoint supports OpenAI tool calling (**VERIFY**; otherwise inline everything):
  - `get_cve(cve_id)` returns the description, CNA vector and predicted vector
  - `explain_flag(cve_id)` returns the top TabPFN or HGB feature contributions (permutation importance or SHAP on HGB)
  - `similar_cves(cve_id, k=3)` returns past CVEs with the same CNA and CWE, together with what NVD did

**Output.** Markdown:
1. a 3-line summary
2. a P0 table, then P1, then a collapsed P2 section
3. one plain-English reason per CVE
4. a footer stating that the scores are estimates, with the data dates

**Guardrail.**
- Extract every CVE ID and every number in the output and check that each appears in the input JSON.
- If the check fails, retry once. If it fails again, fall back to the Jinja template report.
- Log the pass rate.

**Cost logging.** Write tokens, latency and dollars per call to `results/costs.jsonl` through `costs.py`.

### 11.5 API (`api.py`, FastAPI)

| Endpoint | Behaviour |
|---|---|
| `POST /scan` | Multipart: lockfile upload or pasted text. Returns `{rows, report_md, costs, data_as_of}`. |
| `GET /cve/{id}` | Single-CVE second opinion |
| `GET /feed/latest.csv` | The open data feed |
| `GET /health` | Health check |

Limits: uploads up to 2 MB; rate-limit by IP.

### 11.6 Web page (`web/index.html`)

- One static page served by FastAPI.
- A textarea or file drop → POST `/scan` → render the report.
- Show a "data as of" date and an "estimates, not official" banner.
- No framework is required. Keep it clean and readable on mobile.

### 11.7 LLM backends (`llm/backends.py`)

All backends share one interface: `predict_vectors(rows) -> list[str]`.

| Backend | How it works |
|---|---|
| `VLLMBackend` | OpenAI-compatible `/v1/chat/completions` on the DigitalOcean GPU Droplet, `model="patchsloth"` |
| `TinkerBackend` | Tinker sampling client with the saved weights |
| `NullBackend` | Returns the CNA vector; used with `--no-llm` |

Choose the backend with `PATCHSLOTH_LLM_BACKEND`.

## 12. Deployment (DigitalOcean)

**App Platform** (CPU, small instance):
- Docker image of the FastAPI app.
- At start-up, downloads the latest `second_opinion.parquet` from a DigitalOcean Space or the repo's GitHub release.
- Bundles the osv-scanner binary and its offline DB.
- Config lives in `deploy/do-app.yaml`.

**GPU Droplet:**
- `deploy/vllm-droplet.sh` installs vLLM, pulls `peft_adapter/` and serves on port 8000 behind an API key.
- Turn it on only for the feed build, the evaluation and the demo window. Record the hours and dollars. **[HUMAN]** creates it and checks current GPU pricing; there is no DigitalOcean promo credit.
- If a 1-Click vLLM image exists, prefer it (the challenge page mentions 1-Click Models).

**Fallback** if the GPU Droplet is not affordable:
- Run vLLM on the local 24 GB GPU for the feed build.
- Serve on-demand second opinions through `TinkerBackend`.
- Keep DigitalOcean for the app and the feed hosting, and state this honestly in the post.

**Nightly feed** (`.github/workflows/feed.yml`, optional):
- Download data, then run `patchsloth feed build --no-llm` on CPU (HGB-only probabilities), then publish a release asset.
- The full LLM + TabPFN feed is rebuilt manually on the GPU.

## 13. Configuration and secrets

`.env.example` lists:
- `TINKER_API_KEY`
- `PAPERINSTRUMENTS_API_KEY`
- `PATCHSLOTH_LLM_BACKEND`
- `VLLM_BASE_URL`, `VLLM_API_KEY`
- `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`
- `DO_SPACES_*` (if used)

**Never commit secrets.** Entire stores session transcripts in git (`entire/checkpoints/v1`) and redacts secrets only on a best-effort basis. Keep keys in `.env` (gitignored), and never paste keys into the chat with the agent.

## 14. Testing

Run `pytest -q`. It must pass offline.

| Test file | What it checks |
|---|---|
| `test_cvss.py` | Base scores for at least 6 known vectors (9.8, 6.1, 5.5, 9.0, plus a scope-changed and a zero-impact vector); severity bands |
| `test_label_rule.py` | Analyzed with NVD vector → label is NVD; Analyzed without → label is CNA; Deferred → none; NaN inputs never produce a label (**regression for the NaN bug**) |
| `test_features.py` | The feature list contains no forbidden columns (§8.4); train/serve feature parity on a fixture row |
| `test_prompt.py` | `parse_output` handles valid JSON, extra text, invalid values and empty output |
| `test_scan.py` | Fixture lockfiles → expected CVE set (fallback matcher; osv-scanner test is skipped if the binary is missing) |
| `test_priority.py` | Each bucket rule |
| `test_report_guardrail.py` | An injected fake CVE or number is caught |
| `test_api.py` | FastAPI TestClient `/health`, `/scan` with fixtures, using `NullBackend` and a mocked report |

## 15. Milestones (with acceptance criteria)

| # | When (IST) | Milestone | Done when |
|---|---|---|---|
| M0 | Wed night | Repo hygiene | git init; Entire enabled **before** the first Claude Code session (§16); `CLAUDE.md`, `DECISIONS.md`, `.env.example`; package refactor; tests for cvss and the label rule pass |
| M1 | Thu AM | Data + baselines on the human's machine | `01`, `02`, `03` and `07 hgb` reproduce the §2/§9.2 numbers within ±2% (the data is newer); `results/` committed |
| M2 | Thu | TabPFN | `07 --model tabpfn` at 4 sizes; scaling plot; calibration plot |
| M3 | Thu PM | Tinker | Dry run OK; full SFT; `06_eval_llm.py` results for base and fine-tuned on val and test; `stack_train` predictions; cost logged |
| M4 | Thu night / Fri AM | Stacking + frontier baseline | `07 --with_llm`; `09_frontier_baseline.py` (Ultramarine, 1k rows); final results table `results/final_table.md` with CIs |
| M5 | Fri | Product | `scan`, `cve`, priority, report agent with guardrail, API, web page; fixtures green; demo on 2 real public repos |
| M6 | Fri PM / Sat AM | Deploy | DigitalOcean app live URL; vLLM endpoint working; feed published; latency and cost recorded |
| M7 | Sat | Evidence | `08_backlog_charts.py` (deferrals per month, NVD own-score rate, disputes by field, bump rate by CNA, 2026 drift); error analysis sample; GIF and 2-minute video |
| M8 | Sun | Post + submit | Draft (§17), human edit, publish; Entire session links; optional DevRelay embed; submit before Sun 23:59 IST |

If time runs short, cut in this order: GitHub Action → tool-calling in the report (use inline instead) → web polish → DigitalOcean GPU (use the fallback). **Never cut evaluation honesty.**

## 16. Manual tasks for Ahmad **[HUMAN]**

**Before any Claude Code session (M0):**
1. Install Entire and enable it in the repo:
   - `curl -fsSL https://entire.io/install.sh | bash` (or Homebrew/Scoop)
   - then `cd patch-sloth && git init && entire enable --agent claude-code`
   - then `entire status`
   - Source: [docs.entire.io/integrations/claude-code](https://docs.entire.io/integrations/claude-code)
2. Optional: install DevRelay (`curl -fsSL https://devrelay.com/install.sh | sh`), restart Claude Code, and sign in with MLH. Link your DEV account in your MLH profile.
3. Create a **public GitHub repo** and push the scaffold.

**Accounts, keys and credits:**

4. Claim promos at hacktoberfest.com/my/promos: Tinker $10 and Ultramarine $5.
5. Create a Tinker API key and put `TINKER_API_KEY` in `.env`.
6. Get a Paper Instruments API key and put `PAPERINSTRUMENTS_API_KEY` in `.env`.
7. Sign the TabPFN non-commercial licence at platform.priorlabs.ai, plus Hugging Face access for the 2.5 fallback. Run `huggingface-cli login`.
8. Create a DigitalOcean account and add billing. Check the GPU Droplet price and availability, and decide the budget (about $5–10).

**Machine setup** (the 24 GB GPU; Linux or WSL2 recommended for vLLM and TabPFN):

9. Python 3.11 venv, then `pip install -r requirements.txt`, plus `torch` for your CUDA version.
10. Install `osv-scanner` (GitHub release binary) and download the offline DB once.
11. Run M1 scripts 01 → 03 → 07 and send the numbers back.

**Judgement calls only you can make:**

12. Approve the Tinker spend once the dry run prints its cost estimate.
13. Pick 2 real public repos for the demo (Claude Code proposes candidates).
14. Hand-label the 40 error-analysis cases (about 45 minutes).
15. Write the personal parts of the post (§17 points 1 and 3), then edit the whole draft for voice. It is the most heavily weighted criterion.
16. Record the 2-minute demo video.
17. Publish on DEV with the tag `hf26challenge` and the submission template; list partner categories; submit.

**Spend tracking:** fill in `results/costs.md` with Tinker, Ultramarine and DigitalOcean actuals.

## 17. DEV post outline (the writing carries the most weight)

1. **Hook:** "NIST stopped checking. Here's what that costs you." One chart: deferrals per month.
2. **The problem, with evidence:** the April 2026 policy ([Help Net Security](https://www.helpnetsecurity.com/?p=366659), [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)), the §2 numbers, and the backlog-exploitation stats from [VulnCheck](https://us-gov-east-1.vulncheck.com/blog/nvd-backlog-exploitation-lurking).
3. **Who it's for:** the lazy-but-responsible maintainer who ignores Dependabot because of alert fatigue. Make this personal.
4. **Why it rewards laziness:** nobody re-scores 5,000 CVEs a month by hand, so the sloth does.
5. **What I built:** architecture diagram, demo GIF, live URL.
6. **How I know it works:**
   - the baseline ladder and the final table with CIs
   - McNemar's test
   - the TabPFN scaling curve
   - the 2026 drift as a finding
   - per-CNA results
   - the frontier zero-shot comparison
7. **Why open matters (required by the prompt):**
   - an open-weight 8B model fine-tuned on public NVD decisions; you can retrain it, audit it, and run it locally
   - an open feed others can build on
   - cost compared with calling a closed frontier model for 5,000 CVEs a month
8. **What went wrong:** the NaN label bug, the drift, and anything else that comes up during the build.
9. **Limitations:**
   - estimates, not official scores
   - the label caveat
   - NVD worst-casing
   - v3.1 only
   - no CPE generation
10. **Prize categories:** one paragraph each for Tinker, TabPFN, DigitalOcean, Ultramarine and Entire, each with its evidence and cost.
11. **Credits:**
    - data sources and licences
    - prior work: CISA Vulnrichment, VulnCheck, and "Can LLMs Classify CVEs?" (arXiv 2504.10713)
    - the agent sessions (Entire links and the DevRelay embed)
    - the fact that the initial scaffold was produced in a Claude chat session before Entire was enabled

## 18. Risks and fallbacks

| Risk | Fallback |
|---|---|
| Tinker API differs from the script | VERIFY against the docs; use the cookbook's supervised training recipe with a JSONL conversation dataset |
| Fine-tuned model does not beat HGB on bump PR-AUC | Report it honestly; the stack may still add value; Task A per-field accuracy and JSON validity remain the Tinker story |
| TabPFN-3.5 install or licence delays | Use TabPFN-2.5 from Hugging Face |
| No DigitalOcean GPU capacity or budget | §12 fallback |
| Ultramarine has no tool calling | Inline context; the guardrail still applies |
| Data refresh changes the numbers | Pin the data date in `results/data_as_of.txt`; report that date |

## 19. Conventions

- Python 3.11
- Type hints and docstrings on public functions
- `ruff` for linting
- `pytest`
- Small commits with clear messages. Entire links sessions to commits.
- All randomness seeded with 0
- All result files stamped with `data_as_of`
- No notebooks in the critical path; scripts write to `results/`
