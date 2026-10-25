*This is a submission for the [Hacktoberfest Open-Source AI Challenge: Week 3](https://dev.to/challenges/hf26).* [AHMAD: check this line against the Week 3 submission template]

<!-- Suggested tags: hf26challenge, ai, opensource, security -->

# [AHMAD: title]

[AHMAD: hook. SPEC line to riff on: "NIST stopped checking. Here's what that costs you."]

![Deferred CVEs per month: 1,465 in March 2026, 5,768 in September 2026](https://raw.githubusercontent.com/MAUK9086/patch-sloth/master/patch-sloth/results/charts/01_deferred_per_month.png)

## The problem

Since April 2026, NIST's National Vulnerability Database (NVD) no longer analyses every CVE. Many are marked
**Deferred**. For those, the only severity score is the one from the CNA, the organisation that reported the
vulnerability (often the vendor itself).

The numbers below come from NVD's own records, frozen on 2026-10-21:

- **Deferrals are climbing.** 1,465 new CVEs were Deferred in March 2026, and 5,768 in September. From April to 20
  October there were 26,809.
- **NVD writes its own score less and less.** For analysed CVEs that had a CNA score, NVD wrote its own CVSS
  vector 94% of the time in January 2024. By September 2026 it was 12%.
- **When both scored, they often disagreed.** In 2025, NVD and the CNA disagreed on Confidentiality 49% of the
  time, Integrity 43% and Availability 40%. Attack Vector differed only 6% of the time.
- **NVD usually disagreed upwards.** Across 122,459 labelled CVEs, NVD put 16.4% in a higher severity band than
  the scorer.

![How often NVD still writes its own score](https://raw.githubusercontent.com/MAUK9086/patch-sloth/master/patch-sloth/results/charts/02_nvd_own_score_rate.png)

The rate depends heavily on who scored the CVE. NVD raised 77% of VulDB's scores, but 0.1% of Oracle's and the
Linux kernel's. I checked the VulDB number by hand: it is mostly one convention gap. VulDB scores the C/I/A
impact as Low/Low/Low and NVD as High/High/High. That accounts for 5,850 of the 8,747 raised VulDB CVEs, and two
thirds of those are SQL injection.

![How often NVD raised each scorer's severity](https://raw.githubusercontent.com/MAUK9086/patch-sloth/master/patch-sloth/results/charts/04_bump_rate_by_scorer.png)

NVD isn't ground truth either. It tends to score the worst case, and Daniel Stenberg of curl has
[argued that it inflates severity](https://daniel.haxx.se/blog/2023/03/06/nvd-makes-up-vulnerability-severity-levels/).
So Patch Sloth never says "the vendor is wrong". It says that an independent NVD-style reviewer would likely rate a
CVE higher, and every output is labelled an estimate for triage.

[AHMAD: the policy change and backlog-exploitation context. Sources to read before quoting:
[Help Net Security](https://www.helpnetsecurity.com/?p=366659),
[CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/),
[VulnCheck](https://us-gov-east-1.vulncheck.com/blog/nvd-backlog-exploitation-lurking).]

## Who it's for

[AHMAD: the lazy-but-responsible maintainer who ignores Dependabot because of alert fatigue. Make it personal.]

## What I built

Patch Sloth takes your `package-lock.json` or `requirements.txt` and answers three questions for each CVE in it:
patch now, this month, or ignore for now?

```
                  nightly / batch                                 per request
 NVD feeds ──► dataset ──► fine-tuned Qwen3-8B (Tinker) ─┐
 CISA KEV  ──►         └──► TabPFN-3.5 stack ────────────┼─► feed: every unanalysed CVE
 EPSS      ──►                                           │    (band + predicted vector)
                                                         │
 your lockfile ──► scanner (GitHub Advisory DB) ──► CVE IDs ──► feed lookup
                                                         ──► priority rules (KEV, EPSS, band)
                                                         ──► Ultramarine report + guardrail
```

- The **feed** covers all 58,457 CVEs that NVD hasn't analysed: 49,272 Deferred, plus those Awaiting Analysis,
  Received or Undergoing Analysis. It is published as a GitHub release.
- **Priority rules are fixed code, not the LLM.** CISA KEV, EPSS ≥ 0.10 or a confident "likely under-rated" with
  a fix available means P0. HIGH severity, or a flag, means P1.
- **Ultramarine 1 Flash** writes the report. A guardrail checks that every CVE ID and number in the text appears
  in the input. On failure the report is retried once, then replaced by a template.
- For CVEs NIST has already reviewed, the report shows "NIST-reviewed: CNA X / NVD Y" side by side and makes no
  prediction.

**Demo.** I scanned the current lockfiles of three popular npm projects (no issues opened):

| Project | Dependencies | CVEs | Deferred CVEs | Report cost |
|---|---|---|---|---|
| markedjs/marked | 625 | 14 | 8 | $0.0012 |
| mochajs/mocha | 715 | 36 | 11 | $0.0024 |
| socketio/socket.io | 1,212 | 112 | 22 | $0.0077 |

An excerpt of the socket.io report (P1, "this month"). These lockfiles include dev and example dependencies, so a
row doesn't mean the published package is affected.

| CVE | Package | Installed | Fix | Why |
|---|---|---|---|---|
| CVE-2026-90711 | proxy-addr | 2.0.7 | 2.0.8 | CNA CRITICAL; fix available |
| CVE-2024-12905 | tar-fs | 3.0.4 | 3.0.7 | CNA HIGH; fix available |
| CVE-2026-84375 | js-yaml | 3.14.1 | 3.15.2 | CNA HIGH; fix available |
| CVE-2025-64756 | glob | 10.4.5 | 10.5.0 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |

[AHMAD: screenshot or GIF of the web page]

## How I know it works

**Data.** The dataset has 239,058 CVEs from 2021–2026, split by date, never randomly:
- train: before July 2025 (80,098);
- validation: 2025-H2 (11,655);
- test: 2026 (30,706).

The label is NVD's vector if NVD wrote one; otherwise it is the CNA's vector, which NVD reviewed and kept. A
**bump** means the label's severity band is higher than the CNA's. Features only use what is known about a CVE on
the day it is published.

### Headline

> When Patch Sloth said "likely under-rated", NIST had raised the score **75% of the time (281 of 376)**, against a
> **9.5%** base rate, on 8,000 CVEs from 2026.

The "likely" cut-off is the top 10% of scores over Deferred CVEs, so no labels are used to pick it. The "possible"
band was confirmed 29% of the time and "unlikely" 3.8%.

### Tinker: fine-tuning Qwen3-8B to predict NVD's vector

LoRA on Qwen3-8B: rank 32, one epoch over 30,000 CVEs, 469 steps, $3.37. It is scored here by severity accuracy:
the share of CVEs where the predicted vector lands in NVD's severity band. Each split has 8,000 CVEs.

| | Copy the CNA | Base Qwen3-8B | Fine-tuned |
|---|---|---|---|
| Validation (2025-H2) | 0.722 | 0.710 | **0.869** |
| Test (2026) | **0.880** | 0.865 | 0.859 |
| Bump F1, validation / test | 0 / 0 | 0.033 / 0.108 | **0.830 / 0.559** |

On 2025 data, the fine-tune beats copying the CNA by a wide margin (McNemar p = 2e-143). **On 2026 it does not:**
copying the CNA is better (p = 2e-6), because in 2026 NVD changes far fewer CNA vectors. It does catch raises far
better than the base model, and it produced valid JSON 100% of the time.

### The gate, and why the tuning window matters

A gate uses the LLM's vector only when the stacked model is confident, and keeps the CNA's otherwise. I
specified two ways to choose its threshold before running anything. Both use validation labels only:

| Threshold tuned on | Share of 2026 CVEs changed | 2026 severity accuracy vs copying the CNA |
|---|---|---|
| All of 2025-H2 | 99.7% | **−2.1 points** [−3.0, −1.3] |
| Last 3 months of 2025 | 6% | **+2.0 points** [+1.5, +2.5] |

Both rows use the same model and differ only in the tuning window. The second rule holds in all 3 seeds and is
the one that ships.

![2026 drift](https://raw.githubusercontent.com/MAUK9086/patch-sloth/master/patch-sloth/results/charts/05_drift_2026.png)

The same drift breaks plain thresholds. NVD raised 23% of 2025-H2 CVEs but 9% of 2026 ones. A threshold tuned on
late 2025 gave 28% precision on 2026; the label-free cut-off gave 74%.

### TabPFN: ranking the CVEs NVD would raise

PR-AUC on the same 8,000 2026 CVEs (base rate 0.095; mean of 3 seeds):

| Model | PR-AUC |
|---|---|
| Fine-tuned LLM alone | 0.404 |
| TF-IDF + logistic regression | 0.426 |
| TabPFN-3.5 + LLM features (served) | 0.621 |
| HistGBT, all 80,098 rows | 0.627 |
| TabPFN-3.5, 50k rows | 0.631 |

With all the data, TabPFN and a well-trained HistGBT are not significantly different. TabPFN's win is **sample
efficiency**:
- At 5,000 and 10,000 training CVEs, it beats HistGBT on the same rows by 0.05–0.08, in every seed.
- On 5,000 CVEs it reaches 0.602, which is 96% of HistGBT trained on all 80,098, with no tuning.

![TabPFN vs HistGBT learning curve](https://raw.githubusercontent.com/MAUK9086/patch-sloth/master/patch-sloth/results/learning_curve.png)

### Ultramarine: a frontier model, zero-shot

Every model was scored on the same 1,000 test CVEs:

| Model | Severity accuracy | Cost per 1,000 CVEs |
|---|---|---|
| Copy the CNA | 0.874 | $0 |
| Base Qwen3-8B | 0.865 | $0.063 |
| Fine-tuned Qwen3-8B | 0.861 | $0.045 (+ $3.37 training) |
| Ultramarine 1 Flash, zero-shot | 0.795 | $0.092 |

Zero-shot, Ultramarine rewrites CNA vectors too often, and is significantly worse than copying them
(p = 7e-11). So in Patch Sloth it writes the reports instead.

## Why open matters

[AHMAD: your argument]

- The model is an open-weight 8B model plus a LoRA adapter, trained on 30,000 public NVD decisions for $3.37. You
  can retrain it, audit it, or run it yourself.
- Scoring the whole unanalysed backlog (58,457 CVEs) cost $2.57.
- The feed is open: a CSV and a parquet file in a public GitHub release.

## What went wrong

**1. The baseline that was smaller than its name.** For three milestones, "HistGBT on all training data" was
actually trained on 10,000 rows. A command-line default meant for TabPFN applied to every model. Retrained on all
80,098 rows, HistGBT scored 0.627 and wiped out most of TabPFN's accuracy lead. That is why the TabPFN story is
sample efficiency. The clue was an "anomaly": HistGBT on a 30k subsample beat HistGBT on "everything".

**2. The NaN label bug.** The label rule started as `nvd_vector or cna_vector`. In pandas a missing string is
NaN, and NaN counts as true. So every CVE that NVD had accepted unchanged lost its label, and the training set
silently held only the CVEs NVD had rescored. Explicit string checks fixed it: 115,092 labelled rows became
122,459. A regression test covers None, NaN and `pd.NA`.

**3. A test that passed on Windows and failed on Linux.** The advisory scanner read files in filesystem order,
which is alphabetical on NTFS and hash order on ext4. A package that matches several advisories got a different
"fixed" version on each OS. I first blamed fresh data, which was wrong. The index is now built from a sorted
list.

[AHMAD: anything personal about these]

## Limitations

- Every score is an estimate for triage, not an official CVSS score. The labels are NVD's decisions, and NVD tends
  to score the worst case.
- In 2026 NVD writes its own vector for far fewer CVEs, so some "kept the CNA score" labels may reflect less
  review, not agreement.
- On 2026 CVEs, the fine-tuned model alone is less accurate than copying the CNA. Only the gated version beats it.
- The guardrail checks facts, not meaning. In the socket.io demo, the report's summary called three CVEs "axios"
  (only one is) and counted 33 packages for the P1 list (33 is the scan total; P1 spans 24). Every number was in
  the input, so it passed. The P0/P1/P2 tables come from code and are unaffected.
- LoRA weights downloaded from Tinker in PEFT format; vLLM's chat template matches the training prompt (200/200
  checked). The vLLM conversion and end-to-end parity were not run, for lack of time.
- The error analysis uses a HistGBT + LLM stack (PR-AUC 0.609 vs 0.621 for the served model) because the served
  model's per-row predictions were lost with GPU access. [AHMAD: tag summary from `results/error_sample_10.md`]
- Scope: CVSS v3.1 only; npm and PyPI only; no affected-product (CPE) lists; no exploitation prediction (EPSS is
  an input).

## Prize categories

**Tinker.** Tinker ran the LoRA fine-tune of Qwen3-8B ($3.37) and all sampling: base vs fine-tuned evaluation,
the stacking set and the 58,457-CVE backlog. Total logged spend was $8.16. The fine-tune lifted validation
severity accuracy from 0.710 to 0.869, and bump F1 from 0.03 to 0.83. [AHMAD]

**TabPFN.** TabPFN-3.5 is the classifier inside the served stack, behind the 75% "likely" precision. It reached 96%
of a fully trained HistGBT with 1/16 of the labels. It ran on a local GPU at no metered cost. [AHMAD]

**Ultramarine 1 Flash.** It writes every report under a numeric guardrail; the three demo reports cost $0.0012 to
$0.0077 each. It was also the frontier zero-shot baseline: $0.092 per 1,000 CVEs, and less accurate than copying
the CNA. Total logged spend was $0.11. [AHMAD]

**Entire.** Every Claude Code session that built this repo is stored as an Entire checkpoint in the public repo
[AHMAD: session links]

## Costs

| Item | Cost |
|---|---|
| Tinker: LoRA training (incl. dry run) | $3.38 |
| Tinker: evaluation sampling | $2.20 |
| Tinker: 58,457 unanalysed CVEs | $2.57 |
| Ultramarine: 1,000-CVE baseline + pilot | $0.09 |
| Ultramarine: reports so far | $0.015 |
| TabPFN, HistGBT | local, no metered cost |
| **Total metered** | **≈ $8.26** (+ ≤ $0.10 unlogged, interrupted Tinker run) |

## Credits and prior work

- Data: NVD JSON 2.0 via the fkie-cad mirror; CISA KEV; EPSS (FIRST/Empirical); GitHub Advisory Database
  (CC-BY 4.0); OSV / osv-scanner.
- Prior work: CISA Vulnrichment; VulnCheck's NVD backlog research; "Can LLMs Classify CVEs?" (arXiv 2504.10713).
- Built with Claude Code. The initial scaffold came from a Claude chat session before Entire was enabled.

## Links

- Repo: <https://github.com/MAUK9086/patch-sloth>
- Results behind every number: <https://github.com/MAUK9086/patch-sloth/blob/master/patch-sloth/results/final_table.md>
- Open feed (release `feed-2026-10-23`): <https://github.com/MAUK9086/patch-sloth/releases/tag/feed-2026-10-23>
- Entire checkpoints: stored as git refs, not a branch. Fetch them with
  `git fetch origin 'refs/entire/*:refs/entire/*'`. [AHMAD: Entire web links, if available]
