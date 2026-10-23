# Dependency CVE Triage Report

**Summary**
- 1 of 36 CVEs (CVE-2026-102414, `pbkdf2`) is likely under-rated: CNA says LOW (3.7) but an independent reviewer would likely rate this higher (predicted HIGH, 7.5). **Patch today.**
- 21 CVEs are P1 this month — mostly HIGH-rated issues in `fast-uri`, `brace-expansion`, `js-yaml`, `minimatch`, `browserslist`, and `shell-quote`; most are NIST-reviewed with no disputed scores.
- 14 CVEs can be ignored for now; several have no score or no fixed version yet.

## P0: Patch now

| CVE | package | installed | fix | why |
|---|---|---|---|---|
| CVE-2026-102414 | pbkdf2 | 3.1.5 | 3.1.7 | CNA rated LOW (3.7, availability:low, high attack complexity), but predicted HIGH (7.5, low complexity, availability:high) — likely under-rated; a bump is likely |

## P1: This month

| CVE | package | installed | fix | why |
|---|---|---|---|---|
| CVE-2026-9277 | shell-quote | 1.8.1 | 1.8.4 | CNA HIGH (8.1) — C/I/A all high; a higher rating is possible |
| CVE-2026-102276 | brace-expansion | 2.0.2 | 2.1.5 | CNA HIGH (7.5) — high network availability impact |
| CVE-2026-102278 | brace-expansion | 2.0.2 | 2.1.6 | CNA HIGH (7.5) — high availability impact |
| CVE-2026-69152 | brace-expansion | 2.0.2 | 2.1.4 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 |
| CVE-2026-14257 | brace-expansion | 2.0.2 | 2.1.3 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 |
| CVE-2026-33750 | brace-expansion | 2.0.2 | 2.0.3 | NIST-reviewed: CNA MEDIUM 6.5 / NVD HIGH 7.5 — NVD removed the user-interaction requirement |
| CVE-2026-13149 not here — see P2 below | | | | |

*(Note: CVE-2026-13149 is P2.)*

| CVE | package | installed | fix | why |
|---|---|---|---|---|
| CVE-2026-73088 | browserslist | 4.28.1 | 4.28.7 | CNA HIGH (7.5) — high availability impact |
| CVE-2026-73089 | browserslist | 4.28.1 | 4.28.7 | CNA HIGH (7.5) — high availability impact |
| CVE-2026-84375 | js-yaml | 3.14.2 | 3.15.2 | CNA HIGH (7.5) — high availability impact |
| CVE-2026-59869 | js-yaml | 3.14.2 | 3.15.0 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 |
| CVE-2026-27903 | minimatch | 9.0.5 | 9.0.7 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 |
| CVE-2026-27904 | minimatch | 9.0.5 | 9.0.7 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 |
| CVE-2026-6321 | fast-uri | 3.1.0 | 3.1.1 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 — high integrity impact |
| CVE-2026-6322 | fast-uri | 3.1.0 | 3.1.2 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 — high integrity impact |
| CVE-2026-13676 | fast-uri | 3.1.0 | 3.1.3 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 — high integrity impact |
| CVE-2026-16221 | fast-uri | 3.1.0 | 3.1.4 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 — high integrity impact |
| CVE-2026-18446 | fast-uri | 3.1.0 | 3.1.5 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 — high integrity impact |
| CVE-2026-76172 | fast-uri | 3.1.0 | 3.1.6 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 — high integrity impact |
| CVE-2026-75975 | fast-uri | 3.1.0 | 3.1.6 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 — high integrity impact |
| CVE-2026-84292 | fast-uri | 3.1.0 | 3.1.7 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 — high integrity impact |
| CVE-2026-13311 | shell-quote | 1.8.1 | 1.9.0 | NIST-reviewed: CNA HIGH 7.5 / NVD HIGH 7.5 |

**Fast-track tip:** upgrading `fast-uri` to 3.1.7+, `brace-expansion` to 2.1.6+, `js-yaml` to 3.15.2+, and `minimatch` to 9.0.7 clears most P1s at once.

<details>
<summary>P2: Ignore for now</summary>

| CVE | package | installed | fix | why |
|---|---|---|---|---|
| CVE-2025-69873 | ajv | 8.17.1 | 8.18.0 | CNA LOW (2.9); predicted MEDIUM (6.2) — a higher rating is possible |
| CVE-2026-2739 | bn.js | 4.12.2 | 4.12.3 | CNA MEDIUM (5.3); predicted HIGH (7.5) — a higher rating is possible |
| CVE-2025-14505 | elliptic | 6.6.1 | none yet | CNA MEDIUM (5.6) — a higher rating is possible; no fixed version yet |
| CVE-2026-102277 | brace-expansion | 2.0.2 | 2.1.7 | CNA MEDIUM (5.3) — a higher rating is possible |
| CVE-2026-86472 | fast-uri | 3.1.0 | 3.1.8 | CNA MEDIUM (4.8) — low confidentiality/integrity impact |
| CVE-2026-53550 | js-yaml | 3.14.2 | 3.15.0 | NIST-reviewed: CNA MEDIUM 5.3 / NVD MEDIUM 5.3 (fixed by the same update as CVE-2026-84375) |
| CVE-2026-49356 | @babel/core | 7.28.5 | 7.29.6 | NIST-reviewed: CNA LOW 3.2 / NVD LOW 3.6 |
| CVE-2026-26996 | minimatch | 9.0.5 | 9.0.6 | no CNA CVSS v3.1 score (fixed by the 9.0.7 update above) |
| CVE-2026-45819 | baseline-browser-mapping | 2.9.19 | 2.11.0 | no CNA CVSS v3.1 score |
| CVE-2026-41907 | uuid | 8.3.2 | 11.1.1 | no CNA CVSS v3.1 score |
| CVE-2026-13149 | brace-expansion | 2.0.2 | 2.1.2 | no CNA CVSS v3.1 score (fixed by the 2.1.6 update above) |
| CVE-2026-103923 | katex | 0.16.45 | 0.18.2 | no CNA CVSS v3.1 score |
| CVE-2026-97711 | serialize-javascript | 7.1.1 | 7.1.2 | no CNA CVSS v3.1 score |
| CVE-2026-97058 | sprintf-js | 1.0.3 | none yet | not in the feed (no second opinion), no CNA score, no fixed version yet |

</details>

**Data dates:** scan data as of 2026-10-23T05:49Z; EPSS as of 2026-10-22.

Scores are estimates for triage, not official CVSS scores. "Likely under-rated" means an independent NVD-style reviewer would likely rate it higher, not that the vendor is wrong.