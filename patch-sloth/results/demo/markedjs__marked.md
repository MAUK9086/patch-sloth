# Security Triage Report

- **No P0 items.** 6 CVEs across 5 packages are due this month; the highest-attention item is `postcss-selector-parser`, where an independent reviewer would likely rate this higher.
- All P1 items are HIGH severity (CVSS 7.5) network-based issues; `brace-expansion` and `undici` have fixed versions ready to install.
- 8 CVEs are P2: mostly lower-severity issues, un-scored items, and no-exploit intel (EPSS ≤ 0.008, no KEV entries anywhere).

## P0: Patch now

None.

## P1: This month

| CVE | package | installed | fix | why |
|---|---|---|---|---|
| CVE-2026-104844 | postcss-selector-parser | 7.1.4 | 7.1.6 | Likely under-rated: CNA MEDIUM (5.9) → predicted HIGH (7.5); an independent reviewer would likely rate this higher. |
| CVE-2026-93687 | braces | 3.0.3 | — | CNA HIGH (7.5); no fixed version yet. |
| CVE-2026-93748 | http-cache-semantics | 4.2.0 | — | CNA HIGH (7.5) — confidentiality impact; no fixed version yet. |
| CVE-2026-102276 | brace-expansion | 5.0.9 | 5.0.10 | CNA HIGH (7.5); fix available. |
| CVE-2026-102278 | brace-expansion | 5.0.9 | 5.0.11 | CNA HIGH (7.5); fix available. |
| CVE-2026-19534 | undici | 6.28.0 | 6.28.1 | NIST-reviewed: CNA HIGH (7.5) / NVD HIGH (7.5). |

<details>
<summary>P2: Ignore for now</summary>

| CVE | package | installed | fix | why |
|---|---|---|---|---|
| CVE-2026-102277 | brace-expansion | 5.0.9 | 5.0.12 | CNA MEDIUM (5.3); a higher rating is possible but not likely. |
| CVE-2026-85024 | undici | 6.28.0 | 6.28.1 | NIST-reviewed: CNA MEDIUM (5.9) / NVD MEDIUM (5.9). |
| CVE-2026-101910 | ip-address | 10.5.0 | 10.5.1 | No CNA CVSS v3.1 score available. |
| CVE-2026-101913 | ip-address | 10.5.0 | 10.5.1 | No CNA CVSS v3.1 score available. |
| CVE-2026-101912 | ip-address | 10.5.0 | 10.7.1 | No CNA CVSS v3.1 score available. |
| CVE-2026-101911 | ip-address | 10.5.0 | 10.7.1 | No CNA CVSS v3.1 score available. |
| CVE-2026-18540 | undici | 6.28.0 | 6.28.1 | NIST-reviewed: CNA LOW (3.7) / NVD LOW (3.7). |
| CVE-2026-97058 | sprintf-js | 1.0.3 | — | Not in the feed (no second opinion); no CNA CVSS v3.1 score; no fixed version yet. |

</details>

## One-line reasons

- **CVE-2026-104844** — The reporter rated it MEDIUM, but our model predicts HIGH, so an independent reviewer would likely rate this higher — worth patching to 7.1.6.
- **CVE-2026-93687** — A HIGH-severity network issue in `braces` with no fix released yet; track the vendor for a patched version.
- **CVE-2026-93748** — A HIGH-severity network issue in `http-cache-semantics` that can leak confidential data; no fix released yet.
- **CVE-2026-102276 / CVE-2026-102278** — Two HIGH-severity issues in `brace-expansion`; updating to 5.0.12 (which includes both fixes 5.0.10 and 5.0.11) resolves them.
- **CVE-2026-19534** — NIST/NVD independently confirmed HIGH severity (7.5) for `undici`; update to 6.28.1.
- **P2 items** — Either low/medium severity confirmed by NIST, unscored `ip-address` bugs fixed in 10.5.1/10.7.1, or an unscored `sprintf-js` issue with no fix available and no second opinion.

---
Scores are estimates for triage, not official CVSS scores. "Likely under-rated" means an independent NVD-style reviewer would likely rate it higher, not that the vendor is wrong.

*Data as of 2026-10-23T05:49Z; EPSS as of 2026-10-22.*