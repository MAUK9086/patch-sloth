# Dependency CVE Triage Report

## Summary
- **No P0s.** Everything actionable falls in P1 (61 CVEs across 33 packages, axios being the heaviest hit) — no KEV entries and no confirmed under-ratings in this feed.
- **P1 highlights:** three axios CVEs where NVD rated CRITICAL (CVE-2025-62718 at 9.9, CVE-2026-27606 and CVE-2026-27699 at 9.8/9.1), plus a CRITICAL proxy-addr finding. Many P1s still have no fixed version yet.
- **P2 (51 CVEs):** mostly LOW/MEDIUM NIST-reviewed items or CVEs lacking any CVSS score — safe to defer.

## P0: Patch now

_None in this scan._

## P1: This month

| CVE | Package | Installed | Fix | Why |
|---|---|---|---|---|
| CVE-2026-90711 | proxy-addr | 2.0.7 | 2.0.8 | CNA CRITICAL; fix available |
| CVE-2026-19693 | extract-zip | 2.0.1 | none yet | CNA HIGH; no fixed version yet |
| CVE-2026-93687 | braces | 3.0.3 | none yet | CNA HIGH; no fixed version yet |
| CVE-2026-85393 | node-forge | 1.3.1 | none yet | CNA HIGH; no fixed version yet |
| CVE-2026-93748 | http-cache-semantics | 4.2.0 | none yet | CNA HIGH; no fixed version yet |
| CVE-2024-12905 | tar-fs | 3.0.4 | 3.0.7 | CNA HIGH; fix available |
| CVE-2026-69185 | socket.io-parser | 3.3.4 | 3.3.6 | CNA HIGH; fix available |
| CVE-2026-102276 | brace-expansion | 1.1.12 | 1.1.19 | CNA HIGH; fix available |
| CVE-2026-102278 | brace-expansion | 1.1.12 | 1.1.20 | CNA HIGH; fix available |
| CVE-2026-73566 | tar | 6.2.1 | 7.5.21 | CNA HIGH; fix available |
| CVE-2026-73088 | browserslist | 4.26.3 | 4.28.7 | CNA HIGH; fix available |
| CVE-2026-84375 | js-yaml | 3.14.1 | 3.15.2 | CNA HIGH; fix available |
| CVE-2026-73089 | browserslist | 4.26.3 | 4.28.7 | CNA HIGH; fix available |
| CVE-2026-44240 | basic-ftp | 5.0.5 | 5.3.1 | CNA HIGH; fix available |
| CVE-2025-64756 | glob | 10.4.5 | 10.5.0 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-4800 | lodash | 4.17.21 | 4.18.0 | NIST-reviewed: CNA HIGH / NVD CRITICAL (8.1 vs 9.8); fix available |
| CVE-2026-25639 | axios | 1.12.2 | 1.13.5 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2025-13465 | lodash | 4.17.21 | 4.17.23 | NIST-reviewed: CNA HIGH / NVD MEDIUM (8.2 vs 5.3); fix available |
| CVE-2026-27606 | rollup | 2.79.2 | 2.80.0 | NIST-reviewed: CNA CRITICAL / NVD CRITICAL (9.1/9.8); fix available |
| CVE-2025-62718 | axios | 1.12.2 | 1.15.0 | NIST-reviewed: CNA HIGH / NVD CRITICAL (7.0 vs 9.9); fix available |
| CVE-2026-44495 | axios | 1.12.2 | 1.15.2 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-27699 | basic-ftp | 5.0.5 | 5.2.0 | NIST-reviewed: CNA CRITICAL / NVD CRITICAL (9.1/9.8); fix available |
| CVE-2026-42039 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-44496 | axios | 1.12.2 | 1.16.0 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-44494 | axios | 1.12.2 | 1.16.0 | NIST-reviewed: CNA HIGH / NVD HIGH (8.7, scoped); fix available |
| CVE-2026-44488 | axios | 1.12.2 | 1.16.0 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-42033 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-33891 | node-forge | 1.3.1 | 1.4.0 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-42264 | axios | 1.12.2 | 1.15.2 | NIST-reviewed: CNA HIGH / NVD CRITICAL (7.4 vs 9.1); fix available |
| CVE-2026-44486 | axios | 1.12.2 | 1.16.0 | NIST-reviewed: CNA HIGH / NVD HIGH (confidentiality impact); fix available |
| CVE-2026-44487 | axios | 1.12.2 | 1.16.0 | NIST-reviewed: CNA HIGH / NVD HIGH (confidentiality impact); fix available |
| CVE-2025-12816 | node-forge | 1.3.1 | 1.3.2 | NIST-reviewed: CNA HIGH / NVD HIGH (8.6, scoped); fix available |
| CVE-2026-42043 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA HIGH / NVD CRITICAL (7.2 vs 10.0); fix available |
| CVE-2026-69152 | brace-expansion | 1.1.12 | 1.1.18 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-59871 | tar | 6.2.1 | 7.5.18 | NIST-reviewed: CNA MEDIUM / NVD HIGH (5.3 vs 7.5); fix available |
| CVE-2026-14257 | brace-expansion | 1.1.12 | 1.1.17 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-24842 | tar | 6.2.1 | 7.5.7 | NIST-reviewed: CNA HIGH / NVD HIGH (8.2, scoped); fix available |
| CVE-2026-24001 | diff | 4.0.2 | 4.0.4 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-4867 | path-to-regexp | 0.1.12 | 0.1.13 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-33750 | brace-expansion | 1.1.12 | 1.1.13 | NIST-reviewed: CNA MEDIUM / NVD HIGH (6.5 vs 7.5); fix available |
| CVE-2026-27903 | minimatch | 10.0.1 | 10.2.3 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-42044 | axios | 1.12.2 | 1.15.2 | NIST-reviewed: CNA MEDIUM / NVD CRITICAL (6.5 vs 9.1); fix available |
| CVE-2026-59869 | js-yaml | 3.14.1 | 3.15.0 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-34043 | serialize-javascript | 6.0.2 | 7.0.5 | NIST-reviewed: CNA MEDIUM / NVD HIGH (5.9 vs 7.5); fix available |
| CVE-2026-2391 | qs | 6.13.0 | 6.14.2 | NIST-reviewed: CNA LOW / NVD HIGH (3.7 vs 7.5); fix available |
| CVE-2026-56876 | extract-zip | 2.0.1 | none yet | NIST-reviewed: CNA HIGH / NVD HIGH; no fixed version yet |
| CVE-2026-27904 | minimatch | 10.0.1 | 10.2.3 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-42338 | ip-address | 9.0.5 | 10.1.1 | NIST-reviewed: CNA HIGH / NVD MEDIUM (8.1 vs 6.1); fix available |
| CVE-2026-33896 | node-forge | 1.3.1 | 1.4.0 | NIST-reviewed: CNA HIGH / NVD CRITICAL (7.4 vs 9.1); fix available |
| CVE-2026-33671 | picomatch | 2.3.1 | 2.3.2 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-41324 | basic-ftp | 5.0.5 | 5.3.0 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-33895 | node-forge | 1.3.1 | 1.4.0 | NIST-reviewed: CNA HIGH / NVD HIGH (integrity impact); fix available |
| CVE-2026-33894 | node-forge | 1.3.1 | 1.4.0 | NIST-reviewed: CNA HIGH / NVD HIGH (integrity impact); fix available |
| CVE-2026-44490 | axios | 1.12.2 | 1.16.0 | NIST-reviewed: CNA MEDIUM / NVD HIGH (4.8 vs 8.2); fix available |
| CVE-2026-29786 | tar | 6.2.1 | 7.5.10 | NIST-reviewed: CNA HIGH / NVD MEDIUM (8.6 vs 6.3); fix available |
| CVE-2026-42035 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-42038 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA MEDIUM / NVD HIGH (6.8 vs 7.5); fix available |
| CVE-2026-23745 | tar | 6.2.1 | 7.5.3 | NIST-reviewed: CNA HIGH / NVD MEDIUM (8.2 vs 6.1); fix available |
| CVE-2026-23950 | tar | 6.2.1 | 7.5.4 | NIST-reviewed: CNA HIGH / NVD MEDIUM (8.8 vs 5.9); fix available |
| CVE-2026-26960 | tar | 6.2.1 | 7.5.8 | NIST-reviewed: CNA HIGH / NVD HIGH; fix available |
| CVE-2026-44728 | @babel/plugin-transform-modules-systemjs | 7.24.7 | 7.29.4 | NIST-reviewed: CNA HIGH / NVD HIGH (8.2 vs 7.8); fix available |

### Why (one reason per P1 CVE, plain English)
- **CVE-2026-90711 (proxy-addr):** the reporter rated this CRITICAL (9.1) with high confidentiality and integrity impact over the network; a fix is already out in 2.0.8.
- **CVE-2026-19693 (extract-zip):** reported HIGH (8.1, integrity + availability impact) and there is no fixed version yet, so track upstream and consider workarounds.
- **CVE-2026-93687 (braces):** HIGH (7.5, availability impact, no user interaction needed); no fixed version yet.
- **CVE-2026-85393 (node-forge):** HIGH (7.5, integrity impact over the network); no fixed version yet.
- **CVE-2026-93748 (http-cache-semantics):** HIGH (7.5, confidentiality impact over the network); no fixed version yet.
- **CVE-2024-12905 (tar-fs):** HIGH (7.5, integrity impact); upgrade to 3.0.7.
- **CVE-2026-69185 (socket.io-parser):** HIGH (7.5, availability impact); upgrade to 3.3.6.
- **CVE-2026-102276 / CVE-2026-102278 (brace-expansion):** two separate HIGH (7.5) availability-impact findings; upgrading to 1.1.20 fixes both.
- **CVE-2026-73566 (tar):** HIGH (7.5, availability impact); upgrade to 7.5.21.
- **CVE-2026-73088 / CVE-2026-73089 (browserslist):** two HIGH (7.5) availability-impact findings; upgrading to 4.28.7 fixes both.
- **CVE-2026-84375 (js-yaml):** HIGH (7.5, availability impact); upgrade to 3.15.2.
- **CVE-2026-44240 (basic-ftp):** HIGH (7.5, availability impact); upgrade to 5.3.1.
- **CVE-2025-64756 (glob):** NVD agreed with the reporter's HIGH (7.5); upgrade to 10.5.0.
- **CVE-2026-4800 (lodash):** NVD rates it CRITICAL (9.8) versus the reporter's HIGH (8.1); upgrade to 4.18.0.
- **CVE-2026-25639 (axios):** NVD confirmed HIGH (7.5, availability impact); upgrade to 1.13.5.
- **CVE-2025-13465 (lodash):** NVD rated it lower (MEDIUM, 5.3 vs 8.2) but it still lands in this month's batch; upgrade to 4.17.23.
- **CVE-2026-27606 (rollup):** both ratings CRITICAL (9.1/9.8); upgrade to 2.80.0.
- **CVE-2025-62718 (axios):** NVD rates it CRITICAL (9.9) versus the reporter's HIGH (7.0); upgrade to 1.15.0.
- **CVE-2026-44495 (axios):** NVD confirmed HIGH (7.7); upgrade to 1.15.2.
- **CVE-2026-27699 (basic-ftp):** both ratings CRITICAL (9.1/9.8); upgrade to 5.2.0.
- **CVE-2026-42039 (axios):** NVD confirmed HIGH (7.5, availability impact); upgrade to 1.15.1.
- **CVE-2026-44496 (axios):** NVD confirmed HIGH (7.5, availability impact); upgrade to 1.16.0.
- **CVE-2026-44494 (axios):** HIGH (8.7) in both analyses, scoped across systems; upgrade to 1.16.0.
- **CVE-2026-44488 (axios):** NVD confirmed HIGH (7.5, availability impact); upgrade to 1.16.0.
- **CVE-2026-42033 (axios):** NVD confirmed HIGH (7.4, confidentiality + integrity impact); upgrade to 1.15.1.
- **CVE-2026-33891 (node-forge):** NVD confirmed HIGH (7.5, availability impact); upgrade to 1.4.0.
- **CVE-2026-42264 (axios):** NVD rates it CRITICAL (9.1) versus the reporter's HIGH (7.4); upgrade to 1.15.2.
- **CVE-2026-44486 / CVE-2026-44487 (axios):** NVD confirmed HIGH (7.5) with confidentiality impact; upgrade to 1.16.0.
- **CVE-2025-12816 (node-forge):** HIGH (8.6) in both analyses, scoped across systems; upgrade to 1.3.2.
- **CVE-2026-42043 (axios):** NVD rates it CRITICAL (10.0, the maximum) versus the reporter's HIGH (7.2); upgrade to 1.15.1.
- **CVE-2026-69152 (brace-expansion):** NVD confirmed HIGH (7.5, availability impact); upgrade to 1.1.18.
- **CVE-2026-59871 (tar):** NVD rates it higher than the reporter (HIGH 7.5 vs MEDIUM 5.3); upgrade to 7.5.18.
- **CVE-2026-14257 (brace-expansion):** NVD confirmed HIGH (7.5, availability impact); upgrade to 1.1.17.
- **CVE-2026-24842 (tar):** HIGH (8.2) in both analyses, scoped across systems; upgrade to 7.5.7.
- **CVE-2026-24001 (diff):** NVD confirmed HIGH (7.5, availability impact); upgrade to 4.0.4.
- **CVE-2026-4867 (path-to-regexp):** NVD confirmed HIGH (7.5, availability impact); upgrade to 0.1.13.
- **CVE-2026-33750 (brace-expansion):** NVD rates it higher than the reporter (HIGH 7.5 vs MEDIUM 6.5); upgrade to 1.1.13.
- **CVE-2026-27903 (minimatch):** NVD confirmed HIGH (7.5, availability impact); upgrade to 10.2.3.
- **CVE-2026-42044 (axios):** NVD rates it CRITICAL (9.1) versus the reporter's MEDIUM (6.5); upgrade to 1.15.2.
- **CVE-2026-59869 (js-yaml):** NVD confirmed HIGH (7.5, availability impact); upgrade to 3.15.0.
- **CVE-2026-34043 (serialize-javascript):** NVD rates it higher than the reporter (HIGH 7.5 vs MEDIUM 5.9); upgrade to 7.0.5.
- **CVE-2026-2391 (qs):** NVD rates it much higher than the reporter (HIGH 7.5 vs LOW 3.7); upgrade to 6.14.2.
- **CVE-2026-56876 (extract-zip):** NVD confirmed HIGH (8.1, confidentiality + integrity impact); no fixed version yet — monitor upstream.
- **CVE-2026-27904 (minimatch):** NVD confirmed HIGH (7.5, availability impact); upgrade to 10.2.3 (same fix as CVE-2026-27903).
- **CVE-2026-42338 (ip-address):** NVD rated it lower than the reporter (MEDIUM 6.1 vs HIGH 8.1) but still actionable; upgrade to 10.1.1.
- **CVE-2026-33896 (node-forge):** NVD rates it CRITICAL (9.1) versus the reporter's HIGH (7.4); upgrade to 1.4.0.
- **CVE-2026-33671 (picomatch):** NVD confirmed HIGH (7.5, availability impact); upgrade to 2.3.2.
- **CVE-2026-41324 (basic-ftp):** NVD confirmed HIGH (7.5, availability impact); upgrade to 5.3.0.
- **CVE-2026-33895 / CVE-2026-33894 (node-forge):** NVD confirmed HIGH (7.5) with integrity impact; upgrading to 1.4.0 fixes both.
- **CVE-2026-44490 (axios):** NVD rates it much higher than the reporter (HIGH 8.2 vs MEDIUM 4.8); upgrade to 1.16.0.
- **CVE-2026-29786 (tar):** the reporter rated it higher (HIGH 8.6) than NVD (MEDIUM 6.3), but NVD also narrowed the attack surface; upgrade to 7.5.10.
- **CVE-2026-42035 (axios):** NVD confirmed HIGH (7.4, confidentiality + integrity impact); upgrade to 1.15.1.
- **CVE-2026-42038 (axios):** NVD rates it higher than the reporter (HIGH 7.5 vs MEDIUM 6.8); upgrade to 1.15.1.
- **CVE-2026-23745 (tar):** the reporter rated it higher (HIGH 8.2) than NVD (MEDIUM 6.1); upgrade to 7.5.3.
- **CVE-2026-23950 (tar):** the reporter rated it higher (HIGH 8.8) than NVD (MEDIUM 5.9); upgrade to 7.5.4.
- **CVE-2026-26960 (tar):** NVD confirmed HIGH (7.1, local attack vector, confidentiality + integrity impact); upgrade to 7.5.8.
- **CVE-2026-44728 (@babel/plugin-transform-modules-systemjs):** NVD confirmed HIGH (7.8 vs 8.2, local attack vector); upgrade to 7.29.4.

## P2: Ignore for now

<details><summary>P2: Ignore for now</summary>

| CVE | Package | Installed | Fix | Why |
|---|---|---|---|---|
| CVE-2025-69873 | ajv | 8.16.0 | 8.18.0 | CNA LOW; a higher rating is possible (model MEDIUM, 6.2); fix available |
| CVE-2026-59875 | tar | 6.2.1 | 7.5.17 | CNA MEDIUM; a higher rating is possible; fix available |
| CVE-2026-102277 | brace-expansion | 1.1.12 | 1.1.21 | CNA MEDIUM; a higher rating is possible; fix available |
| CVE-2026-8723 | qs | 6.13.0 | 6.15.2 | CNA MEDIUM; a higher rating is possible; fix available |
| CVE-2026-82417 | qs | 6.13.0 | 6.16.0 | CNA MEDIUM; a higher rating is possible; fix available |
| CVE-2024-36751 | parseuri | 0.0.6 | none yet | CNA MEDIUM (6.5, availability impact); no fixed version yet |
| CVE-2026-40175 | axios | 1.12.2 | 1.15.0 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (4.8); fix available |
| CVE-2026-42041 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (4.8/6.5); fix available |
| CVE-2026-33151 | socket.io-parser | 3.3.4 | 3.3.5 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-69192 | ip-address | 9.0.5 | 10.3.1 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-67317 | axios | 1.12.2 | 1.18.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-26996 | minimatch | 10.0.1 | 10.2.1 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-59873 | tar | 6.2.1 | 7.5.19 | No CNA CVSS v3.1 score; fix available |
| CVE-2025-48387 | tar-fs | 3.0.4 | 3.0.9 | No CNA CVSS v3.1 score; fix available |
| CVE-2025-59343 | tar-fs | 3.0.4 | 3.1.1 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-101900 | axios | 1.12.2 | 1.20.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-40345 | deepmerge-ts | 5.1.0 | 8.0.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-67312 | axios | 1.12.2 | 1.18.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-67313 | axios | 1.12.2 | 1.18.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-33672 | picomatch | 2.3.1 | 2.3.2 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (5.3); fix available |
| CVE-2026-45819 | baseline-browser-mapping | 2.8.15 | 2.11.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-42034 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (5.3); fix available |
| CVE-2026-42036 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (5.3); fix available |
| CVE-2025-15284 | qs | 6.13.0 | 6.14.1 | NIST-reviewed: CNA LOW / NVD LOW (3.7); fix available |
| CVE-2026-59874 | tar | 6.2.1 | 7.5.18 | No CNA CVSS v3.1 score; fix available |
| CVE-2025-66031 | node-forge | 1.3.1 | 1.3.2 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-101904 | axios | 1.12.2 | 1.20.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-67316 | axios | 1.12.2 | 1.18.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2025-64718 | js-yaml | 3.14.1 | 3.14.2 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (5.3); fix available |
| CVE-2026-53550 | js-yaml | 3.14.1 | 3.15.0 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (5.3); fix available |
| CVE-2026-101902 | axios | 1.12.2 | 1.20.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-101908 | axios | 1.12.2 | 1.20.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-12590 | body-parser | 1.20.3 | 1.20.6 | NIST-reviewed: CNA LOW / NVD MEDIUM (3.7/5.9); fix available |
| CVE-2026-2950 | lodash | 4.17.21 | 4.18.0 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (6.5/5.3); fix available |
| CVE-2026-101913 | ip-address | 9.0.5 | 10.5.1 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-41907 | uuid | 8.3.2 | 11.1.1 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-101912 | ip-address | 9.0.5 | 10.7.1 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-102990 | basic-ftp | 5.0.5 | 6.2.1 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-13149 | brace-expansion | 1.1.12 | 1.1.16 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-42037 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (5.3); fix available |
| CVE-2026-42042 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA MEDIUM / NVD MEDIUM (5.4); fix available |
| CVE-2025-66030 | node-forge | 1.3.1 | 1.3.2 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-67319 | axios | 1.12.2 | 1.18.0 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-101911 | ip-address | 9.0.5 | 10.7.1 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-42040 | axios | 1.12.2 | 1.15.1 | NIST-reviewed: CNA LOW / NVD LOW (3.7); fix available |
| CVE-2025-68157 | webpack | 5.102.1 | 5.104.0 | NIST-reviewed: CNA LOW / NVD LOW (3.7); fix available |
| CVE-2025-68458 | webpack | 5.102.1 | 5.104.1 | NIST-reviewed: CNA LOW / NVD LOW (3.7); fix available |
| CVE-2026-31802 | tar | 6.2.1 | 7.5.11 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-53655 | tar | 6.2.1 | 7.5.16 | No CNA CVSS v3.1 score; fix available |
| CVE-2026-49356 | @babel/core | 7.24.7 | 7.29.6 | NIST-reviewed: CNA LOW / NVD LOW (3.2/3.6); fix available |
| CVE-2026-97058 | sprintf-js | 1.0.3 | none yet | Not in the feed (no second opinion), no CNA CVSS v3.1 score, no fixed version yet |

Briefly: the P2 bucket holds LOW-rated or mutually-agreed MEDIUM findings, CVEs where the reporter published no CVSS v3.1 score, and one CVE not present in any rating feed. All have low exploitation signal (EPSS well below 1%) and no KEV entries.

</details>

---

Scores are estimates for triage, not official CVSS scores. "Likely under-rated" means an independent NVD-style reviewer would likely rate it higher, not that the vendor is wrong.

*Data as of 2026-10-23T05:49Z · EPSS date 2026-10-22*