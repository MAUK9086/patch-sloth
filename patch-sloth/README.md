# Patch Sloth

NIST no longer analyses every CVE. Since April 2026, many CVEs are marked **Deferred**, and the only severity score they carry comes from the CNA, the organisation that reported the vulnerability (often the vendor itself). In the years when NIST still reviewed those scores, it changed about 4 in 10 of them, and it raised them more often than it lowered them.

Patch Sloth reads your lockfile and finds the vulnerabilities NIST never checked. For each one it says whether an independent reviewer would likely rate it higher, and it writes you a one-minute patch list.

## Stack
- **Tinker:** fine-tunes Qwen3-8B to produce the "second opinion" CVSS vector.
- **TabPFN:** predicts the probability that the severity band gets bumped up.
- **DigitalOcean:** serves the model, the app, and the weekly scan.
- **Ultramarine 1 Flash:** writes the report.

## Reproduce
CPU-only, works on Windows, macOS and Linux. Run everything from this folder.
```
conda create -n patchsloth python=3.11 && conda activate patchsloth
pip install -r requirements.txt && pip install -e .     # GPU box: also requirements-gpu.txt
python scripts/01_download.py        # or: bash scripts/01_download.sh
python scripts/02_build_dataset.py
python scripts/03_baselines.py
python scripts/07_tabpfn_bump.py --model hgb      # or --model tabpfn (GPU)
patchsloth feed build                # HGB-only second-opinion feed -> feed/
pytest -q
```
The M1 numbers are in `results/m1_reproduction.md`. Decisions and their reasons are in `DECISIONS.md`.

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
