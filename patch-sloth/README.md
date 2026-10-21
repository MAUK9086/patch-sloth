# Patch Sloth

NIST no longer analyses every CVE. Since April 2026, many CVEs are marked **Deferred**, and the only severity score they carry comes from the CNA, the organisation that reported the vulnerability (often the vendor itself). In the years when NIST still reviewed those scores, it changed about 4 in 10 of them, and it raised them more often than it lowered them.

Patch Sloth reads your lockfile and finds the vulnerabilities NIST never checked. For each one it says whether an independent reviewer would likely rate it higher, and it writes you a one-minute patch list.

## Stack
- **Tinker:** fine-tunes Qwen3-8B to produce the "second opinion" CVSS vector.
- **TabPFN:** predicts the probability that the severity band gets bumped up.
- **DigitalOcean:** serves the model, the app, and the weekly scan.
- **Ultramarine 1 Flash:** writes the report.

## Reproduce
```
pip install -r requirements.txt
bash scripts/01_download.sh
python scripts/02_build_dataset.py
python scripts/03_baselines.py
python scripts/07_tabpfn_bump.py --model hgb      # or --model tabpfn (GPU)
python scripts/04_make_tinker_data.py && python scripts/05_tinker_train.py --dry_run
```
See `PLAN.md` for the full build plan and the current results.

## Data and licences
- **NVD**, via the [fkie-cad mirror](https://github.com/fkie-cad/nvd-json-data-feeds): public domain.
- **CISA KEV:** public domain.
- **GitHub Advisory Database:** CC-BY 4.0.
- **EPSS:** FIRST.org.
- **TabPFN 2.5:** non-commercial licence. This project is used for research and hackathon purposes only.

Predictions are estimates for triage. They are not official scores.
