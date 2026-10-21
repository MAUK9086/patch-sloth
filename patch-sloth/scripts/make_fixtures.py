"""Build tests/fixtures from real data (SPEC §11.2): two lockfiles with known-vulnerable pins, the GHSA
advisories for exactly those packages, a mini feed for those CVEs, and expected.json (the CVE set the
fallback matcher finds against the FULL advisory index, so the fixture DB is checked to be complete).
Needs data/raw/advisory-database, data/advisory_index.json.gz and feed/second_opinion.parquet."""
import json
import shutil
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import config, scan

FIX = Path("tests/fixtures")
NPM = {"lodash": "4.17.20", "brace-expansion": "1.1.11", "ajv": "6.12.6", "vue": "2.7.16", "ms": "2.1.3"}
PYPI = {"jinja2": "2.10", "requests": "2.31.0", "gradio": "5.20.0", "six": "1.16.0"}

lock = {"name": "patchsloth-fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
        "packages": {"": {"name": "patchsloth-fixture", "version": "1.0.0",
                          "dependencies": {k: f"^{v}" for k, v in NPM.items() if k != "brace-expansion"}}}}
for name, ver in NPM.items():
    key = f"node_modules/{name}" if name != "brace-expansion" else "node_modules/minimatch/node_modules/brace-expansion"
    lock["packages"][key] = {"version": ver, "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{ver}.tgz"}
lock["packages"]["node_modules/minimatch"] = {
    "version": "3.1.2", "resolved": "https://registry.npmjs.org/minimatch/-/minimatch-3.1.2.tgz",
    "dependencies": {"brace-expansion": "^1.1.7"}}

FIX.mkdir(parents=True, exist_ok=True)
(FIX / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
(FIX / "requirements.txt").write_text("# known-vulnerable pins for tests (do not install)\n"
                                      + "".join(f"{k}=={v}\n" for k, v in PYPI.items()))

full = scan.load_index()
expected, cves, ghsa = {}, set(), set()
for fname in ("package-lock.json", "requirements.txt"):
    res = scan.scan_text((FIX / fname).read_text(), fname, engine="fallback", index=full)
    found = sorted({c for f in res["findings"] for c in f["cves"]})
    expected[fname] = dict(cves=found, fixed={f["package"]: f["fixed"] for f in res["findings"]})
    cves |= set(found)
    ghsa |= {f["advisory"] for f in res["findings"]}
# also copy every (non-matching) advisory of these packages, so "not affected" paths are exercised
for eco, pkgs in (("npm", NPM), ("PyPI", PYPI)):
    for name in pkgs:
        ghsa |= {a["id"] for a in full.get(f"{eco}:{name}", [])}

adv_out = FIX / "advisories"
shutil.rmtree(adv_out, ignore_errors=True)
for g in sorted(ghsa):
    src = next(config.ADVISORY_DB.glob(f"*/*/{g}/{g}.json"))
    dst = adv_out / src.relative_to(config.ADVISORY_DB)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(src, dst)

feed = pd.read_parquet(config.FEED / "second_opinion.parquet")
mini = feed[feed.cve.isin(cves)]
(FIX / "feed").mkdir(exist_ok=True)
mini.to_parquet(FIX / "feed" / "second_opinion.parquet", index=False)
meta = json.loads((config.FEED / "meta.json").read_text())
(FIX / "feed" / "meta.json").write_text(json.dumps(meta, indent=1))
expected["deferred_cves"] = sorted(mini[(mini.status == "Deferred") & (mini.source == "model")].cve)
# Deferred but CNA scored only CVSS v4.0: nothing to second-guess (v3.1 only, SPEC §3)
expected["deferred_no_v31"] = sorted(mini[(mini.status == "Deferred") & (mini.source != "model")].cve)
expected["missing_from_feed"] = sorted(cves - set(mini.cve))
(FIX / "expected.json").write_text(json.dumps(expected, indent=1) + "\n")
print(json.dumps({k: (len(v["cves"]) if isinstance(v, dict) else v) for k, v in expected.items()}, indent=1))
print("advisories copied:", len(ghsa), "feed rows:", len(mini))
