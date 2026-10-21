"""Cross-platform port of 01_download.sh (Windows has no bash by default). Run from repo root. ~150 MB.
Downloads the NVD yearly feeds (fkie-cad mirror), CISA KEV, the GitHub Advisory DB (sparse clone of
github-reviewed advisories) and today's EPSS scores, and stamps results/data_as_of.txt."""
import datetime as dt
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.data import epss  # noqa: E402

RAW = Path("data/raw")
RAW.mkdir(parents=True, exist_ok=True)


def get(url: str, out: Path) -> None:
    print("GET", url)
    tmp = out.with_suffix(out.suffix + ".part")
    urllib.request.urlretrieve(url, tmp)
    tmp.replace(out)


for y in range(2021, 2027):
    get(f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{y}.json.xz",
        RAW / f"CVE-{y}.json.xz")
get("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    RAW / "kev.json")

# GitHub Advisory Database (what Dependabot uses): npm + PyPI reviewed advisories, with CVE aliases
adb = RAW / "advisory-database"
if shutil.which("git"):
    if not adb.exists():
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
                        "https://github.com/github/advisory-database.git", str(adb)], check=True)
    else:
        subprocess.run(["git", "-C", str(adb), "pull", "--depth", "1"], check=False)
    subprocess.run(["git", "-C", str(adb), "sparse-checkout", "set", "advisories/github-reviewed"], check=True)
else:
    print("git not found: skipping the advisory database (needed by the fallback scanner)")

try:
    print("EPSS ->", epss.download())
except Exception as e:  # optional, report field only
    print("EPSS download failed (optional):", e)

Path("results").mkdir(exist_ok=True)
Path("results/data_as_of.txt").write_text(dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%MZ") + "\n")
print("done")
