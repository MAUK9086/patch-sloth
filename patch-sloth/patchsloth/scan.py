"""Lockfile -> vulnerable packages -> CVE IDs (SPEC §11.2).

Primary: osv-scanner v2 (`scan source --offline --offline-vulnerabilities -L <lockfile> --format json`).
Fallback: a pure-Python matcher over the local GitHub Advisory DB clone (OSV format), for
package-lock.json (v2/v3 `packages`, v1 `dependencies`) and requirements.txt `==` pins.
"""
import gzip
import json
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

import semver
from packaging.version import InvalidVersion, Version

from . import config

ECOSYSTEMS = ("npm", "PyPI")
INDEX_FILE = config.DATA / "advisory_index.json.gz"


@dataclass(frozen=True)
class Dep:
    ecosystem: str
    name: str
    version: str


@dataclass
class Finding:
    ecosystem: str
    package: str
    version: str
    advisory: str
    cves: list[str]
    fixed: str | None = None
    summary: str = ""
    aliases: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- lockfile parsing
def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_package_lock(text: str) -> list[Dep]:
    j = json.loads(text)
    deps: set[Dep] = set()
    for key, p in (j.get("packages") or {}).items():  # lockfileVersion 2/3
        if not key or p.get("link") or "version" not in p:
            continue
        name = p.get("name") or key.rsplit("node_modules/", 1)[-1]
        deps.add(Dep("npm", name, p["version"]))
    if not j.get("packages"):  # lockfileVersion 1
        def walk(d):
            for name, p in (d or {}).items():
                if "version" in p and not str(p["version"]).startswith(("file:", "link:", "git")):
                    deps.add(Dep("npm", name, p["version"]))
                walk(p.get("dependencies"))
        walk(j.get("dependencies"))
    return sorted(deps, key=lambda d: (d.name, d.version))


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)")


def parse_requirements(text: str) -> list[Dep]:
    deps = set()
    for line in text.splitlines():
        m = _REQ.match(line.split("#", 1)[0])
        if m:
            deps.add(Dep("PyPI", pep503(m.group(1)), m.group(2)))
    return sorted(deps, key=lambda d: (d.name, d.version))


def parse_lockfile(text: str, filename: str) -> list[Dep]:
    """Dispatch on file name; unknown names are sniffed (JSON -> npm, else requirements)."""
    base = Path(filename).name.lower()
    if base.endswith(".json") or text.lstrip().startswith("{"):
        return parse_package_lock(text)
    return parse_requirements(text)


# ---------------------------------------------------------------- advisory DB fallback
def _vkey(ecosystem: str, v: str):
    if ecosystem == "PyPI":
        return Version(v)
    return semver.Version.parse(v.lstrip("v"))


def _affected(ecosystem: str, version: str, affected: dict) -> tuple[bool, str | None]:
    """OSV semantics for one `affected` entry. Returns (is_affected, fixed_version_of_matching_range)."""
    if version in affected.get("versions", []):
        fixed = next((e["fixed"] for r in affected.get("ranges", []) for e in r["events"] if "fixed" in e), None)
        return True, fixed
    try:
        v = _vkey(ecosystem, version)
    except (InvalidVersion, ValueError, TypeError):
        return False, None
    for r in affected.get("ranges", []):
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        hit, fixed = False, None
        # GHSA ranges are introduced -> fixed|last_affected pairs, in order
        for e in r["events"]:
            try:
                if "introduced" in e:
                    hit = e["introduced"] == "0" or v >= _vkey(ecosystem, e["introduced"])
                elif "fixed" in e and hit:
                    if v >= _vkey(ecosystem, e["fixed"]):
                        hit = False
                    else:
                        fixed = e["fixed"]
                        break
                elif "last_affected" in e and hit:
                    if v > _vkey(ecosystem, e["last_affected"]):
                        hit = False
                    else:
                        break
            except (InvalidVersion, ValueError, TypeError):
                hit = False
                break
        if hit:
            return True, fixed
    return False, None


def build_index(advisory_dir: Path = config.ADVISORY_DB, out: Path = INDEX_FILE) -> Path:
    """Compact {ecosystem:name -> [advisory]} index of npm/PyPI advisories that have a CVE alias."""
    idx: dict[str, list] = {}
    skipped = []
    for f in sorted(Path(advisory_dir).rglob("GHSA-*.json")):  # sorted: rglob order differs by OS/filesystem
        try:
            a = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # e.g. Windows Defender blocks advisories that quote exploit payloads
            skipped.append(f.stem)
            continue
        if a.get("withdrawn"):
            continue
        cves = sorted({x for x in a.get("aliases", []) if x.startswith("CVE-")})
        for aff in a.get("affected", []):
            pkg = aff.get("package", {})
            eco = pkg.get("ecosystem")
            if eco not in ECOSYSTEMS:
                continue
            name = pep503(pkg["name"]) if eco == "PyPI" else pkg["name"]
            idx.setdefault(f"{eco}:{name}", []).append(dict(
                id=a["id"], cves=cves, summary=a.get("summary", ""),
                affected={k: aff[k] for k in ("ranges", "versions") if k in aff}))
    idx["_meta"] = {"skipped_unreadable": sorted(skipped)}
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        json.dump(idx, fh)
    if skipped:
        print(f"warning: skipped {len(skipped)} unreadable advisories: {', '.join(sorted(skipped)[:10])}")
    return out


_INDEX_CACHE: dict[str, dict] = {}


def load_index(path: Path = INDEX_FILE, advisory_dir: Path = config.ADVISORY_DB) -> dict:
    key = str(path)
    if key not in _INDEX_CACHE:
        if not Path(path).exists():
            if not Path(advisory_dir).exists():
                raise FileNotFoundError(f"no advisory index at {path} and no advisory DB at {advisory_dir}; "
                                        "run scripts/01_download.py")
            build_index(advisory_dir, path)
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            _INDEX_CACHE[key] = json.load(fh)
    return _INDEX_CACHE[key]


def match_fallback(deps: list[Dep], index: dict) -> list[Finding]:
    out = []
    for d in deps:
        for adv in index.get(f"{d.ecosystem}:{d.name}", []):
            hit, fixed = _affected(d.ecosystem, d.version, adv["affected"])
            if hit:
                out.append(Finding(d.ecosystem, d.name, d.version, adv["id"], adv["cves"], fixed, adv["summary"]))
    return out


# ---------------------------------------------------------------- osv-scanner
def osv_available() -> bool:
    return shutil.which("osv-scanner") is not None


def _osv_fixed(vuln: dict, ecosystem: str, name: str, version: str) -> str | None:
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") == ecosystem and pkg.get("name") == name:
            hit, fixed = _affected(ecosystem, version, aff)
            if hit and fixed:
                return fixed
    return None


def parse_osv_json(j: dict) -> list[Finding]:
    out = []
    for res in j.get("results") or []:
        for p in res.get("packages") or []:
            pkg = p["package"]
            eco, name, ver = pkg.get("ecosystem"), pkg.get("name"), pkg.get("version")
            for v in p.get("vulnerabilities") or []:
                ids = [v["id"], *v.get("aliases", [])]
                cves = sorted({x for x in ids if x.startswith("CVE-")})
                out.append(Finding(eco, name, ver, v["id"], cves, _osv_fixed(v, eco, name, ver),
                                   v.get("summary", ""), v.get("aliases", [])))
    return out


_OSV_SLOTS = threading.Semaphore(1)  # one osv-scanner process at a time: each one loads its DB (~0.6 GB)


def run_osv(lockfile: Path, offline: bool = True) -> list[Finding]:
    """osv-scanner v2 on one lockfile. Exit code 1 means 'vulnerabilities found', not failure."""
    with _OSV_SLOTS, tempfile.TemporaryDirectory() as td:
        out = Path(td) / "osv.json"
        cmd = ["osv-scanner", "scan", "source", "--format", "json", "--output-file", str(out), "-L", str(lockfile)]
        if offline:
            # --offline also stops transitive resolution via deps.dev (it sends the dependency list out)
            cmd[3:3] = ["--offline", "--offline-vulnerabilities"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode not in (0, 1) or not out.exists():
            raise RuntimeError(f"osv-scanner failed ({r.returncode}): {r.stderr[-500:]}")
        return parse_osv_json(json.loads(out.read_text(encoding="utf-8")))


# ---------------------------------------------------------------- entry point
def scan_text(text: str, filename: str, engine: str = "auto", index: dict | None = None) -> dict:
    """Scan lockfile content. engine: auto | osv | fallback. Returns deps count, engine and findings."""
    deps = parse_lockfile(text, filename)
    used = engine
    findings: list[Finding] | None = None
    if engine in ("auto", "osv") and osv_available() and index is None:
        try:
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / Path(filename).name
                p.write_text(text, encoding="utf-8")
                findings, used = run_osv(p), "osv-scanner"
        except Exception:
            if engine == "osv":
                raise
    if findings is None:
        findings, used = match_fallback(deps, index if index is not None else load_index()), "ghsa-fallback"
    return dict(n_deps=len(deps), engine=used, findings=[asdict(f) for f in findings])


def scan_path(path: Path, engine: str = "auto") -> dict:
    """A lockfile, or a directory containing package-lock.json / requirements.txt."""
    path = Path(path)
    files = [path] if path.is_file() else [p for n in ("package-lock.json", "requirements.txt")
                                           if (p := path / n).exists()]
    if not files:
        raise FileNotFoundError(f"no package-lock.json or requirements.txt in {path}")
    res = [scan_text(f.read_text(encoding="utf-8"), f.name, engine) for f in files]
    return dict(n_deps=sum(r["n_deps"] for r in res), engine=",".join(sorted({r["engine"] for r in res})),
                findings=[x for r in res for x in r["findings"]])


def cves_by_package(findings: list[dict]) -> dict[str, dict]:
    """CVE -> {package, version, ecosystem, fixed, advisory}; one row per CVE (first finding wins)."""
    out: dict[str, dict] = {}
    for f in findings:
        for c in f["cves"]:
            out.setdefault(c, dict(package=f["package"], version=f["version"], ecosystem=f["ecosystem"],
                                   fixed=f["fixed"], advisory=f["advisory"]))
    return out
