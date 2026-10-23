"""Lockfile parsing, OSV range semantics, and fixture lockfiles -> expected CVE set (fallback matcher).
The osv-scanner test is skipped when the binary or its offline DB is missing."""
import json
import os
import shutil
from pathlib import Path

import pytest

from patchsloth import scan

FIX = Path(__file__).parent / "fixtures"
EXPECTED = json.loads((FIX / "expected.json").read_text())


@pytest.fixture(scope="module")
def index(tmp_path_factory):
    out = tmp_path_factory.mktemp("idx") / "index.json.gz"
    scan.build_index(FIX / "advisories", out)
    return scan.load_index(out)


def test_parse_package_lock_v3():
    deps = scan.parse_lockfile((FIX / "package-lock.json").read_text(), "package-lock.json")
    names = {(d.name, d.version) for d in deps}
    assert all(d.ecosystem == "npm" for d in deps)
    assert ("lodash", "4.17.20") in names
    assert not any(d.name == "" or d.name.startswith("node_modules") for d in deps)


def test_parse_package_lock_v1_and_nested():
    text = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
        "c": {"version": "file:../c"}}})
    assert {(d.name, d.version) for d in scan.parse_lockfile(text, "package-lock.json")} == {
        ("a", "1.0.0"), ("b", "2.0.0")}


def test_parse_package_lock_v2_scoped_and_nested():
    text = json.dumps({"lockfileVersion": 2, "packages": {
        "": {"name": "root", "version": "1.0.0"},
        "node_modules/@scope/pkg": {"version": "1.2.3"},
        "node_modules/a/node_modules/b": {"version": "0.1.0"},
        "node_modules/linked": {"link": True, "resolved": "../linked"}}})
    assert {(d.name, d.version) for d in scan.parse_lockfile(text, "x.json")} == {
        ("@scope/pkg", "1.2.3"), ("b", "0.1.0")}


def test_parse_requirements():
    text = ("# comment\nDjango==3.2.0\nrequests[security] == 2.19.1 ; python_version>'3'\n"
            "flask>=2\n-e .\nJinja2===2.10\n")
    assert {(d.name, d.version) for d in scan.parse_lockfile(text, "requirements.txt")} == {
        ("django", "3.2.0"), ("requests", "2.19.1"), ("jinja2", "2.10")}


RANGE = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}
TWO = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"},
                                                    {"introduced": "2.0.0"}, {"last_affected": "2.1.0"}]}]}


@pytest.mark.parametrize("eco,ver,aff,expected", [
    ("npm", "4.17.20", RANGE, (True, "4.17.21")),
    ("npm", "4.17.21", RANGE, (False, None)),
    ("npm", "0.9.0", TWO, (False, None)),
    ("npm", "1.1.5", TWO, (True, "1.2.0")),
    ("npm", "1.5.0", TWO, (False, None)),
    ("npm", "2.1.0", TWO, (True, None)),
    ("npm", "2.1.1", TWO, (False, None)),
    ("PyPI", "2.10", {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]},
     (True, "2.10.1")),
    ("PyPI", "2.10.1", {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]},
     (False, None)),
    ("PyPI", "1.0", {"versions": ["1.0"], "ranges": []}, (True, None)),
    ("npm", "not-a-version", RANGE, (False, None)),
])
def test_affected_semantics(eco, ver, aff, expected):
    assert scan._affected(eco, ver, aff) == expected


@pytest.mark.parametrize("name", ["package-lock.json", "requirements.txt"])
def test_fixture_lockfiles_fallback(index, name):
    res = scan.scan_text((FIX / name).read_text(), name, engine="fallback", index=index)
    assert res["engine"] == "ghsa-fallback"
    assert sorted({c for f in res["findings"] for c in f["cves"]}) == sorted(EXPECTED[name]["cves"])
    # a package can match several advisories, each with its own fix: compare sets, not "last finding wins"
    fixed: dict[str, set] = {}
    for f in res["findings"]:
        fixed.setdefault(f["package"], set()).add(f["fixed"])
    for pkg, fx in EXPECTED[name]["fixed"].items():
        assert fx in fixed[pkg]


def test_fixtures_include_a_deferred_cve():
    assert EXPECTED["deferred_cves"], "SPEC §11.2: at least one fixture CVE must be currently Deferred"
    all_cves = EXPECTED["package-lock.json"]["cves"] + EXPECTED["requirements.txt"]["cves"]
    assert set(EXPECTED["deferred_cves"]) <= set(all_cves)


@pytest.mark.skipif(not shutil.which("osv-scanner") or not os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"),
                    reason="osv-scanner binary or offline DB not available")
@pytest.mark.parametrize("name", ["package-lock.json", "requirements.txt"])
def test_fixture_lockfiles_osv(name):
    findings = scan.run_osv(FIX / name, offline=True)
    got = {c for f in findings for c in f.cves}
    assert set(EXPECTED[name]["cves"]) <= got
