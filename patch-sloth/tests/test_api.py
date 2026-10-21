"""FastAPI TestClient: /health, /scan with fixtures (NullBackend, fixture feed + advisories, template report),
/cve/{id}, limits. Runs offline."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from patchsloth import report, scan
from patchsloth.api import create_app
from patchsloth.feed import Feed

FIX = Path(__file__).parent / "fixtures"
EXPECTED = json.loads((FIX / "expected.json").read_text())


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    idx_path = tmp_path_factory.mktemp("idx") / "index.json.gz"
    scan.build_index(FIX / "advisories", idx_path)
    feed = Feed(FIX / "feed" / "second_opinion.parquet")
    app = create_app(feed=feed, scan_kwargs=dict(index=scan.load_index(idx_path), use_llm=False,
                                                 fetch_missing=False, engine="fallback"), rate_limit=50)
    return TestClient(app)


def test_health(client):
    j = client.get("/health").json()
    assert j["status"] == "ok" and j["data_as_of"] and j["feed_rows"] > 0


@pytest.mark.parametrize("name", ["package-lock.json", "requirements.txt"])
def test_scan_upload(client, name):
    r = client.post("/scan", files={"file": (name, (FIX / name).read_bytes())})
    assert r.status_code == 200, r.text
    j = r.json()
    assert set(j) >= {"rows", "report_md", "costs", "data_as_of"}
    assert {x["cve"] for x in j["rows"]} == set(EXPECTED[name]["cves"])
    assert j["costs"]["writer"] == "template" and j["costs"]["usd"] == 0
    assert "not official" in j["report_md"] or "not official CVSS" in j["report_md"]
    facts = json.dumps({k: j[k] for k in ("rows", "counts", "data_as_of", "epss_date")} | {"n_cves": len(j["rows"])})
    ok, bad = report.guardrail(j["report_md"], facts)
    assert ok, bad
    for row in j["rows"]:
        assert row["bucket"] in ("P0", "P1", "P2") and row["reason"]


def test_scan_pasted_text_and_deferred_flagged(client):
    r = client.post("/scan", data={"text": (FIX / "package-lock.json").read_text()})
    rows = {x["cve"]: x for x in r.json()["rows"]}
    deferred = [c for c in EXPECTED["deferred_cves"] if c in rows]
    assert deferred and all(rows[c]["source"] == "model" and rows[c]["p_bump"] is not None for c in deferred)


def test_missing_from_feed_is_labelled(client):
    r = client.post("/scan", data={"text": (FIX / "requirements.txt").read_text(), "filename": "requirements.txt"})
    rows = {x["cve"]: x for x in r.json()["rows"]}
    for c in EXPECTED["missing_from_feed"]:
        if c in rows:
            assert rows[c]["source"] == "not-in-feed" and "not in the feed" in rows[c]["reason"][0]


def test_scan_errors(client):
    assert client.post("/scan").status_code == 400
    big = "a==1.0\n" * (2 * 1024 * 1024 // 7 + 10)
    assert client.post("/scan", files={"file": ("requirements.txt", big.encode())}).status_code == 413
    assert client.post("/scan", data={"text": "{not json"}).status_code == 400


def test_cve_endpoint(client):
    c = EXPECTED["deferred_cves"][0]
    j = client.get(f"/cve/{c.lower()}").json()
    assert j["cve"] == c and j["bucket"] in ("P0", "P1", "P2") and "not an official" in j["note"]
    assert client.get("/cve/not-a-cve").status_code == 400
    assert client.get("/cve/CVE-1999-0001").status_code == 404


def test_rate_limit():
    app = create_app(feed=Feed(FIX / "feed" / "second_opinion.parquet"), rate_limit=2,
                     scan_kwargs=dict(fetch_missing=False))
    c = TestClient(app)
    codes = [c.get("/cve/CVE-1999-0001").status_code for _ in range(3)]
    assert codes == [404, 404, 429]


def test_index_page(client):
    r = client.get("/")
    assert r.status_code == 200 and "Estimates, not official scores" in r.text
