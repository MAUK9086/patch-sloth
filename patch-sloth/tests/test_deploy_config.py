"""Deployment switches: PATCHSLOTH_SCAN_ENGINE is the default scanner, the feed loads at start-up, and a missing
scanner DB is a 503 (not a 500). Runs offline."""
from pathlib import Path

from fastapi.testclient import TestClient

from patchsloth import api, config, service
from patchsloth.feed import Feed

FIX = Path(__file__).parent / "fixtures"


def test_scan_engine_default_comes_from_config(monkeypatch):
    seen = {}

    def fake_scan_text(text, filename, engine, index=None):
        seen["engine"] = engine
        return dict(n_deps=0, engine=engine, findings=[])

    monkeypatch.setattr(config, "SCAN_ENGINE", "fallback")
    monkeypatch.setattr(service.scan, "scan_text", fake_scan_text)
    service.run("{}", "package-lock.json", Feed(FIX / "feed" / "second_opinion.parquet"), write=False, use_llm=False)
    assert seen["engine"] == "fallback"


def test_feed_loads_at_startup_and_missing_index_is_503(monkeypatch):
    monkeypatch.setattr(api, "Feed", lambda: Feed(FIX / "feed" / "second_opinion.parquet"))

    def no_index(*a, **k):
        raise FileNotFoundError("no advisory index")

    monkeypatch.setattr(service, "run", no_index)
    app = api.create_app(download=False)
    with TestClient(app) as c:  # lifespan runs: the feed is loaded before the first request
        j = c.get("/health").json()
        assert j["feed_rows"] > 0 and j["scan_engine"] == config.SCAN_ENGINE
        r = c.post("/scan", data={"text": "requests==2.0.0", "filename": "requirements.txt"})
        assert r.status_code == 503 and "scanner unavailable" in r.text
