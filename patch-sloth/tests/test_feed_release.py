"""download_latest_release picks the newest feed-* tag, skips a tag it already has, and fails soft (no network)."""
import io
import json

from patchsloth import feed


def fake_api(releases, calls):
    def urlopen(req, timeout=None):
        calls.append(req.full_url)
        return io.BytesIO(json.dumps(releases).encode())

    def urlretrieve(url, dest):
        calls.append(url)
        dest.write_text(url)
    return urlopen, urlretrieve


REL = [{"tag_name": "feed-2026-10-22", "published_at": "2026-10-22", "draft": False,
        "assets": [{"name": "second_opinion.parquet", "browser_download_url": "u/old"}]},
       {"tag_name": "feed-2026-10-23", "published_at": "2026-10-23", "draft": False,
        "assets": [{"name": "second_opinion.parquet", "browser_download_url": "u/new.parquet"},
                   {"name": "bump_hgb.joblib", "browser_download_url": "u/hgb"}]},
       {"tag_name": "v0.1", "published_at": "2026-10-24", "draft": False, "assets": []}]


def test_newest_feed_tag_then_cached(tmp_path, monkeypatch):
    calls = []
    op, rt = fake_api(REL, calls)
    monkeypatch.setattr(feed.urllib.request, "urlopen", op)
    monkeypatch.setattr(feed.urllib.request, "urlretrieve", rt)
    out, models = tmp_path / "feed", tmp_path / "models"
    assert feed.download_latest_release("o/r", out, models) == "feed-2026-10-23"
    assert (out / "second_opinion.parquet").read_text() == "u/new.parquet"
    assert (models / "bump_hgb.joblib").exists()
    n = len(calls)
    assert feed.download_latest_release("o/r", out, models) == "feed-2026-10-23"
    assert len(calls) == n + 1  # only the API listing, no asset re-download


def test_fails_soft(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise OSError("offline")
    monkeypatch.setattr(feed.urllib.request, "urlopen", boom)
    assert feed.download_latest_release("o/r", tmp_path / "f", tmp_path / "m") is None
