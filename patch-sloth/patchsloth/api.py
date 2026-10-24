"""FastAPI app (SPEC §11.5): POST /scan, GET /cve/{id}, GET /feed/latest.csv, GET /health, and the web page."""
import asyncio
import re
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse

from . import config, service
from .feed import CSV_FILE, Feed, download_latest_release

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


class RateLimiter:
    """Sliding one-minute window per client IP, in memory (one instance per process)."""

    def __init__(self, per_minute: int = config.RATE_LIMIT_PER_MIN):
        self.per_minute, self.hits, self.lock = per_minute, defaultdict(deque), threading.Lock()

    def __call__(self, request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with self.lock:
            q = self.hits[ip]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                raise HTTPException(429, "rate limit exceeded, try again in a minute")
            q.append(now)


def create_app(feed: Feed | None = None, scan_kwargs: dict | None = None,
               rate_limit: int = config.RATE_LIMIT_PER_MIN, download: bool = False) -> FastAPI:
    """scan_kwargs are passed to service.run (tests inject a fixture advisory index, use_llm=False, ...).
    download=True fetches the newest feed-* GitHub release at server start-up (the deployed app)."""
    state = {"feed": feed, "release": None}

    @asynccontextmanager
    async def lifespan(_app):
        if download and state["feed"] is None:
            state["release"] = await asyncio.to_thread(download_latest_release)
            tag_file = config.FEED / "release_tag.txt"
            if state["release"] is None and tag_file.exists():  # GitHub unreachable: serving the baked/local feed
                state["release"] = tag_file.read_text().strip() + " (local copy)"
        if state["feed"] is None:  # load the ~0.5 GB feed before taking traffic, not on the first health check
            state["feed"] = await asyncio.to_thread(Feed)
        yield

    app = FastAPI(title="Patch Sloth", description="A second opinion on CNA-only CVSS scores. Estimates, not "
                                                   "official scores.", lifespan=lifespan)
    limit = RateLimiter(rate_limit)
    kw = scan_kwargs or {}

    def get_feed() -> Feed:
        if state["feed"] is None:
            state["feed"] = Feed()
        return state["feed"]

    @app.get("/health")
    def health():
        f = get_feed()
        return {"status": "ok", "data_as_of": f.data_as_of, "feed_rows": 0 if f.df is None else len(f.df),
                "model": f.meta.get("model"), "feed_release": state["release"], "llm_backend": config.LLM_BACKEND,
                "scan_engine": config.SCAN_ENGINE}

    @app.post("/scan", dependencies=[Depends(limit)])
    async def scan(request: Request, file: UploadFile | None = File(None), text: str | None = Form(None),
                   filename: str | None = Form(None), no_llm: bool = Form(False)):
        if int(request.headers.get("content-length") or 0) > config.MAX_UPLOAD_BYTES + 64 * 1024:
            raise HTTPException(413, "upload larger than 2 MB")
        if file is not None:
            raw = await file.read(config.MAX_UPLOAD_BYTES + 1)
            name = filename or file.filename or "package-lock.json"
        elif text:
            raw, name = text.encode("utf-8"), filename or ("package-lock.json" if text.lstrip().startswith("{")
                                                          else "requirements.txt")
        else:
            raise HTTPException(400, "send a lockfile as `file` or paste it as `text`")
        if len(raw) > config.MAX_UPLOAD_BYTES:
            raise HTTPException(413, "upload larger than 2 MB")
        try:
            content = raw.decode("utf-8-sig")
            opts = {**kw, **({"use_llm": False} if no_llm else {})}
            return service.run(content, name, get_feed(), **opts)
        except (ValueError, UnicodeDecodeError) as e:
            raise HTTPException(400, f"could not parse lockfile: {e}") from e
        except FileNotFoundError as e:  # no osv-scanner DB and no advisory index in this deployment
            raise HTTPException(503, f"scanner unavailable: {e}") from e

    @app.get("/cve/{cve_id}", dependencies=[Depends(limit)])
    def cve(cve_id: str):
        cve_id = cve_id.upper()
        if not CVE_ID.match(cve_id):
            raise HTTPException(400, "expected an ID like CVE-2026-12345")
        res = service.cve_opinion(cve_id, get_feed(), fetch_missing=kw.get("fetch_missing", True))
        if res is None:
            raise HTTPException(404, f"{cve_id} not found")
        return res

    @app.get("/feed/latest.csv")
    def feed_csv():
        if not CSV_FILE.exists():
            raise HTTPException(404, "feed not built yet: run `patchsloth feed build`")
        return FileResponse(CSV_FILE, media_type="text/csv", filename="patchsloth_second_opinion.csv")

    @app.get("/", response_class=HTMLResponse)
    def index():
        page = config.WEB / "index.html"
        return HTMLResponse(page.read_text(encoding="utf-8") if page.exists() else "<h1>Patch Sloth</h1>")

    return app


app = create_app(download=config.FEED_DOWNLOAD)
