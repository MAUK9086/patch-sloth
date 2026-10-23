"""`patchsloth` CLI (SPEC §11.1)."""
import json
from pathlib import Path

import typer

from . import config

app = typer.Typer(help="Patch Sloth: a second opinion on CNA-only CVSS scores for the CVEs in your lockfile.",
                  no_args_is_help=True)
feed_app = typer.Typer(help="Build the nightly second-opinion feed.", no_args_is_help=True)
app.add_typer(feed_app, name="feed")


@app.command()
def scan(path: Path = typer.Argument(..., exists=True, help="Lockfile or project directory"),
         format: str = typer.Option("md", "--format", "-f", help="md | json"),
         no_llm: bool = typer.Option(False, "--no-llm", help="No LLM calls: NullBackend + template report"),
         no_report: bool = typer.Option(False, "--no-report", help="Rows only, no report"),
         engine: str = typer.Option("auto", help="auto | osv | fallback"),
         fetch_missing: bool = typer.Option(False, help="Fetch CVEs missing from the feed from the NVD API")):
    """Scan a lockfile or a project directory."""
    from . import service
    from .feed import Feed
    from .llm.backends import get_backend

    files = [path] if path.is_file() else [p for n in ("package-lock.json", "requirements.txt")
                                           if (p := path / n).exists()]
    if not files:
        raise typer.BadParameter(f"no package-lock.json or requirements.txt in {path}")
    feed = Feed()
    if feed.df is None:
        typer.echo("warning: no feed found; run `patchsloth feed build` first", err=True)
    backend = get_backend("null" if no_llm else None)
    for f in files:
        res = service.run(f.read_text(encoding="utf-8"), f.name, feed, write=not no_report,
                          use_llm=False if no_llm else None, engine=engine, fetch_missing=fetch_missing,
                          backend=backend)
        if format == "json":
            typer.echo(json.dumps(res, indent=1, default=str))
        elif no_report:
            for r in res["rows"]:
                typer.echo(f"{r['bucket']}  {r['cve']:<18} {r['package']}@{r['version']}  {'; '.join(r['reason'])}")
        else:
            typer.echo(res["report_md"])
        typer.echo(f"[{f.name}: {res['n_deps']} deps, engine={res['engine']}, writer={res['costs']['writer']}, "
                   f"cost=${res['costs']['usd']:.4f}]", err=True)


@app.command()
def cve(cve_id: str = typer.Argument(..., help="e.g. CVE-2026-12345")):
    """Single-CVE second opinion."""
    from .service import cve_opinion
    res = cve_opinion(cve_id.upper())
    if res is None:
        typer.echo(f"{cve_id} not found in the feed or the NVD API", err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps(res, indent=1, default=str))


@feed_app.command("build")
def feed_build(since: str = typer.Option(None, help="Only CVEs published on/after YYYY-MM-DD in the CSV"),
               no_llm: bool = typer.Option(True, "--no-llm/--llm", help="HGB-only (CPU) or with the LLM backend"),
               model: str = typer.Option("hgb", help="Bump model saved by scripts/15 (hgb | tabpfn)")):
    """Score unanalysed CVEs and write feed/second_opinion.parquet + feed/latest.csv.
    Rebuild data/cves.parquet first with scripts/01_download.py and scripts/02_build_dataset.py."""
    from .feed import build
    typer.echo(json.dumps(build(since=since, model_name=model, no_llm=no_llm), indent=1, default=float))


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8080):
    """Run the API and web page locally."""
    import uvicorn
    uvicorn.run("patchsloth.api:app", host=host, port=port)


@app.command()
def costs():
    """Summarise results/costs.jsonl."""
    from .costs import summarise
    s = summarise()
    if not s:
        typer.echo(f"no costs logged yet ({config.RESULTS / 'costs.jsonl'})")
    typer.echo(json.dumps(s, indent=1))


if __name__ == "__main__":
    app()
