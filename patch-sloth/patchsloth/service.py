"""scan -> feed lookup (or on-demand second opinion) -> priority rules -> report. Shared by CLI and API."""
from . import config, priority, report, scan
from .feed import Feed


def lookup_rows(cves: dict[str, dict], feed: Feed, fetch_missing: bool = False, backend=None) -> list[dict]:
    """One row per CVE with the fields priority.prioritise needs, plus package info from the scan."""
    rows = []
    for cve, pkg in sorted(cves.items()):
        rec = feed.get(cve) or (feed.on_demand(cve, backend) if fetch_missing else None)
        if rec is None:
            rows.append(dict(cve=cve, **pkg, source="not-in-feed", cna_vector=None, predicted_vector=None,
                             p_bump=None, bump_band=None, bump_high=None, epss=None, kev_date=None))
            continue
        rows.append(dict(cve=cve, **pkg, source=rec.get("source"), status=rec.get("status"),
                         cna_vector=rec.get("cna_vector"), predicted_vector=rec.get("predicted_vector"),
                         p_bump=rec.get("p_bump"), bump_band=rec.get("bump_band"), bump_high=rec.get("bump_high"),
                         epss=rec.get("epss"), kev_date=rec.get("kev_date")))
    return rows


def cve_opinion(cve_id: str, feed: Feed | None = None, fetch_missing: bool = True, backend=None) -> dict | None:
    """Single-CVE second opinion with its priority bucket (no package context, so no fix version)."""
    feed = feed or Feed()
    rec = feed.get(cve_id) or (feed.on_demand(cve_id, backend) if fetch_missing else None)
    if rec is None:
        return None
    row = priority.prioritise({k: rec.get(k) for k in ("cve", "cna_vector", "predicted_vector", "p_bump", "bump_band",
                                                        "bump_high", "epss", "kev_date", "source")} | {"fixed": None})
    if row.get("bump_band"):  # users see the band, not the raw probability
        row.pop("p_bump", None)
    return {**row, "status": rec.get("status"), "cna": rec.get("cna"), "source": rec.get("source"),
            "description": rec.get("description"), "data_as_of": feed.data_as_of,
            "note": "estimate for triage, not an official score"}


def run(text: str, filename: str, feed: Feed | None = None, *, write: bool = True, use_llm: bool | None = None,
        fetch_missing: bool = False, engine: str | None = None, index: dict | None = None, backend=None,
        report_tools=None) -> dict:
    """Full pipeline on lockfile content. Returns {rows, report_md, costs, data_as_of, engine, n_deps}."""
    feed = feed or Feed()
    sc = scan.scan_text(text, filename, engine=engine or config.SCAN_ENGINE, index=index)
    rows = lookup_rows(scan.cves_by_package(sc["findings"]), feed, fetch_missing, backend)
    ranked = priority.prioritise_all(rows)
    for r in ranked:
        if r["source"] == "not-in-feed":
            r["reason"].insert(0, "not in the feed (no second opinion)")
    payload = report.build_payload(ranked, feed.data_as_of, feed.meta.get("epss_date"))
    if write:
        tools = report_tools if report_tools is not None else report.ToolContext(payload, feed)
        rep = report.write_report(payload, use_llm=use_llm, tools=tools)
    else:
        rep = dict(report_md="", writer="none", guardrail_ok=None, attempts=0, usd=0.0)
    return dict(rows=payload["rows"], counts=payload["counts"], report_md=rep["report_md"],
                costs=dict(usd=rep["usd"], writer=rep["writer"], guardrail_ok=rep["guardrail_ok"]),
                data_as_of=feed.data_as_of, epss_date=payload["epss_date"], engine=sc["engine"],
                n_deps=sc["n_deps"])
