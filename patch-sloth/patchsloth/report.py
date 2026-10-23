"""Report writer (SPEC §11.4): Ultramarine 1 Flash over the already-prioritised scan, with a guardrail
and a deterministic Jinja template fallback. The model explains priorities; it never sets them.

Guardrail: every CVE ID and every number in the model's text must appear in the facts it was given
(the payload plus any tool results). Fail -> retry once -> template.
"""
import json
import re
import time

from jinja2 import Environment

from . import config, costs
from .cvss import base_score, parse, severity

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
NUM_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+)*(?![\w])")
SMALL_INTS = {str(i) for i in range(11)}  # list numbering, "3-line", P0-P2 etc.

FOOTER = ("Scores are estimates for triage, not official CVSS scores. \"Likely under-rated\" means an "
          "independent NVD-style reviewer would likely rate it higher, not that the vendor is wrong.")

SYSTEM = f"""You write a short security triage report for a software maintainer, in Markdown.
You receive JSON with dependency CVEs that are ALREADY prioritised into P0 (patch now), P1 (this month)
and P2 (ignore for now). Never change a priority. Never invent CVE IDs, scores, versions, dates or
probabilities: only use values present in the JSON or returned by tools, written exactly as given.
Fields: cna_* is the reporter's (CNA's) own score. nvd_* is NVD's official analysis (only when NVD analysed it).
predicted_* is a model estimate. p_bump is the estimated probability that an independent NVD-style reviewer
would raise the CNA's severity band. counts.packages is the number of affected packages.
Rows with nist_reviewed=true were already analysed by NIST/NVD: label them "NIST-reviewed", show the CNA and NVD
severities side by side, and give no model prediction or probability for them.
Structure:
1. A 3-line summary.
2. A "P0: Patch now" table, then "P1: This month" (columns: CVE, package, installed, fix, why).
3. P2 inside <details><summary>P2: Ignore for now</summary> ... </details>.
4. One plain-English reason per CVE, based on its `reason` list.
5. End with this footer, then the data dates from the JSON: {FOOTER}
Say "an independent reviewer would likely rate this higher", never "the vendor is wrong"."""

TOOLS = [
    {"type": "function", "function": {
        "name": "get_cve", "description": "Description, CNA vector and predicted vector for one CVE.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}}},
    {"type": "function", "function": {
        "name": "explain_flag", "description": "Top feature contributions to the under-rating probability.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}}},
    {"type": "function", "function": {
        "name": "similar_cves", "description": "Past CVEs with the same CNA and CWE, and what NVD did.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}, "k": {"type": "integer"}},
                       "required": ["cve_id"]}}},
]

TEMPLATE = """\
# Patch Sloth report

{{ summary_lines | join("\\n") }}

{% for b, title in [("P0", "Patch now"), ("P1", "This month")] -%}
## {{ b }}: {{ title }}
{% if rows_by[b] -%}
| CVE | Package | Installed | Fix | CNA | NVD / second opinion | Why |
|---|---|---|---|---|---|---|
{% for r in rows_by[b] -%}
| {{ r.cve }} | {{ r.package }} | {{ r.version }} | {{ r.fixed or "none yet" }} | {{ r.cna_severity or "unscored" }} \
| {{ opinion(r) }} | {{ r.reason | join("; ") }} |
{% endfor %}
{% else -%}
Nothing here.
{% endif %}
{% endfor -%}
<details><summary>P2: Ignore for now ({{ rows_by["P2"] | length }})</summary>

{% for r in rows_by["P2"] -%}
- {{ r.cve }} in {{ r.package }} {{ r.version }}: {{ r.reason | join("; ") }}
{% endfor %}
</details>

---
_{{ footer }} Data as of {{ data_as_of or "unknown" }}; EPSS {{ epss_date or "n/a" }}._
"""


def _sev(v):
    return severity(base_score(parse(v))) if isinstance(v, str) else None


def _score(v):
    return base_score(parse(v)) if isinstance(v, str) else None


def _r(x, nd):
    try:
        x = float(x)
    except (TypeError, ValueError):
        return None
    return None if x != x else round(x, nd)


def build_payload(rows: list[dict], data_as_of: str | None = None, epss_date: str | None = None) -> dict:
    """Display-ready facts (rounded exactly as they may appear in the report)."""
    out = []
    for r in rows:
        # for CVEs NVD analysed, the "predicted" vector is NVD's official one: name it so the writer can't
        # present it as a model prediction
        nvd = r.get("source") == "nvd"
        pv = r.get("predicted_vector")
        out.append(dict(
            cve=r["cve"], package=r.get("package"), version=r.get("version"), fixed=r.get("fixed"),
            bucket=r["bucket"], reason=list(r.get("reason", [])), source=r.get("source"), nist_reviewed=nvd,
            cna_vector=r.get("cna_vector"), cna_score=_score(r.get("cna_vector")),
            cna_severity=_sev(r.get("cna_vector")),
            nvd_vector=pv if nvd else None, nvd_score=_score(pv) if nvd else None,
            nvd_severity=_sev(pv) if nvd else None,
            predicted_vector=None if nvd else pv, predicted_score=None if nvd else _score(pv),
            predicted_severity=None if nvd else _sev(pv),
            p_bump=None if nvd else _r(r.get("p_bump"), 2), epss=_r(r.get("epss"), 3), kev_date=r.get("kev_date")))
    counts = {b: sum(r["bucket"] == b for r in out) for b in ("P0", "P1", "P2")}
    counts["packages"] = len({(r["package"], r["version"]) for r in out})
    counts["likely_underrated"] = sum(any("under-rated" in x for x in r["reason"]) for r in out)
    return dict(counts=counts, n_cves=len(out), data_as_of=data_as_of, epss_date=epss_date, rows=out)


def _opinion(r: dict) -> str:
    """What the second-opinion cell can honestly say for this row."""
    p = f"p(higher)={r['p_bump']}" if r["p_bump"] is not None else ""
    if r["nist_reviewed"]:
        return f"NIST-reviewed: CNA {r['cna_severity'] or 'unscored'} / NVD {r['nvd_severity']}"
    if r["source"] in ("model", "model-on-demand"):
        if r["predicted_vector"] and r["predicted_vector"] != r["cna_vector"]:  # an LLM vector exists
            return f"{r['predicted_severity']} ({p})" if p else r["predicted_severity"]
        return p or "n/a"
    return "n/a"


def template_report(payload: dict) -> str:
    c = payload["counts"]
    rows_by = {b: [r for r in payload["rows"] if r["bucket"] == b] for b in ("P0", "P1", "P2")}
    summary = [f"- {payload['n_cves']} CVEs in {c['packages']} packages: {c['P0']} patch now, {c['P1']} this month, "
               f"{c['P2']} can wait.",
               f"- {c['likely_underrated']} look under-rated by their CNA "
               "(an independent reviewer would likely rate them higher).",
               "- Priorities are deterministic rules (KEV, EPSS, severity, under-rating probability)."]
    env = Environment(autoescape=False, trim_blocks=False)
    return env.from_string(TEMPLATE).render(summary_lines=summary, rows_by=rows_by, footer=FOOTER, opinion=_opinion,
                                            data_as_of=payload.get("data_as_of"),
                                            epss_date=payload.get("epss_date"))


def guardrail(text: str, facts: str) -> tuple[bool, list[str]]:
    """Every CVE ID and number in `text` must appear in `facts` (JSON string of all inputs)."""
    facts_u = facts.upper()
    bad = [c for c in {c.upper() for c in CVE_RE.findall(text)} if c not in facts_u]
    allowed = set(NUM_RE.findall(CVE_RE.sub(" ", facts))) | SMALL_INTS
    stripped = CVE_RE.sub(" ", text)
    bad += [n for n in set(NUM_RE.findall(stripped)) if n not in allowed]
    return not bad, sorted(bad)


class ToolContext:
    """Implements the report tools over the scan rows, the feed and (optionally) the full dataset."""

    def __init__(self, payload: dict, feed=None, dataset=None):
        self.rows = {r["cve"]: r for r in payload["rows"]}
        self.feed, self.dataset = feed, dataset

    def call(self, name: str, args: dict) -> dict:
        cve = str(args.get("cve_id", "")).upper()
        if cve not in self.rows:
            return {"error": f"{cve} is not in this scan"}
        if name == "get_cve":
            rec = self.feed.get(cve) if self.feed is not None else None
            r = self.rows[cve]
            return dict(cve=cve, description=(rec or {}).get("description", "")[:600], cna_vector=r["cna_vector"],
                        nvd_vector=r["nvd_vector"], predicted_vector=r["predicted_vector"])
        if name == "explain_flag":
            model = self.feed.model() if self.feed is not None else None
            rec = self.feed.get(cve) if self.feed is not None else None
            if model is None or rec is None or self.rows[cve]["p_bump"] is None:
                return {"error": "no model explanation available"}
            import pandas as pd
            return {"method": "occlusion vs training median", "top": model.explain(pd.DataFrame([rec]))}
        if name == "similar_cves":
            if self.dataset is None or self.feed is None or (rec := self.feed.get(cve)) is None:
                return {"similar": []}
            d = self.dataset
            cwe = (rec.get("cna_cwe") or "").split(";")[0]
            m = (d.cna == rec["cna"]) & (d.cna_cwe.fillna("").str.split(";").str[0] == cwe) & d.label_vector.notna()
            k = min(int(args.get("k", 3) or 3), 5)
            sims = d[m].sort_values("published", ascending=False).head(k)
            return {"similar": [dict(cve=s.cve, cna_vector=s.cna_vector, nvd_final_vector=s.label_vector,
                                     nvd_raised_severity=bool(s.bump_up)) for s in sims.itertuples()]}
        return {"error": f"unknown tool {name}"}


def _client():
    from openai import OpenAI
    return OpenAI(base_url=config.ULTRAMARINE_BASE_URL, api_key=config.PAPERINSTRUMENTS_API_KEY)


def _llm_report(payload: dict, client, tools: ToolContext | None, max_rounds: int = 4) -> tuple[str, str, dict]:
    """One agent run. Returns (markdown, facts_json, usage_totals)."""
    facts = [json.dumps(payload)]
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": facts[0]}]
    use = dict(input_tokens=0, output_tokens=0, cached_input_tokens=0, calls=0)
    for _ in range(max_rounds + 1):
        kw = dict(tools=TOOLS) if tools is not None else {}
        resp = client.chat.completions.create(model=config.ULTRAMARINE_MODEL, messages=msgs,
                                              reasoning_effort="low", temperature=1, top_p=0.95, **kw)
        u = resp.usage
        use["calls"] += 1
        use["input_tokens"] += u.prompt_tokens
        use["output_tokens"] += u.completion_tokens
        details = getattr(u, "prompt_tokens_details", None)
        use["cached_input_tokens"] += (getattr(details, "cached_tokens", 0) or 0) if details else 0
        choice = resp.choices[0]
        calls = choice.message.tool_calls or []
        if not calls or choice.finish_reason == "length":
            return choice.message.content or "", "\n".join(facts), use
        msgs.append({"role": "assistant", "content": choice.message.content or "",
                     "tool_calls": [c.model_dump() for c in calls]})
        for c in calls:
            try:
                result = tools.call(c.function.name, json.loads(c.function.arguments or "{}"))
            except Exception as e:  # tool errors go back to the model, never crash the report
                result = {"error": str(e)}
            facts.append(json.dumps(result))
            msgs.append({"role": "tool", "tool_call_id": c.id, "content": facts[-1]})
    return "", "\n".join(facts), use


def write_report(payload: dict, use_llm: bool | None = None, client=None, tools: ToolContext | None = None) -> dict:
    """Returns {report_md, writer, guardrail_ok, attempts, usd}. Template if no key, or after 2 failures."""
    if use_llm is None:
        use_llm = bool(config.PAPERINSTRUMENTS_API_KEY) or client is not None
    if not use_llm or not payload["rows"]:
        return dict(report_md=template_report(payload), writer="template", guardrail_ok=None, attempts=0, usd=0.0)
    client = client or _client()
    usd, problems = 0.0, []
    for attempt in (1, 2):
        t0 = time.time()
        try:
            md, facts, use = _llm_report(payload, client, tools)
        except Exception as e:
            problems = [f"api error: {type(e).__name__}"]
            continue
        ok, problems = guardrail(md, facts)
        ok = ok and bool(md.strip())
        cost = costs.dollars(use["input_tokens"], use["output_tokens"], use["cached_input_tokens"])
        usd += cost
        costs.log("ultramarine", config.ULTRAMARINE_MODEL, use["input_tokens"], use["output_tokens"],
                  time.time() - t0, cost, cached_input_tokens=use["cached_input_tokens"], api_calls=use["calls"],
                  task="report", attempt=attempt, guardrail_ok=ok, guardrail_problems=problems[:10])
        if ok:
            return dict(report_md=md, writer="ultramarine", guardrail_ok=True, attempts=attempt, usd=usd)
    return dict(report_md=template_report(payload), writer="template-fallback", guardrail_ok=False,
                attempts=2, usd=usd, guardrail_problems=problems[:10])
