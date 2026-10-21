"""Token / latency / dollar logging for every paid call -> results/costs.jsonl (SPEC §11.4)."""
import json
import time
from pathlib import Path

from .config import RESULTS, ULTRAMARINE_PRICE

COSTS_FILE = RESULTS / "costs.jsonl"


def dollars(input_tokens: int, output_tokens: int, cached_input_tokens: int = 0,
            price: dict = ULTRAMARINE_PRICE) -> float:
    uncached = max(input_tokens - cached_input_tokens, 0)
    return (uncached * price["input"] + cached_input_tokens * price["cached_input"]
            + output_tokens * price["output"]) / 1e6


def log(service: str, model: str, input_tokens: int, output_tokens: int, latency_s: float,
        usd: float, path: Path | None = None, **extra) -> dict:
    path = Path(path or COSTS_FILE)
    rec = dict(ts=time.strftime("%Y-%m-%dT%H:%M:%S"), service=service, model=model,
               input_tokens=input_tokens, output_tokens=output_tokens,
               latency_s=round(latency_s, 3), usd=round(usd, 6), **extra)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def summarise(path: Path | None = None) -> dict:
    """Totals per (service, model) plus the guardrail pass rate where logged."""
    out: dict = {}
    path = Path(path or COSTS_FILE)
    if not path.exists():
        return out
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        k = f"{r['service']}/{r['model']}"
        s = out.setdefault(k, dict(calls=0, input_tokens=0, output_tokens=0, usd=0.0, latency_s=0.0,
                                   guardrail_pass=0, guardrail_checked=0))
        s["calls"] += 1
        s["input_tokens"] += r["input_tokens"]
        s["output_tokens"] += r["output_tokens"]
        s["usd"] += r["usd"]
        s["latency_s"] += r["latency_s"]
        if "guardrail_ok" in r:
            s["guardrail_checked"] += 1
            s["guardrail_pass"] += int(r["guardrail_ok"])
    for s in out.values():
        s["mean_latency_s"] = s["latency_s"] / s["calls"]
        s["usd_per_call"] = s["usd"] / s["calls"]
    return out
