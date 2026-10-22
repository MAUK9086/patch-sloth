"""Frontier zero-shot baseline (SPEC §10): Ultramarine 1 Flash predicts the NVD-style vector for a fixed
1,000-row random test subsample, with the SAME system prompt and user turn as the fine-tune (llm/prompt.py).
The subsample is saved to results/frontier_subsample.json so every model can be compared on the same rows.
Reasoning cannot be disabled on Ultramarine (billed as output), so cost is measured with a pilot first.

Usage:
  python scripts/09_frontier_baseline.py --pilot 10    # run 10 rows, print the projected cost for --n
  python scripts/09_frontier_baseline.py               # full run (resumes; skips CVEs already predicted)
Then: python scripts/06_eval_llm.py  (scores tag "ultramarine" on split "test")"""
import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import config, costs  # noqa: E402
from patchsloth.llm.prompt import messages  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--n", type=int, default=1000)
ap.add_argument("--pilot", type=int, default=0, help="only run this many rows and project the cost")
ap.add_argument("--concurrency", type=int, default=2)
ap.add_argument("--reasoning_effort", default="low", choices=["low", "high", "max"])
ap.add_argument("--max_completion_tokens", type=int, default=2048, help="caps reasoning + answer per call")
ap.add_argument("--budget", type=float, default=2.0, help="abort when logged spend for this run exceeds this")
a = ap.parse_args()

SUB = Path("results/frontier_subsample.json")
OUT = Path("results/llm_preds_ultramarine_test.jsonl")
if SUB.exists():
    cves = json.loads(SUB.read_text())["cves"]
else:
    df = pd.read_parquet("data/cves.parquet")
    cves = sorted(df[df.split == "test"].sample(n=a.n, random_state=0).cve)
    SUB.write_text(json.dumps({"seed": 0, "split": "test", "n": len(cves), "cves": cves}, indent=1))
df = pd.read_parquet("data/cves.parquet").set_index("cve").loc[cves].reset_index()
done = {json.loads(line)["cve"] for line in open(OUT, encoding="utf-8")} if OUT.exists() else set()
todo = [r for r in df.itertuples() if r.cve not in done]
if a.pilot:
    todo = todo[:a.pilot]
print(f"{len(done)} done, {len(todo)} to run (concurrency {a.concurrency}, reasoning_effort {a.reasoning_effort})")
if not config.PAPERINSTRUMENTS_API_KEY:
    sys.exit("PAPERINSTRUMENTS_API_KEY is not set")

from openai import OpenAI  # noqa: E402

client = OpenAI(base_url=config.ULTRAMARINE_BASE_URL, api_key=config.PAPERINSTRUMENTS_API_KEY, max_retries=4)
spent = {"usd": 0.0, "in": 0, "out": 0, "reasoning": 0, "cached": 0, "n": 0}


def call(r):
    t0 = time.time()
    resp = client.chat.completions.create(model=config.ULTRAMARINE_MODEL, messages=messages(r),
                                          reasoning_effort=a.reasoning_effort,
                                          max_completion_tokens=a.max_completion_tokens)
    u = resp.usage
    cached = getattr(getattr(u, "prompt_tokens_details", None), "cached_tokens", 0) or 0
    reasoning = getattr(getattr(u, "completion_tokens_details", None), "reasoning_tokens", 0) or 0
    usd = costs.dollars(u.prompt_tokens, u.completion_tokens, cached)
    costs.log("ultramarine", config.ULTRAMARINE_MODEL, u.prompt_tokens, u.completion_tokens, time.time() - t0, usd,
              cached_input_tokens=cached, reasoning_tokens=reasoning, task="frontier_baseline" + (
                  "_pilot" if a.pilot else ""), cve=r.cve, finish_reason=resp.choices[0].finish_reason)
    return r.cve, resp.choices[0].message.content or "", u.prompt_tokens, u.completion_tokens, reasoning, cached, usd


with open(OUT, "a", encoding="utf-8") as f, ThreadPoolExecutor(a.concurrency) as pool:
    for cve, text, pin, pout, reas, cached, usd in pool.map(call, todo):
        f.write(json.dumps({"cve": cve, "text": text}) + "\n")
        f.flush()
        spent.update(usd=spent["usd"] + usd, n=spent["n"] + 1, cached=spent["cached"] + cached)
        spent["in"] += pin
        spent["out"] += pout
        spent["reasoning"] += reas
        if spent["n"] % 50 == 0:
            print(f"{spent['n']}/{len(todo)} ${spent['usd']:.4f}")
        if spent["usd"] > a.budget:
            pool.shutdown(cancel_futures=True)
            sys.exit(f"ABORT: spent ${spent['usd']:.3f} > budget ${a.budget}")

n = max(spent["n"], 1)
print("SPENT", json.dumps({k: round(v, 5) if isinstance(v, float) else v for k, v in spent.items()}))
print(f"per call: in {spent['in'] / n:.0f}, out {spent['out'] / n:.0f} (reasoning {spent['reasoning'] / n:.0f}), "
      f"${spent['usd'] / n:.6f}")
if a.pilot:
    print(f"PROJECTED for {len(cves)} rows: ${spent['usd'] / n * len(cves):.3f}")
