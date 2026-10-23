"""Fine-tuned Qwen3-8B (Tinker) vectors for every unanalysed CVE in the serving data, so the feed can use the
stacked/gated system (SPEC §9.2). Same prompt (patchsloth/llm/prompt.py) and renderer as training and 05's sampling:
greedy, max_tokens 48. Approved by the human on 2026-10-23: ~$2.6, HARD STOP at $3.5.

Spend control: every prompt is tokenised locally first and the uncached worst case is printed. While sampling,
`spent` adds the measured cost of each finished request (cache hits at the cached price), and no new request is sent
once spent + the worst case of the requests in flight + the next one would exceed --hard_stop. Rows go newest first,
so a stop leaves the oldest CVEs unscored. Resumable: CVEs already in the output file are skipped and not paid twice.
Needs TINKER_API_KEY (in .env). Usage: python scripts/16_tinker_unanalysed.py [--estimate_only] [--limit N]"""
import argparse
import json
import sys
import time
from concurrent.futures import Future
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import config, costs  # noqa: E402
from patchsloth.llm.prompt import messages, parse_output  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--model_path", default=json.loads(Path("results/tinker_run.json").read_text())["ft_path"])
ap.add_argument("--hard_stop", type=float, default=3.5)
ap.add_argument("--max_tokens", type=int, default=48)
ap.add_argument("--concurrency", type=int, default=64)
ap.add_argument("--limit", type=int, default=None, help="only the N newest rows (smoke test)")
ap.add_argument("--estimate_only", action="store_true")
a = ap.parse_args()
load_dotenv()

from tinker_cookbook import renderers  # noqa: E402
from tinker_cookbook.tokenizer_utils import get_tokenizer  # noqa: E402

P = config.TINKER_PRICE
OUT = Path("results/llm_preds_ft_unanalysed.jsonl")
df = pd.read_parquet(config.CVES_PARQUET)
df = df[df.status.isin(config.UNANALYSED_STATUSES) & df.cna_vector.map(lambda v: isinstance(v, str))].copy()
df["description"] = df.description.fillna("")
df = df.sort_values(["published", "cve"], ascending=False)
if a.limit:
    df = df.head(a.limit)
done = {json.loads(line)["cve"] for line in open(OUT, encoding="utf-8")} if OUT.exists() else set()
todo = df[~df.cve.isin(done)]

tok = get_tokenizer(config.BASE_MODEL)
renderer = renderers.get_renderer(config.TINKER_RENDERER, tok)
prompts = [renderer.build_generation_prompt(messages(r)) for r in todo.itertuples()]
pre_tokens = sum(p.length for p in prompts)
worst = (pre_tokens * P["prefill"] + len(prompts) * a.max_tokens * P["sample"]) / 1e6
print(f"ESTIMATE rows={len(todo)} (skipping {len(done)} done) prefill_tokens={pre_tokens} "
      f"worst_case_uncached=${worst:.3f} hard_stop=${a.hard_stop:.2f}", flush=True)
if a.estimate_only or not len(todo):
    sys.exit(0)

import tinker  # noqa: E402
from tinker import types  # noqa: E402

client = tinker.ServiceClient().create_sampling_client(model_path=a.model_path)
params = types.SamplingParams(max_tokens=a.max_tokens, temperature=0.0, stop=renderer.get_stop_sequences())
cves = list(todo.cve)
spent = 0.0
pre = cached = gen = n_done = 0
inflight: list[tuple[int, Future]] = []
t0 = time.time()
f = open(OUT, "a", encoding="utf-8")


def worst_cost(i):
    return (prompts[i].length * P["prefill"] + a.max_tokens * P["sample"]) / 1e6


def drain(k):
    global spent, pre, cached, gen, n_done
    while len(inflight) > k:
        i, fut = inflight.pop(0)
        res = fut.result()
        seq = res.sequences[0]
        f.write(json.dumps({"cve": cves[i], "text": tok.decode(seq.tokens)}) + "\n")
        hit = getattr(res, "prompt_cache_hit_tokens", 0) or 0
        spent += ((prompts[i].length - hit) * P["prefill"] + hit * P["prefill_cached"] + len(seq.tokens) * P["sample"]) / 1e6
        pre, cached, gen, n_done = pre + prompts[i].length, cached + hit, gen + len(seq.tokens), n_done + 1
    f.flush()


stopped = False
for i in range(len(prompts)):
    if spent + sum(worst_cost(j) for j, _ in inflight) + worst_cost(i) > a.hard_stop:
        stopped = True
        print(f"HARD STOP: ${spent:.3f} spent, {len(prompts) - i} rows left unscored", flush=True)
        break
    inflight.append((i, client.sample(prompt=prompts[i], num_samples=1, sampling_params=params)))
    drain(a.concurrency)
    if n_done and n_done % 5000 < 1 and inflight:
        print(f"{n_done}/{len(prompts)} ${spent:.3f}", flush=True)
drain(0)
f.close()
costs.log("tinker", config.BASE_MODEL, pre, gen, time.time() - t0, spent, task="sample_ft_unanalysed",
          cached_input_tokens=cached, n=n_done, skipped=len(done), hard_stop=a.hard_stop, stopped=stopped)
print(f"DONE n={n_done} prefill={pre} (cached {cached}) gen={gen} spent=${spent:.4f} stopped={stopped}", flush=True)

# parsed vectors for the feed (parse failures fall back to the CNA vector and are counted, as in 06)
rows = [json.loads(line) for line in open(OUT, encoding="utf-8")]
cna = dict(zip(df.cve, df.cna_vector))
parsed = {r["cve"]: parse_output(r["text"], cna.get(r["cve"])) for r in rows}
Path("results/llm_vectors_ft_unanalysed.json").write_text(json.dumps({c: v for c, (v, _) in parsed.items()}))
print("json_valid", round(sum(ok for _, ok in parsed.values()) / max(len(parsed), 1), 4), "n", len(parsed))
