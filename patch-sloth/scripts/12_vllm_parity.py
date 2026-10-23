"""vLLM vs Tinker parity for the fine-tuned Qwen3-8B LoRA (SPEC §9.1 export, §12). Two steps:

  export   download the LoRA from Tinker and convert it to PEFT for vLLM (needs TINKER_API_KEY; downloads Qwen3-8B's
           config/weights from Hugging Face to map names). Run on the GPU Droplet, before deploy/vllm-droplet.sh serve.
             python scripts/12_vllm_parity.py export [--out peft_adapter]
  compare  send 300 random 2026 test CVEs (seed 0) to the vLLM server and compare with Tinker's outputs for the same
           CVEs (results/llm_preds_ft_test.jsonl, greedy, max_tokens 48). Writes results/vllm_parity.json.
             python scripts/12_vllm_parity.py compare --base_url http://<droplet>:8000/v1   (VLLM_API_KEY in env)

Two request modes are compared (each on the same 300 rows):
  tokens  /v1/completions with the exact prompt token IDs from Tinker's renderer (qwen3_disable_thinking) and
          <|im_end|> as the stop token: isolates the weights/kernels from prompt formatting.
  chat    /v1/chat/completions with chat_template_kwargs enable_thinking=False: what VLLMBackend (the app) sends.
Greedy decoding on different kernels (Tinker vs vLLM, bf16) can still diverge, so the report gives exact-text match,
parsed-vector match, severity-band match and json_valid, not a pass/fail on exact text alone.
The vLLM parameter names (prompt as token IDs, stop_token_ids, chat_template_kwargs) are checked on 1 row first."""
import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import config  # noqa: E402
from patchsloth.cvss import base_score, parse, severity  # noqa: E402
from patchsloth.llm.prompt import messages, parse_output  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("step", choices=["export", "compare"])
ap.add_argument("--model_path", default=None, help="tinker://... sampler weights (default: results/tinker_run.json)")
ap.add_argument("--out", default="peft_adapter")
ap.add_argument("--base_url", default=config.VLLM_BASE_URL)
ap.add_argument("--n", type=int, default=300)
ap.add_argument("--concurrency", type=int, default=16)
ap.add_argument("--modes", default="tokens,chat")
a = ap.parse_args()
R = Path("results")

if a.step == "export":
    from dotenv import load_dotenv
    load_dotenv()
    from tinker_cookbook import weights
    path = a.model_path or json.loads((R / "tinker_run.json").read_text())["ft_path"]
    print("downloading", path)
    adapter = weights.download(tinker_path=path, output_dir="adapter_raw")
    weights.build_lora_adapter(base_model=config.BASE_MODEL, adapter_path=adapter, output_path=a.out)
    cfg = json.loads((Path(a.out) / "adapter_config.json").read_text())
    print(f"PEFT adapter in {a.out}: rank r={cfg.get('r')} (vllm serve needs --max-lora-rank >= r), "
          f"alpha={cfg.get('lora_alpha')}, targets={cfg.get('target_modules')}")
    sys.exit(0)

# ------------------------------------------------------------------ compare
from openai import OpenAI  # noqa: E402
from tinker_cookbook import renderers  # noqa: E402
from tinker_cookbook.tokenizer_utils import get_tokenizer  # noqa: E402

if not a.base_url:
    sys.exit("set --base_url or VLLM_BASE_URL (e.g. http://<droplet-ip>:8000/v1)")
client = OpenAI(base_url=a.base_url, api_key=config.VLLM_API_KEY or "none", timeout=60, max_retries=2)
tok = get_tokenizer(config.BASE_MODEL)
renderer = renderers.get_renderer(config.TINKER_RENDERER, tok)
stop_ids = renderer.get_stop_sequences()

tinker_text = {}
for line in open(R / "llm_preds_ft_test.jsonl", encoding="utf-8"):
    j = json.loads(line)
    tinker_text[j["cve"]] = j["text"]
df = pd.read_parquet(config.CVES_PARQUET).set_index("cve")
cves = sorted(c for c in tinker_text if c in df.index)
rng = np.random.default_rng(0)
sample = sorted(rng.choice(cves, size=min(a.n, len(cves)), replace=False))
rows = df.loc[sample].reset_index()
rows["description"] = rows.description.fillna("")


def call_tokens(r):
    ids = renderer.build_generation_prompt(messages(r)).to_ints()
    t0 = time.time()
    res = client.completions.create(model=config.VLLM_MODEL, prompt=ids, temperature=0, max_tokens=48,
                                    extra_body={"stop_token_ids": stop_ids, "skip_special_tokens": False})
    return res.choices[0].text, time.time() - t0


def call_chat(r):
    t0 = time.time()
    res = client.chat.completions.create(model=config.VLLM_MODEL, messages=messages(r), temperature=0, max_tokens=48,
                                         extra_body={"chat_template_kwargs": {"enable_thinking": False}})
    return res.choices[0].message.content or "", time.time() - t0


def clean(t):
    return t.replace("<|im_end|>", "").strip()


def band(v):
    return severity(base_score(parse(v))) if isinstance(v, str) else None


modes = {"tokens": call_tokens, "chat": call_chat}
first = next(rows.itertuples())
for m in a.modes.split(","):  # 1-row check of the request parameters before the batch
    print(m, "check:", repr(modes[m](first)[0][:120]))

out = {"n": len(rows),
       "model": config.BASE_MODEL, "lora": "patchsloth", "data_as_of": (R / "data_as_of.txt").read_text().strip(),
       "tinker_source": "results/llm_preds_ft_test.jsonl (greedy, max_tokens 48)", "modes": {}}
for m in a.modes.split(","):
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=a.concurrency) as ex:
        res = list(ex.map(modes[m], rows.itertuples()))
    wall = time.time() - t0
    exact = vec = sev = valid_v = valid_t = 0
    diffs = []
    for r, (text, _) in zip(rows.itertuples(), res):
        tt = tinker_text[r.cve]
        vv, ok_v = parse_output(text, r.cna_vector)
        vt, ok_t = parse_output(tt, r.cna_vector)
        exact += clean(text) == clean(tt)
        vec += vv == vt
        sev += band(vv) == band(vt)
        valid_v += ok_v
        valid_t += ok_t
        if vv != vt and len(diffs) < 10:
            diffs.append(dict(cve=r.cve, tinker=clean(tt), vllm=clean(text)))
    lat = np.array([s for _, s in res])
    n = len(rows)
    out["modes"][m] = dict(exact_text_match=exact / n, vector_match=vec / n, severity_match=sev / n,
                           json_valid_vllm=valid_v / n, json_valid_tinker=valid_t / n,
                           latency_s=dict(p50=float(np.percentile(lat, 50)), p95=float(np.percentile(lat, 95))),
                           wall_s=wall, concurrency=a.concurrency, rows_per_s=n / wall, first_diffs=diffs)
    print(m, json.dumps({k: v for k, v in out["modes"][m].items() if k != "first_diffs"}))
(R / "vllm_parity.json").write_text(json.dumps(out, indent=1))
print("wrote results/vllm_parity.json")
