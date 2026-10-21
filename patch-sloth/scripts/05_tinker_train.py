"""Task A: LoRA SFT of Qwen3-8B on Tinker, then greedy eval on val/test.
Needs: pip install tinker tinker-cookbook ; export TINKER_API_KEY=...
NOTE: written against the Tinker low-level API (ServiceClient / forward_backward / optim_step /
sampling client). Check names against the current docs before the first run - run with --dry_run first.
Usage: python scripts/05_tinker_train.py --epochs 1 --eval_n 8000
"""
import argparse
import json
import random

import tinker
from tinker import types
from tinker_cookbook import renderers
from tinker_cookbook.tokenizer_utils import get_tokenizer

ap = argparse.ArgumentParser()
ap.add_argument("--base", default="Qwen/Qwen3-8B")
ap.add_argument("--rank", type=int, default=32)
ap.add_argument("--lr", type=float, default=2e-4)
ap.add_argument("--batch", type=int, default=64)
ap.add_argument("--epochs", type=int, default=1)
ap.add_argument("--eval_n", type=int, default=8000, help="examples per eval split (cost control)")
ap.add_argument("--dry_run", action="store_true")
a = ap.parse_args()

tok = get_tokenizer(a.base)
renderer = renderers.get_renderer("qwen3", tok)  # chat template matching the base model

def to_datum(msgs):
    tokens, weights = renderer.build_supervised_example(msgs)  # weights=1 only on assistant tokens
    tokens, weights = list(tokens), list(weights)
    return types.Datum(model_input=types.ModelInput.from_ints(tokens[:-1]),
                       loss_fn_inputs=dict(weights=weights[1:], target_tokens=tokens[1:]))

train = [json.loads(l) for l in open("data/tinker/train.jsonl")]
if a.dry_run:
    train = train[:128]
svc = tinker.ServiceClient()
tc = svc.create_lora_training_client(base_model=a.base, rank=a.rank)
log = open("results/tinker_train_log.jsonl", "a")
step = 0
for ep in range(a.epochs):
    random.Random(ep).shuffle(train)
    for i in range(0, len(train), a.batch):
        batch = [to_datum(x["messages"]) for x in train[i:i + a.batch]]
        fb = tc.forward_backward(batch, "cross_entropy")
        opt = tc.optim_step(types.AdamParams(learning_rate=a.lr * (1 - i / len(train))))
        r = fb.result(); opt.result()
        step += 1
        if step % 10 == 0:
            loss = sum(float(x) for x in r.metrics.values()) if hasattr(r, "metrics") else None
            log.write(json.dumps({"step": step, "epoch": ep, "metrics": getattr(r, "metrics", {})}, default=str) + "\n"); log.flush()
            print("step", step, getattr(r, "metrics", ""))

sampler = tc.save_weights_and_get_sampling_client(name="patch-sloth-taskA")
params = types.SamplingParams(max_tokens=48, temperature=0.0, stop=renderer.get_stop_sequences())

def predict(split, client, tag):
    rows = [json.loads(l) for l in open(f"data/tinker/{split}.jsonl")]
    rows = rows[: (64 if a.dry_run else a.eval_n)]
    futures = []
    for x in rows:
        prompt = renderer.build_generation_prompt(x["messages"][:-1])
        futures.append((x["cve"], client.sample(prompt=prompt, num_samples=1, sampling_params=params)))
    with open(f"results/llm_preds_{tag}_{split}.jsonl", "w") as f:
        for cve, fut in futures:
            seq = fut.result().sequences[0].tokens
            f.write(json.dumps({"cve": cve, "text": tok.decode(seq)}) + "\n")

base_sampler = svc.create_sampling_client(base_model=a.base)  # zero-shot baseline, same prompt
for split in ["val", "test"]:
    predict(split, sampler, "ft")
    predict(split, base_sampler, "base")
print("saved preds -> results/llm_preds_*.jsonl ; now run scripts/06_eval_llm.py")
