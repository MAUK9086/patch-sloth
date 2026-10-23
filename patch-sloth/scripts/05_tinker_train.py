"""Task A: LoRA SFT of Qwen3-8B on Tinker, then greedy predictions for val/test (ft + base zero-shot)
and stack_train (ft only, out-of-SFT rows for stacking, SPEC §9.2).
API names VERIFIED 2026-10-23 against tinker 0.34.0 / tinker-cookbook 0.5.7 and tinker-docs (see DECISIONS.md).

Every token is counted locally before any paid call; the run aborts if the estimate exceeds --budget.
Usage:
  python scripts/05_tinker_train.py --dry_run          # 128 train examples, 64 eval rows per split
  python scripts/05_tinker_train.py --estimate_only    # exact token counts + projected cost, no API calls
  python scripts/05_tinker_train.py                    # full run: 1 epoch, eval_n=8000, n_stack=10000
  python scripts/05_tinker_train.py --model_path tinker://.../sampler_weights/... --skip_train   # eval only
  python scripts/05_tinker_train.py --resume_state tinker://.../weights/step-200   # resume training
Resumability: save_state (weights + optimizer) every --save_every steps, path logged to results/tinker_ckpt*.jsonl;
--resume_state restarts from it (same data order and LR schedule). Sampling skips CVEs already written,
so re-running with --skip_train after a crash only pays for what is missing.
"""
import argparse
import json
import random
import sys
import time
from concurrent.futures import Future
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth import config, costs  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--base", default=config.BASE_MODEL)
ap.add_argument("--renderer", default=config.TINKER_RENDERER)
ap.add_argument("--rank", type=int, default=32)
ap.add_argument("--lr", type=float, default=2e-4)
ap.add_argument("--batch", type=int, default=64)
ap.add_argument("--epochs", type=int, default=1)
ap.add_argument("--eval_n", type=int, default=8000, help="rows per eval split (val/test are pre-shuffled by 04)")
ap.add_argument("--n_stack", type=int, default=10000, help="stack_train rows to predict with the fine-tuned model")
ap.add_argument("--max_tokens", type=int, default=48, help="fine-tuned model (compact JSON is ~34 tokens)")
ap.add_argument("--base_max_tokens", type=int, default=128,
                help="base zero-shot answers in fenced, pretty-printed JSON (~70 tokens); 48 would truncate it")
ap.add_argument("--concurrency", type=int, default=64, help="sample requests in flight")
ap.add_argument("--budget", type=float, default=config.TINKER_BUDGET_USD)
ap.add_argument("--dry_run", action="store_true")
ap.add_argument("--estimate_only", action="store_true")
ap.add_argument("--skip_train", action="store_true")
ap.add_argument("--model_path", default=None, help="tinker://... sampler weights to evaluate (with --skip_train)")
ap.add_argument("--save_every", type=int, default=100, help="save_state (weights + optimizer) every N steps")
ap.add_argument("--resume_state", default=None, help="tinker://.../weights/step-N saved by --save_every")
a = ap.parse_args()

import tinker  # noqa: E402
from tinker import types  # noqa: E402
from tinker_cookbook import renderers  # noqa: E402
from tinker_cookbook.renderers import TrainOnWhat  # noqa: E402
from tinker_cookbook.supervised.data import conversation_to_datum  # noqa: E402
from tinker_cookbook.tokenizer_utils import get_tokenizer  # noqa: E402

P = config.TINKER_PRICE
TAG = "_dryrun" if a.dry_run else ""
n_train_rows = 128 if a.dry_run else None
n_eval = 64 if a.dry_run else a.eval_n
n_stack = 64 if a.dry_run else a.n_stack

tok = get_tokenizer(a.base)
renderer = renderers.get_renderer(a.renderer, tok)


def load(split, n=None):
    rows = [json.loads(line) for line in open(f"data/tinker/{split}.jsonl", encoding="utf-8")]
    return rows[:n] if n else rows


def to_datum(msgs):
    # loss only on the assistant JSON; per-example mean reduction (cookbook SFT default)
    return conversation_to_datum(msgs, renderer, max_length=None, train_on_what=TrainOnWhat.LAST_ASSISTANT_MESSAGE)


def prompt_of(x):
    return renderer.build_generation_prompt(x["messages"][:-1])


# ---------------------------------------------------------------- exact token accounting
train = load("train", n_train_rows)
data = [to_datum(x["messages"]) for x in train]
train_tokens = sum(d.model_input.length for d in data) * a.epochs
eval_sets = [("val", "ft", n_eval), ("test", "ft", n_eval), ("val", "base", n_eval), ("test", "base", n_eval),
             ("stack_train", "ft", n_stack)]
prompts = {s: [prompt_of(x) for x in load(s, n)] for s, _, n in eval_sets}
prefill_tokens = sum(sum(p.length for p in prompts[s]) for s, _, _ in eval_sets)
n_samples = sum(len(prompts[s]) for s, _, _ in eval_sets)
max_tok = {"ft": a.max_tokens, "base": a.base_max_tokens}
est = dict(train_tokens=train_tokens, prefill_tokens=prefill_tokens, n_samples=n_samples,
           sample_tokens_max=sum(len(prompts[s]) * max_tok[t] for s, t, _ in eval_sets))
est["usd_train"] = train_tokens * P["train"] / 1e6
est["usd_prefill"] = prefill_tokens * P["prefill"] / 1e6  # upper bound: ignores cached-prefill discount
est["usd_sample_max"] = est["sample_tokens_max"] * P["sample"] / 1e6
est["usd_total_max"] = est["usd_train"] + est["usd_prefill"] + est["usd_sample_max"]
print("ESTIMATE", json.dumps({k: round(v, 4) if isinstance(v, float) else v for k, v in est.items()}))
if a.estimate_only:
    sys.exit(0)
if est["usd_total_max"] > a.budget:
    sys.exit(f"ABORT: estimated ${est['usd_total_max']:.2f} > budget ${a.budget:.2f}")

svc = tinker.ServiceClient()
spent = {"train": 0.0, "prefill": 0.0, "sample": 0.0}
run = dict(base=a.base, renderer=a.renderer, rank=a.rank, lr=a.lr, batch=a.batch, epochs=a.epochs,
           n_train=len(train), dry_run=a.dry_run, estimate=est)

# ---------------------------------------------------------------- training
if a.skip_train:
    if not a.model_path:
        sys.exit("--skip_train needs --model_path")
    ft_path = a.model_path
    prev = Path(f"results/tinker_run{TAG}.json")
    if prev.exists():  # keep the training record of the run that produced these weights
        run["training_run"] = json.loads(prev.read_text())
else:
    start = 0
    if a.resume_state:  # new training client from the saved weights + optimizer state
        tc = svc.create_training_client_from_state_with_optimizer(a.resume_state)
        start = int(a.resume_state.rstrip("/").rsplit("step-", 1)[1])
        print(f"resumed from {a.resume_state} at step {start}")
    else:
        tc = svc.create_lora_training_client(base_model=a.base, rank=a.rank, seed=0)
    log = open(f"results/tinker_train_log{TAG}.jsonl", "a", encoding="utf-8")
    ckpt_log = open(f"results/tinker_ckpt{TAG}.jsonl", "a", encoding="utf-8")
    steps_per_epoch = (len(data) + a.batch - 1) // a.batch
    total, step, t0 = steps_per_epoch * a.epochs, 0, time.time()
    for ep in range(a.epochs):
        order = list(range(len(data)))
        random.Random(ep).shuffle(order)  # deterministic, so a resumed run sees the same batches
        for i in range(0, len(order), a.batch):
            if step < start:  # already trained before the checkpoint
                step += 1
                continue
            batch = [data[j] for j in order[i:i + a.batch]]
            lr = a.lr * (1 - step / total)  # linear decay to 0 over the whole run
            fb = tc.forward_backward(batch, "cross_entropy")
            opt = tc.optim_step(types.AdamParams(learning_rate=lr))
            r = fb.result()
            opt.result()
            step += 1
            ntok = sum(d.model_input.length for d in batch)
            spent["train"] += ntok * P["train"] / 1e6
            if step % 10 == 0 or a.dry_run or step == total:
                rec = dict(step=step, epoch=ep, lr=lr, tokens=ntok, metrics=r.metrics, usd_train=spent["train"],
                           elapsed_s=round(time.time() - t0, 1))
                log.write(json.dumps(rec, default=float) + "\n")
                log.flush()
                print("step", step, "/", total, r.metrics, f"${spent['train']:.3f}", flush=True)
            if a.save_every and step % a.save_every == 0 and step < total:
                path = tc.save_state(f"step-{step}", ttl_seconds=14 * 86400).result().path
                ckpt_log.write(json.dumps(dict(step=step, path=path)) + "\n")
                ckpt_log.flush()
                print("checkpoint", path, flush=True)
    trained = round(spent["train"] / P["train"] * 1e6)  # tokens actually trained in this process
    costs.log("tinker", a.base, int(trained), 0, time.time() - t0, spent["train"], task=f"sft{TAG}",
              train_tokens=int(trained), steps=step - start, resumed_from=a.resume_state)
    ft_path = tc.save_weights_for_sampler(name=f"patchsloth-taskA{TAG or '-final'}").result().path
    print("saved sampler weights:", ft_path)
run["ft_path"] = ft_path
Path(f"results/tinker_run{TAG}.json").write_text(json.dumps(run, indent=1, default=float))

# ---------------------------------------------------------------- sampling
params = {t: types.SamplingParams(max_tokens=m, temperature=0.0, stop=renderer.get_stop_sequences())
          for t, m in max_tok.items()}
clients = {"ft": svc.create_sampling_client(model_path=ft_path),
           "base": svc.create_sampling_client(base_model=a.base)}  # zero-shot baseline, same prompt + renderer


def predict(split, tag, n):
    """Appends each prediction as it completes and skips CVEs already in the file (resumable)."""
    rows = load(split, n)
    path = Path(f"results/llm_preds_{tag}_{split}{TAG}.jsonl")
    done = {json.loads(line)["cve"] for line in open(path, encoding="utf-8")} if path.exists() else set()
    todo = [i for i, x in enumerate(rows) if x["cve"] not in done]
    t0 = time.time()
    pre = cached = gen = 0
    inflight: list[tuple[int, Future]] = []
    f = open(path, "a", encoding="utf-8")

    def drain(k):
        nonlocal pre, cached, gen
        while len(inflight) > k:
            i, fut = inflight.pop(0)
            res = fut.result()
            seq = res.sequences[0]
            f.write(json.dumps({"cve": rows[i]["cve"], "text": tok.decode(seq.tokens)}) + "\n")
            pre += prompts[split][i].length
            cached += getattr(res, "prompt_cache_hit_tokens", 0) or 0
            gen += len(seq.tokens)
        f.flush()

    for i in todo:
        inflight.append((i, clients[tag].sample(prompt=prompts[split][i], num_samples=1, sampling_params=params[tag])))
        drain(a.concurrency)
    drain(0)
    f.close()
    usd_pre = ((pre - cached) * P["prefill"] + cached * P["prefill_cached"]) / 1e6
    usd_gen = gen * P["sample"] / 1e6
    spent["prefill"] += usd_pre
    spent["sample"] += usd_gen
    costs.log("tinker", a.base, pre, gen, time.time() - t0, usd_pre + usd_gen, task=f"sample_{tag}_{split}{TAG}",
              cached_input_tokens=cached, n=len(todo), skipped=len(done))
    print(f"{tag} {split}: n={len(todo)} (skipped {len(done)} done) prefill={pre} (cached {cached}) gen={gen} "
          f"mean_gen={gen / max(len(todo), 1):.1f} ${usd_pre + usd_gen:.4f}", flush=True)
    return dict(n=len(todo), skipped=len(done), prefill=pre, cached=cached, gen=gen)


run["sampling"] = {f"{tag}_{s}": predict(s, tag, n) for s, tag, n in eval_sets}
run["spent_usd"] = {**spent, "total": sum(spent.values())}
Path(f"results/tinker_run{TAG}.json").write_text(json.dumps(run, indent=1, default=float))
print("SPENT", json.dumps({k: round(v, 4) for k, v in run["spent_usd"].items()}))
print("saved preds -> results/llm_preds_*; now run scripts/06_eval_llm.py" + (" --dry_run" if a.dry_run else ""))
