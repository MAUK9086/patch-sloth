"""Build chat-format JSONL for Tinker SFT (Task A). Target = NVD-final vector as compact JSON.
Keeps prompts short (~250 tokens) so Qwen3-8B training stays inside the $10 credit.
Also reserves `stack_train`: train rows OUTSIDE the SFT set, drawn from the same recency-weighted pool,
for out-of-SFT LLM predictions used to train the stacked bump classifier (SPEC §9.1/§9.2).
val/test are shuffled (seed 0) so that 05's first-eval_n rows are a random subsample.
Usage: python scripts/04_make_tinker_data.py --n_train 30000 --n_stack 10000"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.llm.prompt import SYSTEM, prompt, target  # noqa: E402  (shared with serving)

ap = argparse.ArgumentParser()
ap.add_argument("--n_train", type=int, default=30000)
ap.add_argument("--n_stack", type=int, default=10000)
a = ap.parse_args()
df = pd.read_parquet("data/cves.parquet")
out = Path("data/tinker"); out.mkdir(parents=True, exist_ok=True)

tr = df[df.split == "train"]
# oversample recent + changed examples so the model sees enough disagreements
recent = tr[tr.published >= "2024-01-01"]
pool = pd.concat([recent, tr.drop(recent.index).sample(frac=0.3, random_state=0)]).sample(frac=1, random_state=0)
if len(pool) < a.n_train + a.n_stack:
    sys.exit(f"pool has {len(pool)} rows < n_train + n_stack = {a.n_train + a.n_stack}")
splits = {
    "train": pool.iloc[:a.n_train],
    "stack_train": pool.iloc[a.n_train:a.n_train + a.n_stack],
    "val": df[df.split == "val"].sample(frac=1, random_state=0),
    "test": df[df.split == "test"].sample(frac=1, random_state=0),
}
assert not set(splits["train"].cve) & set(splits["stack_train"].cve), "stack_train overlaps the SFT set"
for split, d in splits.items():
    with open(out / f"{split}.jsonl", "w", encoding="utf-8") as f:
        for r in d.itertuples():
            f.write(json.dumps({"cve": r.cve, "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt(r)},
                {"role": "assistant", "content": target(r)}]}) + "\n")
    print(split, len(d), "bump rate", round(d.bump_up.astype(float).mean(), 3),
          "published", d.published.min(), "->", d.published.max())
# rough token estimate: 4 chars/token (05 --dry_run counts real tokens)
n = sum(len(line) for line in open(out / "train.jsonl", encoding="utf-8")) / 4
print(f"~{n/1e6:.1f}M train tokens/epoch -> ~${n/1e6*0.44:.2f} per epoch on Qwen3-8B at $0.44/M")
