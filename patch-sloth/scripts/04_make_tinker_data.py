"""Build chat-format JSONL for Tinker SFT (Task A). Target = NVD-final vector as compact JSON.
Keeps prompts short (~250 tokens) so Qwen3-8B training stays inside the $10 credit.
Usage: python scripts/04_make_tinker_data.py --n_train 30000"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.llm.prompt import SYSTEM, prompt, target  # noqa: E402  (shared with serving)

ap = argparse.ArgumentParser(); ap.add_argument("--n_train", type=int, default=30000); a = ap.parse_args()
df = pd.read_parquet("data/cves.parquet")
out = Path("data/tinker"); out.mkdir(parents=True, exist_ok=True)
for split in ["train", "val", "test"]:
    d = df[df.split == split]
    if split == "train":
        # oversample recent + changed examples so the model sees enough disagreements
        recent = d[d.published >= "2024-01-01"]
        d = pd.concat([recent, d.drop(recent.index).sample(frac=0.3, random_state=0)])
        d = d.sample(n=min(a.n_train, len(d)), random_state=0)
    with open(out / f"{split}.jsonl", "w") as f:
        for r in d.itertuples():
            f.write(json.dumps({"cve": r.cve, "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt(r)},
                {"role": "assistant", "content": target(r)}]}) + "\n")
    print(split, len(d))
# rough token estimate: 4 chars/token
n = sum(len(l) for l in open(out / "train.jsonl")) / 4
print(f"~{n/1e6:.1f}M train tokens/epoch -> ~${n/1e6*0.44:.2f} per epoch on Qwen3-8B at $0.44/M")
