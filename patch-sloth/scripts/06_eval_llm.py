"""Score Tinker base vs fine-tuned predictions with the same metrics as the baselines.
Unparseable outputs fall back to the CNA vector and are counted (JSON validity is reported).
Also writes results/llm_vectors_{tag}_{split}.json, including ft stack_train for 07 --with_llm.
Usage: python scripts/06_eval_llm.py [--dry_run]"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.llm.prompt import parse_output  # noqa: E402
from patchsloth.metrics import evaluate, mcnemar  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--dry_run", action="store_true")
TAG = "_dryrun" if ap.parse_args().dry_run else ""

df = pd.read_parquet("data/cves.parquet").set_index("cve")
for split in ["val", "test", "stack_train"]:
    res = {}
    for tag in ["base", "ft", "ultramarine"]:
        p = Path(f"results/llm_preds_{tag}_{split}{TAG}.jsonl")
        if not p.exists():
            continue
        preds = [json.loads(line) for line in open(p, encoding="utf-8")]
        d = df.loc[[x["cve"] for x in preds]]
        parsed = [parse_output(x["text"], cna) for x, cna in zip(preds, d.cna_vector)]
        vecs = [v for v, _ in parsed]
        r, ok = evaluate(d, vecs, n_boot=200 if TAG else 1000)
        r["json_valid"] = sum(ok_ for _, ok_ in parsed) / len(preds)
        r["n"] = len(preds)
        _, ok_copy = evaluate(d, list(d.cna_vector), n_boot=0)
        r["mcnemar_vs_copy_cna_severity"] = mcnemar(ok, ok_copy)
        res[tag] = r
        Path(f"results/llm_vectors_{tag}_{split}{TAG}.json").write_text(json.dumps(dict(zip(d.index, vecs))))
    if res:
        json.dump(res, open(f"results/llm_{split}{TAG}.json", "w"), indent=1, default=float)
        print(split, pd.DataFrame(res).T[["n", "json_valid", "severity_acc", "exact_vector", "bump_precision",
                                          "bump_recall", "bump_f1"]].round(3).to_string())
