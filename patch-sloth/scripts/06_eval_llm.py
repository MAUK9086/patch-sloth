"""Score Tinker base vs fine-tuned predictions with the same metrics as the baselines.
Unparseable outputs fall back to the CNA vector and are counted (JSON validity is reported)."""
import json, sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchsloth.cvss import METRICS, VALUES, parse, to_vector
from patchsloth.metrics import evaluate, mcnemar

df = pd.read_parquet("data/cves.parquet").set_index("cve")
for split in ["val", "test"]:
    res = {}
    for tag in ["base", "ft"]:
        p = Path(f"results/llm_preds_{tag}_{split}.jsonl")
        if not p.exists(): continue
        preds = [json.loads(l) for l in open(p)]
        d = df.loc[[x["cve"] for x in preds]]
        vecs, valid = [], 0
        for x, cna in zip(preds, d.cna_vector):
            try:
                j = json.loads(x["text"].strip().split("\n")[0])
                assert all(j[k] in VALUES[k] for k in METRICS); vecs.append(to_vector(j)); valid += 1
            except Exception:
                vecs.append(cna)
        r, ok = evaluate(d, vecs); r["json_valid"] = valid / len(preds)
        _, ok_copy = evaluate(d, list(d.cna_vector), n_boot=0)
        r["mcnemar_vs_copy_cna_severity"] = mcnemar(ok, ok_copy)
        res[tag] = r
        Path(f"results/llm_vectors_{tag}_{split}.json").write_text(json.dumps(dict(zip(d.index, vecs))))
    json.dump(res, open(f"results/llm_{split}.json", "w"), indent=1, default=float)
    print(split, pd.DataFrame(res).T[["json_valid", "severity_acc", "exact_vector", "bump_precision", "bump_recall", "bump_f1"]].round(3))
