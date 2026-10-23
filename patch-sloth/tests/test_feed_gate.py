"""score_rows with a stacked model: rows without an LLM vector go to the tabular model (never "LLM agreed"),
and the gate keeps the CNA vector unless the stacked p_bump >= gate_t."""
from types import SimpleNamespace

import numpy as np
import pandas as pd

from patchsloth.feed import score_rows

CNA = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
LLM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class Fake:
    def __init__(self, name, with_llm, p, gate=None):
        self.name, self.fb, self.p, self.gate_t = name, SimpleNamespace(with_llm=with_llm), p, gate
        self.bands, self.seen = None, []

    def predict(self, d):
        self.seen.append(list(d.cve))
        if self.fb.with_llm:
            assert d.llm_vector.notna().all()
        return np.array([self.p[c] for c in d.cve])


class Backend:
    name = "tinker-precomputed"

    def predict_vectors(self, rows):
        return [{"CVE-1": LLM, "CVE-2": LLM}.get(r.cve) for r in rows]


def test_stacked_gated_and_tabular_split():
    df = pd.DataFrame({"cve": ["CVE-1", "CVE-2", "CVE-3"], "status": ["Deferred"] * 3, "cna_vector": [CNA] * 3})
    stack = Fake("stack", True, {"CVE-1": 0.9, "CVE-2": 0.1}, gate=0.5)
    tab = Fake("tabpfn", False, {"CVE-3": 0.4})
    out = score_rows(df, stack, Backend(), tab).set_index("cve")
    assert stack.seen == [["CVE-1", "CVE-2"]] and tab.seen == [["CVE-3"]]
    assert out.predicted_vector.to_dict() == {"CVE-1": LLM, "CVE-2": CNA, "CVE-3": CNA}  # gated; no LLM for 3
    assert out.bump_model.to_dict() == {"CVE-1": "stack", "CVE-2": "stack", "CVE-3": "tabpfn"}
    assert out.p_bump.round(2).to_dict() == {"CVE-1": 0.9, "CVE-2": 0.1, "CVE-3": 0.4}
