"""Tabular features for the bump classifier, shared by training (scripts/07) and serving (feed, api).

Leakage rules (SPEC §8.4): every feature must be computable for a Deferred CVE on the day it was
published. FeatureBuilder only ever reads INPUT_COLUMNS; tests/test_features.py checks that none of
them is in FORBIDDEN. TF-IDF/SVD and the top-k category vocabularies are fitted on train only.
"""
import numpy as np
import pandas as pd
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer

from .cvss import METRICS, VALUES, base_score, parse

# NVD-side or post-analysis information, plus the labels themselves
FORBIDDEN = {
    "status", "nvd_vector", "nvd_cwe", "nvd_ref_tags", "configurations", "has_cpe", "kev_date",
    "label_vector", "label_score", "label_sev", "bump_up", "vector_changed", "nvd_own", "split",
}
INPUT_COLUMNS = ["cna", "cna_vector", "cna_cwe", "score_source", "description", "n_refs",
                 "ref_github", "ref_exploitdb", "has_v40"]
LLM_INPUT = "llm_vector"  # optional, only with with_llm=True; must come from out-of-SFT predictions


def _first_cwe(s: pd.Series) -> pd.Series:
    return s.fillna("").astype(str).str.split(";").str[0]


class FeatureBuilder:
    """fit(train_df) then transform(any_df). transform is row-wise, so train/serve features match."""

    def __init__(self, top_k: int = 40, n_text: int = 32, with_llm: bool = False, min_df: int = 5):
        self.top_k, self.n_text, self.with_llm, self.min_df = top_k, n_text, with_llm, min_df

    def fit(self, train: pd.DataFrame) -> "FeatureBuilder":
        top_cna = list(train.cna.value_counts().index[:self.top_k])
        top_cwe = list(_first_cwe(train.cna_cwe).value_counts().index[:self.top_k])
        # sorted vocab with "other" reproduces the pd.Categorical codes the original 07 used
        self.cna_vocab = sorted(set(top_cna) | {"other"})
        self.cwe_vocab = sorted(set(top_cwe) | {"other"})
        self.tfidf = TfidfVectorizer(min_df=self.min_df, max_features=30000, sublinear_tf=True).fit(train.description)
        self.svd = TruncatedSVD(self.n_text, random_state=0).fit(self.tfidf.transform(train.description))
        return self

    @property
    def feature_names(self) -> list[str]:
        names = [f"cna_{k}" for k in METRICS] + ["cna_score", "cna_id", "cwe", "adp_scored", "n_refs",
                                                 "ref_github", "ref_exploitdb", "desc_len", "has_v40"]
        names += [f"txt{i}" for i in range(self.n_text)]
        if self.with_llm:
            names += ["llm_score_delta"] + [f"llm_changed_{k}" for k in METRICS]
        return names

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        d = df[INPUT_COLUMNS + ([LLM_INPUT] if self.with_llm and LLM_INPUT in df else [])]
        X = pd.DataFrame(index=d.index)
        cna = d.cna_vector.map(lambda v: parse(v) if isinstance(v, str) else None)
        for k in METRICS:
            X[f"cna_{k}"] = cna.map(lambda m, k=k: VALUES[k].index(m[k]) if m else np.nan)
        cna_score = cna.map(lambda m: base_score(m) if m else np.nan)
        X["cna_score"] = cna_score
        cna_id = d.cna.where(d.cna.isin(self.cna_vocab), "other")
        X["cna_id"] = cna_id.map(self.cna_vocab.index)
        cwe = _first_cwe(d.cna_cwe)
        X["cwe"] = cwe.where(cwe.isin(self.cwe_vocab), "other").map(self.cwe_vocab.index)
        X["adp_scored"] = (d.score_source == "CISA-ADP").astype(int)
        X["n_refs"] = d.n_refs
        X["ref_github"] = d.ref_github.astype(int)
        X["ref_exploitdb"] = d.ref_exploitdb.astype(int)
        desc = d.description.fillna("")
        X["desc_len"] = desc.str.len()
        X["has_v40"] = d.has_v40.astype(int)
        emb = self.svd.transform(self.tfidf.transform(desc))
        for i in range(emb.shape[1]):
            X[f"txt{i}"] = emb[:, i]
        if self.with_llm:
            llm = d[LLM_INPUT].map(lambda v: parse(v) if isinstance(v, str) else None) \
                if LLM_INPUT in d else pd.Series(None, index=d.index, dtype=object)
            X["llm_score_delta"] = [base_score(m) - s if m and c else np.nan
                                    for m, c, s in zip(llm, cna, cna_score)]
            for k in METRICS:
                X[f"llm_changed_{k}"] = [float(m[k] != c[k]) if m and c else np.nan for m, c in zip(llm, cna)]
        return X[self.feature_names]
