"""Leakage rules (SPEC §8.4) and train/serve feature parity."""
import numpy as np
import pandas as pd
import pytest

from patchsloth.features import FORBIDDEN, INPUT_COLUMNS, FeatureBuilder

WORDS = ("sql injection remote attacker execute arbitrary code cross site scripting buffer overflow "
         "denial service authentication bypass path traversal privilege escalation plugin wordpress").split()
VECS = ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"]


def _df(n=60, seed=0):
    rng = np.random.default_rng(seed)
    return pd.DataFrame(dict(
        cve=[f"CVE-2024-{i}" for i in range(n)],
        cna=rng.choice(["cna-a", "cna-b", "cna-c"], n),
        cna_vector=rng.choice(VECS, n),
        cna_cwe=rng.choice(["CWE-79", "CWE-89;CWE-20", ""], n),
        score_source=rng.choice(["CNA", "CISA-ADP"], n),
        description=[" ".join(rng.choice(WORDS, 12)) for _ in range(n)],
        n_refs=rng.integers(0, 9, n), ref_github=rng.random(n) > .5, ref_exploitdb=rng.random(n) > .8,
        has_v40=rng.random(n) > .5,
        # forbidden columns present on purpose: the builder must not read them
        status="Analyzed", nvd_vector=VECS[0], has_cpe=True, kev_date="2024-01-01", bump_up=True,
    ))


@pytest.fixture(scope="module")
def fb():
    return FeatureBuilder(n_text=4, min_df=1).fit(_df())


def test_inputs_and_features_exclude_forbidden(fb):
    assert not set(INPUT_COLUMNS) & FORBIDDEN
    assert not set(fb.feature_names) & FORBIDDEN
    for spec_forbidden in ["status", "nvd_vector", "has_cpe", "kev_date", "configurations"]:
        assert spec_forbidden in FORBIDDEN


def test_transform_needs_only_input_columns(fb):
    d = _df(10, seed=1)
    full = fb.transform(d)
    minimal = fb.transform(d[INPUT_COLUMNS])
    pd.testing.assert_frame_equal(full, minimal)


def test_forbidden_columns_do_not_change_features(fb):
    d = _df(10, seed=2)
    d2 = d.assign(status="Deferred", nvd_vector=None, has_cpe=False, kev_date=None, bump_up=False)
    pd.testing.assert_frame_equal(fb.transform(d), fb.transform(d2))


def test_train_serve_parity_single_row(fb):
    """A row scored alone (serve) gets exactly the features it got inside the batch (train)."""
    batch = _df(20, seed=3)
    X_batch = fb.transform(batch)
    row = batch.iloc[[7]][INPUT_COLUMNS].reset_index(drop=True)
    X_row = fb.transform(row)
    np.testing.assert_allclose(X_row.to_numpy(float), X_batch.iloc[[7]].to_numpy(float))


def test_unseen_cna_maps_to_other(fb):
    d = _df(3, seed=4).assign(cna="never-seen")
    assert (fb.transform(d).cna_id == fb.cna_vocab.index("other")).all()


def test_with_llm_features():
    fb = FeatureBuilder(n_text=4, min_df=1, with_llm=True).fit(_df())
    d = _df(3, seed=5).assign(cna_vector=VECS[2], llm_vector=[VECS[0], VECS[2], None])
    X = fb.transform(d)
    assert X.llm_score_delta.iloc[0] == pytest.approx(9.8 - 5.5)
    assert X.llm_changed_C.iloc[0] == 0.0 and X.llm_changed_I.iloc[0] == 1.0
    assert X.llm_score_delta.iloc[1] == 0.0
    assert np.isnan(X.llm_score_delta.iloc[2])
