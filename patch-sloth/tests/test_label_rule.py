"""Label rule (SPEC §8.2), including the regression for the NaN-is-truthy bug."""
import numpy as np
import pandas as pd
import pytest

from patchsloth.data.nvd import add_labels, assign_splits, label_vector

CNA = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"   # 5.4 MEDIUM
NVD = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8 CRITICAL


def test_analyzed_with_nvd_vector_uses_nvd():
    assert label_vector("Analyzed", CNA, NVD) == NVD
    assert label_vector("Modified", CNA, NVD) == NVD


def test_analyzed_without_nvd_vector_uses_cna():
    assert label_vector("Analyzed", CNA, None) == CNA


@pytest.mark.parametrize("status", ["Deferred", "Awaiting Analysis", "Received", "Undergoing Analysis"])
def test_unanalysed_has_no_label(status):
    assert label_vector(status, CNA, NVD) is None
    assert label_vector(status, CNA, None) is None


@pytest.mark.parametrize("missing", [None, float("nan"), np.nan, pd.NA])
def test_nan_never_produces_a_label(missing):
    # regression: a truthiness check treated NaN as a vector and mislabelled ~40% of rows
    assert label_vector("Analyzed", missing, NVD) is None
    assert label_vector("Analyzed", missing, missing) is None
    assert label_vector("Analyzed", CNA, missing) == CNA


def test_nan_regression_through_dataframe():
    """Missing values as pandas actually stores them after a parquet round trip."""
    df = pd.DataFrame(dict(
        cve=["A", "B", "C", "D"], published=["2024-01-01", "2025-08-01", "2026-02-01", "2026-03-01"],
        status=["Analyzed", "Analyzed", "Analyzed", "Deferred"],
        cna_vector=[CNA, CNA, np.nan, CNA], nvd_vector=[NVD, np.nan, NVD, np.nan],
    ))
    df = assign_splits(add_labels(df))
    assert list(df.label_vector[:2]) == [NVD, CNA]
    assert df.label_vector[2:].isna().all()
    assert df.bump_up[0] == True and df.bump_up[1] == False  # noqa: E712
    assert pd.isna(df.bump_up[2]) and pd.isna(df.bump_up[3])
    assert list(df.split) == ["train", "val", None, "deferred_unlabeled"]
