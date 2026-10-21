"""Each bucket rule of SPEC §11.3, with fixed thresholds tau=0.3, tau_high=0.7."""
import pytest

from patchsloth.priority import prioritise, prioritise_all

MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"    # 5.4 MEDIUM
HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"   # 7.5 HIGH
CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8 CRITICAL
LOW = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"    # LOW


def p(**row):
    return prioritise({"cve": "CVE-2026-0001", "cna_vector": MED, "predicted_vector": MED, "p_bump": 0.0,
                       "epss": 0.0, "kev_date": None, "fixed": None, **row}, tau=0.3, tau_high=0.7)


def test_kev_is_p0():
    r = p(kev_date="2026-05-01", cna_vector=LOW, predicted_vector=LOW)
    assert r["bucket"] == "P0" and any("KEV" in x for x in r["reason"])


def test_epss_is_p0():
    assert p(epss=0.10)["bucket"] == "P0"
    assert p(epss=0.099)["bucket"] == "P2"


def test_underrated_high_with_fix_is_p0():
    r = p(predicted_vector=HIGH, p_bump=0.8, fixed="4.17.21")
    assert r["bucket"] == "P0" and r["eff_sev"] == "HIGH"
    assert "likely under-rated: CNA MEDIUM -> predicted HIGH (p=0.80)" in r["reason"]
    assert "fix: 4.17.21" in r["reason"]


def test_underrated_high_without_fix_is_p1():
    assert p(predicted_vector=HIGH, p_bump=0.8, fixed=None)["bucket"] == "P1"


def test_between_tau_and_tau_high_is_p1():
    assert p(predicted_vector=CRIT, p_bump=0.5, fixed="1.0.0")["bucket"] == "P1"


def test_cna_high_is_p1():
    r = p(cna_vector=HIGH, predicted_vector=HIGH, p_bump=0.0)
    assert r["bucket"] == "P1" and r["eff_sev"] == "HIGH"


def test_flag_without_severity_change_is_p1():
    assert p(p_bump=0.35)["bucket"] == "P1"


def test_prediction_ignored_below_tau():
    r = p(predicted_vector=CRIT, p_bump=0.29, fixed="1.0.0")
    assert r["bucket"] == "P2" and r["eff_sev"] == "MEDIUM"


@pytest.mark.parametrize("missing", [None, float("nan")])
def test_missing_values_are_p2(missing):
    r = p(p_bump=missing, epss=missing, kev_date=missing)
    assert r["bucket"] == "P2"


def test_no_cna_score():
    r = p(cna_vector=None, predicted_vector=None, p_bump=None)
    assert r["bucket"] == "P2" and "no CNA CVSS v3.1 score" in r["reason"]


def test_nvd_final_severity_counts_without_threshold():
    r = p(source="nvd", cna_vector=MED, predicted_vector=HIGH, p_bump=None)
    assert r["bucket"] == "P1" and r["eff_sev"] == "HIGH" and "NVD rated HIGH (CNA MEDIUM)" in r["reason"]
    # NVD lowering the band never lowers the priority (max, as in §11.3)
    assert p(source="nvd", cna_vector=HIGH, predicted_vector=MED)["eff_sev"] == "HIGH"


def test_sort_order():
    rows = [dict(cve="a", cna_vector=LOW, p_bump=0.0), dict(cve="b", cna_vector=MED, kev_date="2026-01-01"),
            dict(cve="c", cna_vector=HIGH, p_bump=0.1)]
    assert [r["cve"] for r in prioritise_all(rows, tau=0.3, tau_high=0.7)] == ["b", "c", "a"]
