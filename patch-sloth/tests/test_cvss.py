import pytest

from patchsloth.cvss import base_score, parse, sev_rank, severity, to_vector

KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # scope changed, capped at 10
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),   # scope changed, PR:L uses 0.68
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # zero impact
]


@pytest.mark.parametrize("vector,score", KNOWN)
def test_base_score(vector, score):
    assert base_score(parse(vector)) == score


def test_roundtrip():
    v = KNOWN[0][0]
    assert to_vector(parse(v)) == v
    assert parse(v.removeprefix("CVSS:3.1/")) == parse(v)


@pytest.mark.parametrize("score,band", [(0.0, "NONE"), (0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"),
                                        (6.9, "MEDIUM"), (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"),
                                        (10.0, "CRITICAL")])
def test_severity_bands(score, band):
    assert severity(score) == band


def test_sev_rank_order():
    assert [sev_rank(s) for s in (0.0, 2.0, 5.0, 8.0, 9.5)] == [0, 1, 2, 3, 4]
