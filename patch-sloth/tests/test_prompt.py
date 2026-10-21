from types import SimpleNamespace

import pytest

from patchsloth.llm.prompt import SYSTEM, messages, parse_output, prompt, target

CNA = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
GOOD = '{"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"H"}'
GOOD_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_valid_json():
    assert parse_output(GOOD, CNA) == (GOOD_VEC, True)


@pytest.mark.parametrize("text", [
    f"Here is the vector:\n{GOOD}\nThanks.",
    f"<think>the attacker needs no auth {{maybe}}</think>{GOOD}",
    f"```json\n{GOOD}\n```",
    f'{{"note": 1}} {GOOD}',
])
def test_extra_text(text):
    assert parse_output(text, CNA) == (GOOD_VEC, True)


@pytest.mark.parametrize("text", [
    GOOD.replace('"AV":"N"', '"AV":"X"'),        # invalid value
    GOOD.replace('"A":"H"', '"A":"High"'),
    '{"AV":"N","AC":"L"}',                       # missing keys
    '{"AV":"N", broken',
    "CRITICAL 9.8",
])
def test_invalid_falls_back(text):
    assert parse_output(text, CNA) == (CNA, False)


@pytest.mark.parametrize("text", ["", None, "   "])
def test_empty(text):
    assert parse_output(text, CNA) == (CNA, False)


def test_prompt_and_target_shape():
    r = SimpleNamespace(cna="vuldb", cna_cwe="", cna_vector=CNA, description="x" * 5000, label_vector=GOOD_VEC)
    p = prompt(r)
    assert "CNA weakness: none" in p and p.endswith("x" * 1200) and "x" * 1201 not in p
    assert target(r) == GOOD
    assert messages(r)[0] == {"role": "system", "content": SYSTEM}
