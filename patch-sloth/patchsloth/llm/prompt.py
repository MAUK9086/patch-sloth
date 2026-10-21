"""The single prompt definition for Task A, shared by SFT data (scripts/04), eval (06) and serving."""
import json
import re

from ..cvss import METRICS, VALUES, parse, to_vector

SYSTEM = ("You are an independent CVSS v3.1 analyst, like NIST NVD. Given a CVE description and the "
          "reporter's (CNA's) vector, output the vector an independent analyst would assign, as JSON with "
          "keys AV,AC,PR,UI,S,C,I,A. Change a field only if the description supports it.")
MAX_DESC = 1200
_OBJ = re.compile(r"\{[^{}]*\}")


def prompt(r) -> str:
    """User turn for a row with .cna, .cna_cwe, .cna_vector, .description."""
    desc = r.description[:MAX_DESC]
    return (f"CNA: {r.cna}\nCNA weakness: {r.cna_cwe or 'none'}\nCNA vector: {r.cna_vector}\n"
            f"Description: {desc}")


def messages(r) -> list[dict]:
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt(r)}]


def target(r) -> str:
    """Compact JSON of the label vector, e.g. {"AV":"N",...}."""
    return json.dumps({k: parse(r.label_vector)[k] for k in METRICS}, separators=(",", ":"))


def parse_output(text: str | None, fallback: str | None) -> tuple[str | None, bool]:
    """Model text -> (CVSS vector, valid). Takes the first JSON object with all 8 valid fields;
    anything else falls back to `fallback` (the CNA vector) with valid=False."""
    if not isinstance(text, str):
        return fallback, False
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    for m in _OBJ.finditer(text):
        try:
            j = json.loads(m.group(0))
        except json.JSONDecodeError:
            continue
        if isinstance(j, dict) and all(j.get(k) in VALUES[k] for k in METRICS):
            return to_vector(j), True
    return fallback, False
