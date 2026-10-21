"""CVSS v3.1 helpers: parse vectors, compute base score, severity bands."""
import math

METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
VALUES = {
    "AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "PR": ["N", "L", "H"],
    "UI": ["N", "R"], "S": ["U", "C"], "C": ["H", "L", "N"], "I": ["H", "L", "N"], "A": ["H", "L", "N"],
}
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
SEV = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def parse(vector: str) -> dict:
    parts = vector.split("/")
    if parts[0].startswith("CVSS:"):
        parts = parts[1:]
    d = dict(p.split(":") for p in parts)
    return {k: d[k] for k in METRICS}


def to_vector(m: dict) -> str:
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in METRICS)


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(m: dict) -> float:
    changed = m["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
    iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    s = 1.08 * (impact + expl) if changed else impact + expl
    return _roundup(min(s, 10))


def severity(score: float) -> str:
    if score == 0: return "NONE"
    if score < 4: return "LOW"
    if score < 7: return "MEDIUM"
    if score < 9: return "HIGH"
    return "CRITICAL"


def sev_rank(score: float) -> int:
    return SEV.index(severity(score))
