"""Deterministic priority rules (SPEC §11.3). The report writer never sets priorities; it only explains these.

eff_sev = max(cna_sev, predicted_sev if p_bump >= tau else cna_sev)
P0 "Patch now":       in KEV, or EPSS >= 0.10, or (eff_sev >= HIGH and p_bump >= tau_high and a fix exists)
P1 "This month":      eff_sev >= HIGH, or p_bump >= tau
P2 "Ignore for now":  everything else
Extension (approved 2026-10-23): for NIST-reviewed CVEs (source="nvd"), eff_sev = max(CNA, NVD-final) with no
threshold, and no model prediction or p_bump is used for them.
tau / tau_high come from results/thresholds.json (tau = top 10% of p_bump over Deferred CVEs, no labels).
Rows scored by a model with Bands (feed rows, and on-demand HGB rows) carry bump_band / bump_high instead: the band
"likely" is exactly p_bump >= that model's tau, and bump_high is p_bump >= its tau_high (top 5% of Deferred), so each
row is judged against the cut-offs of the model that scored it. Users see the band, never the raw probability.
"""
from . import config
from .cvss import SEV, base_score, parse, sev_rank

HIGH = SEV.index("HIGH")
BUCKETS = {"P0": "Patch now", "P1": "This month", "P2": "Ignore for now"}


def _sev(vector) -> int | None:
    return sev_rank(base_score(parse(vector))) if isinstance(vector, str) else None


def _num(x) -> float | None:
    """None/NaN -> None, else float."""
    try:
        x = float(x)
    except (TypeError, ValueError):
        return None
    return None if x != x else x


def prioritise(row: dict, tau: float | None = None, tau_high: float | None = None) -> dict:
    """row: cve, cna_vector, predicted_vector, p_bump, epss, kev_date, fixed. Returns row + bucket/reason."""
    thr = config.thresholds()
    tau = thr["tau"] if tau is None else tau
    tau_high = thr["tau_high"] if tau_high is None else tau_high
    cna_sev, pred_sev = _sev(row.get("cna_vector")), _sev(row.get("predicted_vector"))
    p = _num(row.get("p_bump"))
    epss = _num(row.get("epss"))
    kev = row.get("kev_date") if isinstance(row.get("kev_date"), str) and row.get("kev_date") else None
    fixed = row.get("fixed") or None
    # NIST-reviewed: NVD already analysed it, so its final vector is known (no threshold) and no model
    # prediction or probability is used for it
    nvd_final = row.get("source") == "nvd" and pred_sev is not None
    band = row.get("bump_band") if isinstance(row.get("bump_band"), str) else None
    if band is not None:  # judged on the scoring model's own label-free cut-offs
        flagged = not nvd_final and band == "likely"
        high = flagged and bool(row.get("bump_high"))
    else:
        flagged = not nvd_final and p is not None and p >= tau
        high = flagged and p >= tau_high
    shown = "" if band is not None else f" (p={p:.2f})" if p is not None else ""
    base = cna_sev if cna_sev is not None else -1
    eff = max(base, pred_sev) if (flagged or nvd_final) and pred_sev is not None else base

    reasons = []
    if kev:
        reasons.append(f"CISA KEV (added {kev})")
    if epss is not None and epss >= config.EPSS_P0:
        reasons.append(f"EPSS {epss:.2f} >= {config.EPSS_P0:.2f}")
    if cna_sev is None:
        reasons.append("no CNA CVSS v3.1 score")
    if nvd_final:
        reasons.append(f"NIST-reviewed: CNA {SEV[cna_sev] if cna_sev is not None else 'unscored'} / "
                       f"NVD {SEV[pred_sev]}")
    elif flagged:
        if pred_sev is not None and cna_sev is not None and pred_sev > cna_sev:
            reasons.append(f"likely under-rated: CNA {SEV[cna_sev]} -> predicted {SEV[pred_sev]}{shown}")
        else:
            reasons.append(f"likely under-rated{shown}")
    elif band == "possible" and cna_sev is not None:
        reasons.append(f"CNA {SEV[cna_sev]}; a higher rating is possible")
    elif cna_sev is not None:
        reasons.append(f"CNA {SEV[cna_sev]}")

    if kev or (epss is not None and epss >= config.EPSS_P0) or (
            eff >= HIGH and high and fixed):
        bucket = "P0"
    elif eff >= HIGH or flagged:
        bucket = "P1"
    else:
        bucket = "P2"
    reasons.append(f"fix: {fixed}" if fixed else "no fixed version yet")
    return {**row, "eff_sev": SEV[eff] if eff >= 0 else None, "bucket": bucket,
            "bucket_label": BUCKETS[bucket], "reason": reasons}


def prioritise_all(rows: list[dict], **kw) -> list[dict]:
    """Prioritise and sort: bucket, then p_bump (desc), then EPSS (desc)."""
    out = [prioritise(r, **kw) for r in rows]
    return sorted(out, key=lambda r: (r["bucket"], -(_num(r.get("p_bump")) or 0), -(_num(r.get("epss")) or 0)))
