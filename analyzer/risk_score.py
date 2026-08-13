"""Risk scoring (Phase 11): pure 0–100 additive scoring and banding.

Bands (config-driven via rules.json):
  0–24 LOW | 25–49 MEDIUM | 50–74 HIGH | 75–100 CRITICAL

This is a HEURISTIC risk score — a transparent sum of weighted signals —
never a "probability of malware."
"""

from utils.config_loader import settings


def apply_score(record):
    """Clamp `rules_applied` sum into `risk_score` and set `risk_level`."""
    raw = sum(record.get("rules_applied", {}).values())
    score = max(0, min(100, int(raw)))
    record["risk_score"] = score
    record["risk_level"] = band_for_score(score)
    return record


def band_for_score(score):
    """Map a numeric score to its band label using config thresholds."""
    bands = settings().get("risk_bands", {})
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lo, hi = bands.get(label, [None, None])
        if lo is None:
            continue
        if lo <= score <= hi:
            return label
    return "LOW"


def apply_banding_floor(record, min_level="HIGH"):
    """Floor a record's risk_level at min_level (default HIGH) if currently below it."""
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    curr_level = record.get("risk_level", "LOW")
    if order.get(curr_level, 1) < order.get(min_level, 3):
        record["risk_level"] = min_level
        bands = settings().get("risk_bands", {})
        min_score = bands.get(min_level, [50, 74])[0]
        if record.get("risk_score", 0) < min_score:
            record["risk_score"] = min_score
    return record
