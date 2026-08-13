"""Composite Correlation Scoring / Attack Chain Detection Engine.

Consumes findings across independent detection stages (Connection rules, Process
Lineage, Persistence scanning, Defender correlation, and Browser URL Engine),
groups by target identity, applies stage-based score bonuses, floors risk band at
HIGH, and generates human-readable attack chain narratives.
"""

import os
from typing import List, Dict, Any, Set, Tuple

from utils import logger
from utils.config_loader import settings
from utils.formatting import utc_now_iso
from analyzer import risk_score

log = logger.get_logger("analyzer.correlation")


def resolve_target_identity(record: dict) -> str:
    """Return a normalized canonical target identity string for any record type.

    Prefers resolved executable path when available.
    Falls back to 'pid:<pid>' when no path is available.
    """
    if not record:
        return ""

    # 1. Inspect proc_info nested dict (connection records)
    proc = record.get("proc_info") or {}
    exe = proc.get("exe") or proc.get("exe_path")

    # 2. Inspect top-level path attributes
    if not exe:
        exe = (
            record.get("resolved_exe_path")
            or record.get("exe_path")
            or record.get("affected_path")
            or record.get("process_name_if_known")
        )

    # 3. Check lineage chain link 0 (target process itself)
    if not exe and record.get("lineage"):
        chain = record.get("lineage", {}).get("chain", [])
        if chain:
            exe = chain[0].get("exe_path") or chain[0].get("name")

    if exe and str(exe).strip():
        return os.path.normpath(str(exe).strip()).lower()

    # Fallback to PID
    pid = record.get("pid")
    if pid is not None and str(pid).strip() and str(pid) != "?":
        return f"pid:{pid}"

    return ""


def generate_chain_narrative(stages: Set[str], details: dict = None) -> str:
    """Generate a deterministic, human-readable headline narrative for a chain."""
    stages_set = set(stages)

    if {"lineage", "persistence", "connection"}.issubset(stages_set):
        return (
            "Resembles a macro-malware execution chain: a spawned shell or interpreter "
            "both persists across reboot and is actively communicating externally."
        )

    if {"browser", "connection"}.issubset(stages_set):
        return (
            "Resembles a browser-based drive-by compromise: browser process activity "
            "reaches out to flagged external infrastructure."
        )

    if {"persistence", "defender"}.issubset(stages_set):
        return (
            "An autorun persistence entry independently confirmed by Windows Defender's "
            "own native detection engine."
        )

    if {"lineage", "connection"}.issubset(stages_set):
        return (
            "Suspicious process lineage combined with active external network communication."
        )

    if {"defender", "connection"}.issubset(stages_set):
        return (
            "Active network connection established by a process flagged in Windows Defender event logs."
        )

    if {"persistence", "connection"}.issubset(stages_set):
        return (
            "A persistent autorun process actively communicating over external network connections."
        )

    stage_list_str = ", ".join(sorted(stages_set))
    return (
        f"{len(stages_set)} independent detection stages ({stage_list_str}) flagged the same "
        "target identity — this warrants immediate security review."
    )


def evaluate_chain(
    records: List[dict],
    persistence_entries: List[dict] = None,
    defender_events: List[dict] = None,
) -> Tuple[List[dict], List[dict]]:
    """Evaluate all records in a scan pass for multi-stage attack chains.

    Returns:
        (updated_records, detected_chains)
    """
    if not records:
        return records, []

    cfg = settings()
    weights = cfg.get("rule_weights", {})
    bonus_2 = int(weights.get("chain_correlation_bonus_2", 25))
    bonus_3 = int(weights.get("chain_correlation_bonus_3", 40))
    bonus_4 = int(weights.get("chain_correlation_bonus_4", 60))

    persistence_entries = persistence_entries or []
    defender_events = defender_events or []

    # Map target identity -> Dict[stage_name, List[record_or_entry]]
    identity_map: Dict[str, Dict[str, List[Any]]] = {}

    def _track(identity: str, stage: str, item: Any):
        if not identity:
            return
        if identity not in identity_map:
            identity_map[identity] = {}
        if stage not in identity_map[identity]:
            identity_map[identity][stage] = []
        identity_map[identity][stage].append(item)

    # 1. Categorize Connection records and nested enrichments
    for r in records:
        target_id = resolve_target_identity(r)
        if not target_id:
            continue

        # Check connection rules (R1-R6, outside_baseline, etc.)
        applied = r.get("rules_applied", {})
        conn_rules = {k: v for k, v in applied.items() if k != "chain_correlation_bonus"}
        if conn_rules or r.get("is_external"):
            _track(target_id, "connection", r)

        # Check process lineage (Stage 5)
        lineage = r.get("lineage") or {}
        if lineage.get("signals") or lineage.get("risk_points", 0) > 0:
            _track(target_id, "lineage", r)

        # Check Defender correlation (Stage 7)
        if r.get("defender_event") or "defender_correlated_detection" in applied:
            _track(target_id, "defender", r)

        # Check Browser URL threat engine stage
        if r.get("browser_threat") or r.get("url_risk"):
            _track(target_id, "browser", r)

    # 2. Categorize standalone Persistence entries
    for p in persistence_entries:
        p_id = resolve_target_identity(p)
        if p_id and (p.get("risk_points", 0) > 0 or p.get("triggered_signals")):
            _track(p_id, "persistence", p)

    # 3. Categorize standalone Defender events
    for d in defender_events:
        d_id = resolve_target_identity(d)
        if d_id:
            _track(d_id, "defender", d)

    detected_chains = []

    # 4. Evaluate target identities with 2+ distinct stage categories
    for target_id, stages_dict in identity_map.items():
        stages_count = len(stages_dict)
        if stages_count < 2:
            continue

        # Determine bonus weight based on distinct stage count
        if stages_count == 2:
            bonus = bonus_2
        elif stages_count == 3:
            bonus = bonus_3
        else:
            bonus = bonus_4

        stage_names = set(stages_dict.keys())
        narrative = generate_chain_narrative(stage_names)

        # Apply bonus and banding floor to all associated connection records
        conn_recs = stages_dict.get("connection", [])
        if not conn_recs:
            # Create dummy connection reference if chain is non-connection target
            conn_recs = [records[0]] if records else []

        for rec in conn_recs:
            if "rules_applied" not in rec:
                rec["rules_applied"] = {}
            rec["rules_applied"]["chain_correlation_bonus"] = bonus

            # Re-apply score sum and enforce HIGH risk band floor
            risk_score.apply_score(rec)
            risk_score.apply_banding_floor(rec, min_level="HIGH")

            rec["chain_narrative"] = narrative
            rec["is_attack_chain"] = True
            rec["chain_stages"] = list(sorted(stage_names))

            if "reasons" not in rec:
                rec["reasons"] = []
            reason_str = f"Composite attack chain correlation ({stages_count} stages: {', '.join(sorted(stage_names))}) (+{bonus})"
            if reason_str not in rec["reasons"]:
                rec["reasons"].append(reason_str)

        first_rec = conn_recs[0] if conn_recs else {}
        chain_item = {
            "target_identity": target_id,
            "stages_involved": list(sorted(stage_names)),
            "chain_narrative": narrative,
            "bonus_points": bonus,
            "final_risk_score": first_rec.get("risk_score", 50),
            "final_risk_level": first_rec.get("risk_level", "HIGH"),
            "detected_at": utc_now_iso(),
            "related_history_ids": [first_rec.get("id")] if first_rec.get("id") else [],
            "record": first_rec,
        }
        detected_chains.append(chain_item)

    log.info("evaluated correlation scan pass: %d attack chains detected", len(detected_chains))
    return records, detected_chains
