"""Windows Defender / Event Log correlation module.

Queries recent Defender detection events from the modern Event Log channel
(Microsoft-Windows-Windows Defender/Operational) using pywin32's Evt*-prefixed API,
parses event XML for threat metadata, and correlates findings against Feluda's
connection scan records.
"""

import ctypes
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

from utils import logger
from utils.config_loader import settings

log = logger.get_logger("analyzer.defender")

DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
DEFENDER_EVENT_IDS = (1116, 1117, 1006)


def check_elevation() -> bool:
    """Return True if running with Administrator privileges on Windows."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _clean_defender_path(path_str: str) -> str:
    """Strip URI/container prefixes from Defender path fields."""
    if not path_str:
        return ""
    path_clean = path_str.strip()
    for prefix in ("file:_", "file:", "containerfile:_", "containerfile:"):
        if path_clean.lower().startswith(prefix):
            path_clean = path_clean[len(prefix):]
            break
    return path_clean.strip()


def _parse_iso_ts(ts_str: str) -> datetime | None:
    """Parse ISO timestamp strings from Defender XML or Feluda records."""
    if not ts_str:
        return None
    try:
        s = ts_str.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # Python isoformat handles up to 6 microsecond digits; truncate if >6 decimal digits
        if "." in s:
            parts = s.split(".")
            sec = parts[0]
            frac_and_tz = parts[1]
            tz_part = ""
            if "+" in frac_and_tz:
                frac, tz_part = frac_and_tz.split("+", 1)
                tz_part = "+" + tz_part
            elif "-" in frac_and_tz:
                frac, tz_part = frac_and_tz.split("-", 1)
                tz_part = "-" + tz_part
            else:
                frac = frac_and_tz
            frac = frac[:6]
            s = f"{sec}.{frac}{tz_part}"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception as exc:
        log.debug("Failed to parse timestamp '%s': %s", ts_str, exc)
        return None


def parse_event_xml(xml_str: str) -> dict | None:
    """Parse rendered Defender event XML into a structured event dict."""
    if not xml_str:
        return None
    try:
        root = ET.fromstring(xml_str)
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        evt_id_elem = root.find('.//ns:EventID', ns)
        event_id = int(evt_id_elem.text) if (evt_id_elem is not None and evt_id_elem.text) else 0

        time_elem = root.find('.//ns:TimeCreated', ns)
        system_time = time_elem.attrib.get('SystemTime', '') if time_elem is not None else ''

        data_fields = {}
        for data in root.findall('.//ns:EventData/ns:Data', ns):
            name = data.attrib.get('Name')
            if name:
                data_fields[name] = (data.text or '').strip()

        threat_name = data_fields.get("Threat Name") or data_fields.get("Threat ID") or "Unknown Threat"
        severity = data_fields.get("Severity Name") or data_fields.get("Severity ID") or "Unknown"
        raw_path = data_fields.get("Path") or ""
        affected_path = _clean_defender_path(raw_path)
        process_name = data_fields.get("Process Name") or ""
        detected_at = data_fields.get("Detection Time") or system_time

        return {
            "event_id": event_id,
            "threat_name": threat_name,
            "severity": severity,
            "affected_path": affected_path,
            "raw_path": raw_path,
            "process_name_if_known": process_name,
            "detected_at": detected_at,
            "data_fields": data_fields,
        }
    except Exception as exc:
        log.error("Failed to parse Defender event XML: %s", exc)
        return None


def query_defender_events(lookback_minutes: int = 15) -> list[dict]:
    """Query recent Defender detection events (1116, 1117, 1006) from Event Log."""
    if sys.platform != "win32":
        return []

    try:
        import win32evtlog
    except ImportError:
        log.warning("pywin32 (win32evtlog) is required for Defender event correlation.")
        return []

    xpath = "*[System[(EventID=1116 or EventID=1117 or EventID=1006)]]"
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection

    try:
        handle = win32evtlog.EvtQuery(DEFENDER_CHANNEL, flags, xpath)
    except Exception as exc:
        log.error("EvtQuery failed on channel '%s': %s", DEFENDER_CHANNEL, exc)
        return []

    parsed_events = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=lookback_minutes)

    try:
        while True:
            events = win32evtlog.EvtNext(handle, 50)
            if not events:
                break
            for evt in events:
                try:
                    xml_str = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
                    parsed = parse_event_xml(xml_str)
                    if not parsed:
                        continue

                    # Filter by lookback window
                    dt = _parse_iso_ts(parsed.get("detected_at"))
                    if dt and dt < cutoff:
                        # Since events are in reverse order (newest first), hitting an event
                        # older than lookback means we can stop scanning further.
                        break
                    parsed_events.append(parsed)
                except Exception as exc:
                    log.debug("Error processing event: %s", exc)
            else:
                continue
            break
    except Exception as exc:
        log.error("Error reading EvtNext events: %s", exc)

    log.info("Queried %d Defender events within past %d minutes", len(parsed_events), lookback_minutes)
    return parsed_events


def correlate_events(records: list[dict], defender_events: list[dict], time_window_minutes: int = 5) -> tuple[list[dict], list[dict]]:
    """Correlate Defender events against Feluda scan records.

    Args:
        records: connection scan records from pipeline
        defender_events: list of parsed defender event dicts
        time_window_minutes: max minute diff for correlation

    Returns:
        (confirmed_matches, gap_events)
        confirmed_matches: list of dicts with keys: record, event, match_confidence
        gap_events: list of defender_events that did not match any scan record
    """
    confirmed = []
    matched_event_indices = set()

    for evt_idx, evt in enumerate(defender_events):
        evt_dt = _parse_iso_ts(evt.get("detected_at"))
        raw_path = (evt.get("affected_path") or "").strip()
        evt_proc_path = os.path.normpath(raw_path).lower() if raw_path else ""

        raw_proc = (evt.get("process_name_if_known") or "").strip()
        if raw_proc and os.path.isabs(raw_proc):
            evt_proc_name = os.path.basename(raw_proc).lower()
        elif evt_proc_path and os.path.isabs(evt_proc_path):
            evt_proc_name = os.path.basename(evt_proc_path).lower()
        else:
            evt_proc_name = raw_proc.lower()

        best_match_rec = None
        best_confidence = None
        rank_map = {"high": 3, "medium": 2, "low": 1}

        for rec in records:
            rec_dt = _parse_iso_ts(rec.get("timestamp"))

            # Check time proximity if both timestamps are parseable
            in_window = True
            if evt_dt and rec_dt:
                time_diff = abs((evt_dt - rec_dt).total_seconds())
                if time_diff > (time_window_minutes * 60):
                    in_window = False

            if not in_window:
                continue

            proc_info = rec.get("proc_info") or {}
            rec_exe = os.path.normpath(proc_info.get("exe") or "").lower() if proc_info.get("exe") else ""
            rec_name = (proc_info.get("name") or "").lower()

            confidence = None
            # High confidence: exact or relative executable path match
            if rec_exe and evt_proc_path and (rec_exe == evt_proc_path or rec_exe.endswith(evt_proc_path) or evt_proc_path.endswith(rec_exe)):
                confidence = "high"
            # Medium confidence: process name match
            elif rec_name and evt_proc_name and (rec_name == evt_proc_name):
                confidence = "medium"
            # Low confidence: only if event carries NO path/process details at all
            elif not evt_proc_path and not evt_proc_name and in_window:
                confidence = "low"

            if confidence:
                current_best_rank = rank_map.get(best_confidence, 0)
                if rank_map[confidence] > current_best_rank:
                    best_confidence = confidence
                    best_match_rec = rec

        if best_match_rec:
            matched_event_indices.add(evt_idx)
            confirmed.append({
                "record": best_match_rec,
                "event": evt,
                "match_confidence": best_confidence,
            })

    gap_events = [evt for i, evt in enumerate(defender_events) if i not in matched_event_indices]
    log.info("Defender correlation: %d confirmed matches, %d gap events", len(confirmed), len(gap_events))
    return confirmed, gap_events
