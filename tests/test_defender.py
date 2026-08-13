"""Unit and integration test suite for defender_correlator module."""

import os
import sys
import unittest
import time
from datetime import datetime, timezone, timedelta

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer import defender_correlator, rules
from database import database
from utils import formatting


SAMPLE_EVENT_1116_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
    <Provider Name='Microsoft-Windows-Windows Defender'/>
    <EventID>1116</EventID>
    <TimeCreated SystemTime='2026-08-13T06:00:00.0000000Z'/>
</System>
<EventData>
    <Data Name='Threat Name'>Trojan:Win32/EICAR_Test_File</Data>
    <Data Name='Severity Name'>High</Data>
    <Data Name='Path'>file:_C:\\Users\\Public\\eicar.exe</Data>
    <Data Name='Process Name'>C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name='Detection Time'>2026-08-13T06:00:00.000Z</Data>
</EventData>
</Event>"""

SAMPLE_EVENT_1117_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
    <Provider Name='Microsoft-Windows-Windows Defender'/>
    <EventID>1117</EventID>
    <TimeCreated SystemTime='2026-08-13T06:01:00.0000000Z'/>
</System>
<EventData>
    <Data Name='Threat Name'>Behavior:Win32/SuspiciousRemoteConn</Data>
    <Data Name='Severity Name'>Severe</Data>
    <Data Name='Path'>C:\\ProgramData\\malicious.exe</Data>
    <Data Name='Process Name'>C:\\ProgramData\\malicious.exe</Data>
    <Data Name='Detection Time'>2026-08-13T06:01:00.000Z</Data>
</EventData>
</Event>"""


class TestDefenderCorrelator(unittest.TestCase):

    def test_elevation_check(self):
        """Test elevation check function returns a boolean without error."""
        is_admin = defender_correlator.check_elevation()
        self.assertIsInstance(is_admin, bool)

    def test_clean_defender_path(self):
        """Test stripping of file:_ and containerfile:_ prefixes."""
        self.assertEqual(defender_correlator._clean_defender_path("file:_C:\\test.exe"), "C:\\test.exe")
        self.assertEqual(defender_correlator._clean_defender_path("file:C:\\test.exe"), "C:\\test.exe")
        self.assertEqual(defender_correlator._clean_defender_path("containerfile:_D:\\bad.dll"), "D:\\bad.dll")
        self.assertEqual(defender_correlator._clean_defender_path("C:\\normal\\path.exe"), "C:\\normal\\path.exe")

    def test_parse_event_xml(self):
        """Test XML parsing of Event 1116 and 1117 XML structures."""
        parsed1 = defender_correlator.parse_event_xml(SAMPLE_EVENT_1116_XML)
        self.assertIsNotNone(parsed1)
        self.assertEqual(parsed1["event_id"], 1116)
        self.assertEqual(parsed1["threat_name"], "Trojan:Win32/EICAR_Test_File")
        self.assertEqual(parsed1["severity"], "High")
        self.assertEqual(parsed1["affected_path"], "C:\\Users\\Public\\eicar.exe")
        self.assertEqual(parsed1["process_name_if_known"], "C:\\Windows\\System32\\cmd.exe")

        parsed2 = defender_correlator.parse_event_xml(SAMPLE_EVENT_1117_XML)
        self.assertIsNotNone(parsed2)
        self.assertEqual(parsed2["event_id"], 1117)
        self.assertEqual(parsed2["threat_name"], "Behavior:Win32/SuspiciousRemoteConn")
        self.assertEqual(parsed2["severity"], "Severe")
        self.assertEqual(parsed2["affected_path"], "C:\\ProgramData\\malicious.exe")

    def test_correlation_confidence_levels(self):
        """Test correlation logic matching high, medium, low confidence, and gaps."""
        now_str = "2026-08-13T06:00:30.000Z"
        records = [
            {
                "pid": 1001,
                "proc_info": {"name": "malicious.exe", "exe": "C:\\ProgramData\\malicious.exe"},
                "timestamp": now_str,
                "is_external": True,
            },
            {
                "pid": 1002,
                "proc_info": {"name": "cmd.exe", "exe": "C:\\Windows\\System32\\cmd.exe"},
                "timestamp": now_str,
                "is_external": False,
            },
            {
                "pid": 1003,
                "proc_info": {"name": "chrome.exe", "exe": "C:\\Program Files\\Google\\Chrome\\chrome.exe"},
                "timestamp": now_str,
                "is_external": True,
            },
        ]

        events = [
            defender_correlator.parse_event_xml(SAMPLE_EVENT_1117_XML),  # Matches malicious.exe (HIGH confidence)
            defender_correlator.parse_event_xml(SAMPLE_EVENT_1116_XML),  # Matches cmd.exe (MEDIUM confidence by process name)
            {
                "event_id": 1006,
                "threat_name": "UncorrelatedThreat",
                "severity": "Low",
                "affected_path": "Z:\\unknown\\uncorrelated.exe",
                "process_name_if_known": "unknown.exe",
                "detected_at": "2026-08-13T04:00:00.000Z",  # Outside time window -> GAP
            }
        ]

        confirmed, gaps = defender_correlator.correlate_events(records, events, time_window_minutes=5)
        self.assertEqual(len(confirmed), 2)
        self.assertEqual(len(gaps), 1)

        conf_map = {m["record"]["proc_info"]["name"]: m["match_confidence"] for m in confirmed}
        self.assertEqual(conf_map["malicious.exe"], "high")
        self.assertEqual(conf_map["cmd.exe"], "medium")
        self.assertEqual(gaps[0]["threat_name"], "UncorrelatedThreat")

    def test_rules_scoring_integration(self):
        """Test rule defender_correlated_detection (+50) evaluation in rules.analyze()."""
        rec = {
            "pid": 2001,
            "proc_info": {"name": "badapp.exe", "exe": "C:\\Temp\\badapp.exe"},
            "timestamp": "2026-08-13T06:00:00Z",
            "is_external": True,
        }
        match_info = {
            "record": rec,
            "event": {"threat_name": "Trojan:Win32/Test", "severity": "High"},
            "match_confidence": "high",
        }
        defender_matches = {id(rec): match_info}

        analyzed = rules.analyze([rec], use_defender=True, defender_matches=defender_matches)
        self.assertIn("defender_correlated_detection", analyzed[0]["rules_applied"])
        self.assertEqual(analyzed[0]["rules_applied"]["defender_correlated_detection"], 50)
        self.assertTrue(any("Windows Defender detection event correlated" in r for r in analyzed[0]["reasons"]))

    def test_database_defender_events(self):
        """Test save_defender_events and fetch_defender_events SQLite persistence."""
        test_db = os.path.join(os.path.dirname(__file__), "test_defender.db")
        if os.path.exists(test_db):
            os.remove(test_db)

        try:
            event_row = {
                "event_id": 1116,
                "threat_name": "TestThreat",
                "severity": "High",
                "affected_path": "C:\\test\\path.exe",
                "process_name_if_known": "test.exe",
                "detected_at": "2026-08-13T06:00:00Z",
                "correlated_history_id": 42,
                "match_confidence": "high",
            }
            inserted = database.save_defender_events([event_row], db_path=test_db)
            self.assertEqual(inserted, 1)

            fetched = database.fetch_defender_events(limit=10, db_path=test_db)
            self.assertEqual(len(fetched), 1)
            self.assertEqual(fetched[0]["threat_name"], "TestThreat")
            self.assertEqual(fetched[0]["correlated_history_id"], 42)
            self.assertEqual(fetched[0]["match_confidence"], "high")
        finally:
            if os.path.exists(test_db):
                os.remove(test_db)

    def test_query_timing_performance(self):
        """Measure execution time of Defender query to verify no polling loop stall."""
        if not defender_correlator.check_elevation():
            self.skipTest("Skipping live EvtQuery performance test in non-elevated environment.")
        
        t0 = time.perf_counter()
        events = defender_correlator.query_defender_events(lookback_minutes=15)
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000
        print(f"\n[PERFORMANCE] Defender EvtQuery returned {len(events)} events in {elapsed_ms:.2f} ms")
        self.assertLess(elapsed_ms, 2000.0, "Defender query took more than 2 seconds!")


if __name__ == "__main__":
    unittest.main()
