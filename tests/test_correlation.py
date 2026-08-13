"""Unit tests for Composite Correlation Scoring (Attack Chain Detection)."""

import tempfile
import unittest
from pathlib import Path

from analyzer import correlation, risk_score
from database import database


class TestCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_correlation.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_resolve_target_identity(self):
        # 1. Connection record with proc_info.exe
        rec_conn = {"proc_info": {"exe": "C:\\Windows\\System32\\cmd.exe"}, "pid": 1234}
        self.assertEqual(correlation.resolve_target_identity(rec_conn), "c:\\windows\\system32\\cmd.exe")

        # 2. Lineage record with chain[0].exe_path
        rec_lin = {"lineage": {"chain": [{"exe_path": "C:\\Users\\Public\\evil.exe"}]}, "pid": 5678}
        self.assertEqual(correlation.resolve_target_identity(rec_lin), "c:\\users\\public\\evil.exe")

        # 3. Persistence record with resolved_exe_path
        rec_persist = {"resolved_exe_path": "C:\\AppData\\Local\\Temp\\updater.exe"}
        self.assertEqual(correlation.resolve_target_identity(rec_persist), "c:\\appdata\\local\\temp\\updater.exe")

        # 4. Fallback to PID when no path available
        rec_pid = {"pid": 9999, "proc_info": {"name": "unknown"}}
        self.assertEqual(correlation.resolve_target_identity(rec_pid), "pid:9999")

    def test_2_stage_correlation_bonus_and_banding_floor(self):
        # Create a LOW risk connection record for evil.exe
        conn_rec = {
            "pid": 4444,
            "proc_info": {"exe": "C:\\Users\\Public\\evil.exe", "name": "evil.exe"},
            "is_external": True,
            "rules_applied": {"external_unknown_process": 15},  # Raw score 15 (LOW)
            "reasons": ["External unknown process (+15)"],
        }
        risk_score.apply_score(conn_rec)
        self.assertEqual(conn_rec["risk_level"], "LOW")

        # Persistence entry for the exact same target identity
        persist_entry = {
            "resolved_exe_path": "C:\\Users\\Public\\evil.exe",
            "risk_points": 25,
            "triggered_signals": ["registry_run_unusual"],
        }

        # Run correlation engine
        updated_records, detected_chains = correlation.evaluate_chain(
            [conn_rec], persistence_entries=[persist_entry]
        )

        self.assertEqual(len(detected_chains), 1)
        chain = detected_chains[0]
        self.assertEqual(chain["target_identity"], "c:\\users\\public\\evil.exe")
        self.assertEqual(set(chain["stages_involved"]), {"connection", "persistence"})
        self.assertEqual(chain["bonus_points"], 25)

        # Verify score bonus applied and risk band floored at HIGH (minimum 50)
        self.assertGreaterEqual(conn_rec["risk_score"], 50)
        self.assertEqual(conn_rec["risk_level"], "HIGH")
        self.assertTrue(conn_rec.get("is_attack_chain"))
        self.assertIn("persistent autorun process", conn_rec.get("chain_narrative", "").lower())

    def test_unrelated_findings_are_not_correlated(self):
        conn_rec = {
            "pid": 1111,
            "proc_info": {"exe": "C:\\Program Files\\app.exe"},
            "is_external": True,
            "rules_applied": {"external_unknown_process": 10},
        }
        persist_entry = {
            "resolved_exe_path": "C:\\Users\\Public\\unrelated.exe",
            "risk_points": 20,
        }

        updated_records, detected_chains = correlation.evaluate_chain(
            [conn_rec], persistence_entries=[persist_entry]
        )
        self.assertEqual(len(detected_chains), 0)

    def test_3_and_4_stage_correlation_bonus(self):
        target = "C:\\Temp\\malware.exe"
        conn_rec = {
            "pid": 3333,
            "proc_info": {"exe": target},
            "is_external": True,
            "rules_applied": {"external_unknown_process": 30},
            "lineage": {"signals": ["office_spawned_shell"], "risk_points": 30},
            "defender_event": {"threat_name": "Trojan.Win32"},
        }
        persist_entry = {"resolved_exe_path": target, "risk_points": 30}

        # 4 distinct stages: connection, lineage, defender, persistence
        _, detected_chains = correlation.evaluate_chain([conn_rec], persistence_entries=[persist_entry])
        self.assertEqual(len(detected_chains), 1)
        chain = detected_chains[0]
        self.assertEqual(len(chain["stages_involved"]), 4)
        self.assertEqual(chain["bonus_points"], 60)

    def test_database_save_and_fetch_correlated_chains(self):
        chain_data = {
            "target_identity": "c:\\temp\\test.exe",
            "stages_involved": ["connection", "lineage"],
            "chain_narrative": "Suspicious process lineage combined with active external network communication.",
            "bonus_points": 25,
            "final_risk_score": 65,
            "final_risk_level": "HIGH",
            "related_history_ids": [10, 11],
        }

        chain_id = database.save_correlated_chain(chain_data, db_path=self.db_path)
        self.assertIsNotNone(chain_id)

        fetched = database.fetch_correlated_chains(db_path=self.db_path)
        self.assertEqual(len(fetched), 1)
        item = fetched[0]
        self.assertEqual(item["target_identity"], "c:\\temp\\test.exe")
        self.assertEqual(item["stages_involved"], ["connection", "lineage"])
        self.assertEqual(item["final_risk_score"], 65)


if __name__ == "__main__":
    unittest.main()
