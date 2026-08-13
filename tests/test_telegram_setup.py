"""Unit tests for Telegram recipient configuration, database tracking, and setup logic."""

import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from database import database
import telegram_alerter


class TestTelegramSetupAndDB(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_history.db")
        self.settings_path = os.path.join(self.temp_dir.name, "user_settings.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("telegram_alerter.get_user_settings_path")
    def test_user_settings_save_and_load(self, mock_path):
        from pathlib import Path
        mock_path.return_value = Path(self.settings_path)

        # Initial state
        self.assertEqual(telegram_alerter.load_user_settings(), {})

        # Save settings
        ok = telegram_alerter.save_user_settings({"telegram_chat_id": "123456789", "telegram_chat_name": "Test User"})
        self.assertTrue(ok)

        # Load settings
        loaded = telegram_alerter.load_user_settings()
        self.assertEqual(loaded.get("telegram_chat_id"), "123456789")
        self.assertEqual(loaded.get("telegram_chat_name"), "Test User")

    @patch("telegram_alerter.get_user_settings_path")
    @patch("telegram_alerter._load_dotenv")
    def test_resolution_priority(self, mock_dotenv, mock_path):
        from pathlib import Path
        mock_path.return_value = Path(self.settings_path)

        # Case 1: Neither settings nor .env -> none
        mock_dotenv.return_value = {}
        chat_id, source = telegram_alerter.get_chat_id_info()
        self.assertIsNone(chat_id)
        self.assertEqual(source, "none")

        # Case 2: Only .env fallback present
        mock_dotenv.return_value = {"FELUDA_TELEGRAM_CHAT_ID": "99999"}
        chat_id, source = telegram_alerter.get_chat_id_info()
        self.assertEqual(chat_id, "99999")
        self.assertEqual(source, ".env")

        # Case 3: user_settings.json present -> primary over .env
        telegram_alerter.save_user_settings({"telegram_chat_id": "11111"})
        chat_id, source = telegram_alerter.get_chat_id_info()
        self.assertEqual(chat_id, "11111")
        self.assertEqual(source, "user_settings")

    def test_db_telegram_alerts_and_stats_upsert(self):
        chat_id = "test_chat_100"

        # 1. Record alert 1
        ok1 = database.record_telegram_alert(chat_id, alert_type="connection", risk_level="HIGH", risk_score=75, details="Test Alert 1", db_path=self.db_path)
        self.assertTrue(ok1)

        # 2. Record alert 2 for SAME chat_id (tests UPSERT / combining stats without primary key collision)
        ok2 = database.record_telegram_alert(chat_id, alert_type="persistence", risk_level="CRITICAL", risk_score=90, details="Test Alert 2", db_path=self.db_path)
        self.assertTrue(ok2)

        # Verify alerts log table
        alerts = database.fetch_telegram_alerts(chat_id, db_path=self.db_path)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["details"], "Test Alert 2")

        # Verify stats table UPSERT
        stats = database.fetch_telegram_stats(chat_id, db_path=self.db_path)
        self.assertEqual(stats["chat_id"], chat_id)
        self.assertEqual(stats["total_alerts_sent"], 2)

        # 3. Record scan stop
        stop_ok = database.record_telegram_scan_stop(chat_id, db_path=self.db_path)
        self.assertTrue(stop_ok)

        updated_stats = database.fetch_telegram_stats(chat_id, db_path=self.db_path)
        self.assertEqual(updated_stats["total_alerts_sent"], 2)  # preserved, not overwritten or duplicated!
        self.assertIsNotNone(updated_stats["last_scan_ended_at"])


if __name__ == "__main__":
    unittest.main()
