"""Unit tests for Telegram two-way listener and remote control logic."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from database import database
from monitor.realtime import MonitorController
import telegram_listener


class TestTelegramListenerAndControl(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_history.db"
        self.chat_id = "5220202988"

        # Initialize DB & session
        database.upsert_telegram_session(self.chat_id, state="listening", db_path=self.db_path)

        self.mock_alerter = MagicMock()
        self.controller = MonitorController(alerter=self.mock_alerter, chat_id=self.chat_id)
        self.listener = telegram_listener.TelegramListener(
            token="12345:fake_token",
            allowed_chat_id=self.chat_id,
            controller=self.controller,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_monitor_controller_state_transitions(self):
        # Initial state
        self.assertEqual(self.controller.mode, "PAUSED")
        self.assertEqual(self.controller.alert_min_score, 50)

        # Set HIGH mode
        msg = self.controller.set_mode("HIGH", min_score=50)
        self.assertEqual(self.controller.mode, "HIGH")
        self.assertEqual(self.controller.alert_min_score, 50)
        self.mock_alerter.set_alert_threshold.assert_called_with(50)
        self.assertIn("HIGH", msg)

        # Pause scan
        msg = self.controller.pause_scan()
        self.assertEqual(self.controller.mode, "PAUSED")
        self.assertIsNone(self.controller.mode_started_at)
        self.assertIn("paused", msg.lower())

        # Stop session
        msg = self.controller.stop_session()
        self.assertEqual(self.controller.mode, "STOPPED")
        self.assertTrue(self.controller.session_stopped)
        self.assertIn("ended", msg.lower())

    @patch("telegram_listener._send_message_async", new_callable=AsyncMock)
    def test_listener_process_commands(self, mock_send):
        mock_send.return_value = True

        async def _run_tests():
            # /high
            await self.listener.process_command("/high")
            self.assertEqual(self.controller.mode, "HIGH")
            self.assertEqual(self.controller.alert_min_score, 50)

            # /pause
            await self.listener.process_command("/pause")
            self.assertEqual(self.controller.mode, "PAUSED")

            # /medium
            await self.listener.process_command("/medium")
            self.assertEqual(self.controller.mode, "MEDIUM")

            # /stop
            await self.listener.process_command("/stop")
            self.assertEqual(self.controller.mode, "STOPPED")
            self.assertTrue(self.controller.session_stopped)

            # /status
            await self.listener.process_command("/status")
            mock_send.assert_called()

        asyncio.run(_run_tests())

    def test_session_persistence_upsert_and_lifecycle(self):
        # 1. Verify initial upsert
        sess = database.fetch_telegram_sessions(self.chat_id, db_path=self.db_path)
        self.assertEqual(sess["chat_id"], self.chat_id)
        self.assertEqual(sess["last_known_state"], "listening")
        self.assertEqual(sess["total_findings_sent"], 0)

        # 2. State change to active HIGH
        database.update_telegram_session_state(self.chat_id, state="active", severity_focus="HIGH", db_path=self.db_path)
        sess = database.fetch_telegram_sessions(self.chat_id, db_path=self.db_path)
        self.assertEqual(sess["last_known_state"], "active")
        self.assertEqual(sess["current_severity_focus"], "HIGH")

        # 3. Increment findings count
        database.increment_session_findings(self.chat_id, count=3, db_path=self.db_path)
        sess = database.fetch_telegram_sessions(self.chat_id, db_path=self.db_path)
        self.assertEqual(sess["total_findings_sent"], 3)

        # 4. Re-connecting with same chat_id (UPSERT) resets per-session counters
        database.upsert_telegram_session(self.chat_id, state="listening", db_path=self.db_path)
        sess = database.fetch_telegram_sessions(self.chat_id, db_path=self.db_path)
        self.assertEqual(sess["total_findings_sent"], 0)
        self.assertEqual(sess["last_known_state"], "listening")

        # 5. Close session
        database.close_telegram_session(self.chat_id, db_path=self.db_path)
        sess = database.fetch_telegram_sessions(self.chat_id, db_path=self.db_path)
        self.assertEqual(sess["last_known_state"], "stopped")
        self.assertIsNotNone(sess["session_ended_at"])

        # 6. Verify exactly 1 row exists for this chat_id in database
        all_sessions = database.fetch_telegram_sessions(db_path=self.db_path)
        self.assertEqual(len(all_sessions), 1)


if __name__ == "__main__":
    unittest.main()
