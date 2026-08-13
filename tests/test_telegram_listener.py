"""Unit tests for Telegram two-way listener and remote control logic."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from monitor.realtime import MonitorController
import telegram_listener


class TestTelegramListenerAndControl(unittest.TestCase):

    def setUp(self):
        self.mock_alerter = MagicMock()
        self.controller = MonitorController(alerter=self.mock_alerter)
        self.listener = telegram_listener.TelegramListener(
            token="12345:fake_token",
            allowed_chat_id="5220202988",
            controller=self.controller,
        )

    def test_monitor_controller_state_transitions(self):
        # Initial state
        self.assertEqual(self.controller.mode, "STOPPED")
        self.assertEqual(self.controller.alert_min_score, 50)

        # Set HIGH mode
        msg = self.controller.set_mode("HIGH", min_score=50)
        self.assertEqual(self.controller.mode, "HIGH")
        self.assertEqual(self.controller.alert_min_score, 50)
        self.mock_alerter.set_alert_threshold.assert_called_with(50)
        self.assertIn("HIGH", msg)

        # Set MEDIUM mode
        msg = self.controller.set_mode("MEDIUM", min_score=25)
        self.assertEqual(self.controller.mode, "MEDIUM")
        self.assertEqual(self.controller.alert_min_score, 25)
        self.mock_alerter.set_alert_threshold.assert_called_with(25)

        # Stop scan
        msg = self.controller.stop_scan()
        self.assertEqual(self.controller.mode, "STOPPED")
        self.assertIsNone(self.controller.mode_started_at)
        self.assertTrue("paused" in msg.lower() or "stopped" in msg.lower())

    @patch("telegram_listener._send_message_async", new_callable=AsyncMock)
    def test_listener_process_commands(self, mock_send):
        mock_send.return_value = True

        async def _run_tests():
            # /high
            await self.listener.process_command("/high")
            self.assertEqual(self.controller.mode, "HIGH")
            self.assertEqual(self.controller.alert_min_score, 50)

            # /medium
            await self.listener.process_command("/medium")
            self.assertEqual(self.controller.mode, "MEDIUM")
            self.assertEqual(self.controller.alert_min_score, 25)

            # /low
            await self.listener.process_command("/low")
            self.assertEqual(self.controller.mode, "LOW")
            self.assertEqual(self.controller.alert_min_score, 0)

            # /stop
            await self.listener.process_command("/stop")
            self.assertEqual(self.controller.mode, "STOPPED")

            # /status
            await self.listener.process_command("/status")
            mock_send.assert_called()

        asyncio.run(_run_tests())

    @patch("telegram_listener._send_message_async", new_callable=AsyncMock)
    @patch("telegram_listener.answer_callback_query")
    def test_listener_handle_update_access_control(self, mock_answer, mock_send):
        mock_send.return_value = True

        async def _run_tests():
            # Authorized chat message
            auth_update = {
                "update_id": 1,
                "message": {
                    "chat": {"id": 5220202988},
                    "text": "/high",
                },
            }
            await self.listener.handle_update(auth_update)
            self.assertEqual(self.controller.mode, "HIGH")

            # Unauthorized chat message (should be ignored)
            unauth_update = {
                "update_id": 2,
                "message": {
                    "chat": {"id": 999999999},
                    "text": "/stop",
                },
            }
            await self.listener.handle_update(unauth_update)
            self.assertEqual(self.controller.mode, "HIGH")  # Mode remained HIGH!

            # Authorized inline keyboard callback
            cb_update = {
                "update_id": 3,
                "callback_query": {
                    "id": "cb_123",
                    "from": {"id": 5220202988},
                    "message": {"chat": {"id": 5220202988}},
                    "data": "cmd_stop",
                },
            }
            await self.listener.handle_update(cb_update)
            self.assertEqual(self.controller.mode, "STOPPED")
            mock_answer.assert_called_with("12345:fake_token", "cb_123", "Command received")

        asyncio.run(_run_tests())


if __name__ == "__main__":
    unittest.main()
