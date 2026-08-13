"""Telegram two-way long-polling listener and command router.

Listens for incoming Telegram commands (/high, /medium, /low, /stop, /status, /help)
and Inline Keyboard button taps using long-polling against Telegram getUpdates.
Controls the active scan loop mode on MonitorController.
"""

import asyncio
import time
from typing import Optional
import httpx

from telegram_alerter import (
    _esc,
    _send_message_async,
    answer_callback_query,
    build_inline_keyboard,
    register_bot_commands,
)
from utils import logger

log = logger.get_logger("telegram_listener")


class TelegramConflictError(Exception):
    """Raised when Telegram returns HTTP 409 Conflict (another getUpdates poller active)."""
    pass


def _build_help_message() -> str:
    return (
        "\U0001f916 *Feluda Remote Control Menu*\n\n"
        "Use the buttons below or send a command to control the active monitor scan:\n\n"
        "\U0001f534 `/high` \u2014 Alert on HIGH \\& CRITICAL risk \\(score \\>\\= 50\\)\n"
        "\U0001f7e1 `/medium` \u2014 Alert on MEDIUM\\+ risk \\(score \\>\\= 25\\)\n"
        "\U0001f7e2 `/low` \u2014 Alert on ALL findings \\(score \\>\\= 0\\)\n"
        "\u23f8 `/pause` \u2014 Stop scanning but keep this session connected\n"
        "\U0001f6d1 `/stop` \u2014 End this session completely \\(stops scan \\& disconnects\\)\n"
        "\U0001f517 `/chains` \u2014 Show correlated attack chains\n"
        "\U0001f4ca `/status` \u2014 Show current session status, uptime \\& alert count\n"
        "\u2753 `/help` \u2014 Show this menu"
    )


class TelegramListener:
    """Long-polling update listener for Telegram bot commands."""

    def __init__(self, token: str, allowed_chat_id: str, controller):
        self.token = token
        self.allowed_chat_id = str(allowed_chat_id).strip()
        self.controller = controller
        self.offset = 0
        self._running = False

    async def send_menu(self, title: str = None) -> bool:
        """Send the interactive command menu with Inline Keyboard buttons."""
        text = _build_help_message()
        if title:
            text = f"*{_esc(title)}*\n\n" + text
        return await _send_message_async(
            token=self.token,
            chat_id=self.allowed_chat_id,
            text=text,
            alert_type="menu",
            reply_markup=build_inline_keyboard(),
        )

    async def reply(self, text: str, include_keyboard: bool = False) -> bool:
        """Send a reply to the authorized chat ID."""
        reply_markup = build_inline_keyboard() if include_keyboard else None
        return await _send_message_async(
            token=self.token,
            chat_id=self.allowed_chat_id,
            text=text,
            alert_type="custom",
            reply_markup=reply_markup,
        )

    async def process_command(self, cmd_text: str) -> None:
        """Parse and execute a text slash command or inline button action."""
        cmd = cmd_text.strip().lower().split()[0].split("@")[0]  # normalize /high@botname -> /high

        if cmd in ("/high", "cmd_high"):
            msg = self.controller.set_mode("HIGH", min_score=50)
            await self.reply(f"\U0001f534 *Scan Mode set to HIGH*\n`{_esc(msg)}`")

        elif cmd in ("/medium", "cmd_medium"):
            msg = self.controller.set_mode("MEDIUM", min_score=25)
            await self.reply(f"\U0001f7e1 *Scan Mode set to MEDIUM*\n`{_esc(msg)}`")

        elif cmd in ("/low", "cmd_low"):
            msg = self.controller.set_mode("LOW", min_score=0)
            await self.reply(f"\U0001f7e2 *Scan Mode set to LOW*\n`{_esc(msg)}`")

        elif cmd in ("/pause", "cmd_pause"):
            msg = self.controller.pause_scan()
            await self.reply(
                f"\u23f8 *Scanning Paused*\n"
                f"`{_esc(msg)}` Send /high, /medium, or /low to resume, or /stop to end session completely\\."
            )

        elif cmd in ("/stop", "cmd_stop"):
            await self.reply(
                "\U0001f6d1 *Session Ended*\n"
                "`Feluda Telegram Remote Control session has ended. Run 'monitor --telegram-control' again to reconnect.`"
            )
            self.controller.stop_session()
            self.stop()

        elif cmd in ("/chains", "cmd_chains"):
            from database import database
            chains = database.fetch_correlated_chains(limit=5)
            if not chains:
                await self.reply("\U0001f517 *Correlated Attack Chains*\n`No correlated attack chains detected in database.`")
            else:
                lines = ["\U0001f517 *Correlated Attack Chains*"]
                for c in chains:
                    stages_str = ", ".join(c.get("stages_involved", []))
                    lines.append(
                        f"\u2022 *Target:* `{_esc(c.get('target_identity', ''))}`\n"
                        f"  *Stages:* `{_esc(stages_str)}` \\(Score: {_esc(str(c.get('final_risk_score')))} {_esc(str(c.get('final_risk_level')))}\\)\n"
                        f"  _{_esc(c.get('chain_narrative', ''))}_"
                    )
                await self.reply("\n\n".join(lines))

        elif cmd in ("/status", "cmd_status"):
            status_text = self.controller.get_status_markdown()
            await self.reply(status_text)

        elif cmd in ("/help", "cmd_help", "/start"):
            await self.send_menu()

        else:
            await self.reply(f"\u26a0 Unknown command `{_esc(cmd)}`\\. Send /help to see available commands\\.")

    async def handle_update(self, update: dict) -> None:
        """Extract command or callback from an update and verify authorization."""
        # 1. Text Message
        msg = update.get("message")
        if msg:
            chat_id = str(msg.get("chat", {}).get("id", ""))
            if chat_id != self.allowed_chat_id:
                log.warning("Ignored message from unauthorized chat_id=%s", chat_id)
                return
            text = msg.get("text", "")
            if text.startswith("/"):
                await self.process_command(text)
            return

        # 2. Inline Keyboard Callback Query
        cb = update.get("callback_query")
        if cb:
            cb_id = cb.get("id")
            from_id = str(cb.get("from", {}).get("id", ""))
            msg_chat_id = str(cb.get("message", {}).get("chat", {}).get("id", ""))
            
            if msg_chat_id and msg_chat_id != self.allowed_chat_id:
                log.warning("Ignored callback from unauthorized chat_id=%s", msg_chat_id)
                return

            if cb_id:
                answer_callback_query(self.token, cb_id, "Command received")

            cb_data = cb.get("data", "")
            if cb_data:
                await self.process_command(cb_data)

    async def poll_loop(self) -> None:
        """Long-polling loop calling getUpdates against Telegram Bot API."""
        self._running = True
        register_bot_commands(self.token)
        await self.send_menu("Feluda Monitor Listener Started")

        url = f"https://api.telegram.org/bot{self.token}/getUpdates"
        log.info("TelegramListener started (allowed_chat_id=%s)", self.allowed_chat_id)

        async with httpx.AsyncClient(timeout=35.0) as client:
            while self._running:
                try:
                    params = {"timeout": 25, "offset": self.offset}
                    resp = await client.get(url, params=params)

                    if resp.status_code == 409:
                        msg = "Telegram API 409 Conflict: Another process is already long-polling this Bot Token."
                        log.error(msg)
                        raise TelegramConflictError(msg)

                    if resp.status_code != 200:
                        log.warning("getUpdates HTTP %d: %s", resp.status_code, resp.text[:100])
                        await asyncio.sleep(5)
                        continue

                    data = resp.json()
                    if not data.get("ok"):
                        await asyncio.sleep(3)
                        continue

                    updates = data.get("result", [])
                    for u in updates:
                        self.offset = max(self.offset, u["update_id"] + 1)
                        await self.handle_update(u)

                except asyncio.CancelledError:
                    break
                except TelegramConflictError:
                    raise
                except Exception as exc:
                    log.error("TelegramListener poll error: %s", exc)
                    await asyncio.sleep(3)

    def stop(self) -> None:
        self._running = False
