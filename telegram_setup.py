"""Guided CLI Setup and Status commands for Telegram recipient configuration.

Handles:
- `python main.py setup-telegram` (Guided setup flow)
- `python main.py telegram-status` (Displays recipient status & DB stats)
- `python main.py telegram-reset` (Resets user recipient setting)
"""

import sys
import json
import httpx
from database import database
from telegram_alerter import (
    _ENV_TOKEN,
    _TG_API,
    credentials_available,
    get_chat_id_info,
    load_user_settings,
    save_user_settings,
    send_test_alert_sync,
)
from utils import logger

log = logger.get_logger("telegram_setup")


def _fetch_bot_me(token: str) -> dict | None:
    """Fetch bot details from Telegram Bot API getMe method."""
    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        resp = httpx.get(url, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok"):
                return data.get("result")
    except Exception as exc:
        log.error("getMe failed: %s", exc)
    return None


def _fetch_recent_chats(token: str) -> list[dict]:
    """Fetch recent unique chats from Telegram Bot API getUpdates method."""
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    try:
        resp = httpx.get(url, timeout=10.0)
        if resp.status_code != 200:
            log.error("getUpdates HTTP %d: %s", resp.status_code, resp.text[:200])
            return []
        data = resp.json()
        if not data.get("ok"):
            return []
        
        unique_chats = {}
        for item in data.get("result", []):
            chat = None
            if "message" in item:
                chat = item["message"].get("chat")
            elif "edited_message" in item:
                chat = item["edited_message"].get("chat")
            elif "channel_post" in item:
                chat = item["channel_post"].get("chat")
            elif "callback_query" in item and "message" in item["callback_query"]:
                chat = item["callback_query"]["message"].get("chat")
            
            if chat and "id" in chat:
                unique_chats[str(chat["id"])] = chat

        return list(unique_chats.values())
    except Exception as exc:
        log.error("getUpdates failed: %s", exc)
        return []


def setup_telegram_cli() -> None:
    """Guided interactive setup to connect a Telegram account as alert recipient."""
    print("\n" + "=" * 70)
    print("           FELUDA — TELEGRAM RECIPIENT SETUP")
    print("=" * 70 + "\n")

    token, _ = credentials_available()
    if not token:
        print("[!] Developer Setup Required: Bot Token is missing.")
        print(f"    '{_ENV_TOKEN}' is not configured in .env or environment variables.\n")
        print("    How to get a Bot Token (One-time setup):")
        print("      1. Open Telegram app and search for @BotFather.")
        print("      2. Send '/newbot' and follow the instructions.")
        print("      3. Copy the Bot API Token provided by BotFather.")
        print("      4. Add 'FELUDA_BOT_TELEGRAM_TOKEN=<your_token>' to your .env file.")
        print("\nExiting setup.")
        sys.exit(1)

    print("[1/4] Verifying Bot Token...")
    bot_info = _fetch_bot_me(token)
    if not bot_info:
        print("[!] Unable to verify Bot Token with Telegram API.")
        print("    Please double-check your FELUDA_BOT_TELEGRAM_TOKEN in .env.")
        sys.exit(1)

    bot_username = bot_info.get("username") or "your_bot"
    bot_name = bot_info.get("first_name") or "Feluda Bot"
    print(f"     ✓ Bot Identified: @{bot_username} ({bot_name})\n")

    print("[2/4] Activation Instructions:")
    print(f"      1. Open Telegram on your phone or desktop.")
    print(f"      2. Search for @{bot_username} (or open https://t.me/{bot_username}).")
    print(f"      3. Send any message to the bot (e.g., 'hi' or '/start').\n")

    input(f"--> Press Enter once you have sent a message to @{bot_username}...")

    print("\n[3/4] Fetching recent messages via getUpdates...")
    chats = _fetch_recent_chats(token)

    if not chats:
        print("\n[!] No messages found from your Telegram account yet.")
        print(f"    Please make sure you searched for @{bot_username} in Telegram,")
        print(f"    sent it a message, and then re-run:")
        print("      python main.py setup-telegram")
        sys.exit(1)

    selected_chat = None
    if len(chats) == 1:
        selected_chat = chats[0]
    else:
        print(f"\nFound {len(chats)} recent Telegram chats:\n")
        for idx, c in enumerate(chats, 1):
            chat_id = str(c["id"])
            title = c.get("title") or ""
            fname = c.get("first_name") or ""
            lname = c.get("last_name") or ""
            uname = f"@{c['username']}" if c.get("username") else ""
            display_name = f"{fname} {lname}".strip() or title or uname or chat_id
            print(f"  [{idx}] {display_name} {uname} (ID: {chat_id})")

        while True:
            try:
                choice = input(f"\nSelect recipient [1-{len(chats)}]: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(chats):
                    selected_chat = chats[idx]
                    break
            except (ValueError, KeyboardInterrupt):
                pass
            print("Invalid selection. Try again.")

    chat_id = str(selected_chat["id"])
    fname = selected_chat.get("first_name") or ""
    lname = selected_chat.get("last_name") or ""
    uname = selected_chat.get("username") or ""
    title = selected_chat.get("title") or ""
    chat_name = f"{fname} {lname}".strip() or title or (f"@{uname}" if uname else chat_id)

    # Check existing setting & confirm overwrite if present
    existing_chat, existing_src = get_chat_id_info()
    if existing_chat and existing_src == "user_settings" and existing_chat != chat_id:
        confirm = input(f"\nExisting Chat ID '{existing_chat}' is already configured. Overwrite? (y/N): ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Setup cancelled. Retaining existing configuration.")
            return

    # Save to user_settings.json
    save_data = {
        "telegram_chat_id": chat_id,
        "telegram_chat_name": chat_name,
        "telegram_chat_username": f"@{uname}" if uname else "",
    }
    if save_user_settings(save_data):
        print(f"\n[4/4] ✓ Recipient Configured Successfully!")
        print(f"      Chat ID: {chat_id}")
        print(f"      Name:    {chat_name}")
        print("\nSending confirmation test alert to your Telegram...")
        
        # Fire immediate test alert
        if send_test_alert_sync():
            print("      ✓ Confirmation message delivered! Check your Telegram app.\n")
        else:
            print("      [!] Failed to send test alert. Please verify internet connection.\n")
    else:
        print("[!] Failed to save settings to user_settings.json.")


def show_telegram_status_cli() -> None:
    """Display currently configured Telegram recipient, active source, and DB stats."""
    print("\n" + "=" * 70)
    print("           FELUDA — TELEGRAM CONFIGURATION STATUS")
    print("=" * 70 + "\n")

    token, chat_id = credentials_available()
    _, chat_source = get_chat_id_info()
    settings = load_user_settings()

    # Bot Info
    if token:
        bot_info = _fetch_bot_me(token)
        if bot_info:
            print(f"  Bot Account:   @{bot_info.get('username')} ({bot_info.get('first_name')}) [Token configured]")
        else:
            print("  Bot Account:   [Token set, but API validation failed]")
    else:
        print(f"  Bot Account:   [NOT CONFIGURED] ({_ENV_TOKEN} missing in .env)")

    # Chat Recipient Info
    if chat_id:
        source_label = "user_settings.json (Primary)" if chat_source == "user_settings" else ".env fallback (Legacy)"
        print(f"  Active Chat:   {chat_id}")
        if settings.get("telegram_chat_name"):
            print(f"  Recipient:     {settings.get('telegram_chat_name')} {settings.get('telegram_chat_username', '')}")
        print(f"  Config Source: {source_label}")
    else:
        print("  Active Chat:   [NOT CONFIGURED] (Run 'python main.py setup-telegram')")

    # Database Statistics
    if chat_id:
        stats = database.fetch_telegram_stats(chat_id)
        if stats:
            print("\n  --- Recipient Database Statistics ---")
            print(f"  Total Alerts Sent:  {stats.get('total_alerts_sent', 0)}")
            print(f"  Last Alert Sent:    {stats.get('last_alert_at') or 'Never'}")
            print(f"  Last Scan Stopped:  {stats.get('last_scan_ended_at') or 'Never'}")
            print(f"  Record Updated:     {stats.get('updated_at') or '-'}")
        else:
            print("\n  --- Recipient Database Statistics ---")
            print("  Total Alerts Sent:  0 (No alerts logged for this Chat ID yet)")

    print("\n" + "=" * 70 + "\n")


def reset_telegram_cli() -> None:
    """Reset the user-configured Telegram Chat ID setting."""
    settings = load_user_settings()
    current_chat = settings.get("telegram_chat_id")
    if not current_chat:
        print("[Feluda] No user-configured Telegram Chat ID found in user_settings.json.")
        return

    confirm = input(f"Are you sure you want to remove configured Chat ID '{current_chat}'? (y/N): ").strip().lower()
    if confirm in ("y", "yes"):
        # Remove telegram keys
        settings.pop("telegram_chat_id", None)
        settings.pop("telegram_chat_name", None)
        settings.pop("telegram_chat_username", None)
        
        # Save back
        from telegram_alerter import get_user_settings_path
        p = get_user_settings_path()
        try:
            p.write_text(json.dumps(settings, indent=2), encoding="utf-8")
            print("✓ Telegram Chat ID setting cleared from user_settings.json.")
            
            _, fallback_src = get_chat_id_info()
            if fallback_src == ".env":
                print("  Note: .env fallback 'FELUDA_TELEGRAM_CHAT_ID' is still active.")
            else:
                print("  Telegram alerting is now unconfigured.")
        except Exception as exc:
            print(f"[!] Failed to write settings: {exc}")
    else:
        print("Reset cancelled.")
