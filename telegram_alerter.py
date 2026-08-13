"""Telegram alerting layer (Phase 7).

Sends push notifications to a Telegram chat when `monitor` (or
`persistence`-check cross-referencing) produces a finding at or above the
configured ``alert_threshold``.

Design notes
------------
* Credentials are read **only** from environment variables - never hardcoded,
  never logged.  Expected vars (same pattern as FELUDA_VT_API_KEY):
    FELUDA_BOT_TELEGRAM_TOKEN   -- bot HTTP token from @BotFather
    FELUDA_TELEGRAM_CHAT_ID     -- target chat / user numeric ID
* Sending is **async and fire-and-forget** from the monitor loop's perspective:
  ``enqueue_alert()`` puts work on an ``asyncio.Queue``; a background daemon
  thread drains that queue so the polling thread is never blocked.
* **Debounce / dedup** -- the same finding (keyed by a stable identity hash)
  will not re-alert inside a configurable cooldown window (default 30 min).
  Cooldown is per-session in-memory; no persistence required.
* Uses the Telegram Bot API ``sendMessage`` method directly via ``httpx``
  (already a project dependency from Phase 1 VT lookups) -- no third-party
  Telegram wrapper library needed.
* Telegram MarkdownV2 is used for light formatting (bold risk band, monospace
  process/path).  All special characters are escaped before sending.
* Errors from the Telegram API (bad token, bot blocked, rate limits) are
  logged and do **not** crash ``monitor``.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import time
from typing import Optional

from utils import logger

log = logger.get_logger("telegram_alerter")

# ---------------------------------------------------------------------------
# Credentials -- env var names
# ---------------------------------------------------------------------------

_ENV_TOKEN = "FELUDA_BOT_TELEGRAM_TOKEN"
_ENV_CHAT  = "FELUDA_TELEGRAM_CHAT_ID"

# Telegram Bot API endpoint (no third-party library)
_TG_API = "https://api.telegram.org/bot{token}/sendMessage"

# Project-root .env file (same location used by reputation_engine.py)
_ENV_FILE = __import__("pathlib").Path(__file__).resolve().parent / ".env"


# ---------------------------------------------------------------------------
# .env loader (mirrors reputation_engine._load_dotenv pattern)
# ---------------------------------------------------------------------------


def _load_dotenv() -> dict:
    """Best-effort .env loader for Telegram credentials.

    Reads FELUDA_BOT_TELEGRAM_TOKEN and FELUDA_TELEGRAM_CHAT_ID from the
    project-root .env file.  Never raises; a malformed file yields empty dict.
    Values are never logged.
    """
    _WANTED = {_ENV_TOKEN, _ENV_CHAT}
    if not _ENV_FILE.is_file():
        return {}
    try:
        out = {}
        for line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            if k in _WANTED:
                out[k] = v.strip().strip('"').strip("'")
        return out
    except OSError:
        return {}


import json
from pathlib import Path
from database import database

# ---------------------------------------------------------------------------
# User Settings Loader & Storage
# ---------------------------------------------------------------------------


def get_user_settings_path() -> Path:
    r"""Return path to user_settings.json.

    Prefers %LOCALAPPDATA%\Feluda\user_settings.json on Windows if available,
    falling back to database/user_settings.json.
    NOTE: Revisit once packaging establishes a unified per-user app data directory.
    """
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        p = Path(local_appdata) / "Feluda" / "user_settings.json"
    else:
        p = Path(__file__).resolve().parent / "database" / "user_settings.json"
    return p


def load_user_settings() -> dict:
    """Load user settings from user_settings.json."""
    p = get_user_settings_path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_user_settings(data: dict) -> bool:
    """Save/update key-values in user_settings.json."""
    p = get_user_settings_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        current = load_user_settings()
        current.update(data)
        p.write_text(json.dumps(current, indent=2), encoding="utf-8")
        return True
    except Exception as exc:
        log.error("Failed to save user settings: %s", exc)
        return False


def get_chat_id_info() -> tuple[Optional[str], str]:
    """Return (chat_id, source_name) where source_name is 'user_settings', '.env', or 'none'."""
    settings = load_user_settings()
    chat_id = (settings.get("telegram_chat_id") or "").strip()
    if chat_id:
        return chat_id, "user_settings"

    dotenv = _load_dotenv()
    env_chat = (os.environ.get(_ENV_CHAT, "") or dotenv.get(_ENV_CHAT, "")).strip()
    if env_chat:
        return env_chat, ".env"

    return None, "none"


def credentials_available() -> tuple[Optional[str], Optional[str]]:
    """Return (token, chat_id) checking user_settings first, then .env fallback."""
    dotenv = _load_dotenv()
    token = (os.environ.get(_ENV_TOKEN, "") or dotenv.get(_ENV_TOKEN, "")).strip() or None
    chat_id, _ = get_chat_id_info()
    return token, chat_id


def check_credentials(quiet: bool = False) -> bool:
    """Return True if both token and chat ID are set.

    If quiet is False print clear actionable errors.
    """
    token, chat_id = credentials_available()
    _, chat_source = get_chat_id_info()
    ok = True
    if not token:
        if not quiet:
            print(
                "[Feluda] --alert-telegram: " + _ENV_TOKEN + " is not set. "
                "Set it in .env or as a shell env var."
            )
        log.error("--alert-telegram: %s not configured", _ENV_TOKEN)
        ok = False
    if not chat_id:
        if not quiet:
            print(
                "[Feluda] --alert-telegram: Telegram Chat ID is not configured. "
                "Run 'python main.py setup-telegram' to connect your Telegram account, "
                "or set " + _ENV_CHAT + " in .env."
            )
        log.error("--alert-telegram: chat_id not configured")
        ok = False
    return ok


# ---------------------------------------------------------------------------
# Debounce / dedup tracker
# ---------------------------------------------------------------------------


class _DebounceTracker:
    """In-memory cooldown store.  Thread-safe for single-producer pattern."""

    def __init__(self, cooldown_seconds: int = 1800):
        self._cooldown = cooldown_seconds
        self._last_alerted: dict = {}  # identity_key -> monotonic timestamp

    def should_alert(self, identity_key: str) -> bool:
        """Return True if this key has not been alerted within the cooldown."""
        last = self._last_alerted.get(identity_key, 0.0)
        return (time.monotonic() - last) >= self._cooldown

    def mark_alerted(self, identity_key: str) -> None:
        self._last_alerted[identity_key] = time.monotonic()

    def reset(self) -> None:
        """Clear all cooldown state (used between monitor sessions)."""
        self._last_alerted.clear()

    @property
    def cooldown_seconds(self) -> int:
        return self._cooldown


# ---------------------------------------------------------------------------
# Message formatting helpers (Telegram MarkdownV2)
# ---------------------------------------------------------------------------

# Characters that must be escaped in MarkdownV2 per Telegram docs
_MDV2_SPECIAL = re.compile(r"([_\*\[\]\(\)\~\`\>\#\+\-\=\|\{\}\.\!\\])")


def _esc(text: str) -> str:
    """Escape a plain-text string for Telegram MarkdownV2."""
    return _MDV2_SPECIAL.sub(r"\\\1", str(text))


def _risk_emoji(level: str) -> str:
    return {
        "LOW":      "\U0001f7e2",  # green circle
        "MEDIUM":   "\U0001f7e1",  # yellow circle
        "HIGH":     "\U0001f534",  # red circle
        "CRITICAL": "\U0001f480",  # skull
    }.get((level or "").upper(), "\u26aa")


def _truncate(s: str, n: int = 60) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def format_connection_alert(rec: dict) -> str:
    """Format a connection-scan record as a Telegram MarkdownV2 message."""
    level  = (rec.get("risk_level") or "UNKNOWN").upper()
    score  = rec.get("risk_score", 0)
    proc_info = rec.get("proc_info") or {}
    proc   = _truncate(proc_info.get("name") or "unknown", 40)
    exe    = _truncate(proc_info.get("exe") or "", 55)
    pid    = str(rec.get("pid") or "?")
    remote = str(rec.get("remote_ip") or "?") + ":" + str(rec.get("remote_port") or "?")
    sigs   = rec.get("signals") or rec.get("reasons") or []

    emoji = _risk_emoji(level)
    lines = [
        "\U0001f6a8 *Feluda Alert* \u2014 " + emoji + " *" + _esc(level) + "* \\(score " + _esc(str(score)) + "\\)",
        "*Process:* `" + _esc(proc) + "` \\(PID " + _esc(pid) + "\\)",
    ]
    if exe:
        lines.append("*Path:* `" + _esc(exe) + "`")
    lines.append("*Remote:* `" + _esc(remote) + "`")
    # top 3 signals only -- Telegram renders long messages awkwardly
    for sig in sigs[:3]:
        lines.append("  \u2022 " + _esc(_truncate(sig, 80)))
    if len(sigs) > 3:
        lines.append("  \\(\\+" + str(len(sigs) - 3) + " more signals\\)")
    return "\n".join(lines)


def format_persistence_alert(entry: dict) -> str:
    """Format a persistence-scan entry as a Telegram MarkdownV2 message."""
    pts    = entry.get("risk_points", 0)
    src    = _truncate(entry.get("source_type") or "persistence", 30)
    loc    = _truncate(entry.get("location_detail") or "", 50)
    target = _truncate(
        entry.get("resolved_exe_path") or entry.get("raw_command") or "", 55
    )
    sigs = entry.get("triggered_signals") or []

    lines = [
        "\U0001f6a8 *Feluda Persistence Alert* \\(score " + _esc(str(pts)) + "\\)",
        "*Source:* `" + _esc(src) + "`",
        "*Entry:* `" + _esc(loc) + "`",
    ]
    if target:
        lines.append("*Target:* `" + _esc(target) + "`")
    for sig in sigs[:3]:
        lines.append("  \u2022 " + _esc(_truncate(sig, 80)))
    if len(sigs) > 3:
        lines.append("  \\(\\+" + str(len(sigs) - 3) + " more signals\\)")
    return "\n".join(lines)


def _sample_alert_message() -> str:
    """A fixed sample message for --test-alert."""
    return (
        "\U0001f6a8 *Feluda Test Alert*\n"
        "*Process:* `suspicious\\.exe` \\(PID 1234\\)\n"
        "*Path:* `C:\\Windows\\Temp\\suspicious\\.exe`\n"
        "*Remote:* `1\\.2\\.3\\.4:4444`\n"
        "*Risk:* \U0001f480 *CRITICAL* \\(score 95\\)\n"
        "  \u2022 external\\_unknown\\_process\n"
        "  \u2022 unusual\\_remote\\_port\n"
        "  \u2022 suspicious\\_location\n"
        "_This is a test message \u2014 no real threat detected\\._"
    )


# ---------------------------------------------------------------------------
# Async sender core
# ---------------------------------------------------------------------------


async def _send_message_async(
    token: str,
    chat_id: str,
    text: str,
    alert_type: str = "custom",
    risk_level: str = "INFO",
    risk_score: int = 0,
    details: str = "",
) -> bool:
    """POST one message to the Telegram Bot API. Returns True on success.

    Handles transient errors gracefully: logs them and returns False.
    Never raises -- the caller should never crash over a failed notification.
    """
    try:
        import httpx
    except ImportError:
        log.error("httpx not available -- cannot send Telegram alert")
        return False

    url = _TG_API.format(token=token)
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2",
        "disable_web_page_preview": True,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
        if resp.status_code == 200:
            log.info("Telegram alert sent (chat_id=%s)", chat_id)
            database.record_telegram_alert(
                chat_id=chat_id,
                alert_type=alert_type,
                risk_level=risk_level,
                risk_score=risk_score,
                details=details or text[:150],
            )
            return True
        body = resp.text[:200]
        log.error(
            "Telegram API error %d for chat %s: %s",
            resp.status_code, chat_id, body,
        )
        return False
    except Exception as exc:
        log.error("Telegram send failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# TelegramAlerter -- the public interface consumed by monitor
# ---------------------------------------------------------------------------


class TelegramAlerter:
    """Session-scoped alerter: credential validation, debounce, async queue.

    Lifecycle::

        alerter = TelegramAlerter(cooldown_seconds=1800)
        if not alerter.configure():        # checks env vars, prints errors
            # feature disabled gracefully, monitor keeps running
            pass
        alerter.start()                    # starts background daemon thread
        alerter.enqueue_connection_alert(rec)
        alerter.enqueue_persistence_alert(entry)
        alerter.stop()                     # drains queue and shuts down
    """

    def __init__(
        self,
        cooldown_seconds: int = 1800,
        alert_threshold: int = 50,
    ):
        self._threshold   = alert_threshold
        self._tracker     = _DebounceTracker(cooldown_seconds)
        self._token: Optional[str]   = None
        self._chat_id: Optional[str] = None
        self._enabled     = False
        self._queue: Optional[asyncio.Queue] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread = None

    # ------------------------------------------------------------------ setup

    def configure(self) -> bool:
        """Validate credentials; return True when the alerter is usable."""
        token, chat_id = credentials_available()
        if not token or not chat_id:
            check_credentials(quiet=False)
            return False
        self._token   = token
        self._chat_id = chat_id
        self._enabled = True
        return True

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------------ start/stop

    def start(self) -> None:
        """Launch a daemon thread running an asyncio event loop for the sender."""
        if not self._enabled:
            return
        import threading

        self._loop  = asyncio.new_event_loop()
        self._queue = asyncio.Queue()

        def _run_loop(loop):
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._drain())

        self._thread = threading.Thread(
            target=_run_loop, args=(self._loop,), daemon=True, name="feluda-tg"
        )
        self._thread.start()
        log.info(
            "Telegram alerter started (threshold=%d, cooldown=%ds)",
            self._threshold, self._tracker.cooldown_seconds,
        )

    def stop(self) -> None:
        """Signal the drain loop to exit, wait for it, and update scan_stop in DB."""
        if self._loop and self._queue:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, None)  # sentinel
        if self._thread:
            self._thread.join(timeout=5)
        if self._chat_id:
            database.record_telegram_scan_stop(self._chat_id)

    # ------------------------------------------------------------------ enqueueing

    def _make_connection_key(self, rec: dict) -> str:
        pid   = str(rec.get("pid") or "")
        rip   = str(rec.get("remote_ip") or "")
        rport = str(rec.get("remote_port") or "")
        exe   = str(rec.get("exe_path") or "")
        raw   = "conn:" + pid + ":" + rip + ":" + rport + ":" + exe
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _make_persistence_key(self, entry: dict) -> str:
        src = str(entry.get("source_type") or "")
        loc = str(entry.get("location_detail") or "")
        exe = str(entry.get("resolved_exe_path") or "")
        raw = "persist:" + src + ":" + loc + ":" + exe
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def enqueue_connection_alert(self, rec: dict) -> None:
        """Submit a connection-scan record for alerting if it clears threshold+debounce."""
        if not self._enabled or self._queue is None:
            return
        score = rec.get("risk_score", 0)
        if score < self._threshold:
            return
        key = self._make_connection_key(rec)
        if not self._tracker.should_alert(key):
            return
        self._tracker.mark_alerted(key)
        text = format_connection_alert(rec)
        proc_info = rec.get("proc_info") or {}
        proc_name = proc_info.get("name") or "unknown"
        meta = {
            "text": text,
            "alert_type": "connection",
            "risk_level": (rec.get("risk_level") or "UNKNOWN").upper(),
            "risk_score": score,
            "details": f"Process: {proc_name} (PID {rec.get('pid')}) -> {rec.get('remote_ip')}:{rec.get('remote_port')}",
        }
        self._loop.call_soon_threadsafe(self._queue.put_nowait, meta)

    def enqueue_persistence_alert(self, entry: dict) -> None:
        """Submit a persistence entry for alerting if it clears threshold+debounce."""
        if not self._enabled or self._queue is None:
            return
        pts = entry.get("risk_points", 0)
        if pts < self._threshold:
            return
        key = self._make_persistence_key(entry)
        if not self._tracker.should_alert(key):
            return
        self._tracker.mark_alerted(key)
        text = format_persistence_alert(entry)
        meta = {
            "text": text,
            "alert_type": "persistence",
            "risk_level": "HIGH" if pts >= 40 else "MEDIUM",
            "risk_score": pts,
            "details": f"Persistence: {entry.get('source_type')} - {entry.get('location_detail')}",
        }
        self._loop.call_soon_threadsafe(self._queue.put_nowait, meta)

    def enqueue_raw(self, text: str) -> None:
        """Send a pre-formatted message (used by --test-alert)."""
        if not self._enabled or self._queue is None:
            log.error("enqueue_raw called but alerter not started")
            return
        meta = {
            "text": text,
            "alert_type": "test",
            "risk_level": "INFO",
            "risk_score": 0,
            "details": "Raw / test alert",
        }
        self._loop.call_soon_threadsafe(self._queue.put_nowait, meta)

    # ------------------------------------------------------------------ async drain

    async def _drain(self) -> None:
        """Async coroutine: dequeue messages and POST them one by one."""
        while True:
            item = await self._queue.get()
            if item is None:   # sentinel -- shut down
                break
            if isinstance(item, dict):
                await _send_message_async(
                    self._token,
                    self._chat_id,
                    item["text"],
                    alert_type=item.get("alert_type", "connection"),
                    risk_level=item.get("risk_level", "INFO"),
                    risk_score=item.get("risk_score", 0),
                    details=item.get("details", ""),
                )
            else:
                await _send_message_async(self._token, self._chat_id, str(item))
            self._queue.task_done()


# ---------------------------------------------------------------------------
# Standalone send for --test-alert
# ---------------------------------------------------------------------------


def send_test_alert_sync() -> bool:
    """Send a sample alert immediately (blocking).

    Meant for the ``--test-alert`` flag: validates credentials work end-to-end
    without waiting for a real finding.  Returns True on success.
    """
    token, chat_id = credentials_available()
    if not token or not chat_id:
        check_credentials(quiet=False)
        return False

    async def _go():
        return await _send_message_async(token, chat_id, _sample_alert_message())

    return asyncio.run(_go())
