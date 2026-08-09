"""Config loader for Feluda.

Loads config/rules.json and exposes a small Settings accessor. If the config
file is missing or malformed, built-in defaults are used so a scan never
crashes because of configuration.
"""

import copy
import json
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.json"

DEFAULTS = {
    "well_known_ports": {},
    "unusual_remote_ports": [],
    "suspicious_location_substrings": [],
    "normal_location_substrings": [],
    "system_process_names": [],
    "rule_weights": {},
    "thresholds": {
        "multiple_external_connections_min": 3,
        "repeated_connection_min_scans": 3,
        "hash_min_risk_score": 25,
        "alert_min_risk_score": 25,
    },
    "risk_bands": {
        "LOW": [0, 24],
        "MEDIUM": [25, 49],
        "HIGH": [50, 74],
        "CRITICAL": [75, 100],
    },
    "monitor": {"poll_interval_seconds": 5},
    "export": {"directory": "exports"},
}


class Settings:
    """Thin wrapper around the merged config dict."""

    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getitem__(self, key):
        return self._data[key]


def load_config(path=None):
    """Load rules.json, falling back to defaults on any error."""
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    data = copy.deepcopy(DEFAULTS)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            for key, value in user.items():
                if key.startswith("_"):
                    continue
                if isinstance(value, dict) and isinstance(data.get(key), dict):
                    data[key].update(value)
                else:
                    data[key] = value
    except FileNotFoundError:
        print(f"[Feluda] config not found at {path}; using built-in defaults.")
    except json.JSONDecodeError as exc:
        print(f"[Feluda] config parse error ({exc}); using built-in defaults.")
    return Settings(data)


_DEFAULT_SETTINGS = None


def settings():
    """Module-level cached settings."""
    global _DEFAULT_SETTINGS
    if _DEFAULT_SETTINGS is None:
        _DEFAULT_SETTINGS = load_config()
    return _DEFAULT_SETTINGS
