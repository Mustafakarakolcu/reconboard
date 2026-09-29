"""Runtime configuration. Everything can be overridden with environment variables."""
from __future__ import annotations

import os
from pathlib import Path

APP_HOME = Path(os.environ.get("RECONBOARD_HOME", str(Path.home() / ".reconboard")))
DEFAULT_DB_URL = f"sqlite:///{APP_HOME / 'reconboard.db'}"

# Conservative defaults. "safe" is the default profile for every target.
PROFILES = {
    "safe": {"httpx_rate": 20, "httpx_threads": 10, "nmap_rate": 50},
    "normal": {"httpx_rate": 50, "httpx_threads": 25, "nmap_rate": 100},
    "aggressive": {"httpx_rate": 150, "httpx_threads": 50, "nmap_rate": 300},
}
MODES = ("passive", "passive_probe", "full")


def db_url() -> str:
    return os.environ.get("RECONBOARD_DB", DEFAULT_DB_URL)
