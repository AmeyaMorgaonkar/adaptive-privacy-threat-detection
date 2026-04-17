"""
Global configuration — single source of truth for all thresholds,
paths, and tunable values across the application.
"""

import os
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_FILE = DATA_DIR / "app.log"

# ── Application ─────────────────────────────────────────────────────
APP_NAME = "Adaptive Privacy & Threat Detection System"
APP_VERSION = "0.1.0"
WINDOW_WIDTH = 1100
WINDOW_HEIGHT = 700

# ── Wi-Fi Analysis (Milestone 01) ───────────────────────────────────
SCAN_INTERVAL_SECONDS = 30            # How often to re-scan (seconds)
WIFI_SIGNAL_WARN_DBM = -70            # Warn below this signal
WIFI_SIGNAL_CRITICAL_DBM = -85        # Critical below this
EVIL_TWIN_RSSI_DELTA = 10             # dBm difference to flag twin
SUSPICIOUS_SIGNAL_THRESHOLD_DBM = -30 # Sudden RSSI spike from unknown AP
MAX_ALLOWED_OPEN_NETWORKS = 3         # Max open networks before alert
AUTO_DISCONNECT_ON_ROGUE = False      # Safety off by default
VPN_CONFIG_PATH = "configs/client.ovpn"
HARDENED_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]
AUTO_ENABLE_DNS_PROTECTION = True

# ── Threat Scoring (Milestone 02) ───────────────────────────────────
THREAT_SCORE_LOW = 30
THREAT_SCORE_MEDIUM = 60
THREAT_SCORE_HIGH = 85

# ── Behavioral Profiling (Milestone 03) ─────────────────────────────
ANOMALY_CONTAMINATION = 0.05
PROFILE_HISTORY_WINDOW = 100

# ── Web Tracker (Milestone 04) ──────────────────────────────────────
TRACKER_DB_PATH = DATA_DIR / "tracker.db"
DNS_CACHE_TTL_SECONDS = 300

# ── Logging (Milestone 05) ──────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 3
