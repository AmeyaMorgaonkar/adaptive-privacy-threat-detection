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
SCAN_INTERVAL_SECONDS = 10            # How often to re-scan (seconds)
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
# Scoring weights (must sum to 1.0)
SCORE_WEIGHT_WIFI = 0.35
SCORE_WEIGHT_BEHAVIORAL = 0.40
SCORE_WEIGHT_WEB = 0.25

# Tier thresholds (upper bound inclusive)
TIER_SAFE_MAX = 24
TIER_LOW_MAX = 49
TIER_ELEVATED_MAX = 74
TIER_HIGH_MAX = 89
# Score > 89 → Critical

# Dashboard refresh rate (consumed by Milestone 03)
DASHBOARD_REFRESH_MS = 1000           # UI poll interval (ms)
MONITOR_INTERVAL_SECONDS = SCAN_INTERVAL_SECONDS  # Background scan interval
SCORE_HISTORY_LENGTH = 300            # ~5 minutes at 1s intervals

# Response cooldowns (seconds) — per-action deduplication windows
RESPONSE_COOLDOWNS = {
    "wifi_alert_50":        300,   # 5 min
    "wifi_alert_75":        120,
    "wifi_alert_90":        60,    # 1 min
    "behavioral_alert_50":  120,
    "behavioral_alert_75":  60,
    "behavioral_alert_90":  30,
    "web_alert_40":         600,   # 10 min — less urgent
    "web_alert_65":         300,
    "web_alert_85":         120,
    "unified_badge_50":     300,
    "unified_alert_75":     180,
    "unified_alert_90":     60,
}

# ── Behavioral Profiling (Milestone 03) ─────────────────────────────
ANOMALY_CONTAMINATION = 0.05
PROFILE_HISTORY_WINDOW = 100

# ── Web Tracker (Milestone 04) ──────────────────────────────────────
TRACKER_DB_PATH = DATA_DIR / "tracker.db"
DNS_CACHE_TTL_SECONDS = 300

# ── Appearance (Milestone 03) ───────────────────────────────────────
APPEARANCE_MODE = "dark"          # "light" | "dark" | "system"
GLASSMORPHISM_ENABLED = True      # Floating-glass card effect
GLASS_BACKGROUND_BLUR = False     # Blurred background in dark+glass mode

# ── Logging (Milestone 05) ──────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 3
