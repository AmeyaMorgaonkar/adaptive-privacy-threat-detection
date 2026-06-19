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
WIFI_SCAN_INTERVAL_SECONDS = 90       # WiFi hardware scan interval (heavier; needs location permission)
WIFI_SIGNAL_WARN_DBM = -70            # Warn below this signal
WIFI_SIGNAL_CRITICAL_DBM = -85        # Critical below this
EVIL_TWIN_RSSI_DELTA = 10             # dBm difference to flag twin
SUSPICIOUS_SIGNAL_THRESHOLD_DBM = -30 # Sudden RSSI spike from unknown AP
MAX_ALLOWED_OPEN_NETWORKS = 3         # Max open networks before alert
AUTO_DISCONNECT_ON_ROGUE = False      # Safety off by default
VPN_CONFIG_DIR = BASE_DIR / "assets"        # Directory containing .ovpn files
VPN_CONFIG_PATH = VPN_CONFIG_DIR             # Legacy alias (now a directory)
VPN_AUTH_FILE = VPN_CONFIG_DIR / "credentials.txt"  # username\npassword for auth-user-pass
OPENVPN_BINARY = r"C:\Program Files\OpenVPN\bin\openvpn.exe"
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
AUTO_PROTECTION_THREAT_SCORE_THRESHOLD = 50  # Start VPN/DNS hardening at this score

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

# ── Behavioral Profiling (Milestone 04) ─────────────────────────────
BASELINE_LEARNING_MINUTES = 5
SNAPSHOT_INTERVAL_SECONDS = 5
Z_SCORE_THRESHOLD = 3.0

# Process thresholds
HIGH_CPU_PROCESS_THRESHOLD = 40.0       # %
MAX_CONNECTIONS_PER_PROCESS = 20
PROCESS_CHURN_THRESHOLD = 10            # new processes per snapshot interval
BASELINE_PATH = DATA_DIR / "baseline_profile.json"

# Known safe process list (supplement with OS defaults)
KNOWN_SAFE_PROCESSES = [
    # Windows core
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "dwm.exe", "taskhostw.exe", "sihost.exe", "RuntimeBroker.exe",
    "SearchHost.exe", "StartMenuExperienceHost.exe", "ctfmon.exe",
    "conhost.exe", "fontdrvhost.exe", "WmiPrvSE.exe",
    "SecurityHealthSystray.exe", "SecurityHealthService.exe",
    "MsMpEng.exe", "NisSrv.exe", "spoolsv.exe", "dllhost.exe",
    "audiodg.exe", "SearchIndexer.exe", "ShellExperienceHost.exe",
    "TextInputHost.exe", "SystemSettingsBroker.exe", "LockApp.exe",
    "UserOOBEBroker.exe", "WidgetService.exe", "Widgets.exe",
    # Python / dev (safe during development)
    "python.exe", "pythonw.exe", "python3.exe", "Code.exe",
    "WindowsTerminal.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    # Linux / macOS (cross-platform compat)
    "systemd", "init", "kthreadd", "Finder", "launchd",
    "WindowServer", "loginwindow",
]

# EMA smoothing factor for adaptive baseline (0 < α ≤ 1, lower = slower)
EMA_ALPHA = 0.1
PROFILE_HISTORY_WINDOW = 100            # Also used by wifi_analysis signal history

# ── Web Tracker (Milestone 05) ──────────────────────────────────────
TRACKER_BLOCKLIST_PATH = DATA_DIR / "tracker_blocklist.json"
DNS_CAPTURE_INTERVAL_SECONDS = 10
HIGH_VOLUME_TRACKER_KB = 500          # Volume bonus kicks in above this

FINGERPRINT_CONFIDENCE_THRESHOLD = 0.7

# Per-category base scores (0–100)
TRACKER_BASE_SCORES = {
    "Analytics":    30,
    "Advertising":  55,
    "Social":       50,
    "Telemetry":    65,
    "Fingerprint":  85,
}

# Per-category weights for weighted web_score aggregation
TRACKER_CATEGORY_WEIGHTS = {
    "Analytics":    0.10,
    "Advertising":  0.20,
    "Social":       0.15,
    "Telemetry":    0.25,
    "Fingerprint":  0.30,
}

# Severity multipliers applied to individual tracker scores
TRACKER_SEVERITY_MULTIPLIERS = {
    "LOW":    0.5,
    "MEDIUM": 1.0,
    "HIGH":   1.5,
}

# Alert thresholds per category (individual category score)
TRACKER_ALERT_THRESHOLDS = {
    "Analytics":    40,
    "Advertising":  50,
    "Social":       50,
    "Telemetry":    55,
    "Fingerprint":  40,
}

# Multi-category escalation: fire unified alert if this many categories
# exceed their individual threshold simultaneously
TRACKER_MULTI_CATEGORY_ESCALATION_COUNT = 3

# Known fingerprinting CDN/script endpoints
FINGERPRINT_KNOWN_ENDPOINTS = [
    "cdn.jsdelivr.net/npm/@fingerprintjs",
    "fpcdn.io",
    "fpjs.io",
    "openfpcdn.io",
    "api.fpjs.io",
    "cdn.cookielaw.org",
    "cdn.krxd.net",
    "cdn.segment.io",
    "cdn.amplitude.com",
]

# DNS providers with DNS-over-HTTPS (DoH) templates for encrypted resolution
ENCRYPTED_DNS_PROVIDERS = {
    "Cloudflare": {
        "servers": ["1.1.1.1", "1.0.0.1"],
        "doh_template": "https://cloudflare-dns.com/dns-query",
        "description": "Fast, privacy-first DNS (no logging)",
    },
    "Quad9": {
        "servers": ["9.9.9.9", "149.112.112.112"],
        "doh_template": "https://dns.quad9.net/dns-query",
        "description": "Malware-blocking + privacy DNS",
    },
    "Google": {
        "servers": ["8.8.8.8", "8.8.4.4"],
        "doh_template": "https://dns.google/dns-query",
        "description": "Google Public DNS with DoH",
    },
    "OpenDNS": {
        "servers": ["208.67.222.222", "208.67.220.220"],
        "doh_template": "https://doh.opendns.com/dns-query",
        "description": "Cisco OpenDNS with content filtering",
    },
    "NextDNS": {
        "servers": ["45.90.28.0", "45.90.30.0"],
        "doh_template": "https://dns.nextdns.io",
        "description": "Customizable privacy DNS + ad blocking",
    },
}
DEFAULT_DNS_PROVIDER = "Cloudflare"         # Used for auto-switching on threats
AUTO_DNS_SWITCH_ENABLED = True              # Auto-switch DNS on threat detection

# Legacy alias — kept for backward compatibility with existing code
HARDENED_DNS_PROVIDERS = {
    k.lower(): v["servers"] for k, v in ENCRYPTED_DNS_PROVIDERS.items()
}

# Per-category web alert cooldowns (seconds)
WEB_CATEGORY_COOLDOWNS = {
    "web_analytics_alert":    600,
    "web_advertising_alert":  300,
    "web_social_alert":       300,
    "web_telemetry_alert":    120,
    "web_fingerprint_alert":  120,
    "web_multi_escalation":   60,
}

# ── Appearance (Milestone 03) ───────────────────────────────────────
APPEARANCE_MODE = "dark"          # "light" | "dark" | "system"
GLASSMORPHISM_ENABLED = True      # Floating-glass card effect
GLASS_BACKGROUND_BLUR = False     # Blurred background in dark+glass mode

# ── Logging (Milestone 06) ──────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 5
LOG_DIR = DATA_DIR / "logs"
LOG_TO_CONSOLE = True

# ── Reporting & Hardening (Milestone 06) ────────────────────────────
REPORT_DIR = DATA_DIR / "reports"
REPORT_HISTORY_MAX = 50           # Max stored reports
REPORT_FILENAME_FMT = "report_{ts}.{ext}"  # ts = %Y%m%d_%H%M%S

