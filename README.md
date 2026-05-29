# Adaptive Privacy & Threat Detection System

> **Sentinel** — A real-time desktop security dashboard that monitors Wi-Fi networks, profiles system behaviour, tracks web privacy, and generates actionable hardening recommendations.

Built with **PySide6** for the desktop UI, **Python 3.10+** for all analysis modules, and a modular pipeline that scores, alerts, and reports threats from a single interface.

---

## Features

| Module | Description |
|--------|-------------|
| **Wi-Fi Analysis** | Scans nearby networks, detects rogue APs, evil twins, open/WEP networks, signal anomalies |
| **Behavioural Profiling** | Baseline learning + z-score anomaly detection on CPU, memory, process counts |
| **Web Tracker Detection** | DNS/connection monitoring for tracker domains across 5 categories + browser fingerprinting heuristics |
| **Unified Threat Scoring** | Weighted aggregation (WiFi 35%, Behavioural 40%, Web 25%) into 0–100 score with severity tiers |
| **Auto-Responder** | Automated alerts, VPN triggers, DNS hardening, and per-module escalation |
| **Privacy Reports** | Exportable session reports (JSON/TXT) with hardening recommendations |
| **Live Dashboard** | Glassmorphism PySide6 UI with real-time charts, gauges, and module-specific pages |

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **pip** (or any Python package manager)
- **Windows 10+** (primary target), Linux/macOS supported with reduced Wi-Fi features

### Installation

```bash
# Clone the repository
git clone https://github.com/AmeyaMorgaonkar/adaptive-privacy-threat-detection
cd "Adaptive Privacy & Threat Detection System"

# Create a virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (macOS / Linux)
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run

```bash
python main.py
```

The Sentinel dashboard will launch with live monitoring. Navigate between pages using the left sidebar.

### Run Tests

```bash
python -m pytest tests/ -v
```

---

## Project Structure

```
├── main.py                          # Entry point — launches UI + monitor thread
├── config.py                        # Global configuration & all thresholds
├── logger.py                        # Rotating file logger (data/logs/app.log)
├── requirements.txt                 # Python dependencies
├── README.md
│
├── modules/                         # Analysis & processing modules
│   ├── wifi_analysis.py             # Wi-Fi scanning & threat detection
│   ├── behavioral_profiling.py      # System behaviour anomaly detection
│   ├── web_tracker.py               # DNS/tracker monitoring & scoring
│   ├── fingerprint_detector.py      # Browser fingerprinting heuristics
│   ├── threat_scoring.py            # Unified scoring engine
│   ├── auto_responder.py            # Automated response actions
│   ├── reporting.py                 # Report generation & export (JSON/TXT)
│   ├── hardening.py                 # Hardening recommendation engine
│   ├── wifi_responder.py            # Wi-Fi-specific response actions
│   └── process_inspector.py         # Process metadata inspector
│
├── ui/                              # PySide6 desktop UI
│   ├── app.py                       # Main window, sidebar, header, timer
│   ├── pages.py                     # Dashboard, WiFi, Behaviour, Web pages
│   ├── report_panel.py              # Reports page with export controls
│   ├── components.py                # Shared UI components (StatCard, etc.)
│   ├── glass_frame.py               # Glassmorphism card widget
│   ├── theme.py                     # Theme engine (light/dark + glass)
│   └── data_bridge.py               # Thread-safe data bridge for UI
│
├── data/                            # Runtime data (auto-created)
│   ├── logs/                        # Rotating log files
│   ├── reports/                     # Exported privacy reports
│   ├── tracker_blocklist.json       # ~400 tracker domains (5 categories)
│   └── baseline_profile.json        # Learned behavioural baseline
│
├── tests/                           # Unit & integration tests
│   ├── test_wifi_analysis.py
│   ├── test_behavioral_profiling.py
│   ├── test_threat_scoring.py
│   ├── test_web_tracker.py
│   └── test_reporting.py            # Reporting + hardening tests
│
├── utils/
│   └── config_manager.py            # User settings persistence
│
└── milestones/                      # Development milestone specs
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     main.py (Entry Point)                     │
│                                                              │
│  ┌──────────────┐     ┌──────────────────────────────────┐   │
│  │ Monitor Loop │────>│         DataBridge                │   │
│  │  (Thread)    │     │  (Thread-safe queue + history)    │   │
│  └──────┬───────┘     └──────────────┬───────────────────┘   │
│         │                            │                        │
│  ┌──────┴────────────────────┐  ┌────┴─────────────────┐     │
│  │ WiFiAnalyzer              │  │ PySide6 UI (QTimer)  │     │
│  │ BehavioralProfiler        │  │  Dashboard Page      │     │
│  │ WebTrackerMonitor         │  │  WiFi Page           │     │
│  │ ThreatScorer              │  │  Behaviour Page      │     │
│  │ AutoResponder             │  │  Web Tracking Page   │     │
│  │ HardeningAdvisor          │  │  Reports Panel       │     │
│  │ ReportGenerator           │  │  Settings Page       │     │
│  └───────────────────────────┘  └──────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

The **monitor loop** runs in a background thread, polling WiFi, behavioural, and web tracker modules every `MONITOR_INTERVAL_SECONDS`. Results flow through the `DataBridge` to the UI via a `QTimer` poll.

---

## Configuration

All thresholds and tunable values are centralized in [`config.py`](config.py).

| Category | Key Constants |
|----------|--------------|
| **Scoring** | `SCORE_WEIGHT_WIFI=0.35`, `SCORE_WEIGHT_BEHAVIORAL=0.40`, `SCORE_WEIGHT_WEB=0.25` |
| **Tiers** | Safe ≤24, Low Risk ≤49, Elevated ≤74, High Risk ≤89, Critical >89 |
| **WiFi** | `EVIL_TWIN_RSSI_DELTA=10`, `WIFI_SIGNAL_WARN_DBM=-70` |
| **Behavioural** | `Z_SCORE_THRESHOLD=3.0`, `HIGH_CPU_PROCESS_THRESHOLD=40%` |
| **Web** | `FINGERPRINT_CONFIDENCE_THRESHOLD=0.7`, per-category base scores |
| **Logging** | `LOG_DIR=data/logs`, `LOG_MAX_BYTES=5MB`, `LOG_BACKUP_COUNT=5` |
| **Reports** | `REPORT_DIR=data/reports`, `REPORT_HISTORY_MAX=50` |

Environment variable overrides:

```bash
set LOG_LEVEL=INFO       # Windows
export LOG_LEVEL=INFO    # Linux/macOS
```

---

## Report Export

The **Reports** page in the dashboard provides:

1. **Live session summary** — current verdict, duration, component scores
2. **Hardening recommendations** — prioritized by severity (IMMEDIATE → LOW)
3. **Export buttons** — Save as JSON or TXT with a file picker dialog
4. **Report history** — browse past exported reports

### JSON Report
Full structured data, machine-readable, suitable for archiving or external tooling.

### Plain Text Report
Human-readable audit report with sections for Wi-Fi, Processes, Web Tracking, and Recommendations.

Reports are saved to `data/reports/` with timestamp-based filenames:
```
report_20250115_143201.json
report_20250115_143201.txt
```

> **Privacy by design**: Exported reports never include raw packet data, nearby network details, or raw tracker connections.

---

## Logging

Logs are written to `data/logs/app.log` with automatic rotation:

- **Max file size**: 5 MB
- **Backup count**: 5 rotated files
- **Format**: `2025-01-15 14:32:01 | WARNING  | wifi_analysis | Evil twin detected...`
- **Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL

---

## Milestones

| # | Milestone | Status |
|---|-----------|--------|
| 01 | Wi-Fi Analysis & Threat Detection | ✅ Complete |
| 02 | Threat Scoring & Auto-Response | ✅ Complete |
| 03 | PySide6 Dashboard UI | ✅ Complete |
| 04 | Behavioural Profiling | ✅ Complete |
| 05 | Web Tracker & Fingerprint Detection | ✅ Complete |
| 06 | Logging, Reporting & Hardening | ✅ Complete |

---

## License

MIT
