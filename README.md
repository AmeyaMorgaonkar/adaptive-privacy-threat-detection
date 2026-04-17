# Adaptive Privacy & Threat Detection System

A desktop application that monitors network activity, detects threats, profiles system behaviour, and tracks web privacy — all from a single Tkinter dashboard.

## Features (Planned)

| Module | Description |
|--------|-------------|
| **Wi-Fi Analysis** | Scan nearby networks, detect rogue access points |
| **Threat Scoring** | Aggregate signals into a composite threat score |
| **Behavioral Profiling** | ML-based anomaly detection on network patterns |
| **Web Tracker** | DNS/HTTP monitoring for tracker domains |
| **Reporting** | Export logs and generate summary reports |

## Quick Start

### Prerequisites

- Python **3.10+**
- `pip`

### Setup

```bash
# Clone the repo
git clone <repo-url>
cd "Adaptive Privacy & Threat Detection System"

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS / Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run

```bash
python main.py
```

A Tkinter window should open with the application title displayed.

## Project Structure

```
├── main.py                  # Entry point
├── config.py                # Global config & constants
├── logger.py                # Logging setup
├── requirements.txt
├── README.md
│
├── ui/                      # Tkinter UI
│   └── app.py
│
├── modules/                 # Feature modules
│   ├── wifi_analysis.py
│   ├── threat_scoring.py
│   ├── behavioral_profiling.py
│   ├── web_tracker.py
│   └── reporting.py
│
├── data/                    # Logs and reports
└── tests/                   # Unit & integration tests
```

## Configuration

All thresholds and tunable values live in `config.py`. Environment variables can override log level:

```bash
set LOG_LEVEL=INFO   # Windows
export LOG_LEVEL=INFO  # Linux/macOS
```

## License

MIT
