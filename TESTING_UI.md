UI Manual Verification

Run the app

- From project root run:

```bash
python main.py
```

Pages to test

- Dashboard (`ui/pages.py`)
  - Start app without the data bridge running: the `Actions Taken` stat and mini-stats should be hidden (no hardcoded numbers visible).
  - Start the monitor (or mock reports via DataBridge) and verify:
    - `Overall Threat Score` and per-module scores update from `ThreatScore`.
    - `Active Threats`, `Actions Taken`, and mini-stats (`Blocked Req.`, `Suspicious Proc.`, `Networks Scanned`, `Data Sent`) show values only when respective module reports are available.
- WiFi Security
  - When `wifi_report` is None: dynamic frames (connected network card, gauge, detected threats) should be hidden.
  - When `wifi_report` is present: frames should appear and display live values. Verify `Networks Scanned` mini-stat on Dashboard updates accordingly.
- Behaviour Analysis
  - When `behavioral_report` is None: anomaly/fingerprint sections should be hidden.
  - When present: show anomalies and flagged processes counts.
- Web Tracking
  - When `web_report` is None: offenders list, DOM card, and donut should be hidden.
  - When present: offenders and data volumes should display and the `Blocked Req.` / `Data Sent` mini-stats should update.
- All Actions
  - Verify the top stat cards show `Total`, `Active`, `Inactive` computed from `ALL_ACTIONS`.
  - Verify each action row is generated from the `ALL_ACTIONS` canonical list and the pagination label shows the total (e.g., "Showing 1-12 of N actions").

Notes / Troubleshooting

- If widgets do not appear after reports are set, restart the app and ensure `main.py` is pushing reports via `DataBridge.set_reports()` / `push()`.
- To simulate reports quickly, in a Python REPL instantiate the app's `DataBridge` and call `set_reports({...})` with keys `web_report`, `behavioral_report`, `wifi_report`, and `actions_taken`.

Next actions

- If you want action toggles persisted across restarts, I can wire the toggles to `utils/config_manager.py` and store preferences in `data/user_settings.json`.

Created by: automated UI update toolchain
Date: 2026-05-28
