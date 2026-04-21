"""Entry point — launches the PySide6 desktop application with real module data."""

import threading
import time
from datetime import datetime, timezone
from logger import get_logger
from ui.data_bridge import DataBridge

log = get_logger(__name__)


def _show_startup_error(message: str) -> None:
    """Show a visible startup error message even when run from GUI launchers."""
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance() or QApplication([])
        QMessageBox.critical(None, "Application Startup Error", message)
    except Exception:
        print(message)


def monitor_loop(data_bridge: DataBridge):
    """Background thread: runs real WiFi analysis + stub modules on a loop,
    feeds ThreatScorer output into the DataBridge for the UI to consume.

    WiFi analysis runs every DASHBOARD_REFRESH_MS (default 1s).
    BehavioralReport and WebReport use stubs with raw_score=0 until
    those modules are implemented in Milestones 04/05.
    """
    import config
    from modules.wifi_analysis import WiFiAnalyzer
    from modules.threat_scoring import (
        ThreatScorer, BehavioralReport, WebReport,
    )
    from modules.auto_responder import AutoResponder

    analyzer = WiFiAnalyzer()
    scorer = ThreatScorer()
    responder = AutoResponder()

    interval = getattr(config, "MONITOR_INTERVAL_SECONDS",
                       config.SCAN_INTERVAL_SECONDS)

    log.info("Monitor loop started (interval=%ds)", interval)

    while True:
        try:
            # ── WiFi (real) ──
            wifi_report = analyzer.run_analysis()

            # ── Behavioral (stub — scores 0 until M04) ──
            behavioral_report = BehavioralReport(
                timestamp=datetime.now(timezone.utc).isoformat(),
                anomalous_processes=[],
                raw_score=0.0,
                severity="LOW",
            )

            # ── Web Tracker (stub — scores 0 until M05) ──
            web_report = WebReport(
                timestamp=datetime.now(timezone.utc).isoformat(),
                trackers_detected=[],
                tracker_categories=[],
                raw_score=0.0,
                severity="LOW",
            )

            # ── Score ──
            score = scorer.compute(
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
            )

            # ── Push to DataBridge (thread-safe) ──
            data_bridge.push(score)
            data_bridge.set_reports(
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
            )

            # ── Auto-responder (alerts, logging) ──
            responder.evaluate(
                score,
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
            )

        except Exception as exc:
            log.error("Monitor loop error: %s", exc, exc_info=True)

        time.sleep(interval)


def main() -> None:
    log.info("Starting application")

    try:
        from ui.app import run
    except Exception as exc:
        msg = (
            "Failed to initialize the PySide6 UI.\n\n"
            "Install project dependencies and run again:\n"
            "pip install -r requirements.txt\n\n"
            f"Details: {exc}"
        )
        log.exception("UI startup failed")
        _show_startup_error(msg)
        return

    data_bridge = DataBridge()

    # Start the real monitoring thread
    monitor_thread = threading.Thread(
        target=monitor_loop, args=(data_bridge,), daemon=True,
        name="SentinelMonitor",
    )
    monitor_thread.start()

    run(data_bridge)
    log.info("Application closed")


if __name__ == "__main__":
    main()
