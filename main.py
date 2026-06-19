"""Entry point — launches the PySide6 desktop application with real module data."""

import threading
import time
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


def _run_first_scan_concurrent(data_bridge, analyzer, profiler, web_monitor,
                                scorer, responder, wifi_responder):
    """Run the very first scan with all modules in parallel so the UI
    gets data within seconds instead of waiting for sequential completion.

    As each module finishes, we immediately push an incremental score so
    the dashboard updates progressively.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = {"wifi": None, "behavioral": None, "web": None}
    lock = threading.Lock()

    def _run_wifi():
        return ("wifi", analyzer.run_analysis())

    def _run_behavioral():
        return ("behavioral", profiler.run())

    def _run_web():
        return ("web", web_monitor.run())

    log.info("First scan: running all modules concurrently")

    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="FirstScan") as pool:
        futures = [pool.submit(_run_wifi),
                   pool.submit(_run_behavioral),
                   pool.submit(_run_web)]

        for future in as_completed(futures):
            try:
                key, report = future.result()
                with lock:
                    results[key] = report

                    # Push an incremental score with whatever we have so far
                    score = scorer.compute(
                        wifi_report=results["wifi"],
                        behavioral_report=results["behavioral"],
                        web_report=results["web"],
                    )
                    data_bridge.push(score)
                    data_bridge.set_reports(
                        wifi_report=results["wifi"],
                        behavioral_report=results["behavioral"],
                        web_report=results["web"],
                    )
                    log.info("First scan: %s module complete -> pushed score %.1f",
                             key, score.unified_score)
            except Exception as exc:
                log.error("First scan module error: %s", exc, exc_info=True)

    # Final pass: run responder logic with all three reports available
    wifi_report = results["wifi"]
    behavioral_report = results["behavioral"]
    web_report = results["web"]

    if wifi_report and behavioral_report and web_report:
        score = scorer.compute(
            wifi_report=wifi_report,
            behavioral_report=behavioral_report,
            web_report=web_report,
        )
        data_bridge.push(score)

        try:
            fired_actions = responder.evaluate(
                score,
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
            )
        except Exception:
            fired_actions = None

        try:
            recommended = responder.recommend(
                score,
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
            )
        except Exception:
            recommended = []

        data_bridge.set_reports(
            wifi_report=wifi_report,
            behavioral_report=behavioral_report,
            web_report=web_report,
            actions_taken=(len(fired_actions) if fired_actions is not None else 0),
            recommended_actions=recommended,
        )

        if wifi_report.severity in ("HIGH", "CRITICAL"):
            wifi_responder.on_threshold_breach(wifi_report)
        wifi_responder.evaluate_auto_protection(
            score.unified_score,
            wifi_report=wifi_report,
        )

    return results


def monitor_loop(data_bridge: DataBridge, config_manager=None):
    """Background thread: runs real WiFi analysis + behavioral profiling
    + web tracker on a loop, feeds ThreatScorer output into the DataBridge
    for the UI.

    The first scan runs all modules concurrently so the UI shows data
    within seconds.  Subsequent scans run sequentially every
    MONITOR_INTERVAL_SECONDS.
    """
    import config
    from modules.wifi_analysis import WiFiAnalyzer
    from modules.behavioral_profiling import BehavioralProfiler
    from modules.web_tracker import WebTrackerMonitor
    from modules.threat_scoring import ThreatScorer
    from modules.auto_responder import AutoResponder
    from modules.wifi_responder import WiFiResponder

    analyzer = WiFiAnalyzer()
    scorer = ThreatScorer()
    responder = AutoResponder()
    wifi_responder = WiFiResponder(config_manager=config_manager)
    profiler = BehavioralProfiler()
    web_monitor = WebTrackerMonitor()

    # Register WiFiResponder with DataBridge for UI-driven VPN/DNS toggle
    data_bridge.set_wifi_responder(wifi_responder)

    interval = getattr(config, "MONITOR_INTERVAL_SECONDS",
                       config.SCAN_INTERVAL_SECONDS)

    log.info("Monitor loop started (interval=%ds)", interval)

    # ── First scan: run concurrently for fast startup ──
    last_wifi_report = None
    last_wifi_scan_time = 0.0  # epoch; ensures first scan always runs
    wifi_interval = getattr(config, "WIFI_SCAN_INTERVAL_SECONDS", 90)

    try:
        if data_bridge.is_session_running():
            first_results = _run_first_scan_concurrent(
                data_bridge, analyzer, profiler, web_monitor,
                scorer, responder, wifi_responder,
            )
            last_wifi_report = first_results.get("wifi")
            if last_wifi_report is not None:
                last_wifi_scan_time = time.monotonic()
    except Exception as exc:
        log.error("First concurrent scan failed: %s", exc, exc_info=True)

    while True:
        
        try:
            # Skip scanning if session is paused
            if not data_bridge.is_session_running():
                time.sleep(1)
                continue

            # ── WiFi (throttled to WIFI_SCAN_INTERVAL_SECONDS) ──
            now = time.monotonic()
            if now - last_wifi_scan_time >= wifi_interval:
                wifi_report = analyzer.run_analysis()
                last_wifi_report = wifi_report
                last_wifi_scan_time = now
            else:
                wifi_report = last_wifi_report

            # ── Behavioral (real — Milestone 04) ──
            behavioral_report = profiler.run()

            # ── Web Tracker (real — Milestone 05) ──
            web_report = web_monitor.run()

            # ── Score ──
            score = scorer.compute(
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
            )

            # ── Push to DataBridge (thread-safe) ──
            data_bridge.push(score)

            # Evaluate auto-responder and capture fired actions so the UI
            # can display a count of automated responses.
            fired_actions = responder.evaluate(
                score,
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
            )

            # Ask AutoResponder for UI-friendly recommended actions
            try:
                recommended = responder.recommend(
                    score,
                    wifi_report=wifi_report,
                    behavioral_report=behavioral_report,
                    web_report=web_report,
                )
            except Exception:
                recommended = []

            data_bridge.set_reports(
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
                actions_taken=(len(fired_actions) if fired_actions is not None else 0),
                recommended_actions=recommended,
            )

            # ── Auto network protection (VPN + hardened DNS) ──
            if wifi_report and wifi_report.severity in ("HIGH", "CRITICAL"):
                wifi_responder.on_threshold_breach(wifi_report)
            wifi_responder.evaluate_auto_protection(
                score.unified_score,
                wifi_report=wifi_report,
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

    # Shared config manager — persists user settings (DNS, theme, etc.)
    from utils.config_manager import ConfigManager
    config_manager = ConfigManager()

    data_bridge = DataBridge()

    # Start the real monitoring thread
    monitor_thread = threading.Thread(
        target=monitor_loop,
        args=(data_bridge, config_manager),
        daemon=True,
        name="SentinelMonitor",
    )
    monitor_thread.start()

    run(data_bridge, config_manager=config_manager)
    log.info("Application closed")


if __name__ == "__main__":
    main()
