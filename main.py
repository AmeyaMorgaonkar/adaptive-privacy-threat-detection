"""Entry point — launches the Tkinter desktop application."""

import threading
import time
from datetime import datetime, timezone
from logger import get_logger
from ui.data_bridge import DataBridge
from modules.threat_scoring import ThreatScore

log = get_logger(__name__)


def _show_startup_error(message: str) -> None:
    """Show a visible startup error message even when run from GUI launchers."""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Application Startup Error", message)
        root.destroy()
    except Exception:
        # Fallback for environments where Tk is unavailable.
        print(message)

def mock_data_generator(data_bridge: DataBridge):
    """Mock data generator for UI testing without live monitors."""
    while True:
        time.sleep(1)
        mock_score = ThreatScore(
            timestamp=datetime.now(timezone.utc).isoformat(),
            wifi_score=20.0,
            behavioral_score=50.0,
            web_score=65.0,
            unified_score=45.0,
            tier="Low Risk",
            active_threats=["Mock Tracker Detected"],
            recommendations=["Enable VPN"]
        )
        data_bridge.push(mock_score)

def main() -> None:
    log.info("Starting application")

    try:
        from ui.app import App
    except Exception as exc:
        msg = (
            "Failed to initialize the CustomTkinter UI.\n\n"
            "Install project dependencies and run again:\n"
            "pip install -r requirements.txt\n\n"
            f"Details: {exc}"
        )
        log.exception("UI startup failed")
        _show_startup_error(msg)
        return

    data_bridge = DataBridge()
    
    mock_thread = threading.Thread(target=mock_data_generator, args=(data_bridge,), daemon=True)
    mock_thread.start()
    
    app = App(data_bridge)
    app.mainloop()
    log.info("Application closed")

if __name__ == "__main__":
    main()
