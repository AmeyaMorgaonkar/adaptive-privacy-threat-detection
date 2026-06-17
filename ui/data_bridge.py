"""
Data Bridge (Milestone 02)

Thread-safe interface connecting background monitor threads to the UI
dashboard.  Uses ``queue.Queue`` internally so callers never block.
The dashboard (Milestone 03) will poll ``latest()`` or register a
callback via ``subscribe()``.
"""

from __future__ import annotations

import queue
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

try:
    import config
    from logger import get_logger
except ModuleNotFoundError:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    import config
    from logger import get_logger

from modules.threat_scoring import ThreatScore

log = get_logger(__name__)


class DataBridge:
    """Thread-safe queue connecting background monitor threads to the UI.

    Design constraints (from milestone spec):
    - ``push()`` and ``latest()`` must be safe under concurrent access.
    - Must never block callers — uses ``queue.Queue`` with ``block=False``.
    - Score history is capped at ``config.SCORE_HISTORY_LENGTH``.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[ThreatScore] = queue.Queue(
            maxsize=config.SCORE_HISTORY_LENGTH,
        )
        self._latest: Optional[ThreatScore] = None
        self._lock = threading.Lock()
        self._subscribers: list[Callable[[ThreatScore], None]] = []
        self._sub_lock = threading.Lock()

        # Rolling history (most recent N scores)
        self._history: list[ThreatScore] = []
        self._history_lock = threading.Lock()

        # Full module reports (set by monitor loop)
        self._reports: dict = {}
        self._reports_lock = threading.Lock()

        # Session management (Milestone 06)
        self._session_start: str = datetime.now(timezone.utc).isoformat()
        self._session_running: bool = True
        self._session_lock = threading.Lock()

        # WiFiResponder reference for UI-driven VPN toggle
        self._wifi_responder = None
        self._wifi_responder_lock = threading.Lock()

    # ── Producer API (called from background threads) ────────────────

    def push(self, score: ThreatScore) -> None:
        """Enqueue a new ThreatScore and notify subscribers.

        Never blocks: if the internal queue is full, the oldest item is
        discarded to make room.
        """
        # Evict oldest if queue is at capacity
        if self._queue.full():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass

        try:
            self._queue.put_nowait(score)
        except queue.Full:
            log.warning("DataBridge queue unexpectedly full after eviction")

        # Update latest reference (atomic-ish via lock)
        with self._lock:
            self._latest = score

        # Append to bounded history
        with self._history_lock:
            self._history.append(score)
            max_len = config.SCORE_HISTORY_LENGTH
            if len(self._history) > max_len:
                self._history = self._history[-max_len:]

        # Notify subscribers (fire-and-forget, errors are logged)
        self._notify(score)

        log.debug(
            "DataBridge.push — unified=%.1f  tier=%s  queue_depth=%d",
            score.unified_score,
            score.tier,
            self._queue.qsize(),
        )

    # ── Consumer API (called from UI / main thread) ──────────────────

    def latest(self) -> Optional[ThreatScore]:
        """Return the most recently pushed ThreatScore, or ``None``."""
        with self._lock:
            return self._latest

    def drain(self) -> list[ThreatScore]:
        """Drain all pending scores from the queue (non-blocking).

        Useful for batch-consuming items the UI hasn't processed yet.
        """
        items: list[ThreatScore] = []
        while True:
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items

    def history(self, n: int = 0) -> list[ThreatScore]:
        """Return the last *n* scores (0 = all available history).

        Thread-safe snapshot — callers get a copy of the list.
        """
        with self._history_lock:
            if n <= 0:
                return list(self._history)
            return list(self._history[-n:])

    # ── Subscription API ─────────────────────────────────────────────

    def subscribe(self, callback: Callable[[ThreatScore], None]) -> None:
        """Register a callback invoked on every ``push()``.

        Callbacks run in the **pushing thread**, so they must return
        quickly or hand off to the UI event loop (e.g., via
        ``root.after()`` in Tkinter/CTk).
        """
        with self._sub_lock:
            self._subscribers.append(callback)
        log.debug("DataBridge subscriber added (total=%d)", len(self._subscribers))

    def unsubscribe(self, callback: Callable[[ThreatScore], None]) -> None:
        """Remove a previously registered callback."""
        with self._sub_lock:
            try:
                self._subscribers.remove(callback)
            except ValueError:
                pass

    def _notify(self, score: ThreatScore) -> None:
        """Fire all subscriber callbacks (best-effort)."""
        with self._sub_lock:
            subs = list(self._subscribers)

        for cb in subs:
            try:
                cb(score)
            except Exception as exc:
                log.error("DataBridge subscriber error: %s", exc)

    # ── Module Reports API ───────────────────────────────────────────

    def set_reports(self, **reports) -> None:
        """Store full module reports (wifi_report, behavioral_report, etc.).

        Called from the monitor thread alongside push().
        """
        with self._reports_lock:
            self._reports.update(reports)

        # Quick debug: log number of nearby networks when a WiFiReport is set
        try:
            wifi = reports.get("wifi_report")
            if wifi is not None:
                # wifi may be a dataclass or dict
                if isinstance(wifi, dict):
                    nn = len(wifi.get("nearby_networks", []))
                else:
                    nn = len(getattr(wifi, "nearby_networks", []))
                log.debug("DataBridge.set_reports — wifi_report nearby_networks=%d", nn)
        except Exception:
            pass

    def get_reports(self) -> dict:
        """Return a snapshot of the latest module reports."""
        with self._reports_lock:
            return dict(self._reports)

    # ── Utilities ────────────────────────────────────────────────────

    @property
    def queue_depth(self) -> int:
        """Number of unconsumed items in the queue."""
        return self._queue.qsize()

    def clear(self) -> None:
        """Discard all queued data and reset history."""
        self.drain()
        with self._lock:
            self._latest = None
        with self._history_lock:
            self._history.clear()
        with self._reports_lock:
            self._reports.clear()
        log.debug("DataBridge cleared")

    # ── Session management (Milestone 06) ────────────────────────────

    def get_session_start(self) -> str:
        """Return the ISO-8601 timestamp when the session started."""
        with self._session_lock:
            return self._session_start

    def get_session_duration_minutes(self) -> float:
        """Return session duration in minutes."""
        with self._session_lock:
            try:
                start = datetime.fromisoformat(self._session_start)
                now = datetime.now(timezone.utc)
                return round((now - start).total_seconds() / 60, 2)
            except (ValueError, TypeError):
                return 0.0

    def is_session_running(self) -> bool:
        """Return True if the monitoring session is active."""
        with self._session_lock:
            return self._session_running

    def stop_session(self) -> None:
        """Pause the monitoring session."""
        with self._session_lock:
            self._session_running = False
        log.info("Session paused")

    def start_session(self) -> None:
        """Resume (or start) the monitoring session."""
        with self._session_lock:
            if not self._session_running:
                self._session_start = datetime.now(timezone.utc).isoformat()
            self._session_running = True
        log.info("Session started/resumed")

    # ── VPN control (Milestone — UI toggle) ──────────────────────────

    def set_wifi_responder(self, responder) -> None:
        """Store a reference to the WiFiResponder for UI-driven VPN control."""
        with self._wifi_responder_lock:
            self._wifi_responder = responder

    def is_vpn_active(self) -> bool:
        """Query the WiFiResponder for current VPN state."""
        with self._wifi_responder_lock:
            if self._wifi_responder is None:
                return False
            return self._wifi_responder.is_vpn_active

    def set_vpn_state(self, enabled: bool) -> None:
        """Toggle VPN on/off from the UI.

        Runs in the calling thread (UI).  The actual subprocess work is
        fast (sends a signal / launches a process), so it's acceptable.
        """
        with self._wifi_responder_lock:
            if self._wifi_responder is None:
                log.warning("Cannot toggle VPN — WiFiResponder not available")
                return
            if enabled:
                self._wifi_responder.manual_enable_vpn()
            else:
                self._wifi_responder.disable_network_protection()
        log.info("VPN toggled via UI: %s", "ON" if enabled else "OFF")
