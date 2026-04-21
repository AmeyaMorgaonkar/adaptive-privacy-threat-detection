"""
Automated Response Engine (Milestone 02)

Evaluates a ThreatScore and fires scoped actions for each module whose
score exceeds its configured threshold.  Includes alert deduplication
via per-action cooldown timers.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

try:
    import config
    from logger import get_logger
except ModuleNotFoundError:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    import config
    from logger import get_logger

if TYPE_CHECKING:
    from modules.threat_scoring import ThreatScore

log = get_logger(__name__)

# ── Incident log path ───────────────────────────────────────────────
RESPONSE_LOG = config.DATA_DIR / "auto_response_incidents.jsonl"


class AutoResponder:
    """Fires scoped automated responses when threat thresholds are breached.

    Responses are **per-module** — a high Wi-Fi score triggers Wi-Fi-specific
    actions, not a blanket system alert.  The unified score gate is only
    reached when multiple modules are elevated simultaneously.

    Alert deduplication is handled via per-action cooldowns configured in
    ``config.RESPONSE_COOLDOWNS``.
    """

    def __init__(self) -> None:
        # Tracks the last fire time for each action key
        self._cooldowns: dict[str, float] = {}
        # Tracks whether each action key was previously above threshold —
        # cooldown resets when the score drops and re-enters.
        self._was_above: dict[str, bool] = {}
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── Public API ───────────────────────────────────────────────────

    def evaluate(
        self,
        score: ThreatScore,
        wifi_report=None,
        behavioral_report=None,
        web_report=None,
    ) -> list[str]:
        """Evaluate the score and fire appropriate responses.

        Returns a list of action keys that actually fired (useful for
        testing and dashboard display).
        """
        fired: list[str] = []

        fired.extend(
            self._handle_wifi(score.wifi_score, wifi_report),
        )
        fired.extend(
            self._handle_behavioral(score.behavioral_score, behavioral_report),
        )
        fired.extend(
            self._handle_web(score.web_score, web_report),
        )
        fired.extend(
            self._handle_unified(score.unified_score, score),
        )

        if fired:
            log.info("AutoResponder fired %d action(s): %s", len(fired), fired)

        return fired

    # ── Per-module handlers ──────────────────────────────────────────

    def _handle_wifi(self, wifi_score: float, report=None) -> list[str]:
        """Wi-Fi module response chain."""
        fired: list[str] = []

        if wifi_score >= 90:
            if self._try_fire("wifi_alert_90"):
                ssid = getattr(report, "connected_ssid", "Unknown") if report else "Unknown"
                self._send_desktop_alert(
                    title="Critical Wi-Fi Threat",
                    message=(
                        f"Critical network threat detected on '{ssid}'. "
                        f"Score: {wifi_score:.0f}/100. "
                        f"Disconnect from this network?"
                    ),
                    severity="Critical",
                )
                if getattr(config, "AUTO_DISCONNECT_ON_ROGUE", False):
                    self._log_response("wifi_auto_disconnect", {
                        "wifi_score": wifi_score,
                        "ssid": ssid,
                    })
                self._log_response("wifi_alert_90", {"wifi_score": wifi_score})
                fired.append("wifi_alert_90")

        if wifi_score >= 75:
            if self._try_fire("wifi_alert_75"):
                ssid = getattr(report, "connected_ssid", "Unknown") if report else "Unknown"
                self._send_desktop_alert(
                    title="High Wi-Fi Risk",
                    message=(
                        f"Suspicious network activity on '{ssid}'. "
                        f"Score: {wifi_score:.0f}/100."
                    ),
                    severity="High Risk",
                )
                self._log_response("wifi_alert_75", {"wifi_score": wifi_score})
                fired.append("wifi_alert_75")

        if wifi_score >= 50:
            if self._try_fire("wifi_alert_50"):
                ssid = getattr(report, "connected_ssid", "Unknown") if report else "Unknown"
                self._send_desktop_alert(
                    title="Wi-Fi Warning",
                    message=(
                        f"Suspicious network activity detected. "
                        f"SSID: '{ssid}', Score: {wifi_score:.0f}/100."
                    ),
                    severity="Elevated",
                )
                fired.append("wifi_alert_50")

        # Reset cooldown for actions whose thresholds are no longer met
        self._update_above_state("wifi_alert_50", wifi_score >= 50)
        self._update_above_state("wifi_alert_75", wifi_score >= 75)
        self._update_above_state("wifi_alert_90", wifi_score >= 90)

        return fired

    def _handle_behavioral(self, behavioral_score: float, report=None) -> list[str]:
        """Behavioral module response chain."""
        fired: list[str] = []

        if behavioral_score >= 90:
            if self._try_fire("behavioral_alert_90"):
                procs = getattr(report, "anomalous_processes", []) if report else []
                self._send_desktop_alert(
                    title="Critical Process Anomaly",
                    message=(
                        f"Highly anomalous processes detected: "
                        f"{', '.join(procs[:5]) or 'N/A'}. "
                        f"Consider terminating flagged processes."
                    ),
                    severity="Critical",
                )
                self._log_response("behavioral_alert_90", {
                    "behavioral_score": behavioral_score,
                    "processes": procs[:5],
                })
                fired.append("behavioral_alert_90")

        if behavioral_score >= 75:
            if self._try_fire("behavioral_alert_75"):
                self._send_desktop_alert(
                    title="Behavioral Anomaly — High",
                    message=(
                        f"Significant behavioural deviation detected. "
                        f"Score: {behavioral_score:.0f}/100. "
                        f"Open Task Manager to review processes."
                    ),
                    severity="High Risk",
                )
                self._log_response("behavioral_alert_75", {
                    "behavioral_score": behavioral_score,
                })
                fired.append("behavioral_alert_75")

        if behavioral_score >= 50:
            if self._try_fire("behavioral_alert_50"):
                procs = getattr(report, "anomalous_processes", []) if report else []
                self._send_desktop_alert(
                    title="Behavioral Warning",
                    message=(
                        f"Anomalous processes detected: "
                        f"{', '.join(procs[:3]) or 'N/A'}. "
                        f"Score: {behavioral_score:.0f}/100."
                    ),
                    severity="Elevated",
                )
                fired.append("behavioral_alert_50")

        self._update_above_state("behavioral_alert_50", behavioral_score >= 50)
        self._update_above_state("behavioral_alert_75", behavioral_score >= 75)
        self._update_above_state("behavioral_alert_90", behavioral_score >= 90)

        return fired

    def _handle_web(self, web_score: float, report=None) -> list[str]:
        """Web tracker module response chain."""
        fired: list[str] = []

        if web_score >= 85:
            if self._try_fire("web_alert_85"):
                self._send_desktop_alert(
                    title="Heavy Tracking Detected",
                    message=(
                        f"Extensive tracker activity detected. "
                        f"Score: {web_score:.0f}/100. "
                        f"Consider browser hardening steps."
                    ),
                    severity="High Risk",
                )
                self._log_response("web_alert_85", {"web_score": web_score})
                fired.append("web_alert_85")

        if web_score >= 65:
            if self._try_fire("web_alert_65"):
                self._send_desktop_alert(
                    title="Tracking Alert",
                    message=(
                        f"Heavy tracking detected — see report. "
                        f"Score: {web_score:.0f}/100."
                    ),
                    severity="Elevated",
                )
                fired.append("web_alert_65")

        if web_score >= 40:
            if self._try_fire("web_alert_40"):
                categories = getattr(report, "tracker_categories", []) if report else []
                # This is an in-dashboard notification (no desktop alert)
                log.info(
                    "In-dashboard notification: trackers by category — %s",
                    categories or "uncategorised",
                )
                fired.append("web_alert_40")

        self._update_above_state("web_alert_40", web_score >= 40)
        self._update_above_state("web_alert_65", web_score >= 65)
        self._update_above_state("web_alert_85", web_score >= 85)

        return fired

    def _handle_unified(self, unified_score: float, score: ThreatScore) -> list[str]:
        """Unified score response — fires when multiple modules contribute."""
        fired: list[str] = []

        if unified_score >= 90:
            if self._try_fire("unified_alert_90"):
                self._send_desktop_alert(
                    title="⚠ CRITICAL THREAT LEVEL",
                    message=(
                        f"Unified threat score: {unified_score:.0f}/100. "
                        f"Multiple subsystems report elevated risk. "
                        f"Immediate action required."
                    ),
                    severity="Critical",
                )
                self._log_response("unified_alert_90", {
                    "unified_score": unified_score,
                    "tier": score.tier,
                    "active_threats": score.active_threats[:5],
                })
                fired.append("unified_alert_90")

        if unified_score >= 75:
            if self._try_fire("unified_alert_75"):
                self._send_desktop_alert(
                    title="High Risk Environment",
                    message=(
                        f"Unified threat score: {unified_score:.0f}/100. "
                        f"High risk environment detected."
                    ),
                    severity="High Risk",
                )
                self._log_response("unified_alert_75", {
                    "unified_score": unified_score,
                })
                fired.append("unified_alert_75")

        # ≥50: tier badge change only (no extra alert)
        if unified_score >= 50:
            if self._try_fire("unified_badge_50"):
                log.info(
                    "Dashboard tier badge → Elevated (unified=%.1f)",
                    unified_score,
                )
                fired.append("unified_badge_50")

        self._update_above_state("unified_badge_50", unified_score >= 50)
        self._update_above_state("unified_alert_75", unified_score >= 75)
        self._update_above_state("unified_alert_90", unified_score >= 90)

        return fired

    # ── Alert & logging helpers ──────────────────────────────────────

    def _send_desktop_alert(self, title: str, message: str, severity: str) -> None:
        """Emit a desktop notification using a CTk dialog.
        """
        log.warning("🔔 ALERT [%s] %s — %s", severity, title, message)
        try:
            import customtkinter as ctk
            dialog = ctk.CTkToplevel()
            dialog.title(f"{severity} Alert: {title}")
            dialog.geometry("400x200")
            dialog.attributes("-topmost", True)
            
            ctk.CTkLabel(dialog, text=f"🔔 {title}", font=ctk.CTkFont(size=16, weight="bold"), text_color="red" if severity == "Critical" else "orange").pack(pady=(20, 10))
            ctk.CTkLabel(dialog, text=message, wraplength=350).pack(pady=10)
            ctk.CTkButton(dialog, text="Dismiss", command=dialog.destroy).pack(pady=10)
        except Exception as e:
            log.error(f"Failed to show CTk dialog: {e}")

    def _log_response(self, action: str, context: dict) -> None:
        """Append a structured response record to the incident log."""
        try:
            entry = {
                "logged_at": datetime.now(timezone.utc).isoformat(),
                "action": action,
                **context,
            }
            with open(RESPONSE_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
            log.debug("Response logged: %s", action)
        except Exception as exc:
            log.error("Failed to write response log: %s", exc)

    # ── Cooldown / deduplication ─────────────────────────────────────

    def _try_fire(self, action_key: str) -> bool:
        """Return True if the action is allowed to fire (not in cooldown).

        An action that is still within its cooldown window is suppressed.
        """
        now = time.monotonic()
        cooldown_sec = config.RESPONSE_COOLDOWNS.get(action_key, 60)
        last_fire = self._cooldowns.get(action_key, 0.0)

        if (now - last_fire) < cooldown_sec:
            log.debug(
                "Action '%s' suppressed (cooldown %ds, %ds remaining)",
                action_key,
                cooldown_sec,
                int(cooldown_sec - (now - last_fire)),
            )
            return False

        self._cooldowns[action_key] = now
        return True

    def _update_above_state(self, action_key: str, is_above: bool) -> None:
        """Track whether the score is above the threshold.

        When the score drops below and then rises again, the cooldown
        timer is reset so the alert may fire again immediately.
        """
        was = self._was_above.get(action_key, False)
        if was and not is_above:
            # Score dropped below threshold — reset cooldown
            self._cooldowns.pop(action_key, None)
            log.debug("Cooldown reset for '%s' (score dropped below threshold)", action_key)
        self._was_above[action_key] = is_above


# ── CLI demo ─────────────────────────────────────────────────────────

def _demo() -> None:
    """Score a live Wi-Fi report and evaluate automated responses."""
    from modules.wifi_analysis import WiFiAnalyzer
    from modules.threat_scoring import (
        BehavioralReport,
        ThreatScorer,
        WebReport,
    )

    analyzer = WiFiAnalyzer()
    wifi_report = analyzer.run_analysis()

    scorer = ThreatScorer()
    score = scorer.compute(
        wifi_report=wifi_report,
        behavioral_report=BehavioralReport(),
        web_report=WebReport(),
    )

    responder = AutoResponder()
    fired = responder.evaluate(
        score,
        wifi_report=wifi_report,
    )

    print(f"\n=== AutoResponder Demo ===")
    print(f"Unified Score : {score.unified_score:.1f}")
    print(f"Tier          : {score.tier}")
    print(f"Actions Fired : {fired or 'None (all below threshold)'}")


if __name__ == "__main__":
    _demo()
