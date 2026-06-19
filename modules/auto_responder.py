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

    def recommend(
        self,
        score: "ThreatScore",
        wifi_report=None,
        behavioral_report=None,
        web_report=None,
    ) -> list[dict]:
        """Return a list of recommended actions (UI-friendly dicts).

        This is a *suggestion* API — it does not change state or fire
        any actions. Each recommendation is a dict with keys:
          - action_key: internal string id
          - icon: short emoji/icon
          - title: short title
          - message: explanatory subtext
          - tag: action tag label (e.g., REVIEW, APPLY)
        """
        recs: list[dict] = []

        try:
            web_score = getattr(score, "web_score", 0)
            wifi_score = getattr(score, "wifi_score", 0)
            unified = getattr(score, "unified_score", 0)

            # Web-driven recommendations
            if web_score >= 65:
                recs.append({
                    "action_key": "recommend_update_firewall",
                    "icon": "🛡️",
                    "title": "Update Firewall Rules",
                    "message": "Web module threshold met",
                    "tag": "REVIEW",
                })
            if web_score >= 50:
                recs.append({
                    "action_key": "recommend_block_ad_networks",
                    "icon": "🚫",
                    "title": "Block Ad Networks",
                    "message": "Reduce advertising tracking exposure",
                    "tag": "APPLY",
                })

            # Wi-Fi-driven recommendations
            if wifi_score >= 60:
                recs.append({
                    "action_key": "recommend_block_ip_range",
                    "icon": "🚫",
                    "title": "Block IP Range",
                    "message": "Suspicious behaviour detected",
                    "tag": "REVIEW",
                })
            if wifi_score >= 80:
                recs.append({
                    "action_key": "recommend_isolate_node",
                    "icon": "⚠️",
                    "title": "Isolate High-Risk Node",
                    "message": "Isolate device with high outbound risk",
                    "tag": "APPLY",
                })

            # Unified / high-severity recommendation
            if unified >= 80:
                recs.insert(0, {
                    "action_key": "recommend_rotate_api_keys",
                    "icon": "🔑",
                    "title": "Rotate API Keys",
                    "message": "Recommended in high-risk environments",
                    "tag": "APPLY",
                })

        except Exception:
            # On error, return empty list (UI will show placeholder)
            return []

        return recs

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
        """Web tracker module response chain.

        Dispatches both score-based alerts (legacy) and per-category
        alerts using the rich WebReport from M05.
        """
        fired: list[str] = []

        # ── Score-based alerts (legacy thresholds) ───────────────────
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
                categories = getattr(report, "active_categories", []) if report else []
                # This is an in-dashboard notification (no desktop alert)
                log.info(
                    "In-dashboard notification: trackers by category — %s",
                    categories or "uncategorised",
                )
                fired.append("web_alert_40")

        self._update_above_state("web_alert_40", web_score >= 40)
        self._update_above_state("web_alert_65", web_score >= 65)
        self._update_above_state("web_alert_85", web_score >= 85)

        # ── Per-category alerts (M05) ────────────────────────────────
        fired.extend(self._handle_web_categories(report))

        # ── Multi-category escalation ────────────────────────────────
        fired.extend(self._handle_web_multi_escalation(report))

        return fired

    def _handle_web_categories(self, report=None) -> list[str]:
        """Dispatch per-category web alerts based on category_scores.

        Each tracker category (Analytics, Advertising, Social, Telemetry,
        Fingerprint) has its own alert threshold and targeted suggestion.
        """
        fired: list[str] = []
        if report is None:
            return fired

        cat_scores = getattr(report, "category_scores", {})
        if not cat_scores:
            return fired

        thresholds = getattr(config, "TRACKER_ALERT_THRESHOLDS", {})
        top_offenders = getattr(report, "top_offenders", [])

        # ── Analytics ────────────────────────────────────────────────
        analytics_score = cat_scores.get("Analytics", 0)
        if analytics_score >= thresholds.get("Analytics", 40):
            if self._try_fire("web_analytics_alert"):
                log.info(
                    "In-dashboard notification: Analytics trackers detected "
                    "(score=%.0f) — domains: %s",
                    analytics_score, top_offenders[:3],
                )
                self._log_response("web_analytics_alert", {
                    "category": "Analytics",
                    "score": analytics_score,
                })
                fired.append("web_analytics_alert")

        # ── Advertising ──────────────────────────────────────────────
        ad_score = cat_scores.get("Advertising", 0)
        if ad_score >= thresholds.get("Advertising", 50):
            if self._try_fire("web_advertising_alert"):
                log.info(
                    "In-dashboard notification: Advertising trackers "
                    "(score=%.0f)", ad_score,
                )
                if ad_score >= 75:
                    self._send_desktop_alert(
                        title="Ad Network Tracking",
                        message=(
                            f"Ad network trackers actively profiling you. "
                            f"Score: {ad_score:.0f}/100."
                        ),
                        severity="High Risk",
                    )
                self._log_response("web_advertising_alert", {
                    "category": "Advertising",
                    "score": ad_score,
                })
                fired.append("web_advertising_alert")

        # ── Social ───────────────────────────────────────────────────
        social_score = cat_scores.get("Social", 0)
        if social_score >= thresholds.get("Social", 50):
            if self._try_fire("web_social_alert"):
                if social_score >= 75:
                    self._send_desktop_alert(
                        title="Social Tracker Alert",
                        message=(
                            "Social trackers are linking your identity "
                            "across sites."
                        ),
                        severity="High Risk",
                    )
                else:
                    log.info(
                        "In-dashboard notification: Social trackers "
                        "(score=%.0f)", social_score,
                    )
                self._log_response("web_social_alert", {
                    "category": "Social",
                    "score": social_score,
                })
                fired.append("web_social_alert")

        # ── Telemetry ────────────────────────────────────────────────
        telem_score = cat_scores.get("Telemetry", 0)
        if telem_score >= thresholds.get("Telemetry", 55):
            if self._try_fire("web_telemetry_alert"):
                telem_domains = [
                    h.domain for h in getattr(report, "tracker_hits", [])
                    if getattr(h, "tracker_category", "") == "Telemetry"
                ][:5]
                self._send_desktop_alert(
                    title="Telemetry Data Exfiltration",
                    message=(
                        f"System/app telemetry detected — data being "
                        f"sent to: {', '.join(telem_domains) or 'unknown'}. "
                        f"Score: {telem_score:.0f}/100."
                    ),
                    severity="High Risk" if telem_score >= 80 else "Elevated",
                )
                if telem_score >= 80:
                    self._log_response("web_telemetry_high_severity", {
                        "category": "Telemetry",
                        "score": telem_score,
                        "domains": telem_domains,
                    })
                self._log_response("web_telemetry_alert", {
                    "category": "Telemetry",
                    "score": telem_score,
                })
                fired.append("web_telemetry_alert")

        # ── Fingerprint ──────────────────────────────────────────────
        fp_score = cat_scores.get("Fingerprint", 0)
        if fp_score >= thresholds.get("Fingerprint", 40):
            if self._try_fire("web_fingerprint_alert"):
                fp_signals = getattr(report, "fingerprint_signals", [])
                confidence = max(
                    (getattr(s, "confidence", 0) for s in fp_signals
                     if getattr(s, "detected", False)),
                    default=0,
                )
                self._send_desktop_alert(
                    title="Browser Fingerprinting Detected",
                    message=(
                        f"Browser fingerprinting attempt detected "
                        f"(confidence: {confidence:.0%}). "
                        f"Score: {fp_score:.0f}/100."
                    ),
                    severity=(
                        "Critical" if fp_score >= 90
                        else "High Risk" if fp_score >= 70
                        else "Elevated"
                    ),
                )
                self._log_response("web_fingerprint_alert", {
                    "category": "Fingerprint",
                    "score": fp_score,
                    "confidence": confidence,
                })
                fired.append("web_fingerprint_alert")

        return fired

    def _handle_web_multi_escalation(self, report=None) -> list[str]:
        """Multi-category escalation: fire when 3+ categories exceed thresholds.

        When multiple tracker categories are simultaneously active above
        their individual alert thresholds, this is treated as a unified
        escalation event (per M05 spec).
        """
        fired: list[str] = []
        if report is None:
            return fired

        cat_scores = getattr(report, "category_scores", {})
        thresholds = getattr(config, "TRACKER_ALERT_THRESHOLDS", {})
        escalation_count = getattr(
            config, "TRACKER_MULTI_CATEGORY_ESCALATION_COUNT", 3,
        )

        categories_above = [
            cat for cat, score in cat_scores.items()
            if score >= thresholds.get(cat, 50)
        ]

        if len(categories_above) >= escalation_count:
            if self._try_fire("web_multi_escalation"):
                self._send_desktop_alert(
                    title="WARNING: Multi-Category Tracking Escalation",
                    message=(
                        f"{len(categories_above)} tracker categories active "
                        f"above threshold: {', '.join(categories_above)}. "
                        f"This indicates broad privacy exposure."
                    ),
                    severity="Critical",
                )
                self._log_response("web_multi_escalation", {
                    "categories_above": categories_above,
                    "count": len(categories_above),
                })
                fired.append("web_multi_escalation")

        self._update_above_state(
            "web_multi_escalation",
            len(categories_above) >= escalation_count,
        )

        return fired

    def _handle_unified(self, unified_score: float, score: ThreatScore) -> list[str]:
        """Unified score response — fires when multiple modules contribute."""
        fired: list[str] = []

        if unified_score >= 90:
            if self._try_fire("unified_alert_90"):
                self._send_desktop_alert(
                    title="CRITICAL THREAT LEVEL",
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
                    "Dashboard tier badge -> Elevated (unified=%.1f)",
                    unified_score,
                )
                fired.append("unified_badge_50")

        self._update_above_state("unified_badge_50", unified_score >= 50)
        self._update_above_state("unified_alert_75", unified_score >= 75)
        self._update_above_state("unified_alert_90", unified_score >= 90)

        return fired

    # ── Alert & logging helpers ──────────────────────────────────────

    def _send_desktop_alert(self, title: str, message: str, severity: str) -> None:
        """Emit a desktop notification.

        Runs in a background thread, so we cannot create Qt widgets here.
        Instead we log prominently; the UI reads alerts from the incident
        log / DataBridge history.
        """
        log.warning("ALERT [%s] %s - %s", severity, title, message)
        self._log_response(f"desktop_alert_{severity.lower().replace(' ', '_')}", {
            "title": title,
            "message": message,
            "severity": severity,
        })

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
