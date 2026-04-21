"""
Threat Scoring Module (Milestone 02)

Aggregates signals from Wi-Fi (M01), Behavioral (M04), and Web Tracker
(M05) modules into a single normalised 0–100 threat score with severity
tiers and human-readable recommendations.
"""

from __future__ import annotations

import json
import sys
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import config
    from logger import get_logger
except ModuleNotFoundError:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    import config
    from logger import get_logger

log = get_logger(__name__)


# ── Report stubs for modules not yet implemented ─────────────────────
# WiFiReport is already real (wifi_analysis.py).
# BehavioralReport and WebReport are stubs until M04 / M05 land.

@dataclass
class BehavioralReport:
    """Placeholder report until Milestone 04 is implemented."""
    timestamp: str = ""
    anomalous_processes: list[str] = field(default_factory=list)
    raw_score: float = 0.0
    severity: str = "LOW"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WebReport:
    """Placeholder report until Milestone 05 is implemented."""
    timestamp: str = ""
    trackers_detected: list[dict] = field(default_factory=list)
    tracker_categories: list[str] = field(default_factory=list)
    raw_score: float = 0.0
    severity: str = "LOW"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Severity helpers ─────────────────────────────────────────────────

TIER_ORDER = {
    "Safe": 0,
    "Low Risk": 1,
    "Elevated": 2,
    "High Risk": 3,
    "Critical": 4,
}


def classify_tier(score: float) -> str:
    """Map a 0–100 score to a severity tier string."""
    if score <= config.TIER_SAFE_MAX:
        return "Safe"
    if score <= config.TIER_LOW_MAX:
        return "Low Risk"
    if score <= config.TIER_ELEVATED_MAX:
        return "Elevated"
    if score <= config.TIER_HIGH_MAX:
        return "High Risk"
    return "Critical"


def tier_colour(tier: str) -> str:
    """Return the UI colour associated with a tier (used by M03)."""
    return {
        "Safe": "#22c55e",       # Green
        "Low Risk": "#eab308",   # Yellow
        "Elevated": "#f97316",   # Orange
        "High Risk": "#ef4444",  # Red
        "Critical": "#991b1b",   # Deep Red
    }.get(tier, "#6b7280")


# ── ThreatScore dataclass ────────────────────────────────────────────

@dataclass
class ThreatScore:
    """Unified threat snapshot produced by ThreatScorer.compute()."""

    timestamp: str
    wifi_score: float         # 0–100  (component score)
    behavioral_score: float   # 0–100
    web_score: float          # 0–100
    unified_score: float      # 0–100  (weighted aggregate)
    tier: str                 # Safe / Low Risk / Elevated / High Risk / Critical
    active_threats: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise to a plain JSON-safe dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialise to a compact JSON string."""
        return json.dumps(self.to_dict(), default=str)


# ── ThreatScorer engine ─────────────────────────────────────────────

class ThreatScorer:
    """Weighted scoring engine that aggregates per-module reports."""

    def __init__(self) -> None:
        self._history: deque[ThreatScore] = deque(
            maxlen=config.SCORE_HISTORY_LENGTH,
        )
        self._latest: Optional[ThreatScore] = None

    # ── Public API ───────────────────────────────────────────────────

    def compute(
        self,
        wifi_report=None,
        behavioral_report: Optional[BehavioralReport] = None,
        web_report: Optional[WebReport] = None,
    ) -> ThreatScore:
        """Aggregate individual module reports into a unified ThreatScore.

        Any report may be ``None`` — its contribution is treated as 0.
        The ``raw_score`` field on each report is expected to be in the
        range 0.0–1.0; it is scaled to 0–100 here.
        """
        ts = datetime.now(timezone.utc).isoformat()

        # Scale raw 0–1 scores to 0–100
        wifi_score = self._scale(wifi_report)
        behavioral_score = self._scale(behavioral_report)
        web_score = self._scale(web_report)

        # Weighted aggregate
        unified = (
            wifi_score * config.SCORE_WEIGHT_WIFI
            + behavioral_score * config.SCORE_WEIGHT_BEHAVIORAL
            + web_score * config.SCORE_WEIGHT_WEB
        )
        unified = round(min(max(unified, 0.0), 100.0), 2)

        tier = classify_tier(unified)
        active_threats = self._collect_threats(
            wifi_report, behavioral_report, web_report,
        )
        recommendations = self._generate_recommendations(
            wifi_score, behavioral_score, web_score, tier,
            wifi_report, behavioral_report, web_report,
        )

        score = ThreatScore(
            timestamp=ts,
            wifi_score=round(wifi_score, 2),
            behavioral_score=round(behavioral_score, 2),
            web_score=round(web_score, 2),
            unified_score=unified,
            tier=tier,
            active_threats=active_threats,
            recommendations=recommendations,
        )

        self._latest = score
        self._history.append(score)

        log.info(
            "ThreatScore computed — unified=%.1f  tier=%s  threats=%d",
            unified, tier, len(active_threats),
        )
        return score

    def get_latest(self) -> Optional[ThreatScore]:
        """Return the most recently computed ThreatScore (or None)."""
        return self._latest

    def get_history(self, n: int = 0) -> list[ThreatScore]:
        """Return the last *n* scores (0 = all available history)."""
        history = list(self._history)
        if n <= 0:
            return history
        return history[-n:]

    # ── Internal helpers ─────────────────────────────────────────────

    @staticmethod
    def _scale(report) -> float:
        """Convert a report's ``raw_score`` (0–1) to a 0–100 value."""
        if report is None:
            return 0.0
        raw = getattr(report, "raw_score", 0.0)
        return min(max(raw * 100.0, 0.0), 100.0)

    @staticmethod
    def _collect_threats(wifi_report, behavioral_report, web_report) -> list[str]:
        """Merge threat descriptions from all available reports."""
        threats: list[str] = []

        if wifi_report is not None:
            threats.extend(getattr(wifi_report, "threats_detected", []))

        if behavioral_report is not None:
            for proc in getattr(behavioral_report, "anomalous_processes", []):
                threats.append(f"Anomalous process: {proc}")

        if web_report is not None:
            for tracker in getattr(web_report, "trackers_detected", []):
                domain = tracker if isinstance(tracker, str) else tracker.get("domain", "unknown")
                threats.append(f"Tracker detected: {domain}")

        return threats

    @staticmethod
    def _generate_recommendations(
        wifi_score: float,
        behavioral_score: float,
        web_score: float,
        tier: str,
        wifi_report=None,
        behavioral_report=None,
        web_report=None,
    ) -> list[str]:
        """Produce actionable, human-readable recommendations."""
        recs: list[str] = []

        # Wi-Fi recommendations
        if wifi_score >= 75:
            recs.append("Disconnect from the current network and use a trusted connection.")
            if wifi_report and getattr(wifi_report, "encryption", "") in ("OPEN", "WEP"):
                recs.append("Avoid open / WEP networks — use WPA2/WPA3 only.")
        elif wifi_score >= 50:
            recs.append("Enable a VPN to encrypt traffic on this network.")

        # Behavioral recommendations
        if behavioral_score >= 75:
            recs.append("Review flagged processes in Task Manager and terminate suspicious ones.")
        elif behavioral_score >= 50:
            recs.append("Monitor flagged processes — they may be consuming unusual resources.")

        # Web tracker recommendations
        if web_score >= 65:
            recs.append("Consider using a privacy-focused browser or enabling tracker blocking.")
        elif web_score >= 40:
            recs.append("Review the list of detected trackers in the dashboard.")

        # General escalation
        if tier == "Critical":
            recs.append("CRITICAL: Disconnect from all networks, scan for malware, and review system logs immediately.")
        elif tier == "High Risk":
            recs.append("High risk environment — limit sensitive activities until threats are resolved.")

        return recs


# ── CLI demo ─────────────────────────────────────────────────────────

def _demo() -> None:
    """Quick demo: score a live Wi-Fi report with stub behavioral/web."""
    from modules.wifi_analysis import WiFiAnalyzer

    analyzer = WiFiAnalyzer()
    wifi_report = analyzer.run_analysis()

    scorer = ThreatScorer()
    score = scorer.compute(
        wifi_report=wifi_report,
        behavioral_report=BehavioralReport(),
        web_report=WebReport(),
    )

    print("\n=== Threat Score Summary ===")
    print(f"Wi-Fi Score      : {score.wifi_score:.1f}")
    print(f"Behavioral Score : {score.behavioral_score:.1f}")
    print(f"Web Score        : {score.web_score:.1f}")
    print(f"Unified Score    : {score.unified_score:.1f}")
    print(f"Tier             : {score.tier}")
    print(f"Active Threats   : {len(score.active_threats)}")
    for t in score.active_threats:
        print(f"  • {t}")
    print(f"Recommendations  : {len(score.recommendations)}")
    for r in score.recommendations:
        print(f"  → {r}")
    print(f"\nJSON:\n{score.to_json()[:600]}")


if __name__ == "__main__":
    _demo()
