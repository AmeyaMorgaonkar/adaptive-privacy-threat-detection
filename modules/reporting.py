"""
Reporting Module (Milestone 06)

Aggregates data from all analysis modules into a structured
``PrivacyReport``, and exports to JSON and plain-text formats.
Reports are stored in ``data/reports/`` with timestamp-based filenames.
"""

from __future__ import annotations

import json
import sys
import uuid
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


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class HardeningRecommendation:
    """A single system-hardening recommendation."""

    category: str          # WIFI / PROCESSES / BROWSER / SYSTEM
    priority: str          # IMMEDIATE / HIGH / MEDIUM / LOW
    title: str
    description: str
    action_steps: list[str] = field(default_factory=list)
    related_finding: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


_PRIORITY_ORDER = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class PrivacyReport:
    """Full privacy audit report for a monitoring session."""

    report_id: str = ""
    session_start: str = ""
    session_end: str = ""
    duration_minutes: float = 0.0
    threat_score_summary: dict = field(default_factory=dict)
    wifi_summary: dict = field(default_factory=dict)
    behavioral_summary: dict = field(default_factory=dict)
    web_summary: dict = field(default_factory=dict)
    hardening_recommendations: list[dict] = field(default_factory=list)
    overall_verdict: str = "SAFE"
    generated_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "PrivacyReport":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Verdict mapping ─────────────────────────────────────────────────

_TIER_TO_VERDICT = {
    "Safe": "SAFE",
    "Low Risk": "LOW RISK",
    "Elevated": "ELEVATED",
    "High Risk": "HIGH RISK",
    "Critical": "CRITICAL",
}


# ── ReportGenerator ─────────────────────────────────────────────────

class ReportGenerator:
    """Generates and exports privacy audit reports."""

    def __init__(self) -> None:
        self._report_dir = getattr(config, "REPORT_DIR", config.DATA_DIR / "reports")
        self._report_dir.mkdir(parents=True, exist_ok=True)

    # ── Report generation ────────────────────────────────────────────

    def generate_session_report(
        self,
        wifi_report=None,
        behavioral_report=None,
        web_report=None,
        threat_score=None,
        session_start: str = "",
        session_end: str = "",
        hardening_recommendations: Optional[list] = None,
    ) -> PrivacyReport:
        """Aggregate all module reports into a single PrivacyReport."""
        now = datetime.now(timezone.utc)

        # Safely convert reports to dicts
        wifi_dict = _safe_to_dict(wifi_report)
        beh_dict = _safe_to_dict(behavioral_report)
        web_dict = _safe_to_dict(web_report)
        threat_dict = _safe_to_dict(threat_score)

        # Strip raw packet / network data for privacy
        wifi_dict.pop("nearby_networks", None)
        web_dict.pop("tracker_connections", None)

        # Compute duration
        duration = 0.0
        if session_start and session_end:
            try:
                t_start = datetime.fromisoformat(session_start)
                t_end = datetime.fromisoformat(session_end)
                duration = round((t_end - t_start).total_seconds() / 60, 2)
            except (ValueError, TypeError):
                pass

        # Determine verdict from threat tier
        tier = threat_dict.get("tier", "Safe")
        verdict = _TIER_TO_VERDICT.get(tier, "SAFE")

        # Convert hardening recs to dicts
        rec_dicts = []
        if hardening_recommendations:
            for r in hardening_recommendations:
                if hasattr(r, "to_dict"):
                    rec_dicts.append(r.to_dict())
                elif isinstance(r, dict):
                    rec_dicts.append(r)

        report = PrivacyReport(
            report_id=str(uuid.uuid4())[:8],
            session_start=session_start or now.isoformat(),
            session_end=session_end or now.isoformat(),
            duration_minutes=duration,
            threat_score_summary=threat_dict,
            wifi_summary=wifi_dict,
            behavioral_summary=beh_dict,
            web_summary=web_dict,
            hardening_recommendations=rec_dicts,
            overall_verdict=verdict,
            generated_at=now.isoformat(),
        )

        log.info(
            "Session report generated — id=%s verdict=%s duration=%.1f min",
            report.report_id, report.overall_verdict, report.duration_minutes,
        )
        return report

    # ── JSON export ──────────────────────────────────────────────────

    def export_json(self, report: PrivacyReport, path: str = None) -> str:
        """Write the report as a JSON file. Returns the file path."""
        if path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = config.REPORT_FILENAME_FMT.format(ts=ts, ext="json")
            path = str(self._report_dir / filename)

        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            f.write(report.to_json())

        log.info("Report exported to JSON: %s", path)
        return path

    # ── Plain-text export ────────────────────────────────────────────

    def export_txt(self, report: PrivacyReport, path: str = None) -> str:
        """Write the report as a formatted plain-text file. Returns the path."""
        if path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = config.REPORT_FILENAME_FMT.format(ts=ts, ext="txt")
            path = str(self._report_dir / filename)

        Path(path).parent.mkdir(parents=True, exist_ok=True)

        text = self._format_txt(report)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

        log.info("Report exported to TXT: %s", path)
        return path

    # ── Report history ───────────────────────────────────────────────

    def get_report_history(self) -> list[PrivacyReport]:
        """Scan ``data/reports/`` for JSON reports and return parsed objects.

        Returns at most ``config.REPORT_HISTORY_MAX`` reports, newest first.
        """
        reports: list[PrivacyReport] = []

        if not self._report_dir.exists():
            return reports

        json_files = sorted(
            self._report_dir.glob("report_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        max_reports = getattr(config, "REPORT_HISTORY_MAX", 50)
        for fp in json_files[:max_reports]:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    data = json.load(f)
                reports.append(PrivacyReport.from_dict(data))
            except (json.JSONDecodeError, Exception) as exc:
                log.warning("Failed to parse report %s: %s", fp.name, exc)

        return reports

    # ── Internal formatting ──────────────────────────────────────────

    @staticmethod
    def _format_txt(report: PrivacyReport) -> str:
        """Format a PrivacyReport as human-readable plain text."""
        sep = "═" * 55
        lines: list[str] = []

        lines.append(sep)
        lines.append("  PRIVACY AUDIT REPORT")

        # Session time
        start_str = _format_time(report.session_start)
        end_str = _format_time(report.session_end)
        lines.append(f"  Session: {start_str} – {end_str}")
        lines.append(sep)
        lines.append("")

        # Overall verdict
        unified = report.threat_score_summary.get("unified_score", 0)
        lines.append(
            f"OVERALL VERDICT: {report.overall_verdict} "
            f"(Score: {int(unified)}/100)"
        )
        lines.append("")

        # WiFi section
        wifi = report.wifi_summary
        wifi_score = report.threat_score_summary.get("wifi_score", 0)
        lines.append(f"[WI-FI]  Score: {int(wifi_score)}/100")
        threats = wifi.get("threats_detected", [])
        if threats:
            for t in threats:
                lines.append(f"  ⚠ {t}")
        else:
            lines.append("  ✓ No Wi-Fi threats detected")
        ssid = wifi.get("connected_ssid", "N/A")
        enc = wifi.get("encryption", "N/A")
        lines.append(f"  ℹ Connected: {ssid} ({enc})")
        lines.append("")

        # Behavioral section
        beh_score = report.threat_score_summary.get("behavioral_score", 0)
        lines.append(f"[PROCESSES]  Score: {int(beh_score)}/100")
        beh = report.behavioral_summary
        anomalous = beh.get("anomalous_processes", [])
        if anomalous:
            for proc in anomalous[:5]:
                lines.append(f"  ⚠ Anomalous process: {proc}")
        else:
            lines.append("  ✓ No critical anomalies detected")
        deviation = beh.get("baseline_deviation", 0)
        if deviation:
            lines.append(f"  ℹ CPU baseline deviation: +{deviation:.0f}%")
        lines.append("")

        # Web tracking section
        web_score = report.threat_score_summary.get("web_score", 0)
        lines.append(f"[WEB TRACKING]  Score: {int(web_score)}/100")
        web = report.web_summary
        tracker_count = web.get("unique_trackers_count", 0)
        if tracker_count:
            lines.append(f"  ✗ {tracker_count} unique trackers detected")
        else:
            lines.append("  ✓ No trackers detected")
        fp_signals = web.get("fingerprint_signals", [])
        detected_fps = [s for s in fp_signals if s.get("detected")]
        for sig in detected_fps[:3]:
            conf = sig.get("confidence", 0)
            sig_type = sig.get("signal_type", "UNKNOWN")
            lines.append(
                f"  ✗ {sig_type} fingerprinting signal (confidence: {conf:.2f})"
            )
        cat_scores = web.get("category_scores", {})
        if cat_scores:
            active = [f"{k}: {v:.0f}" for k, v in cat_scores.items() if v > 0]
            if active:
                lines.append(f"  ℹ Category scores: {', '.join(active)}")
        lines.append("")

        # Recommendations
        recs = report.hardening_recommendations
        if recs:
            lines.append("RECOMMENDATIONS:")
            for rec in recs:
                priority = rec.get("priority", "LOW")
                title = rec.get("title", "")
                lines.append(f"  [{priority}] {title}")
                desc = rec.get("description", "")
                if desc:
                    lines.append(f"          {desc}")
                steps = rec.get("action_steps", [])
                for i, step in enumerate(steps, 1):
                    lines.append(f"          {i}. {step}")
        else:
            lines.append("RECOMMENDATIONS:")
            lines.append("  ✓ No immediate actions required")
        lines.append("")

        lines.append(sep)
        lines.append(f"  Generated: {_format_time(report.generated_at)}")
        lines.append(f"  Report ID: {report.report_id}")
        lines.append(sep)

        return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────

def _safe_to_dict(obj) -> dict:
    """Convert a report object to dict, handling None and dicts."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    try:
        return asdict(obj)
    except Exception:
        return {}


def _format_time(iso_str: str) -> str:
    """Format an ISO-8601 string to 'YYYY-MM-DD HH:MM'."""
    if not iso_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return iso_str[:16] if len(iso_str) >= 16 else iso_str
