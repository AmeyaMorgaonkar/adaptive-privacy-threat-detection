"""
Tests for Web Tracker & Fingerprinting Detection (Milestone 05)

Covers:
  - Blocklist loading and domain matching
  - Per-tracker scoring with base + severity + volume bonus
  - Per-category score aggregation (active categories only)
  - Weighted web_score formula (single and multi-category)
  - WebReport serialisation and raw_score compat
  - FingerprintDetector signal detection and scoring
  - Multi-category escalation trigger
  - AutoResponder per-category alert dispatch
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import config
from modules.web_tracker import (
    TrackerHit,
    TrackerConnection,
    FingerprintSignal,
    WebReport,
    WebTrackerMonitor,
    score_tracker_hit,
    compute_category_scores,
    compute_web_score,
)
from modules.fingerprint_detector import FingerprintDetector
from modules.auto_responder import AutoResponder


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def monitor():
    """Create a WebTrackerMonitor with a fresh blocklist cache."""
    m = WebTrackerMonitor()
    return m


@pytest.fixture
def detector():
    return FingerprintDetector()


def _make_hit(
    domain="tracker.example.com",
    category="Analytics",
    severity="MEDIUM",
    data_volume_kb=0.0,
    hit_count=1,
) -> TrackerHit:
    """Helper to create a TrackerHit with computed individual_score."""
    hit = TrackerHit(
        domain=domain,
        tracker_category=category,
        severity=severity,
        first_seen="2026-01-01T00:00:00Z",
        hit_count=hit_count,
        data_volume_kb=data_volume_kb,
        individual_score=0.0,
    )
    hit.individual_score = score_tracker_hit(hit)
    return hit


# ═══════════════════════════════════════════════════════════════════════
# BLOCKLIST LOADING & DOMAIN MATCHING
# ═══════════════════════════════════════════════════════════════════════

class TestBlocklistLoading:
    def test_blocklist_loads_successfully(self, monitor):
        """Blocklist loads, parses categories, and has domains."""
        bl = monitor._load_blocklist()
        assert isinstance(bl, dict)
        assert len(bl) > 0, "Blocklist should have at least one category"

    def test_blocklist_has_expected_categories(self, monitor):
        bl = monitor._load_blocklist()
        expected = {"Analytics", "Advertising", "Social", "Telemetry", "Fingerprint"}
        assert expected.issubset(set(bl.keys()))

    def test_blocklist_domain_count(self, monitor):
        monitor._load_blocklist()
        assert len(monitor._domain_to_category) > 50, (
            "Blocklist should have at least 50 domains"
        )

    def test_domain_matching_exact(self, monitor):
        """Exact domain match returns (category, severity)."""
        monitor._load_blocklist()
        result = monitor._match_domain("google-analytics.com")
        assert result is not None
        assert result[0] == "Analytics"

    def test_domain_matching_suffix(self, monitor):
        """Subdomain of a blocklisted domain matches via suffix."""
        monitor._load_blocklist()
        result = monitor._match_domain("sub.deep.google-analytics.com")
        assert result is not None
        assert result[0] == "Analytics"

    def test_domain_matching_no_match(self, monitor):
        """Non-tracker domain returns None."""
        monitor._load_blocklist()
        result = monitor._match_domain("example.com")
        assert result is None

    def test_domain_matching_case_insensitive(self, monitor):
        """Domain matching is case-insensitive."""
        monitor._load_blocklist()
        result = monitor._match_domain("Google-Analytics.COM")
        assert result is not None

    def test_blocklist_cached(self, monitor):
        """Blocklist is loaded once and cached on subsequent calls."""
        bl1 = monitor._load_blocklist()
        bl2 = monitor._load_blocklist()
        assert bl1 is bl2  # Same object reference


# ═══════════════════════════════════════════════════════════════════════
# PER-TRACKER SCORING
# ═══════════════════════════════════════════════════════════════════════

class TestTrackerScoring:
    def test_score_analytics_low_severity(self):
        """Analytics + LOW severity → base(30) * 0.5 = 15."""
        hit = _make_hit(category="Analytics", severity="LOW")
        assert hit.individual_score == pytest.approx(15.0)

    def test_score_analytics_medium_severity(self):
        """Analytics + MEDIUM → base(30) * 1.0 = 30."""
        hit = _make_hit(category="Analytics", severity="MEDIUM")
        assert hit.individual_score == pytest.approx(30.0)

    def test_score_fingerprint_high_severity(self):
        """Fingerprint + HIGH → base(85) * 1.5 = 127.5, clamped to 100."""
        hit = _make_hit(category="Fingerprint", severity="HIGH")
        assert hit.individual_score == pytest.approx(100.0)

    def test_score_telemetry_medium_severity(self):
        """Telemetry + MEDIUM → base(65) * 1.0 = 65."""
        hit = _make_hit(category="Telemetry", severity="MEDIUM")
        assert hit.individual_score == pytest.approx(65.0)

    def test_volume_bonus_applied(self):
        """Data volume above HIGH_VOLUME_TRACKER_KB adds up to 20 points."""
        hit = _make_hit(
            category="Analytics", severity="MEDIUM",
            data_volume_kb=config.HIGH_VOLUME_TRACKER_KB,
        )
        # base(30) * 1.0 + volume(500/500 * 20 = 20) = 50
        assert hit.individual_score == pytest.approx(50.0)

    def test_volume_bonus_capped_at_20(self):
        """Volume bonus never exceeds 20 points."""
        hit = _make_hit(
            category="Analytics", severity="MEDIUM",
            data_volume_kb=config.HIGH_VOLUME_TRACKER_KB * 10,
        )
        # base(30) + volume(capped 20) = 50
        assert hit.individual_score == pytest.approx(50.0)

    def test_score_clamped_at_100(self):
        """Individual score never exceeds 100."""
        hit = _make_hit(
            category="Fingerprint", severity="HIGH",
            data_volume_kb=10000,
        )
        assert hit.individual_score == 100.0


# ═══════════════════════════════════════════════════════════════════════
# CATEGORY SCORE AGGREGATION
# ═══════════════════════════════════════════════════════════════════════

class TestCategoryScoreAggregation:
    def test_single_category(self):
        """Single category produces one entry in category_scores."""
        hits = [_make_hit(category="Analytics", severity="MEDIUM")]
        cat_scores = compute_category_scores(hits)
        assert "Analytics" in cat_scores
        assert len(cat_scores) == 1

    def test_multiple_categories(self):
        """Multiple categories each get their own score."""
        hits = [
            _make_hit(category="Analytics", severity="MEDIUM"),
            _make_hit(category="Advertising", severity="HIGH",
                      domain="ad.example.com"),
        ]
        cat_scores = compute_category_scores(hits)
        assert "Analytics" in cat_scores
        assert "Advertising" in cat_scores

    def test_inactive_categories_absent(self):
        """Categories with no hits are absent from category_scores."""
        hits = [_make_hit(category="Analytics", severity="MEDIUM")]
        cat_scores = compute_category_scores(hits)
        assert "Fingerprint" not in cat_scores
        assert "Telemetry" not in cat_scores

    def test_category_uses_max_score(self):
        """Category score uses the max individual score from its hits."""
        hits = [
            _make_hit(category="Analytics", severity="LOW",
                      domain="a.example.com"),
            _make_hit(category="Analytics", severity="HIGH",
                      domain="b.example.com"),
        ]
        cat_scores = compute_category_scores(hits)
        # LOW=15, HIGH=min(45,100)=45 → max=45
        assert cat_scores["Analytics"] == pytest.approx(45.0)


# ═══════════════════════════════════════════════════════════════════════
# WEIGHTED WEB SCORE
# ═══════════════════════════════════════════════════════════════════════

class TestWeightedWebScore:
    def test_single_category_analytics(self):
        """Single active category: Analytics(30) * weight(0.10) = 3.0."""
        cat_scores = {"Analytics": 30.0}
        ws = compute_web_score(cat_scores)
        assert ws == pytest.approx(3.0)

    def test_single_category_fingerprint(self):
        """Single active category: Fingerprint(85) * weight(0.30) = 25.5."""
        cat_scores = {"Fingerprint": 85.0}
        ws = compute_web_score(cat_scores)
        assert ws == pytest.approx(25.5)

    def test_multi_category(self):
        """Multiple categories: sum of (score_i * weight_i)."""
        cat_scores = {
            "Analytics": 30.0,
            "Advertising": 55.0,
            "Fingerprint": 85.0,
        }
        expected = 30 * 0.10 + 55 * 0.20 + 85 * 0.30
        ws = compute_web_score(cat_scores)
        assert ws == pytest.approx(expected)

    def test_all_categories_max(self):
        """All categories at 100: sum of all weights * 100."""
        cat_scores = {
            "Analytics": 100.0,
            "Advertising": 100.0,
            "Social": 100.0,
            "Telemetry": 100.0,
            "Fingerprint": 100.0,
        }
        expected = 100 * (0.10 + 0.20 + 0.15 + 0.25 + 0.30)
        ws = compute_web_score(cat_scores)
        assert ws == pytest.approx(min(expected, 100.0))

    def test_empty_categories(self):
        """No active categories → web_score = 0."""
        ws = compute_web_score({})
        assert ws == 0.0

    def test_score_clamped_to_100(self):
        """web_score never exceeds 100."""
        cat_scores = {cat: 200.0 for cat in config.TRACKER_CATEGORY_WEIGHTS}
        ws = compute_web_score(cat_scores)
        assert ws == 100.0


# ═══════════════════════════════════════════════════════════════════════
# WEBREPORT SERIALISATION & COMPAT
# ═══════════════════════════════════════════════════════════════════════

class TestWebReport:
    def test_raw_score_compat(self):
        """raw_score property = web_score / 100 for ThreatScorer compat."""
        report = WebReport(web_score=65.0)
        assert report.raw_score == pytest.approx(0.65)

    def test_raw_score_zero(self):
        report = WebReport(web_score=0.0)
        assert report.raw_score == 0.0

    def test_raw_score_clamped(self):
        report = WebReport(web_score=150.0)
        assert report.raw_score == 1.0

    def test_to_dict(self):
        """to_dict() returns a JSON-serializable dictionary."""
        report = WebReport(
            timestamp="2026-01-01T00:00:00Z",
            web_score=42.0,
            active_categories=["Analytics"],
        )
        d = report.to_dict()
        assert isinstance(d, dict)
        assert d["web_score"] == 42.0
        assert d["raw_score"] == pytest.approx(0.42)
        # Ensure it's JSON-serializable
        json.dumps(d)

    def test_to_json(self):
        """to_json() returns a valid JSON string."""
        report = WebReport(web_score=10.0)
        j = report.to_json()
        parsed = json.loads(j)
        assert parsed["web_score"] == 10.0

    def test_trackers_detected_compat(self):
        """trackers_detected property returns dicts from tracker_hits."""
        hit = TrackerHit(
            domain="test.com", tracker_category="Analytics",
            severity="LOW", first_seen="2026-01-01T00:00:00Z",
        )
        report = WebReport(tracker_hits=[hit])
        assert len(report.trackers_detected) == 1
        assert report.trackers_detected[0]["domain"] == "test.com"

    def test_tracker_categories_compat(self):
        """tracker_categories property mirrors active_categories."""
        report = WebReport(active_categories=["Analytics", "Social"])
        assert report.tracker_categories == ["Analytics", "Social"]


# ═══════════════════════════════════════════════════════════════════════
# FINGERPRINT DETECTOR
# ═══════════════════════════════════════════════════════════════════════

class TestFingerprintDetector:
    def test_no_fingerprinting(self, detector):
        """Clean domains produce no detected signals."""
        signals = detector.run(["example.com", "github.com"], [])
        detected = [s for s in signals if s.detected]
        assert len(detected) == 0

    def test_canvas_detection(self, detector):
        """Known canvas fingerprinting endpoint is detected."""
        signals = detector.run(["fpcdn.io"], [])
        canvas = next(s for s in signals if s.signal_type == "CANVAS")
        assert canvas.detected is True
        assert canvas.confidence > 0

    def test_webgl_detection(self, detector):
        """Known WebGL endpoint is detected."""
        signals = detector.run(["cdn.krxd.net"], [])
        webgl = next(s for s in signals if s.signal_type == "WEBGL")
        assert webgl.detected is True

    def test_font_detection(self, detector):
        """Known font enumeration endpoint is detected."""
        signals = detector.run(["cdn.tealiumiq.com"], [])
        font = next(s for s in signals if s.signal_type == "FONT")
        assert font.detected is True

    def test_battery_detection(self, detector):
        """Known battery API telemetry endpoint is detected."""
        signals = detector.run(["cdn.permutive.com"], [])
        battery = next(s for s in signals if s.signal_type == "BATTERY")
        assert battery.detected is True

    def test_confidence_range(self, detector):
        """Confidence values are in [0, 1]."""
        signals = detector.run(["fpcdn.io", "cdn.krxd.net"], [])
        for sig in signals:
            assert 0.0 <= sig.confidence <= 1.0

    def test_fp_score_computation(self, detector):
        """compute_fp_score returns 0–100."""
        signals = detector.run(["fpcdn.io"], [])
        score = detector.compute_fp_score(signals)
        assert 0.0 <= score <= 100.0

    def test_fp_score_zero_when_clean(self, detector):
        """No detected signals → fp_score = 0."""
        signals = detector.run(["example.com"], [])
        score = detector.compute_fp_score(signals)
        assert score == 0.0

    def test_signal_has_description(self, detector):
        """All signals have a non-empty description."""
        signals = detector.run(["fpcdn.io"], [])
        for sig in signals:
            assert isinstance(sig.description, str)
            assert len(sig.description) > 0

    def test_connection_based_detection(self, detector):
        """Fingerprinting detection works via TrackerConnection objects too."""
        conn = TrackerConnection(
            remote_ip="1.2.3.4",
            remote_domain="fpcdn.io",
            local_port=12345,
            protocol="TCP",
        )
        signals = detector.run([], [conn])
        canvas = next(s for s in signals if s.signal_type == "CANVAS")
        assert canvas.detected is True


# ═══════════════════════════════════════════════════════════════════════
# MULTI-CATEGORY ESCALATION
# ═══════════════════════════════════════════════════════════════════════

class TestMultiCategoryEscalation:
    def test_escalation_fires_at_three_categories(self):
        """Escalation fires when 3+ categories exceed thresholds."""
        report = WebReport(
            category_scores={
                "Analytics": 50.0,    # threshold 40 → above
                "Advertising": 60.0,  # threshold 50 → above
                "Telemetry": 70.0,    # threshold 55 → above
            },
            active_categories=["Analytics", "Advertising", "Telemetry"],
            web_score=50.0,
        )
        responder = AutoResponder()
        fired = responder._handle_web_multi_escalation(report)
        assert "web_multi_escalation" in fired

    def test_no_escalation_below_three(self):
        """Escalation does NOT fire when fewer than 3 categories above."""
        report = WebReport(
            category_scores={
                "Analytics": 50.0,
                "Advertising": 60.0,
            },
            active_categories=["Analytics", "Advertising"],
            web_score=30.0,
        )
        responder = AutoResponder()
        fired = responder._handle_web_multi_escalation(report)
        assert "web_multi_escalation" not in fired

    def test_no_escalation_when_below_thresholds(self):
        """Escalation doesn't fire when categories are below thresholds."""
        report = WebReport(
            category_scores={
                "Analytics": 10.0,    # below 40
                "Advertising": 20.0,  # below 50
                "Telemetry": 30.0,    # below 55
            },
            active_categories=["Analytics", "Advertising", "Telemetry"],
            web_score=10.0,
        )
        responder = AutoResponder()
        fired = responder._handle_web_multi_escalation(report)
        assert "web_multi_escalation" not in fired


# ═══════════════════════════════════════════════════════════════════════
# PER-CATEGORY AUTORESPONDER ALERTS
# ═══════════════════════════════════════════════════════════════════════

class TestAutoResponderWebCategories:
    def test_analytics_alert_fires(self):
        """Analytics alert fires when category score >= threshold."""
        report = WebReport(
            category_scores={"Analytics": 50.0},
            active_categories=["Analytics"],
            web_score=5.0,
        )
        responder = AutoResponder()
        fired = responder._handle_web_categories(report)
        assert "web_analytics_alert" in fired

    def test_telemetry_alert_fires(self):
        """Telemetry alert fires at threshold (55)."""
        report = WebReport(
            category_scores={"Telemetry": 60.0},
            active_categories=["Telemetry"],
            tracker_hits=[
                TrackerHit(
                    domain="telemetry.microsoft.com",
                    tracker_category="Telemetry",
                    severity="HIGH",
                    first_seen="2026-01-01T00:00:00Z",
                ),
            ],
            web_score=15.0,
        )
        responder = AutoResponder()
        fired = responder._handle_web_categories(report)
        assert "web_telemetry_alert" in fired

    def test_fingerprint_alert_fires(self):
        """Fingerprint alert fires at threshold (40)."""
        report = WebReport(
            category_scores={"Fingerprint": 50.0},
            active_categories=["Fingerprint"],
            fingerprint_signals=[
                FingerprintSignal(
                    signal_type="CANVAS", detected=True,
                    confidence=0.85, description="test",
                ),
            ],
            web_score=15.0,
        )
        responder = AutoResponder()
        fired = responder._handle_web_categories(report)
        assert "web_fingerprint_alert" in fired

    def test_no_alert_below_threshold(self):
        """No alerts fire when all scores are below thresholds."""
        report = WebReport(
            category_scores={"Analytics": 10.0, "Social": 20.0},
            active_categories=["Analytics", "Social"],
            web_score=3.0,
        )
        responder = AutoResponder()
        fired = responder._handle_web_categories(report)
        assert len(fired) == 0

    def test_no_alert_when_report_is_none(self):
        """No crash when report is None."""
        responder = AutoResponder()
        fired = responder._handle_web_categories(None)
        assert fired == []


# ═══════════════════════════════════════════════════════════════════════
# INTEGRATION: WebTrackerMonitor.run() with mocked data
# ═══════════════════════════════════════════════════════════════════════

class TestWebTrackerMonitorIntegration:
    @patch.object(WebTrackerMonitor, "capture_dns_queries")
    @patch.object(WebTrackerMonitor, "get_active_tracker_connections")
    def test_run_with_tracker_domains(self, mock_conns, mock_dns, monitor):
        """run() produces a valid WebReport when trackers are found."""
        mock_dns.return_value = [
            "google-analytics.com",
            "doubleclick.net",
            "example.com",
        ]
        mock_conns.return_value = []

        report = monitor.run()

        assert isinstance(report, WebReport)
        assert report.unique_trackers_count >= 2
        assert report.web_score > 0
        assert len(report.tracker_hits) >= 2
        assert "Analytics" in report.active_categories

    @patch.object(WebTrackerMonitor, "capture_dns_queries")
    @patch.object(WebTrackerMonitor, "get_active_tracker_connections")
    def test_run_no_trackers(self, mock_conns, mock_dns, monitor):
        """run() returns clean report when no trackers found."""
        mock_dns.return_value = ["example.com", "github.com"]
        mock_conns.return_value = []

        report = monitor.run()

        assert isinstance(report, WebReport)
        assert report.unique_trackers_count == 0
        assert report.web_score == 0.0
        assert len(report.tracker_hits) == 0

    @patch.object(WebTrackerMonitor, "capture_dns_queries")
    @patch.object(WebTrackerMonitor, "get_active_tracker_connections")
    def test_run_report_serializable(self, mock_conns, mock_dns, monitor):
        """WebReport from run() is JSON-serializable."""
        mock_dns.return_value = ["google-analytics.com"]
        mock_conns.return_value = []

        report = monitor.run()
        j = report.to_json()
        parsed = json.loads(j)
        assert "web_score" in parsed
        assert "raw_score" in parsed


# ═══════════════════════════════════════════════════════════════════════
# CHECK_AGAINST_BLOCKLIST
# ═══════════════════════════════════════════════════════════════════════

class TestCheckAgainstBlocklist:
    def test_known_domain_returns_hit(self, monitor):
        """Known tracker domain returns a TrackerHit."""
        hits = monitor.check_against_blocklist(["google-analytics.com"])
        assert len(hits) == 1
        assert hits[0].tracker_category == "Analytics"

    def test_unknown_domain_no_hit(self, monitor):
        """Unknown domain returns no hits."""
        hits = monitor.check_against_blocklist(["example.com"])
        assert len(hits) == 0

    def test_subdomain_matches(self, monitor):
        """Subdomain of a blocklisted domain is matched."""
        hits = monitor.check_against_blocklist(["sub.google-analytics.com"])
        assert len(hits) == 1

    def test_hit_count_increments(self, monitor):
        """Repeated domains increment hit_count."""
        monitor.check_against_blocklist(["google-analytics.com"])
        hits = monitor.check_against_blocklist(["google-analytics.com"])
        assert hits[0].hit_count == 2

    def test_individual_score_computed(self, monitor):
        """Each TrackerHit has a computed individual_score > 0."""
        hits = monitor.check_against_blocklist(["doubleclick.net"])
        assert hits[0].individual_score > 0
