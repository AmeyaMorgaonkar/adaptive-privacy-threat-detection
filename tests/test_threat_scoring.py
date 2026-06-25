"""
Unit Tests — Milestone 02: Unified Threat Scoring & Automated Response

Covers:
    - ThreatScorer weighted aggregation and all 5 severity tiers
    - ThreatScore JSON serialisation
    - Recommendation generation
    - AutoResponder per-module threshold evaluation
    - AutoResponder unified-score escalation
    - Alert cooldown / deduplication logic
    - DataBridge thread-safety under concurrent access
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure project root is on sys.path for direct `pytest` invocation
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import config
from modules.threat_scoring import (
    BehavioralReport,
    ThreatScore,
    ThreatScorer,
    WebReport,
    classify_tier,
    tier_colour,
)
from modules.auto_responder import AutoResponder
from ui.data_bridge import DataBridge


# ── Helpers ──────────────────────────────────────────────────────────

def _make_wifi_report(raw_score: float = 0.0, threats: list[str] | None = None):
    """Create a minimal WiFiReport-like object for testing."""

    @dataclass
    class _FakeWiFiReport:
        timestamp: str = "2026-01-01T00:00:00Z"
        connected_ssid: str = "TestNet"
        bssid: str = "aa:bb:cc:dd:ee:ff"
        encryption: str = "WPA2"
        signal_dbm: int = -55
        nearby_networks: list = field(default_factory=list)
        threats_detected: list[str] = field(default_factory=list)
        severity: str = "LOW"
        raw_score: float = 0.0

    report = _FakeWiFiReport(raw_score=raw_score)
    if threats:
        report.threats_detected = threats
    return report


def _make_behavioral_report(raw_score: float = 0.0, procs: list[str] | None = None):
    report = BehavioralReport(raw_score=raw_score)
    if procs:
        report.anomalous_processes = procs
    return report


def _make_web_report(raw_score: float = 0.0, trackers: list[dict] | None = None):
    # New WebReport uses web_score (0–100); raw_score is a property = web_score/100
    report = WebReport(web_score=raw_score * 100.0)
    if trackers:
        # Build TrackerHit objects for the new WebReport interface
        from modules.web_tracker import TrackerHit
        hits = []
        for t in trackers:
            domain = t.get("domain", "unknown") if isinstance(t, dict) else str(t)
            hits.append(TrackerHit(
                domain=domain,
                tracker_category=t.get("tracker_category", "Analytics") if isinstance(t, dict) else "Analytics",
                severity="MEDIUM",
                first_seen="2026-01-01T00:00:00Z",
            ))
        report.tracker_hits = hits
    return report


def _make_score(
    wifi: float = 0.0,
    behavioral: float = 0.0,
    web: float = 0.0,
) -> ThreatScore:
    """Directly construct a ThreatScore with given component scores (0–100)."""
    unified = (
        wifi * config.SCORE_WEIGHT_WIFI
        + behavioral * config.SCORE_WEIGHT_BEHAVIORAL
        + web * config.SCORE_WEIGHT_WEB
    )
    unified = round(min(max(unified, 0.0), 100.0), 2)
    return ThreatScore(
        timestamp="2026-01-01T00:00:00Z",
        wifi_score=wifi,
        behavioral_score=behavioral,
        web_score=web,
        unified_score=unified,
        tier=classify_tier(unified),
    )


# ═════════════════════════════════════════════════════════════════════
# 1. ThreatScorer — weighted aggregation
# ═════════════════════════════════════════════════════════════════════


class TestThreatScorerCompute:
    """Verify weighted score formula and component scaling."""

    def test_all_zero_scores(self):
        scorer = ThreatScorer()
        score = scorer.compute()
        assert score.unified_score == 5.0
        assert score.tier == "Safe"

    def test_wifi_only(self):
        scorer = ThreatScorer()
        wifi = _make_wifi_report(raw_score=0.8)  # → 80 out of 100
        score = scorer.compute(wifi_report=wifi)
        expected = (
            80.0 * config.SCORE_WEIGHT_WIFI
            + 5.0 * config.SCORE_WEIGHT_BEHAVIORAL
            + 5.0 * config.SCORE_WEIGHT_WEB
        )
        assert score.wifi_score == 80.0
        assert score.unified_score == pytest.approx(expected, abs=0.1)

    def test_behavioral_only(self):
        scorer = ThreatScorer()
        beh = _make_behavioral_report(raw_score=0.6)  # → 60
        score = scorer.compute(behavioral_report=beh)
        expected = (
            5.0 * config.SCORE_WEIGHT_WIFI
            + 60.0 * config.SCORE_WEIGHT_BEHAVIORAL
            + 5.0 * config.SCORE_WEIGHT_WEB
        )
        assert score.behavioral_score == 60.0
        assert score.unified_score == pytest.approx(expected, abs=0.1)

    def test_web_only(self):
        scorer = ThreatScorer()
        web = _make_web_report(raw_score=0.5)  # → 50
        score = scorer.compute(web_report=web)
        expected = (
            5.0 * config.SCORE_WEIGHT_WIFI
            + 5.0 * config.SCORE_WEIGHT_BEHAVIORAL
            + 50.0 * config.SCORE_WEIGHT_WEB
        )
        assert score.web_score == 50.0
        assert score.unified_score == pytest.approx(expected, abs=0.1)

    def test_all_modules_combined(self):
        scorer = ThreatScorer()
        wifi = _make_wifi_report(raw_score=0.6)
        beh = _make_behavioral_report(raw_score=0.4)
        web = _make_web_report(raw_score=0.8)
        score = scorer.compute(wifi, beh, web)

        expected = (
            60.0 * config.SCORE_WEIGHT_WIFI
            + 40.0 * config.SCORE_WEIGHT_BEHAVIORAL
            + 80.0 * config.SCORE_WEIGHT_WEB
        )
        assert score.unified_score == pytest.approx(expected, abs=0.1)

    def test_maximum_scores(self):
        scorer = ThreatScorer()
        wifi = _make_wifi_report(raw_score=1.0)
        beh = _make_behavioral_report(raw_score=1.0)
        web = _make_web_report(raw_score=1.0)
        score = scorer.compute(wifi, beh, web)
        assert score.unified_score == pytest.approx(100.0, abs=0.1)
        assert score.tier == "Critical"

    def test_raw_score_clamped_above_1(self):
        """raw_score > 1.0 should be clamped to 100."""
        scorer = ThreatScorer()
        wifi = _make_wifi_report(raw_score=1.5)
        score = scorer.compute(wifi_report=wifi)
        assert score.wifi_score == 100.0

    def test_weights_sum_to_one(self):
        total = (
            config.SCORE_WEIGHT_WIFI
            + config.SCORE_WEIGHT_BEHAVIORAL
            + config.SCORE_WEIGHT_WEB
        )
        assert total == pytest.approx(1.0)


# ═════════════════════════════════════════════════════════════════════
# 2. Severity tier classification
# ═════════════════════════════════════════════════════════════════════


class TestSeverityTiers:
    """All 5 tiers must be correctly classified at their boundaries."""

    @pytest.mark.parametrize(
        "score, expected_tier",
        [
            (0, "Safe"),
            (12, "Safe"),
            (24, "Safe"),         # upper bound inclusive
            (25, "Low Risk"),
            (37, "Low Risk"),
            (49, "Low Risk"),     # upper bound inclusive
            (50, "Elevated"),
            (62, "Elevated"),
            (74, "Elevated"),     # upper bound inclusive
            (75, "High Risk"),
            (82, "High Risk"),
            (89, "High Risk"),    # upper bound inclusive
            (90, "Critical"),
            (95, "Critical"),
            (100, "Critical"),
        ],
    )
    def test_tier_boundaries(self, score, expected_tier):
        assert classify_tier(score) == expected_tier

    def test_tier_colour_returns_valid_hex(self):
        for tier_name in ("Safe", "Low Risk", "Elevated", "High Risk", "Critical"):
            colour = tier_colour(tier_name)
            assert colour.startswith("#")
            assert len(colour) == 7  # #RRGGBB


# ═════════════════════════════════════════════════════════════════════
# 3. ThreatScore serialisation
# ═════════════════════════════════════════════════════════════════════


class TestThreatScoreSerialization:

    def test_to_dict_roundtrip(self):
        score = _make_score(wifi=30, behavioral=20, web=10)
        d = score.to_dict()
        assert isinstance(d, dict)
        assert d["wifi_score"] == 30.0
        assert d["tier"] == score.tier
        assert "active_threats" in d
        assert "recommendations" in d

    def test_to_json_produces_valid_string(self):
        import json
        score = _make_score()
        raw = score.to_json()
        parsed = json.loads(raw)
        assert parsed["unified_score"] == score.unified_score


# ═════════════════════════════════════════════════════════════════════
# 4. Recommendation generation
# ═════════════════════════════════════════════════════════════════════


class TestRecommendations:

    def test_high_wifi_score_recommends_disconnect(self):
        scorer = ThreatScorer()
        wifi = _make_wifi_report(raw_score=0.8)
        score = scorer.compute(wifi_report=wifi)
        recs = " ".join(score.recommendations).lower()
        assert "disconnect" in recs or "vpn" in recs

    def test_elevated_web_score_recommends_privacy(self):
        scorer = ThreatScorer()
        web = _make_web_report(raw_score=0.7)
        score = scorer.compute(web_report=web)
        recs = " ".join(score.recommendations).lower()
        assert "privacy" in recs or "tracker" in recs or "browser" in recs

    def test_critical_tier_has_critical_recommendation(self):
        scorer = ThreatScorer()
        wifi = _make_wifi_report(raw_score=1.0)
        beh = _make_behavioral_report(raw_score=1.0)
        web = _make_web_report(raw_score=1.0)
        score = scorer.compute(wifi, beh, web)
        recs = " ".join(score.recommendations).upper()
        assert "CRITICAL" in recs

    def test_safe_score_no_recommendations(self):
        scorer = ThreatScorer()
        score = scorer.compute()
        assert score.recommendations == []


# ═════════════════════════════════════════════════════════════════════
# 5. Score history
# ═════════════════════════════════════════════════════════════════════


class TestScoreHistory:

    def test_history_accumulates(self):
        scorer = ThreatScorer()
        for i in range(5):
            scorer.compute(wifi_report=_make_wifi_report(raw_score=i * 0.1))
        assert len(scorer.get_history()) == 5

    def test_history_n_returns_last_n(self):
        scorer = ThreatScorer()
        for i in range(10):
            scorer.compute(wifi_report=_make_wifi_report(raw_score=i * 0.05))
        last3 = scorer.get_history(3)
        assert len(last3) == 3

    def test_get_latest(self):
        scorer = ThreatScorer()
        assert scorer.get_latest() is None
        scorer.compute()
        assert scorer.get_latest() is not None

    def test_history_capped_at_config_length(self):
        scorer = ThreatScorer()
        for i in range(config.SCORE_HISTORY_LENGTH + 50):
            scorer.compute()
        assert len(scorer.get_history()) <= config.SCORE_HISTORY_LENGTH


# ═════════════════════════════════════════════════════════════════════
# 6. Active threats collection
# ═════════════════════════════════════════════════════════════════════


class TestActiveThreats:

    def test_wifi_threats_propagated(self):
        scorer = ThreatScorer()
        wifi = _make_wifi_report(
            raw_score=0.5,
            threats=["Evil-twin detected", "Open network"],
        )
        score = scorer.compute(wifi_report=wifi)
        assert "Evil-twin detected" in score.active_threats
        assert "Open network" in score.active_threats

    def test_behavioral_anomalous_processes(self):
        scorer = ThreatScorer()
        beh = _make_behavioral_report(raw_score=0.5, procs=["malware.exe"])
        score = scorer.compute(behavioral_report=beh)
        assert any("malware.exe" in t for t in score.active_threats)

    def test_web_trackers_reported(self):
        scorer = ThreatScorer()
        web = _make_web_report(
            raw_score=0.5,
            trackers=[{"domain": "tracker.evil.com"}],
        )
        score = scorer.compute(web_report=web)
        assert any("tracker.evil.com" in t for t in score.active_threats)


# ═════════════════════════════════════════════════════════════════════
# 7. AutoResponder — per-module thresholds
# ═════════════════════════════════════════════════════════════════════


class TestAutoResponderThresholds:

    def _responder(self) -> AutoResponder:
        """Fresh responder with zeroed cooldowns for testing."""
        r = AutoResponder()
        # Override cooldowns to 0 so every call fires during tests
        with patch.dict(config.RESPONSE_COOLDOWNS, {
            k: 0 for k in config.RESPONSE_COOLDOWNS
        }):
            pass
        return r

    def test_wifi_50_fires(self):
        r = AutoResponder()
        r._cooldowns.clear()
        score = _make_score(wifi=55)
        with patch.dict(config.RESPONSE_COOLDOWNS, {k: 0 for k in config.RESPONSE_COOLDOWNS}):
            fired = r.evaluate(score)
        assert "wifi_alert_50" in fired

    def test_wifi_below_50_no_fire(self):
        r = AutoResponder()
        score = _make_score(wifi=40)
        fired = r.evaluate(score)
        wifi_actions = [a for a in fired if a.startswith("wifi_")]
        assert wifi_actions == []

    def test_wifi_90_fires_all_levels(self):
        r = AutoResponder()
        score = _make_score(wifi=95)
        with patch.dict(config.RESPONSE_COOLDOWNS, {k: 0 for k in config.RESPONSE_COOLDOWNS}):
            fired = r.evaluate(score)
        assert "wifi_alert_90" in fired
        assert "wifi_alert_75" in fired
        assert "wifi_alert_50" in fired

    def test_behavioral_50_fires(self):
        r = AutoResponder()
        score = _make_score(behavioral=55)
        with patch.dict(config.RESPONSE_COOLDOWNS, {k: 0 for k in config.RESPONSE_COOLDOWNS}):
            fired = r.evaluate(score)
        assert "behavioral_alert_50" in fired

    def test_behavioral_below_50_no_fire(self):
        r = AutoResponder()
        score = _make_score(behavioral=30)
        fired = r.evaluate(score)
        beh_actions = [a for a in fired if a.startswith("behavioral_")]
        assert beh_actions == []

    def test_web_40_fires(self):
        r = AutoResponder()
        score = _make_score(web=45)
        with patch.dict(config.RESPONSE_COOLDOWNS, {k: 0 for k in config.RESPONSE_COOLDOWNS}):
            fired = r.evaluate(score)
        assert "web_alert_40" in fired

    def test_web_85_fires_all_levels(self):
        r = AutoResponder()
        score = _make_score(web=90)
        with patch.dict(config.RESPONSE_COOLDOWNS, {k: 0 for k in config.RESPONSE_COOLDOWNS}):
            fired = r.evaluate(score)
        assert "web_alert_85" in fired
        assert "web_alert_65" in fired
        assert "web_alert_40" in fired


# ═════════════════════════════════════════════════════════════════════
# 8. AutoResponder — unified score escalation
# ═════════════════════════════════════════════════════════════════════


class TestAutoResponderUnified:

    def test_unified_75_fires_when_multi_module(self):
        """Unified ≥75 should fire when multiple modules contribute."""
        r = AutoResponder()
        # wifi=80, behavioral=80, web=60 → unified ≈ 75
        score = _make_score(wifi=80, behavioral=80, web=60)
        assert score.unified_score >= 75
        with patch.dict(config.RESPONSE_COOLDOWNS, {k: 0 for k in config.RESPONSE_COOLDOWNS}):
            fired = r.evaluate(score)
        assert "unified_alert_75" in fired

    def test_unified_90_fires_critical(self):
        r = AutoResponder()
        score = _make_score(wifi=95, behavioral=95, web=85)
        assert score.unified_score >= 90
        with patch.dict(config.RESPONSE_COOLDOWNS, {k: 0 for k in config.RESPONSE_COOLDOWNS}):
            fired = r.evaluate(score)
        assert "unified_alert_90" in fired

    def test_unified_below_50_no_escalation(self):
        r = AutoResponder()
        score = _make_score(wifi=30, behavioral=20, web=10)
        assert score.unified_score < 50
        fired = r.evaluate(score)
        unified_actions = [a for a in fired if a.startswith("unified_")]
        assert unified_actions == []


# ═════════════════════════════════════════════════════════════════════
# 9. Alert cooldown / deduplication
# ═════════════════════════════════════════════════════════════════════


class TestCooldownDeduplication:

    def test_action_suppressed_within_cooldown(self):
        """Same action should NOT fire twice within cooldown window."""
        r = AutoResponder()
        score = _make_score(wifi=55)

        # Use a 10s cooldown for wifi_alert_50
        with patch.dict(config.RESPONSE_COOLDOWNS, {
            **{k: 0 for k in config.RESPONSE_COOLDOWNS},
            "wifi_alert_50": 10,
        }):
            fired1 = r.evaluate(score)
            assert "wifi_alert_50" in fired1

            # Immediately re-evaluate — should be suppressed
            fired2 = r.evaluate(score)
            assert "wifi_alert_50" not in fired2

    def test_action_fires_after_cooldown_expires(self):
        """Action should fire again once cooldown has elapsed."""
        r = AutoResponder()
        score = _make_score(wifi=55)

        with patch.dict(config.RESPONSE_COOLDOWNS, {
            **{k: 0 for k in config.RESPONSE_COOLDOWNS},
            "wifi_alert_50": 0,  # 0s cooldown = always fires
        }):
            fired1 = r.evaluate(score)
            assert "wifi_alert_50" in fired1

            fired2 = r.evaluate(score)
            assert "wifi_alert_50" in fired2

    def test_cooldown_resets_when_score_drops_and_rises(self):
        """Cooldown should reset if score drops below threshold then rises."""
        r = AutoResponder()
        high_score = _make_score(wifi=55)
        low_score = _make_score(wifi=30)

        with patch.dict(config.RESPONSE_COOLDOWNS, {
            **{k: 0 for k in config.RESPONSE_COOLDOWNS},
            "wifi_alert_50": 9999,  # very long cooldown
        }):
            # Fire once
            fired1 = r.evaluate(high_score)
            assert "wifi_alert_50" in fired1

            # Still above — should be suppressed
            fired2 = r.evaluate(high_score)
            assert "wifi_alert_50" not in fired2

            # Drop below threshold — this resets the cooldown
            r.evaluate(low_score)

            # Rise again — should fire because cooldown was reset
            fired3 = r.evaluate(high_score)
            assert "wifi_alert_50" in fired3

    def test_different_actions_independent_cooldowns(self):
        """wifi_alert_50 cooldown should not affect behavioral_alert_50."""
        r = AutoResponder()

        with patch.dict(config.RESPONSE_COOLDOWNS, {
            **{k: 0 for k in config.RESPONSE_COOLDOWNS},
            "wifi_alert_50": 9999,
            "behavioral_alert_50": 0,
        }):
            score = _make_score(wifi=55, behavioral=55)
            fired1 = r.evaluate(score)
            assert "wifi_alert_50" in fired1
            assert "behavioral_alert_50" in fired1

            # Second call — wifi suppressed, behavioral fires again
            fired2 = r.evaluate(score)
            assert "wifi_alert_50" not in fired2
            assert "behavioral_alert_50" in fired2


# ═════════════════════════════════════════════════════════════════════
# 10. DataBridge — thread safety
# ═════════════════════════════════════════════════════════════════════


class TestDataBridge:

    def test_push_and_latest(self):
        bridge = DataBridge()
        assert bridge.latest() is None

        score = _make_score(wifi=10)
        bridge.push(score)
        assert bridge.latest() is score

    def test_push_updates_latest(self):
        bridge = DataBridge()
        s1 = _make_score(wifi=10)
        s2 = _make_score(wifi=50)
        bridge.push(s1)
        bridge.push(s2)
        assert bridge.latest() is s2

    def test_drain_returns_all_pending(self):
        bridge = DataBridge()
        for i in range(5):
            bridge.push(_make_score(wifi=i * 10))
        items = bridge.drain()
        assert len(items) == 5

    def test_drain_empties_queue(self):
        bridge = DataBridge()
        bridge.push(_make_score())
        bridge.drain()
        assert bridge.drain() == []

    def test_history_bounded(self):
        bridge = DataBridge()
        for i in range(config.SCORE_HISTORY_LENGTH + 20):
            bridge.push(_make_score(wifi=i % 100))
        assert len(bridge.history()) <= config.SCORE_HISTORY_LENGTH

    def test_history_n(self):
        bridge = DataBridge()
        for i in range(10):
            bridge.push(_make_score(wifi=i))
        assert len(bridge.history(3)) == 3

    def test_subscribe_callback_called(self):
        bridge = DataBridge()
        received: list[ThreatScore] = []
        bridge.subscribe(lambda s: received.append(s))

        score = _make_score(wifi=42)
        bridge.push(score)
        assert len(received) == 1
        assert received[0] is score

    def test_unsubscribe_stops_callback(self):
        bridge = DataBridge()
        received: list[ThreatScore] = []
        cb = lambda s: received.append(s)
        bridge.subscribe(cb)
        bridge.push(_make_score())
        assert len(received) == 1

        bridge.unsubscribe(cb)
        bridge.push(_make_score())
        assert len(received) == 1  # no new items

    def test_clear_resets_everything(self):
        bridge = DataBridge()
        bridge.push(_make_score())
        bridge.clear()
        assert bridge.latest() is None
        assert bridge.history() == []
        assert bridge.queue_depth == 0

    def test_concurrent_push_safety(self):
        """Multiple threads pushing simultaneously should not corrupt state."""
        bridge = DataBridge()
        n_threads = 8
        pushes_per_thread = 50
        errors: list[Exception] = []

        def pusher(tid: int):
            try:
                for i in range(pushes_per_thread):
                    bridge.push(_make_score(wifi=float(tid * 100 + i)))
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=pusher, args=(t,), daemon=True)
            for t in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"Concurrent push errors: {errors}"
        # latest() should be set (some score)
        assert bridge.latest() is not None
        # History should be bounded
        assert len(bridge.history()) <= config.SCORE_HISTORY_LENGTH

    def test_concurrent_push_and_read_safety(self):
        """One writer + multiple readers should not raise."""
        bridge = DataBridge()
        stop = threading.Event()
        errors: list[Exception] = []

        def writer():
            try:
                for i in range(100):
                    bridge.push(_make_score(wifi=float(i)))
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)
            finally:
                stop.set()

        def reader():
            try:
                while not stop.is_set():
                    _ = bridge.latest()
                    _ = bridge.history(5)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        writer_t = threading.Thread(target=writer, daemon=True)
        readers = [
            threading.Thread(target=reader, daemon=True) for _ in range(4)
        ]
        writer_t.start()
        for r in readers:
            r.start()
        writer_t.join(timeout=10)
        for r in readers:
            r.join(timeout=5)

        assert errors == [], f"Concurrent read/write errors: {errors}"


# ═════════════════════════════════════════════════════════════════════
# 11. Edge cases
# ═════════════════════════════════════════════════════════════════════


class TestEdgeCases:

    def test_none_reports_produce_zero_score(self):
        scorer = ThreatScorer()
        score = scorer.compute(None, None, None)
        assert score.unified_score == 5.0
        assert score.tier == "Safe"

    def test_negative_raw_score_clamped_to_zero(self):
        scorer = ThreatScorer()
        wifi = _make_wifi_report(raw_score=-0.5)
        score = scorer.compute(wifi_report=wifi)
        assert score.wifi_score == 5.0

    def test_exact_boundary_24(self):
        assert classify_tier(24) == "Safe"

    def test_exact_boundary_25(self):
        assert classify_tier(25) == "Low Risk"

    def test_exact_boundary_49(self):
        assert classify_tier(49) == "Low Risk"

    def test_exact_boundary_50(self):
        assert classify_tier(50) == "Elevated"

    def test_exact_boundary_74(self):
        assert classify_tier(74) == "Elevated"

    def test_exact_boundary_75(self):
        assert classify_tier(75) == "High Risk"

    def test_exact_boundary_89(self):
        assert classify_tier(89) == "High Risk"

    def test_exact_boundary_90(self):
        assert classify_tier(90) == "Critical"
