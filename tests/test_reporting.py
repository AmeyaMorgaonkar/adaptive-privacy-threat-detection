"""
Tests for the Reporting & Hardening modules (Milestone 06).

Covers:
- PrivacyReport & HardeningRecommendation data structures
- ReportGenerator (session report, JSON export, TXT export, history)
- HardeningAdvisor (all catalog checks, priority sorting, formatting)
- End-to-end: mock session → report → export → verify
"""

import json
import os
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path

import pytest

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import config
from modules.reporting import (
    PrivacyReport,
    HardeningRecommendation,
    ReportGenerator,
    _TIER_TO_VERDICT,
)
from modules.hardening import HardeningAdvisor


# ═══════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ═══════════════════════════════════════════════════════════════════════

def _make_wifi_report(**overrides):
    base = {
        "timestamp": "2025-01-15T14:00:00+00:00",
        "connected_ssid": "TestNetwork",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "encryption": "WPA2",
        "signal_dbm": -55,
        "nearby_networks": [{"ssid": "Other", "bssid": "11:22:33:44:55:66"}],
        "threats_detected": [],
        "severity": "LOW",
        "raw_score": 0.1,
    }
    base.update(overrides)
    return base


def _make_behavioral_report(**overrides):
    base = {
        "timestamp": "2025-01-15T14:00:00+00:00",
        "anomalous_processes": [],
        "behavioral_score": 15.0,
        "baseline_deviation": 5.0,
        "raw_score": 0.15,
        "severity": "LOW",
    }
    base.update(overrides)
    return base


def _make_web_report(**overrides):
    base = {
        "timestamp": "2025-01-15T14:00:00+00:00",
        "unique_trackers_count": 3,
        "category_scores": {"Analytics": 20, "Advertising": 15},
        "web_score": 18.0,
        "active_categories": ["Analytics", "Advertising"],
        "top_offenders": ["tracker1.com", "ads.example.com"],
        "fingerprint_signals": [],
        "tracker_hits": [],
        "severity": "LOW",
    }
    base.update(overrides)
    return base


def _make_threat_score(**overrides):
    base = {
        "timestamp": "2025-01-15T14:00:00+00:00",
        "wifi_score": 10.0,
        "behavioral_score": 15.0,
        "web_score": 18.0,
        "unified_score": 14.0,
        "tier": "Safe",
        "active_threats": [],
        "recommendations": [],
    }
    base.update(overrides)
    return base


# ═══════════════════════════════════════════════════════════════════════
# TEST: PrivacyReport
# ═══════════════════════════════════════════════════════════════════════

class TestPrivacyReport:
    def test_creation(self):
        r = PrivacyReport(report_id="test123", overall_verdict="SAFE")
        assert r.report_id == "test123"
        assert r.overall_verdict == "SAFE"

    def test_to_dict(self):
        r = PrivacyReport(report_id="abc", overall_verdict="ELEVATED")
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["report_id"] == "abc"
        assert d["overall_verdict"] == "ELEVATED"

    def test_to_json(self):
        r = PrivacyReport(report_id="abc")
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["report_id"] == "abc"

    def test_from_dict(self):
        d = {"report_id": "xyz", "overall_verdict": "HIGH RISK",
             "duration_minutes": 45.5}
        r = PrivacyReport.from_dict(d)
        assert r.report_id == "xyz"
        assert r.overall_verdict == "HIGH RISK"
        assert r.duration_minutes == 45.5

    def test_from_dict_ignores_unknown_keys(self):
        d = {"report_id": "xyz", "unknown_field": "ignored"}
        r = PrivacyReport.from_dict(d)
        assert r.report_id == "xyz"


class TestHardeningRecommendation:
    def test_creation(self):
        rec = HardeningRecommendation(
            category="WIFI", priority="HIGH",
            title="Test", description="Desc",
            action_steps=["Step 1"], related_finding="Finding X",
        )
        assert rec.category == "WIFI"
        assert rec.priority == "HIGH"
        assert len(rec.action_steps) == 1

    def test_to_dict(self):
        rec = HardeningRecommendation(
            category="BROWSER", priority="MEDIUM",
            title="Block ads", description="Install blocker",
        )
        d = rec.to_dict()
        assert d["category"] == "BROWSER"
        assert d["title"] == "Block ads"


# ═══════════════════════════════════════════════════════════════════════
# TEST: ReportGenerator
# ═══════════════════════════════════════════════════════════════════════

class TestReportGenerator:
    def test_generate_session_report_basic(self):
        gen = ReportGenerator()
        report = gen.generate_session_report(
            wifi_report=_make_wifi_report(),
            behavioral_report=_make_behavioral_report(),
            web_report=_make_web_report(),
            threat_score=_make_threat_score(),
            session_start="2025-01-15T14:00:00+00:00",
            session_end="2025-01-15T14:45:00+00:00",
        )
        assert isinstance(report, PrivacyReport)
        assert report.report_id != ""
        assert report.overall_verdict == "SAFE"
        assert report.duration_minutes == 45.0

    def test_generate_report_elevated(self):
        gen = ReportGenerator()
        report = gen.generate_session_report(
            threat_score=_make_threat_score(
                tier="Elevated", unified_score=65.0),
        )
        assert report.overall_verdict == "ELEVATED"

    def test_generate_report_critical(self):
        gen = ReportGenerator()
        report = gen.generate_session_report(
            threat_score=_make_threat_score(
                tier="Critical", unified_score=92.0),
        )
        assert report.overall_verdict == "CRITICAL"

    def test_generate_report_strips_nearby_networks(self):
        """Privacy: nearby_networks should NOT appear in report."""
        gen = ReportGenerator()
        wifi = _make_wifi_report(nearby_networks=[
            {"ssid": "Neighbor", "bssid": "FF:FF:FF:FF:FF:FF"}])
        report = gen.generate_session_report(wifi_report=wifi)
        assert "nearby_networks" not in report.wifi_summary

    def test_generate_report_strips_tracker_connections(self):
        """Privacy: tracker_connections should NOT appear in report."""
        gen = ReportGenerator()
        web = _make_web_report(tracker_connections=[
            {"remote_ip": "1.2.3.4", "remote_domain": "tracker.com"}])
        report = gen.generate_session_report(web_report=web)
        assert "tracker_connections" not in report.web_summary

    def test_generate_report_with_hardening_recs(self):
        rec = HardeningRecommendation(
            category="WIFI", priority="IMMEDIATE",
            title="Disconnect", description="Open network",
            action_steps=["Step 1", "Step 2"],
        )
        gen = ReportGenerator()
        report = gen.generate_session_report(
            threat_score=_make_threat_score(),
            hardening_recommendations=[rec],
        )
        assert len(report.hardening_recommendations) == 1
        assert report.hardening_recommendations[0]["title"] == "Disconnect"

    def test_generate_report_none_reports(self):
        """All reports can be None — should produce a valid report."""
        gen = ReportGenerator()
        report = gen.generate_session_report()
        assert isinstance(report, PrivacyReport)
        assert report.overall_verdict == "SAFE"


class TestExportJSON:
    def test_export_creates_file(self, tmp_path):
        gen = ReportGenerator()
        report = gen.generate_session_report(
            threat_score=_make_threat_score())
        path = str(tmp_path / "test_report.json")
        result = gen.export_json(report, path)
        assert os.path.exists(result)
        with open(result) as f:
            data = json.load(f)
        assert data["report_id"] == report.report_id

    def test_export_json_valid_structure(self, tmp_path):
        gen = ReportGenerator()
        report = gen.generate_session_report(
            wifi_report=_make_wifi_report(),
            behavioral_report=_make_behavioral_report(),
            web_report=_make_web_report(),
            threat_score=_make_threat_score(),
        )
        path = str(tmp_path / "full_report.json")
        gen.export_json(report, path)
        with open(path) as f:
            data = json.load(f)
        required_keys = [
            "report_id", "session_start", "session_end",
            "threat_score_summary", "wifi_summary", "behavioral_summary",
            "web_summary", "overall_verdict", "generated_at",
        ]
        for key in required_keys:
            assert key in data, f"Missing key: {key}"

    def test_export_json_default_path(self):
        """Without explicit path, should write to data/reports/."""
        gen = ReportGenerator()
        report = gen.generate_session_report(
            threat_score=_make_threat_score())
        path = gen.export_json(report)
        try:
            assert os.path.exists(path)
            assert "report_" in Path(path).name
            assert path.endswith(".json")
        finally:
            if os.path.exists(path):
                os.remove(path)


class TestExportTXT:
    def test_export_creates_file(self, tmp_path):
        gen = ReportGenerator()
        report = gen.generate_session_report(
            wifi_report=_make_wifi_report(),
            threat_score=_make_threat_score(),
        )
        path = str(tmp_path / "test_report.txt")
        result = gen.export_txt(report, path)
        assert os.path.exists(result)

    def test_txt_contains_sections(self, tmp_path):
        gen = ReportGenerator()
        report = gen.generate_session_report(
            wifi_report=_make_wifi_report(),
            behavioral_report=_make_behavioral_report(),
            web_report=_make_web_report(),
            threat_score=_make_threat_score(),
        )
        path = str(tmp_path / "sections.txt")
        gen.export_txt(report, path)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        assert "PRIVACY AUDIT REPORT" in text
        assert "OVERALL VERDICT" in text
        assert "[WI-FI]" in text
        assert "[PROCESSES]" in text
        assert "[WEB TRACKING]" in text
        assert "RECOMMENDATIONS" in text

    def test_txt_contains_threats(self, tmp_path):
        gen = ReportGenerator()
        wifi = _make_wifi_report(
            threats_detected=["Evil-twin AP detected"])
        report = gen.generate_session_report(
            wifi_report=wifi,
            threat_score=_make_threat_score(wifi_score=60),
        )
        path = str(tmp_path / "threats.txt")
        gen.export_txt(report, path)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        assert "Evil-twin AP detected" in text


class TestReportHistory:
    def test_empty_history(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "REPORT_DIR", tmp_path / "empty_reports")
        gen = ReportGenerator()
        gen._report_dir = tmp_path / "empty_reports"
        history = gen.get_report_history()
        assert history == []

    def test_history_returns_reports(self, tmp_path, monkeypatch):
        report_dir = tmp_path / "reports"
        report_dir.mkdir()
        monkeypatch.setattr(config, "REPORT_DIR", report_dir)

        gen = ReportGenerator()
        gen._report_dir = report_dir

        # Create two reports
        r1 = gen.generate_session_report(
            threat_score=_make_threat_score())
        r2 = gen.generate_session_report(
            threat_score=_make_threat_score(tier="Elevated"))
        gen.export_json(r1, str(report_dir / "report_20250115_140000.json"))
        gen.export_json(r2, str(report_dir / "report_20250115_144500.json"))

        history = gen.get_report_history()
        assert len(history) == 2
        # Newest first
        assert history[0].overall_verdict in ("SAFE", "ELEVATED")


# ═══════════════════════════════════════════════════════════════════════
# TEST: HardeningAdvisor
# ═══════════════════════════════════════════════════════════════════════

class TestHardeningAdvisorWiFi:
    def test_open_network(self):
        advisor = HardeningAdvisor()
        wifi = _make_wifi_report(
            encryption="OPEN",
            threats_detected=["Connected to an OPEN (unencrypted) network"])
        recs = advisor.analyze(wifi_report=wifi)
        titles = [r.title for r in recs]
        assert "Disconnect from open network" in titles

    def test_evil_twin(self):
        advisor = HardeningAdvisor()
        wifi = _make_wifi_report(
            threats_detected=["Evil-twin AP(s) detected for SSID(s): HomeNet"])
        recs = advisor.analyze(wifi_report=wifi)
        titles = [r.title for r in recs]
        assert "Verify network with administrator" in titles

    def test_wep_encryption(self):
        advisor = HardeningAdvisor()
        wifi = _make_wifi_report(encryption="WEP",
            threats_detected=["Connected to a WEP network"])
        recs = advisor.analyze(wifi_report=wifi)
        titles = [r.title for r in recs]
        assert "Upgrade to WPA3-capable router" in titles

    def test_weak_signal(self):
        advisor = HardeningAdvisor()
        wifi = _make_wifi_report(signal_dbm=-80)
        recs = advisor.analyze(wifi_report=wifi)
        titles = [r.title for r in recs]
        assert "Improve Wi-Fi signal quality" in titles

    def test_safe_wifi_no_recs(self):
        advisor = HardeningAdvisor()
        wifi = _make_wifi_report()
        recs = advisor.analyze(wifi_report=wifi)
        wifi_recs = [r for r in recs if r.category == "WIFI"]
        assert len(wifi_recs) == 0


class TestHardeningAdvisorBehavioral:
    def test_high_cpu_deviation(self):
        advisor = HardeningAdvisor()
        beh = _make_behavioral_report(
            behavioral_score=55, baseline_deviation=35)
        recs = advisor.analyze(behavioral_report=beh)
        titles = [r.title for r in recs]
        assert "Review top CPU processes" in titles

    def test_suspicious_processes(self):
        advisor = HardeningAdvisor()
        beh = _make_behavioral_report(
            anomalous_processes=["mystery.exe", "cryptominer.exe"])
        recs = advisor.analyze(behavioral_report=beh)
        titles = [r.title for r in recs]
        assert "Investigate suspicious processes" in titles

    def test_clean_behavioral_no_recs(self):
        advisor = HardeningAdvisor()
        beh = _make_behavioral_report()
        recs = advisor.analyze(behavioral_report=beh)
        beh_recs = [r for r in recs if r.category == "PROCESSES"]
        assert len(beh_recs) == 0


class TestHardeningAdvisorWeb:
    def test_many_trackers(self):
        advisor = HardeningAdvisor()
        web = _make_web_report(unique_trackers_count=15)
        recs = advisor.analyze(web_report=web)
        titles = [r.title for r in recs]
        assert "Install tracker blocker extension" in titles

    def test_fingerprinting(self):
        advisor = HardeningAdvisor()
        web = _make_web_report(fingerprint_signals=[
            {"signal_type": "CANVAS", "detected": True, "confidence": 0.9}])
        recs = advisor.analyze(web_report=web)
        titles = [r.title for r in recs]
        assert "Enable anti-fingerprinting mode" in titles

    def test_multi_category(self):
        advisor = HardeningAdvisor()
        web = _make_web_report(
            active_categories=["Analytics", "Advertising", "Social"])
        recs = advisor.analyze(web_report=web)
        titles = [r.title for r in recs]
        assert "Review all browser privacy settings" in titles

    def test_advertising_heavy(self):
        advisor = HardeningAdvisor()
        web = _make_web_report(
            category_scores={"Advertising": 60, "Analytics": 20})
        recs = advisor.analyze(web_report=web)
        titles = [r.title for r in recs]
        assert "Block advertising networks" in titles

    def test_clean_web_no_recs(self):
        advisor = HardeningAdvisor()
        web = _make_web_report(
            unique_trackers_count=2, active_categories=["Analytics"])
        recs = advisor.analyze(web_report=web)
        browser_recs = [r for r in recs if r.category == "BROWSER"]
        assert len(browser_recs) == 0


class TestHardeningAdvisorUnified:
    def test_critical_score(self):
        advisor = HardeningAdvisor()
        score = _make_threat_score(tier="Critical", unified_score=92)
        recs = advisor.analyze(threat_score=score)
        titles = [r.title for r in recs]
        assert "Disconnect and investigate immediately" in titles

    def test_high_risk_score(self):
        advisor = HardeningAdvisor()
        score = _make_threat_score(tier="High Risk", unified_score=80)
        recs = advisor.analyze(threat_score=score)
        titles = [r.title for r in recs]
        assert "Review active threats urgently" in titles

    def test_safe_score_no_system_recs(self):
        advisor = HardeningAdvisor()
        score = _make_threat_score(tier="Safe", unified_score=10)
        recs = advisor.analyze(threat_score=score)
        sys_recs = [r for r in recs if r.category == "SYSTEM"]
        assert len(sys_recs) == 0


class TestGetPriorityActions:
    def test_sorted_by_priority(self):
        advisor = HardeningAdvisor()
        recs = [
            HardeningRecommendation("B", "LOW", "Low", ""),
            HardeningRecommendation("A", "IMMEDIATE", "Imm", ""),
            HardeningRecommendation("C", "HIGH", "High", ""),
            HardeningRecommendation("D", "MEDIUM", "Med", ""),
        ]
        sorted_recs = advisor.get_priority_actions(recs)
        priorities = [r.priority for r in sorted_recs]
        assert priorities == ["IMMEDIATE", "HIGH", "MEDIUM", "LOW"]


class TestFormatForDisplay:
    def test_empty_produces_ok_message(self):
        advisor = HardeningAdvisor()
        result = advisor.format_for_display([])
        assert "No hardening actions required" in result

    def test_format_with_recs(self):
        advisor = HardeningAdvisor()
        recs = [HardeningRecommendation(
            "WIFI", "IMMEDIATE", "Disconnect",
            "Open network", ["Step 1", "Step 2"], "Finding X")]
        result = advisor.format_for_display(recs)
        assert "[IMMEDIATE]" in result
        assert "[WIFI]" in result
        assert "Disconnect" in result
        assert "Step 1" in result


# ═══════════════════════════════════════════════════════════════════════
# TEST: End-to-End Integration
# ═══════════════════════════════════════════════════════════════════════

class TestEndToEnd:
    def test_full_session_to_export(self, tmp_path):
        """Simulate a complete session: analyze → report → export → verify."""
        # 1. Create module reports with findings
        wifi = _make_wifi_report(
            encryption="OPEN",
            threats_detected=[
                "Connected to an OPEN (unencrypted) network",
                "Evil-twin AP(s) detected for SSID(s): CoffeeShop",
            ],
            severity="HIGH",
            signal_dbm=-75,
        )
        beh = _make_behavioral_report(
            behavioral_score=55,
            baseline_deviation=35,
            anomalous_processes=["mystery.exe"],
        )
        web = _make_web_report(
            unique_trackers_count=14,
            category_scores={
                "Analytics": 35, "Advertising": 55,
                "Social": 30, "Fingerprint": 40,
            },
            active_categories=["Analytics", "Advertising", "Social", "Fingerprint"],
            fingerprint_signals=[
                {"signal_type": "CANVAS", "detected": True, "confidence": 0.87},
            ],
        )
        threat = _make_threat_score(
            wifi_score=72, behavioral_score=55, web_score=68,
            unified_score=61, tier="Elevated",
        )

        # 2. Run hardening analysis
        advisor = HardeningAdvisor()
        recs = advisor.analyze(
            wifi_report=wifi, behavioral_report=beh,
            web_report=web, threat_score=threat,
        )
        assert len(recs) >= 5  # Should produce many recommendations
        sorted_recs = advisor.get_priority_actions(recs)
        assert sorted_recs[0].priority in ("IMMEDIATE", "HIGH")

        # 3. Generate report
        gen = ReportGenerator()
        report = gen.generate_session_report(
            wifi_report=wifi,
            behavioral_report=beh,
            web_report=web,
            threat_score=threat,
            session_start="2025-01-15T14:00:00+00:00",
            session_end="2025-01-15T14:45:00+00:00",
            hardening_recommendations=recs,
        )
        assert report.overall_verdict == "ELEVATED"
        assert report.duration_minutes == 45.0
        assert len(report.hardening_recommendations) >= 5

        # 4. Export to JSON
        json_path = str(tmp_path / "e2e_report.json")
        gen.export_json(report, json_path)
        assert os.path.exists(json_path)
        with open(json_path) as f:
            data = json.load(f)
        assert data["overall_verdict"] == "ELEVATED"
        assert "nearby_networks" not in data["wifi_summary"]

        # 5. Export to TXT
        txt_path = str(tmp_path / "e2e_report.txt")
        gen.export_txt(report, txt_path)
        assert os.path.exists(txt_path)
        with open(txt_path, encoding="utf-8") as f:
            text = f.read()
        assert "ELEVATED" in text
        assert "[WI-FI]" in text
        assert "Evil-twin" in text
        assert "CANVAS" in text
        assert "[IMMEDIATE]" in text or "[HIGH]" in text

    def test_clean_session_minimal_recs(self, tmp_path):
        """A clean session should produce few or no recommendations."""
        wifi = _make_wifi_report()
        beh = _make_behavioral_report()
        web = _make_web_report(unique_trackers_count=2,
                                active_categories=["Analytics"])
        threat = _make_threat_score()

        advisor = HardeningAdvisor()
        recs = advisor.analyze(
            wifi_report=wifi, behavioral_report=beh,
            web_report=web, threat_score=threat,
        )
        assert len(recs) <= 2  # At most minor recs

        gen = ReportGenerator()
        report = gen.generate_session_report(
            wifi_report=wifi, behavioral_report=beh,
            web_report=web, threat_score=threat,
            hardening_recommendations=recs,
        )
        assert report.overall_verdict == "SAFE"

        json_path = str(tmp_path / "clean_report.json")
        gen.export_json(report, json_path)
        with open(json_path) as f:
            data = json.load(f)
        assert data["overall_verdict"] == "SAFE"
