"""
Unit tests for Wi-Fi Analysis & Responder (Milestone 01)

Tests the detection logic, data structures, and responder behaviour
using mocked scan data — no real Wi-Fi hardware required.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import config
from modules.wifi_analysis import WiFiAnalyzer, WiFiReport, _percent_to_dbm


# ── Sample scan data ────────────────────────────────────────────────

SAMPLE_NETWORKS = [
    {
        "ssid": "HomeNetwork",
        "bssid": "aa:bb:cc:dd:ee:01",
        "encryption": "WPA2-Personal",
        "signal_dbm": -55,
        "channel": 6,
    },
    {
        "ssid": "HomeNetwork",
        "bssid": "aa:bb:cc:dd:ee:02",
        "encryption": "Open",
        "signal_dbm": -45,
        "channel": 6,
    },
    {
        "ssid": "CoffeeShop",
        "bssid": "11:22:33:44:55:66",
        "encryption": "WPA2-Personal",
        "signal_dbm": -72,
        "channel": 11,
    },
    {
        "ssid": "",
        "bssid": "ff:ee:dd:cc:bb:aa",
        "encryption": "WPA2-Personal",
        "signal_dbm": -80,
        "channel": 1,
    },
    {
        "ssid": "FreeWiFi",
        "bssid": "00:11:22:33:44:55",
        "encryption": "Open",
        "signal_dbm": -60,
        "channel": 3,
    },
    {
        "ssid": "Open_Guest",
        "bssid": "00:11:22:33:44:66",
        "encryption": "Open",
        "signal_dbm": -65,
        "channel": 8,
    },
    {
        "ssid": "AnotherOpen",
        "bssid": "00:11:22:33:44:77",
        "encryption": "Open",
        "signal_dbm": -70,
        "channel": 9,
    },
]

SAMPLE_CONNECTED = {
    "ssid": "HomeNetwork",
    "bssid": "aa:bb:cc:dd:ee:01",
    "encryption": "WPA2-Personal",
    "signal_dbm": -55,
    "channel": 6,
    "state": "connected",
}

# ── Netsh mock output ───────────────────────────────────────────────

NETSH_SCAN_OUTPUT = """\
SSID 1 : HomeNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 85%
         Radio type         : 802.11ac
         Channel            : 6
    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 70%
         Radio type         : 802.11n
         Channel            : 6

SSID 2 : CoffeeShop
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 40%
         Radio type         : 802.11ac
         Channel            : 11
"""

NETSH_INTERFACE_OUTPUT = """\
    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : HomeNetwork
    BSSID                  : aa:bb:cc:dd:ee:01
    Authentication         : WPA2-Personal
    Channel                : 6
    Signal                 : 85%
"""


# ═════════════════════════════════════════════════════════════════════
#  Test Cases
# ═════════════════════════════════════════════════════════════════════


class TestWiFiReport(unittest.TestCase):
    """Test WiFiReport dataclass."""

    def test_default_values(self):
        report = WiFiReport(
            timestamp="2026-01-01T00:00:00Z",
            connected_ssid="TestNet",
            bssid="aa:bb:cc:dd:ee:ff",
            encryption="WPA2",
            signal_dbm=-60,
        )
        self.assertEqual(report.severity, "LOW")
        self.assertEqual(report.raw_score, 0.0)
        self.assertIsInstance(report.threats_detected, list)
        self.assertEqual(len(report.threats_detected), 0)

    def test_to_dict(self):
        report = WiFiReport(
            timestamp="2026-01-01T00:00:00Z",
            connected_ssid="TestNet",
            bssid="aa:bb:cc:dd:ee:ff",
            encryption="WPA2",
            signal_dbm=-60,
            threats_detected=["open_network"],
            severity="MEDIUM",
            raw_score=0.35,
        )
        d = report.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["connected_ssid"], "TestNet")
        self.assertEqual(d["severity"], "MEDIUM")
        # Must be JSON-serialisable
        json_str = json.dumps(d)
        self.assertIn("TestNet", json_str)


class TestEvilTwinDetection(unittest.TestCase):
    """Test evil-twin (duplicate SSID) detection."""

    def setUp(self):
        self.analyzer = WiFiAnalyzer()

    def test_detects_twin(self):
        """Two APs with same SSID but different BSSIDs → flagged."""
        twins = self.analyzer.detect_evil_twin(SAMPLE_NETWORKS)
        # "HomeNetwork" appears twice with different BSSIDs
        twin_ssids = {t["ssid"] for t in twins}
        self.assertIn("HomeNetwork", twin_ssids)

    def test_no_false_positive_unique_ssids(self):
        """Unique SSIDs should not be flagged."""
        unique_nets = [
            {"ssid": "Net_A", "bssid": "00:00:00:00:00:01", "signal_dbm": -50},
            {"ssid": "Net_B", "bssid": "00:00:00:00:00:02", "signal_dbm": -60},
        ]
        twins = self.analyzer.detect_evil_twin(unique_nets)
        self.assertEqual(len(twins), 0)

    def test_ignores_empty_ssids(self):
        """Hidden SSIDs (empty string) should NOT trigger twin detection."""
        hidden_nets = [
            {"ssid": "", "bssid": "00:00:00:00:00:01", "signal_dbm": -50},
            {"ssid": "", "bssid": "00:00:00:00:00:02", "signal_dbm": -60},
        ]
        twins = self.analyzer.detect_evil_twin(hidden_nets)
        self.assertEqual(len(twins), 0)

    def test_twin_has_metadata(self):
        """Flagged twins should contain extra metadata keys."""
        twins = self.analyzer.detect_evil_twin(SAMPLE_NETWORKS)
        for t in twins:
            if t["ssid"] == "HomeNetwork":
                self.assertIn("twin_bssids", t)
                self.assertIn("rssi_delta", t)
                self.assertIn("threat", t)
                self.assertEqual(t["threat"], "evil_twin")


class TestEncryptionEvaluation(unittest.TestCase):
    """Test encryption classifier."""

    def setUp(self):
        self.analyzer = WiFiAnalyzer()

    def test_open(self):
        self.assertEqual(
            self.analyzer.evaluate_encryption({"encryption": "Open"}), "OPEN"
        )
        self.assertEqual(
            self.analyzer.evaluate_encryption({"encryption": ""}), "OPEN"
        )
        self.assertEqual(
            self.analyzer.evaluate_encryption({}), "OPEN"
        )

    def test_wep(self):
        self.assertEqual(
            self.analyzer.evaluate_encryption({"encryption": "WEP"}), "WEP"
        )

    def test_wpa2(self):
        self.assertEqual(
            self.analyzer.evaluate_encryption({"encryption": "WPA2-Personal"}),
            "WPA2",
        )

    def test_wpa3(self):
        self.assertEqual(
            self.analyzer.evaluate_encryption({"encryption": "WPA3-SAE"}),
            "WPA3",
        )

    def test_wpa_generic(self):
        self.assertEqual(
            self.analyzer.evaluate_encryption({"encryption": "WPA-TKIP"}),
            "WPA",
        )


class TestHiddenSSID(unittest.TestCase):
    """Test hidden SSID detection."""

    def setUp(self):
        self.analyzer = WiFiAnalyzer()

    def test_detects_hidden(self):
        hidden = self.analyzer.detect_hidden_ssid(SAMPLE_NETWORKS)
        self.assertTrue(len(hidden) >= 1)
        for h in hidden:
            self.assertEqual(h["threat"], "hidden_ssid")

    def test_no_hidden(self):
        nets = [
            {"ssid": "Visible_Net", "bssid": "00:00:00:00:00:01"},
        ]
        hidden = self.analyzer.detect_hidden_ssid(nets)
        self.assertEqual(len(hidden), 0)


class TestSignalAnomaly(unittest.TestCase):
    """Test signal anomaly detection."""

    def setUp(self):
        self.analyzer = WiFiAnalyzer()

    @patch.object(WiFiAnalyzer, "get_connected_network")
    def test_flags_strong_unknown(self, mock_conn):
        mock_conn.return_value = {"bssid": "aa:bb:cc:dd:ee:01"}
        strong_ap = [
            {
                "ssid": "Rogue",
                "bssid": "99:99:99:99:99:99",
                "signal_dbm": -20,  # suspiciously strong
            },
        ]
        anomalies = self.analyzer.detect_signal_anomaly(strong_ap)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["threat"], "signal_anomaly")

    @patch.object(WiFiAnalyzer, "get_connected_network")
    def test_ignores_connected(self, mock_conn):
        mock_conn.return_value = {"bssid": "aa:bb:cc:dd:ee:01"}
        same_ap = [
            {
                "ssid": "MyNet",
                "bssid": "aa:bb:cc:dd:ee:01",
                "signal_dbm": -20,
            },
        ]
        anomalies = self.analyzer.detect_signal_anomaly(same_ap)
        self.assertEqual(len(anomalies), 0)


class TestNetshParsing(unittest.TestCase):
    """Test Windows netsh output parsers."""

    def setUp(self):
        self.analyzer = WiFiAnalyzer()

    def test_parse_netsh_scan(self):
        networks = WiFiAnalyzer._parse_netsh_scan(NETSH_SCAN_OUTPUT)
        self.assertEqual(len(networks), 3)

        # First BSSID
        self.assertEqual(networks[0]["ssid"], "HomeNetwork")
        self.assertEqual(networks[0]["bssid"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(networks[0]["channel"], 6)
        self.assertEqual(networks[0]["signal_percent"], 85)
        self.assertEqual(networks[0]["encryption"], "WPA2-Personal")

        # CoffeeShop
        self.assertEqual(networks[2]["ssid"], "CoffeeShop")
        self.assertEqual(networks[2]["signal_percent"], 40)

    def test_parse_netsh_interface(self):
        info = WiFiAnalyzer._parse_netsh_interface(NETSH_INTERFACE_OUTPUT)
        self.assertEqual(info["ssid"], "HomeNetwork")
        self.assertEqual(info["bssid"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(info["signal_percent"], 85)
        self.assertEqual(info["encryption"], "WPA2-Personal")
        self.assertEqual(info["channel"], 6)

    def test_parse_disconnected_interface(self):
        output = "    State                  : disconnected\n"
        info = WiFiAnalyzer._parse_netsh_interface(output)
        self.assertEqual(info, {})


class TestPercentToDbm(unittest.TestCase):
    """Test the Windows signal quality → dBm converter."""

    def test_100_percent(self):
        self.assertEqual(_percent_to_dbm(100), -50)

    def test_0_percent(self):
        self.assertEqual(_percent_to_dbm(0), -100)

    def test_50_percent(self):
        self.assertEqual(_percent_to_dbm(50), -75)


class TestRunAnalysis(unittest.TestCase):
    """Integration-style test for the full analysis pipeline."""

    @patch.object(WiFiAnalyzer, "get_connected_network")
    @patch.object(WiFiAnalyzer, "scan_networks")
    def test_clean_network(self, mock_scan, mock_conn):
        """A clean, well-encrypted network should produce LOW severity."""
        mock_scan.return_value = [
            {
                "ssid": "SafeNet",
                "bssid": "aa:bb:cc:dd:ee:01",
                "encryption": "WPA2-Personal",
                "signal_dbm": -50,
                "channel": 6,
            },
        ]
        mock_conn.return_value = {
            "ssid": "SafeNet",
            "bssid": "aa:bb:cc:dd:ee:01",
            "encryption": "WPA2-Personal",
            "signal_dbm": -50,
        }

        analyzer = WiFiAnalyzer()
        report = analyzer.run_analysis()

        self.assertIsInstance(report, WiFiReport)
        self.assertEqual(report.severity, "LOW")
        self.assertEqual(len(report.threats_detected), 0)
        self.assertLess(report.raw_score, 0.3)

    @patch.object(WiFiAnalyzer, "get_connected_network")
    @patch.object(WiFiAnalyzer, "scan_networks")
    def test_open_network_medium_severity(self, mock_scan, mock_conn):
        """Connecting to an open network should produce at least MEDIUM."""
        mock_scan.return_value = [
            {
                "ssid": "FreeWiFi",
                "bssid": "00:11:22:33:44:55",
                "encryption": "Open",
                "signal_dbm": -60,
                "channel": 3,
            },
        ]
        mock_conn.return_value = {
            "ssid": "FreeWiFi",
            "bssid": "00:11:22:33:44:55",
            "encryption": "Open",
            "signal_dbm": -60,
        }

        analyzer = WiFiAnalyzer()
        report = analyzer.run_analysis()

        self.assertIn(report.severity, ("MEDIUM", "HIGH", "CRITICAL"))
        self.assertTrue(
            any("OPEN" in t or "open" in t.lower() for t in report.threats_detected)
        )

    @patch.object(WiFiAnalyzer, "get_connected_network")
    @patch.object(WiFiAnalyzer, "scan_networks")
    def test_evil_twin_high_severity(self, mock_scan, mock_conn):
        """Evil twin presence should elevate severity to HIGH."""
        mock_scan.return_value = SAMPLE_NETWORKS[:2]  # HomeNetwork × 2
        mock_conn.return_value = SAMPLE_CONNECTED

        analyzer = WiFiAnalyzer()
        report = analyzer.run_analysis()

        self.assertIn(report.severity, ("HIGH", "CRITICAL"))
        self.assertTrue(
            any("evil" in t.lower() or "twin" in t.lower() for t in report.threats_detected)
        )

    @patch.object(WiFiAnalyzer, "get_connected_network")
    @patch.object(WiFiAnalyzer, "scan_networks")
    def test_critical_signal(self, mock_scan, mock_conn):
        """Signal below critical threshold should trigger CRITICAL."""
        mock_scan.return_value = []
        mock_conn.return_value = {
            "ssid": "WeakNet",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "WPA2-Personal",
            "signal_dbm": -90,
        }

        analyzer = WiFiAnalyzer()
        report = analyzer.run_analysis()

        self.assertEqual(report.severity, "CRITICAL")
        self.assertTrue(
            any("CRITICAL" in t or "signal" in t.lower() for t in report.threats_detected)
        )

    @patch.object(WiFiAnalyzer, "get_connected_network")
    @patch.object(WiFiAnalyzer, "scan_networks")
    def test_report_serialisable(self, mock_scan, mock_conn):
        """WiFiReport.to_dict() must be JSON-serialisable."""
        mock_scan.return_value = SAMPLE_NETWORKS
        mock_conn.return_value = SAMPLE_CONNECTED

        analyzer = WiFiAnalyzer()
        report = analyzer.run_analysis()
        d = report.to_dict()

        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)
        self.assertIn(report.connected_ssid, json_str)


class TestWiFiResponder(unittest.TestCase):
    """Test WiFiResponder behaviour."""

    def _make_report(self, severity: str = "LOW", threats: list | None = None):
        return WiFiReport(
            timestamp="2026-01-01T00:00:00Z",
            connected_ssid="TestNet",
            bssid="aa:bb:cc:dd:ee:ff",
            encryption="WPA2",
            signal_dbm=-60,
            threats_detected=threats or [],
            severity=severity,
            raw_score=0.5,
        )

    def test_import_responder(self):
        """WiFiResponder should be importable."""
        from modules.wifi_responder import WiFiResponder

        responder = WiFiResponder()
        self.assertIsNotNone(responder)

    @patch("modules.wifi_responder.WiFiResponder.toggle_vpn")
    @patch("modules.wifi_responder.WiFiResponder.alert_user")
    @patch("modules.wifi_responder.WiFiResponder.log_incident")
    def test_medium_triggers_alert(self, mock_log, mock_alert, mock_vpn):
        from modules.wifi_responder import WiFiResponder

        responder = WiFiResponder()
        report = self._make_report("MEDIUM", ["open network"])
        responder.on_threshold_breach(report)

        mock_log.assert_called_once()
        mock_alert.assert_called_once()
        mock_vpn.assert_not_called()

    @patch("modules.wifi_responder.WiFiResponder._apply_hardened_dns")
    @patch("modules.wifi_responder.WiFiResponder.toggle_vpn")
    @patch("modules.wifi_responder.WiFiResponder.alert_user")
    @patch("modules.wifi_responder.WiFiResponder.log_incident")
    def test_high_triggers_vpn(self, mock_log, mock_alert, mock_vpn, mock_dns):
        from modules.wifi_responder import WiFiResponder

        responder = WiFiResponder()
        report = self._make_report("HIGH", ["evil twin detected"])
        responder.on_threshold_breach(report)

        mock_log.assert_called_once()
        mock_alert.assert_called_once()
        mock_vpn.assert_called_once_with(state=True)
        mock_dns.assert_called_once()

    @patch("modules.wifi_responder.WiFiResponder._apply_hardened_dns")
    @patch("modules.wifi_responder.WiFiResponder.disconnect_network")
    @patch("modules.wifi_responder.WiFiResponder.toggle_vpn")
    @patch("modules.wifi_responder.WiFiResponder.alert_user")
    @patch("modules.wifi_responder.WiFiResponder.log_incident")
    def test_critical_no_disconnect_by_default(
        self, mock_log, mock_alert, mock_vpn, mock_disconnect, mock_dns
    ):
        """CRITICAL should NOT disconnect when AUTO_DISCONNECT_ON_ROGUE is False."""
        from modules.wifi_responder import WiFiResponder

        original = config.AUTO_DISCONNECT_ON_ROGUE
        try:
            config.AUTO_DISCONNECT_ON_ROGUE = False

            responder = WiFiResponder()
            report = self._make_report("CRITICAL", ["critical threat"])
            responder.on_threshold_breach(report)

            # disconnect_network should NOT be called because the flag is off
            mock_disconnect.assert_not_called()
            mock_dns.assert_called_once()
        finally:
            config.AUTO_DISCONNECT_ON_ROGUE = original

    @patch("modules.wifi_responder.WiFiResponder._apply_hardened_dns")
    @patch("modules.wifi_responder.WiFiResponder.toggle_vpn")
    @patch("modules.wifi_responder.WiFiResponder.alert_user")
    def test_unified_score_triggers_auto_protection(
        self, mock_alert, mock_vpn, mock_dns
    ):
        from modules.wifi_responder import WiFiResponder

        responder = WiFiResponder()
        report = self._make_report("LOW", ["low threat"])

        activated = responder.evaluate_auto_protection(80.0, wifi_report=report)

        self.assertTrue(activated)
        mock_alert.assert_called_once()
        mock_vpn.assert_called_once_with(state=True)
        mock_dns.assert_called_once()

        activated_again = responder.evaluate_auto_protection(
            82.0, wifi_report=report,
        )
        self.assertFalse(activated_again)
        mock_vpn.assert_called_once()
        mock_dns.assert_called_once()

    @patch("modules.wifi_responder.subprocess.run")
    def test_apply_hardened_dns_linux_uses_resolvectl(self, mock_run):
        from modules.wifi_responder import WiFiResponder

        mock_run.side_effect = [
            MagicMock(
                returncode=0,
                stdout="default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.50\n",
            ),
            MagicMock(returncode=0),
        ]

        responder = WiFiResponder()
        responder._os = "Linux"
        responder._apply_hardened_dns()

        self.assertGreaterEqual(mock_run.call_count, 2)
        cmd = mock_run.call_args_list[-1].args[0]
        self.assertIn("resolvectl", cmd)

    @patch("modules.wifi_responder.subprocess.run")
    def test_apply_hardened_dns_windows_uses_netsh(self, mock_run):
        from modules.wifi_responder import WiFiResponder

        mock_run.return_value = MagicMock(returncode=0)

        responder = WiFiResponder()
        responder._os = "Windows"
        responder._apply_hardened_dns()

        self.assertGreaterEqual(mock_run.call_count, 2)
        first_cmd = mock_run.call_args_list[0].args[0]
        self.assertIn("netsh", first_cmd)

    def test_log_incident_creates_file(self):
        """log_incident should write a JSONL entry."""
        from modules.wifi_responder import WiFiResponder, INCIDENT_LOG

        responder = WiFiResponder()
        report = self._make_report("LOW")

        # Clean up before test
        if INCIDENT_LOG.exists():
            INCIDENT_LOG.unlink()

        responder.log_incident(report)

        self.assertTrue(INCIDENT_LOG.exists())
        with open(INCIDENT_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertTrue(len(lines) >= 1)

        entry = json.loads(lines[-1])
        self.assertEqual(entry["connected_ssid"], "TestNet")
        self.assertIn("logged_at", entry)


class TestRawScoring(unittest.TestCase):
    """Test the raw score computation."""

    def test_low_severity_low_score(self):
        score = WiFiAnalyzer._compute_raw_score([], "LOW", "WPA2", -50)
        self.assertLess(score, 0.3)

    def test_high_severity_higher_score(self):
        score = WiFiAnalyzer._compute_raw_score(
            ["threat1", "threat2"], "HIGH", "OPEN", -85
        )
        self.assertGreater(score, 0.5)

    def test_score_capped_at_one(self):
        score = WiFiAnalyzer._compute_raw_score(
            ["t1", "t2", "t3", "t4", "t5", "t6"], "CRITICAL", "OPEN", -95
        )
        self.assertLessEqual(score, 1.0)


if __name__ == "__main__":
    unittest.main()
