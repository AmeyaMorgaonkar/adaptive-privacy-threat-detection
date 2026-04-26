"""
Wi-Fi Analysis Module (Milestone 01)

Scans nearby wireless networks, identifies open/rogue access points,
evaluates encryption strength, detects evil-twin APs, and produces
a structured `WiFiReport` for downstream threat scoring.
"""

from __future__ import annotations

import platform
import re
import subprocess
import sys
import time
import json
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

# ── Data Structures ──────────────────────────────────────────────────


@dataclass
class WiFiReport:
    """Structured output of a single Wi-Fi analysis pass."""

    timestamp: str
    connected_ssid: str
    bssid: str
    encryption: str
    signal_dbm: int
    nearby_networks: list[dict] = field(default_factory=list)
    threats_detected: list[str] = field(default_factory=list)
    severity: str = "LOW"  # LOW / MEDIUM / HIGH / CRITICAL
    raw_score: float = 0.0  # 0.0–1.0, passed to threat scorer

    def to_dict(self) -> dict:
        """Serialise report to a plain dictionary (JSON-safe)."""
        return asdict(self)


# ── Severity helpers ─────────────────────────────────────────────────

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _max_severity(*levels: str) -> str:
    """Return the highest severity among the given levels."""
    return max(levels, key=lambda s: _SEVERITY_ORDER.get(s, 0))


# ── WiFiAnalyzer ─────────────────────────────────────────────────────


class WiFiAnalyzer:
    """Scans the local wireless environment and produces threat reports."""

    def __init__(self) -> None:
        self._os = platform.system()  # Windows / Linux / Darwin
        self._signal_history: list[int] = []

    # ── Public API ───────────────────────────────────────────────────

    def scan_networks(self) -> list[dict]:
        """Discover nearby Wi-Fi networks and return metadata for each.

        Each dict contains:
            ssid, bssid, signal_dbm, channel, encryption
        """
        if self._os == "Windows":
            return self._scan_windows()
        elif self._os == "Linux":
            return self._scan_linux()
        elif self._os == "Darwin":
            return self._scan_macos()
        else:
            log.warning("Unsupported OS for Wi-Fi scanning: %s", self._os)
            return []

    def get_connected_network(self) -> dict:
        """Return metadata of the currently connected Wi-Fi network.

        Returns an empty dict if no Wi-Fi connection is active.
        """
        if self._os == "Windows":
            return self._connected_windows()
        elif self._os == "Linux":
            return self._connected_linux()
        elif self._os == "Darwin":
            return self._connected_macos()
        else:
            return {}

    def detect_evil_twin(self, networks: list[dict]) -> list[dict]:
        """Flag networks that share an SSID but have different BSSIDs.

        Returns a list of suspicious network dicts with an added
        ``twin_bssids`` key listing the conflicting BSSIDs.
        """
        ssid_map: dict[str, list[dict]] = {}
        for net in networks:
            ssid = net.get("ssid", "")
            if not ssid:
                continue
            ssid_map.setdefault(ssid, []).append(net)

        twins: list[dict] = []
        for ssid, group in ssid_map.items():
            if len(group) < 2:
                continue

            bssids = [n.get("bssid", "") for n in group]
            unique_bssids = set(bssids)
            if len(unique_bssids) < 2:
                continue

            # Check if signal strengths vary significantly (RSSI delta)
            signals = [n.get("signal_dbm", -100) for n in group]
            max_delta = max(signals) - min(signals)

            for net in group:
                entry = dict(net)
                entry["twin_bssids"] = list(unique_bssids - {net.get("bssid", "")})
                entry["rssi_delta"] = max_delta
                entry["threat"] = "evil_twin"
                twins.append(entry)

            log.warning(
                "Evil-twin candidate: SSID=%r  BSSIDs=%s  RSSI-delta=%d dBm",
                ssid,
                unique_bssids,
                max_delta,
            )

        return twins

    @staticmethod
    def evaluate_encryption(network: dict) -> str:
        """Classify the encryption type of a network.

        Returns one of: OPEN, WEP, WPA, WPA2, WPA3, UNKNOWN
        """
        raw = (network.get("encryption") or network.get("auth") or "").upper()

        if not raw or raw in ("OPEN", "NONE", ""):
            return "OPEN"
        if "WPA3" in raw:
            return "WPA3"
        if "WPA2" in raw:
            return "WPA2"
        if "WPA" in raw:
            return "WPA"
        if "WEP" in raw:
            return "WEP"
        return "UNKNOWN"

    def get_signal_strength(self) -> int:
        """Return the signal strength (dBm) of the connected network.

        Falls back to -100 if unavailable.
        """
        connected = self.get_connected_network()
        dbm = connected.get("signal_dbm", -100)
        self._signal_history.append(dbm)

        # Keep a rolling window
        max_history = config.PROFILE_HISTORY_WINDOW
        if len(self._signal_history) > max_history:
            self._signal_history = self._signal_history[-max_history:]

        return dbm

    def detect_hidden_ssid(self, networks: list[dict]) -> list[dict]:
        """Flag networks broadcasting an empty / null SSID."""
        hidden = []
        for net in networks:
            ssid = net.get("ssid", "").strip()
            if not ssid:
                entry = dict(net)
                entry["threat"] = "hidden_ssid"
                hidden.append(entry)
        return hidden

    def detect_signal_anomaly(self, networks: list[dict]) -> list[dict]:
        """Flag unknown APs with unusually strong signal spikes."""
        connected = self.get_connected_network()
        connected_bssid = connected.get("bssid", "")

        anomalies = []
        for net in networks:
            bssid = net.get("bssid", "")
            signal = net.get("signal_dbm", -100)
            if bssid == connected_bssid:
                continue
            # Very strong signal from unknown AP is suspicious
            if signal > config.SUSPICIOUS_SIGNAL_THRESHOLD_DBM:
                entry = dict(net)
                entry["threat"] = "signal_anomaly"
                anomalies.append(entry)
                log.warning(
                    "Signal anomaly: BSSID=%s  RSSI=%d dBm (threshold=%d)",
                    bssid,
                    signal,
                    config.SUSPICIOUS_SIGNAL_THRESHOLD_DBM,
                )
        return anomalies

    def run_analysis(self) -> WiFiReport:
        """Execute a full analysis pass and return a WiFiReport."""
        log.info("Starting Wi-Fi analysis pass")
        ts = datetime.now(timezone.utc).isoformat()

        # 1. Scan
        networks = self.scan_networks()
        connected = self.get_connected_network()
        signal = connected.get("signal_dbm", -100)

        # Update signal history
        self._signal_history.append(signal)
        if len(self._signal_history) > config.PROFILE_HISTORY_WINDOW:
            self._signal_history = self._signal_history[-config.PROFILE_HISTORY_WINDOW:]

        # 2. Run detections
        threats: list[str] = []
        severity = "LOW"

        # Evil-twin detection
        twins = self.detect_evil_twin(networks)
        if twins:
            threats.append(
                f"Evil-twin AP(s) detected for SSID(s): "
                f"{', '.join({t['ssid'] for t in twins})}"
            )
            severity = _max_severity(severity, "HIGH")

        # Encryption evaluation on connected network
        enc = self.evaluate_encryption(connected)
        if enc == "OPEN":
            threats.append("Connected to an OPEN (unencrypted) network")
            severity = _max_severity(severity, "MEDIUM")
        elif enc == "WEP":
            threats.append("Connected to a WEP network (weak encryption)")
            severity = _max_severity(severity, "HIGH")

        # Count open networks nearby
        open_count = sum(
            1 for n in networks if self.evaluate_encryption(n) == "OPEN"
        )
        if open_count > config.MAX_ALLOWED_OPEN_NETWORKS:
            threats.append(
                f"{open_count} open networks detected (threshold: "
                f"{config.MAX_ALLOWED_OPEN_NETWORKS})"
            )
            severity = _max_severity(severity, "MEDIUM")

        # Hidden SSIDs
        hidden = self.detect_hidden_ssid(networks)
        if hidden:
            threats.append(f"{len(hidden)} hidden-SSID network(s) detected")
            severity = _max_severity(severity, "LOW")

        # Signal anomalies
        anomalies = self.detect_signal_anomaly(networks)
        if anomalies:
            threats.append(
                f"Signal anomaly from {len(anomalies)} unknown AP(s)"
            )
            severity = _max_severity(severity, "MEDIUM")

        # Signal strength thresholds
        if signal < config.WIFI_SIGNAL_CRITICAL_DBM:
            threats.append(
                f"CRITICAL signal strength: {signal} dBm "
                f"(threshold: {config.WIFI_SIGNAL_CRITICAL_DBM})"
            )
            severity = _max_severity(severity, "CRITICAL")
        elif signal < config.WIFI_SIGNAL_WARN_DBM:
            threats.append(
                f"Weak signal: {signal} dBm "
                f"(threshold: {config.WIFI_SIGNAL_WARN_DBM})"
            )
            severity = _max_severity(severity, "MEDIUM")

        # 3. Compute raw_score (0.0 – 1.0)
        raw_score = self._compute_raw_score(threats, severity, enc, signal)

        report = WiFiReport(
            timestamp=ts,
            connected_ssid=connected.get("ssid", "Unknown"),
            bssid=connected.get("bssid", "Unknown"),
            encryption=enc,
            signal_dbm=signal,
            nearby_networks=networks,
            threats_detected=threats,
            severity=severity,
            raw_score=round(raw_score, 4),
        )

        log.info(
            "Analysis complete — severity=%s  threats=%d  score=%.2f",
            severity,
            len(threats),
            raw_score,
        )
        return report

    # ── Scoring ──────────────────────────────────────────────────────

    @staticmethod
    def _compute_raw_score(
        threats: list[str],
        severity: str,
        encryption: str,
        signal_dbm: int,
    ) -> float:
        """Combine heuristic findings into a 0.0–1.0 threat score."""
        score = 0.0

        # Base score from severity
        severity_weights = {"LOW": 0.1, "MEDIUM": 0.3, "HIGH": 0.6, "CRITICAL": 0.9}
        score += severity_weights.get(severity, 0.0)

        # Per-threat bump
        score += len(threats) * 0.05

        # Encryption penalty
        enc_penalty = {"OPEN": 0.2, "WEP": 0.15, "WPA": 0.05, "UNKNOWN": 0.1}
        score += enc_penalty.get(encryption, 0.0)

        # Weak signal adds minor risk
        if signal_dbm < -80:
            score += 0.05
            
        return min(score, 1.0)

    # ── Windows Scanning ─────────────────────────────────────────────

    def _scan_windows(self) -> list[dict]:
        """Parse `netsh wlan show networks mode=bssid`."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return self._parse_netsh_scan(result.stdout)
        except FileNotFoundError:
            log.error("netsh not found — is this a Windows system?")
            return []
        except subprocess.TimeoutExpired:
            log.error("netsh scan timed out")
            return []
        except Exception as exc:
            log.error("Windows scan failed: %s", exc)
            return []

    def _connected_windows(self) -> dict:
        """Parse `netsh wlan show interfaces` for the active connection."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return self._parse_netsh_interface(result.stdout)
        except Exception as exc:
            log.error("Failed to query Windows interface: %s", exc)
            return {}

    @staticmethod
    def _parse_netsh_scan(output: str) -> list[dict]:
        """Parse the output of `netsh wlan show networks mode=bssid`.

        Example block::
            SSID 1 : MyNetwork
                Network type            : Infrastructure
                Authentication          : WPA2-Personal
                Encryption              : CCMP
                BSSID 1                 : aa:bb:cc:dd:ee:ff
                     Signal             : 85%
                     Radio type         : 802.11ac
                     Channel            : 36
        """
        networks: list[dict] = []
        current_ssid: Optional[str] = None
        current_auth: Optional[str] = None
        current_enc_cipher: Optional[str] = None

        for line in output.splitlines():
            line = line.strip()

            ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)", line)
            if ssid_match:
                current_ssid = ssid_match.group(1).strip()
                current_auth = None
                current_enc_cipher = None
                continue

            auth_match = re.match(r"^Authentication\s*:\s*(.*)", line)
            if auth_match:
                current_auth = auth_match.group(1).strip()
                continue

            enc_match = re.match(r"^Encryption\s*:\s*(.*)", line)
            if enc_match:
                current_enc_cipher = enc_match.group(1).strip()
                continue

            bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*(.*)", line)
            if bssid_match:
                bssid = bssid_match.group(1).strip()
                # Start collecting per-BSSID fields
                net: dict = {
                    "ssid": current_ssid or "",
                    "bssid": bssid,
                    "encryption": current_auth or "Open",
                    "cipher": current_enc_cipher or "",
                    "signal_dbm": -100,
                    "signal_percent": 0,
                    "channel": 0,
                }
                networks.append(net)
                continue

            if networks:
                signal_match = re.match(r"^Signal\s*:\s*(\d+)%", line)
                if signal_match:
                    pct = int(signal_match.group(1))
                    networks[-1]["signal_percent"] = pct
                    networks[-1]["signal_dbm"] = _percent_to_dbm(pct)
                    continue

                chan_match = re.match(r"^Channel\s*:\s*(\d+)", line)
                if chan_match:
                    networks[-1]["channel"] = int(chan_match.group(1))
                    continue

        log.debug("Parsed %d networks from netsh scan", len(networks))
        return networks

    @staticmethod
    def _parse_netsh_interface(output: str) -> dict:
        """Extract connected-network details from `netsh wlan show interfaces`."""
        info: dict = {}
        for line in output.splitlines():
            line = line.strip()

            if line.startswith("SSID") and "BSSID" not in line:
                match = re.match(r"^SSID\s*:\s*(.*)", line)
                if match:
                    info["ssid"] = match.group(1).strip()

            elif line.startswith("BSSID"):
                match = re.match(r"^BSSID\s*:\s*(.*)", line)
                if match:
                    info["bssid"] = match.group(1).strip()

            elif line.startswith("Signal"):
                match = re.match(r"^Signal\s*:\s*(\d+)%", line)
                if match:
                    pct = int(match.group(1))
                    info["signal_percent"] = pct
                    info["signal_dbm"] = _percent_to_dbm(pct)

            elif line.startswith("Authentication"):
                match = re.match(r"^Authentication\s*:\s*(.*)", line)
                if match:
                    info["encryption"] = match.group(1).strip()

            elif line.startswith("Channel"):
                match = re.match(r"^Channel\s*:\s*(\d+)", line)
                if match:
                    info["channel"] = int(match.group(1))

            elif line.startswith("State"):
                match = re.match(r"^State\s*:\s*(.*)", line)
                if match:
                    info["state"] = match.group(1).strip()

        if info.get("state", "").lower() != "connected":
            log.info("Wi-Fi state is '%s' — no active connection", info.get("state", "N/A"))
            return {}

        return info

    # ── Linux Scanning ───────────────────────────────────────────────

    def _scan_linux(self) -> list[dict]:
        """Parse `iwlist <iface> scan` or `nmcli` output."""
        iface = self._get_linux_iface()
        if not iface:
            return []

        try:
            result = subprocess.run(
                ["sudo", "iwlist", iface, "scan"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            return self._parse_iwlist(result.stdout)
        except Exception as exc:
            log.error("Linux scan failed: %s", exc)
            return []

    def _connected_linux(self) -> dict:
        """Get connected network via `iwconfig`."""
        iface = self._get_linux_iface()
        if not iface:
            return {}

        try:
            result = subprocess.run(
                ["iwconfig", iface],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout
            info: dict = {}

            ssid_match = re.search(r'ESSID:"([^"]*)"', output)
            if ssid_match:
                info["ssid"] = ssid_match.group(1)

            bssid_match = re.search(r"Access Point:\s*([\da-fA-F:]+)", output)
            if bssid_match:
                info["bssid"] = bssid_match.group(1)

            signal_match = re.search(r"Signal level[=:](-?\d+)", output)
            if signal_match:
                info["signal_dbm"] = int(signal_match.group(1))

            return info if info.get("ssid") else {}
        except Exception as exc:
            log.error("Failed to query Linux interface: %s", exc)
            return {}

    @staticmethod
    def _get_linux_iface() -> Optional[str]:
        """Determine the default wireless interface name."""
        try:
            result = subprocess.run(
                ["iwconfig"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                if "IEEE 802.11" in line:
                    return line.split()[0]
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_iwlist(output: str) -> list[dict]:
        """Parse `iwlist scan` output into structured dicts."""
        networks: list[dict] = []
        current: Optional[dict] = None

        for line in output.splitlines():
            line = line.strip()

            if "Cell" in line and "Address:" in line:
                if current:
                    networks.append(current)
                bssid = line.split("Address:")[1].strip()
                current = {
                    "ssid": "",
                    "bssid": bssid,
                    "encryption": "OPEN",
                    "signal_dbm": -100,
                    "channel": 0,
                }

            if current is None:
                continue

            if line.startswith("ESSID:"):
                current["ssid"] = line.split('"')[1] if '"' in line else ""
            elif "Channel:" in line:
                chan_match = re.search(r"Channel:(\d+)", line)
                if chan_match:
                    current["channel"] = int(chan_match.group(1))
            elif "Signal level" in line:
                sig_match = re.search(r"Signal level[=:](-?\d+)", line)
                if sig_match:
                    current["signal_dbm"] = int(sig_match.group(1))
            elif "Encryption key:on" in line.lower():
                current["encryption"] = "WPA2"  # refined below
            elif "WPA2" in line:
                current["encryption"] = "WPA2"
            elif "WPA" in line:
                current["encryption"] = "WPA"

        if current:
            networks.append(current)

        return networks

    # ── macOS Scanning ───────────────────────────────────────────────

    def _get_macos_airport_data(self) -> dict:
        """Fetch Wi-Fi data via `system_profiler SPAirPortDataType -json`.

        Returns the first Wi-Fi interface dict (en0) or an empty dict.
        The deprecated `airport` CLI no longer produces output on
        macOS Sonoma and later, so we use system_profiler instead.
        """
        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            data = json.loads(result.stdout)
            interfaces = (
                data.get("SPAirPortDataType", [{}])[0]
                .get("spairport_airport_interfaces", [])
            )
            # Return the first real Wi-Fi interface (skip AWDL, etc.)
            for iface in interfaces:
                if iface.get("_name", "").startswith("en"):
                    return iface
            return interfaces[0] if interfaces else {}
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            log.error("system_profiler Wi-Fi query failed: %s", exc)
            return {}
        except Exception as exc:
            log.error("macOS Wi-Fi data fetch failed: %s", exc)
            return {}

    @staticmethod
    def _parse_security_mode(raw: str) -> str:
        """Map system_profiler security strings to simple labels.

        Example inputs:
            spairport_security_mode_wpa2_personal  -> WPA2
            spairport_security_mode_wpa3_personal  -> WPA3
            spairport_security_mode_open           -> OPEN
        """
        raw = raw.lower()
        if "wpa3" in raw:
            return "WPA3"
        if "wpa2" in raw:
            return "WPA2"
        if "wpa" in raw:
            return "WPA"
        if "wep" in raw:
            return "WEP"
        if "open" in raw or "none" in raw:
            return "OPEN"
        return "UNKNOWN"

    @staticmethod
    def _parse_signal_noise(value: str) -> tuple[int, int]:
        """Parse a 'signal / noise' string like '-59 dBm / -94 dBm'.

        Returns (signal_dbm, noise_dbm). Falls back to (-100, -100).
        """
        try:
            parts = value.split("/")
            signal = int(parts[0].strip().replace("dBm", "").strip())
            noise = int(parts[1].strip().replace("dBm", "").strip())
            return signal, noise
        except (IndexError, ValueError):
            return -100, -100

    @staticmethod
    def _parse_channel_info(value: str) -> int:
        """Extract channel number from e.g. '44 (5GHz, 80MHz)'."""
        try:
            return int(value.strip().split()[0])
        except (IndexError, ValueError):
            return 0

    def _scan_macos(self) -> list[dict]:
        """Scan nearby Wi-Fi networks on macOS via system_profiler."""
        iface_data = self._get_macos_airport_data()
        if not iface_data:
            return []

        raw_networks = iface_data.get(
            "spairport_airport_other_local_wireless_networks", []
        )

        networks: list[dict] = []
        for net in raw_networks:
            ssid = net.get("_name", "")
            security = self._parse_security_mode(
                net.get("spairport_security_mode", "")
            )
            channel = self._parse_channel_info(
                net.get("spairport_network_channel", "")
            )

            signal_dbm = -100
            sn = net.get("spairport_signal_noise", "")
            if sn:
                signal_dbm, _ = self._parse_signal_noise(sn)

            networks.append(
                {
                    "ssid": ssid,
                    "bssid": "",  # system_profiler doesn't expose per-AP BSSIDs
                    "signal_dbm": signal_dbm,
                    "channel": channel,
                    "encryption": security,
                }
            )

        log.debug("Parsed %d nearby networks via system_profiler", len(networks))
        return networks

    def _connected_macos(self) -> dict:
        """Fetch connected network info on macOS via system_profiler."""
        iface_data = self._get_macos_airport_data()
        if not iface_data:
            return {}

        # Check that the interface is actually connected
        status = iface_data.get("spairport_status_information", "")
        if "connected" not in status.lower():
            log.info("macOS Wi-Fi status: %s — not connected", status)
            return {}

        current = iface_data.get("spairport_current_network_information", {})
        if not current:
            return {}

        ssid = current.get("_name", "")
        if not ssid:
            return {}

        security = self._parse_security_mode(
            current.get("spairport_security_mode", "")
        )
        channel = self._parse_channel_info(
            current.get("spairport_network_channel", "")
        )

        signal_dbm = -100
        noise_dbm = -100
        sn = current.get("spairport_signal_noise", "")
        if sn:
            signal_dbm, noise_dbm = self._parse_signal_noise(sn)

        mac_address = iface_data.get("spairport_wireless_mac_address", "")

        return {
            "ssid": ssid,
            "bssid": mac_address,  # local MAC (per-AP BSSID not available)
            "signal_dbm": signal_dbm,
            "noise_dbm": noise_dbm,
            "channel": channel,
            "encryption": security,
        }


# ── Utilities ────────────────────────────────────────────────────────


def _percent_to_dbm(percent: int) -> int:
    """Convert Windows signal-quality percentage to approximate dBm.

    Windows reports quality as 0–100 %; the conventional mapping is:
        dBm = (quality / 2) - 100
    """
    return (percent // 2) - 100


def _print_terminal_summary(report: WiFiReport) -> None:
    """Print a compact one-pass summary when running this file directly."""
    print("\n=== Wi-Fi Analysis Summary ===")
    print(f"Timestamp      : {report.timestamp}")
    print(f"Connected SSID : {report.connected_ssid}")
    print(f"BSSID          : {report.bssid}")
    print(f"Encryption     : {report.encryption}")
    print(f"Signal (dBm)   : {report.signal_dbm}")
    print(f"Severity       : {report.severity}")
    print(f"Raw Score      : {report.raw_score:.4f}")
    print(f"Networks Seen  : {len(report.nearby_networks)}")

    print("Threats:")
    if report.threats_detected:
        for idx, threat in enumerate(report.threats_detected, start=1):
            print(f"  {idx}. {threat}")
    else:
        print("  None")

    print("\nReport JSON (compact):")
    print(json.dumps(report.to_dict(), default=str)[:800])


def _demo_run_once() -> None:
    """Run one analysis cycle and print score/severity to terminal."""
    analyzer = WiFiAnalyzer()
    report = analyzer.run_analysis()
    _print_terminal_summary(report)


if __name__ == "__main__":
    _demo_run_once()
