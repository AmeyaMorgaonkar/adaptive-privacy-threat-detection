"""
Wi-Fi Responder Module (Milestone 01)

Automated response actions triggered when Wi-Fi threat thresholds are
breached — alerts, VPN toggling, optional disconnection, and incident
logging.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

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
    from modules.wifi_analysis import WiFiReport

log = get_logger(__name__)

# ── Incident log path ───────────────────────────────────────────────
INCIDENT_LOG = config.DATA_DIR / "wifi_incidents.jsonl"


class WiFiResponder:
    """Reacts to threshold breaches reported by WiFiAnalyzer."""

    def __init__(self) -> None:
        self._os = platform.system()
        self._network_protection_enabled = False
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── Main entry point ─────────────────────────────────────────────

    def on_threshold_breach(self, report: WiFiReport) -> None:
        """Evaluate a WiFiReport and trigger appropriate responses.

        Actions taken depend on the severity level and config flags:
            - All levels   → log the incident
            - MEDIUM+      → alert the user
            - HIGH+        → attempt to enable VPN
            - CRITICAL     → optionally disconnect from the network
        """
        log.warning(
            "Threshold breach — severity=%s  threats=%d  score=%.2f",
            report.severity,
            len(report.threats_detected),
            report.raw_score,
        )

        # Always log the incident
        self.log_incident(report)

        # Alert
        if report.severity in ("MEDIUM", "HIGH", "CRITICAL"):
            summary = "; ".join(report.threats_detected) or "Unnamed threat"
            self.alert_user(f"[{report.severity}] {summary}")

        # VPN
        if report.severity in ("HIGH", "CRITICAL"):
            self._enable_network_protection(
                reason=f"Wi-Fi severity {report.severity}",
            )

        # Disconnect (safety-off by default)
        if report.severity == "CRITICAL" and config.AUTO_DISCONNECT_ON_ROGUE:
            self.disconnect_network()

    def evaluate_auto_protection(
        self,
        unified_score: float,
        wifi_report: WiFiReport | None = None,
    ) -> bool:
        """Enable VPN/DNS hardening from the unified threat score.

        Returns True when this call transitions the responder into the
        protected state. Subsequent calls while protection remains active
        are ignored to avoid repeatedly restarting VPN/DNS commands.
        """
        threshold = getattr(
            config,
            "AUTO_PROTECTION_THREAT_SCORE_THRESHOLD",
            75,
        )
        wifi_triggered = (
            wifi_report is not None
            and wifi_report.severity in ("HIGH", "CRITICAL")
        )
        score_triggered = unified_score >= threshold

        if not (wifi_triggered or score_triggered):
            return False

        if self._network_protection_enabled:
            log.debug(
                "Network protection already active; skipping (score=%.2f, wifi=%s)",
                unified_score,
                getattr(wifi_report, "severity", "n/a"),
            )
            return False

        reasons = []
        if score_triggered:
            reasons.append(f"unified score {unified_score:.2f}/{threshold}")
        if wifi_triggered:
            reasons.append(f"Wi-Fi severity {wifi_report.severity}")

        self.alert_user(
            "Automatic network protection enabled ("
            + ", ".join(reasons)
            + ")."
        )
        self._enable_network_protection(reason="; ".join(reasons))
        return True

    def planned_actions(self, report: WiFiReport) -> list[str]:
        """Return which actions would run for the given report."""
        actions = ["log_incident"]

        if report.severity in ("MEDIUM", "HIGH", "CRITICAL"):
            actions.append("alert_user")

        if report.severity in ("HIGH", "CRITICAL"):
            actions.append("toggle_vpn(start)")

        if (
            config.AUTO_ENABLE_DNS_PROTECTION
            and report.severity in ("HIGH", "CRITICAL")
        ):
            actions.append("apply_hardened_dns")

        if report.severity == "CRITICAL" and config.AUTO_DISCONNECT_ON_ROGUE:
            actions.append("disconnect_network")

        return actions

    # ── Individual actions ───────────────────────────────────────────

    def alert_user(self, message: str) -> None:
        """Emit a user-facing alert via logging (and future UI hooks)."""
        log.warning("⚠  ALERT: %s", message)
        # Future: push to Tkinter status bar / toast notification

    def toggle_vpn(self, state: bool) -> None:
        """Start or stop the VPN connection using the configured profile.

        Currently supports OpenVPN CLI.  If the VPN config path does
        not exist, the action is logged and skipped.
        """
        vpn_cfg = Path(config.VPN_CONFIG_PATH)
        action = "start" if state else "stop"

        if not vpn_cfg.exists():
            log.info(
                "VPN %s skipped — config not found: %s", action, vpn_cfg
            )
            return

        try:
            if state:
                cmd = ["openvpn", "--config", str(vpn_cfg), "--daemon"]
                log.info("Starting VPN with config %s", vpn_cfg)
            else:
                # Gracefully terminate openvpn
                if self._os == "Windows":
                    cmd = ["taskkill", "/IM", "openvpn.exe", "/F"]
                else:
                    cmd = ["killall", "openvpn"]
                log.info("Stopping VPN")

            subprocess.run(cmd, capture_output=True, timeout=15)
            log.info("VPN %s command executed", action)
        except FileNotFoundError:
            log.error("OpenVPN binary not found on PATH")
        except subprocess.TimeoutExpired:
            log.error("VPN %s timed out", action)
        except Exception as exc:
            log.error("VPN %s failed: %s", action, exc)

    def disconnect_network(self) -> None:
        """Disconnect from the current Wi-Fi network.

        ⚠ Only runs if ``config.AUTO_DISCONNECT_ON_ROGUE`` is True.
        """
        if not config.AUTO_DISCONNECT_ON_ROGUE:
            log.info("Auto-disconnect is disabled (AUTO_DISCONNECT_ON_ROGUE=False)")
            return

        log.warning("Disconnecting from Wi-Fi network")
        try:
            if self._os == "Windows":
                subprocess.run(
                    ["netsh", "wlan", "disconnect"],
                    capture_output=True,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            elif self._os == "Linux":
                subprocess.run(
                    ["nmcli", "device", "disconnect", "wifi"],
                    capture_output=True,
                    timeout=10,
                )
            elif self._os == "Darwin":
                iface = "en0"  # default macOS Wi-Fi interface
                subprocess.run(
                    ["networksetup", "-setairportpower", iface, "off"],
                    capture_output=True,
                    timeout=10,
                )
            log.info("Disconnected from network successfully")
        except Exception as exc:
            log.error("Disconnect failed: %s", exc)

    def log_incident(self, report: WiFiReport) -> None:
        """Append the WiFiReport as a JSON line to the incident log."""
        try:
            entry = {
                "logged_at": datetime.now(timezone.utc).isoformat(),
                **report.to_dict(),
            }
            with open(INCIDENT_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
            log.debug("Incident logged to %s", INCIDENT_LOG)
        except Exception as exc:
            log.error("Failed to write incident log: %s", exc)

    # ── Internal helpers ─────────────────────────────────────────────

    def _apply_hardened_dns(self) -> None:
        """Apply hardened DNS servers from config (best-effort)."""
        dns_servers = config.HARDENED_DNS_SERVERS
        log.info("Applying hardened DNS: %s", dns_servers)

        try:
            if self._os == "Windows":
                # Set primary DNS on the active Wi-Fi adapter
                iface = "Wi-Fi"
                for i, dns in enumerate(dns_servers[:2]):
                    if i == 0:
                        subprocess.run(
                            [
                                "netsh", "interface", "ip", "set", "dns",
                                f"name={iface}", "static", dns,
                            ],
                            capture_output=True,
                            timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                    else:
                        subprocess.run(
                            [
                                "netsh", "interface", "ip", "add", "dns",
                                f"name={iface}", dns, "index=2",
                            ],
                            capture_output=True,
                            timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                log.info("Hardened DNS applied on Windows")
            elif self._os == "Linux":
                self._apply_hardened_dns_linux(dns_servers)
            elif self._os == "Darwin":
                self._apply_hardened_dns_macos(dns_servers)
            else:
                log.info(
                    "Hardened DNS auto-apply not implemented for %s — "
                    "manual setup recommended",
                    self._os,
                )
        except Exception as exc:
            log.error("DNS hardening failed: %s", exc)

    def _apply_hardened_dns_linux(self, dns_servers: list[str]) -> None:
        """Best-effort hardened DNS setup for Linux."""
        dns_args = dns_servers[:2]
        iface = self._get_linux_default_interface()
        if not iface:
            log.info(
                "Hardened DNS auto-apply not fully implemented for Linux — "
                "manual setup recommended"
            )
            return

        try:
            result = subprocess.run(
                ["resolvectl", "dns", iface, *dns_args],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                log.info("Hardened DNS applied on Linux via resolvectl (%s)", iface)
                return
        except FileNotFoundError:
            log.debug("resolvectl not available on Linux")
        except subprocess.TimeoutExpired:
            log.error("Linux DNS hardening timed out via resolvectl")
            return

        log.info(
            "Hardened DNS auto-apply not fully implemented for Linux — "
            "manual setup recommended"
        )

    def _get_linux_default_interface(self) -> str:
        """Return the default-route interface on Linux, if available."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return ""

            tokens = result.stdout.split()
            if "dev" in tokens:
                dev_index = tokens.index("dev")
                if dev_index + 1 < len(tokens):
                    return tokens[dev_index + 1]
        except FileNotFoundError:
            log.debug("ip command not available on Linux")
        except subprocess.TimeoutExpired:
            log.error("Linux interface lookup timed out")
        except Exception as exc:
            log.debug("Linux interface lookup failed: %s", exc)

        return ""

    def _apply_hardened_dns_macos(self, dns_servers: list[str]) -> None:
        """Best-effort hardened DNS setup for macOS."""
        iface = "Wi-Fi"
        try:
            subprocess.run(
                ["networksetup", "-setdnsservers", iface, *dns_servers[:2]],
                capture_output=True,
                timeout=10,
            )
            log.info("Hardened DNS applied on macOS")
        except FileNotFoundError:
            log.debug("networksetup not available on macOS")
            log.info(
                "Hardened DNS auto-apply not fully implemented for macOS — "
                "manual setup recommended"
            )
        except subprocess.TimeoutExpired:
            log.error("macOS DNS hardening timed out")
        except Exception as exc:
            log.error("macOS DNS hardening failed: %s", exc)

    def _enable_network_protection(self, reason: str) -> None:
        """Turn on VPN and DNS hardening once per session."""
        if self._network_protection_enabled:
            log.debug("Network protection already enabled; skipping (%s)", reason)
            return

        log.warning("Enabling network protection: %s", reason)
        self.toggle_vpn(state=True)
        if config.AUTO_ENABLE_DNS_PROTECTION:
            self._apply_hardened_dns()
        self._network_protection_enabled = True


def _demo_preview_or_execute() -> None:
    """Run analysis, print score/actions, and optionally execute responses."""
    from modules.wifi_analysis import WiFiAnalyzer

    analyzer = WiFiAnalyzer()
    report = analyzer.run_analysis()
    responder = WiFiResponder()
    actions = responder.planned_actions(report)

    print("\n=== Wi-Fi Responder Preview ===")
    print(f"Severity  : {report.severity}")
    print(f"Raw Score : {report.raw_score:.4f}")
    print(f"Threats   : {len(report.threats_detected)}")

    if report.threats_detected:
        for idx, threat in enumerate(report.threats_detected, start=1):
            print(f"  {idx}. {threat}")

    print("Planned actions:")
    for action in actions:
        print(f"  - {action}")

    if "--execute" in sys.argv:
        print("\nExecuting responder actions (--execute enabled)...")
        responder.on_threshold_breach(report)
    else:
        print("\nPreview mode only. Re-run with --execute to perform actions.")


if __name__ == "__main__":
    _demo_preview_or_execute()
