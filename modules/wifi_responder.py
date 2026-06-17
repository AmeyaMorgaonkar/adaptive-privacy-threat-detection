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
import time
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
        self._manual_override = False
        self._vpn_process: subprocess.Popen | None = None
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

        # VPN — trigger at MEDIUM and above (skip if user manually disabled)
        if report.severity in ("MEDIUM", "HIGH", "CRITICAL") and not self._manual_override:
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
            and wifi_report.severity in ("MEDIUM", "HIGH", "CRITICAL")
        )
        score_triggered = unified_score >= threshold

        if not (wifi_triggered or score_triggered):
            return False

        # Respect manual user override — don't re-enable if user turned off
        if self._manual_override:
            log.debug(
                "Auto-protection skipped — manual override active "
                "(score=%.2f, wifi=%s)",
                unified_score,
                getattr(wifi_report, "severity", "n/a"),
            )
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

        if report.severity in ("MEDIUM", "HIGH", "CRITICAL"):
            actions.append("toggle_vpn(start)")

        if (
            config.AUTO_ENABLE_DNS_PROTECTION
            and report.severity in ("MEDIUM", "HIGH", "CRITICAL")
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
        """Start or stop the VPN connection.

        Tries, in order:
          1. OpenVPN CLI using .ovpn files from ``config.VPN_CONFIG_DIR``
          2. Windows built-in VPN via rasdial / PowerShell (fallback)

        When starting, each ``.ovpn`` file in the config directory is
        attempted in turn until one succeeds.
        """
        action = "start" if state else "stop"

        # ── Resolve OpenVPN binary ────────────────────────────────────
        openvpn_bin = getattr(config, "OPENVPN_BINARY", "openvpn")
        openvpn_path = Path(openvpn_bin)
        has_openvpn = openvpn_path.exists() or not openvpn_path.is_absolute()

        # ── Stop: kill any running openvpn process ────────────────────
        if not state:
            if has_openvpn:
                try:
                    if self._os == "Windows":
                        cmd = ["taskkill", "/IM", "openvpn.exe", "/F"]
                    else:
                        cmd = ["killall", "openvpn"]
                    log.info("Stopping VPN (killing openvpn process)")
                    subprocess.run(
                        cmd, capture_output=True, timeout=15,
                        creationflags=(
                            subprocess.CREATE_NO_WINDOW
                            if self._os == "Windows" else 0
                        ),
                    )
                    log.info("VPN stop command executed")
                    return
                except Exception as exc:
                    log.warning("OpenVPN stop failed: %s", exc)

            # Fallback: try Windows built-in VPN disconnect
            if self._os == "Windows":
                self._toggle_windows_builtin_vpn(state=False)
            return

        # ── Start: discover .ovpn configs ─────────────────────────────
        vpn_dir = Path(getattr(config, "VPN_CONFIG_DIR", "assets"))
        ovpn_files = sorted(vpn_dir.glob("*.ovpn")) if vpn_dir.is_dir() else []

        if not ovpn_files:
            log.warning(
                "No .ovpn files found in %s — cannot start OpenVPN", vpn_dir,
            )
            if self._os == "Windows":
                self._toggle_windows_builtin_vpn(state=True)
            return

        if not has_openvpn:
            log.warning(
                "OpenVPN binary not found at '%s' — cannot start VPN. "
                "Install OpenVPN or update config.OPENVPN_BINARY.",
                openvpn_bin,
            )
            if self._os == "Windows":
                self._toggle_windows_builtin_vpn(state=True)
            return

        # Try each .ovpn file until one connects
        binary = str(openvpn_path) if openvpn_path.is_absolute() else openvpn_bin

        # ── Resolve auth-user-pass credentials file ───────────────────
        auth_file = Path(getattr(config, "VPN_AUTH_FILE", ""))
        has_auth_file = auth_file.is_file() and auth_file.stat().st_size > 0
        if has_auth_file:
            log.info("Using auth-user-pass file: %s", auth_file)
        else:
            log.debug(
                "No VPN credentials file found at '%s' — "
                "OpenVPN may prompt interactively for username/password",
                auth_file,
            )

        for ovpn in ovpn_files:
            log.info("Attempting VPN connection with config: %s", ovpn.name)
            try:
                # On Windows, --daemon is not supported.  Launch as a
                # background process via Popen and check it stays alive.
                if self._os == "Windows":
                    cmd = [binary, "--config", str(ovpn)]
                    if has_auth_file:
                        cmd.extend(["--auth-user-pass", str(auth_file)])
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=(
                            subprocess.CREATE_NO_WINDOW
                            | subprocess.DETACHED_PROCESS
                        ),
                    )
                    # Give OpenVPN a moment to fail or establish the tunnel
                    time.sleep(3)
                    if proc.poll() is None:
                        # Process still running → connection in progress
                        self._vpn_process = proc
                        log.info(
                            "VPN started successfully via OpenVPN "
                            "(config=%s, pid=%d)",
                            ovpn.name, proc.pid,
                        )
                        return
                    # Process exited — grab the error output
                    _, stderr = proc.communicate(timeout=5)
                    err_msg = stderr.decode(errors="replace").strip()[:200]
                    log.warning(
                        "OpenVPN exited immediately for %s (code=%d): %s",
                        ovpn.name, proc.returncode, err_msg,
                    )
                else:
                    # Unix: --daemon is fine
                    unix_cmd = [binary, "--config", str(ovpn)]
                    if has_auth_file:
                        unix_cmd.extend(["--auth-user-pass", str(auth_file)])
                    unix_cmd.append("--daemon")
                    result = subprocess.run(
                        unix_cmd,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if result.returncode == 0:
                        log.info(
                            "VPN started successfully via OpenVPN (config=%s)",
                            ovpn.name,
                        )
                        return
                    log.warning(
                        "OpenVPN returned code %d for %s: %s",
                        result.returncode,
                        ovpn.name,
                        (result.stderr.strip() or result.stdout.strip())[:200],
                    )
            except subprocess.TimeoutExpired:
                log.warning("OpenVPN timed out with config %s, trying next", ovpn.name)
            except Exception as exc:
                log.warning("OpenVPN failed with config %s: %s", ovpn.name, exc)

        log.error("All %d .ovpn configs failed — VPN not started", len(ovpn_files))

        # Last resort: Windows built-in VPN
        if self._os == "Windows":
            self._toggle_windows_builtin_vpn(state=True)

    def _toggle_windows_builtin_vpn(self, state: bool) -> None:
        """Connect/disconnect using Windows built-in VPN profiles.

        Uses PowerShell ``Get-VpnConnection`` to discover configured
        VPN profiles, then ``rasdial`` to connect/disconnect.
        """
        action = "start" if state else "stop"

        try:
            # Discover configured VPN connections
            discovery = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-VpnConnection | Select-Object -ExpandProperty Name",
                ],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            profiles = [
                line.strip() for line in discovery.stdout.splitlines()
                if line.strip()
            ]

            if not profiles:
                log.warning(
                    "VPN %s skipped — no Windows VPN profiles configured. "
                    "Set up a VPN connection in Windows Settings > "
                    "Network & Internet > VPN, or place .ovpn files in %s",
                    action, getattr(config, "VPN_CONFIG_DIR", "assets"),
                )
                return

            vpn_name = profiles[0]

            if state:
                log.info("Connecting to Windows VPN '%s' via rasdial", vpn_name)
                result = subprocess.run(
                    ["rasdial", vpn_name],
                    capture_output=True, text=True, timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                log.info("Disconnecting Windows VPN '%s'", vpn_name)
                result = subprocess.run(
                    ["rasdial", vpn_name, "/DISCONNECT"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )

            if result.returncode == 0:
                log.info("Windows VPN %s succeeded (profile='%s')", action, vpn_name)
            else:
                stderr = result.stderr.strip() or result.stdout.strip()
                log.error(
                    "Windows VPN %s failed (profile='%s', code=%d): %s",
                    action, vpn_name, result.returncode, stderr,
                )
        except FileNotFoundError:
            log.error("rasdial or powershell not found on PATH")
        except subprocess.TimeoutExpired:
            log.error("Windows VPN %s timed out", action)
        except Exception as exc:
            log.error("Windows VPN %s failed: %s", action, exc)

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
            # Verify the VPN process is actually still alive
            if (
                self._vpn_process is not None
                and self._vpn_process.poll() is None
            ):
                log.debug("Network protection already enabled; skipping (%s)", reason)
                return
            # VPN process died — allow retry
            log.warning(
                "VPN process no longer running — retrying protection (%s)",
                reason,
            )
            self._network_protection_enabled = False

        log.warning("Enabling network protection: %s", reason)
        self.toggle_vpn(state=True)
        if config.AUTO_ENABLE_DNS_PROTECTION:
            self._apply_hardened_dns()

        # Only mark as enabled if VPN actually started
        vpn_alive = (
            self._vpn_process is not None
            and self._vpn_process.poll() is None
        )
        if vpn_alive:
            self._network_protection_enabled = True
            self._manual_override = False
            log.info("Network protection fully enabled (VPN pid=%d)", self._vpn_process.pid)
        else:
            log.warning(
                "VPN did not start — network protection will retry next cycle"
            )

    def disable_network_protection(self) -> None:
        """Turn off VPN and mark as manually overridden.

        Sets ``_manual_override`` so the auto-protection loop will not
        immediately re-enable VPN on the next scan cycle.
        """
        log.warning("Disabling network protection (user request)")
        self.toggle_vpn(state=False)
        self._network_protection_enabled = False
        self._manual_override = True

    @property
    def is_vpn_active(self) -> bool:
        """Return True when the VPN is believed to be running."""
        if not self._network_protection_enabled:
            return False
        # Double-check the process is actually alive
        if self._vpn_process is not None:
            return self._vpn_process.poll() is None
        # Protection was enabled via built-in VPN (no process handle)
        return True

    def manual_enable_vpn(self) -> None:
        """Enable VPN regardless of threat score (user-initiated)."""
        self._manual_override = False
        self._enable_network_protection(reason="Manual user toggle")


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
