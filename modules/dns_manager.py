"""
DNS Manager Module

Manages encrypted DNS switching with DoH (DNS over HTTPS) support.
Handles dynamic network interface detection, DNS server configuration,
DoH template registration, and DNS cache flushing on Windows/Linux/macOS.

All netsh operations require administrator privileges on Windows.
"""

from __future__ import annotations

import platform
import re
import subprocess
import sys
import threading
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

_CREATE_NO_WINDOW = 0x08000000 if platform.system() == "Windows" else 0


class DNSManager:
    """Manages encrypted DNS provider switching with DoH support.

    Key design decisions:
    - Detects the active network interface dynamically (no hardcoded "Wi-Fi")
    - Registers DoH templates for DNS-over-HTTPS on supported Windows versions
    - Flushes DNS cache after every switch/restore operation
    - Thread-safe: can be called from both UI and monitor threads
    - All operations are best-effort with comprehensive error handling
    """

    def __init__(self, config_manager=None) -> None:
        self._os = platform.system()
        self._lock = threading.Lock()
        self._config_manager = config_manager

        # Active provider name ("System Default" when not using encrypted DNS)
        self._active_provider: str = "System Default"

        # Restore persisted provider choice if available
        if config_manager:
            saved = config_manager.get("ACTIVE_DNS_PROVIDER", None)
            if saved and saved in config.ENCRYPTED_DNS_PROVIDERS:
                self._active_provider = saved

    # ── Public API ───────────────────────────────────────────────────

    @property
    def active_provider(self) -> str:
        """Return the name of the currently active DNS provider."""
        with self._lock:
            return self._active_provider

    @staticmethod
    def get_providers() -> dict:
        """Return the ENCRYPTED_DNS_PROVIDERS configuration dict."""
        return dict(config.ENCRYPTED_DNS_PROVIDERS)

    def switch_provider(self, provider_name: str) -> bool:
        """Switch DNS to the named encrypted provider.

        Sets DNS servers on the active interface, registers DoH templates,
        and flushes the DNS cache.

        Returns True on success, False on failure.
        """
        with self._lock:
            return self._switch_provider_locked(provider_name)

    def restore_default(self) -> bool:
        """Restore DNS to system default (DHCP).

        Returns True on success, False on failure.
        """
        with self._lock:
            return self._restore_default_locked()

    def get_current_dns(self) -> list[str]:
        """Query and return the current DNS servers on the active interface."""
        if self._os == "Windows":
            return self._get_current_dns_windows()
        elif self._os == "Linux":
            return self._get_current_dns_linux()
        return []

    # ── Windows implementation ───────────────────────────────────────

    def _switch_provider_locked(self, provider_name: str) -> bool:
        """Internal: switch DNS provider (must hold self._lock)."""
        providers = config.ENCRYPTED_DNS_PROVIDERS
        if provider_name not in providers:
            log.error("Unknown DNS provider: %s", provider_name)
            return False

        provider = providers[provider_name]
        servers = provider["servers"]
        doh_template = provider.get("doh_template", "")

        log.info(
            "Switching DNS to %s (%s) — DoH: %s",
            provider_name, servers, doh_template or "none",
        )

        if self._os == "Windows":
            success = self._apply_dns_windows(servers, doh_template)
        elif self._os == "Linux":
            success = self._apply_dns_linux(servers)
        elif self._os == "Darwin":
            success = self._apply_dns_macos(servers)
        else:
            log.warning("DNS switching not implemented for %s", self._os)
            return False

        if success:
            self._active_provider = provider_name
            self._flush_dns_cache()
            self._persist_choice(provider_name)
            log.info("DNS switched to %s successfully", provider_name)
        return success

    def _restore_default_locked(self) -> bool:
        """Internal: restore DHCP DNS (must hold self._lock)."""
        log.info("Restoring DNS to system default (DHCP)")

        if self._os == "Windows":
            success = self._restore_dhcp_windows()
        elif self._os == "Linux":
            success = self._restore_dhcp_linux()
        elif self._os == "Darwin":
            success = self._restore_dhcp_macos()
        else:
            log.warning("DNS restore not implemented for %s", self._os)
            return False

        if success:
            self._active_provider = "System Default"
            self._flush_dns_cache()
            self._persist_choice("System Default")
            log.info("DNS restored to DHCP defaults")
        return success

    # ── Dynamic interface detection ──────────────────────────────────

    def _get_active_interface_windows(self) -> Optional[str]:
        """Detect the active network interface name on Windows.

        Tries connected Wi-Fi first, then falls back to the first
        connected Ethernet adapter. Handles renamed adapters.
        """
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
                    "Select-Object -ExpandProperty Name",
                ],
                capture_output=True, text=True, timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                log.debug(
                    "Get-NetAdapter failed (code %d): %s",
                    result.returncode, result.stderr.strip(),
                )
                return self._get_active_interface_windows_fallback()

            adapters = [
                line.strip() for line in result.stdout.splitlines()
                if line.strip()
            ]
            if not adapters:
                log.debug("No active network adapters found")
                return None

            # Prefer Wi-Fi-like names, then take the first available
            for name in adapters:
                lower = name.lower()
                if "wi-fi" in lower or "wifi" in lower or "wlan" in lower or "wireless" in lower:
                    log.debug("Active interface (WiFi): %s", name)
                    return name

            # Fallback to first active adapter (likely Ethernet)
            log.debug("Active interface (non-WiFi): %s", adapters[0])
            return adapters[0]

        except FileNotFoundError:
            log.debug("PowerShell not available for interface detection")
            return self._get_active_interface_windows_fallback()
        except subprocess.TimeoutExpired:
            log.debug("Interface detection timed out")
            return self._get_active_interface_windows_fallback()
        except Exception as exc:
            log.debug("Interface detection failed: %s", exc)
            return self._get_active_interface_windows_fallback()

    def _get_active_interface_windows_fallback(self) -> Optional[str]:
        """Fallback: use netsh to find the connected interface."""
        try:
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            for line in result.stdout.splitlines():
                if "Connected" in line:
                    # Format: "Admin State  State  Type  Interface Name"
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = " ".join(parts[3:])
                        log.debug("Fallback interface: %s", iface_name)
                        return iface_name
        except Exception as exc:
            log.debug("Fallback interface detection failed: %s", exc)
        return None

    # ── Windows DNS operations ───────────────────────────────────────

    def _apply_dns_windows(self, servers: list[str], doh_template: str) -> bool:
        """Set DNS servers and register DoH on the active Windows interface."""
        iface = self._get_active_interface_windows()
        if not iface:
            log.error("Cannot set DNS — no active network interface found")
            return False

        try:
            # Set primary DNS
            result = subprocess.run(
                [
                    "netsh", "interface", "ip", "set", "dns",
                    f"name={iface}", "static", servers[0],
                ],
                capture_output=True, text=True, timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip() or result.stdout.strip()
                log.error(
                    "Failed to set primary DNS on '%s' (code %d): %s",
                    iface, result.returncode, stderr,
                )
                return False

            # Set secondary DNS
            if len(servers) > 1:
                subprocess.run(
                    [
                        "netsh", "interface", "ip", "add", "dns",
                        f"name={iface}", servers[1], "index=2",
                    ],
                    capture_output=True, timeout=10,
                    creationflags=_CREATE_NO_WINDOW,
                )

            # Register DoH templates (best-effort, requires Win10 20H2+ & admin)
            if doh_template:
                self._register_doh_windows(servers, doh_template)

            log.info("DNS servers set on '%s': %s", iface, servers)
            return True

        except FileNotFoundError:
            log.error("netsh not found — cannot set DNS")
            return False
        except subprocess.TimeoutExpired:
            log.error("DNS set operation timed out")
            return False
        except Exception as exc:
            log.error("Failed to set DNS: %s", exc)
            return False

    def _register_doh_windows(self, servers: list[str], doh_template: str) -> None:
        """Register DoH encryption templates for each DNS server.

        Uses ``netsh dns add encryption`` which requires:
        - Windows 10 version 20H2 (build 19042) or later
        - Administrator privileges

        Failures are logged but do not prevent the DNS switch.
        """
        for server in servers:
            try:
                result = subprocess.run(
                    [
                        "netsh", "dns", "add", "encryption",
                        f"server={server}",
                        f"dohtemplate={doh_template}",
                        "autoupgrade=yes",
                        "udpfallback=no",
                    ],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATE_NO_WINDOW,
                )
                if result.returncode == 0:
                    log.info(
                        "DoH template registered for %s -> %s",
                        server, doh_template,
                    )
                else:
                    stderr = result.stderr.strip() or result.stdout.strip()
                    log.warning(
                        "DoH registration failed for %s (code %d): %s — "
                        "DNS servers are set but encryption may not be active. "
                        "Requires Windows 10 20H2+ and admin privileges.",
                        server, result.returncode, stderr,
                    )
            except Exception as exc:
                log.warning(
                    "DoH registration failed for %s: %s — "
                    "DNS set but encryption may not be active",
                    server, exc,
                )

    def _restore_dhcp_windows(self) -> bool:
        """Restore DNS to DHCP on the active Windows interface."""
        iface = self._get_active_interface_windows()
        if not iface:
            log.error("Cannot restore DNS — no active network interface found")
            return False

        try:
            result = subprocess.run(
                [
                    "netsh", "interface", "ip", "set", "dns",
                    f"name={iface}", "dhcp",
                ],
                capture_output=True, text=True, timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip() or result.stdout.strip()
                log.error(
                    "Failed to restore DHCP DNS on '%s' (code %d): %s",
                    iface, result.returncode, stderr,
                )
                return False

            log.info("DNS restored to DHCP on '%s'", iface)
            return True

        except FileNotFoundError:
            log.error("netsh not found — cannot restore DNS")
            return False
        except subprocess.TimeoutExpired:
            log.error("DNS restore timed out")
            return False
        except Exception as exc:
            log.error("Failed to restore DNS: %s", exc)
            return False

    def _get_current_dns_windows(self) -> list[str]:
        """Query current DNS servers via netsh."""
        try:
            iface = self._get_active_interface_windows()
            if not iface:
                return []
            result = subprocess.run(
                [
                    "netsh", "interface", "ip", "show", "dns",
                    f"name={iface}",
                ],
                capture_output=True, text=True, timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            servers = []
            for line in result.stdout.splitlines():
                # Match lines containing IP addresses
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    servers.append(match.group(1))
            return servers
        except Exception as exc:
            log.debug("Failed to query current DNS: %s", exc)
            return []

    # ── Linux implementation ─────────────────────────────────────────

    def _get_active_interface_linux(self) -> Optional[str]:
        """Detect the default-route interface on Linux."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=10,
            )
            tokens = result.stdout.split()
            if "dev" in tokens:
                idx = tokens.index("dev")
                if idx + 1 < len(tokens):
                    return tokens[idx + 1]
        except Exception as exc:
            log.debug("Linux interface detection failed: %s", exc)
        return None

    def _apply_dns_linux(self, servers: list[str]) -> bool:
        """Set DNS on Linux via resolvectl."""
        iface = self._get_active_interface_linux()
        if not iface:
            log.error("Cannot set DNS — no default interface found")
            return False
        try:
            result = subprocess.run(
                ["resolvectl", "dns", iface, *servers[:2]],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                log.info("DNS set on Linux interface '%s': %s", iface, servers)
                return True
            log.error("resolvectl failed (code %d)", result.returncode)
            return False
        except FileNotFoundError:
            log.error("resolvectl not found — manual DNS setup required")
            return False
        except Exception as exc:
            log.error("Linux DNS set failed: %s", exc)
            return False

    def _restore_dhcp_linux(self) -> bool:
        """Restore DNS on Linux via resolvectl revert."""
        iface = self._get_active_interface_linux()
        if not iface:
            return False
        try:
            result = subprocess.run(
                ["resolvectl", "revert", iface],
                capture_output=True, timeout=10,
            )
            return result.returncode == 0
        except Exception as exc:
            log.error("Linux DNS restore failed: %s", exc)
            return False

    def _get_current_dns_linux(self) -> list[str]:
        """Query current DNS on Linux."""
        try:
            result = subprocess.run(
                ["resolvectl", "dns"],
                capture_output=True, text=True, timeout=10,
            )
            servers = []
            for line in result.stdout.splitlines():
                for match in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', line):
                    servers.append(match.group(1))
            return servers
        except Exception:
            return []

    # ── macOS implementation ─────────────────────────────────────────

    def _apply_dns_macos(self, servers: list[str]) -> bool:
        """Set DNS on macOS via networksetup."""
        try:
            result = subprocess.run(
                ["networksetup", "-setdnsservers", "Wi-Fi", *servers[:2]],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                log.info("DNS set on macOS: %s", servers)
                return True
            return False
        except Exception as exc:
            log.error("macOS DNS set failed: %s", exc)
            return False

    def _restore_dhcp_macos(self) -> bool:
        """Restore DNS on macOS to automatic (DHCP)."""
        try:
            result = subprocess.run(
                ["networksetup", "-setdnsservers", "Wi-Fi", "empty"],
                capture_output=True, timeout=10,
            )
            return result.returncode == 0
        except Exception as exc:
            log.error("macOS DNS restore failed: %s", exc)
            return False

    # ── DNS cache flush ──────────────────────────────────────────────

    def _flush_dns_cache(self) -> None:
        """Flush the OS DNS resolver cache after a switch or restore."""
        try:
            if self._os == "Windows":
                subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True, timeout=10,
                    creationflags=_CREATE_NO_WINDOW,
                )
                log.debug("Windows DNS cache flushed")
            elif self._os == "Linux":
                subprocess.run(
                    ["resolvectl", "flush-caches"],
                    capture_output=True, timeout=10,
                )
                log.debug("Linux DNS cache flushed")
            elif self._os == "Darwin":
                subprocess.run(
                    ["dscacheutil", "-flushcache"],
                    capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["killall", "-HUP", "mDNSResponder"],
                    capture_output=True, timeout=10,
                )
                log.debug("macOS DNS cache flushed")
        except Exception as exc:
            log.debug("DNS cache flush failed: %s", exc)

    # ── Persistence ──────────────────────────────────────────────────

    def _persist_choice(self, provider_name: str) -> None:
        """Persist the selected DNS provider to config_manager."""
        if self._config_manager:
            try:
                self._config_manager.set("ACTIVE_DNS_PROVIDER", provider_name)
                log.debug("DNS provider choice persisted: %s", provider_name)
            except Exception as exc:
                log.debug("Failed to persist DNS choice: %s", exc)
