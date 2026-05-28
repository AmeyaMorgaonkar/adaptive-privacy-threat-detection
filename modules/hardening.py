"""
Hardening Advisor (Milestone 06)

Analyzes module reports and produces actionable system-hardening
recommendations based on a predefined catalog of findings → actions.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import config
    from logger import get_logger
except ModuleNotFoundError:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    import config
    from logger import get_logger

from modules.reporting import HardeningRecommendation

log = get_logger(__name__)

# ── Priority ordering ───────────────────────────────────────────────

_PRIORITY_ORDER = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ── HardeningAdvisor ────────────────────────────────────────────────

class HardeningAdvisor:
    """Produces hardening recommendations from module analysis data."""

    def analyze(
        self,
        wifi_report=None,
        behavioral_report=None,
        web_report=None,
        threat_score=None,
    ) -> list[HardeningRecommendation]:
        """Inspect all module reports and return matching recommendations."""
        recs: list[HardeningRecommendation] = []

        # ── WiFi-based recommendations ───────────────────────────────
        if wifi_report is not None:
            recs.extend(self._check_wifi(wifi_report))

        # ── Behavioral-based recommendations ─────────────────────────
        if behavioral_report is not None:
            recs.extend(self._check_behavioral(behavioral_report))

        # ── Web-tracking-based recommendations ───────────────────────
        if web_report is not None:
            recs.extend(self._check_web(web_report))

        # ── Unified score-based recommendations ──────────────────────
        if threat_score is not None:
            recs.extend(self._check_unified(threat_score))

        # Deduplicate by title
        seen_titles: set[str] = set()
        unique: list[HardeningRecommendation] = []
        for r in recs:
            if r.title not in seen_titles:
                seen_titles.add(r.title)
                unique.append(r)

        log.info("Hardening analysis produced %d recommendations", len(unique))
        return unique

    def get_priority_actions(
        self, recommendations: list[HardeningRecommendation],
    ) -> list[HardeningRecommendation]:
        """Return recommendations sorted by priority (IMMEDIATE first)."""
        return sorted(
            recommendations,
            key=lambda r: _PRIORITY_ORDER.get(r.priority, 99),
        )

    def format_for_display(
        self, recommendations: list[HardeningRecommendation],
    ) -> str:
        """Format recommendations as a readable multi-line string."""
        if not recommendations:
            return "✓ No hardening actions required at this time."

        lines: list[str] = ["SYSTEM HARDENING RECOMMENDATIONS", ""]
        for i, rec in enumerate(
            self.get_priority_actions(recommendations), 1
        ):
            lines.append(
                f"  {i}. [{rec.priority}] [{rec.category}] {rec.title}"
            )
            lines.append(f"     {rec.description}")
            for j, step in enumerate(rec.action_steps, 1):
                lines.append(f"       {j}. {step}")
            if rec.related_finding:
                lines.append(f"     Finding: {rec.related_finding}")
            lines.append("")

        return "\n".join(lines)

    # ── WiFi checks ──────────────────────────────────────────────────

    @staticmethod
    def _check_wifi(wifi) -> list[HardeningRecommendation]:
        recs: list[HardeningRecommendation] = []
        threats = _get(wifi, "threats_detected", [])
        enc = _get(wifi, "encryption", "")
        signal = _get(wifi, "signal_dbm", -50)

        # Open network
        threat_str = " ".join(str(t).lower() for t in threats)
        if "open" in threat_str or enc == "OPEN":
            recs.append(HardeningRecommendation(
                category="WIFI",
                priority="IMMEDIATE",
                title="Disconnect from open network",
                description="You are connected to an unencrypted Wi-Fi network. "
                            "All traffic is visible to nearby attackers.",
                action_steps=[
                    "Disconnect from the current network immediately",
                    "Connect to a WPA2/WPA3-secured network",
                    "If you must use this network, enable a VPN",
                ],
                related_finding="Connected to OPEN (unencrypted) network",
            ))

        # Evil twin
        if "evil" in threat_str and "twin" in threat_str:
            recs.append(HardeningRecommendation(
                category="WIFI",
                priority="IMMEDIATE",
                title="Verify network with administrator",
                description="An evil-twin access point was detected. A rogue AP "
                            "is impersonating a legitimate network.",
                action_steps=[
                    "Disconnect from the current network",
                    "Verify the legitimate BSSID with the network administrator",
                    "Report the rogue AP to your security team",
                ],
                related_finding="Evil-twin AP detected",
            ))

        # WEP encryption
        if enc == "WEP" or "wep" in threat_str:
            recs.append(HardeningRecommendation(
                category="WIFI",
                priority="HIGH",
                title="Upgrade to WPA3-capable router",
                description="WEP encryption is broken and provides no real security. "
                            "Upgrade your router firmware or replace the router.",
                action_steps=[
                    "Access your router's admin panel",
                    "Change security mode to WPA3-Personal (or WPA2 minimum)",
                    "Update all device passwords after the change",
                ],
                related_finding="Connected to WEP network (weak encryption)",
            ))

        # Weak signal
        if signal < config.WIFI_SIGNAL_WARN_DBM:
            recs.append(HardeningRecommendation(
                category="WIFI",
                priority="MEDIUM",
                title="Improve Wi-Fi signal quality",
                description=f"Current signal strength ({signal} dBm) is below "
                            f"the recommended threshold ({config.WIFI_SIGNAL_WARN_DBM} dBm).",
                action_steps=[
                    "Move closer to the access point",
                    "Remove physical obstructions between you and the AP",
                    "Consider a Wi-Fi range extender",
                ],
                related_finding=f"Weak signal: {signal} dBm",
            ))

        return recs

    # ── Behavioral checks ────────────────────────────────────────────

    @staticmethod
    def _check_behavioral(beh) -> list[HardeningRecommendation]:
        recs: list[HardeningRecommendation] = []
        anomalous = _get(beh, "anomalous_processes", [])
        beh_score = _get(beh, "behavioral_score", 0)
        deviation = _get(beh, "baseline_deviation", 0)

        # High CPU anomaly
        if beh_score >= 50 or deviation >= 30:
            recs.append(HardeningRecommendation(
                category="PROCESSES",
                priority="HIGH",
                title="Review top CPU processes",
                description="Significant CPU deviation from baseline detected. "
                            "This may indicate cryptomining or malware activity.",
                action_steps=[
                    "Open Task Manager and sort by CPU usage",
                    "Identify unknown processes consuming high CPU",
                    "Run a full antivirus/anti-malware scan",
                ],
                related_finding=f"CPU baseline deviation: +{deviation:.0f}%",
            ))

        # Suspicious processes
        if anomalous:
            proc_names = ", ".join(anomalous[:5])
            recs.append(HardeningRecommendation(
                category="PROCESSES",
                priority="HIGH",
                title="Investigate suspicious processes",
                description=f"Unknown processes with network connections detected: "
                            f"{proc_names}",
                action_steps=[
                    "Check each process in Task Manager → Details",
                    "Verify the publisher and file location",
                    "If unknown, block outbound connections via firewall",
                    "Run VirusTotal scan on suspicious executables",
                ],
                related_finding=f"Anomalous processes: {proc_names}",
            ))

        return recs

    # ── Web tracking checks ──────────────────────────────────────────

    @staticmethod
    def _check_web(web) -> list[HardeningRecommendation]:
        recs: list[HardeningRecommendation] = []
        tracker_count = _get(web, "unique_trackers_count", 0)
        category_scores = _get(web, "category_scores", {})
        fp_signals = _get(web, "fingerprint_signals", [])
        active_cats = _get(web, "active_categories", [])

        # 10+ trackers
        if tracker_count >= 10:
            recs.append(HardeningRecommendation(
                category="BROWSER",
                priority="MEDIUM",
                title="Install tracker blocker extension",
                description=f"{tracker_count} unique trackers were detected. "
                            "Install a browser extension to block tracking scripts.",
                action_steps=[
                    "Install uBlock Origin from your browser's extension store",
                    "Enable the 'Privacy' filter lists in uBlock settings",
                    "Consider using Brave Browser or Firefox with Enhanced Tracking Protection",
                ],
                related_finding=f"{tracker_count} trackers detected across "
                                f"{len(active_cats)} categories",
            ))

        # Canvas / fingerprinting
        detected_fps = [s for s in fp_signals
                        if (s.get("detected") if isinstance(s, dict)
                            else getattr(s, "detected", False))]
        if detected_fps:
            types = [s.get("signal_type", "UNKNOWN") if isinstance(s, dict)
                     else getattr(s, "signal_type", "UNKNOWN")
                     for s in detected_fps]
            recs.append(HardeningRecommendation(
                category="BROWSER",
                priority="HIGH",
                title="Enable anti-fingerprinting mode",
                description=f"Browser fingerprinting signals detected: "
                            f"{', '.join(types)}. Your browser identity is being tracked.",
                action_steps=[
                    "In Firefox: set privacy.resistFingerprinting = true in about:config",
                    "In Chrome: install Canvas Blocker extension",
                    "Consider using Tor Browser for sensitive browsing",
                    "Review https://amiunique.org to check your fingerprint",
                ],
                related_finding=f"Fingerprinting signals: {', '.join(types)}",
            ))

        # Multiple categories active
        if len(active_cats) >= 3:
            recs.append(HardeningRecommendation(
                category="BROWSER",
                priority="HIGH",
                title="Review all browser privacy settings",
                description=f"Trackers detected across {len(active_cats)} categories: "
                            f"{', '.join(active_cats)}. Your browsing is heavily tracked.",
                action_steps=[
                    "Clear all cookies and site data",
                    "Enable 'Do Not Track' in browser settings",
                    "Use a privacy-focused DNS (Cloudflare 1.1.1.1, Quad9)",
                    "Consider using a VPN for all browsing",
                ],
                related_finding=f"Active tracker categories: {', '.join(active_cats)}",
            ))

        # Advertising heavy
        ad_score = category_scores.get("Advertising", 0)
        if ad_score >= 50:
            recs.append(HardeningRecommendation(
                category="BROWSER",
                priority="MEDIUM",
                title="Block advertising networks",
                description="High advertising tracker activity detected. "
                            "Ad networks track you across sites.",
                action_steps=[
                    "Enable DNS-level ad blocking (Pi-hole or NextDNS)",
                    "Install uBlock Origin with default filter lists",
                    "Disable third-party cookies in browser settings",
                ],
                related_finding=f"Advertising category score: {ad_score:.0f}/100",
            ))

        return recs

    # ── Unified score checks ─────────────────────────────────────────

    @staticmethod
    def _check_unified(threat) -> list[HardeningRecommendation]:
        recs: list[HardeningRecommendation] = []
        tier = _get(threat, "tier", "Safe")
        unified = _get(threat, "unified_score", 0)

        if tier == "Critical" or unified >= 90:
            recs.append(HardeningRecommendation(
                category="SYSTEM",
                priority="IMMEDIATE",
                title="Disconnect and investigate immediately",
                description=f"Critical threat level detected (score: {unified:.0f}/100). "
                            "Multiple severe threats are active simultaneously.",
                action_steps=[
                    "Disconnect from the current network",
                    "Close all browser windows",
                    "Run a full system antivirus scan",
                    "Review the detailed findings in this report",
                    "Contact your IT security team if on a corporate network",
                ],
                related_finding=f"Unified threat score: {unified:.0f}/100 ({tier})",
            ))
        elif tier == "High Risk" or unified >= 75:
            recs.append(HardeningRecommendation(
                category="SYSTEM",
                priority="HIGH",
                title="Review active threats urgently",
                description=f"High-risk threat level detected (score: {unified:.0f}/100). "
                            "Multiple threats require attention.",
                action_steps=[
                    "Review each module's findings below",
                    "Address IMMEDIATE and HIGH priority items first",
                    "Consider switching to a more secure network",
                ],
                related_finding=f"Unified threat score: {unified:.0f}/100 ({tier})",
            ))

        return recs


# ── Helpers ──────────────────────────────────────────────────────────

def _get(obj, key, default=None):
    """Get attribute or dict key from an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)
