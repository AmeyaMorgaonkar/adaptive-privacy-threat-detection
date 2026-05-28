"""
Fingerprint Detector Module (Milestone 05)

Network-level heuristic detection of browser fingerprinting attempts.
Checks active connections and observed domains against known fingerprinting
CDN endpoints and patterns, producing FingerprintSignal objects with
confidence scores.

This is inherently heuristic — we detect connections to known fingerprinting
infrastructure, not the actual JavaScript API calls.  Confidence scores
reflect this uncertainty.
"""

from __future__ import annotations

import sys
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


# Import FingerprintSignal from web_tracker (defined there for single source)
try:
    from modules.web_tracker import FingerprintSignal, TrackerConnection
except ImportError:
    # Stub for standalone use / testing
    from dataclasses import dataclass

    @dataclass
    class FingerprintSignal:  # type: ignore[no-redef]
        signal_type: str
        detected: bool
        confidence: float = 0.0
        description: str = ""

    @dataclass
    class TrackerConnection:  # type: ignore[no-redef]
        remote_ip: str = ""
        remote_domain: str = ""
        local_port: int = 0
        protocol: str = ""
        data_volume_kb: float = 0.0
        is_known_tracker: bool = False


# ── Known fingerprinting indicators ─────────────────────────────────

# Domains/URL patterns associated with each fingerprinting technique.
# A connection to these endpoints suggests the page is using the
# corresponding fingerprinting API.

CANVAS_FP_INDICATORS = [
    "fpcdn.io",
    "fpjs.io",
    "openfpcdn.io",
    "api.fpjs.io",
    "fpnpmcdn.net",
    "cdn.jsdelivr.net",     # hosts fingerprintjs
    "cdn.cookielaw.org",    # consent + fingerprint combo
]

WEBGL_FP_INDICATORS = [
    "fpcdn.io",
    "fpjs.io",
    "openfpcdn.io",
    "cdn.krxd.net",
    "beacon.krxd.net",
    "consumer.krxd.net",
]

FONT_FP_INDICATORS = [
    "fpcdn.io",
    "fpjs.io",
    "cdn.krxd.net",
    "cdn.tealiumiq.com",
    "tags.tiqcdn.com",
]

BATTERY_FP_INDICATORS = [
    "fpcdn.io",
    "fpjs.io",
    "cdn.permutive.com",
    "cdn.treasuredata.com",
]

AUDIO_FP_INDICATORS = [
    "fpcdn.io",
    "fpjs.io",
    "openfpcdn.io",
    "cdn.amplitude.com",
]

# General fingerprinting script CDN endpoints (from config)
GENERAL_FP_ENDPOINTS: list[str] = []


def _init_general_endpoints() -> None:
    """Load general endpoints from config on first use."""
    global GENERAL_FP_ENDPOINTS
    if not GENERAL_FP_ENDPOINTS:
        GENERAL_FP_ENDPOINTS.extend(
            getattr(config, "FINGERPRINT_KNOWN_ENDPOINTS", []),
        )


# ── FingerprintDetector ─────────────────────────────────────────────

class FingerprintDetector:
    """Network-level browser fingerprinting heuristic detector.

    Checks observed domains and active connections against curated lists
    of known fingerprinting CDN/script endpoints.  Each detection type
    (Canvas, WebGL, Font, Battery, Audio) is scored independently with
    a confidence value reflecting network-level certainty.
    """

    def __init__(self) -> None:
        _init_general_endpoints()

    # ── Individual detection methods ─────────────────────────────────

    def detect_canvas_fingerprinting(
        self, domains: list[str], connections: list[TrackerConnection],
    ) -> FingerprintSignal:
        """Flag connections to known canvas fingerprinting script endpoints."""
        detected, confidence, matched = self._check_indicators(
            domains, connections, CANVAS_FP_INDICATORS,
        )
        return FingerprintSignal(
            signal_type="CANVAS",
            detected=detected,
            confidence=confidence,
            description=(
                f"Canvas fingerprinting script endpoint detected: {matched}"
                if detected
                else "No canvas fingerprinting indicators found"
            ),
        )

    def detect_webgl_fingerprinting(
        self, domains: list[str], connections: list[TrackerConnection],
    ) -> FingerprintSignal:
        """Flag connections to known WebGL renderer enumeration endpoints."""
        detected, confidence, matched = self._check_indicators(
            domains, connections, WEBGL_FP_INDICATORS,
        )
        return FingerprintSignal(
            signal_type="WEBGL",
            detected=detected,
            confidence=confidence,
            description=(
                f"WebGL fingerprinting endpoint detected: {matched}"
                if detected
                else "No WebGL fingerprinting indicators found"
            ),
        )

    def detect_font_enumeration(
        self, domains: list[str], connections: list[TrackerConnection],
    ) -> FingerprintSignal:
        """Flag connections to known font-probing CDN endpoints."""
        detected, confidence, matched = self._check_indicators(
            domains, connections, FONT_FP_INDICATORS,
        )
        return FingerprintSignal(
            signal_type="FONT",
            detected=detected,
            confidence=confidence,
            description=(
                f"Font enumeration endpoint detected: {matched}"
                if detected
                else "No font enumeration indicators found"
            ),
        )

    def detect_battery_api_access(
        self, domains: list[str], connections: list[TrackerConnection],
    ) -> FingerprintSignal:
        """Flag connections to known battery API telemetry endpoints."""
        detected, confidence, matched = self._check_indicators(
            domains, connections, BATTERY_FP_INDICATORS,
        )
        return FingerprintSignal(
            signal_type="BATTERY",
            detected=detected,
            confidence=confidence,
            description=(
                f"Battery API telemetry endpoint detected: {matched}"
                if detected
                else "No battery API access indicators found"
            ),
        )

    def detect_audio_fingerprinting(
        self, domains: list[str], connections: list[TrackerConnection],
    ) -> FingerprintSignal:
        """Flag connections to known audio fingerprinting endpoints."""
        detected, confidence, matched = self._check_indicators(
            domains, connections, AUDIO_FP_INDICATORS,
        )
        return FingerprintSignal(
            signal_type="AUDIO",
            detected=detected,
            confidence=confidence,
            description=(
                f"Audio fingerprinting endpoint detected: {matched}"
                if detected
                else "No audio fingerprinting indicators found"
            ),
        )

    # ── JavaScript API heuristics (network-level) ────────────────────

    def inspect_js_calls(
        self, domains: list[str], connections: list[TrackerConnection],
    ) -> list[FingerprintSignal]:
        """Run all fingerprinting heuristic checks.

        Returns a list of FingerprintSignal objects for each detection type.
        """
        signals = [
            self.detect_canvas_fingerprinting(domains, connections),
            self.detect_webgl_fingerprinting(domains, connections),
            self.detect_font_enumeration(domains, connections),
            self.detect_battery_api_access(domains, connections),
            self.detect_audio_fingerprinting(domains, connections),
        ]
        return signals

    # ── Scoring ──────────────────────────────────────────────────────

    def compute_fp_score(self, signals: list[FingerprintSignal]) -> float:
        """Aggregate confidence-weighted signals into a 0–100 score.

        Each detected signal contributes:
            contribution = confidence * 20  (max 20 per signal)

        Total is clamped to 0–100.
        """
        total = 0.0
        for sig in signals:
            if sig.detected:
                total += sig.confidence * 20.0
        return min(max(total, 0.0), 100.0)

    # ── Orchestrator ─────────────────────────────────────────────────

    def run(
        self,
        domains: list[str],
        connections: list[TrackerConnection],
    ) -> list[FingerprintSignal]:
        """Execute all fingerprinting checks and return signal list.

        Called by WebTrackerMonitor.run().
        """
        signals = self.inspect_js_calls(domains, connections)

        detected_count = sum(1 for s in signals if s.detected)
        if detected_count:
            fp_score = self.compute_fp_score(signals)
            log.info(
                "FingerprintDetector: %d signal(s) detected, fp_score=%.1f",
                detected_count, fp_score,
            )
        else:
            log.debug("FingerprintDetector: no fingerprinting signals detected")

        return signals

    # ── Internal helpers ─────────────────────────────────────────────

    @staticmethod
    def _check_indicators(
        domains: list[str],
        connections: list[TrackerConnection],
        indicators: list[str],
    ) -> tuple[bool, float, str]:
        """Check if any observed domain/connection matches the indicator list.

        Returns (detected, confidence, matched_domain).

        Confidence heuristic:
          - Direct domain match: 0.85
          - Suffix match: 0.65
          - Connection IP reverse-lookup match: 0.50
          - Multiple matches boost confidence by 0.10 each (up to 1.0)
        """
        matched_domains: list[str] = []
        max_confidence = 0.0

        for domain in domains:
            domain_lower = domain.lower().strip().rstrip(".")
            for indicator in indicators:
                indicator_lower = indicator.lower()
                if domain_lower == indicator_lower:
                    matched_domains.append(domain_lower)
                    max_confidence = max(max_confidence, 0.85)
                elif domain_lower.endswith("." + indicator_lower):
                    matched_domains.append(domain_lower)
                    max_confidence = max(max_confidence, 0.65)
                elif indicator_lower.endswith(domain_lower):
                    matched_domains.append(domain_lower)
                    max_confidence = max(max_confidence, 0.65)

        for conn in connections:
            conn_domain = conn.remote_domain.lower().strip().rstrip(".")
            for indicator in indicators:
                indicator_lower = indicator.lower()
                if conn_domain == indicator_lower or conn_domain.endswith("." + indicator_lower):
                    if conn_domain not in matched_domains:
                        matched_domains.append(conn_domain)
                    max_confidence = max(max_confidence, 0.50)

        # Boost confidence for multiple matches
        if len(matched_domains) > 1:
            max_confidence = min(max_confidence + 0.10 * (len(matched_domains) - 1), 1.0)

        detected = len(matched_domains) > 0
        best_match = matched_domains[0] if matched_domains else ""

        return detected, round(max_confidence, 2), best_match


# ── CLI demo ─────────────────────────────────────────────────────────

def _demo() -> None:
    """Quick demo with sample domains."""
    detector = FingerprintDetector()

    sample_domains = [
        "fpcdn.io",
        "cdn.krxd.net",
        "cdn.amplitude.com",
        "example.com",
        "google.com",
    ]

    signals = detector.run(sample_domains, [])

    print("\n=== Fingerprint Detection Demo ===")
    for sig in signals:
        status = "✓ DETECTED" if sig.detected else "✗ clear"
        print(
            f"  {sig.signal_type:<10} {status}  "
            f"confidence={sig.confidence:.2f}  {sig.description}"
        )

    fp_score = detector.compute_fp_score(signals)
    print(f"\nFingerprint Score: {fp_score:.1f} / 100")


if __name__ == "__main__":
    _demo()
