"""
Web Tracker Module (Milestone 05)

Monitors DNS queries, active network connections, and HTTP-level signals
to detect tracking domains and data-exfiltration patterns.  Produces a
rich WebReport consumed by ThreatScorer, AutoResponder, and the dashboard.

Detection is passive (no blocking) and designed to degrade gracefully
when elevated privileges are unavailable.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
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

import psutil

log = get_logger(__name__)


# ── Data Structures ──────────────────────────────────────────────────

@dataclass
class TrackerHit:
    """A single confirmed tracker detection."""

    domain: str
    tracker_category: str        # Analytics / Advertising / Social / Telemetry / Fingerprint
    severity: str                # LOW / MEDIUM / HIGH
    first_seen: str              # ISO-8601 timestamp
    hit_count: int = 1
    data_volume_kb: float = 0.0
    individual_score: float = 0.0  # 0–100, scored independently

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TrackerConnection:
    """An active network connection to a known or suspected tracker."""

    remote_ip: str
    remote_domain: str
    local_port: int
    protocol: str
    data_volume_kb: float = 0.0
    is_known_tracker: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FingerprintSignal:
    """A single fingerprinting heuristic detection."""

    signal_type: str             # CANVAS / WEBGL / FONT / BATTERY / AUDIO / etc.
    detected: bool
    confidence: float = 0.0      # 0.0–1.0
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WebReport:
    """Full report produced by WebTrackerMonitor.run().

    The ``raw_score`` property provides backward-compatibility with
    ``ThreatScorer._scale()`` which expects a 0–1 float.
    """

    timestamp: str = ""
    tracker_hits: list[TrackerHit] = field(default_factory=list)
    tracker_connections: list[TrackerConnection] = field(default_factory=list)
    fingerprint_signals: list[FingerprintSignal] = field(default_factory=list)
    unique_trackers_count: int = 0
    category_scores: dict[str, float] = field(default_factory=dict)
    web_score: float = 0.0                   # weighted aggregation 0–100
    active_categories: list[str] = field(default_factory=list)
    top_offenders: list[str] = field(default_factory=list)

    # ── Compat fields for ThreatScorer / AutoResponder ──────────────
    severity: str = "LOW"

    @property
    def raw_score(self) -> float:
        """0–1 representation of web_score for ThreatScorer._scale()."""
        return min(max(self.web_score / 100.0, 0.0), 1.0)

    # Compat alias consumed by ThreatScorer._collect_threats
    @property
    def trackers_detected(self) -> list[dict]:
        return [h.to_dict() for h in self.tracker_hits]

    @property
    def tracker_categories(self) -> list[str]:
        return list(self.active_categories)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["raw_score"] = self.raw_score
        d["trackers_detected"] = self.trackers_detected
        d["tracker_categories"] = self.tracker_categories
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# ── Severity helper ──────────────────────────────────────────────────

def _score_to_severity(score: float) -> str:
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "MEDIUM"
    return "HIGH"


# ── Scoring helpers ──────────────────────────────────────────────────

def score_tracker_hit(hit: TrackerHit) -> float:
    """Score a single TrackerHit using base + severity multiplier + volume bonus.

    Formula:
        individual_score = min(base * multiplier + volume_bonus, 100)
    """
    base = config.TRACKER_BASE_SCORES.get(hit.tracker_category, 30)
    multiplier = config.TRACKER_SEVERITY_MULTIPLIERS.get(hit.severity, 1.0)
    volume_bonus = min(
        hit.data_volume_kb / config.HIGH_VOLUME_TRACKER_KB * 20, 20,
    )
    return min(base * multiplier + volume_bonus, 100)


def compute_category_scores(hits: list[TrackerHit]) -> dict[str, float]:
    """Aggregate individual hit scores into per-category average scores.

    Only categories with at least one hit appear in the result.
    """
    by_category: dict[str, list[float]] = {}
    for h in hits:
        by_category.setdefault(h.tracker_category, []).append(h.individual_score)

    return {
        cat: round(max(scores), 2)  # Use max score per category
        for cat, scores in by_category.items()
    }


def compute_web_score(category_scores: dict[str, float]) -> float:
    """Weighted aggregation across active categories only.

    web_score = Σ (category_score_i * weight_i) for each active category.
    """
    total = 0.0
    for cat, score in category_scores.items():
        weight = config.TRACKER_CATEGORY_WEIGHTS.get(cat, 0.1)
        total += score * weight
    return round(min(max(total, 0.0), 100.0), 2)


# ── WebTrackerMonitor ────────────────────────────────────────────────

class WebTrackerMonitor:
    """Passive web tracker and fingerprinting detection engine.

    Detection chain:
      1. DNS query capture (scapy → system DNS cache → empty fallback)
      2. Active connection inspection via psutil
      3. Blocklist matching
      4. Per-hit and per-category scoring
      5. Fingerprinting heuristic detection
    """

    def __init__(self) -> None:
        self._blocklist: Optional[dict] = None
        self._domain_to_category: dict[str, tuple[str, str]] = {}  # domain → (category, severity)
        self._hit_history: dict[str, TrackerHit] = {}  # domain → cumulative hit
        self._reverse_dns_cache: dict[str, str] = {}   # IP → domain
        self._fingerprint_detector: Optional[FingerprintDetector] = None

    # ── Blocklist Management ─────────────────────────────────────────

    def _load_blocklist(self) -> dict:
        """Lazy-load and cache the tracker blocklist."""
        if self._blocklist is not None:
            return self._blocklist

        blocklist_path = config.TRACKER_BLOCKLIST_PATH
        try:
            if blocklist_path.exists():
                raw = json.loads(blocklist_path.read_text(encoding="utf-8"))
                self._blocklist = raw
                # Build fast lookup: domain → (category, severity)
                for category, info in raw.items():
                    severity = info.get("severity", "MEDIUM")
                    for domain in info.get("domains", []):
                        self._domain_to_category[domain.lower()] = (category, severity)
                log.info(
                    "Tracker blocklist loaded: %d categories, %d domains",
                    len(raw), len(self._domain_to_category),
                )
            else:
                log.warning("Blocklist not found at %s — using empty list", blocklist_path)
                self._blocklist = {}
        except Exception as exc:
            log.error("Failed to load blocklist: %s", exc)
            self._blocklist = {}

        return self._blocklist

    def _match_domain(self, domain: str) -> Optional[tuple[str, str]]:
        """Check if a domain matches any entry in the blocklist.

        Uses suffix matching: ``sub.tracker.example.com`` matches
        blocklist entry ``example.com``.

        Returns (category, severity) or None.
        """
        self._load_blocklist()
        domain = domain.lower().strip().rstrip(".")

        # Direct match
        if domain in self._domain_to_category:
            return self._domain_to_category[domain]

        # Suffix match (walk up the domain hierarchy)
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._domain_to_category:
                return self._domain_to_category[parent]

        return None

    # ── DNS Query Capture ────────────────────────────────────────────

    def capture_dns_queries(self, duration_sec: int = 0) -> list[str]:
        """Capture DNS queries using a fallback chain.

        1. scapy sniff (requires admin privileges)
        2. System DNS cache (ipconfig /displaydns on Windows)
        3. Empty list with warning

        Returns a list of queried domain names.
        """
        if duration_sec <= 0:
            duration_sec = config.DNS_CAPTURE_INTERVAL_SECONDS

        # Try scapy first
        domains = self._try_scapy_dns(duration_sec)
        if domains is not None:
            return domains

        # Fallback: system DNS cache
        domains = self._try_system_dns_cache()
        if domains:
            return domains

        log.debug("DNS capture: no domains found via any method")
        return []

    def _try_scapy_dns(self, duration_sec: int) -> Optional[list[str]]:
        """Attempt DNS sniffing via scapy (requires admin)."""
        try:
            from scapy.all import sniff, DNS, DNSQR
            domains: list[str] = []

            def _process_pkt(pkt):
                if pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore")
                    qname = qname.rstrip(".")
                    if qname and qname not in domains:
                        domains.append(qname)

            sniff(
                filter="port 53",
                prn=_process_pkt,
                timeout=min(duration_sec, 5),  # Cap at 5s to avoid blocking
                store=False,
            )
            log.debug("Scapy DNS capture: %d domains", len(domains))
            return domains
        except PermissionError:
            log.debug("Scapy DNS sniff requires admin privileges — falling back")
            return None
        except Exception as exc:
            log.debug("Scapy DNS sniff unavailable: %s", exc)
            return None

    def _try_system_dns_cache(self) -> list[str]:
        """Parse the system DNS cache for recently queried domains."""
        domains: list[str] = []
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["ipconfig", "/displaydns"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("Record Name"):
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                domain = parts[1].strip().rstrip(".")
                                if domain and domain not in domains:
                                    domains.append(domain)
            else:
                # Linux/macOS: no universal DNS cache CLI; use /etc/resolv.conf as indicator
                resolv = Path("/etc/resolv.conf")
                if resolv.exists():
                    log.debug("DNS cache not available on this platform via CLI")
        except subprocess.TimeoutExpired:
            log.debug("DNS cache query timed out")
        except Exception as exc:
            log.debug("DNS cache query failed: %s", exc)

        if domains:
            log.debug("System DNS cache: %d domains", len(domains))
        return domains

    # ── DNS Management ───────────────────────────────────────────────

    def flush_dns_cache(self) -> bool:
        """Flush the system DNS cache."""
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                success = result.returncode == 0
            else:
                # Linux
                result = subprocess.run(
                    ["systemd-resolve", "--flush-caches"],
                    capture_output=True, text=True, timeout=10,
                )
                success = result.returncode == 0

            if success:
                log.info("DNS cache flushed successfully")
            else:
                log.warning("DNS cache flush returned non-zero exit code")
            return success
        except Exception as exc:
            log.error("Failed to flush DNS cache: %s", exc)
            return False

    def set_hardened_dns(self, provider: str = "cloudflare") -> None:
        """Log a suggestion to switch DNS to a hardened provider.

        Does NOT auto-apply to avoid breaking network configuration.
        """
        servers = config.HARDENED_DNS_PROVIDERS.get(
            provider, config.HARDENED_DNS_PROVIDERS.get("cloudflare", []),
        )
        log.info(
            "DNS hardening suggestion: switch to %s DNS servers: %s",
            provider, servers,
        )

    # ── Active Connection Inspection ─────────────────────────────────

    def get_active_tracker_connections(self) -> list[TrackerConnection]:
        """Inspect active TCP/UDP connections and match against blocklist.

        Uses psutil.net_connections() + reverse DNS lookup.
        """
        self._load_blocklist()
        connections: list[TrackerConnection] = []

        try:
            net_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            log.debug("net_connections() requires elevated privileges")
            return connections
        except Exception as exc:
            log.debug("net_connections() failed: %s", exc)
            return connections

        for conn in net_conns:
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            local_port = conn.laddr.port if conn.laddr else 0

            # Reverse DNS lookup (cached)
            domain = self._reverse_lookup(remote_ip)

            # Check if known tracker
            match = self._match_domain(domain) if domain else None

            # Only include connections to known trackers or common tracking ports
            if match or remote_port in (80, 443):
                tc = TrackerConnection(
                    remote_ip=remote_ip,
                    remote_domain=domain or remote_ip,
                    local_port=local_port,
                    protocol=conn.type.name if hasattr(conn.type, "name") else str(conn.type),
                    data_volume_kb=0.0,  # psutil doesn't track per-connection volume
                    is_known_tracker=match is not None,
                )
                if match:
                    connections.append(tc)

        log.debug("Active tracker connections: %d", len(connections))
        return connections

    def _reverse_lookup(self, ip: str) -> str:
        """Cached reverse DNS lookup for an IP address."""
        if ip in self._reverse_dns_cache:
            return self._reverse_dns_cache[ip]

        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self._reverse_dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            self._reverse_dns_cache[ip] = ip
            return ip

    # ── HTTP Header Anomaly Detection ────────────────────────────────

    def monitor_http_headers(self) -> list[dict]:
        """Detect tracking headers in active connections.

        This is a heuristic-level check since we cannot inspect HTTP
        headers without a proxy.  Returns anomaly descriptors.
        """
        anomalies: list[dict] = []
        # Network-level: we can detect connections to known tracking
        # header relay endpoints, but cannot inspect headers directly
        # without a MITM proxy.  This is intentionally limited.
        tracker_conns = self.get_active_tracker_connections()
        for tc in tracker_conns:
            if tc.is_known_tracker:
                anomalies.append({
                    "type": "TRACKER_CONNECTION",
                    "domain": tc.remote_domain,
                    "description": f"Active connection to known tracker: {tc.remote_domain}",
                })
        return anomalies

    # ── Blocklist Matching ───────────────────────────────────────────

    def check_against_blocklist(self, domains: list[str]) -> list[TrackerHit]:
        """Match a list of domains against the loaded blocklist.

        Returns a list of TrackerHit objects for matched domains.
        Accumulates hit_count for domains seen multiple times.
        """
        self._load_blocklist()
        now = datetime.now(timezone.utc).isoformat()
        hits: list[TrackerHit] = []

        for domain in domains:
            domain_lower = domain.lower().strip().rstrip(".")
            match = self._match_domain(domain_lower)
            if match is None:
                continue

            category, severity = match

            if domain_lower in self._hit_history:
                # Increment existing hit
                existing = self._hit_history[domain_lower]
                existing.hit_count += 1
                existing.individual_score = score_tracker_hit(existing)
                hits.append(existing)
            else:
                # New hit
                hit = TrackerHit(
                    domain=domain_lower,
                    tracker_category=category,
                    severity=severity,
                    first_seen=now,
                    hit_count=1,
                    data_volume_kb=0.0,
                    individual_score=0.0,
                )
                hit.individual_score = score_tracker_hit(hit)
                self._hit_history[domain_lower] = hit
                hits.append(hit)

        return hits

    # ── Scoring ──────────────────────────────────────────────────────

    def compute_score(self, hits: list[TrackerHit]) -> float:
        """Compute the weighted web_score from tracker hits.

        Steps:
          1. Score each hit individually
          2. Aggregate into per-category scores
          3. Weighted aggregation across active categories
        """
        if not hits:
            return 0.0

        # Ensure all hits have individual scores
        for h in hits:
            if h.individual_score <= 0:
                h.individual_score = score_tracker_hit(h)

        cat_scores = compute_category_scores(hits)
        return compute_web_score(cat_scores)

    # ── Orchestrator ─────────────────────────────────────────────────

    def run(self) -> WebReport:
        """Execute one full detection cycle and return a WebReport.

        Pipeline:
          1. Capture DNS queries
          2. Get active tracker connections → extract domains
          3. Match all domains against blocklist
          4. Run fingerprinting heuristic detection
          5. Compute scores
          6. Build report
        """
        now = datetime.now(timezone.utc).isoformat()

        # 1. Capture DNS queries
        dns_domains = self.capture_dns_queries()

        # 2. Get active tracker connections
        tracker_conns = self.get_active_tracker_connections()
        conn_domains = [
            tc.remote_domain for tc in tracker_conns
            if tc.remote_domain and tc.remote_domain != tc.remote_ip
        ]

        # 3. Merge and deduplicate all observed domains
        all_domains = list(set(dns_domains + conn_domains))

        # 4. Match against blocklist
        hits = self.check_against_blocklist(all_domains)

        # 5. Also mark tracker connections from active connection scan
        # that matched the blocklist
        for tc in tracker_conns:
            if tc.is_known_tracker and tc.remote_domain:
                domain_lower = tc.remote_domain.lower().rstrip(".")
                if domain_lower not in [h.domain for h in hits]:
                    match = self._match_domain(domain_lower)
                    if match:
                        cat, sev = match
                        hit = TrackerHit(
                            domain=domain_lower,
                            tracker_category=cat,
                            severity=sev,
                            first_seen=now,
                            hit_count=1,
                            data_volume_kb=tc.data_volume_kb,
                            individual_score=0.0,
                        )
                        hit.individual_score = score_tracker_hit(hit)
                        hits.append(hit)

        # 6. Run fingerprinting detection
        if self._fingerprint_detector is None:
            from modules.fingerprint_detector import FingerprintDetector
            self._fingerprint_detector = FingerprintDetector()
        fp_signals = self._fingerprint_detector.run(
            all_domains, tracker_conns,
        )

        # Add fingerprint hits if signals detected with high confidence
        for sig in fp_signals:
            if sig.detected and sig.confidence >= config.FINGERPRINT_CONFIDENCE_THRESHOLD:
                # Create a synthetic TrackerHit for significant fingerprinting
                fp_hit = TrackerHit(
                    domain=f"fingerprint:{sig.signal_type.lower()}",
                    tracker_category="Fingerprint",
                    severity="HIGH",
                    first_seen=now,
                    hit_count=1,
                    data_volume_kb=0.0,
                    individual_score=0.0,
                )
                fp_hit.individual_score = score_tracker_hit(fp_hit)
                hits.append(fp_hit)

        # 7. Compute scores
        cat_scores = compute_category_scores(hits) if hits else {}
        web_score = compute_web_score(cat_scores) if cat_scores else 0.0
        active_cats = list(cat_scores.keys())
        severity = _score_to_severity(web_score)

        # Top offenders: tracker domains by individual_score, descending
        sorted_hits = sorted(hits, key=lambda h: h.individual_score, reverse=True)
        top_offenders = []
        seen = set()
        for h in sorted_hits:
            if h.domain not in seen:
                top_offenders.append(h.domain)
                seen.add(h.domain)
            if len(top_offenders) >= 5:
                break

        unique_domains = set(h.domain for h in hits)

        report = WebReport(
            timestamp=now,
            tracker_hits=hits,
            tracker_connections=tracker_conns,
            fingerprint_signals=fp_signals,
            unique_trackers_count=len(unique_domains),
            category_scores=cat_scores,
            web_score=web_score,
            active_categories=active_cats,
            top_offenders=top_offenders,
            severity=severity,
        )

        if hits:
            log.info(
                "WebTracker: web_score=%.1f severity=%s trackers=%d "
                "categories=%s top=%s",
                web_score, severity, len(unique_domains),
                active_cats, top_offenders[:3],
            )
        else:
            log.debug("WebTracker: web_score=0.0 — no trackers detected")

        return report


# ── Lazy import guard for FingerprintDetector ────────────────────────
# (Avoids circular imports; the class is imported inside run())

try:
    from modules.fingerprint_detector import FingerprintDetector
except ImportError:
    FingerprintDetector = None  # type: ignore[assignment,misc]


# ── CLI demo ─────────────────────────────────────────────────────────

def _demo() -> None:
    """Quick demo: run one web tracker cycle and print the report."""
    monitor = WebTrackerMonitor()
    report = monitor.run()

    print("\n=== Web Tracker Report ===")
    print(f"Timestamp          : {report.timestamp}")
    print(f"Web Score          : {report.web_score:.1f} / 100")
    print(f"Raw Score (0–1)    : {report.raw_score:.4f}")
    print(f"Severity           : {report.severity}")
    print(f"Unique Trackers    : {report.unique_trackers_count}")
    print(f"Active Categories  : {report.active_categories}")
    print(f"Category Scores    : {report.category_scores}")
    print(f"Top Offenders      : {report.top_offenders}")

    print(f"\nTracker Hits ({len(report.tracker_hits)}):")
    for h in report.tracker_hits[:10]:
        print(
            f"  {h.domain:<40} cat={h.tracker_category:<12} "
            f"sev={h.severity:<6} score={h.individual_score:.1f}"
        )

    print(f"\nTracker Connections ({len(report.tracker_connections)}):")
    for tc in report.tracker_connections[:10]:
        print(
            f"  {tc.remote_domain:<40} IP={tc.remote_ip:<15} "
            f"tracker={tc.is_known_tracker}"
        )

    print(f"\nFingerprint Signals ({len(report.fingerprint_signals)}):")
    for sig in report.fingerprint_signals:
        status = "✓ DETECTED" if sig.detected else "✗ clear"
        print(
            f"  {sig.signal_type:<10} {status}  "
            f"confidence={sig.confidence:.2f}  {sig.description}"
        )

    print(f"\nJSON (truncated):\n{report.to_json()[:600]}")


if __name__ == "__main__":
    _demo()
