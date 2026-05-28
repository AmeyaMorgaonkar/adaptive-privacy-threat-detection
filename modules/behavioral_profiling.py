"""
Behavioral Profiling Module (Milestone 04)

Monitors CPU usage, running processes, and system activity to establish
a baseline of normal behaviour, then detects anomalies in real time
using Z-score thresholding and per-process heuristics.

Two-phase approach:
  Phase 1 — Baseline Learning  (first N minutes):
      Collects snapshots into a buffer and computes rolling mean / std.
  Phase 2 — Real-time Detection (ongoing):
      Flags deviations via Z-score; adapts baseline with EMA.
"""

from __future__ import annotations

import json
import math
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

from modules.process_inspector import ProcessInfo, ProcessInspector

log = get_logger(__name__)


# ── Data Structures ──────────────────────────────────────────────────

@dataclass
class SystemSnapshot:
    """Point-in-time capture of system-wide resource usage."""

    timestamp: str
    cpu_percent: float              # Overall CPU %
    cpu_per_core: list[float] = field(default_factory=list)
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    processes: list[ProcessInfo] = field(default_factory=list)
    top_cpu_processes: list[ProcessInfo] = field(default_factory=list)


@dataclass
class Anomaly:
    """A single detected behavioural deviation."""

    type: str                       # CPU_SPIKE / MEMORY_SPIKE / etc.
    description: str
    severity: str                   # LOW / MEDIUM / HIGH
    score_contribution: float


@dataclass
class BehavioralReport:
    """Final output of ``BehavioralProfiler.run()``.

    Fields ``raw_score``, ``anomalous_processes``, and ``severity`` are
    included for backward-compatibility with ``ThreatScorer._scale()``
    and ``AutoResponder._handle_behavioral()``.
    """

    timestamp: str = ""
    snapshot: Optional[SystemSnapshot] = None
    anomalies: list[Anomaly] = field(default_factory=list)
    behavioral_score: float = 0.0       # 0–100
    baseline_deviation: float = 0.0     # % deviation from baseline

    # ── Compat fields consumed by ThreatScorer / AutoResponder ──────
    raw_score: float = 0.0              # 0–1 (behavioral_score / 100)
    anomalous_processes: list[str] = field(default_factory=list)
    severity: str = "LOW"

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dictionary."""
        d = asdict(self)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# ── Baseline data holder ─────────────────────────────────────────────

@dataclass
class _BaselineStats:
    """Internal container for baseline statistics."""

    cpu_mean: float = 0.0
    cpu_std: float = 0.0
    memory_mean: float = 0.0
    memory_std: float = 0.0
    process_count_mean: float = 0.0
    process_count_std: float = 0.0
    known_process_names: set[str] = field(default_factory=set)
    snapshot_count: int = 0


# ── Severity helper ──────────────────────────────────────────────────

def _score_to_severity(score: float) -> str:
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "MEDIUM"
    return "HIGH"


# ── BehavioralProfiler ──────────────────────────────────────────────

class BehavioralProfiler:
    """Collects system snapshots, learns a baseline, detects anomalies."""

    def __init__(self) -> None:
        self._inspector = ProcessInspector()

        # Baseline state
        self._baseline = _BaselineStats()
        self._learning = True
        self._learn_buffer: list[dict] = []     # raw stat dicts
        self._learn_start: float = time.monotonic()

        # Previous snapshot (for process churn detection)
        self._prev_processes: list[ProcessInfo] = []

        # EMA update counter (for periodic saves)
        self._ema_updates: int = 0

        # Try to load a persisted baseline
        self._try_load_baseline()

    # ── Public API ───────────────────────────────────────────────────

    def collect_snapshot(self) -> SystemSnapshot:
        """Gather a system-wide snapshot via psutil + ProcessInspector."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
        except Exception:
            cpu_percent = 0.0

        try:
            cpu_per_core = psutil.cpu_percent(interval=0, percpu=True)
        except Exception:
            cpu_per_core = []

        try:
            mem = psutil.virtual_memory()
            memory_percent = mem.percent
            memory_used_mb = round(mem.used / (1024 * 1024), 2)
        except Exception:
            memory_percent = 0.0
            memory_used_mb = 0.0

        processes = self._inspector.list_processes()

        # Top CPU consumers (top 10)
        top_cpu = sorted(processes, key=lambda p: p.cpu_percent, reverse=True)[:10]

        return SystemSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            cpu_percent=cpu_percent,
            cpu_per_core=cpu_per_core,
            memory_percent=memory_percent,
            memory_used_mb=memory_used_mb,
            processes=processes,
            top_cpu_processes=top_cpu,
        )

    def update_baseline(self, snapshot: SystemSnapshot) -> None:
        """Update the baseline with new snapshot data.

        During the learning phase, stats are buffered and mean/std are
        recomputed.  After learning, an EMA update is applied.
        """
        stats = {
            "cpu": snapshot.cpu_percent,
            "memory": snapshot.memory_percent,
            "process_count": len(snapshot.processes),
            "process_names": {p.name.lower() for p in snapshot.processes if p.name},
        }

        if self._learning:
            self._learn_buffer.append(stats)
            self._recompute_baseline_from_buffer()

            # Check if learning period is over
            elapsed_min = (time.monotonic() - self._learn_start) / 60.0
            if elapsed_min >= config.BASELINE_LEARNING_MINUTES:
                self._learning = False
                self.save_baseline()
                log.info(
                    "Baseline learning complete (%d snapshots, %.1f min). "
                    "CPU μ=%.1f σ=%.1f  Mem μ=%.1f σ=%.1f  Procs μ=%.0f",
                    len(self._learn_buffer),
                    elapsed_min,
                    self._baseline.cpu_mean,
                    self._baseline.cpu_std,
                    self._baseline.memory_mean,
                    self._baseline.memory_std,
                    self._baseline.process_count_mean,
                )
        else:
            # EMA update
            alpha = config.EMA_ALPHA
            self._baseline.cpu_mean = (
                alpha * stats["cpu"]
                + (1 - alpha) * self._baseline.cpu_mean
            )
            self._baseline.memory_mean = (
                alpha * stats["memory"]
                + (1 - alpha) * self._baseline.memory_mean
            )
            self._baseline.process_count_mean = (
                alpha * stats["process_count"]
                + (1 - alpha) * self._baseline.process_count_mean
            )
            # Update known process set (union — never shrink)
            self._baseline.known_process_names |= stats["process_names"]
            self._baseline.snapshot_count += 1

            self._ema_updates += 1
            if self._ema_updates % 10 == 0:
                self.save_baseline()

    def detect_anomalies(self, snapshot: SystemSnapshot) -> list[Anomaly]:
        """Detect anomalies by comparing snapshot against the baseline."""
        anomalies: list[Anomaly] = []

        if self._learning and self._baseline.snapshot_count < 3:
            # Not enough data to detect anomalies yet
            return anomalies

        # ── CPU spike ────────────────────────────────────────────────
        z_cpu = self._z_score(
            snapshot.cpu_percent,
            self._baseline.cpu_mean,
            self._baseline.cpu_std,
        )
        if z_cpu > config.Z_SCORE_THRESHOLD:
            anomalies.append(Anomaly(
                type="CPU_SPIKE",
                description=(
                    f"CPU at {snapshot.cpu_percent:.1f}% "
                    f"(baseline {self._baseline.cpu_mean:.1f}% ± "
                    f"{self._baseline.cpu_std:.1f}%, z={z_cpu:.1f})"
                ),
                severity="HIGH" if z_cpu > 5 else "MEDIUM",
                score_contribution=20.0,
            ))

        # ── Memory spike ─────────────────────────────────────────────
        z_mem = self._z_score(
            snapshot.memory_percent,
            self._baseline.memory_mean,
            self._baseline.memory_std,
        )
        if z_mem > config.Z_SCORE_THRESHOLD:
            anomalies.append(Anomaly(
                type="MEMORY_SPIKE",
                description=(
                    f"Memory at {snapshot.memory_percent:.1f}% "
                    f"(baseline {self._baseline.memory_mean:.1f}% ± "
                    f"{self._baseline.memory_std:.1f}%, z={z_mem:.1f})"
                ),
                severity="HIGH" if z_mem > 5 else "MEDIUM",
                score_contribution=15.0,
            ))

        # ── Per-process anomalies ────────────────────────────────────
        for p in snapshot.processes:
            # High CPU single process
            if p.cpu_percent > config.HIGH_CPU_PROCESS_THRESHOLD:
                anomalies.append(Anomaly(
                    type="HIGH_CPU_PROCESS",
                    description=(
                        f"Process '{p.name}' (PID {p.pid}) using "
                        f"{p.cpu_percent:.1f}% CPU"
                    ),
                    severity="MEDIUM",
                    score_contribution=20.0,
                ))

            # Hidden process (no exe path)
            if not p.exe_path and p.name and not self._inspector.is_known_process(p.name):
                anomalies.append(Anomaly(
                    type="HIDDEN_PROCESS",
                    description=(
                        f"Process '{p.name}' (PID {p.pid}) has no "
                        f"executable path — possible hidden process"
                    ),
                    severity="HIGH",
                    score_contribution=35.0,
                ))

            # Many connections
            if len(p.connections) > config.MAX_CONNECTIONS_PER_PROCESS:
                anomalies.append(Anomaly(
                    type="MANY_CONNECTIONS",
                    description=(
                        f"Process '{p.name}' (PID {p.pid}) has "
                        f"{len(p.connections)} open connections "
                        f"(threshold: {config.MAX_CONNECTIONS_PER_PROCESS})"
                    ),
                    severity="MEDIUM",
                    score_contribution=20.0,
                ))

        # ── New unknown processes ────────────────────────────────────
        if not self._learning:
            known = self._baseline.known_process_names
            for p in snapshot.processes:
                name_lower = p.name.lower() if p.name else ""
                if name_lower and name_lower not in known:
                    if not self._inspector.is_known_process(p.name):
                        anomalies.append(Anomaly(
                            type="NEW_UNKNOWN_PROCESS",
                            description=(
                                f"Unknown process '{p.name}' (PID {p.pid}) "
                                f"not seen during baseline learning"
                            ),
                            severity="MEDIUM",
                            score_contribution=25.0,
                        ))

        # ── Process churn ────────────────────────────────────────────
        if self._prev_processes:
            new_procs = self._inspector.get_new_processes(
                self._prev_processes, snapshot.processes,
            )
            if len(new_procs) > config.PROCESS_CHURN_THRESHOLD:
                anomalies.append(Anomaly(
                    type="PROCESS_CHURN",
                    description=(
                        f"{len(new_procs)} new processes spawned since "
                        f"last snapshot (threshold: "
                        f"{config.PROCESS_CHURN_THRESHOLD})"
                    ),
                    severity="MEDIUM",
                    score_contribution=15.0,
                ))

        return anomalies

    def compute_score(self, anomalies: list[Anomaly]) -> float:
        """Sum anomaly score contributions, clamped to 0–100."""
        total = sum(a.score_contribution for a in anomalies)
        return min(max(total, 0.0), 100.0)

    def run(self) -> BehavioralReport:
        """Orchestrate one profiling cycle: collect → update → detect → score."""
        snapshot = self.collect_snapshot()
        self.update_baseline(snapshot)
        anomalies = self.detect_anomalies(snapshot)
        score = self.compute_score(anomalies)
        severity = _score_to_severity(score)

        # Compute baseline deviation %
        deviation = 0.0
        if not self._learning and self._baseline.cpu_mean > 0:
            deviation = abs(
                snapshot.cpu_percent - self._baseline.cpu_mean
            ) / self._baseline.cpu_mean * 100.0

        # Collect names of anomalous processes for AutoResponder compat
        anomalous_names: list[str] = []
        for a in anomalies:
            if a.type in (
                "HIGH_CPU_PROCESS", "HIDDEN_PROCESS",
                "NEW_UNKNOWN_PROCESS", "MANY_CONNECTIONS",
            ):
                # Extract process name from description
                if "'" in a.description:
                    name = a.description.split("'")[1]
                    if name not in anomalous_names:
                        anomalous_names.append(name)

        report = BehavioralReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            snapshot=snapshot,
            anomalies=anomalies,
            behavioral_score=round(score, 2),
            baseline_deviation=round(deviation, 2),
            raw_score=round(score / 100.0, 4),
            anomalous_processes=anomalous_names,
            severity=severity,
        )

        # Remember processes for next churn check
        self._prev_processes = snapshot.processes

        if anomalies:
            log.info(
                "BehavioralProfiler: score=%.1f severity=%s anomalies=%d [%s]",
                score,
                severity,
                len(anomalies),
                ", ".join(a.type for a in anomalies),
            )
        else:
            log.debug("BehavioralProfiler: score=0.0 — no anomalies")

        return report

    # ── Baseline persistence ─────────────────────────────────────────

    def save_baseline(self, path: Optional[str | Path] = None) -> None:
        """Persist the current baseline to JSON."""
        target = Path(path) if path else config.BASELINE_PATH
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "cpu_mean": self._baseline.cpu_mean,
                "cpu_std": self._baseline.cpu_std,
                "memory_mean": self._baseline.memory_mean,
                "memory_std": self._baseline.memory_std,
                "process_count_mean": self._baseline.process_count_mean,
                "process_count_std": self._baseline.process_count_std,
                "known_process_names": sorted(self._baseline.known_process_names),
                "snapshot_count": self._baseline.snapshot_count,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            target.write_text(
                json.dumps(data, indent=2), encoding="utf-8",
            )
            log.info("Baseline saved to %s (%d snapshots)", target, data["snapshot_count"])
        except Exception as exc:
            log.error("Failed to save baseline: %s", exc)

    def load_baseline(self, path: Optional[str | Path] = None) -> bool:
        """Load a persisted baseline from JSON. Returns True on success."""
        target = Path(path) if path else config.BASELINE_PATH
        try:
            if not target.exists():
                return False
            data = json.loads(target.read_text(encoding="utf-8"))
            self._baseline = _BaselineStats(
                cpu_mean=data.get("cpu_mean", 0.0),
                cpu_std=data.get("cpu_std", 0.0),
                memory_mean=data.get("memory_mean", 0.0),
                memory_std=data.get("memory_std", 0.0),
                process_count_mean=data.get("process_count_mean", 0.0),
                process_count_std=data.get("process_count_std", 0.0),
                known_process_names=set(data.get("known_process_names", [])),
                snapshot_count=data.get("snapshot_count", 0),
            )
            self._learning = False
            log.info(
                "Baseline loaded from %s (%d snapshots)",
                target, self._baseline.snapshot_count,
            )
            return True
        except Exception as exc:
            log.warning("Failed to load baseline from %s: %s", target, exc)
            return False

    def reset_baseline(self) -> None:
        """Clear the learned baseline and re-enter learning phase."""
        self._baseline = _BaselineStats()
        self._learning = True
        self._learn_buffer.clear()
        self._learn_start = time.monotonic()
        self._prev_processes.clear()
        self._ema_updates = 0
        log.info("Baseline reset — re-entering learning phase")

    @property
    def is_learning(self) -> bool:
        """True if still in the initial baseline learning phase."""
        return self._learning

    # ── Internal helpers ─────────────────────────────────────────────

    def _try_load_baseline(self) -> None:
        """Attempt to load a saved baseline on init."""
        if self.load_baseline():
            log.info("Using persisted baseline — skipping learning phase")
        else:
            log.info(
                "No saved baseline found — entering %d-minute learning phase",
                config.BASELINE_LEARNING_MINUTES,
            )

    def _recompute_baseline_from_buffer(self) -> None:
        """Recompute mean/std from the full learning buffer."""
        n = len(self._learn_buffer)
        if n == 0:
            return

        cpus = [s["cpu"] for s in self._learn_buffer]
        mems = [s["memory"] for s in self._learn_buffer]
        procs = [s["process_count"] for s in self._learn_buffer]

        self._baseline.cpu_mean = sum(cpus) / n
        self._baseline.cpu_std = self._std(cpus)
        self._baseline.memory_mean = sum(mems) / n
        self._baseline.memory_std = self._std(mems)
        self._baseline.process_count_mean = sum(procs) / n
        self._baseline.process_count_std = self._std(procs)
        self._baseline.snapshot_count = n

        # Union of all observed process names
        all_names: set[str] = set()
        for s in self._learn_buffer:
            all_names |= s.get("process_names", set())
        self._baseline.known_process_names = all_names

    @staticmethod
    def _std(values: list[float]) -> float:
        """Population standard deviation (avoiding numpy dependency in hot path)."""
        n = len(values)
        if n < 2:
            return 0.0
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n
        return math.sqrt(variance)

    @staticmethod
    def _z_score(value: float, mean: float, std: float) -> float:
        """Compute the Z-score. Returns 0 if std is ~0."""
        if std < 1e-9:
            return 0.0
        return abs(value - mean) / std


# ── CLI demo ─────────────────────────────────────────────────────────

def _demo() -> None:
    """Quick demo: run one profiling cycle and print the report."""
    profiler = BehavioralProfiler()
    report = profiler.run()

    print("\n=== Behavioral Profiling Report ===")
    print(f"Timestamp          : {report.timestamp}")
    print(f"Behavioral Score   : {report.behavioral_score:.1f} / 100")
    print(f"Raw Score (0–1)    : {report.raw_score:.4f}")
    print(f"Severity           : {report.severity}")
    print(f"Baseline Deviation : {report.baseline_deviation:.1f}%")
    print(f"Learning Phase     : {profiler.is_learning}")

    if report.snapshot:
        snap = report.snapshot
        print(f"\nCPU Usage          : {snap.cpu_percent:.1f}%")
        print(f"Memory Usage       : {snap.memory_percent:.1f}%")
        print(f"Total Processes    : {len(snap.processes)}")
        print(f"Top CPU Processes  :")
        for p in snap.top_cpu_processes[:5]:
            print(f"  {p.name:<30} CPU={p.cpu_percent:.1f}%  MEM={p.memory_mb:.0f}MB")

    print(f"\nAnomalies ({len(report.anomalies)}):")
    for a in report.anomalies:
        print(f"  [{a.severity}] {a.type}: {a.description} (+{a.score_contribution})")

    print(f"\nAnomalous Processes: {report.anomalous_processes or 'None'}")


if __name__ == "__main__":
    _demo()
