"""
Tests for Behavioral Profiling & Process Inspector (Milestone 04)

Covers data structures, snapshot collection, baseline learning/persistence,
Z-score anomaly detection, process inspection, score computation, and
end-to-end BehavioralProfiler.run() + ThreatScorer integration.
"""

from __future__ import annotations

import json
import math
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import config
from modules.process_inspector import ProcessInfo, ProcessInspector
from modules.behavioral_profiling import (
    Anomaly,
    BehavioralProfiler,
    BehavioralReport,
    SystemSnapshot,
    _BaselineStats,
    _score_to_severity,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _make_process(
    pid=1, name="test.exe", exe_path="C:\\test.exe",
    cpu_percent=1.0, memory_mb=50.0, connections=None,
    create_time=0.0, username="user", is_suspicious=False,
) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        name=name,
        exe_path=exe_path,
        cpu_percent=cpu_percent,
        memory_mb=memory_mb,
        connections=connections or [],
        create_time=create_time,
        username=username,
        is_suspicious=is_suspicious,
    )


def _make_snapshot(
    cpu_percent=10.0, memory_percent=40.0,
    processes=None, timestamp=None,
) -> SystemSnapshot:
    return SystemSnapshot(
        timestamp=timestamp or "2025-01-01T00:00:00+00:00",
        cpu_percent=cpu_percent,
        cpu_per_core=[cpu_percent],
        memory_percent=memory_percent,
        memory_used_mb=memory_percent * 100,
        processes=processes or [],
        top_cpu_processes=[],
    )


# =====================================================================
#  1. Data Structure Tests
# =====================================================================

class TestProcessInfo:
    def test_construction(self):
        p = _make_process(pid=42, name="foo.exe")
        assert p.pid == 42
        assert p.name == "foo.exe"
        assert p.is_suspicious is False

    def test_serialisation(self):
        p = _make_process()
        d = asdict(p)
        assert isinstance(d, dict)
        assert d["pid"] == 1
        assert d["name"] == "test.exe"


class TestSystemSnapshot:
    def test_construction(self):
        snap = _make_snapshot(cpu_percent=55.0, memory_percent=70.0)
        assert snap.cpu_percent == 55.0
        assert snap.memory_percent == 70.0

    def test_serialisation(self):
        snap = _make_snapshot()
        d = asdict(snap)
        assert "timestamp" in d
        assert "cpu_percent" in d


class TestAnomaly:
    def test_construction(self):
        a = Anomaly(
            type="CPU_SPIKE",
            description="CPU at 95%",
            severity="HIGH",
            score_contribution=20.0,
        )
        assert a.type == "CPU_SPIKE"
        assert a.score_contribution == 20.0


class TestBehavioralReport:
    def test_construction(self):
        r = BehavioralReport(
            timestamp="2025-01-01T00:00:00",
            behavioral_score=45.0,
            raw_score=0.45,
            severity="MEDIUM",
        )
        assert r.behavioral_score == 45.0
        assert r.raw_score == 0.45

    def test_to_dict(self):
        r = BehavioralReport()
        d = r.to_dict()
        assert isinstance(d, dict)
        assert "raw_score" in d
        assert "anomalous_processes" in d

    def test_to_json(self):
        r = BehavioralReport()
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["behavioral_score"] == 0.0


# =====================================================================
#  2. ProcessInspector Tests
# =====================================================================

class TestProcessInspector:
    def setup_method(self):
        self.inspector = ProcessInspector()
        # Reset class-level cache
        ProcessInspector._SAFE_SET = None

    def test_is_known_process_safe(self):
        assert self.inspector.is_known_process("explorer.exe") is True
        assert self.inspector.is_known_process("Explorer.EXE") is True  # case-insensitive

    def test_is_known_process_unknown(self):
        assert self.inspector.is_known_process("malware.exe") is False

    def test_is_known_process_empty(self):
        assert self.inspector.is_known_process("") is False

    def test_flag_suspicious_unknown_process(self):
        procs = [
            _make_process(pid=1, name="explorer.exe"),
            _make_process(pid=2, name="totally_unknown_thing.exe"),
        ]
        flagged = self.inspector.flag_suspicious(procs)
        assert len(flagged) == 1
        assert flagged[0].name == "totally_unknown_thing.exe"
        assert flagged[0].is_suspicious is True

    def test_flag_suspicious_high_cpu(self):
        procs = [
            _make_process(
                pid=1, name="explorer.exe",
                cpu_percent=config.HIGH_CPU_PROCESS_THRESHOLD + 10,
            ),
        ]
        flagged = self.inspector.flag_suspicious(procs)
        assert len(flagged) == 1

    def test_flag_suspicious_no_exe_path(self):
        procs = [
            _make_process(pid=1, name="sneaky.exe", exe_path=""),
        ]
        flagged = self.inspector.flag_suspicious(procs)
        assert len(flagged) >= 1

    def test_flag_suspicious_many_connections(self):
        many_conns = [{"fd": i} for i in range(config.MAX_CONNECTIONS_PER_PROCESS + 5)]
        procs = [
            _make_process(
                pid=1, name="weird_net.exe",
                connections=many_conns,
            ),
        ]
        flagged = self.inspector.flag_suspicious(procs)
        assert len(flagged) >= 1

    def test_get_new_processes(self):
        prev = [_make_process(pid=1, name="a.exe"), _make_process(pid=2, name="b.exe")]
        curr = [
            _make_process(pid=1, name="a.exe"),
            _make_process(pid=2, name="b.exe"),
            _make_process(pid=3, name="c.exe"),
        ]
        new = self.inspector.get_new_processes(prev, curr)
        assert len(new) == 1
        assert new[0].pid == 3

    def test_get_new_processes_pid_reuse(self):
        """A recycled PID with a different name counts as new."""
        prev = [_make_process(pid=1, name="old.exe")]
        curr = [_make_process(pid=1, name="new.exe")]
        new = self.inspector.get_new_processes(prev, curr)
        assert len(new) == 1

    @patch("modules.process_inspector.psutil")
    def test_list_processes_handles_access_denied(self, mock_psutil):
        """list_processes should not crash on AccessDenied."""
        import psutil as real_psutil

        mock_proc = MagicMock()
        mock_proc.info = None
        mock_proc.__iter__ = MagicMock(side_effect=real_psutil.AccessDenied(pid=999))

        mock_psutil.process_iter.return_value = []
        result = self.inspector.list_processes()
        assert isinstance(result, list)

    @patch("modules.process_inspector.psutil")
    def test_system_idle_process_is_ignored(self, mock_psutil):
        idle = MagicMock()
        idle.info = {
            "pid": 0,
            "name": "System Idle Process",
            "exe": "",
            "cpu_percent": 99.9,
            "memory_info": None,
            "create_time": 0.0,
            "username": "",
        }
        mock_psutil.process_iter.return_value = [idle]

        processes = self.inspector.list_processes()

        assert processes == []
        assert self.inspector.flag_suspicious(processes) == []


# =====================================================================
#  3. Baseline Learning Tests
# =====================================================================

class TestBaselineLearning:
    def setup_method(self):
        # Patch config to avoid loading a real baseline file
        self._orig_path = config.BASELINE_PATH
        config.BASELINE_PATH = Path(tempfile.mkdtemp()) / "test_baseline.json"

    def teardown_method(self):
        config.BASELINE_PATH = self._orig_path

    def _make_profiler(self) -> BehavioralProfiler:
        """Create a profiler that's guaranteed to be in learning mode."""
        p = BehavioralProfiler()
        p._learning = True
        p._learn_buffer.clear()
        p._learn_start = time.monotonic()
        return p

    def test_initial_state_is_learning(self):
        p = self._make_profiler()
        assert p.is_learning is True

    def test_update_baseline_buffers_stats(self):
        p = self._make_profiler()
        snap = _make_snapshot(cpu_percent=50.0, memory_percent=60.0)
        p.update_baseline(snap)
        assert len(p._learn_buffer) == 1
        assert p._baseline.cpu_mean == 50.0

    def test_baseline_mean_computed_correctly(self):
        p = self._make_profiler()
        for cpu in [10, 20, 30]:
            snap = _make_snapshot(cpu_percent=float(cpu), memory_percent=50.0)
            p.update_baseline(snap)

        assert p._baseline.cpu_mean == pytest.approx(20.0, abs=0.01)

    def test_baseline_std_computed_correctly(self):
        p = self._make_profiler()
        values = [10.0, 20.0, 30.0]
        for v in values:
            snap = _make_snapshot(cpu_percent=v, memory_percent=50.0)
            p.update_baseline(snap)

        # Population std of [10, 20, 30] = sqrt(200/3) ≈ 8.165
        expected_std = math.sqrt(sum((x - 20) ** 2 for x in values) / len(values))
        assert p._baseline.cpu_std == pytest.approx(expected_std, abs=0.01)

    def test_learning_completes_after_time(self):
        p = self._make_profiler()
        # Fake the start time to be 6 minutes ago
        p._learn_start = time.monotonic() - (config.BASELINE_LEARNING_MINUTES * 60 + 10)

        snap = _make_snapshot(cpu_percent=25.0, memory_percent=50.0)
        p.update_baseline(snap)

        assert p.is_learning is False


# =====================================================================
#  4. Baseline Persistence Tests
# =====================================================================

class TestBaselinePersistence:
    def setup_method(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._path = self._tmp / "baseline.json"

    def test_save_and_load_roundtrip(self):
        p = BehavioralProfiler()
        p._learning = False
        p._baseline = _BaselineStats(
            cpu_mean=30.0,
            cpu_std=5.0,
            memory_mean=60.0,
            memory_std=8.0,
            process_count_mean=150.0,
            process_count_std=20.0,
            known_process_names={"explorer.exe", "python.exe"},
            snapshot_count=100,
        )
        p.save_baseline(self._path)

        p2 = BehavioralProfiler()
        p2._learning = True
        result = p2.load_baseline(self._path)

        assert result is True
        assert p2.is_learning is False
        assert p2._baseline.cpu_mean == pytest.approx(30.0)
        assert p2._baseline.cpu_std == pytest.approx(5.0)
        assert "explorer.exe" in p2._baseline.known_process_names

    def test_load_nonexistent_returns_false(self):
        p = BehavioralProfiler()
        result = p.load_baseline(self._tmp / "nonexistent.json")
        assert result is False

    def test_saved_file_is_valid_json(self):
        p = BehavioralProfiler()
        p._baseline = _BaselineStats(cpu_mean=10.0, snapshot_count=5)
        p.save_baseline(self._path)

        data = json.loads(self._path.read_text(encoding="utf-8"))
        assert "cpu_mean" in data
        assert "saved_at" in data


# =====================================================================
#  5. Z-Score Anomaly Detection Tests
# =====================================================================

class TestAnomalyDetection:
    def setup_method(self):
        self._orig_path = config.BASELINE_PATH
        config.BASELINE_PATH = Path(tempfile.mkdtemp()) / "test_baseline.json"

    def teardown_method(self):
        config.BASELINE_PATH = self._orig_path

    def _make_trained_profiler(
        self, cpu_mean=20.0, cpu_std=3.0,
        memory_mean=50.0, memory_std=5.0,
    ) -> BehavioralProfiler:
        p = BehavioralProfiler()
        p._learning = False
        p._baseline = _BaselineStats(
            cpu_mean=cpu_mean,
            cpu_std=cpu_std,
            memory_mean=memory_mean,
            memory_std=memory_std,
            process_count_mean=100,
            process_count_std=10,
            known_process_names={"explorer.exe", "python.exe", "svchost.exe"},
            snapshot_count=50,
        )
        return p

    def test_no_anomalies_normal_snapshot(self):
        p = self._make_trained_profiler()
        snap = _make_snapshot(cpu_percent=22.0, memory_percent=52.0)
        anomalies = p.detect_anomalies(snap)
        # Should not detect CPU_SPIKE or MEMORY_SPIKE at these values
        spike_types = {a.type for a in anomalies}
        assert "CPU_SPIKE" not in spike_types
        assert "MEMORY_SPIKE" not in spike_types

    def test_cpu_spike_detected(self):
        p = self._make_trained_profiler(cpu_mean=20.0, cpu_std=3.0)
        # z = (40 - 20) / 3 = 6.67 > 3.0
        snap = _make_snapshot(cpu_percent=40.0, memory_percent=50.0)
        anomalies = p.detect_anomalies(snap)
        types = [a.type for a in anomalies]
        assert "CPU_SPIKE" in types

    def test_memory_spike_detected(self):
        p = self._make_trained_profiler(memory_mean=50.0, memory_std=5.0)
        # z = (80 - 50) / 5 = 6.0 > 3.0
        snap = _make_snapshot(cpu_percent=20.0, memory_percent=80.0)
        anomalies = p.detect_anomalies(snap)
        types = [a.type for a in anomalies]
        assert "MEMORY_SPIKE" in types

    def test_high_cpu_process_detected(self):
        p = self._make_trained_profiler()
        proc = _make_process(
            name="miner.exe",
            cpu_percent=config.HIGH_CPU_PROCESS_THRESHOLD + 20,
        )
        snap = _make_snapshot(
            cpu_percent=20.0, memory_percent=50.0, processes=[proc],
        )
        anomalies = p.detect_anomalies(snap)
        types = [a.type for a in anomalies]
        assert "HIGH_CPU_PROCESS" in types

    def test_hidden_process_detected(self):
        p = self._make_trained_profiler()
        proc = _make_process(name="stealth.exe", exe_path="")
        snap = _make_snapshot(
            cpu_percent=20.0, memory_percent=50.0, processes=[proc],
        )
        anomalies = p.detect_anomalies(snap)
        types = [a.type for a in anomalies]
        assert "HIDDEN_PROCESS" in types

    def test_many_connections_detected(self):
        p = self._make_trained_profiler()
        conns = [{"fd": i} for i in range(config.MAX_CONNECTIONS_PER_PROCESS + 5)]
        proc = _make_process(name="netspam.exe", connections=conns)
        snap = _make_snapshot(
            cpu_percent=20.0, memory_percent=50.0, processes=[proc],
        )
        anomalies = p.detect_anomalies(snap)
        types = [a.type for a in anomalies]
        assert "MANY_CONNECTIONS" in types

    def test_new_unknown_process_detected(self):
        p = self._make_trained_profiler()
        proc = _make_process(name="brand_new_evil.exe")
        snap = _make_snapshot(
            cpu_percent=20.0, memory_percent=50.0, processes=[proc],
        )
        anomalies = p.detect_anomalies(snap)
        types = [a.type for a in anomalies]
        assert "NEW_UNKNOWN_PROCESS" in types

    def test_process_churn_detected(self):
        p = self._make_trained_profiler()
        # Set up previous processes
        p._prev_processes = [_make_process(pid=i, name=f"old_{i}.exe") for i in range(5)]
        # Current has many new ones
        new_count = config.PROCESS_CHURN_THRESHOLD + 5
        current_procs = [
            _make_process(pid=100 + i, name=f"new_{i}.exe")
            for i in range(new_count)
        ]
        snap = _make_snapshot(
            cpu_percent=20.0, memory_percent=50.0, processes=current_procs,
        )
        anomalies = p.detect_anomalies(snap)
        types = [a.type for a in anomalies]
        assert "PROCESS_CHURN" in types

    def test_no_anomaly_during_early_learning(self):
        """During the first few snapshots of learning, no anomalies should fire."""
        p = BehavioralProfiler()
        p._learning = True
        p._learn_buffer.clear()
        p._baseline = _BaselineStats(snapshot_count=1)
        snap = _make_snapshot(cpu_percent=99.0, memory_percent=99.0)
        anomalies = p.detect_anomalies(snap)
        assert len(anomalies) == 0


# =====================================================================
#  6. Score Computation Tests
# =====================================================================

class TestScoreComputation:
    def test_score_zero_no_anomalies(self):
        p = BehavioralProfiler()
        assert p.compute_score([]) == 0.0

    def test_score_sums_contributions(self):
        p = BehavioralProfiler()
        anomalies = [
            Anomaly("CPU_SPIKE", "test", "HIGH", 20.0),
            Anomaly("MEMORY_SPIKE", "test", "MEDIUM", 15.0),
        ]
        assert p.compute_score(anomalies) == 35.0

    def test_score_clamped_at_100(self):
        p = BehavioralProfiler()
        anomalies = [
            Anomaly("A", "x", "HIGH", 50.0),
            Anomaly("B", "x", "HIGH", 50.0),
            Anomaly("C", "x", "HIGH", 50.0),
        ]
        assert p.compute_score(anomalies) == 100.0

    def test_severity_mapping(self):
        assert _score_to_severity(0) == "LOW"
        assert _score_to_severity(24) == "LOW"
        assert _score_to_severity(25) == "MEDIUM"
        assert _score_to_severity(49) == "MEDIUM"
        assert _score_to_severity(50) == "HIGH"
        assert _score_to_severity(100) == "HIGH"


# =====================================================================
#  7. End-to-End run() Tests
# =====================================================================

class TestBehavioralProfilerRun:
    def setup_method(self):
        self._orig_path = config.BASELINE_PATH
        config.BASELINE_PATH = Path(tempfile.mkdtemp()) / "test_baseline.json"

    def teardown_method(self):
        config.BASELINE_PATH = self._orig_path

    @patch("modules.behavioral_profiling.BehavioralProfiler.collect_snapshot")
    def test_run_returns_report(self, mock_collect):
        mock_collect.return_value = _make_snapshot(
            cpu_percent=15.0, memory_percent=45.0,
        )
        p = BehavioralProfiler()
        p._learning = True
        report = p.run()

        assert isinstance(report, BehavioralReport)
        assert report.timestamp != ""
        assert 0 <= report.behavioral_score <= 100
        assert 0 <= report.raw_score <= 1.0
        assert report.severity in ("LOW", "MEDIUM", "HIGH")

    @patch("modules.behavioral_profiling.BehavioralProfiler.collect_snapshot")
    def test_run_detects_high_cpu_anomaly(self, mock_collect):
        high_cpu_proc = _make_process(
            name="miner.exe",
            cpu_percent=config.HIGH_CPU_PROCESS_THRESHOLD + 30,
        )
        mock_collect.return_value = _make_snapshot(
            cpu_percent=15.0, memory_percent=45.0,
            processes=[high_cpu_proc],
        )

        p = BehavioralProfiler()
        p._learning = False
        p._baseline = _BaselineStats(
            cpu_mean=15.0, cpu_std=3.0,
            memory_mean=45.0, memory_std=5.0,
            process_count_mean=100, process_count_std=10,
            known_process_names={"explorer.exe"},
            snapshot_count=50,
        )

        report = p.run()
        assert report.behavioral_score > 0
        assert "miner.exe" in report.anomalous_processes

    @patch("modules.behavioral_profiling.BehavioralProfiler.collect_snapshot")
    def test_run_report_compatible_with_threat_scorer(self, mock_collect):
        """BehavioralReport from run() must be accepted by ThreatScorer."""
        mock_collect.return_value = _make_snapshot(
            cpu_percent=15.0, memory_percent=45.0,
        )
        p = BehavioralProfiler()
        report = p.run()

        # The report must have the fields ThreatScorer expects
        assert hasattr(report, "raw_score")
        assert hasattr(report, "anomalous_processes")
        assert hasattr(report, "severity")
        assert hasattr(report, "timestamp")

        # Verify it works with ThreatScorer._scale()
        from modules.threat_scoring import ThreatScorer
        scaled = ThreatScorer._scale(report)
        assert 0 <= scaled <= 100


# =====================================================================
#  8. Reset Baseline Test
# =====================================================================

class TestBaselineReset:
    def setup_method(self):
        self._orig_path = config.BASELINE_PATH
        config.BASELINE_PATH = Path(tempfile.mkdtemp()) / "test_baseline.json"

    def teardown_method(self):
        config.BASELINE_PATH = self._orig_path

    def test_reset_returns_to_learning(self):
        p = BehavioralProfiler()
        p._learning = False
        p._baseline = _BaselineStats(cpu_mean=50.0, snapshot_count=100)
        p._learn_buffer = [{"cpu": 50}]

        p.reset_baseline()

        assert p.is_learning is True
        assert p._baseline.cpu_mean == 0.0
        assert p._baseline.snapshot_count == 0
        assert len(p._learn_buffer) == 0
