"""
Process Inspector Module (Milestone 04)

Deep per-process inspection utilities: enumerates running processes,
flags suspicious entries, tracks new/exited processes, and inspects
per-process network connections.

All psutil calls are wrapped to handle AccessDenied / NoSuchProcess /
ZombieProcess gracefully — the inspector degrades rather than crashes.
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

import psutil

log = get_logger(__name__)


# ── ProcessInfo dataclass ────────────────────────────────────────────

from dataclasses import dataclass, field


@dataclass
class ProcessInfo:
    """Snapshot of a single running process."""

    pid: int
    name: str
    exe_path: str
    cpu_percent: float
    memory_mb: float
    connections: list[dict] = field(default_factory=list)
    create_time: float = 0.0
    username: str = ""
    is_suspicious: bool = False


# ── ProcessInspector ─────────────────────────────────────────────────

class ProcessInspector:
    """Enumerates, inspects, and flags running processes."""

    _SAFE_SET: set[str] | None = None
    _IGNORED_NAMES = {"system idle process"}

    @classmethod
    def _get_safe_set(cls) -> set[str]:
        """Lazily build a case-insensitive lookup set from config."""
        if cls._SAFE_SET is None:
            cls._SAFE_SET = {
                name.lower() for name in config.KNOWN_SAFE_PROCESSES
            }
        return cls._SAFE_SET

    # ── Public API ───────────────────────────────────────────────────

    def list_processes(self) -> list[ProcessInfo]:
        """Return a ProcessInfo for every accessible running process.

        Fields that require elevated permissions (exe path, username,
        connections) are filled on a best-effort basis.
        """
        processes: list[ProcessInfo] = []
        # Note: 'connections' is NOT a valid attr for process_iter/as_dict;
        # we fetch connections separately per-process below.
        attrs = [
            "pid", "name", "exe", "cpu_percent",
            "memory_info", "create_time", "username",
        ]

        for proc in psutil.process_iter(attrs=attrs):
            try:
                info = proc.info  # type: ignore[attr-defined]
                pid = info.get("pid", 0)
                name = info.get("name", "") or ""

                if self._is_ignored_process(pid, name):
                    continue

                exe_path = info.get("exe", "") or ""

                mem_info = info.get("memory_info")
                memory_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0.0

                # Fetch connections separately (requires elevated perms)
                connections: list[dict] = []
                try:
                    raw_conns = proc.net_connections()
                    connections = self._serialise_connections(raw_conns)
                except (psutil.AccessDenied, psutil.NoSuchProcess,
                        psutil.ZombieProcess, OSError):
                    pass

                processes.append(ProcessInfo(
                    pid=pid,
                    name=name,
                    exe_path=exe_path,
                    cpu_percent=info.get("cpu_percent", 0.0) or 0.0,
                    memory_mb=round(memory_mb, 2),
                    connections=connections,
                    create_time=info.get("create_time", 0.0) or 0.0,
                    username=info.get("username", "") or "",
                ))
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                # Minimal record — we know the PID exists
                try:
                    processes.append(ProcessInfo(
                        pid=proc.pid,
                        name=proc.name() if proc.is_running() else "unknown",
                        exe_path="",
                        cpu_percent=0.0,
                        memory_mb=0.0,
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            except Exception as exc:
                log.debug("Skipping PID %s: %s", getattr(proc, "pid", "?"), exc)
                continue

        return processes

    def flag_suspicious(
        self, processes: list[ProcessInfo],
    ) -> list[ProcessInfo]:
        """Return the subset of *processes* that are suspicious.

        A process is suspicious if **any** of the following apply:
        - Its name is not in the known-safe list
        - It has no executable path (possible hidden / rootkit process)
        - Its CPU usage exceeds ``config.HIGH_CPU_PROCESS_THRESHOLD``
        - It holds more network connections than ``config.MAX_CONNECTIONS_PER_PROCESS``
        """
        flagged: list[ProcessInfo] = []
        for p in processes:
            if self._is_ignored_process(p.pid, p.name):
                continue

            reasons: list[str] = []

            if not self.is_known_process(p.name):
                reasons.append("unknown")

            if not p.exe_path:
                reasons.append("no_exe_path")

            if p.cpu_percent > config.HIGH_CPU_PROCESS_THRESHOLD:
                reasons.append("high_cpu")

            if len(p.connections) > config.MAX_CONNECTIONS_PER_PROCESS:
                reasons.append("many_connections")

            if reasons:
                p.is_suspicious = True
                flagged.append(p)

        return flagged

    def get_new_processes(
        self, previous: list[ProcessInfo], current: list[ProcessInfo],
    ) -> list[ProcessInfo]:
        """Return processes present in *current* but absent from *previous*.

        Comparison is by PID — a recycled PID with a different name is
        still treated as "new" for safety.
        """
        prev_pids = {(p.pid, p.name) for p in previous}
        return [p for p in current if (p.pid, p.name) not in prev_pids]

    def get_process_connections(self, pid: int) -> list[dict]:
        """Return active network connections for a single PID."""
        try:
            proc = psutil.Process(pid)
            raw = proc.net_connections()
            return self._serialise_connections(raw)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return []
        except Exception as exc:
            log.debug("Cannot get connections for PID %d: %s", pid, exc)
            return []

    def is_known_process(self, name: str) -> bool:
        """Check if *name* belongs to the known-safe process list.

        Matching is **case-insensitive** to handle Windows path quirks.
        """
        if not name:
            return False
        return name.lower() in self._get_safe_set()

    def _is_ignored_process(self, pid: int, name: str) -> bool:
        """Return True for placeholder processes that should not be analyzed."""
        if pid == 0:
            return True
        return name.strip().lower() in self._IGNORED_NAMES

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _serialise_connections(raw_conns) -> list[dict]:
        """Convert psutil connection objects to plain dicts."""
        result: list[dict] = []
        for c in raw_conns:
            try:
                entry: dict = {
                    "fd": getattr(c, "fd", -1),
                    "family": str(getattr(c, "family", "")),
                    "type": str(getattr(c, "type", "")),
                    "status": getattr(c, "status", ""),
                }
                laddr = getattr(c, "laddr", None)
                if laddr:
                    entry["laddr"] = (
                        f"{laddr.ip}:{laddr.port}" if hasattr(laddr, "ip")
                        else str(laddr)
                    )
                raddr = getattr(c, "raddr", None)
                if raddr:
                    entry["raddr"] = (
                        f"{raddr.ip}:{raddr.port}" if hasattr(raddr, "ip")
                        else str(raddr)
                    )
                result.append(entry)
            except Exception:
                continue
        return result
