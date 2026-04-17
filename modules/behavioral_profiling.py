"""
Behavioral Profiling Module (Milestone 03)

Builds a baseline of normal network/system behaviour and uses
anomaly detection (Isolation Forest) to flag deviations.
"""


def build_baseline(history: list[dict]) -> object:
    """Train an anomaly-detection model on historical observations."""
    raise NotImplementedError


def detect_anomalies(model: object, observation: dict) -> bool:
    """Return True if the observation deviates from the baseline."""
    raise NotImplementedError
