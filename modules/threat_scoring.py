"""
Threat Scoring Module (Milestone 02)

Aggregates signals from all analysis modules into a single
composite threat score with per-category breakdowns.
"""


def calculate_score(signals: dict) -> float:
    """Return a 0-100 composite threat score from raw signals."""
    raise NotImplementedError


def classify_threat(score: float) -> str:
    """Map a numeric score to LOW / MEDIUM / HIGH / CRITICAL."""
    raise NotImplementedError
