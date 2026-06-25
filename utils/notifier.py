"""
Push Notification Helper

Sends OS-native toast notifications via plyer.  Designed to be called
from the **UI thread** only (routed through DataBridge signal).

The public function ``show_notification`` checks
``config.PUSH_NOTIFICATIONS_ENABLED`` before dispatching and
gracefully degrades if plyer is unavailable or the backend fails.
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

log = get_logger(__name__)


def show_notification(title: str, message: str, timeout: int = 10) -> None:
    """Display an OS-native push notification.

    Parameters
    ----------
    title : str
        Notification title (e.g. "Protection Enabled").
    message : str
        Body text describing what happened.
    timeout : int
        How long the toast stays visible (seconds, default 10).

    This function is a no-op when ``config.PUSH_NOTIFICATIONS_ENABLED``
    is ``False`` or when plyer is not installed.
    """
    if not getattr(config, "PUSH_NOTIFICATIONS_ENABLED", True):
        return

    try:
        import os
        icon_path = str(Path(config.BASE_DIR) / "assets" / "logo.ico")
        if not os.path.exists(icon_path):
            icon_path = None

        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            app_name="Sentinel Security",
            app_icon=icon_path,
            timeout=timeout,
        )
        log.debug("Push notification sent: %s — %s (icon=%s)", title, message, icon_path)
    except ImportError:
        log.warning(
            "plyer is not installed — push notifications are unavailable. "
            "Install with: pip install plyer"
        )
    except Exception as exc:
        log.warning("Failed to send push notification: %s", exc)
