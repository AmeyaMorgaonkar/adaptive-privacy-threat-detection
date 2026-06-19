"""
GlassFrame — reusable floating-glass card widget (QFrame subclass).

Every card in the Sentinel dashboard is a GlassFrame.  Supports
live theme/glass toggle changes via the refresh_all() classmethod.
Uses real rgba opacity in QSS for genuine glassmorphism.
"""

import weakref
from PySide6.QtWidgets import QFrame, QGraphicsDropShadowEffect
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from ui.theme import get_card_tokens
import config


class GlassFrame(QFrame):
    """
    QFrame styled as a floating glass card.

    Light + glass:  white card (rgba 82% opacity) over off-white root
                    with soft drop shadow → clean float.
    Dark + glass:   semi-transparent slate card + white rim-light border
                    with deeper shadow → frosted depth.
    Glass off:      flat opaque card, standard corner radius, no shadow.
    """

    _instances: list[weakref.ref] = []

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setObjectName("GlassFrame")
        self._apply_tokens()
        GlassFrame._instances.append(weakref.ref(self))

    def _apply_tokens(self):
        tokens = get_card_tokens()
        bg = tokens.get("card_bg_rgba", tokens["card_bg"])
        border = tokens["card_border"]
        radius = tokens.get("card_radius", 12)
        shadow_color = tokens.get("shadow", "rgba(0, 0, 0, 0.05)")

        self.setStyleSheet(f"""
            QFrame#GlassFrame {{
                background-color: {bg};
                border: 1px solid {border};
                border-radius: {radius}px;
            }}
        """)

        # Drop shadow for glassmorphism depth
        glass_on = getattr(config, "GLASSMORPHISM_ENABLED", False)
        if glass_on:
            shadow = QGraphicsDropShadowEffect(self)
            mode = getattr(config, "APPEARANCE_MODE", "dark")
            if mode == "dark":
                shadow.setColor(QColor(0, 0, 0, 60))
                shadow.setBlurRadius(24)
                shadow.setOffset(0, 6)
            else:
                shadow.setColor(QColor(0, 0, 0, 20))
                shadow.setBlurRadius(16)
                shadow.setOffset(0, 4)
            self.setGraphicsEffect(shadow)
        else:
            self.setGraphicsEffect(None)

    @classmethod
    def refresh_all(cls):
        """Re-apply current tokens to every live GlassFrame instance."""
        alive = []
        for ref in cls._instances:
            frame = ref()
            if frame is not None:
                try:
                    frame._apply_tokens()
                    alive.append(ref)
                except RuntimeError:
                    pass  # C++ object deleted
        cls._instances = alive
