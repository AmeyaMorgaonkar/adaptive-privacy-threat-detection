"""
Shared PySide6 UI components for the Sentinel dashboard.
All colors are theme-aware via get_card_tokens().
"""

from PySide6.QtWidgets import (
    QWidget, QFrame, QLabel, QHBoxLayout, QVBoxLayout,
    QPushButton, QProgressBar, QGraphicsOpacityEffect,
)
from PySide6.QtCore import Qt, QRectF, Signal, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QPainter, QPen, QColor, QFont
from ui.theme import get_card_tokens, TIER_COLORS, PILL_COLORS
from ui.glass_frame import GlassFrame


def _t():
    return get_card_tokens()


# ═══════════════════════════════════════════════════════════════════════
# PILL / BADGE LABEL
# ═══════════════════════════════════════════════════════════════════════

class PillLabel(QLabel):
    """Tinted status pill / badge label."""
    def __init__(self, text, color_type=None, parent=None):
        super().__init__(text, parent)
        if color_type is None:
            color_type = text
        bg, fg = PILL_COLORS.get(color_type.upper(), ("#F3F4F6", "#374151"))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg}; color: {fg};
                border-radius: 6px; padding: 3px 10px;
            }}
        """)


# ═══════════════════════════════════════════════════════════════════════
# STAT CARD
# ═══════════════════════════════════════════════════════════════════════

class StatCard(GlassFrame):
    """Top-row metric card, theme-aware."""
    def __init__(self, parent, title, value="--", subtext="",
                 value_color=None, value_size=36, top_icon=None,
                 subtext_color=None):
        super().__init__(parent)
        t = _t()
        if value_color is None:
            value_color = t["text_primary"]

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(4)

        # Header
        top = QHBoxLayout()
        title_lbl = QLabel(title.upper())
        title_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {t['text_muted']};")
        top.addWidget(title_lbl)
        top.addStretch()
        if top_icon:
            icon_lbl = QLabel(top_icon)
            icon_lbl.setFont(QFont("Segoe UI", 14))
            top.addWidget(icon_lbl)
        layout.addLayout(top)

        # Value
        val_row = QHBoxLayout()
        val_row.setSpacing(2)
        self._val_lbl = QLabel(str(value))
        self._val_lbl.setFont(QFont("Segoe UI", value_size, QFont.Weight.Bold))
        self._val_lbl.setStyleSheet(f"color: {value_color};")
        val_row.addWidget(self._val_lbl)
        if "score" in title.lower():
            suffix = QLabel("/100")
            suffix.setFont(QFont("Segoe UI", 12))
            suffix.setStyleSheet(f"color: {t['text_muted']};")
            suffix.setAlignment(Qt.AlignmentFlag.AlignBottom)
            val_row.addWidget(suffix)
        val_row.addStretch()
        layout.addLayout(val_row)

        # Subtext
        if subtext:
            sc = subtext_color or t["text_muted"]
            if "elevated" in subtext.lower():
                sc = t["warning"]
            elif "safe" in subtext.lower() or "optimal" in subtext.lower():
                sc = t["accent"]
            elif "requires" in subtext.lower():
                sc = t["warning"]
            self._sub_lbl = QLabel(subtext)
            self._sub_lbl.setFont(QFont("Segoe UI", 10))
            self._sub_lbl.setStyleSheet(f"color: {sc};")
            self._sub_lbl.setWordWrap(True)
            layout.addWidget(self._sub_lbl)
        else:
            self._sub_lbl = None
            layout.addSpacing(18)

    def update_value(self, value, color=None):
        self._val_lbl.setText(str(value))
        if color:
            self._val_lbl.setStyleSheet(f"color: {color};")

    def update_subtext(self, text, color=None):
        if self._sub_lbl:
            self._sub_lbl.setText(text)
            if color:
                self._sub_lbl.setStyleSheet(f"color: {color};")


# ═══════════════════════════════════════════════════════════════════════
# SECTION HEADER
# ═══════════════════════════════════════════════════════════════════════

def section_header(parent, title, right_text=None, right_color=None,
                   right_callback=None):
    """Bold title left, optional clickable link right."""
    t = _t()
    if right_color is None:
        right_color = t["accent"]
    fr = QWidget(parent)
    lay = QHBoxLayout(fr)
    lay.setContentsMargins(22, 22, 22, 12)
    lbl = QLabel(title)
    lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
    lbl.setStyleSheet(f"color: {t['text_primary']};")
    lay.addWidget(lbl)
    lay.addStretch()
    if right_text:
        rl = ClickableLabel(right_text, right_color, right_callback)
        lay.addWidget(rl)
    return fr


class ClickableLabel(QLabel):
    """Label that acts as a link with hover underline."""
    clicked = Signal()

    def __init__(self, text, color="#10B981", callback=None, parent=None):
        super().__init__(text, parent)
        self._color = color
        self.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._set_normal()
        if callback:
            self.clicked.connect(callback)

    def _set_normal(self):
        self.setStyleSheet(f"color: {self._color};")

    def enterEvent(self, event):
        self.setStyleSheet(f"color: {self._color}; text-decoration: underline;")

    def leaveEvent(self, event):
        self._set_normal()

    def mousePressEvent(self, event):
        self.clicked.emit()


# ═══════════════════════════════════════════════════════════════════════
# TABLE HEADER & ROW
# ═══════════════════════════════════════════════════════════════════════

def table_header(parent, columns):
    """Column header row + divider."""
    t = _t()
    container = QWidget(parent)
    outer = QVBoxLayout(container)
    outer.setContentsMargins(22, 0, 22, 0)
    outer.setSpacing(0)

    row = QHBoxLayout()
    row.setSpacing(5)
    for width, text in columns:
        lbl = QLabel(text.upper())
        lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lbl.setStyleSheet(f"color: {t['text_muted']};")
        lbl.setFixedWidth(width)
        row.addWidget(lbl)
    row.addStretch()
    outer.addLayout(row)

    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(f"background-color: {t['divider']}; border: none;"
                       " max-height: 1px;")
    line.setFixedHeight(1)
    outer.addWidget(line)
    return container


class HoverRow(QWidget):
    """Table data row with hover highlight."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._normal_bg = "transparent"
        self._hover_bg = _t().get("row_hover", "#F3F4F6")
        self.setStyleSheet(f"background: {self._normal_bg};")

    def enterEvent(self, event):
        self.setStyleSheet(f"background: {self._hover_bg}; border-radius: 6px;")

    def leaveEvent(self, event):
        self.setStyleSheet(f"background: {self._normal_bg};")


def table_row(parent, cells):
    """One data row with hover effect.
    Each cell: (width, text, style). style: normal|bold|light|pill|mono|trash
    """
    t = _t()
    fr = HoverRow(parent)
    lay = QHBoxLayout(fr)
    lay.setContentsMargins(22, 8, 22, 8)
    lay.setSpacing(5)

    for item in cells:
        w, txt = item[0], item[1]
        style = item[2] if len(item) > 2 else "normal"
        if style == "pill":
            p = PillLabel(txt, txt)
            p.setFixedWidth(w)
            lay.addWidget(p)
        elif style == "trash":
            tl = QLabel("🗑️")
            tl.setFont(QFont("Segoe UI", 12))
            tl.setFixedWidth(w)
            tl.setCursor(Qt.CursorShape.PointingHandCursor)
            lay.addWidget(tl)
        else:
            font = QFont("Segoe UI", 11)
            col = t["text_primary"]
            if style == "bold":
                font.setWeight(QFont.Weight.Bold)
            elif style == "light":
                col = t["text_secondary"]
            elif style == "mono":
                font = QFont("Consolas", 10)
                col = t["text_secondary"]
            lbl = QLabel(txt)
            lbl.setFont(font)
            lbl.setStyleSheet(f"color: {col};")
            lbl.setFixedWidth(w)
            lay.addWidget(lbl)
    lay.addStretch()
    return fr


# ═══════════════════════════════════════════════════════════════════════
# ACTION CARD (with hover)
# ═══════════════════════════════════════════════════════════════════════

class ActionCard(QFrame):
    """Recommended-action row card with hover."""
    clicked = Signal()

    def __init__(self, parent, icon, title, subtitle, badge_text=None):
        super().__init__(parent)
        t = _t()
        self._bg = t.get("row_hover", "#F9FAFB")
        self._bg_hover = t.get("divider", "#E5E7EB")
        self.setStyleSheet(f"QFrame {{ background-color: {self._bg};"
                           f" border-radius: 10px; border: none; }}")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(15, 14, 15, 14)
        lay.setSpacing(12)

        ib = QLabel(icon)
        ib.setFont(QFont("Segoe UI", 14))
        ib.setFixedSize(38, 38)
        ib.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ib.setStyleSheet(f"background-color: {t['divider']}; border-radius: 8px;")
        lay.addWidget(ib)

        txt = QVBoxLayout()
        txt.setSpacing(2)
        t_lbl = QLabel(title)
        t_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        t_lbl.setStyleSheet(f"color: {t['text_primary']};")
        txt.addWidget(t_lbl)
        s_lbl = QLabel(subtitle)
        s_lbl.setFont(QFont("Segoe UI", 9))
        s_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        s_lbl.setWordWrap(True)
        s_lbl.setMaximumWidth(320)
        txt.addWidget(s_lbl)
        lay.addLayout(txt, 1)

        if badge_text:
            p = PillLabel(badge_text, badge_text)
            lay.addWidget(p)
        else:
            chev = QLabel("›")
            chev.setFont(QFont("Segoe UI", 18))
            chev.setStyleSheet(f"color: {t['text_muted']};")
            lay.addWidget(chev)

    def enterEvent(self, event):
        self.setStyleSheet(f"QFrame {{ background-color: {self._bg_hover};"
                           f" border-radius: 10px; border: none; }}")

    def leaveEvent(self, event):
        self.setStyleSheet(f"QFrame {{ background-color: {self._bg};"
                           f" border-radius: 10px; border: none; }}")

    def mousePressEvent(self, event):
        self.clicked.emit()


# ═══════════════════════════════════════════════════════════════════════
# MINI STAT
# ═══════════════════════════════════════════════════════════════════════

def mini_stat(parent, icon, value, label):
    """Small icon + value + label card."""
    t = _t()
    f = GlassFrame(parent)
    layout = QVBoxLayout(f)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.setSpacing(4)

    icon_lbl = QLabel(icon)
    icon_lbl.setFont(QFont("Segoe UI", 16))
    icon_lbl.setStyleSheet(f"color: {t['text_secondary']};")
    layout.addWidget(icon_lbl)

    val_lbl = QLabel(str(value))
    val_lbl.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
    val_lbl.setStyleSheet(f"color: {t['text_primary']};")
    layout.addWidget(val_lbl)

    lbl = QLabel(label.upper())
    lbl.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
    lbl.setStyleSheet(f"color: {t['text_muted']};")
    layout.addWidget(lbl)
    return f


# ═══════════════════════════════════════════════════════════════════════
# PROGRESS ROW
# ═══════════════════════════════════════════════════════════════════════

class ProgressRow(QWidget):
    """Module threat score bar row with live update support."""
    def __init__(self, parent, label, pct_text="0%", color="#10B981", value=0):
        super().__init__(parent)
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 8, 22, 8)
        lay.setSpacing(5)

        hdr = QHBoxLayout()
        self._lbl = QLabel(label)
        self._lbl.setFont(QFont("Segoe UI", 11))
        self._lbl.setStyleSheet(f"color: {t['text_primary']};")
        hdr.addWidget(self._lbl)
        hdr.addStretch()
        self._pct = QLabel(pct_text)
        self._pct.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._pct.setStyleSheet(f"color: {t['text_primary']};")
        hdr.addWidget(self._pct)
        lay.addLayout(hdr)

        self._bar = QProgressBar()
        self._bar.setFixedHeight(8)
        self._bar.setRange(0, 100)
        self._bar.setValue(int(value * 100))
        self._bar.setTextVisible(False)
        self._set_bar_color(color)
        lay.addWidget(self._bar)

    def _set_bar_color(self, color):
        self._bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {_t()['divider']};
                border: none; border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {color}; border-radius: 4px;
            }}
        """)

    def update_value(self, score_100, color=None):
        self._pct.setText(f"{int(score_100)}%")
        self._bar.setValue(int(score_100))
        if color:
            self._set_bar_color(color)


# ═══════════════════════════════════════════════════════════════════════
# CIRCULAR GAUGE
# ═══════════════════════════════════════════════════════════════════════

class CircularGauge(QWidget):
    """Half-arc gauge widget drawn with QPainter."""
    def __init__(self, parent=None, size=140, score=0, color="#10B981",
                 show_label=True):
        super().__init__(parent)
        self._size = size
        self._score = score
        self._color = color
        self._show_label = show_label
        self.setFixedSize(size, size)

    def set_score(self, score, color=None):
        self._score = score
        if color:
            self._color = color
        self.update()

    def paintEvent(self, event):
        t = _t()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2 + 15
        r = min(w, h) / 2 - 15
        rect = QRectF(cx - r, cy - r, 2 * r, 2 * r)

        # Background arc
        pen = QPen(QColor(t["divider"]), 14)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 0 * 16, 180 * 16)

        # Progress arc
        if self._score > 0:
            pen = QPen(QColor(self._color), 14)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            extent = (self._score / 100.0) * 180
            painter.drawArc(rect, 180 * 16, -int(extent * 16))

        # Score text
        painter.setPen(QColor(t["text_primary"]))
        painter.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        painter.drawText(QRectF(0, cy - 35, w, 40),
                         Qt.AlignmentFlag.AlignCenter, str(int(self._score)))

        if self._show_label:
            painter.setPen(QColor(t["text_muted"]))
            painter.setFont(QFont("Segoe UI", 9))
            painter.drawText(QRectF(0, cy + 2, w, 20),
                             Qt.AlignmentFlag.AlignCenter, "/100")
        painter.end()


# ═══════════════════════════════════════════════════════════════════════
# TOGGLE SWITCH (with signal)
# ═══════════════════════════════════════════════════════════════════════

class ToggleSwitch(QWidget):
    """Animated toggle switch widget."""
    toggled = Signal(bool)

    def __init__(self, parent=None, checked=False, enabled=True):
        super().__init__(parent)
        self._checked = checked
        self._enabled = enabled
        self.setFixedSize(44, 24)
        self.setCursor(Qt.CursorShape.PointingHandCursor if enabled
                       else Qt.CursorShape.ForbiddenCursor)

    def isChecked(self):
        return self._checked

    def setChecked(self, val):
        self._checked = val
        self.update()

    def mousePressEvent(self, event):
        if self._enabled:
            self._checked = not self._checked
            self.toggled.emit(self._checked)
            self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        r = h / 2

        if self._checked:
            bg = QColor("#10B981")
        else:
            bg = QColor("#D1D5DB")
        if not self._enabled:
            bg = QColor("#E5E7EB")

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(bg)
        painter.drawRoundedRect(0, 0, w, h, r, r)

        knob_r = h - 6
        knob_x = w - knob_r - 3 if self._checked else 3
        painter.setBrush(QColor("#FFFFFF"))
        painter.drawEllipse(int(knob_x), 3, int(knob_r), int(knob_r))
        painter.end()


# ═══════════════════════════════════════════════════════════════════════
# STYLED BUTTON HELPERS
# ═══════════════════════════════════════════════════════════════════════

def accent_button(text, parent=None, width=None):
    """Green filled button."""
    t = _t()
    btn = QPushButton(text, parent)
    btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    style = f"""
        QPushButton {{
            background-color: {t['accent']}; color: white;
            border-radius: 8px; padding: 8px 18px; border: none;
        }}
        QPushButton:hover {{ background-color: {t['accent_hover']}; }}
        QPushButton:pressed {{ background-color: #047857; }}
    """
    btn.setStyleSheet(style)
    if width:
        btn.setFixedWidth(width)
    return btn


def outline_button(text, parent=None, color=None, width=None):
    """Outlined border button."""
    t = _t()
    c = color or t["text_secondary"]
    border = t.get("input_border", "#D1D5DB")
    btn = QPushButton(text, parent)
    btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setStyleSheet(f"""
        QPushButton {{
            background: transparent; border: 1px solid {border};
            color: {c}; border-radius: 6px; padding: 6px 16px;
        }}
        QPushButton:hover {{ background-color: {t['row_hover']}; }}
    """)
    if width:
        btn.setFixedWidth(width)
    return btn


def danger_outline_button(text, parent=None):
    """Red outlined button for danger zone."""
    t = _t()
    btn = QPushButton(text, parent)
    btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setStyleSheet(f"""
        QPushButton {{
            background: transparent; border: 1px solid {t['danger']};
            color: {t['danger']}; border-radius: 6px; padding: 6px 16px;
        }}
        QPushButton:hover {{ background-color: {t['danger_tint']}; }}
    """)
    return btn


def pill_button(text, active=False, parent=None):
    """Rounded pill filter button."""
    t = _t()
    btn = QPushButton(text, parent)
    btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    btn.setFixedHeight(32)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    if active:
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t['accent']}; color: white;
                border-radius: 16px; padding: 0 18px; border: none;
            }}
            QPushButton:hover {{ background-color: {t['accent_hover']}; }}
        """)
    else:
        btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {t['text_secondary']};
                border: 1px solid {t['divider']}; border-radius: 16px;
                padding: 0 18px;
            }}
            QPushButton:hover {{ background-color: {t['row_hover']}; }}
        """)
    return btn
