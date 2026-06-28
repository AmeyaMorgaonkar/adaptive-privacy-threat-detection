"""
Shared PySide6 UI components for the Sentinel dashboard.
All colors are theme-aware via get_card_tokens().
"""

from PySide6.QtWidgets import (
    QWidget, QFrame, QLabel, QHBoxLayout, QVBoxLayout,
    QPushButton, QProgressBar, QGraphicsOpacityEffect,
    QSizePolicy,
)
from PySide6.QtCore import Qt, QRectF, Signal, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QPainter, QPen, QColor, QFont
from ui.theme import get_card_tokens, TIER_COLORS, PILL_COLORS
from ui.glass_frame import GlassFrame


def _t():
    return get_card_tokens()


def _resolve_color_name(color_str):
    if not color_str:
        return "primary"
    color_str = color_str.lower()
    if color_str in ("primary", "secondary", "muted", "accent", "danger", "warning", "blue", "critical"):
        return color_str
    t = get_card_tokens()
    if color_str == t.get("accent", "").lower():
        return "accent"
    elif color_str == t.get("danger", "").lower():
        return "danger"
    elif color_str == t.get("warning", "").lower():
        return "warning"
    elif color_str == t.get("text_primary", "").lower():
        return "primary"
    elif color_str == t.get("text_secondary", "").lower():
        return "secondary"
    elif color_str == t.get("text_muted", "").lower():
        return "muted"
    
    for tier, info in TIER_COLORS.items():
        if color_str == info["fg"].lower():
            if tier == "Safe":
                return "accent"
            elif tier == "Low Risk":
                return "blue"
            elif tier == "Elevated":
                return "warning"
            elif tier == "High Risk":
                return "danger"
            elif tier == "Critical":
                return "critical"
    
    return "primary"


# ═══════════════════════════════════════════════════════════════════════
# PILL / BADGE LABEL
# ═══════════════════════════════════════════════════════════════════════

class PillLabel(QLabel):
    """Tinted status pill / badge label."""
    def __init__(self, text, color_type=None, parent=None):
        super().__init__(text, parent)
        if color_type is None:
            color_type = text
        pill_type = color_type.upper()
        if pill_type not in PILL_COLORS:
            pill_type = "DEFAULT"
        self.setProperty("pillType", pill_type)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))


# ═══════════════════════════════════════════════════════════════════════
# STAT CARD
# ═══════════════════════════════════════════════════════════════════════

class StatCard(GlassFrame):
    """Top-row metric card, theme-aware."""
    def __init__(self, parent, title, value="--", subtext="",
                 value_color=None, value_size=36, top_icon=None,
                 subtext_color=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(4)

        # Header
        top = QHBoxLayout()
        title_lbl = QLabel(title.upper())
        title_lbl.setObjectName("statCardTitle")
        title_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
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
        self._val_lbl.setObjectName("statCardValue")
        self._val_lbl.setProperty("colorClass", _resolve_color_name(value_color))
        self._val_lbl.setFont(QFont("Segoe UI", value_size, QFont.Weight.Bold))
        val_row.addWidget(self._val_lbl)
        if "score" in title.lower():
            suffix = QLabel("/100")
            suffix.setObjectName("statCardSuffix")
            suffix.setFont(QFont("Segoe UI", 12))
            suffix.setAlignment(Qt.AlignmentFlag.AlignBottom)
            val_row.addWidget(suffix)
        val_row.addStretch()
        layout.addLayout(val_row)

        # Subtext
        if subtext:
            if "elevated" in subtext.lower() or "requires" in subtext.lower():
                color_name = "warning"
            elif "safe" in subtext.lower() or "optimal" in subtext.lower():
                color_name = "accent"
            else:
                color_name = _resolve_color_name(subtext_color) if subtext_color else "muted"
            
            self._sub_lbl = QLabel(subtext)
            self._sub_lbl.setObjectName("statCardSubtext")
            self._sub_lbl.setProperty("colorClass", color_name)
            self._sub_lbl.setFont(QFont("Segoe UI", 10))
            self._sub_lbl.setWordWrap(True)
            layout.addWidget(self._sub_lbl)
        else:
            self._sub_lbl = None
            layout.addSpacing(18)

    def update_value(self, value, color=None):
        self._val_lbl.setText(str(value))
        if color:
            self._val_lbl.setProperty("colorClass", _resolve_color_name(color))
            self._val_lbl.style().unpolish(self._val_lbl)
            self._val_lbl.style().polish(self._val_lbl)

    def update_subtext(self, text, color=None):
        if self._sub_lbl:
            self._sub_lbl.setText(text)
            if color:
                self._sub_lbl.setProperty("colorClass", _resolve_color_name(color))
                self._sub_lbl.style().unpolish(self._sub_lbl)
                self._sub_lbl.style().polish(self._sub_lbl)


# ═══════════════════════════════════════════════════════════════════════
# SECTION HEADER
# ═══════════════════════════════════════════════════════════════════════

def section_header(parent, title, right_text=None, right_color=None,
                   right_callback=None):
    """Bold title left, optional clickable link right."""
    fr = QWidget(parent)
    lay = QHBoxLayout(fr)
    lay.setContentsMargins(22, 22, 22, 12)
    lbl = QLabel(title)
    lbl.setObjectName("sectionHeaderTitle")
    lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
    lay.addWidget(lbl)
    lay.addStretch()
    if right_text:
        rc = right_color or "accent"
        rl = ClickableLabel(right_text, rc, right_callback)
        lay.addWidget(rl)
    return fr


class ClickableLabel(QLabel):
    """Label that acts as a link with hover underline."""
    clicked = Signal()

    def __init__(self, text, color="#10B981", callback=None, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("colorClass", _resolve_color_name(color))
        if callback:
            self.clicked.connect(callback)

    def mousePressEvent(self, event):
        self.clicked.emit()


# ═══════════════════════════════════════════════════════════════════════
# TABLE HEADER & ROW
# ═══════════════════════════════════════════════════════════════════════

def table_header(parent, columns):
    """Column header row + divider.
    Each column: (width, text) or (width, text, alignment)
    """
    container = QWidget(parent)
    outer = QVBoxLayout(container)
    outer.setContentsMargins(22, 0, 22, 0)
    outer.setSpacing(0)

    row = QHBoxLayout()
    row.setSpacing(5)
    for col in columns:
        width = col[0]
        text = col[1]
        align = col[2] if len(col) > 2 else Qt.AlignmentFlag.AlignLeft
        
        lbl = QLabel(text.upper())
        lbl.setObjectName("tableHeaderLabel")
        lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lbl.setFixedWidth(width)
        lbl.setAlignment(align | Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(lbl)
    row.addStretch()
    outer.addLayout(row)

    line = QFrame()
    line.setObjectName("tableHeaderDivider")
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    outer.addWidget(line)
    return container


class HoverRow(QWidget):
    """Table data data row with hover highlight."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)


def table_row(parent, cells):
    """One data row with hover effect.
    Each cell: (width, text, style). style: normal|bold|light|pill|mono|trash
    If style ends with "_center", it center-aligns the text.
    """
    fr = HoverRow(parent)
    lay = QHBoxLayout(fr)
    # Increase vertical padding to make rows taller (improves Nearby Networks)
    lay.setContentsMargins(22, 14, 22, 14)
    lay.setSpacing(5)

    for item in cells:
        w, txt = item[0], item[1]
        style = item[2] if len(item) > 2 else "normal"
        
        align = Qt.AlignmentFlag.AlignLeft
        if style.endswith("_center"):
            style = style[:-7]
            align = Qt.AlignmentFlag.AlignCenter

        if style == "pill":
            # Wrap the pill in a centered container of width w to prevent it from stretching
            container = QWidget(fr)
            container.setObjectName("tableRowPillContainer")
            container.setFixedWidth(w)
            c_lay = QHBoxLayout(container)
            c_lay.setContentsMargins(0, 0, 0, 0)
            p = PillLabel(txt, txt, container)
            c_lay.addWidget(p, alignment=align | Qt.AlignmentFlag.AlignVCenter)
            lay.addWidget(container)
        elif style == "trash":
            tl = QLabel("🗑️")
            tl.setFont(QFont("Segoe UI", 12))
            tl.setFixedWidth(w)
            tl.setCursor(Qt.CursorShape.PointingHandCursor)
            lay.addWidget(tl)
        else:
            font = QFont("Segoe UI", 11)
            color_class = "primary"
            if style == "bold":
                font.setWeight(QFont.Weight.Bold)
            elif style == "light":
                color_class = "secondary"
            elif style == "mono":
                font = QFont("Consolas", 10)
                color_class = "secondary"
            lbl = QLabel(txt)
            lbl.setObjectName("tableRowLabel")
            lbl.setProperty("colorClass", color_class)
            lbl.setFont(font)
            lbl.setFixedWidth(w)
            lbl.setAlignment(align | Qt.AlignmentFlag.AlignVCenter)
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
        self.setObjectName("actionCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(15, 14, 15, 14)
        lay.setSpacing(12)

        self._icon_lbl = QLabel(icon)
        self._icon_lbl.setObjectName("actionCardIcon")
        self._icon_lbl.setFont(QFont("Segoe UI", 14))
        self._icon_lbl.setFixedSize(38, 38)
        self._icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._icon_lbl)

        txt = QVBoxLayout()
        txt.setSpacing(2)
        self._title_lbl = QLabel(title)
        self._title_lbl.setObjectName("actionCardTitle")
        self._title_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._title_lbl.setWordWrap(True)
        self._title_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        txt.addWidget(self._title_lbl)
        self._sub_lbl = QLabel(subtitle)
        self._sub_lbl.setObjectName("actionCardSubtitle")
        self._sub_lbl.setFont(QFont("Segoe UI", 9))
        self._sub_lbl.setWordWrap(True)
        self._sub_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        txt.addWidget(self._sub_lbl)
        lay.addLayout(txt, 1)

        self._badge = None
        if badge_text:
            self._badge = PillLabel(badge_text, badge_text)
            lay.addWidget(self._badge)
        else:
            chev = QLabel("›")
            chev.setObjectName("actionCardChevron")
            chev.setFont(QFont("Segoe UI", 18))
            lay.addWidget(chev)

    def update_content(self, icon=None, title=None, subtitle=None, badge_text=None):
        """Update card text in place without recreating the widget."""
        if icon is not None:
            self._icon_lbl.setText(icon)
        if title is not None:
            self._title_lbl.setText(title)
        if subtitle is not None:
            self._sub_lbl.setText(subtitle)
        if badge_text is not None and self._badge is not None:
            self._badge.setText(badge_text)
        self.adjustSize()

    def mousePressEvent(self, event):
        self.clicked.emit()


# ═══════════════════════════════════════════════════════════════════════
# MINI STAT
# ═══════════════════════════════════════════════════════════════════════

class MiniStat(GlassFrame):
    """Small icon + value + label card with runtime update API."""
    def __init__(self, parent, icon, value="--", label=""):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(18, 18, 18, 18)
        self._layout.setSpacing(4)

        self._icon_lbl = QLabel(icon)
        self._icon_lbl.setObjectName("miniStatIcon")
        self._icon_lbl.setFont(QFont("Segoe UI", 16))
        self._layout.addWidget(self._icon_lbl)

        self._val_lbl = QLabel(str(value))
        self._val_lbl.setObjectName("miniStatValue")
        self._val_lbl.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        self._layout.addWidget(self._val_lbl)

        self._label = QLabel(label.upper())
        self._label.setObjectName("miniStatLabel")
        self._label.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        self._layout.addWidget(self._label)

    def update_value(self, value: str) -> None:
        """Update the displayed value (string)."""
        self._val_lbl.setText(str(value))

    def set_visible(self, visible: bool) -> None:
        """Show or hide the entire mini-stat card."""
        if visible:
            self.show()
        else:
            self.hide()


def mini_stat(parent, icon, value, label):
    """Factory kept for backward compatibility; returns `MiniStat`."""
    return MiniStat(parent, icon, value, label)


# ═══════════════════════════════════════════════════════════════════════
# PROGRESS BAR & ROW
# ═══════════════════════════════════════════════════════════════════════

class SentinelProgressBar(QWidget):
    """Custom-painted, extremely reliable progress bar that avoids Qt QSS bugs."""
    def __init__(self, parent=None, value=0, color="#10B981"):
        super().__init__(parent)
        self._value = value  # 0 to 100
        self._color = color
        self.setFixedHeight(8)

    def setValue(self, value):
        self._value = max(0, min(100, value))
        self.update()

    def set_color(self, color):
        self._color = color
        self.update()

    def paintEvent(self, event):
        t = _t()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Draw background track
        track_color = QColor(t.get("input_border", "#374151"))
        painter.setBrush(track_color)
        painter.setPen(Qt.PenStyle.NoPen)
        
        w = self.width()
        h = self.height()
        painter.drawRoundedRect(0, 0, w, h, 4, 4)

        # Draw progress chunk
        if self._value > 0:
            c_str = self._color
            # Resolve semantic theme color or hex string
            if c_str.startswith("#"):
                color = QColor(c_str)
            else:
                if c_str == "accent":
                    color = QColor(t.get("accent", "#10B981"))
                elif c_str == "danger":
                    color = QColor(t.get("danger", "#EF4444"))
                elif c_str == "warning":
                    color = QColor(t.get("warning", "#F59E0B"))
                elif c_str == "blue":
                    color = QColor("#3B82F6")
                elif c_str == "critical":
                    color = QColor("#DC2626")
                elif c_str == "primary":
                    color = QColor(t.get("text_primary", "#F9FAFB"))
                elif c_str == "secondary":
                    color = QColor(t.get("text_secondary", "#9CA3AF"))
                elif c_str == "muted":
                    color = QColor(t.get("text_muted", "#6B7280"))
                else:
                    # Fallback to resolving name or parsing raw color string
                    name = _resolve_color_name(c_str)
                    if name in t:
                        color = QColor(t[name])
                    elif name == "blue":
                        color = QColor("#3B82F6")
                    elif name == "critical":
                        color = QColor("#DC2626")
                    else:
                        color = QColor(c_str)

            painter.setBrush(color)
            chunk_width = int((self._value / 100.0) * w)
            if chunk_width > 0:
                painter.drawRoundedRect(0, 0, chunk_width, h, 4, 4)


class ProgressRow(QWidget):
    """Module threat score bar row with live update support."""
    def __init__(self, parent, label, pct_text="0%", color="#10B981", value=0):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 8, 22, 8)
        lay.setSpacing(5)

        hdr = QHBoxLayout()
        self._lbl = QLabel(label)
        self._lbl.setObjectName("progressRowLabel")
        self._lbl.setFont(QFont("Segoe UI", 11))
        hdr.addWidget(self._lbl)
        hdr.addStretch()
        self._pct = QLabel(pct_text)
        self._pct.setObjectName("progressRowPercent")
        self._pct.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        hdr.addWidget(self._pct)
        lay.addLayout(hdr)

        self._bar = SentinelProgressBar(self, value=int(value * 100), color=color)
        lay.addWidget(self._bar)

    def _set_bar_color(self, color):
        self._bar.set_color(color)

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
    btn = QPushButton(text, parent)
    btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setProperty("btnStyle", "accent")
    if width:
        btn.setFixedWidth(width)
    return btn


def outline_button(text, parent=None, color=None, width=None):
    """Outlined border button."""
    btn = QPushButton(text, parent)
    btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setProperty("btnStyle", "outline")
    if color:
        btn.setProperty("colorClass", _resolve_color_name(color))
    if width:
        btn.setFixedWidth(width)
    return btn


def danger_outline_button(text, parent=None):
    """Red outlined button for danger zone."""
    btn = QPushButton(text, parent)
    btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setProperty("btnStyle", "danger-outline")
    return btn


def pill_button(text, active=False, parent=None):
    """Rounded pill filter button."""
    btn = QPushButton(text, parent)
    btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    btn.setFixedHeight(32)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setProperty("btnStyle", "pill")
    if active:
        btn.setProperty("active", True)
    return btn
