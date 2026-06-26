"""
Theme engine for the PySide6 Sentinel dashboard.

Single source of truth for all colour tokens, glassmorphism palettes,
tier/pill colours, and the Qt stylesheet generator.  No widget file
should hardcode colour strings — everything comes from here.
"""

import threading

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPalette, QColor, QFont
import config

# ── Cache State ───────────────────────────────────────────────────────
_cache_lock = threading.Lock()
_resolved_mode_cache: str | None = None
_token_cache: dict | None = None

# ── Base Colour Tokens ────────────────────────────────────────────────
TOKENS = {
    "light": {
        "bg_root":          "#F9FAFB",
        "bg_sidebar":       "#FFFFFF",
        "card_bg":          "#FFFFFF",
        "card_border":      "#E5E7EB",
        "text_primary":     "#111827",
        "text_secondary":   "#6B7280",
        "text_muted":       "#9CA3AF",
        "accent":           "#10B981",
        "accent_hover":     "#059669",
        "accent_tint":      "#F0FDF4",
        "divider":          "#E5E7EB",
        "row_hover":        "#F3F4F6",
        "danger":           "#EF4444",
        "danger_tint":      "#FEF2F2",
        "warning":          "#F59E0B",
        "warning_tint":     "#FFFBEB",
        "input_bg":         "#FFFFFF",
        "input_border":     "#E5E7EB",
        "shadow":           "rgba(0, 0, 0, 0.05)",
    },
    "dark": {
        "bg_root":          "#0B0F19",
        "bg_sidebar":       "#111827",
        "card_bg":          "#1A1F2E",
        "card_border":      "#2A3045",
        "text_primary":     "#F9FAFB",
        "text_secondary":   "#9CA3AF",
        "text_muted":       "#6B7280",
        "accent":           "#10B981",
        "accent_hover":     "#059669",
        "accent_tint":      "#064E3B",
        "divider":          "#1F2937",
        "row_hover":        "#1F2937",
        "danger":           "#EF4444",
        "danger_tint":      "#7F1D1D",
        "warning":          "#F59E0B",
        "warning_tint":     "#78350F",
        "input_bg":         "#1F2937",
        "input_border":     "#374151",
        "shadow":           "rgba(0, 0, 0, 0.3)",
    },
}

# ── Glassmorphism Overrides ───────────────────────────────────────────
GLASS_TOKENS = {
    "light": {
        "card_bg":       "#FFFFFF",
        "card_border":   "#F3F4F6",
        "card_radius":   16,
        "card_bg_rgba":  "rgba(255, 255, 255, 0.82)",
        "shadow":        "rgba(0, 0, 0, 0.06)",
    },
    "dark": {
        "card_bg":       "#1A1F2E",
        "card_border":   "rgba(255, 255, 255, 0.08)",
        "card_radius":   16,
        "card_bg_rgba":  "rgba(26, 31, 46, 0.72)",
        "shadow":        "rgba(0, 0, 0, 0.4)",
    },
}

# ── Tier Colours ──────────────────────────────────────────────────────
TIER_COLORS = {
    "Safe":       {"fg": "#10B981", "bg_tint": "#D1FAE5", "text": "#065F46"},
    "Low Risk":   {"fg": "#3B82F6", "bg_tint": "#DBEAFE", "text": "#1E40AF"},
    "Elevated":   {"fg": "#F59E0B", "bg_tint": "#FEF3C7", "text": "#92400E"},
    "High Risk":  {"fg": "#EF4444", "bg_tint": "#FEE2E2", "text": "#991B1B"},
    "Critical":   {"fg": "#DC2626", "bg_tint": "#FECACA", "text": "#7F1D1D"},
}

# ── Pill Colours ──────────────────────────────────────────────────────
PILL_COLORS = {
    "CRITICAL":    ("#FEE2E2", "#991B1B"),
    "WARNING":     ("#FEF3C7", "#92400E"),
    "INFO":        ("#D1FAE5", "#065F46"),
    "REVIEW":      ("#FEF3C7", "#92400E"),
    "APPLY":       ("#D1FAE5", "#065F46"),
    "SAFE":        ("#D1FAE5", "#065F46"),
    "SUSPICIOUS":  ("#FEE2E2", "#991B1B"),
    "UNKNOWN":     ("#DBEAFE", "#1E40AF"),
    "ADVERTISING": ("#DBEAFE", "#1E40AF"),
    "ANALYTICS":   ("#D1FAE5", "#065F46"),
    "FINGERPRINT": ("#FEE2E2", "#991B1B"),
    "SOCIAL":      ("#F3E8FF", "#6B21A8"),
    "AUTO":        ("#D1FAE5", "#065F46"),
    "MANUAL":      ("#F3F4F6", "#374151"),
    "HIGH":        ("#FEE2E2", "#991B1B"),
    "MED":         ("#FEF3C7", "#92400E"),
    "LOW":         ("#D1FAE5", "#065F46"),
    "ACTIVE":      ("#D1FAE5", "#065F46"),
    "WIFI":        ("#DBEAFE", "#1E40AF"),
    "WEB":         ("#FEF3C7", "#92400E"),
    "SYSTEM":      ("#F3F4F6", "#374151"),
    "BEHAVIOUR":   ("#F0FDF4", "#065F46"),
}


def invalidate_token_cache() -> None:
    """Clear both the resolved-mode and token-dict caches.

    Must be called from the theme-toggle event path (e.g. inside
    ``apply_full_theme`` in ``app.py``) **before** any stylesheet or
    widget rebuild begins so the first ``get_card_tokens()`` call after
    a toggle always produces a fresh dict.
    """
    global _resolved_mode_cache, _token_cache
    with _cache_lock:
        _resolved_mode_cache = None
        _token_cache = None


def _resolve_mode() -> str:
    """Return 'light' or 'dark' based on config."""
    global _resolved_mode_cache
    with _cache_lock:
        if _resolved_mode_cache is not None:
            return _resolved_mode_cache

    mode = getattr(config, "APPEARANCE_MODE", "dark")
    if mode == "system":
        app = QApplication.instance()
        if app:
            pal = app.palette()
            resolved = "dark" if pal.color(QPalette.ColorRole.Window).lightness() < 128 else "light"
        else:
            resolved = "dark"
    else:
        resolved = mode if mode in ("light", "dark") else "dark"

    with _cache_lock:
        _resolved_mode_cache = resolved
    return resolved


def get_card_tokens() -> dict:
    """Return the merged token dict for the current mode + glass state."""
    global _token_cache
    with _cache_lock:
        if _token_cache is not None:
            return _token_cache

    mode = _resolve_mode()
    tokens = dict(TOKENS[mode])
    if getattr(config, "GLASSMORPHISM_ENABLED", False):
        tokens.update(GLASS_TOKENS[mode])
    tokens.setdefault("card_radius", 12)

    with _cache_lock:
        _token_cache = tokens
    return tokens


def build_stylesheet() -> str:
    """Generate the full application QSS string."""
    t = get_card_tokens()
    mode = _resolve_mode()
    bg_rgba = t.get("card_bg_rgba", t["card_bg"])
    radius = t.get("card_radius", 12)
    glass = getattr(config, "GLASSMORPHISM_ENABLED", False)

    # Sidebar active item colours
    sidebar_active_bg = t["accent_tint"]
    sidebar_hover_bg = t["row_hover"]

    # Generate PillLabel style rules dynamically from PILL_COLORS
    pill_styles = ["""
        QLabel[pillType] {
            border-radius: 6px;
            padding: 3px 10px;
        }
        QLabel[pillType="DEFAULT"] {
            background-color: #F3F4F6;
            color: #374151;
        }
    """]
    for name, (bg, fg) in PILL_COLORS.items():
        pill_styles.append(f"""
        QLabel[pillType="{name}"] {{
            background-color: {bg};
            color: {fg};
        }}
        """)
    pill_qss = "\n".join(pill_styles)

    return f"""
        /* ── Root ── */
        QMainWindow {{
            background-color: {t['bg_root']};
        }}
        QWidget#central {{
            background-color: {t['bg_root']};
        }}
        QWidget#sidebar {{
            background-color: {t['bg_sidebar']};
            border-right: 1px solid {t['divider']};
        }}
        QWidget#pageContainer {{
            background-color: {t['bg_root']};
        }}
        QFrame#topBar {{
            background-color: {t['card_bg']};
            border-bottom: 1px solid {t['divider']};
        }}

        /* ── Scrollbar ── */
        QScrollArea {{
            background-color: transparent;
            border: none;
        }}
        QScrollArea > QWidget > QWidget {{
            background-color: transparent;
        }}
        QScrollBar:vertical {{
            background: transparent;
            width: 8px;
            margin: 4px 2px;
        }}
        QScrollBar::handle:vertical {{
            background: {t['text_muted']};
            border-radius: 4px;
            min-height: 30px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {t['text_secondary']};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        QScrollBar:horizontal {{
            height: 0px;
        }}

        /* ── GlassFrame cards ── */
        QFrame#GlassFrame {{
            background-color: {bg_rgba};
            border: 1px solid {t['card_border']};
            border-radius: {radius}px;
        }}

        /* ── Labels ── */
        QLabel {{
            background: transparent;
            border: none;
        }}

        /* ── Generic buttons ── */
        QPushButton {{
            background: transparent;
            border: none;
        }}

        /* ── Inputs ── */
        QLineEdit {{
            background-color: {t['input_bg']};
            border: 1px solid {t['input_border']};
            border-radius: 8px;
            padding: 6px 12px;
            color: {t['text_primary']};
            selection-background-color: {t['accent']};
        }}
        QLineEdit:focus {{
            border-color: {t['accent']};
        }}

        /* ── ComboBox ── */
        QComboBox {{
            background-color: {t['input_bg']};
            border: 1px solid #232733;
            border-radius: 8px;
            padding: 4px 28px 4px 12px;
            color: {t['text_primary']};
            min-height: 28px;
        }}
        QComboBox:hover {{
            border-color: {t['accent']};
        }}
        QComboBox::drop-down {{
            width: 0px;
            border: none;
        }}
        QComboBox QAbstractItemView {{
            background-color: {t['card_bg']};
            border: 1px solid {t['card_border']};
            color: {t['text_primary']};
            selection-background-color: {t['accent_tint']};
            selection-color: {t['accent']};
            outline: 0;
        }}
        QComboBox QAbstractItemView::item {{
            background-color: {t['card_bg']};
            color: {t['text_primary']};
            min-height: 28px;
            padding: 4px 10px;
        }}
        QComboBox QAbstractItemView::item:hover {{
            background-color: {t['row_hover']};
            color: {t['text_primary']};
        }}
        QComboBox QAbstractItemView::item:selected {{
            background-color: {t['accent_tint']};
            color: {t['accent']};
        }}
        QListView {{
            background-color: {t['card_bg']};
            border: 1px solid {t['card_border']};
            color: {t['text_primary']};
            outline: 0;
        }}
        QListView::item {{
            background-color: {t['card_bg']};
            color: {t['text_primary']};
            min-height: 28px;
            padding: 4px 10px;
        }}
        QListView::item:hover {{
            background-color: {t['row_hover']};
            color: {t['text_primary']};
        }}
        QListView::item:selected {{
            background-color: {t['accent_tint']};
            color: {t['accent']};
        }}

        /* ── CheckBox ── */
        QCheckBox {{
            color: {t['text_primary']};
            spacing: 8px;
        }}
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border: 2px solid {t['input_border']};
            border-radius: 4px;
            background: {t['input_bg']};
        }}
        QCheckBox::indicator:checked {{
            background: {t['accent']};
            border-color: {t['accent']};
        }}
        QCheckBox::indicator:hover {{
            border-color: {t['accent']};
        }}

        /* ── ProgressBar ── */
        QProgressBar {{
            background-color: {t['input_border']};
            border: none;
            border-radius: 4px;
            max-height: 8px;
        }}
        QProgressBar::chunk {{
            border-radius: 4px;
        }}

        /* ── Tooltips ── */
        QToolTip {{
            background-color: {t['card_bg']};
            color: {t['text_primary']};
            border: 1px solid {t['card_border']};
            border-radius: 6px;
            padding: 6px 10px;
        }}

        /* ── PillLabel ── */
        {pill_qss}

        /* ── ClickableLabel ── */
        ClickableLabel[colorClass="accent"] {{
            color: {t['accent']};
        }}
        ClickableLabel[colorClass="accent"]:hover {{
            color: {t['accent']};
            text-decoration: underline;
        }}

        /* ── StatCard Labels ── */
        QLabel#statCardTitle {{
            color: {t['text_muted']};
        }}
        QLabel#statCardSuffix {{
            color: {t['text_muted']};
        }}
        QLabel#statCardValue[colorClass="primary"] {{
            color: {t['text_primary']};
        }}
        QLabel#statCardValue[colorClass="accent"] {{
            color: {t['accent']};
        }}
        QLabel#statCardValue[colorClass="danger"] {{
            color: {t['danger']};
        }}
        QLabel#statCardValue[colorClass="warning"] {{
            color: {t['warning']};
        }}
        QLabel#statCardValue[colorClass="secondary"] {{
            color: {t['text_secondary']};
        }}
        QLabel#statCardValue[colorClass="muted"] {{
            color: {t['text_muted']};
        }}
        QLabel#statCardValue[colorClass="blue"] {{
            color: #3B82F6;
        }}
        QLabel#statCardValue[colorClass="critical"] {{
            color: #DC2626;
        }}

        QLabel#statCardSubtext[colorClass="primary"] {{
            color: {t['text_primary']};
        }}
        QLabel#statCardSubtext[colorClass="accent"] {{
            color: {t['accent']};
        }}
        QLabel#statCardSubtext[colorClass="danger"] {{
            color: {t['danger']};
        }}
        QLabel#statCardSubtext[colorClass="warning"] {{
            color: {t['warning']};
        }}
        QLabel#statCardSubtext[colorClass="secondary"] {{
            color: {t['text_secondary']};
        }}
        QLabel#statCardSubtext[colorClass="muted"] {{
            color: {t['text_muted']};
        }}
        QLabel#statCardSubtext[colorClass="blue"] {{
            color: #3B82F6;
        }}
        QLabel#statCardSubtext[colorClass="critical"] {{
            color: #DC2626;
        }}

        /* ── Section Header ── */
        QLabel#sectionHeaderTitle {{
            color: {t['text_primary']};
        }}

        /* ── Table Header ── */
        QLabel#tableHeaderLabel {{
            color: {t['text_muted']};
        }}
        QFrame#tableHeaderDivider {{
            background-color: {t['divider']};
            border: none;
        }}

        /* ── HoverRow ── */
        HoverRow {{
            background-color: transparent;
        }}
        HoverRow:hover {{
            background-color: {t['row_hover']};
            border-radius: 6px;
        }}

        /* ── Table Row Labels ── */
        QLabel#tableRowLabel[colorClass="primary"] {{
            color: {t['text_primary']};
        }}
        QLabel#tableRowLabel[colorClass="secondary"] {{
            color: {t['text_secondary']};
        }}
        QWidget#tableRowPillContainer {{
            background: transparent;
            border: none;
        }}

        /* ── ActionCard ── */
        QFrame#actionCard {{
            background-color: transparent;
            border-radius: 8px;
            border: none;
        }}
        QFrame#actionCard:hover {{
            background-color: {t['row_hover']};
        }}
        QLabel#actionCardIcon {{
            background-color: {t['divider']};
            border-radius: 8px;
        }}
        QLabel#actionCardTitle {{
            color: {t['text_primary']};
        }}
        QLabel#actionCardSubtitle {{
            color: {t['text_secondary']};
        }}
        QLabel#actionCardChevron {{
            color: {t['text_muted']};
        }}

        /* ── MiniStat Labels ── */
        QLabel#miniStatIcon {{
            color: {t['text_secondary']};
        }}
        QLabel#miniStatValue {{
            color: {t['text_primary']};
        }}
        QLabel#miniStatLabel {{
            color: {t['text_muted']};
        }}

        /* ── ProgressRow Labels & Progress Bar ── */
        QLabel#progressRowLabel, QLabel#progressRowPercent {{
            color: {t['text_primary']};
        }}
        QProgressBar#progressBar_accent::chunk {{
            background-color: {t['accent']};
            border-radius: 4px;
        }}
        QProgressBar#progressBar_danger::chunk {{
            background-color: {t['danger']};
            border-radius: 4px;
        }}
        QProgressBar#progressBar_warning::chunk {{
            background-color: {t['warning']};
            border-radius: 4px;
        }}

        /* ── Custom Styled Buttons ── */
        QPushButton[btnStyle="accent"] {{
            background-color: {t['accent']};
            color: white;
            border-radius: 8px;
            padding: 8px 18px;
            border: none;
        }}
        QPushButton[btnStyle="accent"]:hover {{
            background-color: {t['accent_hover']};
        }}
        QPushButton[btnStyle="accent"]:pressed {{
            background-color: #047857;
        }}

        QPushButton[btnStyle="outline"] {{
            background: transparent;
            border: 1px solid {t['input_border']};
            color: {t['text_secondary']};
            border-radius: 6px;
            padding: 6px 16px;
        }}
        QPushButton[btnStyle="outline"][colorClass="accent"] {{
            color: {t['accent']};
        }}
        QPushButton[btnStyle="outline"]:hover {{
            background-color: {t['row_hover']};
        }}

        QPushButton[btnStyle="danger-outline"] {{
            background: transparent;
            border: 1px solid {t['danger']};
            color: {t['danger']};
            border-radius: 6px;
            padding: 6px 16px;
        }}
        QPushButton[btnStyle="danger-outline"]:hover {{
            background-color: {t['danger_tint']};
        }}

        QPushButton[btnStyle="pill"] {{
            background: transparent;
            color: {t['text_secondary']};
            border: 1px solid {t['divider']};
            border-radius: 16px;
            padding: 0 18px;
        }}
        QPushButton[btnStyle="pill"]:hover {{
            background-color: {t['row_hover']};
        }}
        QPushButton[btnStyle="pill"][active="true"] {{
            background-color: {t['accent']};
            color: white;
            border: none;
        }}
        QPushButton[btnStyle="pill"][active="true"]:hover {{
            background-color: {t['accent_hover']};
        }}
    """


def apply_theme(app: QApplication = None):
    """Apply current theme stylesheet to the QApplication."""
    if app is None:
        app = QApplication.instance()
    if app is None:
        return
    app.setStyleSheet(build_stylesheet())


def setup_fonts():
    """Load and set application-wide font."""
    app = QApplication.instance()
    if app:
        font = QFont("Segoe UI", 10)
        app.setFont(font)
