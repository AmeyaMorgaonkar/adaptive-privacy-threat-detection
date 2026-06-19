"""
PySide6 Application Shell — QMainWindow with sidebar navigation,
header bar, scrollable content, QTimer data refresh, and live theme switching.
"""

import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel,
    QHBoxLayout, QVBoxLayout, QPushButton, QScrollArea,
    QStackedWidget, QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont

from ui.theme import apply_theme, get_card_tokens, setup_fonts, build_stylesheet
from ui.glass_frame import GlassFrame
from ui.data_bridge import DataBridge
from ui.pages import (
    DashboardPage, WiFiSecurityPage, BehaviourAnalysisPage,
    WebTrackingPage, SettingsPage,
)
from ui.report_panel import ReportPanel
from utils.config_manager import ConfigManager
import config


class NavButton(QPushButton):
    """Sidebar nav button with hover effect and active state."""
    def __init__(self, text, icon_char, parent=None):
        super().__init__(f"  {icon_char}   {text}", parent)
        self.page_name = text
        self._active = False
        self.setFont(QFont("Segoe UI", 12))
        self.setFixedHeight(42)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._apply_style()

    def set_active(self, active):
        self._active = active
        self.setFont(QFont("Segoe UI", 12,
                           QFont.Weight.Bold if active else QFont.Weight.Normal))
        self._apply_style()

    def _apply_style(self):
        t = get_card_tokens()
        if self._active:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {t['accent_tint']};
                    color: {t['accent']};
                    font-weight: bold;
                    border: none; border-radius: 10px;
                    text-align: left; padding-left: 2px;
                    margin: 2px 12px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {t['text_secondary']};
                    border: none; border-radius: 10px;
                    text-align: left; padding-left: 2px;
                    margin: 2px 12px;
                }}
                QPushButton:hover {{
                    background-color: {t['row_hover']};
                    color: {t['text_primary']};
                }}
            """)


class Sidebar(QFrame):
    """Left navigation sidebar."""
    def __init__(self, parent, app_window):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(210)
        self.app_window = app_window
        self.buttons: dict[str, NavButton] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Logo ──
        logo_c = QWidget()
        logo_l = QVBoxLayout(logo_c)
        logo_l.setContentsMargins(25, 35, 25, 30)
        logo_l.setSpacing(2)
        logo_r = QHBoxLayout()
        logo_r.setSpacing(4)
        shield = QLabel("🛡️")
        shield.setFont(QFont("Segoe UI", 20))
        logo_r.addWidget(shield)
        brand = QLabel("Sentinel")
        brand.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        brand.setStyleSheet("color: #10B981;")
        logo_r.addWidget(brand)
        logo_r.addStretch()
        logo_l.addLayout(logo_r)
        tagline = QLabel("Tactical Security")
        tagline.setFont(QFont("Segoe UI", 9))
        tagline.setStyleSheet("color: #9CA3AF;")
        tagline.setContentsMargins(4, 0, 0, 0)
        logo_l.addWidget(tagline)
        layout.addWidget(logo_c)

        # ── Top Nav ──
        for name, icon in [("Dashboard", "⊞"), ("WiFi Security", "◉"),
                           ("Behaviour Analysis", "◎"),
                           ("Web Tracking", "◈")]:
            btn = NavButton(name, icon)
            btn.clicked.connect(lambda _, n=name: self.app_window.show_page(n))
            layout.addWidget(btn)
            self.buttons[name] = btn

        layout.addStretch()

        # ── Bottom Nav ──
        for name, icon in [("Reports", "📊"), ("Settings", "⚙")]:
            btn = NavButton(name, icon)
            btn.clicked.connect(lambda _, n=name: self.app_window.show_page(n))
            layout.addWidget(btn)
            self.buttons[name] = btn

        layout.addSpacing(25)

    def set_active(self, page_name):
        for name, btn in self.buttons.items():
            btn.set_active(name == page_name)

    def refresh_styles(self):
        """Re-apply styles after theme change."""
        t = get_card_tokens()
        self.setStyleSheet(f"""
            QFrame#sidebar {{
                background-color: {t['bg_sidebar']};
                border-right: 1px solid {t['divider']};
            }}
        """)
        for btn in self.buttons.values():
            btn._apply_style()


class Header(QFrame):
    """Top bar with centered page title."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("topBar")
        self.setFixedHeight(72)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(24, 0, 24, 0)
        outer.setSpacing(0)
        outer.addStretch(1)

        center = QWidget(self)
        center_layout = QHBoxLayout(center)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(16)

        self.title_lbl = QLabel("Dashboard")
        self.title_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self.title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        center_layout.addWidget(self.title_lbl)
        outer.addWidget(center)
        outer.addStretch(1)
        self._apply_style()

    def set_title(self, title):
        self.title_lbl.setText(title)

    def _apply_style(self):
        t = get_card_tokens()
        self.title_lbl.setStyleSheet(f"color: {t['text_primary']};")

    def refresh_styles(self):
        self._apply_style()


class App(QMainWindow):
    """Main application window."""

    def __init__(self, data_bridge: DataBridge, config_manager: ConfigManager = None):
        super().__init__()
        self.setWindowTitle("Sentinel Dashboard")
        self.resize(1440, 950)
        self.setMinimumSize(1100, 768)

        self.data_bridge = data_bridge
        self.config_manager = config_manager or ConfigManager()
        self._current_page = "Dashboard"

        # Apply initial theme
        apply_theme()
        setup_fonts()

        # ── Central widget ──
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Sidebar ──
        self.sidebar = Sidebar(central, self)
        main_layout.addWidget(self.sidebar)

        # ── Right content ──
        right = QWidget()
        right.setObjectName("pageContainer")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 10)
        rl.setSpacing(0)

        self.header = Header()
        rl.addWidget(self.header)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(40, 25, 0, 0)
        content_layout.setSpacing(0)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        scroll_content = QWidget()
        scroll_content.setStyleSheet("background: transparent;")
        scl = QVBoxLayout(scroll_content)
        scl.setContentsMargins(0, 2, 24, 0)
        scl.setSpacing(0)

        self.page_stack = QStackedWidget()
        # Keep the stack height tied to the visible page to avoid
        # scrolling into blank space from larger hidden pages.
        self.page_stack.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        scl.addWidget(self.page_stack)
        scl.addStretch()

        self.scroll_area.setWidget(scroll_content)
        content_layout.addWidget(self.scroll_area)
        rl.addWidget(content)
        main_layout.addWidget(right, 1)

        # ── Pages ──
        self._build_pages()
        self.show_page("Dashboard")

        # ── QTimer ──
        self._timer = QTimer(self)
        self._timer.setInterval(config.DASHBOARD_REFRESH_MS)
        self._timer.timeout.connect(self._on_refresh)
        self._timer.start()

    def _build_pages(self):
        """Create all page widgets."""
        self.pages = {}
        self.pages["Dashboard"] = DashboardPage(self.page_stack,
                                                self.data_bridge)
        self.pages["WiFi Security"] = WiFiSecurityPage(
            self.page_stack, data_bridge=self.data_bridge)
        self.pages["Behaviour Analysis"] = BehaviourAnalysisPage(
            self.page_stack, data_bridge=self.data_bridge)
        self.pages["Web Tracking"] = WebTrackingPage(self.page_stack,
                                                      data_bridge=self.data_bridge)
        self.pages["Reports"] = ReportPanel(self.page_stack,
                                            data_bridge=self.data_bridge)
        self.pages["Settings"] = SettingsPage(
            self.page_stack,
            config_manager=self.config_manager,
            app_window=self)

        for page in self.pages.values():
            self.page_stack.addWidget(page)

    def show_page(self, page_name):
        if page_name in self.pages:
            self._current_page = page_name
            self.page_stack.setCurrentWidget(self.pages[page_name])
            self._sync_page_stack_height()
            self.sidebar.set_active(page_name)
            self.header.set_title(page_name)
            self.scroll_area.verticalScrollBar().setValue(0)

    def _sync_page_stack_height(self):
        """Match the stacked widget height to the current page only."""
        page = self.page_stack.currentWidget()
        if page is None:
            return
        page.adjustSize()
        target_height = max(page.sizeHint().height(), page.minimumSizeHint().height())
        self.page_stack.setMinimumHeight(target_height)
        self.page_stack.setMaximumHeight(target_height)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_page_stack_height()

    def _on_refresh(self):
        """Polls DataBridge every tick, updates live pages."""
        score = self.data_bridge.latest()
        if score and "Dashboard" in self.pages:
            self.pages["Dashboard"].refresh(score)
        # WiFi page gets full WiFiReport
        reports = self.data_bridge.get_reports()
        wifi_report = reports.get("wifi_report")
        if wifi_report is not None and "WiFi Security" in self.pages:
            self.pages["WiFi Security"].refresh(score, wifi_report)
        # Behaviour page gets full BehavioralReport
        behavioral_report = reports.get("behavioral_report")
        if behavioral_report is not None and "Behaviour Analysis" in self.pages:
            self.pages["Behaviour Analysis"].refresh(score, behavioral_report)
        # Web Tracking page gets full WebReport
        web_report = reports.get("web_report")
        if web_report is not None and "Web Tracking" in self.pages:
            self.pages["Web Tracking"].refresh(score, web_report)
        # Reports page gets all module reports
        if "Reports" in self.pages:
            self.pages["Reports"].refresh(
                score,
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
            )

    def apply_full_theme(self):
        """Rebuild entire stylesheet and refresh all UI components.
        Called when theme or glass setting changes from Settings page.
        """
        apply_theme()
        GlassFrame.refresh_all()
        self.sidebar.refresh_styles()
        self.header.refresh_styles()

        # Rebuild pages to pick up new token colors
        current = self._current_page
        # Remove old pages
        while self.page_stack.count() > 0:
            w = self.page_stack.widget(0)
            self.page_stack.removeWidget(w)
            w.deleteLater()
        self.pages.clear()
        # Rebuild
        self._build_pages()
        self.show_page(current)


def run(data_bridge: DataBridge, config_manager: ConfigManager = None):
    """Launch the PySide6 application."""
    app = QApplication(sys.argv)
    window = App(data_bridge, config_manager=config_manager)
    window.show()
    sys.exit(app.exec())
