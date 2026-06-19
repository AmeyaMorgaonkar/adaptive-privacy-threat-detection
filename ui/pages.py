"""
All page views for the Sentinel dashboard (PySide6).
Each page matches the design mockups and is wired for live data.
"""

from datetime import datetime
import config
import time
from logger import get_logger

log = get_logger(__name__)

from PySide6.QtWidgets import (
    QWidget, QFrame, QLabel, QHBoxLayout, QVBoxLayout,
    QGridLayout, QPushButton, QComboBox, QLineEdit,
    QCheckBox, QMessageBox,
)
from PySide6.QtCore import Qt, QRectF, QThread, Signal, Slot, QTimer
from PySide6.QtGui import QFont, QPainter, QPen, QColor

from ui.glass_frame import GlassFrame
from ui.theme import get_card_tokens, TIER_COLORS
from ui.components import (
    PillLabel, StatCard, section_header, table_header, table_row,
    ActionCard, mini_stat, ProgressRow, CircularGauge, ToggleSwitch,
    ClickableLabel, accent_button, outline_button, danger_outline_button,
    pill_button, HoverRow,
)

# Canonical list of actions (UI-only source-of-truth for All Actions page).
# Derived from modules/auto_responder.py and modules/wifi_responder.py.
ALL_ACTIONS = [
    {"name": "Auto-Isolation High-Risk IP", "module": "System", "type": "AUTO", "enabled": True, "last": "2m ago", "desc": "Disconnects nodes showing high-risk outbound…"},
    {"name": "Rogue AP De-auth", "module": "WiFi", "type": "AUTO", "enabled": True, "last": "14m ago", "desc": "Sends de-auth packets to unauthorized APs…"},
    {"name": "WPA3 Enforcement", "module": "WiFi", "type": "AUTO", "enabled": True, "last": "--", "desc": "Auto-upgrades connecting clients to WPA3…"},
    {"name": "Auto-disconnect Suspicious WiFi", "module": "WiFi", "type": "AUTO", "enabled": True, "last": "--", "desc": "Disconnects from suspicious networks automatically."},
    {"name": "Exfil Threshold Alert", "module": "Behaviour", "type": "AUTO", "enabled": True, "last": "1h ago", "desc": "Logs warning when data egress exceeds limit…"},
    {"name": "Beacon Frequency Monitor", "module": "Behaviour", "type": "AUTO", "enabled": True, "last": "12h ago", "desc": "Detects C2 beaconing patterns in network…"},
    {"name": "Manual Credential Flush", "module": "Web Tracking", "type": "MANUAL", "enabled": False, "last": "--", "desc": "Clears all active session tokens for the user…"},
    {"name": "Tracker Pixel Scrubber", "module": "Web Tracking", "type": "MANUAL", "enabled": False, "last": "2d ago", "desc": "Filters invisible tracking pixels from pages…"},
    {"name": "Block Ad Networks", "module": "Web Tracking", "type": "AUTO", "enabled": True, "last": "42m ago", "desc": "Enable DNS-level ad blocking (Pi-hole, NextDNS)."},
    {"name": "Kernel Integrity Check", "module": "System", "type": "AUTO", "enabled": True, "last": "5m ago", "desc": "Verifies boot sequence and kernel space…"},
    {"name": "SSH Bruteforce Lockout", "module": "System", "type": "AUTO", "enabled": True, "last": "3h ago", "desc": "Blocks IPs with >5 failed login attempts…"},
    {"name": "Manual Port Sweep", "module": "System", "type": "MANUAL", "enabled": False, "last": "Yesterday", "desc": "Initiates comprehensive scan of open ports…"},
    {"name": "Manual Node Blacklist", "module": "System", "type": "MANUAL", "enabled": False, "last": "--", "desc": "Hard-blocks hardware addresses from access…"},
]


def _t():
    return get_card_tokens()


def _vspacer(h=15):
    s = QWidget()
    s.setFixedHeight(h)
    s.setStyleSheet("background: transparent;")
    return s


# ═══════════════════════════════════════════════════════════════════════
# VPN AND DNS CONTROL CARDS (with custom power toggle button)
# ═══════════════════════════════════════════════════════════════════════

class VpnToggleThread(QThread):
    finished_signal = Signal(bool, str) # (success, status)

    def __init__(self, data_bridge, enabled, country=None, reconnect=False):
        super().__init__()
        self.data_bridge = data_bridge
        self.enabled = enabled
        self.country = country
        self.reconnect = reconnect

    def run(self):
        try:
            if self.data_bridge:
                responder = getattr(self.data_bridge, "_wifi_responder", None)
                if responder:
                    if self.reconnect:
                        log.info("VpnToggleThread: Reconnecting to VPN in country %s", self.country)
                        responder.disable_network_protection()
                        time.sleep(1.0)
                        if self.country:
                            responder.set_vpn_country(self.country)
                        responder.manual_enable_vpn()
                    else:
                        if self.enabled:
                            log.info("VpnToggleThread: Enabling VPN")
                            if self.country:
                                responder.set_vpn_country(self.country)
                            responder.manual_enable_vpn()
                        else:
                            log.info("VpnToggleThread: Disabling VPN")
                            responder.disable_network_protection()
                    
                    # Wait a moment to check final status
                    time.sleep(0.5)
                    status = responder.vpn_status
                    success = (status == "connected") if self.enabled else (status == "disconnected")
                    self.finished_signal.emit(success, status)
                    return
            self.finished_signal.emit(False, "disconnected")
        except Exception as exc:
            log.error("VpnToggleThread error: %s", exc)
            self.finished_signal.emit(False, "disconnected")


class DnsToggleThread(QThread):
    finished_signal = Signal(bool, str)  # (success, active_provider)

    def __init__(self, data_bridge, provider_name):
        super().__init__()
        self.data_bridge = data_bridge
        self.provider_name = provider_name

    def run(self):
        try:
            if self.data_bridge:
                if self.provider_name == "System Default":
                    success = self.data_bridge.restore_default_dns()
                else:
                    success = self.data_bridge.switch_dns_provider(self.provider_name)
                
                # Sleep briefly to ensure backend changes take effect
                time.sleep(0.5)
                active_dns = self.data_bridge.get_active_dns_provider()
                self.finished_signal.emit(success, active_dns)
                return
            self.finished_signal.emit(False, "System Default")
        except Exception as exc:
            log.error("DnsToggleThread error: %s", exc)
            self.finished_signal.emit(False, "System Default")


class SentinelComboBox(QComboBox):
    """Custom combobox that overrides native OS styles to overlay a custom text arrow."""
    def __init__(self, parent=None, background=None):
        super().__init__(parent)
        self.setFrame(False)
        t = _t()
        bg = background or t['input_bg']
        
        # Hide the native drop-down arrow
        self.setStyleSheet(f"""
            QComboBox {{
                background-color: {bg};
                color: {t['text_primary']};
                border: 1px solid #232733;
                border-radius: 6px;
                padding-left: 12px;
                padding-right: 28px;
                min-height: 32px;
            }}
            QComboBox:hover {{
                border-color: {t['accent']};
            }}
            QComboBox::drop-down {{
                width: 0px;
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {t.get('card_bg', '#1F2937')};
                color: {t['text_primary']};
                border: 1px solid #232733;
                border-radius: 6px;
                selection-background-color: {t.get('accent_tint', '#064E3B')};
                selection-color: {t['accent']};
                padding: 4px;
            }}
        """)
        
        # Create standard QLabel containing text "▼"
        self.arrow_label = QLabel("▼", self)
        self.arrow_label.setStyleSheet("color: #a0aab4; background: transparent; border: none;")
        self.arrow_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.arrow_label.setFont(QFont("Segoe UI Symbol", 8))
        self.arrow_label.adjustSize()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Position label on the right side
        self.arrow_label.move(self.width() - 20, (self.height() - self.arrow_label.height()) // 2)


class PowerButton(QPushButton):
    """Circular power button (toggle) that turns green when ON, no color when OFF,
    and spins/animates when CONNECTING."""
    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setChecked(checked)
        self.setFixedSize(54, 54)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._is_connecting = False
        self._spin_angle = 0
        
        # 30 FPS timer (approx. 33ms interval)
        self._spin_timer = QTimer(self)
        self._spin_timer.setInterval(33)
        self._spin_timer.timeout.connect(self._rotate_spin)

    def set_connecting(self, connecting: bool):
        self._is_connecting = connecting
        if connecting:
            if not self._spin_timer.isActive():
                self._spin_timer.start()
        else:
            self._spin_timer.stop()
        self.update()

    def is_connecting(self) -> bool:
        return self._is_connecting

    def _rotate_spin(self):
        self._spin_angle = (self._spin_angle + 8) % 360
        self.update()

    def paintEvent(self, event):
        t = _t()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2
        
        # 1. Background
        painter.setPen(Qt.PenStyle.NoPen)
        if self._is_connecting:
            bg_color = QColor(t.get('accent_tint', '#064E3B'))
            painter.setBrush(bg_color)
        elif self.isChecked():
            bg_color = QColor(t['accent'])
            painter.setBrush(bg_color)
        else:
            bg_color = QColor("transparent")
            painter.setBrush(bg_color)
        painter.drawEllipse(0, 0, w, h)
        
        # 2. Border / Spinning Arc
        if self._is_connecting:
            pen = QPen(QColor(t['accent']), 3)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawArc(QRectF(2, 2, w - 4, h - 4), -self._spin_angle * 16, 270 * 16)
        elif not self.isChecked():
            pen = QPen(QColor(t['divider']), 2)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(1, 1, w - 2, h - 2)
            
        # 3. Power Symbol (\u23fb)
        symbol_color = QColor("#FFFFFF") if (self.isChecked() or self._is_connecting) else QColor(t['text_secondary'])
        painter.setPen(symbol_color)
        painter.setFont(QFont("Segoe UI Symbol", 20, QFont.Weight.Bold))
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "\u23fb")
        painter.end()

    def update_style(self):
        self.update()


class VpnCard(GlassFrame):
    """
    Dashboard card for VPN control.
    Includes a title, a circular power toggle button, a status label, and a location selector.
    """
    def __init__(self, parent=None, data_bridge=None):
        super().__init__(parent)
        self.data_bridge = data_bridge
        t = _t()
        
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(8)
        
        # Title
        title_lbl = QLabel("VPN")
        title_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {t['text_muted']};")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(title_lbl)
        
        # Center: Power Button
        self.power_btn = PowerButton(checked=False, parent=self)
        self.power_btn.toggled.connect(self._on_power_toggled)
        lay.addWidget(self.power_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Status Label
        self.status_lbl = QLabel("Disconnected")
        self.status_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self.status_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_lbl.setFixedHeight(18)
        lay.addWidget(self.status_lbl)
        
        # Bottom: Location Selector (dynamically populated)
        self.location_combo = SentinelComboBox(self, background="transparent")
        if self.data_bridge:
            countries = self.data_bridge.get_vpn_countries()
            for country in countries:
                self.location_combo.addItem(country)
            
            # Select the currently active country in DataBridge if set
            current_country = self.data_bridge.get_vpn_country()
            idx = self.location_combo.findText(current_country)
            if idx >= 0:
                self.location_combo.setCurrentIndex(idx)
        else:
            self.location_combo.addItem("Japan")
            self.location_combo.addItem("USA")
            
        self.location_combo.setFont(QFont("Segoe UI", 10))
        self.location_combo.setFixedHeight(32)
        self.location_combo.setFixedWidth(130)
        self.location_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        
        self.location_combo.activated.connect(lambda: self._on_location_changed(self.location_combo.currentText()))
        lay.addWidget(self.location_combo, alignment=Qt.AlignmentFlag.AlignCenter)

    def _on_power_toggled(self, checked: bool):
        p = self.parent()
        while p and not hasattr(p, "_on_vpn_toggle"):
            p = p.parent()
        if p:
            p._on_vpn_toggle(checked)

    def _on_location_changed(self, location: str):
        # Update the active country in data_bridge
        if self.data_bridge:
            self.data_bridge.set_vpn_country(location)

        # If VPN is ON, reconnect
        if self.power_btn.isChecked():
            p = self.parent()
            while p and not hasattr(p, "_on_vpn_reconnect"):
                p = p.parent()
            if p:
                p._on_vpn_reconnect(location)

    def setCheckedSilently(self, checked: bool):
        self.power_btn.blockSignals(True)
        self.power_btn.setChecked(checked)
        self.power_btn.update_style()
        self.power_btn.blockSignals(False)

    def setCountrySilently(self, country: str):
        self.location_combo.blockSignals(True)
        idx = self.location_combo.findText(country)
        if idx >= 0:
            self.location_combo.setCurrentIndex(idx)
        self.location_combo.blockSignals(False)

    def setStatus(self, status: str):
        t = _t()
        if status == "connecting":
            self.status_lbl.setText("Connecting...")
            self.status_lbl.setStyleSheet("color: #F59E0B;") # Amber
            self.power_btn.setEnabled(False)
            self.power_btn.set_connecting(True)
            self.location_combo.setEnabled(False)
        elif status == "disconnecting":
            self.status_lbl.setText("Disconnecting...")
            self.status_lbl.setStyleSheet("color: #EF4444;") # Red-ish
            self.power_btn.setEnabled(False)
            self.power_btn.set_connecting(True)
            self.location_combo.setEnabled(False)
        elif status == "connected":
            self.status_lbl.setText("Connected")
            self.status_lbl.setStyleSheet(f"color: {t['accent']};") # Green
            self.power_btn.setEnabled(True)
            self.power_btn.set_connecting(False)
            self.location_combo.setEnabled(True)
            self.setCheckedSilently(True)
        else: # disconnected
            self.status_lbl.setText("Disconnected")
            self.status_lbl.setStyleSheet(f"color: {t['text_secondary']};")
            self.power_btn.setEnabled(True)
            self.power_btn.set_connecting(False)
            self.location_combo.setEnabled(True)
            self.setCheckedSilently(False)


class DnsCard(GlassFrame):
    """
    Dashboard card for DNS switching control.
    Includes a title, a circular power toggle button, a dummy status label for alignment, and a DNS provider selector.
    """
    def __init__(self, parent=None, data_bridge=None):
        super().__init__(parent)
        self.data_bridge = data_bridge
        t = _t()
        
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(8)
        
        # Title
        title_lbl = QLabel("DNS SWITCHING")
        title_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {t['text_muted']};")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(title_lbl)
        
        # Center: Power Button
        self.power_btn = PowerButton(checked=False, parent=self)
        self.power_btn.toggled.connect(self._on_power_toggled)
        lay.addWidget(self.power_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Dummy Status Label (empty text to align layout with VPN card)
        self.status_lbl = QLabel("")
        self.status_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self.status_lbl.setStyleSheet("background: transparent; border: none;")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_lbl.setFixedHeight(18)
        lay.addWidget(self.status_lbl)
        
        # Bottom: DNS Provider Selector
        self.dns_combo = SentinelComboBox(self, background="transparent")
        self.dns_combo.setFont(QFont("Segoe UI", 10))
        self.dns_combo.setFixedHeight(32)
        self.dns_combo.setFixedWidth(170)
        self.dns_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        
        lay.addWidget(self.dns_combo, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Populate combobox
        self.dns_combo.addItem("System Default")
        providers = getattr(config, "ENCRYPTED_DNS_PROVIDERS", {})
        for name in providers:
            self.dns_combo.addItem(name)
            
        self.dns_combo.currentTextChanged.connect(self._on_dns_combo_changed)

    def set_loading(self, loading: bool):
        self.power_btn.setEnabled(not loading)
        self.power_btn.set_connecting(loading)
        self.dns_combo.setEnabled(not loading)

    def _on_power_toggled(self, checked: bool):
        if checked:
            if self.dns_combo.currentText() == "System Default":
                providers = getattr(config, "ENCRYPTED_DNS_PROVIDERS", {})
                first_provider = list(providers.keys())[0] if providers else "Cloudflare"
                self.dns_combo.setCurrentText(first_provider)
        else:
            self.dns_combo.setCurrentText("System Default")

    def _on_dns_combo_changed(self, provider_name: str):
        is_on = provider_name != "System Default"
        self.power_btn.blockSignals(True)
        self.power_btn.setChecked(is_on)
        self.power_btn.update_style()
        self.power_btn.blockSignals(False)
        
        p = self.parent()
        while p and not hasattr(p, "_on_dns_changed"):
            p = p.parent()
        if p:
            p._on_dns_changed(provider_name)

    def setProviderSilently(self, provider_name: str):
        self.dns_combo.blockSignals(True)
        self.dns_combo.setCurrentText(provider_name)
        self.dns_combo.blockSignals(False)
        
        is_on = provider_name != "System Default"
        self.power_btn.blockSignals(True)
        self.power_btn.setChecked(is_on)
        self.power_btn.update_style()
        self.power_btn.blockSignals(False)


# ═══════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD  (live data from DataBridge)
# ═══════════════════════════════════════════════════════════════════════

class DashboardPage(QWidget):
    def __init__(self, parent, data_bridge):
        super().__init__(parent)
        self.data_bridge = data_bridge
        
        # VPN Async Thread & Timeout Timer
        self._vpn_thread = None
        self._vpn_timeout_timer = QTimer(self)
        self._vpn_timeout_timer.setSingleShot(True)
        self._vpn_timeout_timer.timeout.connect(self._on_vpn_timeout)
        
        # DNS Async Thread
        self._dns_thread = None
        
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Header ──
        h = QWidget()
        hl = QVBoxLayout(h)
        hl.setContentsMargins(0, 0, 0, 25)
        title = QLabel("Hi, Admin!")
        title.setFont(QFont("Segoe UI", 26, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {t['text_primary']};")
        hl.addWidget(title)
        sub = QLabel("Welcome back to your security overview. "
                     "Here is the current status of your network.")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet(f"color: {t['text_secondary']};")
        hl.addWidget(sub)
        lay.addWidget(h)

        # ── Row 1: stat cards ──
        r1 = QWidget()
        r1g = QGridLayout(r1)
        r1g.setContentsMargins(0, 0, 0, 15)
        r1g.setSpacing(12)

        self.score_card = StatCard(r1, "Overall Threat Score", "--",
                                  "Waiting for data…", top_icon="🎯")
        self.threats_card = StatCard(r1, "Active Threats", "--",
                        "No threats detected",
                                    value_color=t["danger"], top_icon="⚠️")
        self.vpn_card = VpnCard(r1, self.data_bridge)
        self.dns_card = DnsCard(r1, self.data_bridge)
        r1g.addWidget(self.score_card, 0, 0)
        r1g.addWidget(self.threats_card, 0, 1)
        r1g.addWidget(self.vpn_card, 0, 2)
        r1g.addWidget(self.dns_card, 0, 3)
        for c in range(4):
            r1g.setColumnStretch(c, 1)
        lay.addWidget(r1)

        # ── Row 2: Module scores + Actions ──
        r2 = QWidget()
        r2g = QGridLayout(r2)
        r2g.setContentsMargins(0, 0, 0, 15)
        r2g.setSpacing(12)
        r2g.setColumnStretch(0, 3)
        r2g.setColumnStretch(1, 2)

        m_card = GlassFrame(r2)
        m_lay = QVBoxLayout(m_card)
        m_lay.setContentsMargins(0, 0, 0, 0)
        m_lay.setSpacing(0)
        m_lay.addWidget(section_header(m_card, "Module Threat Scores"))
        self.wifi_bar = ProgressRow(m_card, "WiFi", "0%", t["accent"], 0)
        self.web_bar = ProgressRow(m_card, "Web", "0%", t["danger"], 0)
        self.behav_bar = ProgressRow(m_card, "Behaviour Analysis", "0%",
                                    t["warning"], 0)
        m_lay.addWidget(self.wifi_bar)
        m_lay.addWidget(self.web_bar)
        m_lay.addWidget(self.behav_bar)
        m_lay.addWidget(_vspacer(15))
        r2g.addWidget(m_card, 0, 0)

        ra_card = GlassFrame(r2)
        ra_lay = QVBoxLayout(ra_card)
        ra_lay.setContentsMargins(0, 0, 0, 0)
        ra_lay.setSpacing(0)
        ra_lay.addWidget(section_header(ra_card, "Recommended Actions"))
        # Dynamic recommended actions container (populated in refresh)
        self._recommended_widget = QWidget(ra_card)
        self._recommended_layout = QVBoxLayout(self._recommended_widget)
        self._recommended_layout.setContentsMargins(0, 0, 0, 0)
        self._recommended_layout.setSpacing(8)
        # initial placeholder
        self._no_recs_lbl = QLabel("✅ No recommended actions required.")
        self._no_recs_lbl.setFont(QFont("Segoe UI", 11))
        self._no_recs_lbl.setStyleSheet(f"color: {t['accent']};")
        self._recommended_layout.addWidget(self._no_recs_lbl)
        ra_lay.addWidget(self._recommended_widget)
        ra_lay.addWidget(_vspacer(8))
        r2g.addWidget(ra_card, 0, 1)
        lay.addWidget(r2)

        # ── Row 3: Active Threats ──
        self.threats_table_frame = GlassFrame(self)
        self.threats_table_lay = QVBoxLayout(self.threats_table_frame)
        self.threats_table_lay.setContentsMargins(0, 0, 0, 0)
        self.threats_table_lay.setSpacing(0)
        self.threats_table_lay.addWidget(section_header(self.threats_table_frame, "Active Threats"))
        self.threats_table_lay.addWidget(table_header(self.threats_table_frame, [
            (150, "Module"),
            (710, "Threat Description"),
            (120, "Severity")
        ]))
        
        # Row container
        self._threats_rows_widget = QWidget(self.threats_table_frame)
        self._threats_rows_lay = QVBoxLayout(self._threats_rows_widget)
        self._threats_rows_lay.setContentsMargins(0, 0, 0, 0)
        self._threats_rows_lay.setSpacing(0)
        self.threats_table_lay.addWidget(self._threats_rows_widget)
        
        # Empty placeholder label when no threats
        self._no_threats_lbl = QLabel("✅ No active threats detected.")
        self._no_threats_lbl.setFont(QFont("Segoe UI", 11))
        self._no_threats_lbl.setStyleSheet(f"color: {t['accent']};")
        self._no_threats_lbl.setContentsMargins(22, 14, 22, 14)
        self._threats_rows_lay.addWidget(self._no_threats_lbl)
        
        self.threats_table_lay.addWidget(_vspacer(10))
        lay.addWidget(self.threats_table_frame)
        lay.addStretch()

    # ── VPN toggle handler ──

    def _on_vpn_toggle(self, checked: bool):
        """Called when the user clicks the VPN toggle switch."""
        if self._vpn_thread and self._vpn_thread.isRunning():
            log.warning("Vpn toggle requested but thread is already running")
            return

        # Start connecting/disconnecting visual transitions
        if checked:
            self.vpn_card.setStatus("connecting")
            if self.data_bridge and self.data_bridge._wifi_responder:
                self.data_bridge._wifi_responder.vpn_status = "connecting"
            # Start 12s timeout guard for connection phase
            self._vpn_timeout_timer.start(12000)
        else:
            self.vpn_card.setStatus("disconnecting")
            if self.data_bridge and self.data_bridge._wifi_responder:
                self.data_bridge._wifi_responder.vpn_status = "disconnecting"
            # Start 5s timeout guard for disconnection phase
            self._vpn_timeout_timer.start(5000)

        # Start asynchronous connection / disconnection via QThread
        self._vpn_thread = VpnToggleThread(self.data_bridge, checked)
        self._vpn_thread.finished_signal.connect(self._on_vpn_finished)
        self._vpn_thread.start()

    def _on_vpn_reconnect(self, location: str):
        """Called when the user changes country while VPN is ON."""
        if self._vpn_thread and self._vpn_thread.isRunning():
            log.warning("Vpn reconnect requested but thread is already running")
            return

        # Start connecting transition
        self.vpn_card.setStatus("connecting")
        if self.data_bridge and self.data_bridge._wifi_responder:
            self.data_bridge._wifi_responder.vpn_status = "connecting"

        # Start 12s timeout guard
        self._vpn_timeout_timer.start(12000)

        # Start asynchronous reconnection via QThread
        self._vpn_thread = VpnToggleThread(self.data_bridge, enabled=True, country=location, reconnect=True)
        self._vpn_thread.finished_signal.connect(self._on_vpn_finished)
        self._vpn_thread.start()

    @Slot(bool, str)
    def _on_vpn_finished(self, success: bool, status: str):
        """Called when the VpnToggleThread finishes execution."""
        self._vpn_timeout_timer.stop()
        log.info("VPN toggle task finished — success=%s, status=%s", success, status)
        
        # Ensure final state is set on the responder
        if self.data_bridge and self.data_bridge._wifi_responder:
            self.data_bridge._wifi_responder.vpn_status = status
            
        self.vpn_card.setStatus(status)

    def _on_vpn_timeout(self):
        """Called when the VPN connection phase exceeds the safety timeout."""
        log.error("VPN toggle action TIMED OUT! Forcing UI state reset.")
        
        # Clean up the thread if running
        if self._vpn_thread and self._vpn_thread.isRunning():
            try:
                self._vpn_thread.terminate()
                self._vpn_thread.wait(2000) # brief wait
            except Exception as exc:
                log.warning("Failed to terminate VPN thread on timeout: %s", exc)

        # Re-sync final status from the backend if possible, else default to disconnected
        status = "disconnected"
        if self.data_bridge and self.data_bridge._wifi_responder:
            # Force status check
            self.data_bridge._wifi_responder.vpn_status = "disconnected"
            status = self.data_bridge._wifi_responder.vpn_status
            
        self.vpn_card.setStatus(status)
        
        QMessageBox.warning(self, "VPN Connection Timeout", 
                            "VPN connection attempt timed out. "
                            "Please check your OpenVPN client config or system connection.")

    # ── DNS dropdown handler ──

    def _on_dns_changed(self, provider_name: str):
        """Called when the user selects a DNS provider from the dropdown."""
        if not self.data_bridge:
            return
        if self._dns_thread and self._dns_thread.isRunning():
            log.warning("Dns switch requested but thread is already running")
            return

        self.dns_card.set_loading(True)

        self._dns_thread = DnsToggleThread(self.data_bridge, provider_name)
        self._dns_thread.finished_signal.connect(self._on_dns_finished)
        self._dns_thread.start()

    @Slot(bool, str)
    def _on_dns_finished(self, success: bool, provider_name: str):
        """Called when the DnsToggleThread finishes execution."""
        log.info("DNS switch task finished — success=%s, active=%s", success, provider_name)
        self.dns_card.set_loading(False)
        self.dns_card.setProviderSilently(provider_name)

    # ── Live data refresh (called by App.on_refresh) ──

    def refresh(self, score):
        """Update dashboard widgets with latest ThreatScore."""
        if score is None:
            return
        tier_info = TIER_COLORS.get(score.tier, TIER_COLORS["Safe"])

        self.score_card.update_value(int(score.unified_score), tier_info["fg"])
        self.score_card.update_subtext(score.tier, tier_info["fg"])

        n = len(score.active_threats)
        self.threats_card.update_value(n, _t()["danger"] if n else _t()["accent"])
        self.threats_card.update_subtext(
            f"{n} threat{'s' if n != 1 else ''} detected" if n else "No threats detected",
            _t()["danger"] if n else _t()["accent"])

        # ── Sync VPN toggle and country with backend state ──
        try:
            if self.data_bridge:
                # Only sync card status from backend if the async thread is not running
                if not (self._vpn_thread and self._vpn_thread.isRunning()):
                    vpn_status = self.data_bridge.get_vpn_status()
                    self.vpn_card.setStatus(vpn_status)
                vpn_country = self.data_bridge.get_vpn_country()
                self.vpn_card.setCountrySilently(vpn_country)
        except Exception:
            pass

        # ── Sync DNS dropdown with backend state ──
        try:
            if self.data_bridge:
                if not (self._dns_thread and self._dns_thread.isRunning()):
                    active_dns = self.data_bridge.get_active_dns_provider()
                    self.dns_card.setProviderSilently(active_dns)
        except Exception:
            pass

        # ── Live module reports (used for mini-stats and recommended actions)
        reports = {}
        try:
            reports = self.data_bridge.get_reports() if getattr(self, "data_bridge", None) else {}
        except Exception:
            reports = {}

        web_report = reports.get("web_report")
        behavioral_report = reports.get("behavioral_report")
        wifi_report = reports.get("wifi_report")

        # ── Recommended actions (fed from HardeningAdvisor)
        try:
            # clear previous items
            while self._recommended_layout.count():
                item = self._recommended_layout.takeAt(0)
                w = item.widget()
                if w is not None:
                    w.deleteLater()

            from modules.hardening import HardeningAdvisor
            advisor = HardeningAdvisor()
            hardening_recs = advisor.analyze(
                wifi_report=wifi_report,
                behavioral_report=behavioral_report,
                web_report=web_report,
                threat_score=score
            )
            # Sort by priority
            hardening_recs = advisor.get_priority_actions(hardening_recs)

            if not hardening_recs:
                self._recommended_layout.addWidget(self._no_recs_lbl)
            else:
                cat_icons = {
                    "WIFI": "📶",
                    "PROCESSES": "⚙️",
                    "BROWSER": "🌐",
                    "SYSTEM": "🖥️"
                }
                for rec in hardening_recs:
                    icon = cat_icons.get(rec.category.upper(), "🛡️")
                    title = rec.title
                    sub = rec.description
                    tag = rec.priority  # E.g., IMMEDIATE, HIGH, MEDIUM, LOW
                    self._recommended_layout.addWidget(ActionCard(self._recommended_widget, icon, title, sub, tag))
        except Exception as exc:
            log.error("Failed to generate recommendations: %s", exc)
            try:
                self._recommended_layout.addWidget(self._no_recs_lbl)
            except Exception:
                pass

        # ── Active threats table ──
        try:
            # Clear previous items
            while self._threats_rows_lay.count():
                item = self._threats_rows_lay.takeAt(0)
                w = item.widget()
                if w is not None:
                    w.deleteLater()

            active_threats = getattr(score, "active_threats", [])
            if not active_threats:
                self._threats_rows_lay.addWidget(self._no_threats_lbl)
            else:
                for threat in active_threats:
                    threat_str = str(threat)
                    
                    # Determine Module
                    if "anomalous process" in threat_str.lower() or "behavior" in threat_str.lower():
                        module = "Behaviour"
                        report_severity = getattr(behavioral_report, "severity", "WARNING") if behavioral_report else "WARNING"
                    elif "tracker" in threat_str.lower() or "fingerprint" in threat_str.lower():
                        module = "Web"
                        report_severity = getattr(web_report, "severity", "WARNING") if web_report else "WARNING"
                    else:
                        module = "WiFi"
                        report_severity = getattr(wifi_report, "severity", "WARNING") if wifi_report else "WARNING"

                    # Determine Severity
                    if "evil-twin" in threat_str.lower() or "critical" in threat_str.lower() or "unauthorized" in threat_str.lower():
                        severity = "CRITICAL"
                    else:
                        # Use the report severity or map it
                        severity = report_severity.upper()
                        if severity not in ("CRITICAL", "HIGH", "WARNING", "INFO"):
                            severity = "WARNING"
                    
                    self._threats_rows_lay.addWidget(table_row(
                        self.threats_table_frame,
                        [
                            (150, module, "bold"),
                            (710, threat_str),
                            (120, severity, "pill")
                        ]
                    ))
        except Exception as exc:
            log.error("Failed to populate active threats: %s", exc)

        # Module bars
        def bar_color(v):
            if v < 40:
                return _t()["accent"]
            elif v < 70:
                return _t()["warning"]
            else:
                return _t()["danger"]

        self.wifi_bar.update_value(score.wifi_score, bar_color(score.wifi_score))
        self.web_bar.update_value(score.web_score, bar_color(score.web_score))
        self.behav_bar.update_value(score.behavioral_score,
                                   bar_color(score.behavioral_score))


# ═══════════════════════════════════════════════════════════════════════
# PAGE: WIFI SECURITY  (live data from WiFiReport)
# ═══════════════════════════════════════════════════════════════════════

class WiFiSecurityPage(QWidget):
    def __init__(self, parent=None, data_bridge=None):
        super().__init__(parent)
        self.data_bridge = data_bridge
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Title row ──
        tr = QWidget()
        trl = QHBoxLayout(tr)
        trl.setContentsMargins(0, 0, 0, 20)
        t_left = QVBoxLayout()
        title = QLabel("WiFi Security")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {t['text_primary']};")
        t_left.addWidget(title)
        sub = QLabel("Network threat analysis")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet(f"color: {t['text_secondary']};")
        t_left.addWidget(sub)
        trl.addLayout(t_left)
        trl.addStretch()
        self._tier_pill = QLabel("● -- — Scanning…")
        self._tier_pill.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._tier_pill.setStyleSheet("background-color: #F3F4F6; color: #374151;"
                                     " border-radius: 14px; padding: 6px 16px;")
        trl.addWidget(self._tier_pill)
        lay.addWidget(tr)

        # ── Stats row ──
        r1 = QWidget()
        r1g = QGridLayout(r1)
        r1g.setContentsMargins(0, 0, 0, 15)
        r1g.setSpacing(12)

        # Connected network card
        cn = GlassFrame(r1)
        cn_lay = QVBoxLayout(cn)
        cn_lay.setContentsMargins(22, 22, 22, 22)
        cn_lay.setSpacing(4)
        ct = QHBoxLayout()
        ctl = QLabel("CONNECTED NETWORK")
        ctl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        ctl.setStyleSheet(f"color: {t['text_muted']};")
        ct.addWidget(ctl)
        ct.addStretch()
        ct.addWidget(QLabel("📶"))
        cn_lay.addLayout(ct)
        self._ssid_lbl = QLabel("Scanning…")
        self._ssid_lbl.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self._ssid_lbl.setStyleSheet(f"color: {t['text_primary']};")
        cn_lay.addWidget(self._ssid_lbl)
        self._enc_lbl = QLabel("--")
        self._enc_lbl.setFont(QFont("Consolas", 10))
        self._enc_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        cn_lay.addWidget(self._enc_lbl)
        cn_btm = QHBoxLayout()
        self._sec_pill = PillLabel("SCANNING", "UNKNOWN")
        cn_btm.addWidget(self._sec_pill)
        cn_btm.addStretch()
        self._signal_lbl = QLabel("Signal: --")
        self._signal_lbl.setFont(QFont("Segoe UI", 10))
        self._signal_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        cn_btm.addWidget(self._signal_lbl)
        cn_lay.addLayout(cn_btm)
        r1g.addWidget(cn, 0, 0)

        # Gauge card
        ns = GlassFrame(r1)
        ns_lay = QVBoxLayout(ns)
        ns_lay.setContentsMargins(22, 22, 22, 22)
        ns_lay.setSpacing(4)
        ns_t = QLabel("NETWORK THREAT SCORE")
        ns_t.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        ns_t.setStyleSheet(f"color: {t['text_muted']};")
        ns_lay.addWidget(ns_t)
        self._gauge = CircularGauge(ns, size=140, score=0, color="#10B981")
        ns_lay.addWidget(self._gauge, alignment=Qt.AlignmentFlag.AlignCenter)
        self._gauge_status = QLabel("STATUS: WAITING")
        self._gauge_status.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._gauge_status.setStyleSheet(f"color: {t['text_muted']};")
        self._gauge_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ns_lay.addWidget(self._gauge_status)
        r1g.addWidget(ns, 0, 1)

        # Anomalies card
        self._anomaly_card = StatCard(r1, "Anomalies Detected", "–",
                                      "Waiting for scan…",
                                      value_color=t["text_muted"], top_icon="⏳")
        r1g.addWidget(self._anomaly_card, 0, 2)
        for c in range(3):
            r1g.setColumnStretch(c, 1)
        lay.addWidget(r1)

        # ── Middle Row: Nearby Networks (Left) & Info/Threats (Right) ──
        r2 = QWidget()
        r2_lay = QHBoxLayout(r2)
        r2_lay.setContentsMargins(0, 0, 0, 15)
        r2_lay.setSpacing(12)

        # Left side: Nearby Networks
        self._net_card = GlassFrame(r2)
        self._net_layout = QVBoxLayout(self._net_card)
        self._net_layout.setContentsMargins(0, 0, 0, 0)
        self._net_layout.setSpacing(0)
        self._net_layout.addWidget(section_header(self._net_card, "Nearby Networks"))
        self._net_header = table_header(self._net_card,
                                        [(200, "SSID"), (120, "Signal (dBm)"),
                                         (140, "Security"), (140, "Status")])
        self._net_layout.addWidget(self._net_header)
        self._net_rows: list[QWidget] = []
        placeholder = QLabel("    Waiting for first scan…")
        placeholder.setFont(QFont("Segoe UI", 11))
        placeholder.setStyleSheet(f"color: {t['text_muted']};")
        placeholder.setContentsMargins(22, 15, 22, 15)
        self._net_rows.append(placeholder)
        self._net_layout.addWidget(placeholder)
        self._net_spacer = _vspacer(10)
        self._net_layout.addWidget(self._net_spacer)
        r2_lay.addWidget(self._net_card, 3)

        # Right side: Vertical Stack for DNS Leak and Detected Threats
        right_lay = QVBoxLayout()
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(12)

        leak = GlassFrame(r2)
        leak_lay = QVBoxLayout(leak)
        leak_lay.setContentsMargins(22, 22, 22, 30)
        leak_lay.setSpacing(5)
        lt = QHBoxLayout()
        lt_t = QLabel("DNS Leak Test")
        lt_t.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lt_t.setStyleSheet(f"color: {t['text_primary']};")
        lt.addWidget(lt_t)
        lt.addStretch()
        lt.addWidget(outline_button("RUN TEST"))
        leak_lay.addLayout(lt)
        leak_icon = QLabel("✅")
        leak_icon.setFont(QFont("Segoe UI", 32))
        leak_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        leak_lay.addWidget(leak_icon)
        leak_title = QLabel("No leaks detected")
        leak_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        leak_title.setStyleSheet(f"color: {t['text_primary']};")
        leak_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        leak_lay.addWidget(leak_title)
        leak_sub = QLabel("Your DNS requests are properly routed through\n"
                          "your secure gateway.")
        leak_sub.setFont(QFont("Segoe UI", 11))
        leak_sub.setStyleSheet(f"color: {t['text_secondary']};")
        leak_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        leak_lay.addWidget(leak_sub)
        right_lay.addWidget(leak)

        # Detected threats card (dynamic)
        self._threats_frame = GlassFrame(r2)
        tc_lay = QVBoxLayout(self._threats_frame)
        tc_lay.setContentsMargins(0, 0, 0, 0)
        tc_lay.setSpacing(0)
        tc_lay.addWidget(section_header(self._threats_frame, "Detected Threats"))
        self._threats_container = QVBoxLayout()
        self._threats_container.setContentsMargins(22, 0, 22, 15)
        self._threats_container.setSpacing(4)
        no_threat = QLabel("✅  No threats detected yet.")
        no_threat.setFont(QFont("Segoe UI", 11))
        no_threat.setStyleSheet(f"color: {t['accent']};")
        self._threats_container.addWidget(no_threat)
        self._threat_widgets: list[QWidget] = [no_threat]
        tc_lay.addLayout(self._threats_container)
        right_lay.addWidget(self._threats_frame)
        right_lay.addStretch()

        r2_lay.addLayout(right_lay, 2)
        lay.addWidget(r2)
        lay.addStretch()

    def refresh(self, score, wifi_report):
        """Update all WiFi page widgets from real WiFiReport data."""
        # Hide dynamic sections when no report available
        if wifi_report is None:
            try:
                self._net_card.setVisible(False)
            except Exception:
                pass
            try:
                self._gauge.setVisible(False)
            except Exception:
                pass
            try:
                self._threats_frame.setVisible(False)
            except Exception:
                pass
            return
        else:
            # Ensure dynamic sections are visible
            try:
                self._net_card.setVisible(True)
            except Exception:
                pass
            try:
                self._gauge.setVisible(True)
            except Exception:
                pass
            try:
                self._threats_frame.setVisible(True)
            except Exception:
                pass
        t = _t()

        def _rget(key, default=None):
            if isinstance(wifi_report, dict):
                return wifi_report.get(key, default)
            return getattr(wifi_report, key, default)

        # ── Tier pill ──
        wifi_score = score.wifi_score if score else 0
        tier_text = score.tier if score else "Safe"
        tier_info = TIER_COLORS.get(tier_text, TIER_COLORS["Safe"])
        self._tier_pill.setText(f"● {int(wifi_score)} — {tier_text}")
        self._tier_pill.setStyleSheet(
            f"background-color: {tier_info['bg_tint']};"
            f" color: {tier_info['text']};"
            " border-radius: 14px; padding: 6px 16px;")

        # ── Connected network ──
        ssid = _rget("connected_ssid", "Unknown")
        enc = _rget("encryption", "UNKNOWN")
        signal = _rget("signal_dbm", -100)
        self._ssid_lbl.setText(ssid if ssid else "No Connection")
        self._enc_lbl.setText(f"{enc} Protocol")
        if enc in ("WPA3", "WPA2"):
            self._sec_pill.setText("🟢 SECURE")
            self._sec_pill.setStyleSheet(
                "QLabel { background-color: #D1FAE5; color: #065F46;"
                " border-radius: 6px; padding: 3px 10px; }")
        elif enc == "OPEN":
            self._sec_pill.setText("🔴 OPEN")
            self._sec_pill.setStyleSheet(
                "QLabel { background-color: #FEE2E2; color: #991B1B;"
                " border-radius: 6px; padding: 3px 10px; }")
        else:
            self._sec_pill.setText(f"🟡 {enc}")
            self._sec_pill.setStyleSheet(
                "QLabel { background-color: #FEF3C7; color: #92400E;"
                " border-radius: 6px; padding: 3px 10px; }")
        self._signal_lbl.setText(f"Signal: {signal} dBm")

        # ── Gauge ──
        gauge_color = (t["accent"] if wifi_score < 40
                       else t["warning"] if wifi_score < 70
                       else t["danger"])
        self._gauge.set_score(wifi_score, gauge_color)
        sev = _rget("severity", "LOW")
        status_map = {"LOW": "OPTIMAL", "MEDIUM": "CAUTION",
                      "HIGH": "WARNING", "CRITICAL": "CRITICAL"}
        color_map = {"LOW": t["accent"], "MEDIUM": t["warning"],
                     "HIGH": t["danger"], "CRITICAL": t["danger"]}
        self._gauge_status.setText(f"STATUS: {status_map.get(sev, 'OPTIMAL')}")
        self._gauge_status.setStyleSheet(
            f"color: {color_map.get(sev, t['accent'])};")

        # ── Anomalies ──
        threats = _rget("threats_detected", [])
        n = len(threats)
        if n == 0:
            self._anomaly_card.update_value("0", t["accent"])
            self._anomaly_card.update_subtext("No anomalies detected.", t["accent"])
        else:
            self._anomaly_card.update_value(str(n), t["danger"])
            self._anomaly_card.update_subtext(
                f"{n} issue{'s' if n != 1 else ''} found", t["danger"])

        # ── Nearby networks ──
        networks = _rget("nearby_networks", [])
        for w in self._net_rows:
            self._net_layout.removeWidget(w)
            w.deleteLater()
        self._net_rows.clear()
        if networks:
            from modules.wifi_analysis import WiFiAnalyzer
            insert_idx = self._net_layout.indexOf(self._net_spacer)
            for net in networks:
                ssid_n = net.get("ssid", "") or "(hidden)"
                sig_n = net.get("signal_dbm", -100)
                enc_n = WiFiAnalyzer.evaluate_encryption(net)
                status = ("SUSPICIOUS" if enc_n == "OPEN"
                          else "SAFE" if enc_n in ("WPA3", "WPA2")
                          else "UNKNOWN")
                row = table_row(self._net_card,
                                [(200, ssid_n, "bold"),
                                 (120, f"{sig_n} dBm"),
                                 (140, enc_n),
                                 (140, status, "pill")])
                self._net_rows.append(row)
                self._net_layout.insertWidget(insert_idx, row)
                insert_idx += 1

        # ── Threats list ──
        for w in self._threat_widgets:
            self._threats_container.removeWidget(w)
            w.deleteLater()
        self._threat_widgets.clear()
        if threats:
            for threat_str in threats:
                lbl = QLabel(f"⚠️  {threat_str}")
                lbl.setFont(QFont("Segoe UI", 11))
                lbl.setStyleSheet(f"color: {t['danger']};")
                lbl.setWordWrap(True)
                self._threats_container.addWidget(lbl)
                self._threat_widgets.append(lbl)
        else:
            ok = QLabel("✅  No threats detected. Network is clean.")
            ok.setFont(QFont("Segoe UI", 11))
            ok.setStyleSheet(f"color: {t['accent']};")
            self._threats_container.addWidget(ok)
            self._threat_widgets.append(ok)


# ═══════════════════════════════════════════════════════════════════════
# PAGE: BEHAVIOUR ANALYSIS
# ═══════════════════════════════════════════════════════════════════════

class BehaviourAnalysisPage(QWidget):
    def __init__(self, parent=None, data_bridge=None):
        super().__init__(parent)
        self.data_bridge = data_bridge
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Title ──
        tr = QWidget()
        trl = QHBoxLayout(tr)
        trl.setContentsMargins(0, 0, 0, 20)
        t_left = QVBoxLayout()
        title = QLabel("Behaviour Analysis")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {t['text_primary']};")
        t_left.addWidget(title)
        sub = QLabel("Process & application monitoring across the entire network node")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet(f"color: {t['text_secondary']};")
        t_left.addWidget(sub)
        trl.addLayout(t_left)
        trl.addStretch()
        self._tier_pill = QLabel("● -- — Scanning…")
        self._tier_pill.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._tier_pill.setStyleSheet("background-color: #F3F4F6; color: #374151;"
                                     " border-radius: 14px; padding: 6px 16px;")
        trl.addWidget(self._tier_pill)
        lay.addWidget(tr)

        # ── Stats row ──
        r1 = QWidget()
        r1g = QGridLayout(r1)
        r1g.setContentsMargins(0, 0, 0, 15)
        r1g.setSpacing(12)

        # Behaviour Score card
        self._score_card = StatCard(r1, "Behaviour Score", "--",
                                    "Waiting for data…",
                                    value_color=t["text_muted"], top_icon="🎯")
        r1g.addWidget(self._score_card, 0, 0)

        # Suspicious processes card
        sp = GlassFrame(r1)
        sp_lay = QVBoxLayout(sp)
        sp_lay.setContentsMargins(22, 22, 22, 22)
        sp_lay.setSpacing(4)
        spt = QHBoxLayout()
        sptl = QLabel("SUSPICIOUS PROCESSES")
        sptl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        sptl.setStyleSheet(f"color: {t['text_muted']};")
        spt.addWidget(sptl)
        spt.addStretch()
        spt.addWidget(QLabel("⚠️"))
        sp_lay.addLayout(spt)
        self._susp_count_lbl = QLabel("-- flagged")
        self._susp_count_lbl.setFont(QFont("Segoe UI", 32, QFont.Weight.Bold))
        self._susp_count_lbl.setStyleSheet(f"color: {t['text_muted']};")
        sp_lay.addWidget(self._susp_count_lbl)
        r1g.addWidget(sp, 0, 1)

        # Anomalies detected card
        self._anomaly_card = StatCard(r1, "Anomalies Detected", "--",
                                      "Waiting for data…",
                                      value_color=t["text_muted"], top_icon="⚡")
        r1g.addWidget(self._anomaly_card, 0, 2)
        for c in range(3):
            r1g.setColumnStretch(c, 1)
        lay.addWidget(r1)

        # ── System resources row ──
        r1b = QWidget()
        r1bg = QGridLayout(r1b)
        r1bg.setContentsMargins(0, 0, 0, 15)
        r1bg.setSpacing(12)

        # CPU gauge card
        cpu_card = GlassFrame(r1b)
        cpu_lay = QVBoxLayout(cpu_card)
        cpu_lay.setContentsMargins(22, 22, 22, 22)
        cpu_lay.setSpacing(4)
        cpu_t = QLabel("CPU USAGE")
        cpu_t.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        cpu_t.setStyleSheet(f"color: {t['text_muted']};")
        cpu_lay.addWidget(cpu_t)
        self._cpu_gauge = CircularGauge(cpu_card, size=120, score=0,
                                        color=t["accent"])
        cpu_lay.addWidget(self._cpu_gauge,
                          alignment=Qt.AlignmentFlag.AlignCenter)
        self._cpu_status = QLabel("--")
        self._cpu_status.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._cpu_status.setStyleSheet(f"color: {t['text_muted']};")
        self._cpu_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cpu_lay.addWidget(self._cpu_status)
        r1bg.addWidget(cpu_card, 0, 0)

        # Memory gauge card
        mem_card = GlassFrame(r1b)
        mem_lay = QVBoxLayout(mem_card)
        mem_lay.setContentsMargins(22, 22, 22, 22)
        mem_lay.setSpacing(4)
        mem_t = QLabel("MEMORY USAGE")
        mem_t.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        mem_t.setStyleSheet(f"color: {t['text_muted']};")
        mem_lay.addWidget(mem_t)
        self._mem_gauge = CircularGauge(mem_card, size=120, score=0,
                                        color=t["accent"])
        mem_lay.addWidget(self._mem_gauge,
                          alignment=Qt.AlignmentFlag.AlignCenter)
        self._mem_status = QLabel("--")
        self._mem_status.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._mem_status.setStyleSheet(f"color: {t['text_muted']};")
        self._mem_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mem_lay.addWidget(self._mem_status)
        r1bg.addWidget(mem_card, 0, 1)

        # Baseline status card
        bl_card = GlassFrame(r1b)
        bl_lay = QVBoxLayout(bl_card)
        bl_lay.setContentsMargins(22, 22, 22, 22)
        bl_lay.setSpacing(4)
        blt = QHBoxLayout()
        bltl = QLabel("BASELINE STATUS")
        bltl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        bltl.setStyleSheet(f"color: {t['text_muted']};")
        blt.addWidget(bltl)
        blt.addStretch()
        self._baseline_pill = PillLabel("LEARNING", "WARNING")
        blt.addWidget(self._baseline_pill)
        bl_lay.addLayout(blt)
        self._baseline_status = QLabel("Collecting data…")
        self._baseline_status.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._baseline_status.setStyleSheet(f"color: {t['text_primary']};")
        bl_lay.addWidget(self._baseline_status)
        self._baseline_detail = QLabel("Baseline will be established after the learning period")
        self._baseline_detail.setFont(QFont("Segoe UI", 10))
        self._baseline_detail.setStyleSheet(f"color: {t['text_secondary']};")
        self._baseline_detail.setWordWrap(True)
        bl_lay.addWidget(self._baseline_detail)
        r1bg.addWidget(bl_card, 0, 2)
        for c in range(3):
            r1bg.setColumnStretch(c, 1)
        lay.addWidget(r1b)

        # ── Flagged processes table + Anomalies list ──
        r2 = QWidget()
        r2g = QGridLayout(r2)
        r2g.setContentsMargins(0, 0, 0, 15)
        r2g.setSpacing(12)
        r2g.setColumnStretch(0, 3)
        r2g.setColumnStretch(1, 2)

        # Flagged Processes table (dynamic)
        self._fp_frame = GlassFrame(r2)
        fp_lay = QVBoxLayout(self._fp_frame)
        fp_lay.setContentsMargins(0, 0, 0, 0)
        fp_lay.setSpacing(0)
        fph = QWidget(self._fp_frame)
        fphl = QHBoxLayout(fph)
        fphl.setContentsMargins(22, 22, 22, 12)
        fpt = QLabel("Flagged Processes")
        fpt.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        fpt.setStyleSheet(f"color: {t['text_primary']};")
        fphl.addWidget(fpt)
        fphl.addStretch()
        fprl = QLabel("Real-time update")
        fprl.setFont(QFont("Segoe UI", 9))
        fprl.setStyleSheet(f"color: {t['text_muted']};")
        fphl.addWidget(fprl)
        fp_lay.addWidget(fph)
        self._fp_header = table_header(self._fp_frame, [(180, "Process Name"), (80, "CPU%"),
                            (80, "Memory"), (80, "Risk")])
        fp_lay.addWidget(self._fp_header)
        self._fp_container = fp_lay
        self._fp_rows: list[QWidget] = []
        placeholder = QLabel("    Waiting for first scan…")
        placeholder.setFont(QFont("Segoe UI", 11))
        placeholder.setStyleSheet(f"color: {t['text_muted']};")
        placeholder.setContentsMargins(22, 15, 22, 15)
        self._fp_rows.append(placeholder)
        fp_lay.addWidget(placeholder)
        self._fp_spacer = _vspacer(10)
        fp_lay.addWidget(self._fp_spacer)
        r2g.addWidget(self._fp_frame, 0, 0)

        # Anomaly details list (dynamic)
        self._anom_frame = GlassFrame(r2)
        anom_lay = QVBoxLayout(self._anom_frame)
        anom_lay.setContentsMargins(0, 0, 0, 0)
        anom_lay.setSpacing(0)
        anom_lay.addWidget(section_header(self._anom_frame, "Detected Anomalies"))
        self._anom_container = QVBoxLayout()
        self._anom_container.setContentsMargins(22, 0, 22, 15)
        self._anom_container.setSpacing(4)
        no_anom = QLabel("✅  No anomalies detected yet.")
        no_anom.setFont(QFont("Segoe UI", 11))
        no_anom.setStyleSheet(f"color: {t['accent']};")
        self._anom_container.addWidget(no_anom)
        self._anom_widgets: list[QWidget] = [no_anom]
        anom_lay.addLayout(self._anom_container)
        anom_lay.addStretch()
        r2g.addWidget(self._anom_frame, 0, 1)
        lay.addWidget(r2)

        # ── Rules + Alerts ──
        r3 = QWidget()
        r3g = QGridLayout(r3)
        r3g.setContentsMargins(0, 0, 0, 15)
        r3g.setSpacing(12)
        r3g.setColumnStretch(0, 1)
        r3g.setColumnStretch(1, 1)

        rules = GlassFrame(r3)
        r_lay = QVBoxLayout(rules)
        r_lay.setContentsMargins(0, 0, 0, 0)
        r_lay.setSpacing(0)
        r_lay.addWidget(section_header(rules, "Behaviour Rules", "EDIT ALL",
                                       t["accent"]))
        for title_, sub_, on in [
            ("Alert on high CPU spike",
             f"Trigger alert if single process exceeds {config.HIGH_CPU_PROCESS_THRESHOLD:.0f}%", True),
            ("Flag unknown processes",
             "Alert when processes not in the safe list are detected", True),
            ("Process churn detection",
             f"Alert on > {config.PROCESS_CHURN_THRESHOLD} new processes per interval", True),
        ]:
            r_lay.addWidget(_toggle_row(rules, title_, sub_, on))
        r_lay.addWidget(_vspacer(15))
        r3g.addWidget(rules, 0, 0)

        # Recent alerts (dynamic)
        alerts_frame = GlassFrame(r3)
        alerts_lay = QVBoxLayout(alerts_frame)
        alerts_lay.setContentsMargins(0, 0, 0, 0)
        alerts_lay.setSpacing(0)
        alerts_lay.addWidget(section_header(alerts_frame,
                                            "Recent Behaviour Alerts"))
        self._alerts_container = QVBoxLayout()
        self._alerts_container.setContentsMargins(0, 0, 0, 0)
        self._alerts_container.setSpacing(0)
        no_alert = _alert_row(alerts_frame, "--:--:--",
                              "Waiting for data…", "INFO")
        self._alerts_container.addWidget(no_alert)
        self._alert_widgets: list[QWidget] = [no_alert]
        alerts_lay.addLayout(self._alerts_container)
        alerts_lay.addWidget(_vspacer(10))
        r3g.addWidget(alerts_frame, 0, 1)
        lay.addWidget(r3)
        lay.addStretch()

    # ── Live data refresh ──────────────────────────────────────────

    def refresh(self, score, behavioral_report):
        """Update all Behaviour Analysis widgets with live BehavioralReport data."""
        # Hide dynamic sections when no report available
        if behavioral_report is None:
            try:
                self._score_card.setVisible(False)
            except Exception:
                pass
            try:
                self._susp_count_lbl.setVisible(False)
            except Exception:
                pass
            try:
                self._anomaly_card.setVisible(False)
            except Exception:
                pass
            try:
                self._fp_frame.setVisible(False)
            except Exception:
                pass
            try:
                self._anom_frame.setVisible(False)
            except Exception:
                pass
            return
        else:
            # Ensure dynamic sections are visible
            try:
                self._score_card.setVisible(True)
            except Exception:
                pass
            try:
                self._susp_count_lbl.setVisible(True)
            except Exception:
                pass
            try:
                self._anomaly_card.setVisible(True)
            except Exception:
                pass
            try:
                self._fp_frame.setVisible(True)
            except Exception:
                pass
            try:
                self._anom_frame.setVisible(True)
            except Exception:
                pass
        t = _t()

        def _rget(key, default=None):
            if isinstance(behavioral_report, dict):
                return behavioral_report.get(key, default)
            return getattr(behavioral_report, key, default)

        bscore = _rget("behavioral_score", 0.0)
        severity = _rget("severity", "LOW")
        anomalies = _rget("anomalies", [])
        anomalous_procs = _rget("anomalous_processes", [])
        snapshot = _rget("snapshot", None)
        raw = _rget("raw_score", 0.0)
        deviation = _rget("baseline_deviation", 0.0)

        # ── Tier pill ──
        tier_text = score.tier if score else "Safe"
        tier_info = TIER_COLORS.get(tier_text, TIER_COLORS["Safe"])
        sev_labels = {"LOW": "Safe", "MEDIUM": "Moderate Threat",
                      "HIGH": "High Threat"}
        self._tier_pill.setText(
            f"● {int(bscore)} — {sev_labels.get(severity, severity)}")
        if severity == "HIGH":
            self._tier_pill.setStyleSheet(
                "background-color: #FEE2E2; color: #991B1B;"
                " border-radius: 14px; padding: 6px 16px;")
        elif severity == "MEDIUM":
            self._tier_pill.setStyleSheet(
                "background-color: #FEF3C7; color: #92400E;"
                " border-radius: 14px; padding: 6px 16px;")
        else:
            self._tier_pill.setStyleSheet(
                "background-color: #D1FAE5; color: #065F46;"
                " border-radius: 14px; padding: 6px 16px;")

        # ── Score card ──
        def score_color(v):
            if v < 25: return t["accent"]
            elif v < 50: return t["warning"]
            else: return t["danger"]

        self._score_card.update_value(int(bscore), score_color(bscore))
        sev_sub = {"LOW": "System is behaving normally",
                   "MEDIUM": "Some anomalies detected",
                   "HIGH": "Significant deviations detected"}
        self._score_card.update_subtext(
            sev_sub.get(severity, ""), score_color(bscore))

        # Count the number of processes visible in the table below (at most 8 shown)
        visible_count = 0
        if snapshot is not None:
            processes = getattr(snapshot, "top_cpu_processes", []) if not isinstance(snapshot, dict) else snapshot.get("top_cpu_processes", [])
            visible_count = min(len(processes), 8)

        # ── Suspicious processes count ──
        n_susp = visible_count
        if n_susp == 0:
            self._susp_count_lbl.setText("0 flagged")
            self._susp_count_lbl.setStyleSheet(f"color: {t['accent']};")
        else:
            self._susp_count_lbl.setText(f"{n_susp} flagged")
            self._susp_count_lbl.setStyleSheet(f"color: {t['warning']};")

        # ── Anomalies card ──
        n_anom = len(anomalies)
        if n_anom == 0:
            self._anomaly_card.update_value("0", t["accent"])
            self._anomaly_card.update_subtext("No anomalies detected", t["accent"])
        else:
            self._anomaly_card.update_value(str(n_anom), t["danger"])
            self._anomaly_card.update_subtext(
                f"{n_anom} anomal{'ies' if n_anom != 1 else 'y'} detected",
                t["danger"])

        # ── CPU / Memory gauges ──
        if snapshot is not None:
            cpu = getattr(snapshot, "cpu_percent", 0.0) if not isinstance(snapshot, dict) else snapshot.get("cpu_percent", 0.0)
            mem = getattr(snapshot, "memory_percent", 0.0) if not isinstance(snapshot, dict) else snapshot.get("memory_percent", 0.0)
            mem_mb = getattr(snapshot, "memory_used_mb", 0.0) if not isinstance(snapshot, dict) else snapshot.get("memory_used_mb", 0.0)

            cpu_color = t["accent"] if cpu < 50 else t["warning"] if cpu < 80 else t["danger"]
            self._cpu_gauge.set_score(cpu, cpu_color)
            self._cpu_status.setText(f"{cpu:.1f}%")
            self._cpu_status.setStyleSheet(f"color: {cpu_color};")

            mem_color = t["accent"] if mem < 60 else t["warning"] if mem < 85 else t["danger"]
            self._mem_gauge.set_score(mem, mem_color)
            self._mem_status.setText(f"{mem:.1f}% ({mem_mb:.0f} MB)")
            self._mem_status.setStyleSheet(f"color: {mem_color};")

        # ── Baseline status ──
        # Try to detect learning state from the profiler via data_bridge
        is_learning = deviation == 0.0 and bscore == 0.0 and n_anom == 0
        if is_learning:
            self._baseline_pill.setText("LEARNING")
            self._baseline_pill.setStyleSheet(
                "QLabel { background-color: #FEF3C7; color: #92400E;"
                " border-radius: 6px; padding: 3px 10px; }")
            self._baseline_status.setText("Building baseline…")
            self._baseline_detail.setText(
                f"Collecting system snapshots to establish normal behaviour")
        else:
            self._baseline_pill.setText("ACTIVE")
            self._baseline_pill.setStyleSheet(
                "QLabel { background-color: #D1FAE5; color: #065F46;"
                " border-radius: 6px; padding: 3px 10px; }")
            self._baseline_status.setText("Baseline active")
            self._baseline_detail.setText(
                f"Deviation: {deviation:.1f}% from baseline")

        # ── Flagged processes table ──
        for w in self._fp_rows:
            self._fp_container.removeWidget(w)
            w.deleteLater()
        self._fp_rows.clear()

        insert_idx = self._fp_container.indexOf(self._fp_spacer)
        if snapshot is not None:
            processes = getattr(snapshot, "top_cpu_processes", []) if not isinstance(snapshot, dict) else snapshot.get("top_cpu_processes", [])
            # Show top processes, highlighting suspicious ones
            shown = 0
            for p in processes:
                if shown >= 8:
                    break
                if isinstance(p, dict):
                    pname = p.get("name", "unknown")
                    pcpu = p.get("cpu_percent", 0.0)
                    pmem = p.get("memory_mb", 0.0)
                    psusp = p.get("is_suspicious", False)
                else:
                    pname = getattr(p, "name", "unknown")
                    pcpu = getattr(p, "cpu_percent", 0.0)
                    pmem = getattr(p, "memory_mb", 0.0)
                    psusp = getattr(p, "is_suspicious", False)

                is_flagged = pname in anomalous_procs or psusp
                risk = "HIGH" if pcpu > config.HIGH_CPU_PROCESS_THRESHOLD else (
                    "MED" if is_flagged else "LOW")

                row = table_row(self, [
                    (180, pname, "mono"),
                    (80, f"{pcpu:.1f}%"),
                    (80, f"{pmem:.0f} MB", "light"),
                    (80, risk, "pill"),
                ])
                self._fp_rows.append(row)
                self._fp_container.insertWidget(insert_idx, row)
                insert_idx += 1
                shown += 1

        if not self._fp_rows:
            placeholder = QLabel("    No processes to display")
            placeholder.setFont(QFont("Segoe UI", 11))
            placeholder.setStyleSheet(f"color: {t['text_muted']};")
            placeholder.setContentsMargins(22, 15, 22, 15)
            self._fp_rows.append(placeholder)
            self._fp_container.insertWidget(insert_idx, placeholder)

        # ── Anomaly details list ──
        for w in self._anom_widgets:
            self._anom_container.removeWidget(w)
            w.deleteLater()
        self._anom_widgets.clear()

        if anomalies:
            for anom in anomalies:
                if isinstance(anom, dict):
                    atype = anom.get("type", "UNKNOWN")
                    adesc = anom.get("description", "")
                    asev = anom.get("severity", "LOW")
                    acontrib = anom.get("score_contribution", 0)
                else:
                    atype = getattr(anom, "type", "UNKNOWN")
                    adesc = getattr(anom, "description", "")
                    asev = getattr(anom, "severity", "LOW")
                    acontrib = getattr(anom, "score_contribution", 0)

                sev_icon = {"LOW": "ℹ️", "MEDIUM": "⚠️", "HIGH": "🔴"}
                icon = sev_icon.get(asev, "⚠️")
                sev_color = {"LOW": t["text_secondary"], "MEDIUM": t["warning"],
                             "HIGH": t["danger"]}
                color = sev_color.get(asev, t["warning"])

                anom_w = QWidget()
                anom_l = QVBoxLayout(anom_w)
                anom_l.setContentsMargins(0, 6, 0, 6)
                anom_l.setSpacing(2)
                top_row = QHBoxLayout()
                type_lbl = QLabel(f"{icon}  {atype}")
                type_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
                type_lbl.setStyleSheet(f"color: {color};")
                top_row.addWidget(type_lbl)
                top_row.addStretch()
                score_lbl = QLabel(f"+{acontrib:.0f}")
                score_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
                score_lbl.setStyleSheet(f"color: {color};")
                top_row.addWidget(score_lbl)
                anom_l.addLayout(top_row)
                desc_lbl = QLabel(adesc)
                desc_lbl.setFont(QFont("Segoe UI", 10))
                desc_lbl.setStyleSheet(f"color: {t['text_secondary']};")
                desc_lbl.setWordWrap(True)
                anom_l.addWidget(desc_lbl)
                self._anom_container.addWidget(anom_w)
                self._anom_widgets.append(anom_w)
        else:
            ok = QLabel("✅  No anomalies detected. System is behaving normally.")
            ok.setFont(QFont("Segoe UI", 11))
            ok.setStyleSheet(f"color: {t['accent']};")
            self._anom_container.addWidget(ok)
            self._anom_widgets.append(ok)

        # ── Recent alerts (from anomalies) ──
        for w in self._alert_widgets:
            self._alerts_container.removeWidget(w)
            w.deleteLater()
        self._alert_widgets.clear()

        if anomalies:
            now_str = datetime.now().strftime("%H:%M:%S")
            for anom in anomalies[:5]:
                if isinstance(anom, dict):
                    adesc = anom.get("description", "")
                    asev = anom.get("severity", "LOW")
                else:
                    adesc = getattr(anom, "description", "")
                    asev = getattr(anom, "severity", "LOW")

                sev_map = {"LOW": "INFO", "MEDIUM": "WARNING", "HIGH": "CRITICAL"}
                row = _alert_row(self, now_str, adesc, sev_map.get(asev, "INFO"))
                self._alerts_container.addWidget(row)
                self._alert_widgets.append(row)
        else:
            now_str = datetime.now().strftime("%H:%M:%S")
            ok_row = _alert_row(self, now_str,
                                "No behavioural anomalies detected", "INFO")
            self._alerts_container.addWidget(ok_row)
            self._alert_widgets.append(ok_row)


class TimelineCanvas(QWidget):
    """Custom painted timeline for behaviour page."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")

    def paintEvent(self, event):
        t = _t()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        normal = [(0.04, 0.78), (0.16, 0.75), (0.28, 0.72), (0.40, 0.69),
                  (0.52, 0.71), (0.64, 0.67), (0.76, 0.61)]
        suspicious = [(0.76, 0.61), (0.84, 0.44), (0.92, 0.25), (0.98, 0.22)]

        pen = QPen(QColor(t["text_muted"]), 2.5)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        for i in range(len(normal) - 1):
            painter.drawLine(int(normal[i][0]*w), int(normal[i][1]*h),
                             int(normal[i+1][0]*w), int(normal[i+1][1]*h))

        pen = QPen(QColor(t["warning"]), 2.5)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        for i in range(len(suspicious) - 1):
            painter.drawLine(int(suspicious[i][0]*w), int(suspicious[i][1]*h),
                             int(suspicious[i+1][0]*w), int(suspicious[i+1][1]*h))

        bx, by = int(0.80*w), int(0.10*h)
        painter.setPen(QPen(QColor(t["warning"]), 1))
        painter.setBrush(QColor("#FEF3C7"))
        painter.drawRoundedRect(bx, by, int(0.18*w), 30, 4, 4)
        painter.setPen(QColor("#92400E"))
        painter.setFont(QFont("Segoe UI", 8))
        painter.drawText(QRectF(bx, by, 0.18*w, 30),
                         Qt.AlignmentFlag.AlignCenter, "Anomaly detected 2 PM")

        painter.setPen(QColor(t["text_muted"]))
        painter.setFont(QFont("Segoe UI", 8))
        for i, label in enumerate(["08:00", "10:00", "12:00", "14:00",
                                    "16:00", "18:00", "20:00"]):
            painter.drawText(int(0.04*w + i*(0.94*w/6)), int(0.95*h), label)
        painter.end()


# ═══════════════════════════════════════════════════════════════════════
# PAGE: WEB TRACKING
# ═══════════════════════════════════════════════════════════════════════

class WebTrackingPage(QWidget):
    def __init__(self, parent=None, data_bridge=None):
        super().__init__(parent)
        self.data_bridge = data_bridge
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Title row ──
        tr = QWidget()
        trl = QHBoxLayout(tr)
        trl.setContentsMargins(0, 0, 0, 20)
        t_left = QVBoxLayout()
        title = QLabel("Web Tracking")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {t['text_primary']};")
        t_left.addWidget(title)
        sub = QLabel("Privacy & tracker monitoring")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet(f"color: {t['text_secondary']};")
        t_left.addWidget(sub)
        trl.addLayout(t_left)
        trl.addStretch()
        self._tier_pill = QLabel("● -- — Scanning…")
        self._tier_pill.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._tier_pill.setStyleSheet("background-color: #F3F4F6; color: #374151;"
                                     " border-radius: 14px; padding: 6px 16px;")
        trl.addWidget(self._tier_pill)
        lay.addWidget(tr)

        # ── Stats row ──
        r1 = QWidget()
        r1g = QGridLayout(r1)
        r1g.setContentsMargins(0, 0, 0, 15)
        r1g.setSpacing(12)
        self._trackers_card = StatCard(r1, "Trackers Detected", "--",
                                       "Waiting for scan…", top_icon="🛡️")
        self._categories_card = StatCard(r1, "Active Categories", "--",
                                          "Waiting for scan…", top_icon="⊕")
        self._fp_card = StatCard(r1, "Fingerprint Signals", "--",
                                  "Waiting for scan…", top_icon="🔏")
        self._score_card = StatCard(r1, "Web Threat Score", "--",
                                     "Waiting for scan…", top_icon="🎯")
        r1g.addWidget(self._trackers_card, 0, 0)
        r1g.addWidget(self._categories_card, 0, 1)
        r1g.addWidget(self._fp_card, 0, 2)
        r1g.addWidget(self._score_card, 0, 3)
        for c in range(4):
            r1g.setColumnStretch(c, 1)
        lay.addWidget(r1)

        # ── Row 2: Tracker domains table + Category breakdown ──
        r2 = QWidget()
        r2g = QGridLayout(r2)
        r2g.setContentsMargins(0, 0, 0, 15)
        r2g.setSpacing(12)
        r2g.setColumnStretch(0, 3)
        r2g.setColumnStretch(1, 1)

        # Tracker domains table (dynamic)
        self._dom_card = GlassFrame(r2)
        dl = QVBoxLayout(self._dom_card)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.setSpacing(0)
        dl.addWidget(section_header(self._dom_card, "Top Tracking Domains Detected",
                                    "Live data"))
        self._dom_header = table_header(self._dom_card,
                                         [(200, "Domain"), (120, "Category"),
                                          (80, "Score"), (120, "Severity")])
        dl.addWidget(self._dom_header)
        self._dom_rows: list[QWidget] = []
        placeholder = QLabel("    Waiting for first scan…")
        placeholder.setFont(QFont("Segoe UI", 11))
        placeholder.setStyleSheet(f"color: {t['text_muted']};")
        placeholder.setContentsMargins(22, 15, 22, 15)
        self._dom_rows.append(placeholder)
        dl.addWidget(placeholder)
        self._dom_spacer = _vspacer(10)
        dl.addWidget(self._dom_spacer)
        r2g.addWidget(self._dom_card, 0, 0)

        # Category breakdown donut + legend (dynamic)
        cat_card = GlassFrame(r2)
        cl = QVBoxLayout(cat_card)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(section_header(cat_card, "Categories Breakdown"))
        self._donut = DonutChart(cat_card)
        self._donut.setFixedHeight(140)
        cl.addWidget(self._donut)
        # Category legend rows (dynamic)
        self._cat_legend_container = QVBoxLayout()
        self._cat_legend_container.setContentsMargins(0, 0, 0, 0)
        self._cat_legend_container.setSpacing(0)
        self._cat_legend_widgets: list[QWidget] = []
        # Initial static placeholders
        _cat_colors = {
            "Advertising": "#3B82F6", "Analytics": "#10B981",
            "Fingerprint": "#EF4444", "Social": "#8B5CF6",
            "Telemetry": "#F59E0B",
        }
        for label_text in ["◉ Advertising", "◉ Analytics",
                           "◉ Fingerprinting", "◉ Social", "◉ Telemetry"]:
            cfr = QWidget(cat_card)
            cfl = QHBoxLayout(cfr)
            cfl.setContentsMargins(22, 5, 22, 5)
            clbl = QLabel(label_text)
            clbl.setFont(QFont("Segoe UI", 11))
            clbl.setStyleSheet(f"color: {t['text_primary']};")
            cfl.addWidget(clbl)
            cfl.addStretch()
            cp = QLabel("--")
            cp.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            cp.setStyleSheet(f"color: {t['text_muted']};")
            cfl.addWidget(cp)
            self._cat_legend_container.addWidget(cfr)
            self._cat_legend_widgets.append(cfr)
        cl.addLayout(self._cat_legend_container)
        cl.addWidget(_vspacer(15))
        r2g.addWidget(cat_card, 0, 1)
        lay.addWidget(r2)

        # ── Row 3: Category Score Bars + Fingerprint Signals ──
        r2b = QWidget()
        r2bg = QGridLayout(r2b)
        r2bg.setContentsMargins(0, 0, 0, 15)
        r2bg.setSpacing(12)
        r2bg.setColumnStretch(0, 1)
        r2bg.setColumnStretch(1, 1)

        # Category score bars
        cat_bar_card = GlassFrame(r2b)
        cat_bar_lay = QVBoxLayout(cat_bar_card)
        cat_bar_lay.setContentsMargins(0, 0, 0, 0)
        cat_bar_lay.setSpacing(0)
        cat_bar_lay.addWidget(section_header(cat_bar_card, "Category Threat Scores"))
        self._analytics_bar = ProgressRow(cat_bar_card, "Analytics", "0%", "#10B981", 0)
        self._advertising_bar = ProgressRow(cat_bar_card, "Advertising", "0%", "#3B82F6", 0)
        self._social_bar = ProgressRow(cat_bar_card, "Social", "0%", "#8B5CF6", 0)
        self._telemetry_bar = ProgressRow(cat_bar_card, "Telemetry", "0%", "#F59E0B", 0)
        self._fingerprint_bar = ProgressRow(cat_bar_card, "Fingerprint", "0%", "#EF4444", 0)
        cat_bar_lay.addWidget(self._analytics_bar)
        cat_bar_lay.addWidget(self._advertising_bar)
        cat_bar_lay.addWidget(self._social_bar)
        cat_bar_lay.addWidget(self._telemetry_bar)
        cat_bar_lay.addWidget(self._fingerprint_bar)
        cat_bar_lay.addWidget(_vspacer(15))
        r2bg.addWidget(cat_bar_card, 0, 0)

        # Fingerprint signals (dynamic)
        fp_frame = GlassFrame(r2b)
        fp_lay = QVBoxLayout(fp_frame)
        fp_lay.setContentsMargins(0, 0, 0, 0)
        fp_lay.setSpacing(0)
        fp_lay.addWidget(section_header(fp_frame, "Fingerprinting Detection"))
        self._fp_container = QVBoxLayout()
        self._fp_container.setContentsMargins(22, 0, 22, 15)
        self._fp_container.setSpacing(4)
        no_fp = QLabel("✅  No fingerprinting attempts detected.")
        no_fp.setFont(QFont("Segoe UI", 11))
        no_fp.setStyleSheet(f"color: {t['accent']};")
        self._fp_container.addWidget(no_fp)
        self._fp_widgets: list[QWidget] = [no_fp]
        fp_lay.addLayout(self._fp_container)
        r2bg.addWidget(fp_frame, 0, 1)
        lay.addWidget(r2b)

        # ── Row 4: Top Offenders + Recommended Actions ──
        r3 = QWidget()
        r3g = QGridLayout(r3)
        r3g.setContentsMargins(0, 0, 0, 15)
        r3g.setSpacing(12)
        r3g.setColumnStretch(0, 1)
        r3g.setColumnStretch(1, 1)

        # Top offenders list (dynamic)
        self._offenders_frame = GlassFrame(r3)
        off_lay = QVBoxLayout(self._offenders_frame)
        off_lay.setContentsMargins(0, 0, 0, 0)
        off_lay.setSpacing(0)
        off_lay.addWidget(section_header(self._offenders_frame, "Top Offenders"))
        self._offenders_container = QVBoxLayout()
        self._offenders_container.setContentsMargins(22, 0, 22, 15)
        self._offenders_container.setSpacing(4)
        no_off = QLabel("✅  No tracker offenders detected yet.")
        no_off.setFont(QFont("Segoe UI", 11))
        no_off.setStyleSheet(f"color: {t['accent']};")
        self._offenders_container.addWidget(no_off)
        self._offender_widgets: list[QWidget] = [no_off]
        off_lay.addLayout(self._offenders_container)
        r3g.addWidget(self._offenders_frame, 0, 0)

        # Recommended actions (dynamic)
        ra = GlassFrame(r3)
        ral = QVBoxLayout(ra)
        ral.setContentsMargins(0, 0, 0, 0)
        ral.setSpacing(0)
        ral.addWidget(section_header(ra, "Recommended Actions"))
        self._actions_container = QVBoxLayout()
        self._actions_container.setContentsMargins(0, 0, 0, 0)
        self._actions_container.setSpacing(0)
        self._action_widgets: list[QWidget] = []
        # Default static actions
        a1 = ActionCard(ra, "🔏", "Enable Fingerprint Resistance",
                        "Set privacy.resistFingerprinting=true in your browser.")
        a2 = ActionCard(ra, "🔗", "Block Ad Trackers",
                        "Enable DNS-level ad blocking (Pi-hole, NextDNS).")
        a3 = ActionCard(ra, "🛡️", "Review Detected Trackers",
                        "Check the tracker list and consider browser extensions.")
        self._actions_container.addWidget(a1)
        self._actions_container.addWidget(a2)
        self._actions_container.addWidget(a3)
        self._action_widgets.extend([a1, a2, a3])
        ral.addLayout(self._actions_container)
        ral.addWidget(_vspacer(10))
        r3g.addWidget(ra, 0, 1)
        lay.addWidget(r3)
        lay.addStretch()

    # ── Live data refresh ──────────────────────────────────────────

    def refresh(self, score, web_report):
        """Update all Web Tracking widgets with live WebReport data."""
        # Hide dynamic sections when no report available
        if web_report is None:
            try:
                self._dom_card.setVisible(False)
            except Exception:
                pass
            try:
                self._donut.setVisible(False)
            except Exception:
                pass
            try:
                self._offenders_frame.setVisible(False)
            except Exception:
                pass
            try:
                self._actions_container.setVisible(False)
            except Exception:
                pass
            return
        else:
            # Ensure dynamic sections are visible
            try:
                self._dom_card.setVisible(True)
            except Exception:
                pass
            try:
                self._donut.setVisible(True)
            except Exception:
                pass
            try:
                self._offenders_frame.setVisible(True)
            except Exception:
                pass
            try:
                self._actions_container.setVisible(True)
            except Exception:
                pass
        t = _t()

        def _rget(key, default=None):
            if isinstance(web_report, dict):
                return web_report.get(key, default)
            return getattr(web_report, key, default)

        web_score = _rget("web_score", 0.0)
        severity = _rget("severity", "LOW")
        tracker_hits = _rget("tracker_hits", [])
        category_scores = _rget("category_scores", {})
        active_categories = _rget("active_categories", [])
        unique_count = _rget("unique_trackers_count", 0)
        top_offenders = _rget("top_offenders", [])
        fp_signals = _rget("fingerprint_signals", [])

        # ── Tier pill ──
        sev_labels = {"LOW": "Safe", "MEDIUM": "Moderate", "HIGH": "High Threat"}
        self._tier_pill.setText(
            f"● {int(web_score)} — {sev_labels.get(severity, severity)}")
        if severity == "HIGH":
            self._tier_pill.setStyleSheet(
                "background-color: #FEE2E2; color: #991B1B;"
                " border-radius: 14px; padding: 6px 16px;")
        elif severity == "MEDIUM":
            self._tier_pill.setStyleSheet(
                "background-color: #FEF3C7; color: #92400E;"
                " border-radius: 14px; padding: 6px 16px;")
        else:
            self._tier_pill.setStyleSheet(
                "background-color: #D1FAE5; color: #065F46;"
                " border-radius: 14px; padding: 6px 16px;")

        # ── Stat cards ──
        def _score_color(v):
            if v < 25: return t["accent"]
            elif v < 50: return t["warning"]
            else: return t["danger"]

        self._trackers_card.update_value(str(unique_count),
                                          t["danger"] if unique_count > 0 else t["accent"])
        self._trackers_card.update_subtext(
            f"{unique_count} unique tracker{'s' if unique_count != 1 else ''} found"
            if unique_count else "No trackers detected",
            t["danger"] if unique_count > 0 else t["accent"])

        n_cats = len(active_categories)
        self._categories_card.update_value(str(n_cats),
                                            t["warning"] if n_cats >= 2 else t["accent"])
        self._categories_card.update_subtext(
            ", ".join(active_categories[:3]) if active_categories else "None active",
            t["text_secondary"])

        n_fp = sum(1 for s in fp_signals
                   if getattr(s, "detected", False) if isinstance(s, object))
        fp_color = t["danger"] if n_fp > 0 else t["accent"]
        self._fp_card.update_value(str(n_fp), fp_color)
        self._fp_card.update_subtext(
            f"{n_fp} signal{'s' if n_fp != 1 else ''} detected" if n_fp
            else "No fingerprinting detected", fp_color)

        self._score_card.update_value(int(web_score), _score_color(web_score))
        sev_sub = {"LOW": "Low risk", "MEDIUM": "Moderate risk",
                   "HIGH": "High risk"}
        self._score_card.update_subtext(sev_sub.get(severity, ""),
                                         _score_color(web_score))

        # ── Tracker domains table ──
        dom_layout = self._dom_card.layout()
        for w in self._dom_rows:
            dom_layout.removeWidget(w)
            w.deleteLater()
        self._dom_rows.clear()

        if tracker_hits:
            insert_idx = dom_layout.indexOf(self._dom_spacer)
            # Sort by individual_score descending
            sorted_hits = sorted(tracker_hits,
                                  key=lambda h: getattr(h, "individual_score", 0),
                                  reverse=True)
            for hit in sorted_hits[:10]:
                domain = getattr(hit, "domain", "unknown")
                cat = getattr(hit, "tracker_category", "unknown")
                ind_score = getattr(hit, "individual_score", 0)
                sev = getattr(hit, "severity", "LOW")
                row = table_row(self._dom_card,
                                [(200, domain, "bold"),
                                 (120, cat.upper(), "pill"),
                                 (80, f"{ind_score:.0f}"),
                                 (120, sev, "pill")])
                self._dom_rows.append(row)
                dom_layout.insertWidget(insert_idx, row)
                insert_idx += 1
        else:
            placeholder = QLabel("    ✅ No trackers detected. Network is clean.")
            placeholder.setFont(QFont("Segoe UI", 11))
            placeholder.setStyleSheet(f"color: {t['accent']};")
            placeholder.setContentsMargins(22, 15, 22, 15)
            self._dom_rows.append(placeholder)
            insert_idx = dom_layout.indexOf(self._dom_spacer)
            dom_layout.insertWidget(insert_idx, placeholder)

        # ── Category score bars ──
        def _bar_color(v):
            if v < 40: return t["accent"]
            elif v < 70: return t["warning"]
            else: return t["danger"]

        a_score = category_scores.get("Analytics", 0)
        ad_score = category_scores.get("Advertising", 0)
        s_score = category_scores.get("Social", 0)
        tel_score = category_scores.get("Telemetry", 0)
        fp_score = category_scores.get("Fingerprint", 0)

        self._analytics_bar.update_value(a_score, _bar_color(a_score))
        self._advertising_bar.update_value(ad_score, _bar_color(ad_score))
        self._social_bar.update_value(s_score, _bar_color(s_score))
        self._telemetry_bar.update_value(tel_score, _bar_color(tel_score))
        self._fingerprint_bar.update_value(fp_score, _bar_color(fp_score))

        # ── Donut chart ──
        cat_hit_counts = {}
        for hit in tracker_hits:
            cat = getattr(hit, "tracker_category", "Other")
            cat_hit_counts[cat] = cat_hit_counts.get(cat, 0) + 1
        total_hits = sum(cat_hit_counts.values()) or 1
        self._donut.set_data(cat_hit_counts, total_hits)

        # ── Category legend ──
        _cat_colors_map = {
            "Advertising": "#3B82F6", "Analytics": "#10B981",
            "Fingerprint": "#EF4444", "Social": "#8B5CF6",
            "Telemetry": "#F59E0B",
        }
        for w in self._cat_legend_widgets:
            self._cat_legend_container.removeWidget(w)
            w.deleteLater()
        self._cat_legend_widgets.clear()

        for cat_name in ["Advertising", "Analytics", "Fingerprint",
                         "Social", "Telemetry"]:
            count = cat_hit_counts.get(cat_name, 0)
            pct = f"{count / total_hits * 100:.0f}%" if total_hits > 1 else "0%"
            color = _cat_colors_map.get(cat_name, t["text_muted"])

            cfr = QWidget()
            cfl = QHBoxLayout(cfr)
            cfl.setContentsMargins(22, 5, 22, 5)
            clbl = QLabel(f"◉ {cat_name}")
            clbl.setFont(QFont("Segoe UI", 11))
            clbl.setStyleSheet(f"color: {color};")
            cfl.addWidget(clbl)
            cfl.addStretch()
            cv = QLabel(f"{count}")
            cv.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            cv.setStyleSheet(f"color: {t['text_primary']};")
            cfl.addWidget(cv)
            cpct = QLabel(f"  {pct}")
            cpct.setFont(QFont("Segoe UI", 10))
            cpct.setStyleSheet(f"color: {t['text_secondary']};")
            cfl.addWidget(cpct)
            self._cat_legend_container.addWidget(cfr)
            self._cat_legend_widgets.append(cfr)

        # ── Fingerprint signals ──
        for w in self._fp_widgets:
            self._fp_container.removeWidget(w)
            w.deleteLater()
        self._fp_widgets.clear()

        detected_fps = [s for s in fp_signals if getattr(s, "detected", False)]
        if detected_fps:
            for sig in detected_fps:
                sig_type = getattr(sig, "signal_type", "UNKNOWN")
                confidence = getattr(sig, "confidence", 0)
                desc = getattr(sig, "description", "")
                # Icon by type
                icon_map = {"CANVAS": "🎨", "WEBGL": "🖼️", "FONT": "🔤",
                            "BATTERY": "🔋", "AUDIO": "🔊"}
                icon = icon_map.get(sig_type, "🔏")
                lbl = QLabel(
                    f"{icon}  {sig_type} — confidence: {confidence:.0%}")
                lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
                lbl.setStyleSheet(f"color: {t['danger']};")
                lbl.setWordWrap(True)
                self._fp_container.addWidget(lbl)
                self._fp_widgets.append(lbl)
                if desc:
                    dlbl = QLabel(f"     {desc}")
                    dlbl.setFont(QFont("Segoe UI", 10))
                    dlbl.setStyleSheet(f"color: {t['text_secondary']};")
                    dlbl.setWordWrap(True)
                    self._fp_container.addWidget(dlbl)
                    self._fp_widgets.append(dlbl)
        else:
            ok = QLabel("✅  No fingerprinting attempts detected.")
            ok.setFont(QFont("Segoe UI", 11))
            ok.setStyleSheet(f"color: {t['accent']};")
            self._fp_container.addWidget(ok)
            self._fp_widgets.append(ok)

        # ── Top offenders ──
        for w in self._offender_widgets:
            self._offenders_container.removeWidget(w)
            w.deleteLater()
        self._offender_widgets.clear()

        if top_offenders:
            for i, domain in enumerate(top_offenders[:5], 1):
                lbl = QLabel(f"  {i}.  {domain}")
                lbl.setFont(QFont("Segoe UI", 11,
                                   QFont.Weight.Bold if i <= 3
                                   else QFont.Weight.Normal))
                lbl.setStyleSheet(
                    f"color: {t['danger'] if i <= 2 else t['warning'] if i <= 3 else t['text_primary']};")
                lbl.setContentsMargins(0, 4, 0, 4)
                self._offenders_container.addWidget(lbl)
                self._offender_widgets.append(lbl)
        else:
            ok = QLabel("✅  No tracker offenders detected.")
            ok.setFont(QFont("Segoe UI", 11))
            ok.setStyleSheet(f"color: {t['accent']};")
            self._offenders_container.addWidget(ok)
            self._offender_widgets.append(ok)

        # ── Recommended actions (update based on active categories) ──
        for w in self._action_widgets:
            self._actions_container.removeWidget(w)
            w.deleteLater()
        self._action_widgets.clear()

        if category_scores.get("Fingerprint", 0) >= 40:
            w = ActionCard(None, "🔏", "Enable Fingerprint Resistance",
                           "Set privacy.resistFingerprinting=true in Firefox.", "APPLY")
            self._actions_container.addWidget(w)
            self._action_widgets.append(w)
        if category_scores.get("Advertising", 0) >= 50:
            w = ActionCard(None, "🛡️", "Block Ad Networks",
                           "Enable DNS-level ad blocking (Pi-hole, NextDNS).", "REVIEW")
            self._actions_container.addWidget(w)
            self._action_widgets.append(w)
        if category_scores.get("Social", 0) >= 50:
            w = ActionCard(None, "🔗", "Isolate Social Trackers",
                           "Use Firefox containers to isolate social logins.", "REVIEW")
            self._actions_container.addWidget(w)
            self._action_widgets.append(w)
        if category_scores.get("Telemetry", 0) >= 55:
            w = ActionCard(None, "⚠️", "Block Telemetry",
                           "Review app telemetry settings; block at firewall.", "REVIEW")
            self._actions_container.addWidget(w)
            self._action_widgets.append(w)
        if category_scores.get("Analytics", 0) >= 40:
            w = ActionCard(None, "📊", "Block Analytics Scripts",
                           "Install uBlock Origin to block analytics trackers.", "REVIEW")
            self._actions_container.addWidget(w)
            self._action_widgets.append(w)
        if not self._action_widgets:
            w = ActionCard(None, "✅", "All Clear",
                           "No tracker categories exceed alert thresholds.")
            self._actions_container.addWidget(w)
            self._action_widgets.append(w)


class DonutChart(QWidget):
    """Donut chart painted with QPainter — supports dynamic data."""
    _CAT_COLORS = {
        "Advertising": "#3B82F6",
        "Analytics": "#10B981",
        "Fingerprint": "#EF4444",
        "Social": "#8B5CF6",
        "Telemetry": "#F59E0B",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")
        self._data: dict[str, int] = {}
        self._total: int = 0

    def set_data(self, cat_counts: dict[str, int], total: int) -> None:
        """Update the chart data and repaint."""
        self._data = cat_counts
        self._total = total
        self.update()

    def paintEvent(self, event):
        t = _t()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2 - 10
        rect = QRectF(cx - r, cy - r, 2 * r, 2 * r)

        if self._data and self._total > 0:
            # Dynamic segments from real data
            segments: list[tuple[int, str]] = []
            for cat, count in self._data.items():
                extent = int(count / self._total * 360)
                color = self._CAT_COLORS.get(cat, "#6B7280")
                if extent > 0:
                    segments.append((extent, color))
        else:
            # Default placeholder ring
            segments = [(360, "#374151")]

        start = 90
        for extent, color in segments:
            pen = QPen(QColor(color), 18)
            pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            painter.setPen(pen)
            painter.drawArc(rect, start * 16, extent * 16)
            start += extent

        # Center label
        painter.setPen(QColor(t["text_primary"]))
        painter.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        center_text = str(self._total) if self._total > 0 else "--"
        painter.drawText(QRectF(0, cy - 15, w, 25),
                         Qt.AlignmentFlag.AlignCenter, center_text)
        painter.setPen(QColor(t["text_muted"]))
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        painter.drawText(QRectF(0, cy + 8, w, 15),
                         Qt.AlignmentFlag.AlignCenter, "TOTAL HITS")
        painter.end()


# ═══════════════════════════════════════════════════════════════════════
# PAGE: ALL ACTIONS
# ═══════════════════════════════════════════════════════════════════════

class AllActionsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        tr = QWidget()
        trl = QVBoxLayout(tr)
        trl.setContentsMargins(0, 0, 0, 20)
        title = QLabel("All Actions")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {t['text_primary']};")
        trl.addWidget(title)
        sub = QLabel("Manage automated and manual security actions")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet(f"color: {t['text_secondary']};")
        trl.addWidget(sub)
        lay.addWidget(tr)

        r1 = QWidget()
        r1g = QGridLayout(r1)
        r1g.setContentsMargins(0, 0, 0, 15)
        r1g.setSpacing(12)
        # Compute totals from the canonical ALL_ACTIONS list
        total_actions = len(ALL_ACTIONS)
        active_actions = sum(1 for a in ALL_ACTIONS if a.get("enabled"))
        inactive_actions = total_actions - active_actions

        self.total_actions_card = StatCard(r1, "Total Actions", str(total_actions), "", top_icon="☰")
        self.active_actions_card = StatCard(r1, "Active", str(active_actions), "",
                           value_color=t["accent"], top_icon="✅")
        self.inactive_actions_card = StatCard(r1, "Inactive", str(inactive_actions), "",
                             value_color=t["danger"], top_icon="⏸")
        r1g.addWidget(self.total_actions_card, 0, 0)
        r1g.addWidget(self.active_actions_card, 0, 1)
        r1g.addWidget(self.inactive_actions_card, 0, 2)
        for c in range(3):
            r1g.setColumnStretch(c, 1)
        lay.addWidget(r1)

        fb = QWidget()
        fbl = QHBoxLayout(fb)
        fbl.setContentsMargins(0, 0, 0, 15)
        for txt, active in [("All", True), ("Active", False), ("Inactive", False)]:
            fbl.addWidget(pill_button(txt, active))
        fbl.addStretch()
        search = QLineEdit()
        search.setPlaceholderText("🔍 Search actions...")
        search.setFixedSize(200, 32)
        search.setFont(QFont("Segoe UI", 11))
        fbl.addWidget(search)
        mod_filter = SentinelComboBox()
        mod_filter.addItems(["All Modules", "System", "WiFi",
                             "Web Tracking", "Behaviour"])
        mod_filter.setFont(QFont("Segoe UI", 11))
        mod_filter.setFixedSize(150, 32)
        fbl.addWidget(mod_filter)
        lay.addWidget(fb)

        tbl = GlassFrame(self)
        tbl_lay = QVBoxLayout(tbl)
        tbl_lay.setContentsMargins(0, 0, 0, 0)
        tbl_lay.setSpacing(0)
        tbl_lay.addWidget(table_header(tbl, [(190, "Action Name"), (90, "Module"),
                                             (70, "Type"), (70, "Status"),
                                             (90, "Last Triggered"),
                                             (280, "Description")]))
        # Use the canonical ALL_ACTIONS list defined at module level
        actions = ALL_ACTIONS
        for a in actions:
            name = a.get("name", "Unnamed Action")
            mod = a.get("module", "Unknown")
            typ = a.get("type", "MANUAL")
            on = a.get("enabled", False)
            last = a.get("last", "--")
            desc = a.get("desc", "")
            
            fr = HoverRow(tbl)
            fl = QHBoxLayout(fr)
            fl.setContentsMargins(22, 10, 22, 10)
            fl.setSpacing(5)
            n_lbl = QLabel(name)
            n_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            n_lbl.setStyleSheet(f"color: {t['text_primary']};")
            n_lbl.setFixedWidth(190)
            fl.addWidget(n_lbl)
            m_lbl = QLabel(mod)
            m_lbl.setFont(QFont("Segoe UI", 11))
            m_lbl.setStyleSheet(f"color: {t['text_secondary']};")
            m_lbl.setFixedWidth(90)
            fl.addWidget(m_lbl)
            pill = PillLabel(typ, typ)
            pill.setFixedWidth(70)
            fl.addWidget(pill)
            sw = ToggleSwitch(fr, checked=on)
            fl.addWidget(sw)
            l_lbl = QLabel(last)
            l_lbl.setFont(QFont("Segoe UI", 11))
            l_lbl.setStyleSheet(f"color: {t['text_secondary']};")
            l_lbl.setFixedWidth(90)
            fl.addWidget(l_lbl)
            d_lbl = QLabel(desc)
            d_lbl.setFont(QFont("Segoe UI", 11))
            d_lbl.setStyleSheet(f"color: {t['text_secondary']};")
            fl.addWidget(d_lbl, 1)
            tbl_lay.addWidget(fr)
        lay.addWidget(tbl)
        fr = HoverRow(tbl)
        fl = QHBoxLayout(fr)
        fl.setContentsMargins(22, 10, 22, 10)
        fl.setSpacing(5)
        n_lbl = QLabel(name)
        n_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        n_lbl.setStyleSheet(f"color: {t['text_primary']};")
        n_lbl.setFixedWidth(190)
        fl.addWidget(n_lbl)
        m_lbl = QLabel(mod)
        m_lbl.setFont(QFont("Segoe UI", 11))
        m_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        m_lbl.setFixedWidth(90)
        fl.addWidget(m_lbl)
        pill = PillLabel(typ, typ)
        pill.setFixedWidth(70)
        fl.addWidget(pill)
        sw = ToggleSwitch(fr, checked=on)
        fl.addWidget(sw)
        l_lbl = QLabel(last)
        l_lbl.setFont(QFont("Segoe UI", 11))
        l_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        l_lbl.setFixedWidth(90)
        fl.addWidget(l_lbl)
        d_lbl = QLabel(desc)
        d_lbl.setFont(QFont("Segoe UI", 11))
        d_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        fl.addWidget(d_lbl, 1)
        tbl_lay.addWidget(fr)
        lay.addWidget(tbl)

        pag = QWidget()
        pag_l = QHBoxLayout(pag)
        pag_l.setContentsMargins(0, 5, 0, 15)
        pag_info = QLabel(f"Showing 1-12 of {total_actions} actions")
        pag_info.setFont(QFont("Segoe UI", 11))
        pag_info.setStyleSheet(f"color: {t['accent']};")
        pag_l.addWidget(pag_info)
        pag_l.addStretch()
        for txt, active in [("‹", False), ("1", True), ("2", False), ("›", False)]:
            btn = QPushButton(txt)
            btn.setFixedSize(32, 32)
            btn.setFont(QFont("Segoe UI", 11))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if active:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {t['accent']}; color: white;
                        border-radius: 6px; border: none;
                    }}
                    QPushButton:hover {{ background-color: {t['accent_hover']}; }}
                """)
            else:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: transparent; color: {t['text_secondary']};
                        border: 1px solid {t['divider']}; border-radius: 6px;
                    }}
                    QPushButton:hover {{ background-color: {t['row_hover']}; }}
                """)
            pag_l.addWidget(btn)
        lay.addWidget(pag)
        lay.addStretch()


# ═══════════════════════════════════════════════════════════════════════
# PAGE: NETWORK LOGS
# ═══════════════════════════════════════════════════════════════════════

class NetworkLogsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        tr = QWidget()
        trl = QVBoxLayout(tr)
        trl.setContentsMargins(0, 0, 0, 20)
        title = QLabel("Logs")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {t['text_primary']};")
        trl.addWidget(title)
        sub = QLabel("System event history")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet(f"color: {t['text_secondary']};")
        trl.addWidget(sub)
        lay.addWidget(tr)

        fb = QWidget()
        fbl = QHBoxLayout(fb)
        fbl.setContentsMargins(0, 0, 0, 15)
        date_cb = SentinelComboBox()
        date_cb.addItems(["Last 7 days", "Last 24 hours", "Last 30 days",
                          "All time"])
        date_cb.setFont(QFont("Segoe UI", 11))
        date_cb.setFixedSize(150, 34)
        fbl.addWidget(date_cb)
        fbl.addSpacing(15)
        for txt, active in [("All", True), ("Info", False),
                            ("Warning", False), ("Critical", False)]:
            fbl.addWidget(pill_button(txt, active))
        fbl.addStretch()
        dl_btn = outline_button("⬇ Download Logs", color=t["accent"], width=150)
        fbl.addWidget(dl_btn)
        lay.addWidget(fb)

        summary = QWidget()
        sl = QHBoxLayout(summary)
        sl.setContentsMargins(0, 0, 0, 10)
        for text, color, bold in [
            ("Showing ", t["text_secondary"], False),
            ("248 events", t["text_primary"], True),
            (" — ", t["text_secondary"], False),
            ("3 Critical", t["danger"], True),
            (", ", t["text_secondary"], False),
            ("12 Warnings", t["warning"], True),
            (", 233 Info", t["text_secondary"], False),
        ]:
            lbl = QLabel(text)
            font = QFont("Segoe UI", 11)
            if bold:
                font.setWeight(QFont.Weight.Bold)
            lbl.setFont(font)
            lbl.setStyleSheet(f"color: {color};")
            sl.addWidget(lbl)
        sl.addStretch()
        lay.addWidget(summary)

        logs_card = GlassFrame(self)
        logs_lay = QVBoxLayout(logs_card)
        logs_lay.setContentsMargins(0, 0, 0, 0)
        logs_lay.setSpacing(0)

        entries = [
            ("2023-11-24\n14:22:01", "WIFI",
             "Unauthorized Access Point Detected",
             "MAC: 00:0A:95:9D:68:16 - Evil twin spoofing gateway", "#EF4444"),
            ("2023-11-24\n14:15:33", "SYSTEM",
             "Database Optimization Complete",
             "Index rebuild for security_events table finished in 1.4s",
             t["divider"]),
            ("2023-11-24\n13:58:12", "WEB",
             "Outbound SSH Connection",
             "Host 192.168.1.44 initiated SSH to 203.0.113.5 (Unknown)",
             "#F59E0B"),
            ("2023-11-24\n13:45:00", "BEHAVIOUR",
             "User Session Validated",
             "MFA success for user 'j_doe' from known office IP", "#10B981"),
            ("2023-11-24\n12:30:44", "SYSTEM",
             "Kernel Panic Averted",
             "Unexpected process termination in module 'auth_vault'", "#EF4444"),
            ("2023-11-24\n11:12:05", "WIFI",
             "High Interference Level",
             "2.4GHz spectrum congested (85%). Channel hopping to Ch 11.",
             "#EF4444"),
            ("2023-11-24\n10:45:22", "WEB",
             "SSL Certificate Verified",
             "External gateway certificate renewed until 2025.", "#10B981"),
            ("2023-11-24\n09:22:18", "BEHAVIOUR",
             "Unusual Data Volume Transfer",
             "Station 'LAB-WS-02' uploaded 4.5GB to cloud-backup.",
             "#F59E0B"),
            ("2023-11-24\n08:30:11", "SYSTEM",
             "Guardian AI Core Update",
             "Heuristics engine updated to v4.2.1-stable.",
             t["divider"]),
            ("2023-11-24\n07:15:01", "WEB",
             "Phishing Domain Blocked",
             "Request to 'secure-bank-login.cn' intercepted and dropped.",
             "#EF4444"),
        ]
        for time_str, mod, title_, desc, bar_color in entries:
            fr = HoverRow(logs_card)
            fl = QHBoxLayout(fr)
            fl.setContentsMargins(22, 12, 22, 12)
            fl.setSpacing(15)
            bar = QFrame()
            bar.setFixedWidth(4)
            bar.setStyleSheet(f"background-color: {bar_color};"
                              " border-radius: 2px; border: none;")
            bar.setMinimumHeight(40)
            fl.addWidget(bar)
            time_lbl = QLabel(time_str)
            time_lbl.setFont(QFont("Segoe UI", 10))
            time_lbl.setStyleSheet(f"color: {t['text_secondary']};")
            time_lbl.setFixedWidth(100)
            fl.addWidget(time_lbl)
            pill = PillLabel(mod, mod)
            fl.addWidget(pill)
            tf = QVBoxLayout()
            tf.setSpacing(2)
            t_lbl = QLabel(title_)
            t_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            t_lbl.setStyleSheet(f"color: {t['text_primary']};")
            tf.addWidget(t_lbl)
            d_lbl = QLabel(desc)
            d_lbl.setFont(QFont("Consolas", 9))
            d_lbl.setStyleSheet(f"color: {t['text_secondary']};")
            d_lbl.setWordWrap(True)
            tf.addWidget(d_lbl)
            fl.addLayout(tf, 1)
            det = ClickableLabel("Details", t["accent"])
            fl.addWidget(det)
            logs_lay.addWidget(fr)

        lay.addWidget(logs_card)

        load_w = QWidget()
        load_l = QHBoxLayout(load_w)
        load_l.setContentsMargins(0, 15, 0, 20)
        load_l.addStretch()
        lb = outline_button("Load 20 more", color=t["accent"], width=200)
        load_l.addWidget(lb)
        load_l.addStretch()
        lay.addWidget(load_w)
        lay.addStretch()


# ═══════════════════════════════════════════════════════════════════════
# PAGE: SETTINGS  (functional - changes config/theme live)
# ═══════════════════════════════════════════════════════════════════════

class SettingsPage(QWidget):
    """Settings page with live theme/glass toggle."""

    def __init__(self, parent=None, config_manager=None, app_window=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.app_window = app_window
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        tr = QWidget()
        trl = QVBoxLayout(tr)
        trl.setContentsMargins(0, 0, 0, 20)
        title = QLabel("Settings")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {t['text_primary']};")
        trl.addWidget(title)
        sub = QLabel("Manage your account security and application preferences.")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet(f"color: {t['text_secondary']};")
        trl.addWidget(sub)
        lay.addWidget(tr)

        card = GlassFrame(self)
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(0, 0, 0, 0)
        card_lay.setSpacing(0)

        # ── PROFILE ──
        card_lay.addWidget(self._section_label(card, "PROFILE"))
        prof = QWidget(card)
        pl = QHBoxLayout(prof)
        pl.setContentsMargins(40, 0, 40, 25)
        avatar = QLabel("👨🏻‍💼")
        avatar.setFont(QFont("Segoe UI", 36))
        pl.addWidget(avatar)
        pl.addSpacing(18)
        info = QVBoxLayout()
        info.setSpacing(2)
        name = QLabel("Alexander Sterling")
        name.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        name.setStyleSheet(f"color: {t['text_primary']};")
        info.addWidget(name)
        email = QLabel("alex.sterling@sentinel-defense.io")
        email.setFont(QFont("Segoe UI", 11))
        email.setStyleSheet(f"color: {t['text_secondary']};")
        info.addWidget(email)
        pl.addLayout(info)
        pl.addStretch()
        pl.addWidget(accent_button("Edit Profile"))
        card_lay.addWidget(prof)
        card_lay.addWidget(self._divider(card))

        # ── APPEARANCE ──
        card_lay.addWidget(self._section_label(card, "APPEARANCE"))

        # Theme selector
        theme_fr = QWidget(card)
        tfl = QHBoxLayout(theme_fr)
        tfl.setContentsMargins(40, 0, 40, 12)
        tfl.addWidget(self._bold_label("Theme"))
        tfl.addStretch()
        self.theme_cb = SentinelComboBox()
        self.theme_cb.addItems(["Light", "Dark", "System"])
        self.theme_cb.setFont(QFont("Segoe UI", 11))
        self.theme_cb.setFixedWidth(120)
        current = getattr(config, "APPEARANCE_MODE", "dark").title()
        idx = self.theme_cb.findText(current)
        if idx >= 0:
            self.theme_cb.setCurrentIndex(idx)
        self.theme_cb.currentTextChanged.connect(self._on_theme_change)
        tfl.addWidget(self.theme_cb)
        card_lay.addWidget(theme_fr)

        # Glass toggle
        glass_fr = QWidget(card)
        gfl = QHBoxLayout(glass_fr)
        gfl.setContentsMargins(40, 0, 40, 5)
        gfl.addWidget(self._bold_label("Glassmorphism Effect"))
        gfl.addStretch()
        self.glass_sw = ToggleSwitch(glass_fr,
                                     checked=getattr(config,
                                                     "GLASSMORPHISM_ENABLED",
                                                     True))
        self.glass_sw.toggled.connect(self._on_glass_toggle)
        gfl.addWidget(self.glass_sw)
        card_lay.addWidget(glass_fr)

        glass_desc = QLabel("Gives cards a floating glass look with subtle\n"
                            "depth and shadow effects.")
        glass_desc.setFont(QFont("Segoe UI", 10))
        glass_desc.setStyleSheet(f"color: {t['text_muted']};")
        glass_desc.setContentsMargins(40, 0, 0, 25)
        card_lay.addWidget(glass_desc)
        card_lay.addWidget(self._divider(card))

        # ── AUTOMATION ──
        card_lay.addWidget(self._section_label(card, "AUTOMATION PREFERENCES"))
        card_lay.addWidget(self._sub_header("Automatic Actions"))
        
        auto_vpn_val = getattr(config, "AUTO_CONNECT_VPN", True)
        auto_dns_val = getattr(config, "AUTO_DNS_SWITCH_ENABLED", True)
        
        card_lay.addWidget(_toggle_row(
            card, 
            "Auto connect VPN",
            "Automatically connect to VPN when threat score >= 50 or on Wi-Fi threat breach",
            value=auto_vpn_val,
            callback=self._on_auto_vpn_toggle
        ))
        card_lay.addWidget(_toggle_row(
            card, 
            "Auto switch DNS",
            "Automatically switch to secure DNS resolvers when threat score >= 50 or on Wi-Fi threat breach",
            value=auto_dns_val,
            callback=self._on_auto_dns_toggle
        ))
        card_lay.addWidget(self._divider(card))

        # ── NOTIFICATIONS ──
        card_lay.addWidget(self._section_label(card, "NOTIFICATIONS"))
        card_lay.addWidget(self._sub_header("Communication Channels"))
        for ch in ["In-App Notifications", "Desktop Push Alerts",
                   "Email Security Digests"]:
            cfr = QWidget(card)
            cfl = QHBoxLayout(cfr)
            cfl.setContentsMargins(40, 4, 40, 4)
            cb = QCheckBox(ch)
            cb.setFont(QFont("Segoe UI", 11))
            cb.setChecked(True)
            cfl.addWidget(cb)
            card_lay.addWidget(cfr)

        card_lay.addWidget(_vspacer(15))
        card_lay.addWidget(self._sub_header("Quiet hours"))
        qh = QFrame(card)
        qh.setStyleSheet(f"QFrame {{ background-color: {t['row_hover']};"
                         " border-radius: 8px; border: none; }}")
        qhl = QHBoxLayout(qh)
        qhl.setContentsMargins(20, 15, 20, 15)
        for label, val in [("START", "10:00 PM"), ("END", "07:00 AM")]:
            vl = QVBoxLayout()
            vl.setSpacing(2)
            l = QLabel(label)
            l.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            l.setStyleSheet(f"color: {t['text_muted']};")
            vl.addWidget(l)
            v = QLabel(val)
            v.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            v.setStyleSheet(f"color: {t['text_primary']};")
            vl.addWidget(v)
            qhl.addLayout(vl)
            qhl.addSpacing(40)
        qhl.addStretch()
        qh.setContentsMargins(40, 0, 40, 25)
        card_lay.addWidget(qh)
        card_lay.addWidget(self._divider(card))

        # ── DANGER ZONE ──
        dz = QFrame(card)
        dz.setStyleSheet(f"QFrame {{ background-color: {t['danger_tint']};"
                         " border-radius: 10px; border: none; }}")
        dz_lay = QVBoxLayout(dz)
        dz_lay.setContentsMargins(20, 20, 20, 20)
        dz_t = QLabel("DANGER ZONE")
        dz_t.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        dz_t.setStyleSheet(f"color: {t['danger']};")
        dz_lay.addWidget(dz_t)
        dz_lay.addSpacing(15)

        for btn_text, desc_title, desc_sub in [
            ("Log Out", "Log Out",
             "Sign out of all active Sentinel instances."),
            ("Delete Account", "Delete Account",
             "Once deleted, your threat history, logs, and custom rules\n"
             "will be permanently erased. Cannot be undone."),
        ]:
            row = QWidget(dz)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 10)
            tv = QVBoxLayout()
            tv.setSpacing(2)
            dt = QLabel(desc_title)
            dt.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            dt.setStyleSheet(f"color: {t['text_primary']};")
            tv.addWidget(dt)
            ds = QLabel(desc_sub)
            ds.setFont(QFont("Segoe UI", 10))
            ds.setStyleSheet(f"color: {t['text_secondary']};")
            tv.addWidget(ds)
            rl.addLayout(tv)
            rl.addStretch()
            rl.addWidget(danger_outline_button(btn_text))
            dz_lay.addWidget(row)

        dz.setContentsMargins(30, 10, 30, 30)
        card_lay.addWidget(dz)
        card_lay.addWidget(_vspacer(20))

        lay.addWidget(card)

        footer = QLabel("Build v2.4.12-secure  •  Sentinel Defense Systems")
        footer.setFont(QFont("Segoe UI", 9))
        footer.setStyleSheet(f"color: {t['text_muted']};")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setContentsMargins(0, 10, 0, 20)
        lay.addWidget(footer)
        lay.addStretch()

    def _on_theme_change(self, value):
        import config as cfg
        mode = value.lower()
        cfg.APPEARANCE_MODE = mode
        if self.config_manager:
            self.config_manager.set("APPEARANCE_MODE", mode)
        if self.app_window:
            self.app_window.apply_full_theme()

    def _on_glass_toggle(self, checked):
        import config as cfg
        cfg.GLASSMORPHISM_ENABLED = checked
        if self.config_manager:
            self.config_manager.set("GLASSMORPHISM_ENABLED", checked)
        GlassFrame.refresh_all()
        if self.app_window:
            self.app_window.apply_full_theme()

    def _on_auto_vpn_toggle(self, checked):
        import config as cfg
        cfg.AUTO_CONNECT_VPN = checked
        if self.config_manager:
            self.config_manager.set("AUTO_CONNECT_VPN", checked)

    def _on_auto_dns_toggle(self, checked):
        import config as cfg
        cfg.AUTO_DNS_SWITCH_ENABLED = checked
        cfg.AUTO_ENABLE_DNS_PROTECTION = checked
        if self.config_manager:
            self.config_manager.set("AUTO_DNS_SWITCH_ENABLED", checked)
            self.config_manager.set("AUTO_ENABLE_DNS_PROTECTION", checked)

    def _section_label(self, parent, text):
        t = _t()
        fr = QWidget(parent)
        fl = QHBoxLayout(fr)
        fl.setContentsMargins(40, 20, 40, 15)
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        lbl.setStyleSheet(f"color: {t['accent']};")
        fl.addWidget(lbl)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"background-color: {t['divider']}; border: none;"
                           " max-height: 1px;")
        line.setFixedHeight(1)
        fl.addWidget(line, 1)
        return fr

    def _divider(self, parent):
        t = _t()
        line = QFrame(parent)
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"background-color: {t['divider']}; border: none;"
                           " max-height: 1px;")
        line.setFixedHeight(1)
        line.setContentsMargins(40, 0, 40, 0)
        return line

    def _bold_label(self, text):
        t = _t()
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        lbl.setStyleSheet(f"color: {t['text_primary']};")
        return lbl

    def _sub_header(self, text):
        t = _t()
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        lbl.setStyleSheet(f"color: {t['text_primary']};")
        lbl.setContentsMargins(40, 0, 0, 10)
        return lbl


# ═══════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _toggle_row(parent, title, subtitle=None, value=False, enabled=True, callback=None):
    t = _t()
    fr = QWidget(parent)
    hl = QHBoxLayout(fr)
    hl.setContentsMargins(40, 8, 40, 8)
    vl = QVBoxLayout()
    vl.setSpacing(2)
    t_lbl = QLabel(title)
    t_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
    t_lbl.setStyleSheet(f"color: {t['text_primary']};")
    vl.addWidget(t_lbl)
    if subtitle:
        s_lbl = QLabel(subtitle)
        s_lbl.setFont(QFont("Segoe UI", 9))
        s_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        vl.addWidget(s_lbl)
    hl.addLayout(vl)
    hl.addStretch()
    sw = ToggleSwitch(fr, checked=value, enabled=enabled)
    if callback:
        sw.toggled.connect(callback)
    hl.addWidget(sw)
    return fr



def _alert_row(parent, time_str, desc, severity):
    t = _t()
    fr = QWidget(parent)
    vl = QVBoxLayout(fr)
    vl.setContentsMargins(22, 8, 22, 8)
    vl.setSpacing(5)
    top = QHBoxLayout()
    s_color = (t["danger"] if severity == "CRITICAL"
               else t["warning"] if severity == "WARNING"
               else "#3B82F6")
    dot = QLabel("●")
    dot.setFont(QFont("Segoe UI", 8))
    dot.setStyleSheet(f"color: {s_color};")
    top.addWidget(dot)
    time_lbl = QLabel(time_str)
    time_lbl.setFont(QFont("Segoe UI", 10))
    time_lbl.setStyleSheet(f"color: {t['text_secondary']};")
    top.addWidget(time_lbl)
    top.addStretch()
    pill = PillLabel(severity, severity)
    top.addWidget(pill)
    vl.addLayout(top)
    desc_lbl = QLabel(desc)
    desc_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
    desc_lbl.setStyleSheet(f"color: {t['text_primary']};")
    desc_lbl.setWordWrap(True)
    vl.addWidget(desc_lbl)
    return fr
