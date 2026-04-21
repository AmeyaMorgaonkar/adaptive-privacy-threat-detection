"""
All page views for the Sentinel dashboard (PySide6).
Each page matches the design mockups and is wired for live data.
"""

import config

from PySide6.QtWidgets import (
    QWidget, QFrame, QLabel, QHBoxLayout, QVBoxLayout,
    QGridLayout, QPushButton, QComboBox, QLineEdit,
    QCheckBox, QMessageBox,
)
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QFont, QPainter, QPen, QColor

from ui.glass_frame import GlassFrame
from ui.theme import get_card_tokens, TIER_COLORS
from ui.components import (
    PillLabel, StatCard, section_header, table_header, table_row,
    ActionCard, mini_stat, ProgressRow, CircularGauge, ToggleSwitch,
    ClickableLabel, accent_button, outline_button, danger_outline_button,
    pill_button, HoverRow,
)


def _t():
    return get_card_tokens()


def _vspacer(h=15):
    s = QWidget()
    s.setFixedHeight(h)
    s.setStyleSheet("background: transparent;")
    return s


# ═══════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD  (live data from DataBridge)
# ═══════════════════════════════════════════════════════════════════════

class DashboardPage(QWidget):
    def __init__(self, parent, data_bridge):
        super().__init__(parent)
        self.data_bridge = data_bridge
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
        self.threats_card = StatCard(r1, "Active Threats", "0",
                                    "No threats detected",
                                    value_color=t["danger"], top_icon="⚠️")
        self.actions_card = StatCard(r1, "Actions Taken", "12",
                                    "Resolved automatically",
                                    value_color=t["accent"], top_icon="✅")
        self.scan_card = StatCard(r1, "Last Scan", "--",
                                 "System continuous monitoring",
                                 value_size=24, top_icon="⏱")
        r1g.addWidget(self.score_card, 0, 0)
        r1g.addWidget(self.threats_card, 0, 1)
        r1g.addWidget(self.actions_card, 0, 2)
        r1g.addWidget(self.scan_card, 0, 3)
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
        ra_lay.addWidget(ActionCard(ra_card, "🛡️", "Update Firewall Rules",
                                    "Web module threshold met", "REVIEW"))
        ra_lay.addWidget(ActionCard(ra_card, "🔑", "Rotate API Keys",
                                    "Scheduled rotation due", "APPLY"))
        ra_lay.addWidget(ActionCard(ra_card, "🚫", "Block IP Range",
                                    "Suspicious behaviour detected", "REVIEW"))
        ra_lay.addWidget(_vspacer(8))
        r2g.addWidget(ra_card, 0, 1)
        lay.addWidget(r2)

        # ── Row 3: Alerts + mini stats ──
        r3 = QWidget()
        r3g = QGridLayout(r3)
        r3g.setContentsMargins(0, 0, 0, 15)
        r3g.setSpacing(12)
        r3g.setColumnStretch(0, 3)
        r3g.setColumnStretch(1, 1)

        al = GlassFrame(r3)
        al_lay = QVBoxLayout(al)
        al_lay.setContentsMargins(0, 0, 0, 0)
        al_lay.setSpacing(0)
        al_lay.addWidget(section_header(al, "Recent Alerts", "View All"))
        al_lay.addWidget(table_header(al, [(100, "Time"), (100, "Module"),
                                           (280, "Alert"), (100, "Severity")]))
        alerts = [
            ("10:42 AM", "Behaviour", "Multiple failed admin logins", "CRITICAL"),
            ("09:15 AM", "Web", "Unusual outbound traffic spike", "WARNING"),
            ("08:03 AM", "WiFi", "New unauthorized device connected", "WARNING"),
            ("07:22 AM", "System", "Routine definition update applied", "INFO"),
        ]
        for time_, mod, alert, sev in alerts:
            al_lay.addWidget(table_row(al, [(100, time_), (100, mod, "bold"),
                                            (280, alert), (100, sev, "pill")]))
        al_lay.addWidget(_vspacer(10))
        r3g.addWidget(al, 0, 0)

        sg = QWidget(r3)
        sg_grid = QGridLayout(sg)
        sg_grid.setContentsMargins(0, 0, 0, 0)
        sg_grid.setSpacing(8)
        sg_grid.addWidget(mini_stat(sg, "🛑", "1,204", "Blocked Req."), 0, 0)
        sg_grid.addWidget(mini_stat(sg, "⚙️", "4", "Suspicious\nProc."), 0, 1)
        sg_grid.addWidget(mini_stat(sg, "📡", "8", "Networks\nScanned"), 1, 0)
        sg_grid.addWidget(mini_stat(sg, "🔄", "3.2 GB", "Data Sent"), 1, 1)
        r3g.addWidget(sg, 0, 1)
        lay.addWidget(r3)
        lay.addStretch()

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

        self.scan_card.update_value("Just now")

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

        # ── Nearby Networks (dynamic) ──
        self._net_card = GlassFrame(self)
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
        lay.addWidget(self._net_card)
        lay.addWidget(_vspacer(15))

        # ── Bottom: DNS Leak + Threats ──
        r3 = QWidget()
        r3g = QGridLayout(r3)
        r3g.setContentsMargins(0, 0, 0, 15)
        r3g.setSpacing(12)
        r3g.setColumnStretch(0, 1)
        r3g.setColumnStretch(1, 1)

        leak = GlassFrame(r3)
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
        r3g.addWidget(leak, 0, 0)

        # Detected threats card (dynamic)
        threats_frame = GlassFrame(r3)
        tc_lay = QVBoxLayout(threats_frame)
        tc_lay.setContentsMargins(0, 0, 0, 0)
        tc_lay.setSpacing(0)
        tc_lay.addWidget(section_header(threats_frame, "Detected Threats"))
        self._threats_container = QVBoxLayout()
        self._threats_container.setContentsMargins(22, 0, 22, 15)
        self._threats_container.setSpacing(4)
        no_threat = QLabel("✅  No threats detected yet.")
        no_threat.setFont(QFont("Segoe UI", 11))
        no_threat.setStyleSheet(f"color: {t['accent']};")
        self._threats_container.addWidget(no_threat)
        self._threat_widgets: list[QWidget] = [no_threat]
        tc_lay.addLayout(self._threats_container)
        r3g.addWidget(threats_frame, 0, 1)
        lay.addWidget(r3)
        lay.addStretch()

    def refresh(self, score, wifi_report):
        """Update all WiFi page widgets from real WiFiReport data."""
        if wifi_report is None:
            return
        t = _t()

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
        ssid = getattr(wifi_report, "connected_ssid", "Unknown")
        enc = getattr(wifi_report, "encryption", "UNKNOWN")
        signal = getattr(wifi_report, "signal_dbm", -100)
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
        sev = getattr(wifi_report, "severity", "LOW")
        status_map = {"LOW": "OPTIMAL", "MEDIUM": "CAUTION",
                      "HIGH": "WARNING", "CRITICAL": "CRITICAL"}
        color_map = {"LOW": t["accent"], "MEDIUM": t["warning"],
                     "HIGH": t["danger"], "CRITICAL": t["danger"]}
        self._gauge_status.setText(f"STATUS: {status_map.get(sev, 'OPTIMAL')}")
        self._gauge_status.setStyleSheet(
            f"color: {color_map.get(sev, t['accent'])};")

        # ── Anomalies ──
        threats = getattr(wifi_report, "threats_detected", [])
        n = len(threats)
        if n == 0:
            self._anomaly_card.update_value("0", t["accent"])
            self._anomaly_card.update_subtext("No anomalies detected.", t["accent"])
        else:
            self._anomaly_card.update_value(str(n), t["danger"])
            self._anomaly_card.update_subtext(
                f"{n} issue{'s' if n != 1 else ''} found", t["danger"])

        # ── Nearby networks ──
        networks = getattr(wifi_report, "nearby_networks", [])
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
    def __init__(self, parent=None):
        super().__init__(parent)
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
        pill = QLabel("● 61 — Moderate Threat")
        pill.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        pill.setStyleSheet("background-color: #FEF3C7; color: #92400E;"
                           " border-radius: 14px; padding: 6px 16px;")
        trl.addWidget(pill)
        lay.addWidget(tr)

        # ── Stats row ──
        r1 = QWidget()
        r1g = QGridLayout(r1)
        r1g.setContentsMargins(0, 0, 0, 15)
        r1g.setSpacing(12)
        r1g.addWidget(StatCard(r1, "Behaviour Score", "61", "",
                               value_color=t["warning"]), 0, 0)

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
        spv = QLabel("4 flagged")
        spv.setFont(QFont("Segoe UI", 32, QFont.Weight.Bold))
        spv.setStyleSheet(f"color: {t['warning']};")
        sp_lay.addWidget(spv)
        spl = ClickableLabel("VIEW FLAGGED LIST →", t["accent"])
        sp_lay.addWidget(spl)
        r1g.addWidget(sp, 0, 1)

        aa = GlassFrame(r1)
        aa_lay = QVBoxLayout(aa)
        aa_lay.setContentsMargins(22, 22, 22, 22)
        aa_lay.setSpacing(4)
        aat = QHBoxLayout()
        aatl = QLabel("AUTO-ACTIONS TAKEN")
        aatl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        aatl.setStyleSheet(f"color: {t['text_muted']};")
        aat.addWidget(aatl)
        aat.addStretch()
        aat.addWidget(PillLabel("ACTIVE", "ACTIVE"))
        aa_lay.addLayout(aat)
        aav = QLabel("7 today")
        aav.setFont(QFont("Segoe UI", 32, QFont.Weight.Bold))
        aav.setStyleSheet(f"color: {t['text_primary']};")
        aa_lay.addWidget(aav)
        aas = QLabel("Last action: Blocked svchost spoofing 12m ago")
        aas.setFont(QFont("Segoe UI", 10))
        aas.setStyleSheet(f"color: {t['text_secondary']};")
        aas.setWordWrap(True)
        aa_lay.addWidget(aas)
        r1g.addWidget(aa, 0, 2)
        for c in range(3):
            r1g.setColumnStretch(c, 1)
        lay.addWidget(r1)

        # ── Timeline + Flagged ──
        r2 = QWidget()
        r2g = QGridLayout(r2)
        r2g.setContentsMargins(0, 0, 0, 15)
        r2g.setSpacing(12)
        r2g.setColumnStretch(0, 3)
        r2g.setColumnStretch(1, 2)

        graph = GlassFrame(r2)
        g_lay = QVBoxLayout(graph)
        g_lay.setContentsMargins(0, 0, 0, 0)
        g_lay.setSpacing(0)
        gh = QWidget(graph)
        ghl = QHBoxLayout(gh)
        ghl.setContentsMargins(22, 22, 22, 10)
        gt = QLabel("Process Activity Timeline")
        gt.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        gt.setStyleSheet(f"color: {t['text_primary']};")
        ghl.addWidget(gt)
        ghl.addStretch()
        leg1 = QLabel("● Normal  ")
        leg1.setFont(QFont("Segoe UI", 9))
        leg1.setStyleSheet(f"color: {t['text_muted']};")
        ghl.addWidget(leg1)
        leg2 = QLabel("● Suspicious")
        leg2.setFont(QFont("Segoe UI", 9))
        leg2.setStyleSheet(f"color: {t['warning']};")
        ghl.addWidget(leg2)
        g_lay.addWidget(gh)
        timeline = TimelineCanvas(graph)
        timeline.setFixedHeight(180)
        g_lay.addWidget(timeline)
        g_lay.addWidget(_vspacer(10))
        r2g.addWidget(graph, 0, 0)

        fp = GlassFrame(r2)
        fp_lay = QVBoxLayout(fp)
        fp_lay.setContentsMargins(0, 0, 0, 0)
        fp_lay.setSpacing(0)
        fph = QWidget(fp)
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
        fp_lay.addWidget(table_header(fp, [(150, "Process Name"), (70, "CPU%"),
                                           (80, "Risk")]))
        for name, cpu, risk in [
            ("crypt_x64.exe", "84%", "HIGH"),
            ("unknown_v3.bin", "12%", "MED"),
            ("svchost_tnt.exe", "41%", "HIGH"),
            ("ps_update.sh", "0.4%", "LOW"),
        ]:
            fp_lay.addWidget(table_row(fp, [(150, name, "mono"), (70, cpu),
                                            (80, risk, "pill")]))
        fp_lay.addWidget(_vspacer(10))
        r2g.addWidget(fp, 0, 1)
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
             "Trigger alert if single process exceeds 80%", True),
            ("Block keylogger patterns",
             "Heuristic monitoring of keystroke listeners", True),
            ("Monitor startup items",
             "Alert on new entries in boot registry", False),
        ]:
            r_lay.addWidget(_toggle_row(rules, title_, sub_, on))
        r_lay.addWidget(_vspacer(15))
        r3g.addWidget(rules, 0, 0)

        alerts = GlassFrame(r3)
        a_lay = QVBoxLayout(alerts)
        a_lay.setContentsMargins(0, 0, 0, 0)
        a_lay.setSpacing(0)
        a_lay.addWidget(section_header(alerts, "Recent Behaviour Alerts"))
        for time_, desc, sev in [
            ("14:02:11", "Unauthorized memory access blocked in kernel_bridge",
             "CRITICAL"),
            ("13:45:00", "High disk I/O detected: search_agent scanning",
             "WARNING"),
            ("11:12:32", "Behavioral heuristics engine v2.1.4 deployed",
             "INFO"),
        ]:
            a_lay.addWidget(_alert_row(alerts, time_, desc, sev))
        a_lay.addWidget(_vspacer(10))
        r3g.addWidget(alerts, 0, 1)
        lay.addWidget(r3)
        lay.addStretch()


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
    def __init__(self, parent=None):
        super().__init__(parent)
        t = _t()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

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
        pill = QLabel("● 61 — Moderate")
        pill.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        pill.setStyleSheet("background-color: #FEF3C7; color: #92400E;"
                           " border-radius: 14px; padding: 6px 16px;")
        trl.addWidget(pill)
        lay.addWidget(tr)

        r1 = QWidget()
        r1g = QGridLayout(r1)
        r1g.setContentsMargins(0, 0, 0, 15)
        r1g.setSpacing(12)
        r1g.addWidget(StatCard(r1, "Trackers Blocked Today", "143",
                               "↗ 12% from yesterday", top_icon="🛡️",
                               subtext_color=t["accent"]), 0, 0)
        r1g.addWidget(StatCard(r1, "Data Requests Intercepted", "28",
                               "↗ 8 new anomalies", top_icon="⊕",
                               subtext_color=t["warning"]), 0, 1)
        r1g.addWidget(StatCard(r1, "Sites With High Tracking", "5",
                               "▲ Requires immediate review",
                               value_color=t["danger"], top_icon="❗"), 0, 2)
        r1g.addWidget(StatCard(r1, "Web Threat Score", "61", "Moderate",
                               value_color=t["warning"]), 0, 3)
        for c in range(4):
            r1g.setColumnStretch(c, 1)
        lay.addWidget(r1)

        r2 = QWidget()
        r2g = QGridLayout(r2)
        r2g.setContentsMargins(0, 0, 0, 15)
        r2g.setSpacing(12)
        r2g.setColumnStretch(0, 3)
        r2g.setColumnStretch(1, 1)

        dom = GlassFrame(r2)
        dl = QVBoxLayout(dom)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.setSpacing(0)
        dl.addWidget(section_header(dom, "Top Tracking Domains Blocked",
                                    "View all logs →"))
        dl.addWidget(table_header(dom, [(200, "Domain"), (120, "Category"),
                                        (80, "Count"), (120, "Last Blocked")]))
        for d, cat, cnt, when, style in [
            ("doubleclick.net", "ADVERTISING", "1,244", "2m ago", "bold"),
            ("google-analytics.com", "ANALYTICS", "892", "15m ago", "bold"),
            ("canvas-fingerprint.io", "FINGERPRINT", "412", "42m ago", "normal"),
            ("facebook.com/tr", "SOCIAL", "355", "1h ago", "normal"),
            ("hotjar.io/tracker", "ANALYTICS", "298", "2h ago", "normal"),
            ("amazon-adsystem.com", "ADVERTISING", "211", "3h ago", "normal"),
            ("taboola.map", "ADVERTISING", "184", "5h ago", "normal"),
            ("font-telemetry.net", "FINGERPRINT", "156", "6h ago", "normal"),
        ]:
            dl.addWidget(table_row(dom, [(200, d, style), (120, cat, "pill"),
                                         (80, cnt), (120, when, "light")]))
        dl.addWidget(_vspacer(10))
        r2g.addWidget(dom, 0, 0)

        cat_card = GlassFrame(r2)
        cl = QVBoxLayout(cat_card)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(section_header(cat_card, "Categories Breakdown"))
        donut = DonutChart(cat_card)
        donut.setFixedHeight(140)
        cl.addWidget(donut)
        for label, pct in [("◉ Ad Networks", "42%"), ("◉ Analytics", "31%"),
                           ("◉ Fingerprinting", "15%"), ("◉ Social Media", "12%")]:
            cfr = QWidget(cat_card)
            cfl = QHBoxLayout(cfr)
            cfl.setContentsMargins(22, 5, 22, 5)
            clbl = QLabel(label)
            clbl.setFont(QFont("Segoe UI", 11))
            clbl.setStyleSheet(f"color: {t['text_primary']};")
            cfl.addWidget(clbl)
            cfl.addStretch()
            cp = QLabel(pct)
            cp.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            cp.setStyleSheet(f"color: {t['text_primary']};")
            cfl.addWidget(cp)
            cl.addWidget(cfr)
        cl.addWidget(_vspacer(15))
        r2g.addWidget(cat_card, 0, 1)
        lay.addWidget(r2)

        r3 = QWidget()
        r3g = QGridLayout(r3)
        r3g.setContentsMargins(0, 0, 0, 15)
        r3g.setSpacing(12)
        r3g.setColumnStretch(0, 1)
        r3g.setColumnStretch(1, 1)

        wl = GlassFrame(r3)
        wl_lay = QVBoxLayout(wl)
        wl_lay.setContentsMargins(0, 0, 0, 0)
        wl_lay.setSpacing(0)
        wlh = QWidget(wl)
        wlhl = QHBoxLayout(wlh)
        wlhl.setContentsMargins(22, 22, 22, 12)
        wlt = QLabel("Whitelist / Exceptions")
        wlt.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        wlt.setStyleSheet(f"color: {t['text_primary']};")
        wlhl.addWidget(wlt)
        wlhl.addStretch()
        wlhl.addWidget(accent_button("+ Add Exception"))
        wl_lay.addWidget(wlh)
        wl_lay.addWidget(table_header(wl, [(180, "Site Domain"),
                                            (180, "Reasoning"), (60, "Actions")]))
        for site, reason in [
            ("internal.company-wiki.com", "Required for team metrics"),
            ("stripe.com/dashboard", "Payment processor verification"),
            ("cloud.provider.com/logs", "Infrastructure monitoring"),
        ]:
            wl_lay.addWidget(table_row(wl, [(180, site, "bold"),
                                             (180, reason), (60, "", "trash")]))
        wl_lay.addWidget(_vspacer(15))
        r3g.addWidget(wl, 0, 0)

        ra = GlassFrame(r3)
        ral = QVBoxLayout(ra)
        ral.setContentsMargins(0, 0, 0, 0)
        ral.setSpacing(0)
        ral.addWidget(section_header(ra, "Recommended Actions"))
        ral.addWidget(ActionCard(ra, "🔏", "Stricter Fingerprinting",
                                 'Enable "Canvas Noise" for high-risk domains.'))
        ral.addWidget(ActionCard(ra, "🔗", "Social Media Trackers",
                                 "Found 12 sites with non-essential social pixel tracking."))
        ral.addWidget(ActionCard(ra, "⚠️", "Review High-Risk Sites",
                                 "5 domains flagged for aggressive tracking."))
        ral.addWidget(_vspacer(10))
        r3g.addWidget(ra, 0, 1)
        lay.addWidget(r3)
        lay.addStretch()


class DonutChart(QWidget):
    """Donut chart painted with QPainter."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")

    def paintEvent(self, event):
        t = _t()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2 - 10
        rect = QRectF(cx - r, cy - r, 2 * r, 2 * r)
        segments = [(151, "#3B82F6"), (112, "#10B981"),
                    (54, "#EF4444"), (43, "#8B5CF6")]
        start = 90
        for extent, color in segments:
            pen = QPen(QColor(color), 18)
            pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            painter.setPen(pen)
            painter.drawArc(rect, start*16, extent*16)
            start += extent

        painter.setPen(QColor(t["text_primary"]))
        painter.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        painter.drawText(QRectF(0, cy-15, w, 25),
                         Qt.AlignmentFlag.AlignCenter, "3.4k")
        painter.setPen(QColor(t["text_muted"]))
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        painter.drawText(QRectF(0, cy+8, w, 15),
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
        r1g.addWidget(StatCard(r1, "Total Actions", "24", "", top_icon="☰"), 0, 0)
        r1g.addWidget(StatCard(r1, "Active", "14", "",
                               value_color=t["accent"], top_icon="✅"), 0, 1)
        r1g.addWidget(StatCard(r1, "Inactive", "10", "",
                               value_color=t["danger"], top_icon="⏸"), 0, 2)
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
        mod_filter = QComboBox()
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
        actions = [
            ("Auto-Isolation High-Risk IP", "System", "AUTO", True, "2m ago",
             "Disconnects nodes showing high-risk outbound…"),
            ("Rogue AP De-auth", "WiFi", "AUTO", True, "14m ago",
             "Sends de-auth packets to unauthorized APs…"),
            ("Manual Credential Flush", "Web Tracking", "MANUAL", False, "--",
             "Clears all active session tokens for the user…"),
            ("Exfil Threshold Alert", "Behaviour", "AUTO", True, "1h ago",
             "Logs warning when data egress exceeds limit…"),
            ("Cookie Injection Block", "Web Tracking", "AUTO", True, "42m ago",
             "Prevents cross-site cookie manipulation…"),
            ("SSH Bruteforce Lockout", "System", "AUTO", True, "3h ago",
             "Blocks IPs with >5 failed login attempts…"),
            ("Manual Port Sweep", "System", "MANUAL", False, "Yesterday",
             "Initiates comprehensive scan of open ports…"),
            ("Beacon Frequency Monitor", "Behaviour", "AUTO", True, "12h ago",
             "Detects C2 beaconing patterns in network…"),
            ("WPA3 Enforcement", "WiFi", "AUTO", True, "--",
             "Auto-upgrades connecting clients to WPA3…"),
            ("Tracker Pixel Scrubber", "Web Tracking", "MANUAL", False, "2d ago",
             "Filters invisible tracking pixels from pages…"),
            ("Kernel Integrity Check", "System", "AUTO", True, "5m ago",
             "Verifies boot sequence and kernel space…"),
            ("Manual Node Blacklist", "System", "MANUAL", False, "--",
             "Hard-blocks hardware addresses from access…"),
        ]
        for name, mod, typ, on, last, desc in actions:
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
        pag_info = QLabel("Showing 1-12 of 24 actions")
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
        date_cb = QComboBox()
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
        self.theme_cb = QComboBox()
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
        for title_, sub_, on in [
            ("Auto-block high-risk processes",
             "Sentinel will kill suspicious threads instantly", True),
            ("Auto-disconnect suspicious WiFi",
             "Sever connection if SSL pinning fails", False),
            ("Auto-clear tracking cookies daily",
             "Remove browser fingerprints at midnight", True),
            ("Quarantine flagged files automatically",
             "Move threat vectors to sandbox isolation", False),
        ]:
            card_lay.addWidget(_toggle_row(card, title_, sub_, on))

        card_lay.addWidget(_vspacer(15))
        card_lay.addWidget(self._sub_header("Alert Me When"))
        for title_, sub_, on in [
            ("New device joins my network", None, True),
            ("Behaviour score exceeds 70", None, True),
            ("High-risk tracker detected", None, False),
            ("Unusual data upload detected", None, True),
        ]:
            card_lay.addWidget(_toggle_row(card, title_, sub_, on))

        card_lay.addWidget(_vspacer(15))
        never_h = QLabel("Never Do")
        never_h.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        never_h.setStyleSheet(f"color: {t['danger']};")
        never_h.setContentsMargins(40, 0, 0, 10)
        card_lay.addWidget(never_h)
        for title_, sub_, on in [
            ("Send data to third parties", None, False),
            ("Auto-delete user files", None, False),
            ("Share location data", None, False),
        ]:
            card_lay.addWidget(_toggle_row(card, title_, sub_, on,
                                           enabled=False))

        lock_note = QLabel("These settings are hard-locked by the "
                           "Sentinel Privacy Manifest.")
        lock_note.setFont(QFont("Segoe UI", 9))
        lock_note.setStyleSheet(f"color: {t['text_muted']};")
        lock_note.setContentsMargins(40, 5, 0, 15)
        card_lay.addWidget(lock_note)
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

def _toggle_row(parent, title, subtitle=None, value=False, enabled=True):
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
