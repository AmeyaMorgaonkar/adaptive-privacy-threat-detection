"""
Report Panel (Milestone 06)

PySide6 page for viewing session summaries, hardening recommendations,
exporting reports (JSON / TXT), and browsing report history.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QFrame, QLabel, QHBoxLayout, QVBoxLayout,
    QGridLayout, QPushButton, QScrollArea, QFileDialog,
    QMessageBox, QSizePolicy,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

try:
    import config
    from logger import get_logger
except ModuleNotFoundError:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    import config
    from logger import get_logger

from ui.glass_frame import GlassFrame
from ui.theme import get_card_tokens, TIER_COLORS
from ui.components import (
    StatCard, section_header, ActionCard, accent_button,
    outline_button, PillLabel,
)

log = get_logger(__name__)


def _t():
    return get_card_tokens()


# ── Priority badge colors ───────────────────────────────────────────

_PRIORITY_COLORS = {
    "IMMEDIATE": ("#FEE2E2", "#991B1B"),
    "HIGH":      ("#FED7AA", "#9A3412"),
    "MEDIUM":    ("#FEF3C7", "#92400E"),
    "LOW":       ("#D1FAE5", "#065F46"),
}


# ═══════════════════════════════════════════════════════════════════════
# REPORT PANEL PAGE
# ═══════════════════════════════════════════════════════════════════════

class ReportPanel(QWidget):
    """Reports page: session summary, hardening recs, export, history."""

    def __init__(self, parent=None, data_bridge=None):
        super().__init__(parent)
        self.data_bridge = data_bridge
        self._last_report = None
        
        # Fix 7: Snapshot guard for hardening recommendations
        self._last_recs_snapshot = None
        
        # Fix 8: HardeningAdvisor caching
        self._hardening_advisor = None
        self._hardening_analysis_cache = None  # (input_snapshot, priority_actions)
        
        t = _t()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Title row ──
        tr = QWidget()
        trl = QHBoxLayout(tr)
        trl.setContentsMargins(0, 0, 0, 20)
        t_left = QVBoxLayout()
        title = QLabel("Reports")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {t['text_primary']};")
        t_left.addWidget(title)
        sub = QLabel("Privacy audit & hardening")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet(f"color: {t['text_secondary']};")
        t_left.addWidget(sub)
        trl.addLayout(t_left)
        trl.addStretch()

        # Session controls
        self._toggle_btn = accent_button("⏸ Pause", width=150)
        self._toggle_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {t['accent']}; color: white;
                border-radius: 8px; padding: 10px 22px; border: none;
            }}
            QPushButton:hover {{ background-color: {t['accent_hover']}; }}
            QPushButton:pressed {{ background-color: #047857; }}
        """)
        self._toggle_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._toggle_btn.clicked.connect(self._toggle_session)
        trl.addWidget(self._toggle_btn)

        lay.addWidget(tr)

        # ── Session summary cards ──
        r1 = QWidget()
        r1g = QGridLayout(r1)
        r1g.setContentsMargins(0, 0, 0, 15)
        r1g.setSpacing(12)
        self._verdict_card = StatCard(r1, "Overall Verdict", "--",
                                       "Waiting for data…", top_icon="🎯")
        self._duration_card = StatCard(r1, "Session Duration", "--",
                                        "Since start", top_icon="⏱️")
        self._scans_card = StatCard(r1, "Scan Cycles", "--",
                                     "", top_icon="🔄")
        self._recs_card = StatCard(r1, "Recommendations", "--",
                                    "", top_icon="📋")
        r1g.addWidget(self._verdict_card, 0, 0)
        r1g.addWidget(self._duration_card, 0, 1)
        r1g.addWidget(self._scans_card, 0, 2)
        r1g.addWidget(self._recs_card, 0, 3)
        lay.addWidget(r1)

        # ── Side-by-side: Component Scores & Export Report ──
        mid_row = QWidget()
        mid_l = QHBoxLayout(mid_row)
        mid_l.setContentsMargins(0, 0, 0, 0)
        mid_l.setSpacing(20)

        # Left Column: Component Scores
        col_left = QWidget()
        col_left_lay = QVBoxLayout(col_left)
        col_left_lay.setContentsMargins(0, 0, 0, 0)
        col_left_lay.setSpacing(0)
        col_left_lay.addWidget(section_header(col_left, "Component Scores"))
        
        r2 = QWidget()
        r2g = QGridLayout(r2)
        r2g.setContentsMargins(22, 0, 22, 15)
        r2g.setSpacing(12)
        self._wifi_score_lbl = self._score_row(r2g, 0, "🛜", "Wi-Fi Security")
        self._beh_score_lbl = self._score_row(r2g, 1, "⚙️", "Behaviour Analysis")
        self._web_score_lbl = self._score_row(r2g, 2, "🌐", "Web Tracking")
        col_left_lay.addWidget(r2)
        col_left_lay.addStretch()
        mid_l.addWidget(col_left, 1)

        # Vertical Separator Line
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setFrameShadow(QFrame.Shadow.Plain)
        sep.setStyleSheet(f"background-color: {t.get('input_border', '#374151')}; width: 1px; max-width: 1px; border: none; margin-top: 50px; margin-bottom: 15px;")
        mid_l.addWidget(sep)

        # Right Column: Export controls
        col_right = QWidget()
        col_right_lay = QVBoxLayout(col_right)
        col_right_lay.setContentsMargins(0, 0, 0, 0)
        col_right_lay.setSpacing(0)
        
        # Centering stretch spacer at the top (higher weight to push down)
        col_right_lay.addStretch(3)
        
        # Center-aligned Header
        self._export_hdr = QLabel("Export Report")
        self._export_hdr.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._export_hdr.setStyleSheet(f"color: {t['text_primary']};")
        self._export_hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col_right_lay.addWidget(self._export_hdr)
        
        # Spacing between header and buttons
        col_right_lay.addSpacing(15)
        
        # Buttons Row (horizontally centered)
        btn_row = QWidget()
        btn_l = QHBoxLayout(btn_row)
        btn_l.setContentsMargins(0, 0, 0, 0)
        btn_l.setSpacing(12)
        btn_l.addStretch()
        
        self._json_btn = accent_button("📄 Save JSON", width=160)
        self._json_btn.clicked.connect(self._export_json)
        btn_l.addWidget(self._json_btn)
        
        self._txt_btn = outline_button("📝 Save TXT", width=160)
        self._txt_btn.clicked.connect(self._export_txt)
        btn_l.addWidget(self._txt_btn)
        
        btn_l.addStretch()
        col_right_lay.addWidget(btn_row)
        
        # Spacing between buttons and status
        col_right_lay.addSpacing(10)
        
        # Status Label (horizontally centered)
        self._export_status = QLabel("")
        self._export_status.setFont(QFont("Segoe UI", 10))
        self._export_status.setStyleSheet(f"color: {t['accent']};")
        self._export_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col_right_lay.addWidget(self._export_status)
        
        # Centering stretch spacer at the bottom
        col_right_lay.addStretch(2)
        
        mid_l.addWidget(col_right, 1)

        lay.addWidget(mid_row)

        # ── Hardening recommendations ──
        lay.addWidget(section_header(self, "Hardening Recommendations"))
        self._recs_container = QVBoxLayout()
        self._recs_container.setContentsMargins(22, 0, 22, 15)
        self._recs_container.setSpacing(8)
        self._recs_placeholder = QLabel("  Waiting for scan data…")
        self._recs_placeholder.setFont(QFont("Segoe UI", 11))
        self._recs_placeholder.setStyleSheet(f"color: {t['text_muted']};")
        self._recs_container.addWidget(self._recs_placeholder)
        recs_w = QWidget()
        recs_w.setLayout(self._recs_container)
        lay.addWidget(recs_w)

        # ── Report history ──
        lay.addWidget(section_header(self, "Report History"))
        self._history_container = QVBoxLayout()
        self._history_container.setContentsMargins(22, 0, 22, 15)
        self._history_container.setSpacing(6)
        self._history_placeholder = QLabel("  No saved reports yet.")
        self._history_placeholder.setFont(QFont("Segoe UI", 11))
        self._history_placeholder.setStyleSheet(f"color: {t['text_muted']};")
        self._history_container.addWidget(self._history_placeholder)
        hist_w = QWidget()
        hist_w.setLayout(self._history_container)
        lay.addWidget(hist_w)

        lay.addStretch()

        # Load history on startup
        self._refresh_history()
        self._history_placeholder = None

    # ── Score row helper ─────────────────────────────────────────────

    @staticmethod
    def _score_row(grid, row, icon, label):
        t = _t()
        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI", 14))
        grid.addWidget(icon_lbl, row, 0)
        name = QLabel(label)
        name.setFont(QFont("Segoe UI", 12))
        name.setStyleSheet(f"color: {t['text_primary']};")
        grid.addWidget(name, row, 1)
        val = QLabel("--/100")
        val.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        val.setStyleSheet(f"color: {t['text_muted']};")
        val.setAlignment(Qt.AlignmentFlag.AlignRight)
        grid.addWidget(val, row, 2)
        return val

    # ── Live refresh (called by App._on_refresh) ─────────────────────

    def refresh(self, score, wifi_report=None, behavioral_report=None,
                web_report=None):
        """Update the panel with latest scan data."""
        if score is None:
            return

        t = _t()
        tier_info = TIER_COLORS.get(score.tier, TIER_COLORS["Safe"])

        # Verdict card
        from modules.reporting import _TIER_TO_VERDICT
        verdict = _TIER_TO_VERDICT.get(score.tier, "SAFE")
        self._verdict_card.update_value(verdict, tier_info["fg"])
        self._verdict_card.update_subtext(
            f"Score: {int(score.unified_score)}/100", tier_info["fg"])

        # Duration
        if self.data_bridge:
            dur = self.data_bridge.get_session_duration_minutes()
            if dur < 60:
                dur_str = f"{dur:.1f} min"
            else:
                dur_str = f"{dur / 60:.1f} hr"
            self._duration_card.update_value(dur_str)

            # Scan cycles
            hist = self.data_bridge.history()
            self._scans_card.update_value(str(len(hist)))

            # Session controls
            if self.data_bridge.is_session_running():
                self._toggle_btn.setText("⏸ Pause")
            else:
                self._toggle_btn.setText("▶ Resume")

        # Component scores
        def _color(v):
            if v < 40:
                return t["accent"]
            elif v < 70:
                return t["warning"]
            return t["danger"]

        self._wifi_score_lbl.setText(f"{int(score.wifi_score)}/100")
        self._wifi_score_lbl.setStyleSheet(
            f"color: {_color(score.wifi_score)};")
        self._beh_score_lbl.setText(f"{int(score.behavioral_score)}/100")
        self._beh_score_lbl.setStyleSheet(
            f"color: {_color(score.behavioral_score)};")
        self._web_score_lbl.setText(f"{int(score.web_score)}/100")
        self._web_score_lbl.setStyleSheet(
            f"color: {_color(score.web_score)};")

        # Hardening recommendations
        try:
            from modules.hardening import HardeningAdvisor

            # Fix 8: Lazy-create advisor singleton; never recreate
            if self._hardening_advisor is None:
                self._hardening_advisor = HardeningAdvisor()

            # Fix 8: Compute lightweight input snapshot for cache check
            _inp_parts = []
            if wifi_report is not None:
                _inp_parts.append(str(getattr(wifi_report, 'severity', '')))
                _inp_parts.append(str(getattr(wifi_report, 'connected_ssid', '')))
                _inp_parts.append(str(getattr(wifi_report, 'encryption', '')))
                _inp_parts.append(str(len(getattr(wifi_report, 'threats_detected', []))))
            if behavioral_report is not None:
                _inp_parts.append(str(getattr(behavioral_report, 'severity', '')))
                _inp_parts.append(str(getattr(behavioral_report, 'behavioral_score', 0)))
            if web_report is not None:
                _inp_parts.append(str(getattr(web_report, 'severity', '')))
                _inp_parts.append(str(getattr(web_report, 'web_score', 0)))
            _inp_parts.append(str(int(score.unified_score)))
            _inp_parts.append(score.tier)
            _hardening_input_snapshot = tuple(_inp_parts)

            # Fix 8: Use cached result if input hasn't changed
            if (self._hardening_analysis_cache is not None
                    and self._hardening_analysis_cache[0] == _hardening_input_snapshot):
                recs = self._hardening_analysis_cache[1]
            else:
                recs = self._hardening_advisor.analyze(
                    wifi_report=wifi_report,
                    behavioral_report=behavioral_report,
                    web_report=web_report,
                    threat_score=score,
                )
                recs = self._hardening_advisor.get_priority_actions(recs)
                recs = list(recs)  # prevent mutation of cached value
                self._hardening_analysis_cache = (_hardening_input_snapshot, recs)

            self._recs_card.update_value(str(len(recs)))

            # Snapshot includes description so content changes are detected
            _recs_snapshot = tuple(
                (getattr(rec, 'title', ''), getattr(rec, 'priority', ''),
                 getattr(rec, 'category', ''), getattr(rec, 'description', ''))
                for rec in recs
            ) if recs else ()

            if _recs_snapshot != self._last_recs_snapshot:
                self._last_recs_snapshot = _recs_snapshot

                # Count existing rec card widgets (GlassFrame instances)
                existing_cards = []
                for i in range(self._recs_container.count()):
                    w = self._recs_container.itemAt(i).widget()
                    if w is not None and isinstance(w, GlassFrame):
                        existing_cards.append(w)

                if recs and len(recs) == len(existing_cards):
                    # In-place update: same number of cards → update text
                    for card, rec in zip(existing_cards, recs):
                        self._update_rec_card(card, rec)
                else:
                    # Count changed — full rebuild
                    while self._recs_container.count():
                        child = self._recs_container.takeAt(0)
                        if child.widget():
                            child.widget().deleteLater()

                    if recs:
                        for rec in recs:
                            self._recs_container.addWidget(
                                self._build_rec_card(rec))
                    else:
                        ok = QLabel("  ✓ No hardening actions required at this time.")
                        ok.setFont(QFont("Segoe UI", 11))
                        ok.setStyleSheet(f"color: {t['accent']};")
                        self._recs_container.addWidget(ok)

            # Store latest report data for export
            self._last_score = score
            self._last_wifi = wifi_report
            self._last_behavioral = behavioral_report
            self._last_web = web_report
            self._last_recs = recs

        except Exception as exc:
            log.error("Hardening analysis error: %s", exc)

    # ── Recommendation card builder ──────────────────────────────────

    @staticmethod
    def _build_rec_card(rec) -> QWidget:
        t = _t()
        card = GlassFrame()
        card.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        card_l = QVBoxLayout(card)
        card_l.setContentsMargins(18, 14, 18, 14)
        card_l.setSpacing(6)
        card_l.setSizeConstraint(QVBoxLayout.SizeConstraint.SetMinimumSize)

        # Row 1: category + title (left) — priority badge (right)
        hdr = QHBoxLayout()
        hdr.setSpacing(10)

        category = getattr(rec, "category", rec.get("category", "")
                           if isinstance(rec, dict) else "")
        cat_lbl = QLabel(f"[{category}]")
        cat_lbl.setObjectName("recCardCategory")
        cat_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        cat_lbl.setStyleSheet(f"color: {t['text_muted']};")
        cat_lbl.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        hdr.addWidget(cat_lbl)

        title_text = getattr(rec, "title", rec.get("title", "")
                             if isinstance(rec, dict) else "")
        title_lbl = QLabel(title_text)
        title_lbl.setObjectName("recCardTitle")
        title_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {t['text_primary']};")
        title_lbl.setWordWrap(True)
        title_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        hdr.addWidget(title_lbl, 1)

        priority = getattr(rec, "priority", rec.get("priority", "LOW")
                           if isinstance(rec, dict) else "LOW")
        bg, fg = _PRIORITY_COLORS.get(priority, ("#F3F4F6", "#374151"))
        badge = QLabel(priority)
        badge.setObjectName("recCardBadge")
        badge.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedWidth(80)
        badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        badge.setStyleSheet(
            f"background-color: {bg}; color: {fg};"
            " border-radius: 4px; padding: 3px 8px;")
        hdr.addWidget(badge)

        card_l.addLayout(hdr)

        # Row 2: Description
        desc = getattr(rec, "description", rec.get("description", "")
                       if isinstance(rec, dict) else "")
        if desc:
            desc_lbl = QLabel(desc)
            desc_lbl.setObjectName("recCardDesc")
            desc_lbl.setFont(QFont("Segoe UI", 10))
            desc_lbl.setStyleSheet(f"color: {t['text_secondary']};")
            desc_lbl.setWordWrap(True)
            desc_lbl.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
            card_l.addWidget(desc_lbl)

        # Action steps
        steps = getattr(rec, "action_steps", rec.get("action_steps", [])
                        if isinstance(rec, dict) else [])
        for i, step in enumerate(steps, 1):
            step_lbl = QLabel(f"  {i}. {step}")
            step_lbl.setFont(QFont("Segoe UI", 9))
            step_lbl.setStyleSheet(f"color: {t['text_muted']};")
            step_lbl.setWordWrap(True)
            step_lbl.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
            card_l.addWidget(step_lbl)

        return card

    @staticmethod
    def _update_rec_card(card: QWidget, rec) -> None:
        """Update an existing recommendation card's text in place."""
        title_lbl = card.findChild(QLabel, "recCardTitle")
        if title_lbl:
            title_lbl.setText(
                getattr(rec, "title", rec.get("title", "")
                        if isinstance(rec, dict) else ""))

        cat_lbl = card.findChild(QLabel, "recCardCategory")
        if cat_lbl:
            category = getattr(rec, "category", rec.get("category", "")
                               if isinstance(rec, dict) else "")
            cat_lbl.setText(f"[{category}]")

        badge = card.findChild(QLabel, "recCardBadge")
        if badge:
            priority = getattr(rec, "priority", rec.get("priority", "LOW")
                               if isinstance(rec, dict) else "LOW")
            bg, fg = _PRIORITY_COLORS.get(priority, ("#F3F4F6", "#374151"))
            badge.setText(priority)
            badge.setStyleSheet(
                f"background-color: {bg}; color: {fg};"
                " border-radius: 4px; padding: 3px 8px;")

        desc_lbl = card.findChild(QLabel, "recCardDesc")
        desc = getattr(rec, "description", rec.get("description", "")
                       if isinstance(rec, dict) else "")
        if desc_lbl:
            desc_lbl.setText(desc)

        card.adjustSize()

    # ── Session toggle ───────────────────────────────────────────────

    def _toggle_session(self):
        if self.data_bridge is None:
            return
        if self.data_bridge.is_session_running():
            self.data_bridge.stop_session()
        else:
            self.data_bridge.start_session()

    # ── Export handlers ──────────────────────────────────────────────

    def _export_json(self):
        self._do_export("json")

    def _export_txt(self):
        self._do_export("txt")

    def _do_export(self, fmt: str):
        try:
            from modules.reporting import ReportGenerator
            from modules.hardening import HardeningAdvisor

            generator = ReportGenerator()

            score = getattr(self, "_last_score", None)
            wifi = getattr(self, "_last_wifi", None)
            beh = getattr(self, "_last_behavioral", None)
            web = getattr(self, "_last_web", None)
            recs = getattr(self, "_last_recs", [])

            if score is None:
                QMessageBox.warning(
                    self, "No Data",
                    "No scan data available yet. Wait for at least one scan cycle.")
                return

            session_start = ""
            session_end = datetime.now(timezone.utc).isoformat()
            if self.data_bridge:
                session_start = self.data_bridge.get_session_start()

            report = generator.generate_session_report(
                wifi_report=wifi,
                behavioral_report=beh,
                web_report=web,
                threat_score=score,
                session_start=session_start,
                session_end=session_end,
                hardening_recommendations=recs,
            )

            # Default save path
            report_dir = getattr(config, "REPORT_DIR",
                                 config.DATA_DIR / "reports")
            report_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"report_{ts}.{fmt}"
            default_path = str(report_dir / default_name)

            # File dialog
            if fmt == "json":
                filt = "JSON Files (*.json)"
            else:
                filt = "Text Files (*.txt)"

            path, _ = QFileDialog.getSaveFileName(
                self, f"Save {fmt.upper()} Report",
                default_path, filt)

            if not path:
                return

            if fmt == "json":
                generator.export_json(report, path)
            else:
                generator.export_txt(report, path)

            self._export_status.setText(f"✓ Saved: {Path(path).name}")
            self._refresh_history()

        except Exception as exc:
            log.error("Export failed: %s", exc)
            QMessageBox.critical(self, "Export Error", str(exc))

    # ── History refresh ──────────────────────────────────────────────

    def _refresh_history(self):
        """Reload report history from disk."""
        t = _t()

        # Clear container
        while self._history_container.count():
            child = self._history_container.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        try:
            from modules.reporting import ReportGenerator
            gen = ReportGenerator()
            history = gen.get_report_history()

            if not history:
                lbl = QLabel("  No saved reports yet.")
                lbl.setFont(QFont("Segoe UI", 11))
                lbl.setStyleSheet(f"color: {t['text_muted']};")
                self._history_container.addWidget(lbl)
                return

            for report in history[:10]:
                row = self._build_history_row(report)
                self._history_container.addWidget(row)

        except Exception as exc:
            log.error("History load failed: %s", exc)

    @staticmethod
    def _build_history_row(report) -> QWidget:
        t = _t()
        row = GlassFrame()
        row_l = QHBoxLayout(row)
        row_l.setContentsMargins(18, 10, 18, 10)
        row_l.setSpacing(16)

        # Timestamp
        from modules.reporting import _format_time
        ts_lbl = QLabel(_format_time(report.generated_at))
        ts_lbl.setFont(QFont("Segoe UI", 11))
        ts_lbl.setStyleSheet(f"color: {t['text_primary']};")
        ts_lbl.setFixedWidth(140)
        row_l.addWidget(ts_lbl)

        # Verdict
        verdict = report.overall_verdict
        v_colors = {
            "SAFE": ("#D1FAE5", "#065F46"),
            "LOW RISK": ("#FEF3C7", "#92400E"),
            "ELEVATED": ("#FED7AA", "#9A3412"),
            "HIGH RISK": ("#FEE2E2", "#991B1B"),
            "CRITICAL": ("#FEE2E2", "#7F1D1D"),
        }
        bg, fg = v_colors.get(verdict, ("#F3F4F6", "#374151"))
        v_lbl = QLabel(verdict)
        v_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        v_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v_lbl.setFixedWidth(90)
        v_lbl.setStyleSheet(
            f"background-color: {bg}; color: {fg};"
            " border-radius: 4px; padding: 3px 8px;")
        row_l.addWidget(v_lbl)

        # Unified score
        unified = report.threat_score_summary.get("unified_score", 0)
        score_lbl = QLabel(f"Score: {int(unified)}/100")
        score_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        score_lbl.setStyleSheet(f"color: {t['text_secondary']};")
        row_l.addWidget(score_lbl)

        # Duration
        dur = report.duration_minutes
        dur_lbl = QLabel(f"{dur:.1f} min")
        dur_lbl.setFont(QFont("Segoe UI", 10))
        dur_lbl.setStyleSheet(f"color: {t['text_muted']};")
        row_l.addWidget(dur_lbl)

        # Report ID
        id_lbl = QLabel(f"#{report.report_id}")
        id_lbl.setFont(QFont("Consolas", 9))
        id_lbl.setStyleSheet(f"color: {t['text_muted']};")
        row_l.addWidget(id_lbl)

        row_l.addStretch()
        return row
