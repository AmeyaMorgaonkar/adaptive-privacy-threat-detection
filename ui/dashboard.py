import customtkinter as ctk
from ui.glass_frame import GlassFrame
from ui.data_bridge import DataBridge
from modules.threat_scoring import ThreatScore
from ui.components import StatCard, CircularGaugeCard, ModuleProgressBar, TimelineGraph
from ui.theme import get_card_tokens, TIER_COLORS

class Dashboard(ctk.CTkFrame):
    def __init__(self, master, data_bridge: DataBridge):
        super().__init__(master, fg_color="transparent")
        self.data_bridge = data_bridge
        self._build_layout()

    def _build_layout(self):
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure((0, 1, 2), weight=1)

        # Row 0: 3 Stat Cards
        self.wifi_stat = StatCard(self, title="Wi-Fi Security", value="--", delta="Scanning", icon="📡")
        self.wifi_stat.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 20))
        self.behav_stat = StatCard(self, title="System Behavior", value="--", delta="Active", icon="🧠")
        self.behav_stat.grid(row=0, column=1, sticky="nsew", padx=10, pady=(0, 20))
        self.web_stat = StatCard(self, title="Web Trackers", value="--", delta="Monitoring", icon="🌐")
        self.web_stat.grid(row=0, column=2, sticky="nsew", padx=(10, 0), pady=(0, 20))

        # Row 1: Graph + Gauge
        self.graph_card = GlassFrame(self)
        self.graph_card.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=(0, 10), pady=(0, 20))
        ctk.CTkLabel(self.graph_card, text="Threat Timeline", font=("Segoe UI", 18, "bold"), text_color=get_card_tokens()["text_primary"]).pack(anchor="w", padx=30, pady=(20, 0))
        self.timeline = TimelineGraph(self.graph_card)
        self.timeline.pack(fill="both", expand=True, padx=30, pady=(10, 25))

        self.gauge_card = CircularGaugeCard(self)
        self.gauge_card.grid(row=1, column=2, sticky="nsew", padx=(10, 0), pady=(0, 20))

        # Row 2: Active Threats + Module Load
        self.threats_card = GlassFrame(self)
        self.threats_card.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=(0, 10))
        ctk.CTkLabel(self.threats_card, text="Active Threats", font=("Segoe UI", 18, "bold"), text_color=get_card_tokens()["text_primary"]).pack(anchor="w", padx=30, pady=(20, 10))
        self.threats_list = ctk.CTkLabel(self.threats_card, text="No active threats logged.", font=("Consolas", 14), justify="left", anchor="nw")
        self.threats_list.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        self.progress_card = GlassFrame(self)
        self.progress_card.grid(row=2, column=2, sticky="nsew", padx=(10, 0))
        ctk.CTkLabel(self.progress_card, text="Module Load", font=("Segoe UI", 18, "bold"), text_color=get_card_tokens()["text_primary"]).pack(anchor="w", padx=30, pady=(20, 20))
        self.web_bar = ModuleProgressBar(self.progress_card, label_text="Network Scans")
        self.web_bar.pack(fill="x", padx=30, pady=(0, 20))
        self.behav_bar = ModuleProgressBar(self.progress_card, label_text="Proc Analysis")
        self.behav_bar.pack(fill="x", padx=30, pady=(0, 20))

    def refresh(self):
        score = self.data_bridge.latest()
        if score:
            self._update_score_card(score)
            self._update_module_cards(score)
            self._update_history_card()
            self._update_threats_card(score)

    def _update_score_card(self, score: ThreatScore): 
        color = TIER_COLORS.get(score.tier, TIER_COLORS["Safe"])["fg"]
        self.gauge_card.update_score(score.unified_score, score.tier, color)
        
    def _update_module_cards(self, score: ThreatScore):
        self.wifi_stat.update_val(f"{score.wifi_score:.0f}")
        self.behav_stat.update_val(f"{score.behavioral_score:.0f}")
        
        self.web_bar.update_val(score.web_score, TIER_COLORS.get(score.tier, TIER_COLORS["Safe"])["fg"])
        self.behav_bar.update_val(score.behavioral_score, TIER_COLORS.get(score.tier, TIER_COLORS["Safe"])["fg"])

    def _update_history_card(self):
        history = self.data_bridge.history(n=20)
        self.timeline.update_data(history)

    def _update_threats_card(self, score: ThreatScore):
        if not score.active_threats:
            self.threats_list.configure(text="No active threats logged.", text_color="#10B981")
        else:
            text = "\n\n".join(f"• {t}" for t in score.active_threats[:4])
            color = TIER_COLORS.get(score.tier, TIER_COLORS["Safe"])["fg"]
            self.threats_list.configure(text=text, text_color=color)

