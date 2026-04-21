import customtkinter as ctk
import tkinter as tk
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import scipy.interpolate as interpolate
from ui.theme import get_card_tokens, TIER_COLORS
from ui.glass_frame import GlassFrame

class StatCard(GlassFrame):
    def __init__(self, master, title, value="--", delta=None, icon="📈", **kwargs):
        super().__init__(master, **kwargs)
        
        header_fr = ctk.CTkFrame(self, fg_color="transparent")
        header_fr.pack(fill="x", padx=20, pady=(20, 5))
        ctk.CTkLabel(header_fr, text=title, font=("Segoe UI", 14, "bold"), text_color=get_card_tokens()["text_secondary"]).pack(side="left")
        ctk.CTkLabel(header_fr, text=icon, font=("Segoe UI", 16)).pack(side="right")
        
        self.val_lbl = ctk.CTkLabel(self, text=value, font=("Segoe UI", 38, "bold"), text_color=get_card_tokens()["text_primary"])
        self.val_lbl.pack(anchor="w", padx=20, pady=(0, 5))
        
        self.delta_lbl = None
        if delta is not None:
            delta_color = "#10B981" if "safe" in delta.lower() or "scanning" in delta.lower() else "#F59E0B"
            self.delta_lbl = ctk.CTkLabel(self, text=delta, font=("Segoe UI", 12, "bold"), text_color=delta_color)
            self.delta_lbl.pack(anchor="w", padx=20, pady=(0, 20))
        else:
            ctk.CTkFrame(self, height=20, fg_color="transparent").pack()

    def update_val(self, value, delta=None):
        self.val_lbl.configure(text=value)
        if self.delta_lbl and delta:
            self.delta_lbl.configure(text=delta)

class CircularGauge(ctk.CTkFrame):
    def __init__(self, master, size=180, **kwargs):
        self._gauge_size = size
        super().__init__(master, fg_color="transparent", **kwargs)
        self._bg_color = get_card_tokens()["card_bg"]
        self.canvas = tk.Canvas(self, width=self._gauge_size, height=self._gauge_size, bg=self._bg_color, highlightthickness=0)
        self.canvas.pack(expand=True, fill="both")
        self.score = 0
        self.color = TIER_COLORS["Safe"]["fg"]
        self.after(50, self._draw)
        
    def update_score(self, score, color):
        self.score = score
        self.color = color
        self._bg_color = get_card_tokens()["card_bg"]
        self.canvas.configure(bg=self._bg_color)
        self.canvas.delete("all")
        self._draw()

    def _draw(self, *args, **kwargs):
        if not hasattr(self, "canvas"):
            return
        cx, cy = self._gauge_size / 2, self._gauge_size / 2 + 30
        r = self._gauge_size / 2 - 20
        outline_col = get_card_tokens()["card_border"]
        self.canvas.create_arc(cx-r, cy-r, cx+r, cy+r, start=0, extent=180, outline=outline_col, width=16, style=tk.ARC)
        extent = (self.score / 100.0) * 180
        if extent > 180: extent = 180
        self.canvas.create_arc(cx-r, cy-r, cx+r, cy+r, start=180, extent=-extent, outline=self.color, width=16, style=tk.ARC)
        self.canvas.create_text(cx, cy - 20, text=f"{int(self.score)}", font=("Segoe UI", 42, "bold"), fill=get_card_tokens()["text_primary"])
        self.canvas.create_text(cx, cy + 15, text="Threat Score", font=("Segoe UI", 12), fill=get_card_tokens()["text_secondary"])

class CircularGaugeCard(GlassFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.pack_propagate(False)
        ctk.CTkLabel(self, text="Overall Threat", font=("Segoe UI", 16, "bold"), text_color=get_card_tokens()["text_primary"]).pack(anchor="w", padx=20, pady=(20, 0))
        self.gauge = CircularGauge(self, size=180)
        self.gauge.pack(pady=(15, 10))
        self.pill = SeverityPill(self, tier="Safe")
        self.pill.pack(pady=(0, 20))
        
    def update_score(self, score, tier, color):
        self.gauge.update_score(score, color)
        self.pill.set_tier(tier)

class ModuleProgressBar(ctk.CTkFrame):
    def __init__(self, master, label_text="Module", **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", pady=(0, 5))
        self.lbl = ctk.CTkLabel(header, text=label_text, font=("Segoe UI", 13, "bold"), text_color=get_card_tokens()["text_secondary"])
        self.lbl.pack(side="left")
        self.pct = ctk.CTkLabel(header, text="0%", font=("Consolas", 13, "bold"), text_color=get_card_tokens()["text_primary"])
        self.pct.pack(side="right")
        self.bar = ctk.CTkProgressBar(self, height=8, corner_radius=4)
        self.bar.pack(fill="x")
        self.bar.set(0)
        
    def update_val(self, score_100, color):
        self.pct.configure(text=f"{int(score_100)}%")
        self.bar.set(score_100 / 100.0)
        self.bar.configure(progress_color=color)

class SeverityPill(ctk.CTkFrame):
    def __init__(self, master, tier="Safe", **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.lbl = ctk.CTkLabel(self, text=tier.upper(), font=("Segoe UI", 12, "bold"), corner_radius=8)
        self.lbl.pack(ipadx=12, ipady=4)
        self.set_tier(tier)
        
    def set_tier(self, tier):
        tconf = TIER_COLORS.get(tier, TIER_COLORS["Safe"])
        self.lbl.configure(text=tier.upper(), text_color=tconf["text"], fg_color=tconf["bg_tint"])

class TimelineGraph(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.fig = Figure(figsize=(5, 3), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.fig.patch.set_alpha(0)
        self.ax.patch.set_alpha(0)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self._bg_col = ""
        
    def update_data(self, history):
        self.ax.clear()
        tokens = get_card_tokens()
        curr_bg = tokens["card_bg"]
        if self._bg_col != curr_bg:
            self._bg_col = curr_bg
            self.canvas.get_tk_widget().configure(bg=curr_bg)
            
        self.ax.tick_params(colors=tokens["text_secondary"])
        for spine in self.ax.spines.values():
            spine.set_color("none")
        self.ax.spines["bottom"].set_color(tokens["card_border"])
        self.ax.spines["bottom"].set_visible(True)
        
        if len(history) < 2:
            self.canvas.draw()
            return
            
        y = [float(s.unified_score) for s in history]
        x = np.arange(len(y))
        
        if len(x) >= 4:
            x_new = np.linspace(x.min(), x.max(), 100)
            spl = interpolate.make_interp_spline(x, y, k=3)
            y_new = spl(x_new)
            y_new = np.clip(y_new, 0, 100)
        else:
            x_new = x
            y_new = y
            
        color = TIER_COLORS["Low Risk"]["fg"]
        if y[-1] >= 90: color = TIER_COLORS["Critical"]["fg"]
        elif y[-1] >= 75: color = TIER_COLORS["High Risk"]["fg"]
        elif y[-1] >= 50: color = TIER_COLORS["Elevated"]["fg"]
            
        self.ax.plot(x_new, y_new, color=color, linewidth=3)
        self.ax.fill_between(x_new, y_new, 0, color=color, alpha=0.15)
        self.ax.set_ylim(0, 105)
        self.ax.set_xticks([])
        self.fig.tight_layout()
        self.canvas.draw()

