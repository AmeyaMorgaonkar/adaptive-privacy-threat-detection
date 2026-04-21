import customtkinter as ctk
import config
from utils.config_manager import ConfigManager
from ui.glass_frame import GlassFrame
from ui.theme import get_card_tokens

class SettingsPanelPage(ctk.CTkFrame):
    def __init__(self, master, config_manager: ConfigManager):
        super().__init__(master, fg_color="transparent")
        self.config_manager = config_manager
        
        self.card = GlassFrame(self)
        self.card.pack(fill="both", expand=True)

        ctk.CTkLabel(self.card, text="Settings", font=("Segoe UI", 24, "bold"), text_color=get_card_tokens()["text_primary"]).pack(anchor="w", padx=30, pady=(30, 20))
        
        self.tabs = ctk.CTkTabview(self.card, fg_color="transparent")
        self.tabs.pack(fill="both", expand=True, padx=30, pady=(0, 30))

        self._build_appearance_tab()

    def _build_appearance_tab(self):
        tab = self.tabs.add("Appearance")

        ctk.CTkLabel(tab, text="Theme Mode", font=("Segoe UI", 14, "bold"), text_color=get_card_tokens()["text_primary"]).pack(anchor="w", pady=(20, 5))
        self.mode_menu = ctk.CTkOptionMenu(
            tab,
            values=["Light", "Dark", "System"],
            font=("Segoe UI", 13),
            command=self._on_mode_change,
        )
        current_mode = self.config_manager.get("APPEARANCE_MODE", "System")
        self.mode_menu.set(current_mode.title())
        self.mode_menu.pack(anchor="w")

        ctk.CTkLabel(
            tab,
            text="Glassmorphism Effect",
            font=("Segoe UI", 14, "bold"),
            text_color=get_card_tokens()["text_primary"]
        ).pack(anchor="w", pady=(30, 5))

        ctk.CTkLabel(
            tab,
            text="Gives cards a floating glass look.\nLight mode: white cards over off-white canvas.\nDark mode: translucent slate cards with a lit rim edge.",
            text_color="gray",
            justify="left",
            font=("Segoe UI", 13)
        ).pack(anchor="w")

        self.glass_switch = ctk.CTkSwitch(
            tab,
            text="Enable glass effect",
            font=("Segoe UI", 13),
            command=self._on_glass_toggle,
        )
        self.glass_switch.pack(anchor="w", pady=(15, 0))
        if self.config_manager.get("GLASSMORPHISM_ENABLED"):
            self.glass_switch.select()

    def _on_mode_change(self, value: str):
        mode = value.lower()
        ctk.set_appearance_mode(mode)
        self.config_manager.set("APPEARANCE_MODE", mode)
        GlassFrame.refresh_all()

    def _on_glass_toggle(self):
        enabled = self.glass_switch.get() == 1
        self.config_manager.set("GLASSMORPHISM_ENABLED", enabled)
        GlassFrame.refresh_all()

