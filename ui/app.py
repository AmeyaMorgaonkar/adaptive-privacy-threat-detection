import customtkinter as ctk
from ui.theme import apply_theme, get_card_tokens
from ui.navigation import Sidebar, Header
from ui.data_bridge import DataBridge
from utils.config_manager import ConfigManager
from ui.pages import DashboardPage, WiFiSecurityPage, BehaviourAnalysisPage, WebTrackingPage, AllActionsPage, NetworkLogsPage, SettingsPage

class App(ctk.CTk):
    def __init__(self, data_bridge: DataBridge):
        super().__init__()
        self.title("Sentinel Dashboard")
        self.geometry("1440x950")
        self.minsize(1100, 768)
        
        self.config_manager = ConfigManager()
        # Force a very specific theme as requested
        ctk.set_appearance_mode("Light")
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ── Sidebar ──
        self.sidebar_frame = Sidebar(self, self)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        # ── Main container ──
        self.main_container = ctk.CTkFrame(self, fg_color="#F9FAFB", corner_radius=0)
        self.main_container.grid(row=0, column=1, sticky="nsew")
        self.main_container.grid_rowconfigure(1, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        # ── Header ──
        self.header = Header(self.main_container)
        self.header.grid(row=0, column=0, sticky="ew", padx=(40, 28), pady=(25, 0))

        # ── Scrollable content area ──
        self.content_frame = ctk.CTkScrollableFrame(
            self.main_container, fg_color="transparent",
            scrollbar_button_color="#CBD5E1",
            scrollbar_button_hover_color="#94A3B8",
        )
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 10))
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Keep content breathing room while allowing scrollbar to sit on the outer edge.
        self.content_body = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.content_body.grid(row=0, column=0, sticky="nsew", padx=(40, 26), pady=(2, 0))
        self.content_body.grid_columnconfigure(0, weight=1)

        self.pages = {}
        self.data_bridge = data_bridge
        
        self.pages["Dashboard"] = DashboardPage(self.content_body, self.data_bridge)
        self.pages["WiFi Security"] = WiFiSecurityPage(self.content_body)
        self.pages["Behaviour Analysis"] = BehaviourAnalysisPage(self.content_body)
        self.pages["Web Tracking"] = WebTrackingPage(self.content_body)
        self.pages["All Actions"] = AllActionsPage(self.content_body)
        self.pages["Network Logs"] = NetworkLogsPage(self.content_body)
        self.pages["Settings"] = SettingsPage(self.content_body)

        self.show_page("Dashboard")

    def show_page(self, page_name):
        for page in self.pages.values():
            page.grid_forget()
        self.pages[page_name].grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.set_active(page_name)
        self.header.set_title(page_name)

    def configure(self, **kwargs):
        super().configure(**kwargs)
        if "fg_color" in kwargs:
            self.sidebar_frame.configure(fg_color=get_card_tokens()["bg_sidebar"])
