import customtkinter as ctk
from ui.theme import get_card_tokens
from ui.glass_frame import GlassFrame

class Sidebar(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        tokens = get_card_tokens()
        super().__init__(master, width=240, fg_color=tokens["bg_sidebar"], corner_radius=0, **kwargs)
        self.pack_propagate(False)
        self.grid_propagate(False)
        self.app = app
        self.buttons = {}
        
        # Right-side border line
        self.configure(border_width=0)
        
        # Logo Section
        logo_fr = ctk.CTkFrame(self, fg_color="transparent")
        logo_fr.pack(pady=(35, 5), padx=25, anchor="w", fill="x")
        ctk.CTkLabel(logo_fr, text="🛡️", font=("Segoe UI", 24)).pack(side="left")
        ctk.CTkLabel(logo_fr, text=" Sentinel", font=("Segoe UI", 20, "bold"), text_color="#10B981").pack(side="left")
        
        ctk.CTkLabel(self, text="    Tactical Security", font=("Segoe UI", 11), text_color=tokens["text_muted"]).pack(anchor="w", padx=25, pady=(0, 30))

        # Top Navigation Items
        self.add_nav_item("Dashboard", "⊞")
        self.add_nav_item("WiFi Security", "◉")
        self.add_nav_item("Behaviour Analysis", "◎")
        self.add_nav_item("Web Tracking", "◈")
        self.add_nav_item("All Actions", "⚡")
        
        # Bottom section
        bottom_fr = ctk.CTkFrame(self, fg_color="transparent")
        bottom_fr.pack(side="bottom", fill="x", pady=(0, 25))
        
        btn1 = self._make_btn(bottom_fr, "Network Logs", "▣")
        btn1.pack(fill="x", padx=12, pady=2, ipady=10)
        self.buttons["Network Logs"] = btn1
        
        btn2 = self._make_btn(bottom_fr, "Settings", "⚙")
        btn2.pack(fill="x", padx=12, pady=2, ipady=10)
        self.buttons["Settings"] = btn2

    def add_nav_item(self, name, icon):
        btn = self._make_btn(self, name, icon)
        btn.pack(fill="x", padx=12, pady=2, ipady=10)
        self.buttons[name] = btn
        
    def _make_btn(self, parent, name, icon):
        tokens = get_card_tokens()
        return ctk.CTkButton(
            parent, text=f"  {icon}   {name}", 
            anchor="w", font=("Segoe UI", 14), 
            fg_color="transparent", 
            text_color=tokens["text_secondary"],
            hover_color="#F0FDF4",
            corner_radius=10,
            height=38,
            command=lambda n=name: self.app.show_page(n)
        )

    def set_active(self, page_name):
        tokens = get_card_tokens()
        for name, btn in self.buttons.items():
            if name == page_name:
                btn.configure(
                    fg_color="#F0FDF4", 
                    text_color="#10B981", 
                    font=("Segoe UI", 14, "bold")
                )
            else:
                btn.configure(
                    fg_color="transparent", 
                    text_color=tokens["text_secondary"], 
                    font=("Segoe UI", 14)
                )


class Header(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", height=60, **kwargs)
        tokens = get_card_tokens()

        self.title_lbl = ctk.CTkLabel(
            self, text="Dashboard", 
            font=("Segoe UI", 22, "bold"), 
            text_color=tokens["text_primary"]
        )
        self.title_lbl.pack(side="left", pady=10)

        self.support_btn = ctk.CTkButton(
            self, text="Support", width=95, height=36, 
            corner_radius=8, font=("Segoe UI", 13, "bold"),
            fg_color="transparent", 
            border_color="#D1D5DB",
            border_width=1,
            hover_color="#F3F4F6", 
            text_color="#374151"
        )
        self.support_btn.pack(side="right", padx=5)

    def set_title(self, title):
        self.title_lbl.configure(text=title)

