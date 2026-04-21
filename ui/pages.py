"""
All page views for the Sentinel dashboard.
Each page matches the corresponding design mockup from /designs/stitch/.
"""
import customtkinter as ctk
import tkinter as tk
from ui.glass_frame import GlassFrame
from ui.theme import get_card_tokens, PILL_COLORS, TIER_COLORS

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SHARED HELPER FUNCTIONS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _t():
    """Shorthand for current tokens."""
    return get_card_tokens()

def pill_lbl(master, text, color_type=None):
    """Create a tinted status pill / badge label."""
    if color_type is None:
        color_type = text
    bg, fg = PILL_COLORS.get(color_type.upper(), ("#F3F4F6", "#374151"))
    lbl = ctk.CTkLabel(master, text=text, font=("Segoe UI", 11, "bold"),
                        fg_color=bg, text_color=fg, corner_radius=6)
    return lbl

def stat_card(master, title, value, subtext="", value_color="#111827",
              value_size=36, top_icon=None, subtext_color=None):
    """Re-usable stat card matching the design spec."""
    f = GlassFrame(master)
    # Header row
    top = ctk.CTkFrame(f, fg_color="transparent")
    top.pack(fill="x", padx=22, pady=(22, 4))
    ctk.CTkLabel(top, text=title.upper(), font=("Segoe UI", 11, "bold"),
                 text_color="#9CA3AF", anchor="w").pack(side="left")
    if top_icon:
        ctk.CTkLabel(top, text=top_icon, font=("Segoe UI", 16)).pack(side="right")
    # Value
    val_fr = ctk.CTkFrame(f, fg_color="transparent")
    val_fr.pack(fill="x", padx=22, pady=(2, 0))
    ctk.CTkLabel(val_fr, text=str(value), font=("Segoe UI", value_size, "bold"),
                 text_color=value_color, anchor="w").pack(side="left")
    if "Score" in title or "SCORE" in title:
        ctk.CTkLabel(val_fr, text="/100", font=("Segoe UI", 14),
                     text_color="#9CA3AF").pack(side="left", pady=(12, 0))
    # Subtext
    if subtext:
        sc = subtext_color or "#9CA3AF"
        if "ELEVATED" in subtext.upper():
            sc = "#F59E0B"
        elif "SAFE" in subtext.upper() or "OPTIMAL" in subtext.upper():
            sc = "#10B981"
        elif "Requires" in subtext:
            sc = "#F59E0B"
        ctk.CTkLabel(f, text=subtext, font=("Segoe UI", 12),
                     text_color=sc, wraplength=250, justify="left",
                     anchor="w").pack(anchor="w", padx=22, pady=(4, 22))
    else:
        ctk.CTkFrame(f, height=18, fg_color="transparent").pack()
    return f

def section_header(master, title, right_text=None, right_color="#10B981",
                   right_command=None):
    """Header bar inside a card: bold title on left, optional link on right."""
    fr = ctk.CTkFrame(master, fg_color="transparent")
    fr.pack(fill="x", padx=22, pady=(22, 12))
    ctk.CTkLabel(fr, text=title, font=("Segoe UI", 16, "bold"),
                 text_color="#111827").pack(side="left")
    if right_text:
        if right_command:
            ctk.CTkButton(fr, text=right_text, font=("Segoe UI", 13, "bold"),
                          text_color=right_color, fg_color="transparent",
                          hover_color="#F0FDF4", command=right_command,
                          width=10).pack(side="right")
        else:
            ctk.CTkLabel(fr, text=right_text, font=("Segoe UI", 13, "bold"),
                         text_color=right_color).pack(side="right")
    return fr

def table_header(master, columns):
    """Render a light-gray column header row + divider."""
    fr = ctk.CTkFrame(master, fg_color="transparent")
    fr.pack(fill="x", padx=22, pady=(0, 0))
    for width, text in columns:
        ctk.CTkLabel(fr, text=text.upper(), font=("Segoe UI", 11, "bold"),
                     text_color="#9CA3AF", width=width, anchor="w"
                     ).pack(side="left", padx=(0, 5))
    ctk.CTkFrame(master, height=1, fg_color="#E5E7EB").pack(fill="x", padx=22, pady=(8, 0))

def table_row(parent, cells):
    """Render one data row.  Each cell is (width, text, style).
    style: 'normal' | 'bold' | 'light' | 'pill' | 'mono' | 'trash'
    """
    fr = ctk.CTkFrame(parent, fg_color="transparent")
    fr.pack(fill="x", padx=22, pady=8)
    for item in cells:
        w, t = item[0], item[1]
        style = item[2] if len(item) > 2 else "normal"
        if style == "pill":
            p = pill_lbl(fr, t, t)
            p.pack(side="left", padx=(0, 10), ipadx=8, ipady=2)
        elif style == "trash":
            ctk.CTkLabel(fr, text="🗑️", font=("Segoe UI", 14), width=w,
                         anchor="w").pack(side="left")
        else:
            font = ("Segoe UI", 13)
            col = "#111827"
            if style == "bold":
                font = ("Segoe UI", 13, "bold")
            elif style == "light":
                col = "#6B7280"
            elif style == "mono":
                font = ("Consolas", 12)
                col = "#6B7280"
            ctk.CTkLabel(fr, text=t, font=font, text_color=col,
                         width=w, anchor="w").pack(side="left", padx=(0, 5))

def action_card(parent, icon, title, subtitle, badge_text=None):
    """Recommended-action row card used on multiple pages."""
    fr = ctk.CTkFrame(parent, fg_color="#F9FAFB", corner_radius=10)
    fr.pack(fill="x", padx=22, pady=(0, 10))
    # Icon box
    ib = ctk.CTkFrame(fr, fg_color="#E5E7EB", width=38, height=38, corner_radius=8)
    ib.pack(side="left", padx=(15, 12), pady=14)
    ib.pack_propagate(False)
    ctk.CTkLabel(ib, text=icon, font=("Segoe UI", 16)).place(relx=0.5, rely=0.5, anchor="center")
    # Text
    txt = ctk.CTkFrame(fr, fg_color="transparent")
    txt.pack(side="left", pady=14, fill="x", expand=True)
    ctk.CTkLabel(txt, text=title, font=("Segoe UI", 13, "bold"),
                 text_color="#111827", anchor="w").pack(anchor="w")
    ctk.CTkLabel(txt, text=subtitle, font=("Segoe UI", 11),
                 text_color="#6B7280", anchor="w", wraplength=320,
                 justify="left").pack(anchor="w")
    # Badge / chevron
    if badge_text:
        pill_lbl(fr, badge_text, badge_text).pack(side="right", padx=15, ipadx=8, ipady=2)
    else:
        ctk.CTkLabel(fr, text="›", font=("Segoe UI", 20),
                     text_color="#9CA3AF").pack(side="right", padx=15)

def mini_stat(parent, icon, value, label):
    """Small icon + value + label card for the 2Ã—2 grid on the dashboard."""
    f = GlassFrame(parent)
    ctk.CTkLabel(f, text=icon, font=("Segoe UI", 18),
                 text_color="#6B7280").pack(anchor="w", padx=18, pady=(18, 6))
    ctk.CTkLabel(f, text=str(value), font=("Segoe UI", 26, "bold"),
                 text_color="#111827").pack(anchor="w", padx=18)
    ctk.CTkLabel(f, text=label.upper(), font=("Segoe UI", 10, "bold"),
                 text_color="#9CA3AF", justify="left"
                 ).pack(anchor="w", padx=18, pady=(2, 18))
    return f

def progress_row(parent, label, pct_text, color, value):
    """Module threat score progress bar row."""
    fr = ctk.CTkFrame(parent, fg_color="transparent")
    fr.pack(fill="x", padx=22, pady=8)
    hdr = ctk.CTkFrame(fr, fg_color="transparent")
    hdr.pack(fill="x")
    ctk.CTkLabel(hdr, text=label, font=("Segoe UI", 13),
                 text_color="#111827").pack(side="left")
    ctk.CTkLabel(hdr, text=pct_text, font=("Segoe UI", 13, "bold"),
                 text_color="#111827").pack(side="right")
    pb = ctk.CTkProgressBar(fr, progress_color=color, height=8,
                            corner_radius=4)
    pb.pack(fill="x", pady=(5, 0))
    pb.set(value)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE: DASHBOARD
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, data_bridge):
        super().__init__(master, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)

        # â”€â”€ Page header â”€â”€
        h = ctk.CTkFrame(self, fg_color="transparent")
        h.pack(fill="x", pady=(0, 25))
        ctk.CTkLabel(h, text="Hi, Admin!", font=("Segoe UI", 30, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(h, text="Welcome back to your security overview. Here is the current status of your network.",
                     font=("Segoe UI", 14), text_color="#6B7280").pack(anchor="w", pady=(5, 0))

        # â”€â”€ Row 1: 4 stat cards â”€â”€
        r1 = ctk.CTkFrame(self, fg_color="transparent")
        r1.pack(fill="x", pady=(0, 15))
        r1.columnconfigure((0, 1, 2, 3), weight=1)

        stat_card(r1, "Overall Threat Score", "34", "ELEVATED",
              top_icon="🎯").grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        stat_card(r1, "Active Threats", "3", "Requires immediate attention",
              value_color="#EF4444", top_icon="⚠️").grid(row=0, column=1, sticky="nsew", padx=8)
        stat_card(r1, "Actions Taken", "12", "Resolved automatically",
              value_color="#10B981", top_icon="✅").grid(row=0, column=2, sticky="nsew", padx=8)
        stat_card(r1, "Last Scan", "2 mins ago", "System continuous monitoring",
              value_size=28, top_icon="⏱").grid(row=0, column=3, sticky="nsew", padx=(8, 0))

        # â”€â”€ Row 2: Module scores + Recommended actions â”€â”€
        r2 = ctk.CTkFrame(self, fg_color="transparent")
        r2.pack(fill="x", pady=(0, 15))
        r2.columnconfigure(0, weight=3)
        r2.columnconfigure(1, weight=2)

        m_card = GlassFrame(r2)
        m_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        section_header(m_card, "Module Threat Scores")
        progress_row(m_card, "WiFi", "28%", "#10B981", 0.28)
        progress_row(m_card, "Web", "76%", "#EF4444", 0.76)
        progress_row(m_card, "Behaviour Analysis", "61%", "#F59E0B", 0.61)
        ctk.CTkFrame(m_card, height=15, fg_color="transparent").pack()

        ra_card = GlassFrame(r2)
        ra_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        section_header(ra_card, "Recommended Actions")
        action_card(ra_card, "🛡️", "Update Firewall Rules", "Web module threshold met", "REVIEW")
        action_card(ra_card, "🔑", "Rotate API Keys", "Scheduled rotation due", "APPLY")
        action_card(ra_card, "🚫", "Block IP Range", "Suspicious behaviour detected", "REVIEW")
        ctk.CTkFrame(ra_card, height=8, fg_color="transparent").pack()

        # â”€â”€ Row 3: Recent alerts + stats grid â”€â”€
        r3 = ctk.CTkFrame(self, fg_color="transparent")
        r3.pack(fill="x", pady=(0, 15))
        r3.columnconfigure(0, weight=3)
        r3.columnconfigure(1, weight=1)

        al = GlassFrame(r3)
        al.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        section_header(al, "Recent Alerts", "View All")
        table_header(al, [(100, "Time"), (100, "Module"), (280, "Alert"), (100, "Severity")])
        table_row(al, [(100, "10:42 AM"), (100, "Behaviour", "bold"), (280, "Multiple failed admin logins"), (100, "CRITICAL", "pill")])
        table_row(al, [(100, "09:15 AM"), (100, "Web", "bold"), (280, "Unusual outbound traffic spike"), (100, "WARNING", "pill")])
        table_row(al, [(100, "08:03 AM"), (100, "WiFi", "bold"), (280, "New unauthorized device connected"), (100, "WARNING", "pill")])
        table_row(al, [(100, "07:22 AM"), (100, "System", "bold"), (280, "Routine definition update applied"), (100, "INFO", "pill")])
        ctk.CTkFrame(al, height=10, fg_color="transparent").pack()

        sg = ctk.CTkFrame(r3, fg_color="transparent")
        sg.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        sg.rowconfigure((0, 1), weight=1)
        sg.columnconfigure((0, 1), weight=1)
        mini_stat(sg, "🛑", "1,204", "Blocked Req.").grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 5))
        mini_stat(sg, "⚙️", "4", "Suspicious\nProc.").grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=(0, 5))
        mini_stat(sg, "📡", "8", "Networks\nScanned").grid(row=1, column=0, sticky="nsew", padx=(0, 5), pady=(5, 0))
        mini_stat(sg, "🔄", "3.2 GB", "Data Sent").grid(row=1, column=1, sticky="nsew", padx=(5, 0), pady=(5, 0))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE: WIFI SECURITY
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class WiFiSecurityPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")

        # â”€â”€ Page title row â”€â”€
        title_row = ctk.CTkFrame(self, fg_color="transparent")
        title_row.pack(fill="x", pady=(0, 20))
        t_left = ctk.CTkFrame(title_row, fg_color="transparent")
        t_left.pack(side="left")
        ctk.CTkLabel(t_left, text="WiFi Security", font=("Segoe UI", 26, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(t_left, text="Network threat analysis", font=("Segoe UI", 14),
                     text_color="#6B7280").pack(anchor="w", pady=(4, 0))
        # Threat pill
        pill_fr = ctk.CTkFrame(title_row, fg_color="#D1FAE5", corner_radius=20)
        pill_fr.pack(side="right", padx=5)
        ctk.CTkLabel(pill_fr, text="● 28 — Low Risk", font=("Segoe UI", 13, "bold"),
                     text_color="#065F46").pack(padx=16, pady=6)

        # â”€â”€ Row 1: 3 stat cards â”€â”€
        r1 = ctk.CTkFrame(self, fg_color="transparent")
        r1.pack(fill="x", pady=(0, 15))
        r1.columnconfigure((0, 1, 2), weight=1)

        # Connected Network card
        cn = GlassFrame(r1)
        cn.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        top = ctk.CTkFrame(cn, fg_color="transparent")
        top.pack(fill="x", padx=22, pady=(22, 4))
        ctk.CTkLabel(top, text="CONNECTED NETWORK", font=("Segoe UI", 11, "bold"),
                     text_color="#9CA3AF").pack(side="left")
        ctk.CTkLabel(top, text="📶", font=("Segoe UI", 16)).pack(side="right")
        ctk.CTkLabel(cn, text="HomeNet-5G", font=("Segoe UI", 28, "bold"),
                     text_color="#111827").pack(anchor="w", padx=22, pady=(2, 0))
        ctk.CTkLabel(cn, text="WPA3 Protocol", font=("Consolas", 12),
                     text_color="#6B7280").pack(anchor="w", padx=22, pady=(2, 10))
        btm_row = ctk.CTkFrame(cn, fg_color="transparent")
        btm_row.pack(fill="x", padx=22, pady=(0, 22))
        pill_lbl(btm_row, "💚 SECURE", "SAFE").pack(side="left", ipadx=8, ipady=2)
        ctk.CTkLabel(btm_row, text="Up: 4h 23m", font=("Segoe UI", 12),
                     text_color="#6B7280").pack(side="right")

        # Network Threat Score card (with canvas gauge)
        ns = GlassFrame(r1)
        ns.grid(row=0, column=1, sticky="nsew", padx=8)
        ctk.CTkLabel(ns, text="NETWORK THREAT SCORE", font=("Segoe UI", 11, "bold"),
                     text_color="#9CA3AF").pack(anchor="w", padx=22, pady=(22, 0))
        gc = tk.Canvas(ns, width=140, height=100, bg="#FFFFFF", highlightthickness=0)
        gc.pack(pady=(10, 0))
        cx, cy, r = 70, 75, 50
        gc.create_arc(cx-r, cy-r, cx+r, cy+r, start=0, extent=180, outline="#E5E7EB", width=12, style=tk.ARC)
        extent = (28 / 100) * 180
        gc.create_arc(cx-r, cy-r, cx+r, cy+r, start=180, extent=-extent, outline="#10B981", width=12, style=tk.ARC)
        gc.create_text(cx, cy - 18, text="28", font=("Segoe UI", 28, "bold"), fill="#111827")
        gc.create_text(cx, cy + 5, text="/100", font=("Segoe UI", 11), fill="#9CA3AF")
        ctk.CTkLabel(ns, text="STATUS: OPTIMAL", font=("Segoe UI", 12, "bold"),
                     text_color="#10B981").pack(pady=(5, 22))

        # Anomalies card
        stat_card(r1, "Anomalies Detected", "0",
                  "No unusual activity detected in the last 24 hours.",
                  value_color="#10B981", top_icon="✅"
                  ).grid(row=0, column=2, sticky="nsew", padx=(8, 0))

        # â”€â”€ Nearby Networks table â”€â”€
        net = GlassFrame(self)
        net.pack(fill="x", pady=(0, 15))
        section_header(net, "Nearby Networks", "SCAN NOW", "#10B981")
        table_header(net, [(180, "SSID"), (160, "Signal Strength"), (140, "Security Type"), (120, "Status"), (140, "First Seen")])
        networks = [
            ("HomeNet-5G", "â–‚â–ƒâ–…â–†â–‡", "WPA3", "SAFE", "2023-10-24 08:12", "bold"),
            ("Guest_WiFi_Exp", "â–‚â–ƒ    ", "OPEN", "SUSPICIOUS", "2023-10-24 09:45", "bold"),
            ("Starbucks_Free", "â–‚â–ƒâ–…   ", "WPA2", "UNKNOWN", "2023-10-24 10:02", "normal"),
            ("OfficeNet_Secure", "â–‚â–ƒâ–…â–†â–‡", "WPA2 Enterprise", "SAFE", "2023-10-24 07:30", "bold"),
            ("ASUS_Main_Floor", "â–‚â–ƒâ–…â–† ", "WPA3", "SAFE", "2023-10-23 15:21", "normal"),
            ("TP-Link_28A1", "â–‚â–ƒâ–…   ", "WPA2", "SAFE", "2023-10-22 21:05", "normal"),
        ]
        for ssid, sig, sec, status, seen, style in networks:
            table_row(net, [(180, ssid, style), (160, sig), (140, sec), (120, status, "pill"), (140, seen, "light")])

        # â”€â”€ Bottom: DNS Leak + Recommended Actions â”€â”€
        r3 = ctk.CTkFrame(self, fg_color="transparent")
        r3.pack(fill="x", pady=(0, 15))
        r3.columnconfigure(0, weight=1)
        r3.columnconfigure(1, weight=1)

        leak = GlassFrame(r3)
        leak.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        lt = ctk.CTkFrame(leak, fg_color="transparent")
        lt.pack(fill="x", padx=22, pady=(22, 0))
        ctk.CTkLabel(lt, text="DNS Leak Test", font=("Segoe UI", 16, "bold"),
                     text_color="#111827").pack(side="left")
        ctk.CTkButton(lt, text="RUN TEST", fg_color="transparent", border_color="#D1D5DB",
                      border_width=1, text_color="#374151", font=("Segoe UI", 12, "bold"),
                      width=90, height=32, corner_radius=6).pack(side="right")
        ctk.CTkLabel(leak, text="✅", font=("Segoe UI", 36)).pack(pady=(25, 5))
        ctk.CTkLabel(leak, text="No leaks detected", font=("Segoe UI", 18, "bold"),
                     text_color="#111827").pack()
        ctk.CTkLabel(leak, text="Your DNS requests are properly routed through\nyour secure gateway.",
                     font=("Segoe UI", 13), text_color="#6B7280", justify="center").pack(pady=(5, 30))

        ra = GlassFrame(r3)
        ra.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        section_header(ra, "Recommended Actions")
        action_card(ra, "🌍", "Enable VPN on public networks", "Encrypt traffic when away from home", "APPLY")
        action_card(ra, "🚫", "Block unknown device on network", "1 unrecognized device connected", "REVIEW")
        ctk.CTkFrame(ra, height=15, fg_color="transparent").pack()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE: BEHAVIOUR ANALYSIS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class BehaviourAnalysisPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")

        # â”€â”€ Title row â”€â”€
        tr = ctk.CTkFrame(self, fg_color="transparent")
        tr.pack(fill="x", pady=(0, 20))
        tl = ctk.CTkFrame(tr, fg_color="transparent")
        tl.pack(side="left")
        ctk.CTkLabel(tl, text="Behaviour Analysis", font=("Segoe UI", 26, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(tl, text="Process & application monitoring across the entire network node",
                     font=("Segoe UI", 14), text_color="#6B7280").pack(anchor="w", pady=(4, 0))
        pill_fr = ctk.CTkFrame(tr, fg_color="#FEF3C7", corner_radius=20)
        pill_fr.pack(side="right")
        ctk.CTkLabel(pill_fr, text="● 61 — Moderate Threat", font=("Segoe UI", 13, "bold"),
                     text_color="#92400E").pack(padx=16, pady=6)

        # â”€â”€ Row 1: 3 stat cards â”€â”€
        r1 = ctk.CTkFrame(self, fg_color="transparent")
        r1.pack(fill="x", pady=(0, 15))
        r1.columnconfigure((0, 1, 2), weight=1)

        stat_card(r1, "Behaviour Score", "61", "",
                  value_color="#F59E0B").grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        # Suspicious Processes with link
        sp = GlassFrame(r1)
        sp.grid(row=0, column=1, sticky="nsew", padx=8)
        top = ctk.CTkFrame(sp, fg_color="transparent")
        top.pack(fill="x", padx=22, pady=(22, 4))
        ctk.CTkLabel(top, text="SUSPICIOUS PROCESSES", font=("Segoe UI", 11, "bold"),
                     text_color="#9CA3AF").pack(side="left")
        ctk.CTkLabel(top, text="⚠️", font=("Segoe UI", 16)).pack(side="right")
        ctk.CTkLabel(sp, text="4 flagged", font=("Segoe UI", 36, "bold"),
                     text_color="#F59E0B").pack(anchor="w", padx=22)
        ctk.CTkLabel(sp, text="VIEW FLAGGED LIST →", font=("Segoe UI", 12, "bold"),
                     text_color="#10B981").pack(anchor="w", padx=22, pady=(5, 22))

        # Auto-actions
        aa = GlassFrame(r1)
        aa.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        top2 = ctk.CTkFrame(aa, fg_color="transparent")
        top2.pack(fill="x", padx=22, pady=(22, 4))
        ctk.CTkLabel(top2, text="AUTO-ACTIONS TAKEN", font=("Segoe UI", 11, "bold"),
                     text_color="#9CA3AF").pack(side="left")
        pill_lbl(top2, "ACTIVE", "ACTIVE").pack(side="right", ipadx=6, ipady=2)
        ctk.CTkLabel(aa, text="7 today", font=("Segoe UI", 36, "bold"),
                     text_color="#111827").pack(anchor="w", padx=22)
        ctk.CTkLabel(aa, text="Last action: Blocked svchost spoofing 12m ago",
                     font=("Segoe UI", 12), text_color="#6B7280",
                     wraplength=260, justify="left").pack(anchor="w", padx=22, pady=(5, 22))

        # â”€â”€ Row 2: Timeline graph + Flagged processes â”€â”€
        r2 = ctk.CTkFrame(self, fg_color="transparent")
        r2.pack(fill="x", pady=(0, 15))
        r2.columnconfigure(0, weight=3)
        r2.columnconfigure(1, weight=2)

        graph = GlassFrame(r2)
        graph.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        g_hdr = ctk.CTkFrame(graph, fg_color="transparent")
        g_hdr.pack(fill="x", padx=22, pady=(22, 10))
        ctk.CTkLabel(g_hdr, text="Process Activity Timeline", font=("Segoe UI", 16, "bold"),
                     text_color="#111827").pack(side="left")
        leg = ctk.CTkFrame(g_hdr, fg_color="transparent")
        leg.pack(side="right")
        ctk.CTkLabel(leg, text="● Normal  ", font=("Segoe UI", 11), text_color="#9CA3AF").pack(side="left")
        ctk.CTkLabel(leg, text="● Suspicious", font=("Segoe UI", 11), text_color="#F59E0B").pack(side="left")

        cv = tk.Canvas(graph, bg="#FFFFFF", highlightthickness=0, height=180)
        cv.pack(fill="both", expand=True, padx=22, pady=(0, 10))
        # Draw a nice stepped line chart
        points_normal = [(20, 140), (80, 135), (140, 130), (200, 125), (260, 128), (320, 120), (380, 110)]
        points_suspicious = [(380, 110), (420, 80), (460, 45), (490, 40)]
        # Normal line
        for i in range(len(points_normal) - 1):
            cv.create_line(*points_normal[i], *points_normal[i+1], fill="#9CA3AF", width=2.5, smooth=True)
        # Suspicious spike
        for i in range(len(points_suspicious) - 1):
            cv.create_line(*points_suspicious[i], *points_suspicious[i+1], fill="#F59E0B", width=2.5, smooth=True)
        # Anomaly callout
        cv.create_rectangle(400, 25, 520, 55, fill="#FEF3C7", outline="#F59E0B", width=1)
        cv.create_text(460, 40, text="Anomaly detected 2 PM", font=("Segoe UI", 9), fill="#92400E")
        # Time axis
        for i, t in enumerate(["08:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00"]):
            cv.create_text(30 + i * 70, 170, text=t, font=("Segoe UI", 9), fill="#9CA3AF")

        ctk.CTkFrame(graph, height=10, fg_color="transparent").pack()

        fp = GlassFrame(r2)
        fp.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        fh = ctk.CTkFrame(fp, fg_color="transparent")
        fh.pack(fill="x", padx=22, pady=(22, 12))
        ctk.CTkLabel(fh, text="Flagged Processes", font=("Segoe UI", 16, "bold"),
                     text_color="#111827").pack(side="left")
        ctk.CTkLabel(fh, text="Real-time update", font=("Segoe UI", 11),
                     text_color="#9CA3AF").pack(side="right")
        table_header(fp, [(150, "Process Name"), (70, "CPU%"), (80, "Risk")])
        table_row(fp, [(150, "crypt_x64.exe", "mono"), (70, "84%"), (80, "HIGH", "pill")])
        table_row(fp, [(150, "unknown_v3.bin", "mono"), (70, "12%"), (80, "MED", "pill")])
        table_row(fp, [(150, "svchost_tnt.exe", "mono"), (70, "41%"), (80, "HIGH", "pill")])
        table_row(fp, [(150, "ps_update.sh", "mono"), (70, "0.4%"), (80, "LOW", "pill")])
        ctk.CTkFrame(fp, height=10, fg_color="transparent").pack()

        # â”€â”€ Row 3: Behaviour Rules + Recent Alerts â”€â”€
        r3 = ctk.CTkFrame(self, fg_color="transparent")
        r3.pack(fill="x", pady=(0, 15))
        r3.columnconfigure(0, weight=1)
        r3.columnconfigure(1, weight=1)

        rules = GlassFrame(r3)
        rules.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        rh = ctk.CTkFrame(rules, fg_color="transparent")
        rh.pack(fill="x", padx=22, pady=(22, 12))
        ctk.CTkLabel(rh, text="Behaviour Rules", font=("Segoe UI", 16, "bold"),
                     text_color="#111827").pack(side="left")
        ctk.CTkLabel(rh, text="EDIT ALL", font=("Segoe UI", 12, "bold"),
                     text_color="#10B981").pack(side="right")
        rules_data = [
            ("Alert on high CPU spike", "Trigger alert if single process exceeds 80%", True),
            ("Block keylogger patterns", "Heuristic monitoring of keystroke listeners", True),
            ("Monitor startup items", "Alert on new entries in boot registry", False),
        ]
        for title, sub, on in rules_data:
            fr = ctk.CTkFrame(rules, fg_color="transparent")
            fr.pack(fill="x", padx=22, pady=10)
            tf = ctk.CTkFrame(fr, fg_color="transparent")
            tf.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(tf, text=title, font=("Segoe UI", 13, "bold"),
                         text_color="#111827").pack(anchor="w")
            ctk.CTkLabel(tf, text=sub, font=("Segoe UI", 11), text_color="#6B7280").pack(anchor="w")
            sw = ctk.CTkSwitch(fr, text="", progress_color="#10B981", width=44)
            sw.pack(side="right")
            if on:
                sw.select()
        ctk.CTkFrame(rules, height=15, fg_color="transparent").pack()

        alerts = GlassFrame(r3)
        alerts.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        section_header(alerts, "Recent Behaviour Alerts")
        alert_data = [
            ("14:02:11", "Unauthorized memory access blocked in kernel_bridge", "CRITICAL"),
            ("13:45:00", "High disk I/O detected: Unusual scanning behavior from search_agent", "WARNING"),
            ("11:12:32", "System policy update: Behavioral heuristics engine v2.1.4 successfully deployed", "INFO"),
        ]
        for time_str, desc, severity in alert_data:
            afr = ctk.CTkFrame(alerts, fg_color="transparent")
            afr.pack(fill="x", padx=22, pady=8)
            # Colored dot + time + pill
            top_row = ctk.CTkFrame(afr, fg_color="transparent")
            top_row.pack(fill="x")
            s_color = "#EF4444" if severity == "CRITICAL" else "#F59E0B" if severity == "WARNING" else "#3B82F6"
            ctk.CTkLabel(top_row, text="●", font=("Segoe UI", 10), text_color=s_color).pack(side="left", padx=(0, 5))
            ctk.CTkLabel(top_row, text=time_str, font=("Segoe UI", 12), text_color="#6B7280").pack(side="left")
            pill_lbl(top_row, severity, severity).pack(side="right", ipadx=6, ipady=1)
            ctk.CTkLabel(afr, text=desc, font=("Segoe UI", 13, "bold"), text_color="#111827",
                         wraplength=380, justify="left", anchor="w").pack(anchor="w", pady=(5, 0))
        ctk.CTkFrame(alerts, height=10, fg_color="transparent").pack()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE: WEB TRACKING
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class WebTrackingPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")

        # â”€â”€ Title row â”€â”€
        tr = ctk.CTkFrame(self, fg_color="transparent")
        tr.pack(fill="x", pady=(0, 20))
        tl = ctk.CTkFrame(tr, fg_color="transparent")
        tl.pack(side="left")
        ctk.CTkLabel(tl, text="Web Tracking", font=("Segoe UI", 26, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(tl, text="Privacy & tracker monitoring", font=("Segoe UI", 14),
                     text_color="#6B7280").pack(anchor="w", pady=(4, 0))
        pill_fr = ctk.CTkFrame(tr, fg_color="#FEF3C7", corner_radius=20)
        pill_fr.pack(side="right")
        ctk.CTkLabel(pill_fr, text="● 61 — Moderate", font=("Segoe UI", 13, "bold"),
                     text_color="#92400E").pack(padx=16, pady=6)

        # â”€â”€ Row 1: 4 stat cards â”€â”€
        r1 = ctk.CTkFrame(self, fg_color="transparent")
        r1.pack(fill="x", pady=(0, 15))
        r1.columnconfigure((0, 1, 2, 3), weight=1)
        stat_card(r1, "Trackers Blocked Today", "143", "↗ 12% from yesterday",
              top_icon="🛡️", subtext_color="#10B981"
                  ).grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        stat_card(r1, "Data Requests Intercepted", "28", "↗ 8 new anomalies",
              top_icon="⊕", subtext_color="#F59E0B"
                  ).grid(row=0, column=1, sticky="nsew", padx=8)
        stat_card(r1, "Sites With High Tracking", "5",
              "▲ Requires immediate review", value_color="#EF4444",
              top_icon="❗"
                  ).grid(row=0, column=2, sticky="nsew", padx=8)
        stat_card(r1, "Web Threat Score", "61", "Moderate",
                  value_color="#F59E0B"
                  ).grid(row=0, column=3, sticky="nsew", padx=(8, 0))

        # â”€â”€ Row 2: Domains table + Categories â”€â”€
        r2 = ctk.CTkFrame(self, fg_color="transparent")
        r2.pack(fill="x", pady=(0, 15))
        r2.columnconfigure(0, weight=3)
        r2.columnconfigure(1, weight=1)

        dom = GlassFrame(r2)
        dom.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        section_header(dom, "Top Tracking Domains Blocked", "View all logs →")
        table_header(dom, [(200, "Domain"), (120, "Category"), (80, "Count"), (120, "Last Blocked")])
        domains = [
            ("doubleclick.net", "ADVERTISING", "1,244", "2m ago", "bold"),
            ("google-analytics.com", "ANALYTICS", "892", "15m ago", "bold"),
            ("canvas-fingerprint.io", "FINGERPRINT", "412", "42m ago", "normal"),
            ("facebook.com/tr", "SOCIAL", "355", "1h ago", "normal"),
            ("hotjar.io/tracker", "ANALYTICS", "298", "2h ago", "normal"),
            ("amazon-adsystem.com", "ADVERTISING", "211", "3h ago", "normal"),
            ("taboola.map", "ADVERTISING", "184", "5h ago", "normal"),
            ("font-telemetry.net", "FINGERPRINT", "156", "6h ago", "normal"),
        ]
        for d, cat, cnt, when, style in domains:
            table_row(dom, [(200, d, style), (120, cat, "pill"), (80, cnt), (120, when, "light")])
        ctk.CTkFrame(dom, height=10, fg_color="transparent").pack()

        cat_card = GlassFrame(r2)
        cat_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        section_header(cat_card, "Tracking Categories Breakdown")

        # Mini donut representation with canvas
        donut = tk.Canvas(cat_card, width=160, height=140, bg="#FFFFFF", highlightthickness=0)
        donut.pack(pady=(5, 0))
        cx, cy, r_out, r_in = 80, 70, 55, 35
        # Draw segments (approximate)
        donut.create_arc(cx-r_out, cy-r_out, cx+r_out, cy+r_out, start=0, extent=151, outline="#3B82F6", width=18, style=tk.ARC)
        donut.create_arc(cx-r_out, cy-r_out, cx+r_out, cy+r_out, start=151, extent=112, outline="#10B981", width=18, style=tk.ARC)
        donut.create_arc(cx-r_out, cy-r_out, cx+r_out, cy+r_out, start=263, extent=54, outline="#EF4444", width=18, style=tk.ARC)
        donut.create_arc(cx-r_out, cy-r_out, cx+r_out, cy+r_out, start=317, extent=43, outline="#8B5CF6", width=18, style=tk.ARC)
        donut.create_text(cx, cy - 5, text="3.4k", font=("Segoe UI", 18, "bold"), fill="#111827")
        donut.create_text(cx, cy + 15, text="TOTAL HITS", font=("Segoe UI", 8, "bold"), fill="#9CA3AF")

        cats = [
            ("◉ Ad Networks", "42%", "#3B82F6"),
            ("◉ Analytics", "31%", "#10B981"),
            ("◉ Fingerprinting", "15%", "#EF4444"),
            ("◉ Social Media", "12%", "#8B5CF6"),
        ]
        for label, pct, color in cats:
            cfr = ctk.CTkFrame(cat_card, fg_color="transparent")
            cfr.pack(fill="x", padx=22, pady=5)
            ctk.CTkLabel(cfr, text=label, font=("Segoe UI", 13), text_color="#111827").pack(side="left")
            ctk.CTkLabel(cfr, text=pct, font=("Segoe UI", 13, "bold"), text_color="#111827").pack(side="right")
        ctk.CTkFrame(cat_card, height=15, fg_color="transparent").pack()

        # â”€â”€ Row 3: Whitelist + Recommended Actions â”€â”€
        r3 = ctk.CTkFrame(self, fg_color="transparent")
        r3.pack(fill="x", pady=(0, 15))
        r3.columnconfigure(0, weight=1)
        r3.columnconfigure(1, weight=1)

        wl = GlassFrame(r3)
        wl.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        wl_hdr = ctk.CTkFrame(wl, fg_color="transparent")
        wl_hdr.pack(fill="x", padx=22, pady=(22, 12))
        ctk.CTkLabel(wl_hdr, text="Whitelist / Exceptions", font=("Segoe UI", 16, "bold"),
                     text_color="#111827").pack(side="left")
        ctk.CTkButton(wl_hdr, text="+ Add Exception", fg_color="#10B981",
                      text_color="#FFFFFF", font=("Segoe UI", 12, "bold"),
                      width=130, height=32, corner_radius=6).pack(side="right")

        table_header(wl, [(180, "Site Domain"), (180, "Reasoning"), (60, "Actions")])
        whitelist = [
            ("internal.company-wiki.com", "Required for team metrics"),
            ("stripe.com/dashboard", "Payment processor verification"),
            ("cloud.provider.com/logs", "Infrastructure monitoring"),
        ]
        for site, reason in whitelist:
            table_row(wl, [(180, site, "bold"), (180, reason), (60, "", "trash")])
        ctk.CTkFrame(wl, height=15, fg_color="transparent").pack()

        ra = GlassFrame(r3)
        ra.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        section_header(ra, "Recommended Actions")
        action_card(ra, "🔏", "Stricter Fingerprinting",
                    'Enable "Canvas Noise" to prevent advanced device fingerprinting on high-risk domains.')
        action_card(ra, "🔗", "Social Media Trackers",
                    "Found 12 sites with non-essential social pixel tracking. Recommend blocking.")
        action_card(ra, "⚠️", "Review High-Risk Sites",
                    "5 domains flagged for aggressive tracking. Inspect source traffic origins.")
        ctk.CTkFrame(ra, height=10, fg_color="transparent").pack()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE: ALL ACTIONS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AllActionsPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")

        # â”€â”€ Title â”€â”€
        tr = ctk.CTkFrame(self, fg_color="transparent")
        tr.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(tr, text="All Actions", font=("Segoe UI", 26, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(tr, text="Manage automated and manual security actions",
                     font=("Segoe UI", 14), text_color="#6B7280").pack(anchor="w", pady=(4, 0))

        # â”€â”€ Row 1: 3 stat cards â”€â”€
        r1 = ctk.CTkFrame(self, fg_color="transparent")
        r1.pack(fill="x", pady=(0, 15))
        r1.columnconfigure((0, 1, 2), weight=1)
        stat_card(r1, "Total Actions", "24", "", top_icon="☰").grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        stat_card(r1, "Active", "14", "", value_color="#10B981", top_icon="✅").grid(row=0, column=1, sticky="nsew", padx=8)
        stat_card(r1, "Inactive", "10", "", value_color="#EF4444", top_icon="⏸").grid(row=0, column=2, sticky="nsew", padx=(8, 0))

        # â”€â”€ Filter bar â”€â”€
        fb = ctk.CTkFrame(self, fg_color="transparent")
        fb.pack(fill="x", pady=(0, 15))

        # Tab pills
        tabs_fr = ctk.CTkFrame(fb, fg_color="transparent")
        tabs_fr.pack(side="left")
        for i, (txt, active) in enumerate([("All", True), ("Active", False), ("Inactive", False)]):
            ctk.CTkButton(
                tabs_fr, text=txt, width=70, height=32, corner_radius=16,
                font=("Segoe UI", 13, "bold"),
                fg_color="#10B981" if active else "transparent",
                text_color="#FFFFFF" if active else "#6B7280",
                hover_color="#059669" if active else "#F3F4F6",
                border_width=0 if active else 1,
                border_color="#E5E7EB",
            ).pack(side="left", padx=(0, 6))

        # Module filter
        ctk.CTkOptionMenu(fb, values=["All Modules", "System", "WiFi", "Web Tracking", "Behaviour"],
                          font=("Segoe UI", 13), width=150, height=32).pack(side="right")
        # Search
        ctk.CTkEntry(fb, placeholder_text="🔍 Search actions...", width=200, height=32,
                     font=("Segoe UI", 13), corner_radius=8, border_color="#E5E7EB").pack(side="right", padx=(0, 10))

        # â”€â”€ Actions table â”€â”€
        tbl = GlassFrame(self)
        tbl.pack(fill="x", pady=(0, 15))
        table_header(tbl, [(190, "Action Name"), (90, "Module"), (70, "Type"), (70, "Status"),
                           (90, "Last Triggered"), (280, "Description")])

        actions = [
            ("Auto-Isolation High-Risk IP", "System", "AUTO", True, "2m ago", "Disconnects nodes showing high-risk o..."),
            ("Rogue AP De-auth", "WiFi", "AUTO", True, "14m ago", "Sends de-auth packets to unauthorize..."),
            ("Manual Credential Flush", "Web Tracking", "MANUAL", False, "--", "Clears all active session tokens for the ..."),
            ("Exfil Threshold Alert", "Behaviour", "AUTO", True, "1h ago", "Logs warning when data egress excee..."),
            ("Cookie Injection Block", "Web Tracking", "AUTO", True, "42m ago", "Prevents cross-site cookie manipulation..."),
            ("SSH Bruteforce Lockout", "System", "AUTO", True, "3h ago", "Blocks IPs with >5 failed login attempts..."),
            ("Manual Port Sweep", "System", "MANUAL", False, "Yesterday", "Initiates a comprehensive scan of all op..."),
            ("Beacon Frequency Monitor", "Behaviour", "AUTO", True, "12h ago", "Detects C2 beaconing patterns in netw..."),
            ("WPA3 Enforcement", "WiFi", "AUTO", True, "--", "Automatically upgrades connecting clie..."),
            ("Tracker Pixel Scrubber", "Web Tracking", "MANUAL", False, "2d ago", "Filters invisible tracking pixels from inco..."),
            ("Kernel Integrity Check", "System", "AUTO", True, "5m ago", "Verifies boot sequence and kernel spac..."),
            ("Manual Node Blacklist", "System", "MANUAL", False, "--", "Hard-blocks hardware addresses from ..."),
        ]
        for name, mod, typ, on, last, desc in actions:
            fr = ctk.CTkFrame(tbl, fg_color="transparent")
            fr.pack(fill="x", padx=22, pady=10)
            ctk.CTkLabel(fr, text=name, font=("Segoe UI", 13, "bold"), text_color="#111827",
                         width=190, anchor="w").pack(side="left")
            ctk.CTkLabel(fr, text=mod, font=("Segoe UI", 13), text_color="#6B7280",
                         width=90, anchor="w").pack(side="left")
            pill_lbl(fr, typ, typ).pack(side="left", padx=(0, 15), ipadx=6, ipady=2)
            sw = ctk.CTkSwitch(fr, text="", width=44, progress_color="#10B981")
            sw.pack(side="left", padx=(0, 15))
            if on:
                sw.select()
            ctk.CTkLabel(fr, text=last, font=("Segoe UI", 13), text_color="#6B7280",
                         width=90, anchor="w").pack(side="left")
            ctk.CTkLabel(fr, text=desc, font=("Segoe UI", 13), text_color="#6B7280",
                         anchor="w").pack(side="left", fill="x", expand=True)

        # â”€â”€ Pagination â”€â”€
        pag = ctk.CTkFrame(self, fg_color="transparent")
        pag.pack(fill="x", pady=(5, 15))
        ctk.CTkLabel(pag, text="Showing 1-12 of 24 actions", font=("Segoe UI", 13),
                     text_color="#10B981").pack(side="left")
        pg_fr = ctk.CTkFrame(pag, fg_color="transparent")
        pg_fr.pack(side="right")
        ctk.CTkButton(pg_fr, text="‹", width=32, height=32, corner_radius=6,
                      fg_color="transparent", text_color="#6B7280",
                      border_width=1, border_color="#E5E7EB").pack(side="left", padx=2)
        ctk.CTkButton(pg_fr, text="1", width=32, height=32, corner_radius=6,
                      fg_color="#10B981", text_color="#FFFFFF").pack(side="left", padx=2)
        ctk.CTkButton(pg_fr, text="2", width=32, height=32, corner_radius=6,
                      fg_color="transparent", text_color="#6B7280",
                      border_width=1, border_color="#E5E7EB").pack(side="left", padx=2)
        ctk.CTkButton(pg_fr, text="›", width=32, height=32, corner_radius=6,
                      fg_color="transparent", text_color="#6B7280",
                      border_width=1, border_color="#E5E7EB").pack(side="left", padx=2)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE: NETWORK LOGS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class NetworkLogsPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")

        # â”€â”€ Title â”€â”€
        tr = ctk.CTkFrame(self, fg_color="transparent")
        tr.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(tr, text="Logs", font=("Segoe UI", 26, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(tr, text="System event history", font=("Segoe UI", 14),
                     text_color="#6B7280").pack(anchor="w", pady=(4, 0))

        # â”€â”€ Filter bar â”€â”€
        fb = ctk.CTkFrame(self, fg_color="transparent")
        fb.pack(fill="x", pady=(0, 15))

        # Date dropdown
        ctk.CTkOptionMenu(fb, values=["Last 7 days", "Last 24 hours", "Last 30 days", "All time"],
                          font=("Segoe UI", 13), width=150, height=34).pack(side="left")

        # Filter pills
        pills_fr = ctk.CTkFrame(fb, fg_color="transparent")
        pills_fr.pack(side="left", padx=15)
        for txt, active in [("All", True), ("Info", False), ("Warning", False), ("Critical", False)]:
            ctk.CTkButton(
                pills_fr, text=txt, width=65, height=30, corner_radius=15,
                font=("Segoe UI", 12, "bold"),
                fg_color="#10B981" if active else "transparent",
                text_color="#FFFFFF" if active else "#6B7280",
                hover_color="#059669" if active else "#F3F4F6",
                border_width=0 if active else 1,
                border_color="#E5E7EB",
            ).pack(side="left", padx=3)

        # Download button
        ctk.CTkButton(fb, text="⬇ Download Logs", font=("Segoe UI", 13, "bold"),
                      fg_color="transparent", border_color="#10B981", border_width=1,
                      text_color="#10B981", hover_color="#F0FDF4",
                      width=140, height=34, corner_radius=8).pack(side="right")

        # â”€â”€ Event summary â”€â”€
        summary = ctk.CTkFrame(self, fg_color="transparent")
        summary.pack(fill="x", pady=(0, 10))
        s_txt = ctk.CTkFrame(summary, fg_color="transparent")
        s_txt.pack(side="left")
        ctk.CTkLabel(s_txt, text="Showing ", font=("Segoe UI", 13), text_color="#6B7280").pack(side="left")
        ctk.CTkLabel(s_txt, text="248 events", font=("Segoe UI", 13, "bold"), text_color="#111827").pack(side="left")
        ctk.CTkLabel(s_txt, text=" - ", font=("Segoe UI", 13), text_color="#6B7280").pack(side="left")
        ctk.CTkLabel(s_txt, text="3 Critical", font=("Segoe UI", 13, "bold"), text_color="#EF4444").pack(side="left")
        ctk.CTkLabel(s_txt, text=", ", font=("Segoe UI", 13), text_color="#6B7280").pack(side="left")
        ctk.CTkLabel(s_txt, text="12 Warnings", font=("Segoe UI", 13, "bold"), text_color="#F59E0B").pack(side="left")
        ctk.CTkLabel(s_txt, text=", 233 Info", font=("Segoe UI", 13), text_color="#6B7280").pack(side="left")

        # â”€â”€ Log entries â”€â”€
        logs_card = GlassFrame(self)
        logs_card.pack(fill="x", pady=(0, 15))

        log_entries = [
            ("2023-11-24\n14:22:01", "WIFI", "Unauthorized Access Point Detected",
             "MAC: 00:0A:95:9D:68:16 - Potential evil twin spoofing internal gateway", "#EF4444"),
            ("2023-11-24\n14:15:33", "SYSTEM", "Database Optimization Complete",
             "Index rebuild for security_events table finished in 1.4s", "#E5E7EB"),
            ("2023-11-24\n13:58:12", "WEB", "Outbound SSH Connection",
             "Host 192.168.1.44 initiated SSH to 203.0.113.5 (Unknown Registry)", "#F59E0B"),
            ("2023-11-24\n13:45:00", "BEHAVIOUR", "User Session Validated",
             "MFA success for user 'j_doe' from known office IP (10.0.4.15)", "#10B981"),
            ("2023-11-24\n12:30:44", "SYSTEM", "Kernel Panic Averted",
             "Unexpected process termination in module 'auth_vault'. Auto-restart initiate...", "#EF4444"),
            ("2023-11-24\n11:12:05", "WIFI", "High Interference Level",
             "2.4GHz spectrum congested (85%). Channel hopping to Ch 11.", "#EF4444"),
            ("2023-11-24\n10:45:22", "WEB", "SSL Certificate Verified",
             "External gateway certificate renewed until 2025.", "#10B981"),
            ("2023-11-24\n09:22:18", "BEHAVIOUR", "Unusual Data Volume Transfer",
             "Station 'LAB-WS-02' uploaded 4.5GB to cloud-backup.local in 15min.", "#F59E0B"),
            ("2023-11-24\n08:30:11", "SYSTEM", "Guardian AI Core Update",
             "Heuristics engine updated to v4.2.1-stable.", "#E5E7EB"),
            ("2023-11-24\n07:15:01", "WEB", "Phishing Domain Blocked",
             "Request to 'secure-bank-login.cn' intercepted and dropped for 4 clients.", "#EF4444"),
        ]
        for time_str, mod, title, desc, bar_color in log_entries:
            fr = ctk.CTkFrame(logs_card, fg_color="transparent")
            fr.pack(fill="x", padx=22, pady=12)
            # Colored bar
            ctk.CTkFrame(fr, width=4, fg_color=bar_color, corner_radius=2).pack(side="left", fill="y", padx=(0, 15))
            # Time
            ctk.CTkLabel(fr, text=time_str, font=("Segoe UI", 12), text_color="#6B7280",
                         width=100, anchor="w", justify="left").pack(side="left", padx=(0, 10))
            # Module pill
            pill_lbl(fr, mod, mod).pack(side="left", padx=(0, 15), ipadx=6, ipady=2)
            # Text block
            tf = ctk.CTkFrame(fr, fg_color="transparent")
            tf.pack(side="left", fill="x", expand=True, padx=(0, 10))
            ctk.CTkLabel(tf, text=title, font=("Segoe UI", 13, "bold"),
                         text_color="#111827", anchor="w").pack(anchor="w")
            ctk.CTkLabel(tf, text=desc, font=("Consolas", 11),
                         text_color="#6B7280", anchor="w", wraplength=500,
                         justify="left").pack(anchor="w")
            # Details link
            ctk.CTkLabel(fr, text="Details", font=("Segoe UI", 13, "bold"),
                         text_color="#10B981").pack(side="right")

        # â”€â”€ Load more button â”€â”€
        ctk.CTkButton(self, text="Load 20 more", fg_color="transparent",
                      border_color="#10B981", border_width=1, text_color="#10B981",
                      font=("Segoe UI", 14, "bold"), hover_color="#F0FDF4",
                      width=200, height=42, corner_radius=8).pack(pady=(5, 20))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE: SETTINGS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class SettingsPage(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")

        # â”€â”€ Title â”€â”€
        tr = ctk.CTkFrame(self, fg_color="transparent")
        tr.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(tr, text="Settings", font=("Segoe UI", 26, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(tr, text="Manage your account security and application preferences.",
                     font=("Segoe UI", 14), text_color="#6B7280").pack(anchor="w", pady=(4, 0))

        card = GlassFrame(self)
        card.pack(fill="x", pady=(0, 20))

        # â•â•â•â•â•â•â•â•â•â• PROFILE SECTION â•â•â•â•â•â•â•â•â•â•
        self._section_label(card, "PROFILE")
        prof = ctk.CTkFrame(card, fg_color="transparent")
        prof.pack(fill="x", padx=40, pady=(0, 25))
        ctk.CTkLabel(prof, text="👨🏻‍💼", font=("Segoe UI", 42)).pack(side="left", padx=(0, 18))
        info = ctk.CTkFrame(prof, fg_color="transparent")
        info.pack(side="left")
        ctk.CTkLabel(info, text="Alexander Sterling", font=("Segoe UI", 18, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(info, text="alex.sterling@sentinel-defense.io", font=("Segoe UI", 13),
                     text_color="#6B7280").pack(anchor="w")
        ctk.CTkButton(prof, text="Edit Profile", fg_color="#10B981", text_color="#FFFFFF",
                      font=("Segoe UI", 13, "bold"), width=110, height=36,
                      corner_radius=8).pack(side="right")
        self._divider(card)

        # â•â•â•â•â•â•â•â•â•â• APPEARANCE â•â•â•â•â•â•â•â•â•â•
        self._section_label(card, "APPEARANCE")
        app_fr = ctk.CTkFrame(card, fg_color="transparent")
        app_fr.pack(fill="x", padx=40, pady=(0, 25))
        ctk.CTkLabel(app_fr, text="Theme", font=("Segoe UI", 14, "bold"),
                     text_color="#111827").pack(side="left")
        ctk.CTkOptionMenu(app_fr, values=["Light", "Dark", "System"],
                          font=("Segoe UI", 13), width=120).pack(side="right")
        self._divider(card)

        # â•â•â•â•â•â•â•â•â•â• AUTOMATION PREFERENCES â•â•â•â•â•â•â•â•â•â•
        self._section_label(card, "AUTOMATION PREFERENCES")

        ctk.CTkLabel(card, text="Automatic Actions", font=("Segoe UI", 14, "bold"),
                     text_color="#111827").pack(anchor="w", padx=40, pady=(0, 10))
        auto_items = [
            ("Auto-block high-risk processes", "Sentinel will kill suspicious threads instantly", True),
            ("Auto-disconnect suspicious WiFi", "Sever connection if SSL pinning fails", False),
            ("Auto-clear tracking cookies daily", "Remove browser fingerprints at midnight", True),
            ("Quarantine flagged files automatically", "Move threat vectors to sandbox isolation", False),
        ]
        for t, s, v in auto_items:
            self._toggle_row(card, t, s, v)

        ctk.CTkFrame(card, height=15, fg_color="transparent").pack()
        ctk.CTkLabel(card, text="Alert Me When", font=("Segoe UI", 14, "bold"),
                     text_color="#111827").pack(anchor="w", padx=40, pady=(0, 10))
        alert_items = [
            ("New device joins my network", None, True),
            ("Behaviour score exceeds 70", None, True),
            ("High-risk tracker detected", None, False),
            ("Unusual data upload detected", None, True),
        ]
        for t, s, v in alert_items:
            self._toggle_row(card, t, s, v)

        ctk.CTkFrame(card, height=15, fg_color="transparent").pack()
        ctk.CTkLabel(card, text="Never Do", font=("Segoe UI", 14, "bold"),
                     text_color="#EF4444").pack(anchor="w", padx=40, pady=(0, 10))
        never_items = [
            ("Send data to third parties", None, False),
            ("Auto-delete user files", None, False),
            ("Share location data", None, False),
        ]
        for t, s, v in never_items:
            self._toggle_row(card, t, s, v, disabled=True)
        ctk.CTkLabel(card, text="These settings are hard-locked by the Sentinel Privacy Manifest.",
                     font=("Segoe UI", 11), text_color="#9CA3AF").pack(anchor="w", padx=40, pady=(5, 15))
        self._divider(card)

        # â•â•â•â•â•â•â•â•â•â• NOTIFICATIONS â•â•â•â•â•â•â•â•â•â•
        self._section_label(card, "NOTIFICATIONS")
        ctk.CTkLabel(card, text="Communication Channels", font=("Segoe UI", 14, "bold"),
                     text_color="#111827").pack(anchor="w", padx=40, pady=(0, 10))
        for ch in ["In-App Notifications", "Desktop Push Alerts", "Email Security Digests"]:
            cfr = ctk.CTkFrame(card, fg_color="transparent")
            cfr.pack(fill="x", padx=40, pady=4)
            cb = ctk.CTkCheckBox(cfr, text=ch, font=("Segoe UI", 13),
                                 text_color="#111827", fg_color="#10B981",
                                 hover_color="#059669")
            cb.pack(anchor="w")
            cb.select()

        ctk.CTkFrame(card, height=15, fg_color="transparent").pack()
        ctk.CTkLabel(card, text="Quiet hours", font=("Segoe UI", 14, "bold"),
                     text_color="#111827").pack(anchor="w", padx=40, pady=(0, 10))
        qh = ctk.CTkFrame(card, fg_color="#F9FAFB", corner_radius=8)
        qh.pack(fill="x", padx=40, pady=(0, 25))
        qs = ctk.CTkFrame(qh, fg_color="transparent")
        qs.pack(side="left", padx=20, pady=15)
        ctk.CTkLabel(qs, text="START", font=("Segoe UI", 10, "bold"), text_color="#9CA3AF").pack(anchor="w")
        ctk.CTkLabel(qs, text="10:00 PM", font=("Segoe UI", 14, "bold"), text_color="#111827").pack(anchor="w")
        qe = ctk.CTkFrame(qh, fg_color="transparent")
        qe.pack(side="left", padx=20, pady=15)
        ctk.CTkLabel(qe, text="END", font=("Segoe UI", 10, "bold"), text_color="#9CA3AF").pack(anchor="w")
        ctk.CTkLabel(qe, text="07:00 AM", font=("Segoe UI", 14, "bold"), text_color="#111827").pack(anchor="w")
        self._divider(card)

        # â•â•â•â•â•â•â•â•â•â• DANGER ZONE â•â•â•â•â•â•â•â•â•â•
        dz = ctk.CTkFrame(card, fg_color="#FEF2F2", corner_radius=10)
        dz.pack(fill="x", padx=30, pady=(10, 30))
        ctk.CTkLabel(dz, text="DANGER ZONE", font=("Segoe UI", 12, "bold"),
                     text_color="#EF4444").pack(anchor="w", padx=20, pady=(20, 15))
        # Logout
        lo = ctk.CTkFrame(dz, fg_color="transparent")
        lo.pack(fill="x", padx=20, pady=(0, 10))
        lo_t = ctk.CTkFrame(lo, fg_color="transparent")
        lo_t.pack(side="left")
        ctk.CTkLabel(lo_t, text="Log Out", font=("Segoe UI", 14, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(lo_t, text="Sign out of all active Sentinel instances on this device.",
                     font=("Segoe UI", 12), text_color="#6B7280").pack(anchor="w")
        ctk.CTkButton(lo, text="Log Out", fg_color="transparent", border_color="#EF4444",
                      border_width=1, text_color="#EF4444", font=("Segoe UI", 12, "bold"),
                      width=90, height=32, corner_radius=6).pack(side="right")
        # Delete
        da = ctk.CTkFrame(dz, fg_color="transparent")
        da.pack(fill="x", padx=20, pady=(0, 20))
        da_t = ctk.CTkFrame(da, fg_color="transparent")
        da_t.pack(side="left")
        ctk.CTkLabel(da_t, text="Delete Account", font=("Segoe UI", 14, "bold"),
                     text_color="#111827").pack(anchor="w")
        ctk.CTkLabel(da_t, text="Once deleted, your threat history, logs, and custom rules\nwill be permanently erased. This action cannot be undone.",
                     font=("Segoe UI", 12), text_color="#6B7280", justify="left").pack(anchor="w")
        ctk.CTkButton(da, text="Delete Account", fg_color="transparent",
                      border_color="#EF4444", border_width=1, text_color="#EF4444",
                      font=("Segoe UI", 12, "bold"), width=120, height=32,
                      corner_radius=6).pack(side="right")

        # â”€â”€ Build version footer â”€â”€
        ctk.CTkLabel(self, text="Build v2.4.12-secure  •  Sentinel Defense Systems",
                     font=("Segoe UI", 11), text_color="#9CA3AF").pack(pady=(10, 20))

    # â”€â”€ Helper methods â”€â”€

    def _section_label(self, parent, text):
        fr = ctk.CTkFrame(parent, fg_color="transparent")
        fr.pack(fill="x", padx=40, pady=(20, 15))
        ctk.CTkLabel(fr, text=text, font=("Segoe UI", 12, "bold"),
                     text_color="#10B981").pack(side="left")
        ctk.CTkFrame(fr, height=1, fg_color="#E5E7EB").pack(side="left", fill="x", expand=True, padx=(15, 0))

    def _divider(self, parent):
        ctk.CTkFrame(parent, height=1, fg_color="#E5E7EB").pack(fill="x", padx=40)

    def _toggle_row(self, parent, title, subtitle=None, value=False, disabled=False):
        fr = ctk.CTkFrame(parent, fg_color="transparent")
        fr.pack(fill="x", padx=40, pady=8)
        tf = ctk.CTkFrame(fr, fg_color="transparent")
        tf.pack(side="left")
        ctk.CTkLabel(tf, text=title, font=("Segoe UI", 13, "bold"),
                     text_color="#111827").pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(tf, text=subtitle, font=("Segoe UI", 11),
                         text_color="#6B7280").pack(anchor="w")
        sw = ctk.CTkSwitch(fr, text="", progress_color="#10B981", width=44)
        sw.pack(side="right")
        if value:
            sw.select()
        if disabled:
            sw.configure(state="disabled")

