import customtkinter as ctk
import config

TOKENS = {
    "light": {
        "bg_root":          "#F9FAFB",
        "bg_sidebar":       "#FFFFFF",
        "card_bg":          "#FFFFFF",
        "card_border":      "#E5E7EB",
        "text_primary":     "#111827",
        "text_secondary":   "#6B7280",
        "text_muted":       "#9CA3AF",
        "accent":           "#10B981",
        "accent_hover":     "#059669",
        "accent_tint":      "#F0FDF4",
        "divider":          "#E5E7EB",
        "row_hover":        "#F9FAFB",
        "danger":           "#EF4444",
        "danger_tint":      "#FEF2F2",
        "warning":          "#F59E0B",
        "warning_tint":     "#FFFBEB",
    },
    "dark": {
        "bg_root":          "#0B0F19",
        "bg_sidebar":       "#111827",
        "card_bg":          "#111827",
        "card_border":      "#1F2937",
        "text_primary":     "#F9FAFB",
        "text_secondary":   "#9CA3AF",
        "text_muted":       "#6B7280",
        "accent":           "#10B981",
        "accent_hover":     "#059669",
        "accent_tint":      "#064E3B",
        "divider":          "#1F2937",
        "row_hover":        "#1F2937",
        "danger":           "#EF4444",
        "danger_tint":      "#7F1D1D",
        "warning":          "#F59E0B",
        "warning_tint":     "#78350F",
    },
}

GLASS_TOKENS = {
    "light": {
        "card_bg":       "#FFFFFF",
        "card_border":   "#F3F4F6",
        "shadow_color":  "#E5E7EB",
        "corner_radius": 16,
    },
    "dark": {
        "card_bg":       "#111827",
        "card_border":   "#374151", 
        "shadow_color":  "#000000",
        "corner_radius": 16,
    },
}

TIER_COLORS = {
    "Safe":       {"fg": "#10B981", "bg_tint": "#D1FAE5", "text": "#065F46"},
    "Low Risk":   {"fg": "#3B82F6", "bg_tint": "#DBEAFE", "text": "#1E40AF"},
    "Elevated":   {"fg": "#F59E0B", "bg_tint": "#FEF3C7", "text": "#92400E"},
    "High Risk":  {"fg": "#EF4444", "bg_tint": "#FEE2E2", "text": "#991B1B"},
    "Critical":   {"fg": "#DC2626", "bg_tint": "#FECACA", "text": "#7F1D1D"},
}

PILL_COLORS = {
    "CRITICAL":    ("#FEE2E2", "#991B1B"),
    "WARNING":     ("#FEF3C7", "#92400E"),
    "INFO":        ("#D1FAE5", "#065F46"),
    "REVIEW":      ("#FEF3C7", "#92400E"),
    "APPLY":       ("#D1FAE5", "#065F46"),
    "SAFE":        ("#D1FAE5", "#065F46"),
    "SUSPICIOUS":  ("#FEE2E2", "#991B1B"),
    "UNKNOWN":     ("#DBEAFE", "#1E40AF"),
    "ADVERTISING": ("#DBEAFE", "#1E40AF"),
    "ANALYTICS":   ("#D1FAE5", "#065F46"),
    "FINGERPRINT": ("#FEE2E2", "#991B1B"),
    "SOCIAL":      ("#F3E8FF", "#6B21A8"),
    "AUTO":        ("#D1FAE5", "#065F46"),
    "MANUAL":      ("#F3F4F6", "#374151"),
    "HIGH":        ("#FEE2E2", "#991B1B"),
    "MED":         ("#FEF3C7", "#92400E"),
    "LOW":         ("#D1FAE5", "#065F46"),
    "ACTIVE":      ("#D1FAE5", "#065F46"),
    "WIFI":        ("#DBEAFE", "#1E40AF"),
    "WEB":         ("#FEF3C7", "#92400E"),
    "SYSTEM":      ("#F3F4F6", "#374151"),
    "BEHAVIOUR":   ("#F0FDF4", "#065F46"),
}

def apply_theme():
    ctk.set_appearance_mode(config.APPEARANCE_MODE)
    ctk.set_default_color_theme("blue")

def get_card_tokens() -> dict:
    mode = ctk.get_appearance_mode().lower()
    if mode not in ("light", "dark"):
        mode = "dark"
    if getattr(config, "GLASSMORPHISM_ENABLED", False):
        return {**TOKENS[mode], **GLASS_TOKENS[mode]}
    return TOKENS[mode]
