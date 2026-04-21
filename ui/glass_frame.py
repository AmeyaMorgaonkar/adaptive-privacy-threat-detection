import customtkinter as ctk
from ui.theme import get_card_tokens

class GlassFrame(ctk.CTkFrame):
    """
    A CTkFrame styled as a floating glass card.
    """

    _instances: list["GlassFrame"] = []

    def __init__(self, master, **kwargs):
        tokens = get_card_tokens()
        kwargs.setdefault("fg_color",      tokens["card_bg"])
        kwargs.setdefault("border_color",  tokens["card_border"])
        kwargs.setdefault("border_width",  1)
        kwargs.setdefault("corner_radius", tokens.get("corner_radius", 12))
        super().__init__(master, **kwargs)
        GlassFrame._instances.append(self)

    def apply_tokens(self):
        """Re-apply current token set. Called on theme or glass toggle."""
        tokens = get_card_tokens()
        self.configure(
            fg_color=tokens["card_bg"],
            border_color=tokens["card_border"],
            corner_radius=tokens.get("corner_radius", 12),
        )

    @classmethod
    def refresh_all(cls):
        """Propagate token changes to every live GlassFrame instance."""
        for frame in cls._instances:
            try:
                frame.apply_tokens()
            except Exception:
                pass   # widget may have been destroyed; skip silently
