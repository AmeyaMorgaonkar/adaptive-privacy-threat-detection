"""
Tkinter application shell — root window setup.
Design will be integrated in Milestone 02.
"""

import tkinter as tk
from logger import get_logger
import config

log = get_logger(__name__)


class App(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title(config.APP_NAME)
        self.geometry(f"{config.WINDOW_WIDTH}x{config.WINDOW_HEIGHT}")
        self.minsize(800, 500)
        self.configure(bg="#1a1a2e")

        self._build_placeholder()
        log.info("Application window initialised")

    def _build_placeholder(self) -> None:
        """Temporary centered label — removed once the real UI lands."""
        label = tk.Label(
            self,
            text=f"{config.APP_NAME}\nv{config.APP_VERSION}",
            font=("Segoe UI", 18, "bold"),
            fg="#e0e0e0",
            bg="#1a1a2e",
        )
        label.place(relx=0.5, rely=0.5, anchor="center")
