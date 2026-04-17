"""Entry point — launches the Tkinter desktop application."""

from logger import get_logger
from ui.app import App

log = get_logger(__name__)


def main() -> None:
    log.info("Starting application")
    app = App()
    app.mainloop()
    log.info("Application closed")


if __name__ == "__main__":
    main()
