"""
Logging infrastructure — console + rotating file handlers.
All modules should obtain their logger via `get_logger(__name__)`.

Milestone 06 finalization:
- Logs written to ``data/logs/app.log`` (rotated at 5 MB, 5 backups)
- Console output controlled by ``config.LOG_TO_CONSOLE``
- Module tagging via ``%(name)s`` in the format string
"""

import logging
from logging.handlers import RotatingFileHandler

import config


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger that writes to data/logs/app.log.

    Idempotent — repeated calls for the same *name* return the same
    logger without adding duplicate handlers.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(config.LOG_LEVEL)

    formatter = logging.Formatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)

    # Console handler (optional)
    if getattr(config, "LOG_TO_CONSOLE", True):
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler (rotating) — writes to data/logs/app.log
    log_dir = getattr(config, "LOG_DIR", config.DATA_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "app.log"

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
