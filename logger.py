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


class SafeRotatingFileHandler(RotatingFileHandler):
    """A RotatingFileHandler that handles PermissionError/OSError during rollover gracefully

    on Windows if another process/thread locks the file.
    """
    def doRollover(self) -> None:
        if self.stream:
            self.stream.close()
            self.stream = None
        try:
            if self.backupCount > 0:
                import os
                for i in range(self.backupCount - 1, 0, -1):
                    sfn = self.rotation_filename("%s.%d" % (self.baseFilename, i))
                    dfn = self.rotation_filename("%s.%d" % (self.baseFilename, i + 1))
                    if os.path.exists(sfn):
                        if os.path.exists(dfn):
                            os.remove(dfn)
                        os.rename(sfn, dfn)
                dfn = self.rotation_filename(self.baseFilename + ".1")
                if os.path.exists(dfn):
                    os.remove(dfn)
                self.rotate(self.baseFilename, dfn)
        except (PermissionError, OSError):
            # Roll over failed because file is locked by another process.
            # Catch it to prevent traceback spam to stderr/console.
            pass
        finally:
            if not self.delay:
                self.stream = self._open()


def is_file_locked(filepath) -> bool:
    """Check if a file is locked/open by another process on Windows."""
    if not filepath.exists():
        return False
    try:
        # On Windows, try renaming the file to a temp name and back.
        # If it is open by another process, this raises a PermissionError.
        temp_name = filepath.with_name(f"{filepath.name}.tmp_test_lock")
        filepath.rename(temp_name)
        temp_name.rename(filepath)
        return False
    except (PermissionError, OSError):
        return True


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

    # Use PID log if main log file is locked
    import os
    if is_file_locked(log_file):
        log_file = log_dir / f"app_{os.getpid()}.log"

    try:
        file_handler = SafeRotatingFileHandler(
            log_file,
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT,
        )
    except Exception:
        file_handler = logging.NullHandler()

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

