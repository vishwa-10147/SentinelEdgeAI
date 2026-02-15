import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logger(
    name="sentinel",
    log_file="logs/sentinel.log",
    level=logging.INFO,
    max_bytes=5 * 1024 * 1024,   # 5 MB
    backup_count=5               # Keep last 5 log files
):
    """
    Set up a logger with rotating file and console handlers.
    Creates logs directory if it doesn't exist.
    Automatically rotates log files when max_bytes is exceeded.
    """
    os.makedirs("logs", exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    # 🔁 Rotating file handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

