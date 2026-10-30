import json
import logging
import os
from logging.handlers import RotatingFileHandler


class JsonFormatter(logging.Formatter):
    """One JSON object per line (SENTINEL_LOG_FORMAT=json), for log shippers."""

    def format(self, record):
        out = {'ts': self.formatTime(record, '%Y-%m-%dT%H:%M:%S'), 'level': record.levelname,
               'logger': record.name, 'msg': record.getMessage()}
        if record.exc_info:
            out['exc'] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False)


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

    if os.environ.get('SENTINEL_LOG_FORMAT', '').lower() == 'json':
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )

    # 🔁 Rotating file handler (graceful fallback on permission errors)
    file_handler = None
    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
    except PermissionError as e:
        # If the process cannot open the log file, continue with console-only logging.
        print(f"Warning: cannot open log file {log_file}: {e}")

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers
    if not logger.handlers:
        if file_handler is not None:
            logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

