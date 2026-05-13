import threading
import time
import os
from typing import Optional

from .storage import get_storage


class DBMaintenance:
    """Simple background maintenance for SQLite retention and VACUUM."""

    def __init__(self, db_path: Optional[str] = None, interval: int = 3600):
        self.db_path = db_path or os.environ.get("SENTINEL_DB_PATH", "data/sentinel.db")
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _run(self):
        storage = get_storage(self.db_path)
        while not self._stop.wait(self.interval):
            try:
                # purge old alerts (30 days), flows (7 days), events (7 days), risk_timeline (30 days)
                storage.cleanup_retention("alerts", max_age_seconds=30 * 24 * 3600)
                storage.cleanup_retention("flows", max_age_seconds=7 * 24 * 3600)
                storage.cleanup_retention("live_events", max_age_seconds=7 * 24 * 3600)
                storage.cleanup_retention("risk_timeline", max_age_seconds=30 * 24 * 3600)
                # run VACUUM occasionally to keep DB compact
                storage.vacuum()
            except Exception:
                # best-effort maintenance; swallow exceptions to avoid crashing service
                pass

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="DBMaintenance")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


def start_background(db_path: Optional[str] = None, interval: int = 3600):
    if os.environ.get("DISABLE_DB_MAINTENANCE", "0") == "1":
        return None
    m = DBMaintenance(db_path=db_path, interval=interval)
    m.start()
    return m
