import json
import os
import time
from datetime import datetime, timezone
from core.storage import get_storage


class AlertLogger:
    def __init__(self, file_path="alerts.json"):
        self.file_path = file_path

        # Create file if it doesn't exist
        if not os.path.exists(self.file_path):
            with open(self.file_path, "w") as f:
                json.dump([], f)

    def log(self, alert_data):
        """
        Append alert to alerts.json
        """

        try:
            with open(self.file_path, "r") as f:
                alerts = json.load(f)
        except Exception:
            alerts = []

        # Add internal ID + logged timestamp (timezone-aware UTC)
        alert_data["logged_at"] = datetime.now(timezone.utc).isoformat()

        alerts.append(alert_data)

        with open(self.file_path, "w") as f:
            json.dump(alerts, f, indent=4)

        # also persist to SQLite if available
        try:
            storage = get_storage('data/sentinel.db')
            storage.connect()
            try:
                storage.create_tables()
            except Exception:
                pass
            storage.insert_alert(int(time.time()), alert_data.get('src_ip'), alert_data.get('dst_ip'), alert_data.get('port', 0), 0, alert_data.get('protocol', ''), alert_data.get('final_risk_score', alert_data.get('risk_score', 0)), float(alert_data.get('confidence', 0)), json.dumps(alert_data))
        except Exception:
            # do not fail the main flow on DB issues
            pass


