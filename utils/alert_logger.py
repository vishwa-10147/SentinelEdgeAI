import json
import os
from datetime import datetime


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

        # Add internal ID + logged timestamp
        alert_data["logged_at"] = datetime.utcnow().isoformat()

        alerts.append(alert_data)

        with open(self.file_path, "w") as f:
            json.dump(alerts, f, indent=4)
