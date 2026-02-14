import json
import os
from datetime import datetime


class AlertLogger:

    def __init__(self, file_path="alerts/alerts.json"):
        self.file_path = file_path
        os.makedirs("alerts", exist_ok=True)

        if not os.path.exists(self.file_path):
            with open(self.file_path, "w") as f:
                json.dump([], f)

    def log(self, flow, score):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "initiator_ip": flow.initiator_ip,
            "responder_ip": flow.responder_ip,
            "protocol": flow.protocol,
            "duration": flow.duration,
            "forward_bytes": flow.forward_bytes,
            "backward_bytes": flow.backward_bytes,
            "score": score
        }

        with open(self.file_path, "r+") as f:
            data = json.load(f)
            data.append(alert)
            f.seek(0)
            json.dump(data, f, indent=4)
