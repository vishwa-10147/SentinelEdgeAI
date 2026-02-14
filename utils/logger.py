import json
from datetime import datetime
from pathlib import Path


class AlertLogger:
    def __init__(self, file_path="alerts.json"):
        self.file_path = Path(file_path)

    def log(self, flow, score, severity):
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "initiator_ip": flow.initiator_ip,
            "responder_ip": flow.responder_ip,
            "protocol": flow.protocol,
            "duration": flow.duration,
            "forward_bytes": flow.forward_bytes,
            "backward_bytes": flow.backward_bytes,
            "score": score,
            "severity": severity
        }

        if self.file_path.exists():
            with open(self.file_path, "r") as f:
                data = json.load(f)
        else:
            data = []

        data.append(alert)

        with open(self.file_path, "w") as f:
            json.dump(data, f, indent=4)
