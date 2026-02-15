class MitreMapper:

    ATTACK_MAP = {
        "POSSIBLE_DATA_EXFILTRATION": {
            "tactic": "Exfiltration",
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel"
        },
        "TRAFFIC_FLOOD": {
            "tactic": "Impact",
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service"
        },
        "LONG_SUSPICIOUS_SESSION": {
            "tactic": "Command and Control",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol"
        },
        "POSSIBLE_PORT_SCAN": {
            "tactic": "Reconnaissance",
            "technique_id": "T1595",
            "technique_name": "Active Scanning"
        }
    }

    def map_attack(self, attack_type):

        if attack_type in self.ATTACK_MAP:
            return self.ATTACK_MAP[attack_type]

        return {
            "tactic": "Unknown",
            "technique_id": "N/A",
            "technique_name": "Generic Anomaly"
        }
