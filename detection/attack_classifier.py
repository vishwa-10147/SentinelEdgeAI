class AttackClassifier:

    def classify(self, flow, threat_score):

        if threat_score < 2:
            return "NONE"

        # Possible data exfiltration
        if flow.forward_bytes > 5 * flow.backward_bytes:
            return "POSSIBLE_DATA_EXFILTRATION"

        # Long session anomaly
        if flow.duration > 30:
            return "LONG_SUSPICIOUS_SESSION"

        # Large traffic burst
        if flow.forward_packets + flow.backward_packets > 500:
            return "TRAFFIC_FLOOD"

        # Common scan ports
        if flow.responder_port in [22, 23, 3389, 445]:
            return "POSSIBLE_PORT_SCAN"

        return "GENERIC_ANOMALY"
