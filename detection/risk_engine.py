class RiskEscalationEngine:

    def calculate_risk(
        self,
        anomaly_score,
        ml_score,
        drift_flag,
        attack_type
    ):

        risk = 0

        # Statistical anomaly weight
        risk += anomaly_score * 15

        # ML anomaly weight
        risk += ml_score * 20

        # Behavioral drift weight
        if drift_flag:
            risk += 25

        # Attack classification weight
        if attack_type == "POSSIBLE_DATA_EXFILTRATION":
            risk += 30
        elif attack_type == "TRAFFIC_FLOOD":
            risk += 25
        elif attack_type == "LONG_SUSPICIOUS_SESSION":
            risk += 20
        elif attack_type == "POSSIBLE_PORT_SCAN":
            risk += 15

        # Cap at 100
        return min(risk, 100)
