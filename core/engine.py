class SentinelEngine:
    """
    Orchestrates all detection layers in a clean separation of concerns.
    """

    def __init__(
        self,
        anomaly_engine,
        ml_engine,
        fingerprint_engine,
        attack_classifier,
        risk_engine,
        mitre_mapper
    ):
        self.anomaly_engine = anomaly_engine
        self.ml_engine = ml_engine
        self.fingerprint_engine = fingerprint_engine
        self.attack_classifier = attack_classifier
        self.risk_engine = risk_engine
        self.mitre_mapper = mitre_mapper

    def process_flow(self, flow, features):
        """
        Process a single flow through all detection layers.
        Returns a structured result containing all analysis outputs.
        """

        # Statistical anomaly detection
        analysis = self.anomaly_engine.analyze(
            features,
            flow.initiator_ip,
            flow.protocol
        )

        anomaly_score = analysis["score"]
        triggers = analysis["triggers"]
        confidence = analysis["confidence"]

        # ML-based prediction layer
        ml_score = self.ml_engine.predict(features)

        # Behavioral fingerprinting
        self.fingerprint_engine.update(flow, anomaly_score)

        drift_info = self.fingerprint_engine.detect_drift(
            flow.initiator_ip
        )

        drift_flag = drift_info["drift"]
        drift_reason = drift_info.get("reason", "")

        # Attack type classification
        attack_type = self.attack_classifier.classify(
            flow,
            anomaly_score
        )

        # Final risk calculation
        final_risk = self.risk_engine.calculate_risk(
            anomaly_score,
            ml_score,
            drift_flag,
            attack_type
        )

        # MITRE ATT&CK mapping
        mitre_info = self.mitre_mapper.map_attack(attack_type)

        return {
            "anomaly_score": anomaly_score,
            "triggers": triggers,
            "confidence": confidence,
            "ml_score": ml_score,
            "drift": drift_flag,
            "drift_reason": drift_reason,
            "attack_type": attack_type,
            "final_risk": final_risk,
            "mitre": mitre_info
        }
