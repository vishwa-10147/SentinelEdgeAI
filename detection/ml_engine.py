from sklearn.ensemble import IsolationForest
import numpy as np


class MLEngine:
    def __init__(self, contamination=0.02):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42
        )
        self.trained = False
        self.training_data = []

    def add_training_sample(self, features):
        vector = self._to_vector(features)
        self.training_data.append(vector)

    def train(self):
        if len(self.training_data) < 100:
            return False  # Need minimum samples

        X = np.array(self.training_data)
        self.model.fit(X)
        self.trained = True
        return True

    def predict(self, features):
        if not self.trained:
            return 0  # Neutral (no ML decision yet)

        vector = self._to_vector(features)
        result = self.model.predict([vector])

        # IsolationForest returns:
        # -1 = anomaly
        #  1 = normal
        return 1 if result[0] == -1 else 0

    def _to_vector(self, features):
        return [
            features["duration"],
            features["total_bytes"],
            features["total_packets"],
            features["byte_ratio"],
        ]
