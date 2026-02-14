from sklearn.ensemble import IsolationForest
import numpy as np
import joblib
import os


class MLEngine:

    def __init__(self, contamination=0.02, model_path="model/isolation_forest.pkl"):

        self.model_path = model_path
        self.training_data = []
        self.trained = False

        # Create folder if not exists
        os.makedirs("model", exist_ok=True)

        # Try loading existing model
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            self.trained = True
            print("✅ Loaded existing ML model.")
        else:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=42
            )

    def add_training_sample(self, features):
        self.training_data.append(self._to_vector(features))

    def train(self):
        if len(self.training_data) < 100:
            return False

        X = np.array(self.training_data)
        self.model.fit(X)
        self.trained = True

        # Save model after training
        joblib.dump(self.model, self.model_path)
        print("💾 ML model trained and saved.")

        return True

    def predict(self, features):
        if not self.trained:
            return 0

        vector = self._to_vector(features)
        result = self.model.predict([vector])

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
