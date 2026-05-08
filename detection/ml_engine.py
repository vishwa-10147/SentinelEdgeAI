from sklearn.ensemble import IsolationForest
import numpy as np
import joblib
import os
from security.model_signing import ModelSignatureError, sign_model, verify_model_signature
from utils import metrics as metrics_utils


class MLEngine:

    def __init__(self, contamination=0.02, model_path="model/isolation_forest.pkl"):

        self.model_path = model_path
        self.training_data = []
        self.trained = False
        self.allow_unsigned_models = os.environ.get("SENTINEL_ALLOW_UNSIGNED_MODELS", "0") == "1"

        # Create folder if not exists
        os.makedirs("model", exist_ok=True)

        # Try loading existing model
        if os.path.exists(self.model_path):
            if self.allow_unsigned_models:
                # attempt to verify but do not fail startup if verification fails
                try:
                    verify_model_signature(self.model_path)
                    print("Loaded existing signed ML model (allow unsigned fallback enabled).")
                    try:
                        if metrics_utils.ML_MODEL_LOADED is not None:
                            metrics_utils.ML_MODEL_LOADED.set(1)
                        if metrics_utils.ML_SIGNATURE_STATUS is not None:
                            metrics_utils.ML_SIGNATURE_STATUS.set(1)
                    except Exception:
                        pass
                except ModelSignatureError as e:
                    print(f"Warning: model signature verification failed but continuing due to SENTINEL_ALLOW_UNSIGNED_MODELS=1: {e}")
                    try:
                        if metrics_utils.ML_MODEL_LOADED is not None:
                            metrics_utils.ML_MODEL_LOADED.set(1)
                        if metrics_utils.ML_SIGNATURE_STATUS is not None:
                            metrics_utils.ML_SIGNATURE_STATUS.set(2)
                    except Exception:
                        pass
                try:
                    self.model = joblib.load(self.model_path)
                    self.trained = True
                    try:
                        if metrics_utils.ML_MODEL_LOADED is not None:
                            metrics_utils.ML_MODEL_LOADED.set(1)
                        if metrics_utils.ML_SIGNATURE_STATUS is not None:
                            metrics_utils.ML_SIGNATURE_STATUS.set(1)
                    except Exception:
                        pass
                except Exception as e:
                    print(f"Failed to load existing model file: {e}")
                    self.model = IsolationForest(
                        n_estimators=100,
                        contamination=contamination,
                        random_state=42
                    )
                    self.trained = False
            else:
                # strict mode: require valid signature to load model
                # Let ModelSignatureError propagate so callers can handle startup failure
                verify_model_signature(self.model_path)
                try:
                    self.model = joblib.load(self.model_path)
                    self.trained = True
                    print("Loaded existing signed ML model.")
                    try:
                        if metrics_utils.ML_MODEL_LOADED is not None:
                            metrics_utils.ML_MODEL_LOADED.set(1)
                        if metrics_utils.ML_SIGNATURE_STATUS is not None:
                            metrics_utils.ML_SIGNATURE_STATUS.set(1)
                    except Exception:
                        pass
                except Exception as e:
                    print(f"Failed to load existing model file: {e}")
                    self.model = IsolationForest(
                        n_estimators=100,
                        contamination=contamination,
                        random_state=42
                    )
                    self.trained = False
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
        try:
            sign_model(self.model_path, signer="MLEngine.train")
            print("ML model trained, saved, and signed.")
        except ModelSignatureError:
            self.trained = False
            raise

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
