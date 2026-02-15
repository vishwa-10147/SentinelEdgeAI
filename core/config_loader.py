import yaml


class Config:
    """
    Centralized configuration loader for SentinelEdge AI.
    Loads all tunable parameters from config.yaml.
    """

    def __init__(self, path="config.yaml"):
        with open(path, "r") as f:
            self.config = yaml.safe_load(f)

    def get(self, *keys):
        """
        Get configuration value by nested keys.
        Example: config.get("risk_thresholds", "critical")
        """
        value = self.config
        for key in keys:
            value = value[key]
        return value
