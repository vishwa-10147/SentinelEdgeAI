import os
import yaml

try:
    # optional: load .env if python-dotenv is installed
    from dotenv import load_dotenv  # type: ignore
    _HAS_DOTENV = True
except Exception:
    _HAS_DOTENV = False


class Config:
    """
    Centralized configuration loader for SentinelEdge AI.
    Loads parameters from `config.yaml` and optionally overlays environment
    variables. Environment variables intended to override nested keys should
    use a double-underscore separator, e.g. `logging__level=DEBUG`.
    """

    def __init__(self, path="config.yaml"):
        with open(path, "r") as f:
            self.config = yaml.safe_load(f) or {}

        # Load .env file into environment if python-dotenv is available.
        if _HAS_DOTENV:
            load_dotenv()

        # Overlay environment variables using double-underscore as nesting.
        for env_key, env_val in os.environ.items():
            if "__" in env_key:
                keys = [k.lower() for k in env_key.split("__")]
                self._set_nested(keys, env_val)

    def _set_nested(self, keys, value):
        """Set a nested value in the config, attempting to cast to the
        existing value's type when possible.
        """
        node = self.config
        for k in keys[:-1]:
            if k not in node or not isinstance(node[k], dict):
                node[k] = {}
            node = node[k]

        last = keys[-1]
        # Attempt to cast based on existing value type if present.
        if last in node:
            existing = node[last]
            try:
                if isinstance(existing, bool):
                    node[last] = value.lower() in ("1", "true", "yes", "on")
                elif isinstance(existing, int):
                    node[last] = int(value)
                elif isinstance(existing, float):
                    node[last] = float(value)
                else:
                    node[last] = value
            except Exception:
                node[last] = value
        else:
            # No existing value to infer type from; leave as string.
            node[last] = value

    def get(self, *keys):
        """
        Get configuration value by nested keys.
        Example: config.get("risk_thresholds", "critical")
        """
        value = self.config
        for key in keys:
            value = value[key]
        return value
