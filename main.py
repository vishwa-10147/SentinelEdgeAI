from capture.sniffer import start_sniffing, health_monitor
from core.config_loader import Config
from core.health_server import start_health_server
from utils.logger import setup_logger
import logging
try:
    from prometheus_client import start_http_server, Gauge, Counter
except Exception:
    start_http_server = None
    Gauge = None
    Counter = None


def _log_config_summary(cfg, logger):
    try:
        keys = list(cfg.config.keys())
    except Exception:
        keys = []
    logger.info("Config keys: %s", keys)
    try:
        logger.info("Logging level: %s", cfg.get("logging", "level"))
    except Exception:
        logger.debug("No logging.level in config")


if __name__ == "__main__":
    # Load configuration
    config = Config()

    # Set up logging with rotation
    log_level = getattr(
        logging,
        config.get("logging", "level"),
        logging.INFO
    )
    logger = setup_logger(
        level=log_level,
        max_bytes=config.get("logging", "max_bytes"),
        backup_count=config.get("logging", "backup_count")
    )

    _log_config_summary(config, logger)

    # Start health HTTP endpoint using the health monitor from the sniffer
    try:
        start_health_server(health_monitor, host=config.get("app", "host"), port=config.get("app", "port"))
    except Exception:
        logger.exception("Failed to start health server; continuing without it")

    # Start Prometheus metrics endpoint if library present
    try:
        metrics_port = config.get("app", "metrics_port") or 8001
        if start_http_server:
            # basic metrics: up and flows processed (flows_processed left for capture to increment)
            start_http_server(int(metrics_port))
            process_up = Gauge("sentinel_process_up", "Sentinel process up (1/0)")
            flows_processed = Counter("sentinel_flows_processed_total", "Total flows processed")
            process_up.set(1)
            logger.info("Prometheus metrics available on port %s", metrics_port)
        else:
            logger.debug("prometheus_client not installed; skipping metrics endpoint")
    except Exception:
        logger.exception("Failed to start Prometheus metrics server")

    logger.info("Starting SentinelEdge AI Flow Engine...")
    start_sniffing()
