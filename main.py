from capture.sniffer import start_sniffing, health_monitor
from core.config_loader import Config
from core.health_server import start_health_server
from utils.logger import setup_logger
import logging
from utils.metrics import start_metrics_server, PROCESS_UP, FLOWS_COUNTER


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
        ok = start_metrics_server(metrics_port)
        if ok:
            try:
                if PROCESS_UP is not None:
                    PROCESS_UP.set(1)
            except Exception:
                pass
            logger.info("Prometheus metrics available on port %s", metrics_port)
        else:
            logger.debug("prometheus_client not installed or failed; skipping metrics endpoint")
    except Exception:
        logger.exception("Failed to start Prometheus metrics server")

    logger.info("Starting SentinelEdge AI Flow Engine...")
    start_sniffing()
