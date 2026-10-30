from capture.sniffer import start_sniffing, health_monitor
from core.config_loader import Config
from core.health_server import start_health_server
from utils.logger import setup_logger
import logging
import os
import threading
import time
from core import setup as device_setup
from utils.metrics import start_metrics_server

# exit code that tells systemd (Restart=on-failure) to start the engine again
RESTART_EXIT_CODE = 75


def _watch_capture_interface(active, logger, interval=5):
    # the setup wizard runs in the unprivileged API, which cannot restart this
    # service; when the chosen interface changes, exit and let systemd restart us
    while True:
        time.sleep(interval)
        try:
            wanted = device_setup.capture_interface()
        except Exception:
            logger.debug("could not read setup", exc_info=True)
            continue
        if wanted != active:
            logger.warning("capture interface changed from %s to %s; restarting the engine",
                           active or "default", wanted or "default")
            logging.shutdown()
            os._exit(RESTART_EXIT_CODE)


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
            logger.info("Prometheus metrics available on port %s", metrics_port)
        else:
            logger.debug("prometheus_client not installed or failed; skipping metrics endpoint")
    except Exception:
        logger.exception("Failed to start Prometheus metrics server")

    def _refresh_identities():
        from enforcement import identity
        while True:
            try:
                identity.get_registry().refresh_from_arp()
            except Exception:
                logger.debug("ARP refresh failed", exc_info=True)
            time.sleep(60)

    threading.Thread(target=_refresh_identities, daemon=True).start()

    def _collect_metrics():
        from utils.metrics import collect_system
        while True:
            collect_system()
            time.sleep(15)

    threading.Thread(target=_collect_metrics, daemon=True).start()

    try:
        from capture.sniffer import alert_logger
        from integrations.suricata import start_in_engine
        start_in_engine(alert_logger)
    except Exception:
        logger.exception("Suricata integration failed to start")

    interface = device_setup.capture_interface()
    logger.info("Starting SentinelEdge AI Flow Engine on %s", interface or "the default interface")
    threading.Thread(target=_watch_capture_interface, args=(interface, logger), daemon=True).start()
    start_sniffing(interface=interface)
