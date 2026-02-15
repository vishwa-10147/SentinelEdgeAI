from capture.sniffer import start_sniffing
from core.config_loader import Config
from utils.logger import setup_logger
import logging


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

    logger.info("Starting SentinelEdge AI Flow Engine...")
    start_sniffing()
