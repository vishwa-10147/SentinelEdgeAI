"""
Health Monitoring Module - Engine Self-Monitoring

Provides:
- System health indicator
- Engine uptime tracking
- Flow count metrics
- CPU + Memory snapshot
- "Is engine alive?" check for production systems
"""

import time
import psutil


class HealthMonitor:
    """Monitors engine health and resource usage"""

    def __init__(self):
        self.start_time = time.time()
        self.flows_processed = 0

    def update_flows(self):
        """Increment flow counter"""
        self.flows_processed += 1

    def get_status(self):
        """
        Get comprehensive health status

        Returns:
            dict: Status including uptime, flows, CPU, memory
        """
        uptime_seconds = int(time.time() - self.start_time)
        process = psutil.Process()

        return {
            "status": "running",
            "uptime_seconds": uptime_seconds,
            "flows_processed": self.flows_processed,
            "cpu_usage_percent": psutil.cpu_percent(interval=None),
            "memory_usage_mb": round(
                process.memory_info().rss / (1024 * 1024), 2
            )
        }
