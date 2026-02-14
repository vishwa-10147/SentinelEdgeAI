from dataclasses import dataclass
from datetime import datetime


@dataclass
class FlowRecord:
    # Flow identity (initiator-based)
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    protocol: str  # TCP / UDP / ICMP

    # Timing
    start_time: datetime
    end_time: datetime
    duration: float  # seconds

    # Directional statistics
    forward_bytes: int
    backward_bytes: int
    forward_packets: int
    backward_packets: int

    # Flow termination reason
    flow_state: str  # "IDLE_TIMEOUT" / "ACTIVE_TIMEOUT"
