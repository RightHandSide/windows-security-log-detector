from ipaddress import IPv4Address, IPv6Address
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Event:
    event_id: int
    timestamp: datetime
    record_id: int
    channel: str
    computer: str
    target_username: str
    target_domain: str
    source_ip: IPv4Address | IPv6Address

@dataclass(frozen=True)
class RepeatedSignInFinding:
    first_timestamp: datetime
    last_timestamp: datetime
    computer: str
    target_username: str
    target_domain: str
    source_ip: IPv4Address | IPv6Address
    count: int
    reason: str

class ReadResult:
    def __init__(self, events, skipped_count):
        self.events = events
        self.skipped_count = skipped_count