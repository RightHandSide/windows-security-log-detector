from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta

from security_log_detector.models import Event, RepeatedSignInFinding

class RepeatedSignInDetector:
    def detect(self, events: list[Event]) -> list[RepeatedSignInFinding]:
        ordered_events = sorted(events, key=lambda event: (
            event.timestamp,
            event.record_id,
            event.computer,
            event.target_domain,
            event.target_username))

        findings = []
        seen_record_ids = {}
        group_states = defaultdict(_GroupState)
        for event in ordered_events:
            record_identity = (event.computer.casefold(), event.channel, event.record_id)
            record_details = (
                event.timestamp,
                event.target_domain.casefold(),
                event.target_username.casefold(),
                event.source_ip)
            user_identity = (
                event.computer.casefold(),
                event.target_domain.casefold(),
                event.target_username.casefold(),
                event.source_ip)

            if record_identity in seen_record_ids:
                if seen_record_ids[record_identity] != record_details:
                    raise ValueError(f"Conflicting copies of {event.channel} record {event.record_id} on {event.computer}: timestamp, target account, or source IP differs.")
                continue
            seen_record_ids[record_identity] = record_details

            state = group_states[user_identity]
            while state.window and event.timestamp - state.window[0].timestamp > timedelta(minutes=5):
                state.window.popleft()

            if len(state.window) < 5:
                state.alerted = False

            state.window.append(event)
            if len(state.window) == 5 and not state.alerted:
                state.alerted = True
                findings.append(RepeatedSignInFinding(
                    first_timestamp=state.window[0].timestamp,
                    last_timestamp=event.timestamp,
                    computer=event.computer,
                    target_username=event.target_username,
                    target_domain=event.target_domain,
                    source_ip=event.source_ip,
                    count=5,
                    reason="Five failed sign-ins for the same target account on the same computer from the same source IP within five minutes."))
        return findings

@dataclass
class _GroupState:
    window: deque[Event] = field(default_factory=deque)
    alerted: bool = False