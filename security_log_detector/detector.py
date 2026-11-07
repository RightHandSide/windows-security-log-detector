from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta

from security_log_detector.models import DetectionResult, Event, RepeatedSignInFinding

class RepeatedSignInDetector:
    def analyze(self, events: list[Event]) -> DetectionResult:
        distinct_events = self._find_distinct_events(events)
        findings = self._detect_distinct_events(distinct_events)
        return DetectionResult(
            analyzed_count=len(distinct_events),
            findings=findings)

    def _find_distinct_events(self, events: list[Event]) -> list[Event]:
        ordered_events = sorted(events, key=lambda event: (
            event.timestamp,
            event.record_id,
            event.computer,
            event.target_domain,
            event.target_username))

        distinct_events = []
        seen_record_identities = {}
        for event in ordered_events:
            record_identity = (event.computer.casefold(), event.channel, event.record_id)
            record_details = (
                event.timestamp,
                event.target_domain.casefold(),
                event.target_username.casefold(),
                event.source_ip)

            if record_identity in seen_record_identities:
                if seen_record_identities[record_identity] != record_details:
                    raise ValueError(f"Conflicting copies of {event.channel} record {event.record_id} on {event.computer}: timestamp, target account, or source IP differs.")
                continue
            distinct_events.append(event)
            seen_record_identities[record_identity] = record_details
        return distinct_events


    def _detect_distinct_events(self, distinct_events: list[Event]) -> list[RepeatedSignInFinding]:
        findings = []
        group_states = defaultdict(_GroupState)
        for event in distinct_events:
            group_key = (
                event.computer.casefold(),
                event.target_domain.casefold(),
                event.target_username.casefold(),
                event.source_ip)

            state = group_states[group_key]
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

    def detect(self, events: list[Event]) -> list[RepeatedSignInFinding]:
        return self.analyze(events).findings

@dataclass
class _GroupState:
    window: deque[Event] = field(default_factory=deque)
    alerted: bool = False