from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_address

import pytest

from security_log_detector.detector import RepeatedSignInDetector
from security_log_detector.models import Event


def make_event(record_id, timestamp):
    return Event(
        event_id=4625,
        timestamp=timestamp,
        record_id=record_id,
        channel="Security",
        computer="PC-A",
        target_username="alice",
        target_domain="LAB",
        source_ip=ip_address("192.0.2.10"),
    )


class TestRepeatedSignInDetector:
    def test_equivalent_ipv6_spellings_of_distinct_records_form_qualifying_group(self):
        events = [
            replace(
                make_event(
                    record_id=minute + 1,
                    timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
                ),
                source_ip=ip_address("2001:0db8:0000:0000:0000:0000:0000:0010"),
            )
            for minute in range(5)
        ]
        events[-1] = replace(events[-1], source_ip=ip_address("2001:db8::10"))

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        assert findings[0].source_ip == ip_address("2001:db8::10")
        assert findings[0].count == 5
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    def test_conflicting_copy_after_qualifying_burst_still_raises_value_error(self):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(5)
        ]
        conflicting_copy = replace(
            events[-1], timestamp=datetime(2026, 11, 5, 10, 6, tzinfo=timezone.utc)
        )

        with pytest.raises(ValueError):
            RepeatedSignInDetector().detect(events + [conflicting_copy])

    def test_ipv4_and_mapped_ipv6_do_not_combine_attempt_counts(self):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(5)
        ]
        events[-1] = replace(
            events[-1], source_ip=ip_address("::ffff:192.0.2.10")
        )

        findings = RepeatedSignInDetector().detect(events)

        assert findings == []

    def test_simultaneous_findings_follow_triggering_record_id_order(self):
        events = []
        for minute in range(4):
            events.append(make_event(
                record_id=2 * minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            ))
            events.append(replace(
                make_event(
                    record_id=2 * minute + 2,
                    timestamp=datetime(2026, 11, 5, 10, minute, 30, tzinfo=timezone.utc),
                ),
                target_username="bob",
            ))
        events.extend([
            make_event(20, datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)),
            replace(
                make_event(10, datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)),
                target_username="bob",
            ),
        ])

        findings = RepeatedSignInDetector().detect(events)

        assert [finding.target_username for finding in findings] == ["bob", "alice"]
        assert [finding.count for finding in findings] == [5, 5]
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, 30, tzinfo=timezone.utc)
        assert findings[1].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)
        assert findings[1].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    def test_alerted_account_does_not_suppress_another_accounts_finding(self):
        events = []
        for minute in range(9):
            events.append(make_event(
                record_id=2 * minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            ))
            if minute >= 4:
                events.append(replace(
                    make_event(
                        record_id=2 * minute + 2,
                        timestamp=datetime(2026, 11, 5, 10, minute, 30, tzinfo=timezone.utc),
                    ),
                    target_username="bob",
                ))

        findings = RepeatedSignInDetector().detect(events)

        assert [finding.target_username for finding in findings] == ["alice", "bob"]
        assert [finding.count for finding in findings] == [5, 5]
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)
        assert findings[1].first_timestamp == datetime(2026, 11, 5, 10, 4, 30, tzinfo=timezone.utc)
        assert findings[1].last_timestamp == datetime(2026, 11, 5, 10, 8, 30, tzinfo=timezone.utc)

    @pytest.mark.parametrize(
        ("preferred_domain", "preferred_username", "other_domain", "other_username"),
        [
            pytest.param("LAB", "alice", "lab", "ALICE", id="domain-before-username"),
            pytest.param("LAB", "ALICE", "LAB", "alice", id="username-breaks-domain-tie"),
        ],
    )
    def test_consistent_copy_selection_compares_domain_then_username(
        self, preferred_domain, preferred_username, other_domain, other_username
    ):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(4)
        ]
        triggering_record = make_event(
            record_id=5,
            timestamp=datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc),
        )
        preferred_copy = replace(
            triggering_record,
            target_domain=preferred_domain,
            target_username=preferred_username,
        )
        other_copy = replace(
            triggering_record,
            target_domain=other_domain,
            target_username=other_username,
        )

        findings = RepeatedSignInDetector().detect(events + [other_copy, preferred_copy])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.computer == "PC-A"
        assert finding.target_domain == preferred_domain
        assert finding.target_username == preferred_username
        assert finding.count == 5
        assert finding.first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert finding.last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    @pytest.mark.parametrize(
        "preferred_copy_first",
        [True, False],
        ids=["preferred-copy-first", "preferred-copy-last"],
    )
    def test_consistent_copies_choose_smallest_original_spelling_tuple(self, preferred_copy_first):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(4)
        ]
        triggering_record = make_event(
            record_id=5,
            timestamp=datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc),
        )
        preferred_copy = replace(
            triggering_record, computer="PC-A", target_domain="lab", target_username="alice"
        )
        other_copy = replace(
            triggering_record, computer="pc-a", target_domain="LAB", target_username="ALICE"
        )
        copies = [preferred_copy, other_copy] if preferred_copy_first else [other_copy, preferred_copy]

        findings = RepeatedSignInDetector().detect(events + copies)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.computer == "PC-A"
        assert finding.target_domain == "lab"
        assert finding.target_username == "alice"
        assert finding.count == 5
        assert finding.first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert finding.last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    def test_reusing_detector_analyzes_same_records_again(self):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(5)
        ]
        detector = RepeatedSignInDetector()

        first_findings = detector.detect(events)
        second_findings = detector.detect(events)

        for findings in [first_findings, second_findings]:
            assert len(findings) == 1
            assert findings[0].count == 5
            assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
            assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    def test_separate_calls_do_not_combine_attempts_into_threshold(self):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(5)
        ]
        detector = RepeatedSignInDetector()

        first_findings = detector.detect(events[:4])
        second_findings = detector.detect(events[4:])

        assert first_findings == []
        assert second_findings == []

    @pytest.mark.parametrize(
        "tied_record_ids",
        [
            pytest.param([104, 105], id="lower-record-id-first"),
            pytest.param([105, 104], id="higher-record-id-first"),
        ],
    )
    def test_equal_timestamps_use_record_id_to_choose_triggering_evidence(self, tied_record_ids):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(4)
        ]
        tied_events = {
            104: replace(
                make_event(104, datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)),
                computer="pc-a", target_domain="lab", target_username="Alice",
            ),
            105: replace(
                make_event(105, datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)),
                computer="PC-A", target_domain="LAB", target_username="ALICE",
            ),
        }
        events.extend(tied_events[record_id] for record_id in tied_record_ids)

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        assert findings[0].computer == "pc-a"
        assert findings[0].target_domain == "lab"
        assert findings[0].target_username == "Alice"
        assert findings[0].count == 5
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    def test_evidence_spelling_comes_from_chronological_fifth_triggering_attempt(self):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(5)
        ]
        events[-1] = replace(
            events[-1], computer="pc-a", target_domain="lab", target_username="ALICE"
        )

        findings = RepeatedSignInDetector().detect(list(reversed(events)))

        assert len(findings) == 1
        finding = findings[0]
        assert finding.computer == "pc-a"
        assert finding.target_domain == "lab"
        assert finding.target_username == "ALICE"
        assert finding.count == 5
        assert finding.first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert finding.last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    @pytest.mark.parametrize(
        ("field", "equivalent_value"),
        [
            pytest.param("computer", "pc-a", id="computer-capitalization"),
            pytest.param("target_domain", "lab", id="domain-capitalization"),
            pytest.param("target_username", "ALICE", id="username-capitalization"),
        ],
    )
    def test_capitalization_variants_of_distinct_records_share_group(
        self, field, equivalent_value
    ):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(5)
        ]
        events[-1] = replace(events[-1], **{field: equivalent_value})

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        assert findings[0].count == 5
        assert findings[0].source_ip == ip_address("192.0.2.10")
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    @pytest.mark.parametrize(
        ("field", "equivalent_value"),
        [
            pytest.param("computer", "pc-a", id="computer-capitalization"),
            pytest.param("target_domain", "lab", id="domain-capitalization"),
            pytest.param("target_username", "ALICE", id="username-capitalization"),
            pytest.param("source_ip", ip_address("2001:db8::10"), id="equivalent-ipv6"),
        ],
    )
    def test_equivalent_copies_are_not_conflicts_and_count_once(self, field, equivalent_value):
        original = replace(
            make_event(
                record_id=1,
                timestamp=datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc),
            ),
            source_ip=ip_address("2001:0db8:0000:0000:0000:0000:0000:0010"),
        )
        events = [original] + [
            replace(original, **{field: equivalent_value}) for _ in range(4)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert findings == []

    @pytest.mark.parametrize(
        ("field", "different_value"),
        [
            pytest.param("target_username", "bob", id="conflicting-username"),
            pytest.param("target_domain", "OTHER", id="conflicting-domain"),
            pytest.param("source_ip", ip_address("192.0.2.20"), id="conflicting-source-ip"),
        ],
    )
    def test_same_record_identity_with_conflicting_details_raises_value_error(
        self, field, different_value
    ):
        original = make_event(
            record_id=1,
            timestamp=datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc),
        )
        conflicting_copy = replace(original, **{field: different_value})

        with pytest.raises(ValueError):
            RepeatedSignInDetector().detect([original, conflicting_copy])

    def test_same_record_identity_with_conflicting_timestamps_raises_value_error(self):
        original = make_event(
            record_id=1,
            timestamp=datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc),
        )
        conflicting_copy = replace(
            original,
            timestamp=datetime(2026, 11, 5, 10, 1, tzinfo=timezone.utc),
        )

        with pytest.raises(ValueError):
            RepeatedSignInDetector().detect([original, conflicting_copy])

    def test_duplicate_copies_preserve_genuine_finding_and_evidence(self):
        events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, record_id - 1, tzinfo=timezone.utc),
            )
            for record_id in [1, 1, 2, 2, 3, 3, 4, 4, 5, 5]
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.computer == "PC-A"
        assert finding.target_domain == "LAB"
        assert finding.target_username == "alice"
        assert finding.source_ip == ip_address("192.0.2.10")
        assert finding.count == 5
        assert finding.first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert finding.last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    def test_distinct_record_ids_at_same_timestamp_count_separately(self):
        timestamp = datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        events = [make_event(record_id, timestamp) for record_id in [1, 2, 3, 4, 5]]

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        assert findings[0].count == 5
        assert findings[0].first_timestamp == timestamp
        assert findings[0].last_timestamp == timestamp

    @pytest.mark.parametrize(
        "record_ids",
        [
            pytest.param([1, 1, 1, 1, 1], id="five-copies-of-one-record"),
            pytest.param([1, 2, 3, 4, 4], id="four-distinct-records-plus-copy"),
        ],
    )
    def test_duplicate_copies_do_not_manufacture_threshold(self, record_ids):
        events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, record_id - 1, tzinfo=timezone.utc),
            )
            for record_id in record_ids
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert findings == []

    @pytest.mark.parametrize("bob_attempt_count", [4, 5])
    def test_interleaved_accounts_have_independent_windows_and_evidence(self, bob_attempt_count):
        events = []
        for minute in range(5):
            events.append(make_event(
                record_id=2 * minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            ))
            if minute < bob_attempt_count:
                events.append(replace(
                    make_event(
                        record_id=2 * minute + 2,
                        timestamp=datetime(2026, 11, 5, 10, minute, 30, tzinfo=timezone.utc),
                    ),
                    target_username="bob",
                ))

        findings = RepeatedSignInDetector().detect(events)

        expected_count = 1 if bob_attempt_count == 4 else 2
        assert len(findings) == expected_count
        by_username = {finding.target_username: finding for finding in findings}
        assert set(by_username) == ({"alice"} if bob_attempt_count == 4 else {"alice", "bob"})
        alice = by_username["alice"]
        assert alice.count == 5
        assert alice.first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert alice.last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)
        if bob_attempt_count == 5:
            bob = by_username["bob"]
            assert bob.count == 5
            assert bob.first_timestamp == datetime(2026, 11, 5, 10, 0, 30, tzinfo=timezone.utc)
            assert bob.last_timestamp == datetime(2026, 11, 5, 10, 4, 30, tzinfo=timezone.utc)

    @pytest.mark.parametrize(
        ("field", "different_value"),
        [
            pytest.param("target_username", "bob", id="different-username"),
            pytest.param("target_domain", "OTHER", id="different-domain"),
            pytest.param("source_ip", ip_address("192.0.2.20"), id="different-source-ip"),
        ],
    )
    def test_different_group_does_not_supply_fifth_attempt(self, field, different_value):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(5)
        ]
        events[-1] = replace(events[-1], **{field: different_value})

        findings = RepeatedSignInDetector().detect(events)

        assert findings == []

    @pytest.mark.parametrize(
        "input_order",
        [
            pytest.param([4, 3, 2, 1, 0], id="reversed"),
            pytest.param([3, 0, 4, 1, 2], id="shuffled"),
        ],
    )
    def test_input_order_does_not_change_findings_or_mutate_input(self, input_order):
        chronological_events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for record_id, minute in enumerate([0, 1, 2, 3, 5], start=1)
        ]
        events = [chronological_events[index] for index in input_order]
        original_order = list(events)

        findings = RepeatedSignInDetector().detect(events)

        assert events == original_order
        assert len(findings) == 1
        finding = findings[0]
        assert finding.computer == "PC-A"
        assert finding.target_domain == "LAB"
        assert finding.target_username == "alice"
        assert finding.source_ip == ip_address("192.0.2.10")
        assert finding.count == 5
        assert finding.first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert finding.last_timestamp == datetime(2026, 11, 5, 10, 5, tzinfo=timezone.utc)

    def test_empty_input_returns_no_findings(self):
        findings = RepeatedSignInDetector().detect([])

        assert findings == []

    @pytest.mark.parametrize("attempt_count", [1, 4])
    def test_fewer_than_five_failures_returns_no_findings(self, attempt_count):
        events = [
            make_event(
                record_id=minute + 1,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for minute in range(attempt_count)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert findings == []

    def test_five_failures_in_inclusive_window_returns_triggering_evidence(self):
        events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for record_id, minute in enumerate([0, 1, 2, 3, 5], start=1)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.computer == "PC-A"
        assert finding.target_domain == "LAB"
        assert finding.target_username == "alice"
        assert finding.source_ip == ip_address("192.0.2.10")
        assert finding.count == 5
        assert finding.first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert finding.last_timestamp == datetime(2026, 11, 5, 10, 5, tzinfo=timezone.utc)
        assert isinstance(finding.reason, str)
        assert finding.reason.strip()

    def test_five_failures_just_outside_window_returns_no_findings(self):
        timestamps = [
            datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc),
            datetime(2026, 11, 5, 10, 1, tzinfo=timezone.utc),
            datetime(2026, 11, 5, 10, 2, tzinfo=timezone.utc),
            datetime(2026, 11, 5, 10, 3, tzinfo=timezone.utc),
            datetime(2026, 11, 5, 10, 5, 0, 1, tzinfo=timezone.utc),
        ]
        events = [
            make_event(record_id, timestamp)
            for record_id, timestamp in enumerate(timestamps, start=1)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert findings == []

    def test_later_qualifying_window_excludes_expired_attempt_from_evidence(self):
        events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for record_id, minute in enumerate([0, 6, 7, 8, 9, 10], start=1)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.count == 5
        assert finding.first_timestamp == datetime(2026, 11, 5, 10, 6, tzinfo=timezone.utc)
        assert finding.last_timestamp == datetime(2026, 11, 5, 10, 10, tzinfo=timezone.utc)

    def test_single_attempt_after_expired_burst_does_not_trigger_again(self):
        events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for record_id, minute in enumerate([0, 1, 2, 3, 4, 10], start=1)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        assert findings[0].count == 5
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    def test_new_burst_after_expiration_produces_second_finding(self):
        events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for record_id, minute in enumerate([0, 1, 2, 3, 4, 10, 11, 12, 13, 14], start=1)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 2
        assert findings[0].count == 5
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)
        assert findings[1].count == 5
        assert findings[1].first_timestamp == datetime(2026, 11, 5, 10, 10, tzinfo=timezone.utc)
        assert findings[1].last_timestamp == datetime(2026, 11, 5, 10, 14, tzinfo=timezone.utc)

    def test_continuing_burst_suppresses_findings_and_preserves_first_evidence(self):
        events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for record_id, minute in enumerate([0, 1, 2, 3, 4, 5, 6], start=1)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 1
        assert findings[0].count == 5
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)

    def test_expiration_rearms_before_new_attempt_brings_count_back_to_five(self):
        events = [
            make_event(
                record_id=record_id,
                timestamp=datetime(2026, 11, 5, 10, minute, tzinfo=timezone.utc),
            )
            for record_id, minute in enumerate([0, 1, 2, 3, 4, 6], start=1)
        ]

        findings = RepeatedSignInDetector().detect(events)

        assert len(findings) == 2
        assert findings[0].count == 5
        assert findings[0].first_timestamp == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
        assert findings[0].last_timestamp == datetime(2026, 11, 5, 10, 4, tzinfo=timezone.utc)
        assert findings[1].count == 5
        assert findings[1].first_timestamp == datetime(2026, 11, 5, 10, 1, tzinfo=timezone.utc)
        assert findings[1].last_timestamp == datetime(2026, 11, 5, 10, 6, tzinfo=timezone.utc)
