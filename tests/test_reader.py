import builtins
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from xml.etree.ElementTree import ParseError

import pytest

from security_log_detector.reader import XmlEventReader


def _event_xml(**overrides):
    """Build the original single-event fixture, preserving its XML formatting."""
    fields = {
        "system": True,
        "event_data": True,
        "time_created": True,
        "event_id": "4625",
        "timestamp": "2026-11-03T10:00:00Z",
        "record_id": "42",
        "channel": "Security",
        "computer": "PC-A",
        "target_username": "alice",
        "target_domain": "LAB",
        "source_ip": "192.0.2.10",
    }
    fields.update(overrides)
    lines = [
        "<Events>",
        '                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
    ]
    if fields["system"]:
        lines.extend([
            "                    <System>",
            '                        <Provider Name="Microsoft-Windows-Security-Auditing" />',
        ])
        if fields["event_id"] is not None:
            lines.append(f"                        <EventID>{fields['event_id']}</EventID>")
        if fields["time_created"]:
            if fields["timestamp"] is None:
                lines.append("                        <TimeCreated />")
            else:
                lines.append(f'                        <TimeCreated SystemTime="{fields["timestamp"]}" />')
        for field, tag in [("record_id", "EventRecordID"), ("channel", "Channel"), ("computer", "Computer")]:
            if fields[field] is not None:
                lines.append(f"                        <{tag}>{fields[field]}</{tag}>")
        lines.append("                    </System>")
    if fields["event_data"]:
        lines.append("                    <EventData>")
        for field, name in [
            ("target_username", "TargetUserName"),
            ("target_domain", "TargetDomainName"),
            ("source_ip", "IpAddress"),
        ]:
            if fields[field] is not None:
                lines.append(f'                        <Data Name="{name}">{fields[field]}</Data>')
        lines.append("                    </EventData>")
    lines.extend(["                </Event>", "            </Events>"])
    return "\n".join(lines)


class TestXmlEventReader:
    def test_reads_empty_events_document(self, tmp_path):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text("<Events />", encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 0

    def test_propagates_missing_file_error(self, tmp_path):
        xml_path = tmp_path / "missing.xml"

        with pytest.raises(FileNotFoundError):
            XmlEventReader().read(xml_path)

    def test_propagates_permission_error(self, tmp_path, monkeypatch):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text("<Events />", encoding="utf-8")
        denied_error = PermissionError("Access denied to events.xml")
        original_open = builtins.open

        def deny_event_file(file, *args, **kwargs):
            if file == xml_path:
                raise denied_error
            return original_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", deny_event_file)

        with pytest.raises(PermissionError) as raised:
            XmlEventReader().read(xml_path)

        assert raised.value is denied_error

    def test_rejects_malformed_xml(self, tmp_path):
        xml_path = tmp_path / "malformed.xml"
        xml_path.write_text("<Events>", encoding="utf-8")

        with pytest.raises(ParseError):
            XmlEventReader().read(xml_path)

    @pytest.mark.parametrize(
        ("root_tag", "event_namespace"),
        [
            pytest.param(
                "Logs",
                "http://schemas.microsoft.com/win/2004/08/events/event",
                id="unsupported-root",
            ),
            pytest.param("Events", None, id="missing-event-namespace"),
            pytest.param("Events", "urn:unsupported-events", id="wrong-event-namespace"),
        ],
    )
    def test_rejects_unsupported_xml_structure(self, tmp_path, root_tag, event_namespace):
        namespace_declaration = (
            f' xmlns="{event_namespace}"' if event_namespace is not None else ""
        )
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<{root_tag}>
                <Event{namespace_declaration}>
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-03T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </{root_tag}>""",
            encoding="utf-8")

        with pytest.raises(ValueError):
            XmlEventReader().read(xml_path)

    @pytest.mark.parametrize(
        "child_xml",
        [
            pytest.param(
                "<Metadata />",
                id="unexpected-child",
            ),
            pytest.param(
                """<Wrapper>
                        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event" />
                    </Wrapper>""",
                id="nested-event-wrapper",
            ),
        ],
    )
    def test_version_1_rejects_non_event_children(self, tmp_path, child_xml):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                {child_xml}
            </Events>""",
            encoding="utf-8")

        with pytest.raises(ValueError):
            XmlEventReader().read(xml_path)

    @pytest.mark.parametrize(
        ("invalid_tail", "expected_error"),
        [
            pytest.param(
                "</Events><",
                ParseError,
                id="malformed-xml-after-valid-event",
            ),
            pytest.param(
                """<Event xmlns="urn:unsupported-events" />
            </Events>""",
                ValueError,
                id="wrong-namespace-after-valid-event",
            ),
        ],
    )
    def test_rejects_file_with_error_after_valid_event(self, tmp_path, invalid_tail, expected_error):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
                {invalid_tail}""",
            encoding="utf-8")

        with pytest.raises(expected_error):
            XmlEventReader().read(xml_path)

    @pytest.mark.parametrize(
        ("timestamp_text", "expected_microsecond"),
        [
            pytest.param("2026-11-04T10:00:00.123456Z", 123456, id="six-digits"),
            pytest.param("2026-11-04T10:00:00.1234567Z", 123456, id="seventh-digit-discarded"),
            pytest.param("2026-11-04T10:00:00.0000001Z", 0, id="sub-microsecond-discarded"),
        ],
    )
    def test_converts_fractional_timestamp_to_datetime(self, tmp_path, timestamp_text, expected_microsecond):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="{timestamp_text}" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert len(result.events) == 1
        assert result.skipped_count == 0
        assert result.events[0].timestamp == datetime(
            2026, 11, 4, 10, 0, 0, expected_microsecond, tzinfo=timezone.utc
        )

    @pytest.mark.parametrize(
        ("timestamp_text", "expected_timestamp"),
        [
            pytest.param(
                "0001-01-01T00:00:00Z",
                datetime(1, 1, 1, tzinfo=timezone.utc),
                id="minimum-utc",
            ),
            pytest.param(
                "9999-12-31T23:59:59.999999Z",
                datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc),
                id="maximum-utc",
            ),
            pytest.param("0001-01-01T00:00:00+01:00", None, id="utc-underflow"),
            pytest.param("9999-12-31T23:59:59.999999-01:00", None, id="utc-overflow"),
        ],
    )
    def test_handles_utc_timestamp_range(self, tmp_path, timestamp_text, expected_timestamp):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(_event_xml(timestamp=timestamp_text), encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        if expected_timestamp is None:
            assert result.events == []
            assert result.skipped_count == 1
        else:
            assert len(result.events) == 1
            assert result.events[0].timestamp == expected_timestamp
            assert result.skipped_count == 0

    @pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
    def test_reads_declared_encoding_and_preserves_unicode(self, tmp_path, encoding):
        xml_path = tmp_path / "events.xml"
        xml_text = (
            f'<?xml version="1.0" encoding="{encoding}"?>\n'
            + _event_xml(target_username="José")
        )
        xml_path.write_text(xml_text, encoding=encoding)

        result = XmlEventReader().read(xml_path)

        assert len(result.events) == 1
        assert result.events[0].target_username == "José"
        assert result.skipped_count == 0

    def test_extracts_one_valid_failed_sign_in(self, tmp_path):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            """<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-03T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert len(result.events) == 1
        assert result.skipped_count == 0
        event = result.events[0]
        assert event.timestamp == datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)
        assert event.computer == "PC-A"
        assert event.target_domain == "LAB"
        assert event.target_username == "alice"
        assert event.source_ip == IPv4Address("192.0.2.10")
        assert event.channel == "Security"
        assert event.record_id == 42

    def test_extracts_event_with_valid_ipv6_source_ip(self, tmp_path):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            """<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-03T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">2001:0db8:0000:0000:0000:0000:0000:0001</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert len(result.events) == 1
        assert result.skipped_count == 0
        assert result.events[0].source_ip == IPv6Address("2001:db8::1")

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({'source_ip': None}, id="missing-source-ip"),
            pytest.param({'target_username': None}, id="missing-target-username"),
            pytest.param({'target_domain': None}, id="missing-target-domain"),
            pytest.param({'computer': None}, id="missing-computer"),
            pytest.param({'channel': None}, id="missing-channel"),
            pytest.param({'record_id': None}, id="missing-record-id"),
            pytest.param({'time_created': False}, id="missing-time-created"),
            pytest.param({'timestamp': None}, id="missing-system-time"),
            pytest.param({'timestamp': '2026-11-03T10:00:00'}, id="missing-timezone"),
            pytest.param({'event_data': False}, id="missing-event-data"),
            pytest.param({'system': False}, id="missing-system"),
            pytest.param({'event_id': None}, id="missing-event-id"),
        ],
    )
    def test_skips_event_with_missing_required_data(self, tmp_path, overrides):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(_event_xml(**overrides), encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 1

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({'timestamp': 'not-a-timestamp'}, id="invalid-timestamp"),
            pytest.param({'record_id': 'not-a-record-id'}, id="invalid-record-id"),
            pytest.param({'event_id': 'not-an-event-id'}, id="nonnumeric-event-id"),
        ],
    )
    def test_skips_event_with_invalid_field_value(self, tmp_path, overrides):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(_event_xml(**overrides), encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 1

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({'target_username': '   '}, id="whitespace-only-target-username"),
            pytest.param({'target_domain': '   '}, id="whitespace-only-target-domain"),
            pytest.param({'computer': '   '}, id="whitespace-only-computer"),
            pytest.param({'channel': '   '}, id="whitespace-only-channel"),
        ],
    )
    def test_skips_event_with_whitespace_only_required_text(self, tmp_path, overrides):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(_event_xml(**overrides), encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 1

    @pytest.mark.parametrize(
        "source_ip",
        [
            pytest.param("192.0.2.999", id="malformed-ipv4"),
            pytest.param("2001:db8::gggg", id="malformed-ipv6"),
            pytest.param("not-an-ip", id="non-address-text"),
        ],
    )
    def test_skips_event_with_invalid_source_ip(self, tmp_path, source_ip):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-03T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">{source_ip}</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 1

    @pytest.mark.parametrize(
        "empty_field",
        [
            "timestamp",
            "record_id",
            "channel",
            "computer",
            "target_username",
            "target_domain",
            "source_ip",
        ],
    )
    def test_skips_event_with_empty_required_field(self, tmp_path, empty_field):
        fields = {
            "timestamp": "2026-11-03T10:00:00Z",
            "record_id": "42",
            "channel": "Security",
            "computer": "PC-A",
            "target_username": "alice",
            "target_domain": "LAB",
            "source_ip": "192.0.2.10",
        }
        fields[empty_field] = ""
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="{fields['timestamp']}" />
                        <EventRecordID>{fields['record_id']}</EventRecordID>
                        <Channel>{fields['channel']}</Channel>
                        <Computer>{fields['computer']}</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">{fields['target_username']}</Data>
                        <Data Name="TargetDomainName">{fields['target_domain']}</Data>
                        <Data Name="IpAddress">{fields['source_ip']}</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 1

    @pytest.mark.parametrize(
        "event_id_text",
        [
            pytest.param("", id="empty"),
            pytest.param("   ", id="whitespace-only"),
            pytest.param("4625.0", id="decimal-form"),
        ],
    )
    def test_skips_event_with_unusable_event_id(self, tmp_path, event_id_text):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>{event_id_text}</EventID>
                        <TimeCreated SystemTime="2026-11-03T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 1

    @pytest.mark.parametrize(
        ("timestamp_text", "expected_timestamp"),
        [
            pytest.param(
                "2026-11-03T18:00:00+08:00",
                datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc),
                id="positive-offset",
            ),
            pytest.param(
                "2026-11-02T23:00:00-05:00",
                datetime(2026, 11, 3, 4, 0, tzinfo=timezone.utc),
                id="negative-offset-crosses-date-boundary",
            ),
        ],
    )
    def test_normalizes_timestamp_to_utc(self, tmp_path, timestamp_text, expected_timestamp):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="{timestamp_text}" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert len(result.events) == 1
        assert result.skipped_count == 0
        timestamp = result.events[0].timestamp
        assert timestamp == expected_timestamp
        assert timestamp.utcoffset().total_seconds() == 0

    @pytest.mark.parametrize(
        ("channel", "provider_xml"),
        [
            pytest.param("Application", '<Provider Name="Microsoft-Windows-Security-Auditing" />', id="wrong-channel"),
            pytest.param("security", '<Provider Name="Microsoft-Windows-Security-Auditing" />', id="wrong-channel-case"),
            pytest.param("Security", "", id="missing-provider"),
            pytest.param("Security", "<Provider />", id="missing-provider-name"),
            pytest.param("Security", '<Provider Name="Other-Provider" />', id="wrong-provider"),
            pytest.param("Security", '<Provider Name="microsoft-windows-security-auditing" />', id="wrong-provider-case"),
            pytest.param(" Security ", '<Provider Name="Microsoft-Windows-Security-Auditing" />', id="padded-channel"),
            pytest.param("Security", '<Provider Name=" Microsoft-Windows-Security-Auditing " />', id="padded-provider"),
        ],
    )
    def test_skips_event_with_invalid_channel_or_provider(self, tmp_path, channel, provider_xml):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        {provider_xml}
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-03T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>{channel}</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 1

    @pytest.mark.parametrize(
        "invalid_record_data",
        [
            pytest.param(
                """<System>
                        <EventID>4625</EventID>
                    </System>""",
                id="missing-event-data",
            ),
            pytest.param(
                """<System>
                        <EventID>not-an-event-id</EventID>
                    </System>""",
                id="unidentifiable-event-type",
            ),
            pytest.param(
                """<System>
                        <EventID>4625</EventID>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <TimeCreated SystemTime="not-a-timestamp" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>""",
                id="invalid-timestamp",
            ),
        ],
    )
    def test_keeps_valid_records_around_rejected_record(self, tmp_path, invalid_record_data):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:00:00Z" />
                        <EventRecordID>41</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    {invalid_record_data}
                </Event>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:02:00Z" />
                        <EventRecordID>43</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert [event.record_id for event in result.events] == [41, 43]
        assert result.skipped_count == 1

    def test_does_not_count_ignored_event_as_skipped(self, tmp_path):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            """<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <EventID>4624</EventID>
                    </System>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert [event.record_id for event in result.events] == []
        assert result.skipped_count == 0

    def test_counts_record_with_multiple_invalid_fields_once(self, tmp_path):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            """<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="not-a-timestamp" />
                        <EventRecordID>43</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetDomainName">LAB</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert [event.record_id for event in result.events] == []
        assert result.skipped_count == 1

    def test_counts_rejected_records_in_mixed_file(self, tmp_path):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            """<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <EventID>4624</EventID>
                    </System>
                </Event>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="not-a-timestamp" />
                        <EventRecordID>43</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetDomainName">LAB</Data>
                    </EventData>
                </Event>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <EventData />
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert [event.record_id for event in result.events] == [42]
        assert result.skipped_count == 2

    @pytest.mark.parametrize("placeholder_field", ["computer", "target_domain", "target_username"])
    def test_version_1_skips_event_with_placeholder(self, tmp_path, placeholder_field):
        fields = {
            "computer": "PC-A",
            "target_domain": "LAB",
            "target_username": "alice",
        }
        fields[placeholder_field] = "-"
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>{fields['computer']}</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">{fields['target_username']}</Data>
                        <Data Name="TargetDomainName">{fields['target_domain']}</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
        assert result.skipped_count == 1

    @pytest.mark.parametrize("normalized_field", ["computer", "target_domain", "target_username"])
    @pytest.mark.parametrize("placeholder", [False, True], ids=["padded-valid-value", "padded-placeholder"])
    def test_version_1_normalizes_identity_text(self, tmp_path, normalized_field, placeholder):
        fields = {
            "computer": "Pc-A",
            "target_domain": "Lab",
            "target_username": "Alice",
        }
        expected_value = fields[normalized_field]
        fields[normalized_field] = "  -  " if placeholder else f"  {expected_value}  "
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:00:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>{fields['computer']}</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">{fields['target_username']}</Data>
                        <Data Name="TargetDomainName">{fields['target_domain']}</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        if placeholder:
            assert result.events == []
            assert result.skipped_count == 1
        else:
            assert len(result.events) == 1
            assert result.skipped_count == 0
            assert getattr(result.events[0], normalized_field) == expected_value

    @pytest.mark.parametrize(
        ("second_computer", "reject_file"),
        [
            pytest.param("PC-A", False, id="same-computer"),
            pytest.param("  PC-A  ", False, id="same-computer-after-normalization"),
            pytest.param("pc-a", False, id="same-computer-lowercase"),
            pytest.param("Pc-A", False, id="same-computer-mixed-case"),
            pytest.param("PC-B", True, id="different-computer"),
        ],
    )
    def test_version_1_requires_single_computer(self, tmp_path, second_computer, reject_file):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:00:00Z" />
                        <EventRecordID>41</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:01:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>{second_computer}</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        if reject_file:
            with pytest.raises(ValueError):
                XmlEventReader().read(xml_path)
        else:
            result = XmlEventReader().read(xml_path)

            assert [event.record_id for event in result.events] == [41, 42]
            assert result.skipped_count == 0
            assert [event.computer for event in result.events] == ["PC-A", second_computer.strip()]

    @pytest.mark.parametrize(
        ("other_event_id", "expected_skips"),
        [
            pytest.param(4624, 0, id="ignored-other-computer"),
            pytest.param(4625, 1, id="unusable-other-computer"),
        ],
    )
    def test_single_computer_check_uses_only_usable_records(self, tmp_path, other_event_id, expected_skips):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>{other_event_id}</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:00:00Z" />
                        <EventRecordID>41</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-B</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                    </EventData>
                </Event>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:01:00Z" />
                        <EventRecordID>42</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert [event.record_id for event in result.events] == [42]
        assert result.events[0].computer == "PC-A"
        assert result.skipped_count == expected_skips

    @pytest.mark.parametrize(
        ("record_id", "accepted"),
        [
            pytest.param(0, True, id="minimum"),
            pytest.param(18446744073709551615, True, id="maximum"),
            pytest.param(-1, False, id="negative"),
            pytest.param(18446744073709551616, False, id="above-maximum"),
        ],
    )
    def test_validates_record_id_range(self, tmp_path, record_id, accepted):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            f"""<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4625</EventID>
                        <TimeCreated SystemTime="2026-11-04T10:00:00Z" />
                        <EventRecordID>{record_id}</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="TargetUserName">alice</Data>
                        <Data Name="TargetDomainName">LAB</Data>
                        <Data Name="IpAddress">192.0.2.10</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        if accepted:
            assert len(result.events) == 1
            assert result.events[0].record_id == record_id
            assert result.skipped_count == 0
        else:
            assert result.events == []
            assert result.skipped_count == 1

    def test_ignores_other_event_without_failed_sign_in_fields(self, tmp_path):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            """<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System>
                        <Provider Name="Microsoft-Windows-Security-Auditing" />
                        <EventID>4624</EventID>
                        <TimeCreated SystemTime="2026-11-03T10:00:00Z" />
                        <EventRecordID>43</EventRecordID>
                        <Channel>Security</Channel>
                        <Computer>PC-A</Computer>
                    </System>
                    <EventData>
                        <Data Name="SubjectUserName">SYSTEM</Data>
                    </EventData>
                </Event>
            </Events>""",
            encoding="utf-8",
        )

        result = XmlEventReader().read(xml_path)

        assert result.events == []

    def test_ignores_other_event_types(self, tmp_path):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            """<Events>
                <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                <System>
                    <Provider Name="Microsoft-Windows-Security-Auditing" />
                    <EventID>4624</EventID>
                    <TimeCreated SystemTime="2026-11-03T10:00:00Z" />
                    <EventRecordID>43</EventRecordID>
                    <Channel>Security</Channel>
                    <Computer>PC-A</Computer>
                </System>
                <EventData>
                    <Data Name="TargetUserName">alice</Data>
                    <Data Name="TargetDomainName">LAB</Data>
                    <Data Name="IpAddress">192.0.2.10</Data>
                </EventData>
            </Event>
        </Events>""",
        encoding="utf-8")

        result = XmlEventReader().read(xml_path)

        assert result.events == []
