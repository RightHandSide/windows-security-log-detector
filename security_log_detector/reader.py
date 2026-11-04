from ipaddress import ip_address, IPv4Address, IPv6Address
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

from security_log_detector.models import Event, ReadResult

class XmlEventReader:
    def read(self, xml_path):
        root = ET.parse(xml_path).getroot()
        ns = {"win": "http://schemas.microsoft.com/win/2004/08/events/event"}
        self._validate_xml_structure(root, ns)
        events = []
        skipped_count = 0
        for xml_event in root.findall("win:Event", ns):
            event_id = self._parse_event_id(xml_event, ns)
            if event_id is None:
                skipped_count += 1
            elif event_id == 4625:
                event = self._parse_xml_event(xml_event, ns)
                if event is None:
                    skipped_count += 1
                else:
                    events.append(event)

        self._validate_single_computer(events)

        return ReadResult(events, skipped_count)

    def _validate_xml_structure(self, root, ns) -> None:
        if root.tag != "Events":
            raise ValueError(f"Unsupported XML root {root.tag!r}: expected an unnamespaced 'Events' element.")

        for child in root:
            if child.tag != f"{{{ns["win"]}}}Event":
                raise ValueError(f"Unsupported child {child.tag!r} under 'Events': version 1 requires direct 'Event' elements in namespace {ns['win']!r}.")

    def _parse_xml_event(self, xml_event, ns) -> Event | None:
        system = xml_event.find("win:System", ns)
        event_data = xml_event.find("win:EventData", ns)
        if event_data is None:
            return None

        provider = self._parse_provider(system, ns)
        event_id = self._parse_event_id(xml_event, ns)
        timestamp = self._parse_timestamp(system, ns)
        record_id = self._parse_record_id(system, ns)
        channel = self._parse_text(system, "win:Channel", ns)
        computer = self._parse_text(system, "win:Computer", ns)
        target_username = self._parse_text(event_data, "win:Data[@Name='TargetUserName']", ns)
        target_domain = self._parse_text(event_data, "win:Data[@Name='TargetDomainName']", ns)
        source_ip = self._parse_source_ip(event_data, ns)

        if (not self._is_security_event(provider, channel) or timestamp is None
            or record_id is None or computer is None or
            target_username is None or target_domain is None or source_ip is None):
            return None
        event = Event(
            event_id=event_id,
            timestamp=timestamp,
            record_id=record_id,
            channel=channel,
            computer=computer.strip(),
            target_username=target_username.strip(),
            target_domain=target_domain.strip(),
            source_ip=source_ip
            )
        return event

    def _parse_provider(self, system, ns) -> str | None:
        provider_element = system.find("win:Provider", ns)
        if provider_element is None:
            return None

        provider = provider_element.get("Name")
        if provider is None or provider.strip() == "":
            return None
        return provider

    def _parse_event_id(self, xml_event, ns) -> int | None:
        system = xml_event.find("win:System", ns)
        if system is None:
            return None

        event_id_txt = system.findtext("win:EventID", None, ns)
        if event_id_txt is None:
            return None

        try:
            event_id = int(event_id_txt)
        except ValueError:
            return None
        return event_id

    def _parse_timestamp(self, system, ns) -> datetime | None:
        time_created = system.find("win:TimeCreated", ns)
        if time_created is None:
            return None

        timestamp_txt = time_created.get("SystemTime")
        if timestamp_txt is None:
            return None

        try:
            dt_timestamp = datetime.fromisoformat(timestamp_txt)
        except ValueError:
            return None

        if dt_timestamp.tzinfo is None:
            return None

        try:
            timestamp = dt_timestamp.astimezone(timezone.utc)
        except OverflowError:
            return None
        return timestamp

    def _parse_record_id(self, system, ns) -> int | None:
        record_id_txt = system.findtext("win:EventRecordID", None, ns)
        if record_id_txt is None:
            return None

        try:
            record_id = int(record_id_txt)
        except ValueError:
            return None

        if record_id < 0 or record_id > 2**64 - 1:
            return None
        return record_id

    def _parse_text(self, parent, path, ns) -> str | None:
        txt = parent.findtext(path, None, ns)
        if txt is None:
            return None

        stripped_txt = txt.strip()
        if stripped_txt == "" or stripped_txt == "-":
            return None
        return txt

    def _parse_source_ip(self, event_data, ns) -> IPv4Address | IPv6Address | None:
        source_ip_txt = event_data.findtext("win:Data[@Name='IpAddress']", None, ns)
        if source_ip_txt is None:
            return None

        try:
            source_ip = ip_address(source_ip_txt)
        except ValueError:
            return None
        return source_ip

    def _is_security_event(self, provider, channel) -> bool:
        if provider is None or channel is None:
            return False

        if provider != "Microsoft-Windows-Security-Auditing" or channel != "Security":
            return False
        return True

    def _validate_single_computer(self, events) -> None:
        computers = {event.computer.casefold() for event in events}
        if len(computers) > 1:
            names = ", ".join(sorted(computers))
            raise ValueError(f"Version 1 supports one computer per file; found: {names}. Export events from a single computer.")