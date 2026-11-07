import builtins
from pathlib import Path
import subprocess
import sys

import pytest

from security_log_detector import cli


def _failed_sign_in_xml(record_id, minute):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4625</EventID>
        <TimeCreated SystemTime="2026-11-03T10:{minute:02d}:00Z" />
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>Security</Channel>
        <Computer>PC-A</Computer>
    </System>
    <EventData>
        <Data Name="TargetDomainName">LAB</Data>
        <Data Name="TargetUserName">alice</Data>
        <Data Name="IpAddress">192.0.2.10</Data>
    </EventData>
</Event>'''


_FIRST_FINDING_TEXT = (
    "Finding 1\n"
    "Computer: PC-A\n"
    "Target account: LAB\\alice\n"
    "Source IP: 192.0.2.10\n"
    "Failed sign-ins: 5\n"
    "First attempt (UTC): 2026-11-03T10:00:00Z\n"
    "Last attempt (UTC): 2026-11-03T10:04:00Z\n"
    "Reason: Five failed sign-ins for the same target account on the same computer from the same source IP within five minutes.\n"
)

_SECOND_FINDING_TEXT = (
    "Finding 2\n"
    "Computer: PC-A\n"
    "Target account: LAB\\alice\n"
    "Source IP: 192.0.2.10\n"
    "Failed sign-ins: 5\n"
    "First attempt (UTC): 2026-11-03T10:10:00Z\n"
    "Last attempt (UTC): 2026-11-03T10:14:00Z\n"
    "Reason: Five failed sign-ins for the same target account on the same computer from the same source IP within five minutes.\n"
)


class TestCli:
    def test_empty_events_file_displays_no_findings_and_zero_summary(self, tmp_path, capsys):
        xml_path = tmp_path / "events.xml"
        xml_path.write_text("<Events />", encoding="utf-8")

        status = cli.main([str(xml_path)])

        captured = capsys.readouterr()
        assert status == 0
        assert captured.err == ""
        assert captured.out == (
            "No suspicious activity was found by this rule among the usable events in the supplied file.\n"
            "\n"
            "Summary\n"
            "Events analyzed: 0\n"
            "Events skipped: 0\n"
            "Findings produced: 0\n"
        )

    @pytest.mark.parametrize("help_option", ["-h", "--help"])
    def test_help_without_file_displays_usage_and_description_and_returns_success(self, help_option, capsys):
        status = cli.main([help_option])

        captured = capsys.readouterr()
        assert status == 0
        assert captured.err == ""
        assert "usage" in captured.out.lower()
        assert (
            "Analyze one Windows Security-log XML export for repeated failed sign-ins."
            in captured.out.splitlines()
        )

    @pytest.mark.parametrize(
        "argv",
        [[], ["events.xml", "extra.xml"], ["--unknown-option"]],
        ids=["missing-path", "multiple-paths", "unknown-option"],
    )
    def test_invalid_arguments_report_usage_on_stderr_and_return_two(self, argv, capsys):
        status = cli.main(argv)

        captured = capsys.readouterr()
        assert status == 2
        assert captured.out == ""
        assert "usage" in captured.err.lower()

    def test_main_without_explicit_arguments_reads_command_arguments(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["security_log_detector", "--help"])

        status = cli.main()

        captured = capsys.readouterr()
        assert status == 0
        assert captured.err == ""
        assert "usage" in captured.out.lower()

    def test_mixed_file_reports_analyzed_skipped_and_ignored_records(self, tmp_path, capsys):
        xml_path = tmp_path / "practice events.xml"
        xml_path.write_text(
            '<Events>\n'
            '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
            '    <System>\n'
            '      <Provider Name="Microsoft-Windows-Security-Auditing" />\n'
            '      <EventID>4625</EventID>\n'
            '      <TimeCreated SystemTime="2026-11-03T10:00:00Z" />\n'
            '      <EventRecordID>1</EventRecordID>\n'
            '      <Channel>Security</Channel>\n'
            '      <Computer>PC-A</Computer>\n'
            '    </System>\n'
            '    <EventData>\n'
            '      <Data Name="TargetDomainName">LAB</Data>\n'
            '      <Data Name="TargetUserName">alice</Data>\n'
            '      <Data Name="IpAddress">192.0.2.10</Data>\n'
            '    </EventData>\n'
            '  </Event>\n'
            '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event" />\n'
            '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
            '    <System><EventID>4624</EventID></System>\n'
            '  </Event>\n'
            '</Events>',
            encoding="utf-8",
        )

        status = cli.main([str(xml_path)])

        captured = capsys.readouterr()
        assert status == 0
        assert captured.err == ""
        assert captured.out == (
            "No suspicious activity was found by this rule among the usable events in the supplied file.\n"
            "\n"
            "Summary\n"
            "Events analyzed: 1\n"
            "Events skipped: 1\n"
            "Findings produced: 0\n"
        )

    @pytest.mark.parametrize("file_problem", ["missing", "malformed-xml"])
    def test_input_file_failure_reports_error_without_success_output(self, file_problem, tmp_path, capsys):
        xml_path = tmp_path / "events.xml"
        if file_problem == "malformed-xml":
            xml_path.write_text("<Events>", encoding="utf-8")

        status = cli.main([str(xml_path)])

        captured = capsys.readouterr()
        assert status == 1
        assert captured.out == ""
        assert captured.err.strip()

    @pytest.mark.parametrize(
        "minutes, expected_findings_text, expected_summary",
        [
            (
                [0, 1, 2, 3, 4],
                _FIRST_FINDING_TEXT,
                "Summary\nEvents analyzed: 5\nEvents skipped: 0\nFindings produced: 1\n",
            ),
            (
                [0, 1, 2, 3, 4, 10, 11, 12, 13, 14],
                _FIRST_FINDING_TEXT + "\n" + _SECOND_FINDING_TEXT,
                "Summary\nEvents analyzed: 10\nEvents skipped: 0\nFindings produced: 2\n",
            ),
        ],
        ids=["one-finding", "two-findings"],
    )
    def test_findings_display_numbered_evidence_and_distinct_summary(
        self, minutes, expected_findings_text, expected_summary, tmp_path, capsys
    ):
        records = [
            _failed_sign_in_xml(record_id, minute)
            for record_id, minute in enumerate(minutes, start=1)
        ]
        records.append(records[0])
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(
            "<Events>\n" + "\n".join(reversed(records)) + "\n</Events>",
            encoding="utf-8",
        )

        status = cli.main([str(xml_path)])

        captured = capsys.readouterr()
        assert status == 0
        assert captured.err == ""
        assert captured.out == expected_findings_text + "\n" + expected_summary

    @pytest.mark.parametrize(
        "input_case, expected_status",
        [("empty-file", 0), ("missing-file", 1), ("missing-path", 2)],
    )
    def test_package_command_propagates_status_and_output_streams(
        self, input_case, expected_status, tmp_path
    ):
        xml_path = tmp_path / "practice events.xml"
        if input_case == "empty-file":
            xml_path.write_text("<Events />", encoding="utf-8")
        arguments = [] if input_case == "missing-path" else [str(xml_path)]

        completed = subprocess.run(
            [sys.executable, "-B", "-m", "security_log_detector", *arguments],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert completed.returncode == expected_status
        if expected_status == 0:
            assert completed.stderr == ""
            assert completed.stdout == (
                "No suspicious activity was found by this rule among the usable events in the supplied file.\n"
                "\n"
                "Summary\n"
                "Events analyzed: 0\n"
                "Events skipped: 0\n"
                "Findings produced: 0\n"
            )
        else:
            assert completed.stdout == ""
            assert completed.stderr.strip()

    @pytest.mark.parametrize(
        "input_problem",
        ["unsupported-root", "multiple-computers", "conflicting-copies"],
    )
    def test_invalid_analysis_input_reports_failure_without_partial_results(
        self, input_problem, tmp_path, capsys
    ):
        if input_problem == "unsupported-root":
            xml_text = "<Other />"
        elif input_problem == "multiple-computers":
            records = [
                _failed_sign_in_xml(1, 0),
                _failed_sign_in_xml(2, 1).replace("<Computer>PC-A</Computer>", "<Computer>PC-B</Computer>"),
            ]
            xml_text = "<Events>" + "".join(records) + "</Events>"
        else:
            records = [_failed_sign_in_xml(minute + 1, minute) for minute in range(5)]
            records.append(records[-1].replace("192.0.2.10", "192.0.2.11"))
            xml_text = "<Events>" + "".join(records) + "</Events>"
        xml_path = tmp_path / "events.xml"
        xml_path.write_text(xml_text, encoding="utf-8")

        status = cli.main([str(xml_path)])

        captured = capsys.readouterr()
        assert status == 1
        assert captured.out == ""
        assert captured.err.strip()

    @pytest.mark.parametrize(
        "input_ip, displayed_ip",
        [
            ("192.0.2.10", "192.0.2.10"),
            ("2001:0db8:0000:0000:0000:0000:0000:0010", "2001:db8::10"),
        ],
        ids=["ipv4", "ipv6"],
    )
    def test_finding_displays_fractional_utc_times_and_normalized_source_ip(
        self, input_ip, displayed_ip, tmp_path, capsys
    ):
        records = [
            _failed_sign_in_xml(minute + 1, minute)
            .replace(
                f"T10:{minute:02d}:00Z",
                f"T10:{minute:02d}:00.1234567+08:00",
            )
            .replace("192.0.2.10", input_ip)
            for minute in range(5)
        ]
        xml_path = tmp_path / "events.xml"
        xml_path.write_text("<Events>" + "".join(records) + "</Events>", encoding="utf-8")

        status = cli.main([str(xml_path)])

        captured = capsys.readouterr()
        expected_finding = (
            _FIRST_FINDING_TEXT
            .replace("2026-11-03T10:00:00Z", "2026-11-03T02:00:00.123456Z")
            .replace("2026-11-03T10:04:00Z", "2026-11-03T02:04:00.123456Z")
            .replace("192.0.2.10", displayed_ip)
        )
        assert status == 0
        assert captured.err == ""
        assert captured.out == (
            expected_finding
            + "\nSummary\nEvents analyzed: 5\nEvents skipped: 0\nFindings produced: 1\n"
        )

    def test_file_access_denied_reports_error_without_success_output(self, tmp_path, monkeypatch, capsys):
        xml_path = tmp_path / "practice events.xml"
        xml_path.write_text("<Events />", encoding="utf-8")
        original_open = builtins.open

        def deny_xml_file(file, *args, **kwargs):
            if file == str(xml_path) or file == xml_path:
                raise PermissionError("Access denied to practice events.xml")
            return original_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", deny_xml_file)

        status = cli.main([str(xml_path)])

        captured = capsys.readouterr()
        assert status == 1
        assert captured.out == ""
        assert "Access denied to practice events.xml" in captured.err

    def test_package_command_with_finding_returns_success_and_displays_evidence(self, tmp_path):
        records = [_failed_sign_in_xml(minute + 1, minute) for minute in range(5)]
        xml_path = tmp_path / "practice events.xml"
        xml_path.write_text("<Events>" + "".join(records) + "</Events>", encoding="utf-8")

        completed = subprocess.run(
            [sys.executable, "-B", "-m", "security_log_detector", str(xml_path)],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert completed.returncode == 0
        assert completed.stderr == ""
        assert completed.stdout == (
            _FIRST_FINDING_TEXT
            + "\nSummary\nEvents analyzed: 5\nEvents skipped: 0\nFindings produced: 1\n"
        )
