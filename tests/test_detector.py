from detector import detect_log_clearing
from detector import print_alerts
from detector import main
import sys

successful_login_event = {
        "event_id": 4624,
        "timestamp": "2026-10-28T10:00:00Z",
        "computer": "LAB-PC",
        "user": "student",
        "description": "An account successfully logged on"
    }

log_clearing_event = {
        "event_id": 1102,
        "timestamp": "2026-10-28T10:05:00Z",
        "computer": "LAB-PC",
        "user": "student",
        "description": "The audit log was cleared"
    }

failed_login_event = {
        "event_id": 4625,
        "timestamp": "2026-10-28T10:10:00Z",
        "computer": "LAB-PC",
        "user": "student",
        "description": "An account failed to log on"
    }

log_clearing_alert = {
    "severity": "HIGH",
    "message": "Windows Security audit log cleared",
    "computer": log_clearing_event.get("computer", "Unknown"),
    "user": log_clearing_event.get("user", "Unknown"),
    "timestamp": log_clearing_event.get("timestamp", "Unknown"),
    "event_id": log_clearing_event.get("event_id"),
    "investigation": "Determine who cleared the log and whether it was authorized."
    }

def test_detect_log_clearing_no_event_id():
    event_without_id = {
        "timestamp": "2026-10-28T10:05:00Z",
        "computer": "LAB-PC",
        "user": "student"
    }

    alerts = detect_log_clearing([event_without_id])
    assert len(alerts) == 0

def test_detect_log_clearing_no_1102_alert():
    alerts = detect_log_clearing([successful_login_event, failed_login_event])
    assert len(alerts) == 0

def test_detect_log_clearing_one_1102_alert():
    alerts = detect_log_clearing([successful_login_event, log_clearing_event])
    assert len(alerts) == 1
    assert alerts == [log_clearing_alert]

def test_detect_log_clearing_two_1102_alert():
    alerts = detect_log_clearing([log_clearing_event, log_clearing_event])
    assert len(alerts) == 2
    assert alerts == [log_clearing_alert, log_clearing_alert]

def test_detect_log_clearing_unknown_field():
    event_without_field = {
        "event_id": 1102
    }
    alert_without_field = {
        "severity": "HIGH",
        "message": "Windows Security audit log cleared",
        "computer": "Unknown",
        "user": "Unknown",
        "timestamp": "Unknown",
        "event_id": 1102,
        "investigation": "Determine who cleared the log and whether it was authorized."
    }

    alerts = detect_log_clearing([event_without_field])
    assert len(alerts) == 1
    assert alerts == [alert_without_field]

def test_print_alerts_no_alert(capsys):
    print_alerts([])
    captured = capsys.readouterr()
    assert "No security alerts found." in captured.out

def test_print_alerts_one_log_clearing_alert(capsys):
    print_alerts([log_clearing_alert])
    captured = capsys.readouterr()
    assert "1 security alert found." in captured.out
    assert "[HIGH] Windows Security audit log cleared" in captured.out
    assert "Event ID: 1102" in captured.out
    assert "Investigation: Determine who cleared the log and whether it was authorized." in captured.out

def test_main_with_missing_file(monkeypatch, capsys, tmp_path):
    missing_file = tmp_path / "missing.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["detector.py", str(missing_file)]
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert f"File does not exist: {missing_file}" in captured.out

def test_main_with_invalid_json(monkeypatch, capsys, tmp_path):
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("{invalid json", encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        ["detector.py", str(invalid_file)]
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "File provided cannot be decoded into JSON format." in captured.out

def test_main_rejects_top_level_object(monkeypatch, capsys, tmp_path):
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text('{"event_id": 1102}', encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        ["detector.py", str(invalid_file)]
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "The top-level JSON value must be a list." in captured.out

def test_main_rejects_non_object_events(monkeypatch, capsys, tmp_path):
    invalid_file = tmp_path / "invalid-events.json"
    invalid_file.write_text('[null, "hello", 1102]', encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        ["detector.py", str(invalid_file)]
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Every event in the list must be a JSON object." in captured.out

def test_main_returns_zero_for_valid_input(monkeypatch, capsys, tmp_path):
    valid_file = tmp_path / "valid.json"
    valid_file.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        ["detector.py", str(valid_file)]
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "No security alerts found." in captured.out