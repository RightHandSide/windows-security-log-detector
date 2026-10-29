from detector import detect_log_clearing
from detector import print_alerts

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