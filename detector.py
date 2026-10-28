import sys
import json

def load_events(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def detect_log_clearing(events): # Subject to change after change of event
    log_clearing_alerts = []
    for event in events:
        if event.get("event_id") == 1102:
            alert = {
                "severity": "HIGH",
                "message": "Windows Security audit log cleared",
                "computer": event.get("computer", "Unknown"),
                "user": event.get("user", "Unknown"),
                "timestamp": event.get("timestamp", "Unknown"),
                "event_id": event.get("event_id"),
                "investigation": "Determine who cleared the log and whether it was authorized."
            }
            log_clearing_alerts.append(alert)
    return log_clearing_alerts

def print_alerts(alerts): # Subject for change after change of event
    if len(alerts) == 0:
        print("No security alerts found")
    else:
        print(f"{len(alerts)} security alert found")
        print("------------------------------")
    for alert in alerts:
        print(f"[{alert["severity"]}] {alert["message"]}")
        print(f"Computer: {alert["computer"]}")
        print(f"User: {alert["user"]}")
        print(f"Timestamp: {alert["timestamp"]}")
        print(f"Event ID: {alert["event_id"]}")
        print("------------------------------")

filename = sys.argv[1]
events = load_events(filename)
log_clearing_alerts = detect_log_clearing(events)
print_alerts(log_clearing_alerts)