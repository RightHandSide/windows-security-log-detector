import sys
import json

def load_events(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def detect_log_clearing(events):
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

def print_alerts(alerts):
    if len(alerts) == 0:
        print("No security alerts found.")
    elif len(alerts) == 1:
        print(f"{len(alerts)} security alert found.")
        print("------------------------------")
    else:
        print(f"{len(alerts)} security alerts found.")
        print("------------------------------")

    for alert in alerts:
        print(f"[{alert.get("severity")}] {alert.get("message")}")
        print(f"Computer: {alert.get("computer")}")
        print(f"User: {alert.get("user")}")
        print(f"Time: {alert.get("timestamp")}")
        print(f"Event ID: {alert.get("event_id")}")
        print(f"Investigation: {alert.get("investigation")}")
        print("------------------------------")

def main():
    filename = sys.argv[1]
    events = load_events(filename)
    log_clearing_alerts = detect_log_clearing(events)
    print_alerts(log_clearing_alerts)

if __name__ == "__main__":
    main()