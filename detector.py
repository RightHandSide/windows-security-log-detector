import sys
import json
import argparse

def load_events(filename):
    with open(filename, "r", encoding="utf-8") as file:
        events = json.load(file)
        if not isinstance(events, list):
            raise ValueError("The top-level JSON value must be a list.")
        if not all(isinstance(event, dict) for event in events):
            raise ValueError("Every event in the list must be a JSON object.")
        return events

def detect_log_clearing(events):
    log_clearing_alerts = []
    for event in events:
        if event.get('event_id') == 1102:
            alert = {
                "severity": "HIGH",
                "message": "Windows Security audit log cleared",
                "computer": event.get('computer', 'Unknown'),
                "user": event.get('user', 'Unknown'),
                "timestamp": event.get('timestamp', 'Unknown'),
                "event_id": event.get('event_id'),
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
        print(f"[{alert.get('severity')}] {alert.get('message')}")
        print(f"Computer: {alert.get('computer')}")
        print(f"User: {alert.get('user')}")
        print(f"Time: {alert.get('timestamp')}")
        print(f"Event ID: {alert.get('event_id')}")
        print(f"Investigation: {alert.get('investigation')}")
        print("------------------------------")

def main():
    parser = argparse.ArgumentParser(usage="detector.py <events.json>")
    parser.add_argument("filename", metavar="<events.json>", help="Path to a JSON file containing Windows events.")
    args = parser.parse_args()
    filename = args.filename
    try:
        events = load_events(filename)
    except FileNotFoundError:
        print(f"File does not exist: {filename}")
        return 2
    except json.JSONDecodeError:
        print("File provided cannot be decoded into JSON format.")
        return 2
    except ValueError as error:
        print(f"Invalid event data: {error}")
        return 2
    else:
        log_clearing_alerts = detect_log_clearing(events)
        print_alerts(log_clearing_alerts)
        return 0

if __name__ == '__main__':
    sys.exit(main())