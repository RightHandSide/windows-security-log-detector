# Windows Security Log Detector

A small Python command-line program that reads synthetic Windows Security events
from a JSON file and reports suspicious activity.

The current version detects Windows Event ID `1102`, which indicates that the
Windows Security audit log was cleared. Clearing the audit log may be legitimate,
but it should be investigated because it can also be used to hide activity.

## Requirements

- Python 3.12 or later

## Installation

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it in Git Bash on Windows:

```bash
source .venv/Scripts/activate
```

Install the development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

## Input format

The input must be a JSON array of event objects. For example:

```json
[
  {
    "event_id": 1102,
    "timestamp": "2026-10-28T10:05:00Z",
    "computer": "LAB-PC",
    "user": "student"
  }
]
```

The included `sample_events.json` contains synthetic data. Do not commit real
Windows Security logs or other sensitive information to the repository.

## Run

From the project directory, run:

```bash
python detector.py sample_events.json
```

For an Event ID `1102`, the program prints an alert similar to:

```text
1 security alert found.
------------------------------
[HIGH] Windows Security audit log cleared
Computer: LAB-PC
User: student
Time: 2026-10-28T10:05:00Z
Event ID: 1102
Investigation: Determine who cleared the log and whether it was authorized.
------------------------------
```

If no matching event is found, it prints:

```text
No security alerts found.
```

Use the help option to view the expected command format:

```bash
python detector.py --help
```

The program also reports readable errors when the input file does not exist or
does not contain valid JSON.

## Test

Run the automated tests from the project directory:

```bash
python -m pytest
```

The tests cover missing event IDs, zero, one, and two matching events, and alert
output.

## Current scope

This is the first stage of the project. It reads synthetic JSON data and detects
only Event ID `1102`. Detection for other suspicious activity will be added in
later stages.
