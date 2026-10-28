# Windows Security Log Detector

A Python project that detects suspicious activity in Windows Security event logs.

## Current stage

The first version reads synthetic Windows events from a JSON file and detects
when the Windows Security audit log has been cleared.

## First detection

- Event ID 1102: Security audit log cleared