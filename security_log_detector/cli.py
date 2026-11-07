from xml.etree.ElementTree import ParseError
import sys

from security_log_detector.reader import XmlEventReader
from security_log_detector.detector import RepeatedSignInDetector

def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if len(argv) == 0:
        _print_usage(sys.stderr, "Error: An XML-file path is required.")
        return 2
    if len(argv) > 1:
        _print_usage(sys.stderr, "Error: Supply exactly one XML-file path.")
        return 2

    arg = argv[0]
    if arg == "-h" or arg == "--help":
        _print_usage(sys.stdout)
        return 0
    if arg.startswith("-"):
        _print_usage(sys.stderr, f"Error: Unknown option {arg!r}. Use -h or --help for help.")
        return 2

    try:
        read_result = XmlEventReader().read(arg)
        detection_result = RepeatedSignInDetector().analyze(read_result.events)
    except (OSError, ParseError, ValueError) as error:
        print(f"Error: Analysis could not be completed: {error}", file=sys.stderr)
        return 1

    _print_results(
        read_result.skipped_count,
        detection_result.analyzed_count,
        detection_result.findings)
    return 0

def _print_usage(output_channel, error_message = None):
    print("Usage: python -m security_log_detector <xml-file>", file=output_channel)
    print("Analyze one Windows Security-log XML export for repeated failed sign-ins.", file=output_channel)
    if error_message is not None:
        print(error_message, file=output_channel)

def _print_results(skipped_count, analyzed_count, findings):
    if len(findings) == 0:
        print("No suspicious activity was found by this rule among the usable events in the supplied file.")
        print()
    else:
        for finding_number, finding in enumerate(findings, start=1):
            print(f"Finding {finding_number}")
            print(f"Computer: {finding.computer}")
            print(f"Target account: {finding.target_domain + "\\" + finding.target_username}")
            print(f"Source IP: {finding.source_ip}")
            print(f"Failed sign-ins: {finding.count}")
            print(f"First attempt (UTC): {finding.first_timestamp.isoformat().replace("+00:00", "Z")}")
            print(f"Last attempt (UTC): {finding.last_timestamp.isoformat().replace("+00:00", "Z")}")
            print(f"Reason: {finding.reason}")
            print()

    print("Summary")
    print(f"Events analyzed: {analyzed_count}")
    print(f"Events skipped: {skipped_count}")
    print(f"Findings produced: {len(findings)}")