# Version 1 specification

**Status:** the reader milestone is implemented. The detector, command-line workflow, and controlled real-log walkthrough remain pending; see [README.md](README.md#development-setup) for verified development setup and reader coverage. The requirements below describe the complete version 1 plan, not a claim that the whole tool is implemented.

This document defines required behavior. [README.md](README.md) explains the project's purpose, usage, documentation convention, and learning workflow.

## Smallest usable version

The author supplies one saved XML export from one computer's Windows Security log to a Python command-line tool. The tool identifies repeated failed sign-ins, displays the evidence behind each finding, and summarizes the analysis.

Version 1 contains one detection rule. Its purpose is learning to turn Windows events into an explainable finding, including possible innocent explanations and detection limits.

## Input and event selection

- Accept one XML file per run, containing events from one computer's Security log.
- **Version 1 single-computer restriction:** after validation and text normalization, usable 4625 records must identify at most one distinct computer. Raise `ValueError` if usable records identify multiple computers; do not return a partial result or silently select one computer. Unusable records and intentionally ignored event types do not establish the computer for this check.
- Support real practice logs and synthetic test examples using the agreed XML structure.
- Use an unnamespaced `<Events>` document root containing `<Event>` records in the `http://schemas.microsoft.com/win/2004/08/events/event` namespace. Usable 4625 records contain the required `System` and `EventData` fields. Identified non-4625 records do not need failed-sign-in fields, as specified below.
- Raise `ValueError` for an unsupported document root or an `Event` record with a missing or incorrect namespace. Treat this as an input-file failure, not an empty successful analysis or a skipped-record result.
- **Version 1 structure restriction:** every direct element child of `<Events>` must be an `<Event>` in the required Windows event namespace. Raise `ValueError` for other element children, including wrappers containing nested events. This strict input shape is a version 1 decision; later versions may reconsider it through an explicit specification change.
- An empty `<Events />` document is valid. The reader returns an empty `events` list and `skipped_count` of zero.
- Use Windows Security Event ID `4625` (failed sign-in) for detection; ignore other event types.
- A 4625 record must have `System/Channel` exactly `Security` and `System/Provider/@Name` exactly `Microsoft-Windows-Security-Auditing`. Comparisons are case-sensitive. Skip and count the record once when either value is missing or different, including a missing `Provider` element or `Name` attribute.
- Skip and count each record with a missing `System` element or a missing or nonnumeric `EventID`, because its event type cannot be identified. Count the record once, even if other fields are also missing.
- Ignored event types do not need the fields required for failed-sign-in extraction.
- `skipped_count` counts unusable records, once per record even when multiple fields are invalid. Identified non-4625 events are intentionally ignored and contribute zero skips. Mixed files retain usable events and total the rejected records.
- Read the timestamp from `System/TimeCreated/@SystemTime`.
- Require an explicit time zone, normalize timestamps to UTC for comparison, and display finding times in UTC.
- A usable timestamp must remain representable as a `datetime` after UTC conversion. If applying its offset moves it outside the `datetime` range, skip and count the record instead of aborting the file. The minimum and maximum representable UTC timestamps are accepted.
- **Version 1 timestamp precision:** store timestamps only as timezone-aware UTC `datetime` objects at microsecond precision. Accept Windows timestamps with seven fractional-second digits and discard digits beyond the first six rather than rounding. Sorting and rolling-window comparisons use these converted values; do not add a separate field to preserve the seventh digit.
- Extract the target computer, target account domain, target username, and source IP address. The account is the target of the failed sign-in, not the subject that requested it.
- Require a usable computer, target domain, target username, source IP, and timestamp. Skip unusable failed-sign-in records and report the skipped count.
- Required text fields must not be empty or contain only whitespace. Skip and count records with such values.
- **Version 1 text normalization:** strip surrounding whitespace from computer, target domain, and target username before validation and storage. Preserve their letter case. Channel and provider retain their exact, case-sensitive matching rules and are not trimmed to make otherwise different values match.
- **Version 1 name comparison:** compare computer, target domain, and target username case-insensitively for identity checks and detector grouping, while retaining the trimmed original spelling in Event objects and finding evidence. The reader's single-computer check must therefore accept capitalization variants of the same computer. Different domain or username names remain separate; channel and provider comparisons remain exact.
- **Version 1 placeholder rule:** a `-` value for computer, target domain, or target username after the above normalization is unusable. Skip and count that record once. Version 1 has no additional placeholder list; other nonempty text is not rejected merely as a suspected placeholder.
- Accept syntactically valid IPv4 and IPv6 source-address strings, storing the parsed address as an `IPv4Address` or `IPv6Address` object. Skip and count a record whose source IP cannot be parsed as either address type. Use address-object equality for grouping, so equivalent IPv6 spellings identify the same source. Display addresses using `str(address)`.
- Require the computer, log channel, and Windows event record ID used for duplicate identification. Skip records missing that identity and report them.
- A usable record ID must be an integer in the inclusive range `0` through `2**64 - 1`. Skip and count records with IDs outside that range. Both boundary values are accepted.
- The detector must count a record only once when its computer, channel, and event record ID match another record in the input. Do not deduplicate solely by timestamp or account. The reader returns usable records in input order, including duplicate copies; deduplication is pending detector work.
- The detector must sort usable, distinct events by recorded timestamp before detection. XML record order must not affect detection results; sorting is not a reader responsibility.

Stop with a clear error if the file cannot be read or the XML cannot be parsed. Do not present a partial analysis as a successful run after such an error. A parseable file may still contain individual unusable events, which are handled by skipping and reporting them.

For malformed XML, `XmlEventReader.read(path)` raises `xml.etree.ElementTree.ParseError`. The command-line layer is responsible for displaying a clear error to the user.

For file-access failures, `XmlEventReader.read(path)` propagates the original `OSError` subclass, including `FileNotFoundError` and `PermissionError`. Do not replace these errors with an empty result. The command-line layer will display the corresponding readable error.

## Detection rule

### Grouping

Count failures separately for each combination of:

1. Target computer.
2. Target account domain and username.
3. Source IP address.

Compare computer, domain, and username case-insensitively using `casefold()`, preserving the original trimmed spelling in evidence. Use source-address object equality, subject to the unresolved IPv4-mapped IPv6 choice below. Different account identities or source IPs belong to different groups. Computer identity remains part of the group key, but the version 1 reader rejects files containing usable records from multiple distinct computers.

### Threshold and time window

The threshold is fixed at **five failed sign-ins within a rolling five-minute window**. Version 1 offers no command-line threshold settings.

For each event at time `t`, consider that group's events between `t - 5 minutes` and `t`, inclusive. Attempts exactly five minutes apart can belong to the same window. An older attempt falls outside it.

This threshold is a learning choice, not a universal security standard.

### Findings and suppression

- Emit one finding when a group's rolling count first reaches five.
- Capture the evidence at that moment: computer, target domain and username, source IP, count of five, earliest and latest timestamps among the five triggering attempts, and a readable reason.
- Keep the finding unchanged when later attempts arrive.
- Suppress additional findings for that group while its rolling count remains at least five.
- Allow a new finding after that group's rolling count has dropped below five and subsequently reaches five again.
- Groups have independent windows and suppression state.

In saved-file analysis, expiration follows recorded event time, not the time the program takes to run. A gap can let a group's count fall below five even when no new event occurs during that gap; a subsequent burst may trigger again.

## Command-line result

Every successful run displays findings and a summary containing:

- Number of events analyzed.
- Number of events skipped.
- Number of findings produced.

When no finding is produced, explicitly state that no suspicious activity was found by this rule among the usable events in the supplied file. Do not imply that the computer is free of malicious activity.

Invalid-file errors must clearly indicate that analysis could not be completed. Exact output formatting and command syntax will be agreed before their tests are written.

## OOP responsibilities and test organization

| Module or data type | Responsibility | Proposed tests |
| --- | --- | --- |
| `XmlEventReader` class | Read XML, select and validate events, produce event objects and report unusable records | `tests/test_reader.py`: `TestXmlEventReader` |
| Event data class | Carry a usable event's timestamp, grouping fields, and record identity | Covered through reader and detector behavior |
| `RepeatedSignInDetector` class | Deduplicate, sort, group, apply windows and suppression, and return findings | `tests/test_detector.py`: `TestRepeatedSignInDetector` |
| Finding data class | Carry the triggering evidence and reason | Covered through detector behavior |
| Small command-line entry function | Accept a path, connect the modules, and display results or errors | `tests/test_cli.py`: `TestCli` |

The detector accepts event objects rather than XML, so its rule can be tested without constructing XML. It returns findings rather than printing them. The reader does not decide whether activity is suspicious. No inheritance hierarchy or plugin framework is required.

The agreed reader interface is `XmlEventReader().read(path)`, returning a result with `events` and `skipped_count`.

Each usable record is represented by an `Event` data class with these public attributes:

| Attribute | Type | XML source |
| --- | --- | --- |
| `event_id` | `int` (4625 for accepted records) | `System/EventID` |
| `timestamp` | Timezone-aware `datetime`, normalized to UTC | `System/TimeCreated/@SystemTime` |
| `computer` | `str` | `System/Computer` |
| `target_domain` | `str` | `EventData/Data[@Name='TargetDomainName']` |
| `target_username` | `str` | `EventData/Data[@Name='TargetUserName']` |
| `source_ip` | `IPv4Address` or `IPv6Address` from `ipaddress` | `EventData/Data[@Name='IpAddress']` |
| `channel` | `str` | `System/Channel` |
| `record_id` | `int` | `System/EventRecordID` |

XML source paths above are relative to a namespaced `Event` element; child elements use the same Windows event namespace.

Other precise public interfaces remain to be agreed before their tests. Tests target observable behavior, not private methods or a required internal algorithm. Use one small failing test at a time unless the author requests a related batch, with implementation written by the author.

## Acceptance criteria

The following behaviors will be covered incrementally, rather than by generating a complete test suite upfront:

| Scenario | Expected behavior |
| --- | --- |
| Empty `<Events />` document | Reader returns an empty event list and zero skipped events |
| One valid Security 4625 event | Reader produces an event with the required fields |
| Other event types | Ignored for detection |
| Unreadable file or malformed XML | Clear error; analysis fails |
| 4625 record missing a required grouping field, timestamp, time zone, or record identity | Record skipped and reported |
| Same record identity repeated | Counted once; copies cannot manufacture a threshold |
| Same events in a different XML order | Equivalent findings |
| Fewer than five failures in a window | No finding |
| Five failures at minutes 0, 1, 2, 3, and 5 in one group | One finding, count five, range minute 0 through minute 5 |
| Five failures at minutes 0, 1, 2, 3, and 5 plus one microsecond | No finding; only four remain in the window at the stored timestamp precision |
| Usable records from multiple distinct computers in one file | Reader raises `ValueError`; no partial analysis |
| Capitalization variants of the same computer, account domain, or username | Same identity for checks and grouping; preserve original trimmed spelling |
| Different account domain, username, or source IP within the supported single-computer input | Separate counts |
| Additional failures while an alerted group's count stays at least five | No additional finding and no change to existing evidence |
| Count drops below five, then a later burst reaches five | Another finding |
| Different explicit time-zone offsets representing the same instants | Equivalent window calculations in UTC |
| Successful run with no findings | Explicit no-findings result and analysis summary |
| End-to-end command-line run | File input produces the expected findings or errors and summary |

## Limitations

- Version 1 discards sub-microsecond timestamp precision. Distinct source instants can become equal after conversion, and a source interval just beyond five minutes can become exactly five minutes at the stored precision. The inclusive-window rule applies to the stored `datetime` values.
- A finding indicates suspicious activity, not a proven attack. Mistyped passwords or outdated stored credentials can produce repeated failures.
- Grouping by a single source and target account can miss password spraying across accounts and attempts distributed across source addresses.
- Missing or unusable source IPs exclude some local sign-ins. Required-field validation can exclude other relevant evidence; summary counts make that gap visible.
- Findings depend on the events available in the supplied export. Absent or incomplete logs limit conclusions.
- The rule does not correlate successful sign-ins or establish that an account was compromised.
- The fixed threshold is not tuned for a production environment.
- Duplicate identity assumes one export from one computer's Security log; merging logs across log resets or different exports is outside the version 1 input contract.

## Details to settle before their implementation tests

Resolve these incrementally with the author rather than silently treating suggestions as agreed requirements:

- Public interfaces, command syntax, output layout, and success/error exit behavior.
- Whether IPv4-mapped IPv6 addresses should be grouped with their corresponding IPv4 addresses. Other name comparisons and text normalization are already settled above.
- Summary accounting for duplicate copies and the command-line analyzed-event count.
- Handling inconsistent copies of the same record identity and deterministic ordering for simultaneous findings.
- A supported Python-version policy beyond the verified development environment in [README.md](README.md#development-setup), and a verified Windows XML export procedure. The development dependency setup is already established.

These details do not introduce additional features; they refine how the agreed workflow behaves.

The reader milestone uses the validation rules above and Python's `datetime.fromisoformat` for timestamp parsing, with no additional timestamp grammar or undocumented placeholder list. Further restrictions would be explicit scope changes rather than prerequisites for completing the current reader. Detector grouping, duplicate handling, and command-line accounting will be settled at those interfaces.

## Completion criteria

Version 1 is complete when:

1. The agreed behavior is implemented and its tests pass.
2. The author can export real events from a controlled Windows practice environment, analyze the XML, and explain a finding and its limitations.
3. `README.md` includes verified setup, usage, and a worked example, with learning explanations written by the author.
4. Both documents match the delivered behavior and clearly identify limitations.

## Version scope

| Version | Scope |
| --- | --- |
| 1 | Saved XML analysis with the single repeated-failed-sign-in rule and command-line results |
| 2 or 3 | Live monitoring; exact release placement and design to be decided |
| Later consideration | Other detection rules, additional input formats, configurable thresholds, and successful-sign-in correlation |
| Future improvement to consider | Support multi-computer exports with defined validation and duplicate-identity rules; no release is assigned |

Native `.evtx` input, direct live collection, a graphical interface, and a general rule framework are outside version 1. Later considerations are not committed features or designs.
