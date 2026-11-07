# Version 1 specification

**Status:** version 1 is implemented and its controlled real-log walkthrough is documented. Reader, detector, and CLI behavior are tested; the author has explained the trigger, an innocent explanation, and a detection limit. See [completion evidence](#completion-evidence) and [README.md](README.md#development-setup) for verified setup and coverage.

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
- The detector must count a record only once when its computer, channel, and event record ID match another record in the input. Do not deduplicate solely by timestamp or account. The reader returns usable records in input order, including duplicate copies; deduplication belongs to the detector.
- **Conflicting copies:** for the same record identity (casefolded computer, exact channel, and record ID), the detector raises `ValueError` if copies disagree on stored timestamp, casefolded target domain or username, or source-address identity. Do not silently select a copy or return a partial analysis. Capitalization differences alone in computer, domain, or username are not conflicts, and equivalent source-address objects are not conflicts. Consistent copies count once.
- **Consistent-copy spelling:** choose the copy whose original `(computer, target_domain, target_username)` tuple is smallest in case-sensitive lexicographic order. Compare computer first, then domain, then username, using the stored trimmed strings. Preserve that copy's complete spelling tuple rather than choosing each field independently. Selection must not depend on input order and must be resolved before that record supplies finding evidence.
- The detector must sort usable, distinct events by recorded timestamp ascending, then by record ID ascending for equal timestamps, before detection. XML record order must not affect detection results; sorting is not a reader responsibility. Return findings in their triggering events' processing order.

Stop with a clear error if the file cannot be read or the XML cannot be parsed. Do not present a partial analysis as a successful run after such an error. A parseable file may still contain individual unusable events, which are handled by skipping and reporting them.

For malformed XML, `XmlEventReader.read(path)` raises `xml.etree.ElementTree.ParseError`. The command-line layer is responsible for displaying a clear error to the user.

For file-access failures, `XmlEventReader.read(path)` propagates the original `OSError` subclass, including `FileNotFoundError` and `PermissionError`. Do not replace these errors with an empty result. The command-line layer will display the corresponding readable error.

## Detection rule

### Grouping

Count failures separately for each combination of:

1. Target computer.
2. Target account domain and username.
3. Source IP address.

Compare computer, domain, and username case-insensitively using `casefold()`, preserving the original trimmed spelling in evidence. Use source-address object equality. An IPv4 address and its IPv4-mapped IPv6 form belong to separate groups; for example, `192.0.2.10` and `::ffff:192.0.2.10` do not combine their counts. Do not convert mapped IPv6 addresses to IPv4 for grouping. Different account identities or source IPs belong to different groups. Computer identity remains part of the group key, but the version 1 reader rejects files containing usable records from multiple distinct computers.

### Threshold and time window

The threshold is fixed at **five failed sign-ins within a rolling five-minute window**. Version 1 offers no command-line threshold settings.

For each event at time `t`, consider that group's events between `t - 5 minutes` and `t`, inclusive. Attempts exactly five minutes apart can belong to the same window. An older attempt falls outside it.

This threshold is a learning choice, not a universal security standard.

### Findings and suppression

- Emit one finding when a group's rolling count first reaches five.
- Capture the evidence at that moment: computer, target domain and username, source IP, count of five, earliest and latest timestamps among the five triggering attempts, and a readable reason. Use the fifth triggering attempt's original trimmed spelling for computer, target domain, and target username. This is the attempt that brings the group's rolling count to five in timestamp-then-record-ID processing order; it is not necessarily the fifth record in input order.
- Keep the finding unchanged when later attempts arrive.
- Suppress additional findings for that group while its rolling count remains at least five.
- Allow a new finding after that group's rolling count has dropped below five and subsequently reaches five again.
- Groups have independent windows and suppression state.

In saved-file analysis, expiration follows recorded event time, not the time the program takes to run. A gap can let a group's count fall below five even when no new event occurs during that gap; a subsequent burst may trigger again.

## Command-line interface

The agreed command accepts exactly one required positional XML-file path:

```powershell
python -m security_log_detector "C:\Logs\events.xml"
```

The supplied file must satisfy the input requirements above. The following command-line behavior is implemented.

### Help and argument handling

| Arguments | Required behavior | Exit status |
| --- | --- | --- |
| `-h` or `--help` | Display usage and a short description; perform no analysis | `0` |
| No file path | Display usage and a missing-path error | `2` |
| Multiple file paths or an unknown option | Display usage and an argument error | `2` |
| One file path | Attempt analysis of the supplied file | `0` on completion; `1` on analysis failure |

For `-h` and `--help`, display this agreed description beneath the usage line: `Analyze one Windows Security-log XML export for repeated failed sign-ins.`

### Exit statuses

- `0`: analysis completed, whether or not findings were produced; also used for help.
- `1`: analysis could not be completed, including file-access failures, malformed XML, unsupported input structure, multiple usable computers, or conflicting event copies. Do not present a successful partial analysis.
- `2`: incorrect command usage.

The package entry point must propagate the command's exit status to the calling process. Finding suspicious activity does not itself make a completed analysis fail.

### Command-line result

Display plain text in the terminal. Version 1 does not automatically create an output file or provide a Markdown export feature.

Write findings, analysis summaries, no-findings messages, and help to standard output (`stdout`). Write errors and any usage accompanying an argument error to standard error (`stderr`).

Every successful run displays findings and a summary containing:

- Number of events analyzed: distinct usable events after detector deduplication. Consistent copies of the same record identity contribute one analyzed event, regardless of how many copies appear in the file. For example, six usable records containing two consistent copies of one event and four other distinct events represent five analyzed events.
- Number of events skipped.
- Number of findings produced.

The summary contains only these three counts. Version 1 does not display a separate duplicate-copy count. The agreed `DetectionResult` therefore does not need a duplicate-copy count field.

Skipped events retain the reader's existing meaning: unusable records counted once per record. Consistent duplicate copies are not skipped events, and intentionally ignored non-4625 events contribute to neither the analyzed count nor the skipped count. A conflicting-copy failure produces no successful analysis summary.

When no finding is produced, explicitly state that no suspicious activity was found by this rule among the usable events in the supplied file. Do not imply that the computer is free of malicious activity.

Use the following agreed result layout, with findings numbered from 1 in detector result order and a blank line between finding blocks and before the summary:

```text
Finding 1
Computer: PC-A
Target account: LAB\alice
Source IP: 192.0.2.10
Failed sign-ins: 5
First attempt (UTC): 2026-11-03T10:00:00Z
Last attempt (UTC): 2026-11-03T10:05:00Z
Reason: <the detector's reason text>

Summary
Events analyzed: 5
Events skipped: 0
Findings produced: 1
```

The example values illustrate the layout, not a completed real-log walkthrough. Substitute each finding's evidence and its detector-provided reason. Display the target account as domain, a backslash, and username. Display timestamps in UTC using `Z`, retaining nonzero fractional seconds at the stored microsecond precision.

With no findings, display exactly `No suspicious activity was found by this rule among the usable events in the supplied file.`, followed by a blank line and the same three-line summary under `Summary`, with the actual counts and zero findings.

Analysis errors must clearly indicate that analysis could not be completed. Help uses the agreed description above; errors identify the problem. Error text is not otherwise fixed verbatim by this specification.

## OOP responsibilities and test organization

| Module or data type | Responsibility | Proposed tests |
| --- | --- | --- |
| `XmlEventReader` class | Read XML, select and validate events, produce event objects and report unusable records | `tests/test_reader.py`: `TestXmlEventReader` |
| Event data class | Carry a usable event's timestamp, grouping fields, and record identity | Covered through reader and detector behavior |
| `RepeatedSignInDetector` class | Deduplicate, sort, group, apply windows and suppression, and return findings with analysis accounting when requested | `tests/test_detector.py`: `TestRepeatedSignInDetector` |
| `DetectionResult` data type | Carry findings and the distinct analyzed-event count | Covered through detector behavior |
| `RepeatedSignInFinding` frozen data class | Carry the repeated-failed-sign-in evidence and reason | Covered through detector behavior |
| Small command-line entry function | Accept a path, connect the modules, and display results or errors | `tests/test_cli.py`: `TestCli` |

The detector accepts event objects rather than XML, so its rule can be tested without constructing XML. It returns findings rather than printing them. The reader does not decide whether activity is suspicious. No inheritance hierarchy or plugin framework is required.

The implemented command-line entry interface is `main(argv: list[str] | None = None) -> int` in `security_log_detector/cli.py`. With `argv=None`, read the calling command's arguments, excluding the program name. An explicit list supplies those arguments directly, so a test can call `main([str(xml_path)])`.

`main` displays output on the agreed streams and returns the agreed integer exit status for completed analysis, analysis failure, help, and argument errors. Help and argument errors must return their status rather than raise `SystemExit` to callers of `main`. The package entry point propagates the returned status to the calling process.

CLI tests exercise `main` through `TestCli`, checking observable output and returned statuses with supplied XML files where appropriate. An end-to-end package-command check also verifies argument forwarding and process exit-status propagation; direct function calls alone do not verify that wiring.

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

The agreed detector interface is `RepeatedSignInDetector().detect(events: list[Event]) -> list[RepeatedSignInFinding]`, defined in `security_log_detector/detector.py`. It accepts usable Event objects supplied by the reader. Each call analyzes its supplied events independently, retains no analysis state between calls, and does not modify the input list or its Event objects. Empty input returns `[]`. Deduplication, sorting, grouping, windows, and suppression are detector responsibilities; displaying results belongs to the command-line layer.

The additional agreed interface is `RepeatedSignInDetector().analyze(events: list[Event]) -> DetectionResult`. This interface is implemented. The result has these public attributes:

| Attribute | Type | Meaning |
| --- | --- | --- |
| `findings` | `list[RepeatedSignInFinding]` | Findings produced by the existing detection rule, in the same order as `detect(events)` |
| `analyzed_count` | `int` | Number of distinct usable events after detector deduplication, as defined under command-line results |

`analyze(events)` follows the same input-preservation, independent-call, duplicate-conflict, grouping, ordering, window, and suppression contracts as `detect(events)`. Empty input produces an empty findings list and an analyzed count of zero. A conflicting-copy failure raises `ValueError` instead of returning a partial result.

Preserve the existing `detect(events)` interface and behavior. Both public methods share the detection implementation; the command-line layer obtains findings and the analyzed count through `analyze(events)` rather than repeating duplicate-handling logic or reading private detector state.

`RepeatedSignInFinding` is a frozen data class in `security_log_detector/models.py`, specific to this rule, with these public attributes:

| Attribute | Type | Meaning |
| --- | --- | --- |
| `computer` | `str` | Target computer, preserving original trimmed spelling |
| `target_domain` | `str` | Target account domain, preserving original trimmed spelling |
| `target_username` | `str` | Target username, preserving original trimmed spelling |
| `source_ip` | `IPv4Address` or `IPv6Address` | Source address |
| `count` | `int` | Five triggering attempts |
| `first_timestamp` | Timezone-aware UTC `datetime` | Earliest triggering attempt |
| `last_timestamp` | Timezone-aware UTC `datetime` | Latest triggering attempt |
| `reason` | `str` | Readable explanation of why the rule triggered |

The public interfaces above are agreed and implemented. Any future interface changes must be agreed before their tests. Tests target observable behavior, not private methods or a required internal algorithm. Use one small failing test at a time unless the author requests a related batch, with implementation written by the author.

## Acceptance criteria

The following behaviors will be covered incrementally, rather than by generating a complete test suite upfront:

| Scenario | Expected behavior |
| --- | --- |
| Empty `<Events />` document | Reader returns an empty event list and zero skipped events |
| One valid Security 4625 event | Reader produces an event with the required fields |
| Other event types | Ignored for detection |
| Unreadable file or malformed XML | Clear error; analysis fails |
| 4625 record missing a required grouping field, timestamp, time zone, or record identity | Record skipped and reported |
| Consistent copies of the same record identity | Counted once; copies cannot manufacture a threshold |
| Copies of one record identity disagree on stored timestamp, casefolded target account, or source-address identity | Detector raises `ValueError`; no partial analysis |
| Consistent copies have different capitalization | Select the complete lexicographically smallest original spelling tuple, independently of input order |
| Same events in a different XML order | Equivalent findings |
| Distinct records have equal timestamps | Process by ascending record ID; return findings in trigger-processing order |
| Fewer than five failures in a window | No finding |
| Five failures at minutes 0, 1, 2, 3, and 5 in one group | One finding, count five, range minute 0 through minute 5 |
| Five failures at minutes 0, 1, 2, 3, and 5 plus one microsecond | No finding; only four remain in the window at the stored timestamp precision |
| Usable records from multiple distinct computers in one file | Reader raises `ValueError`; no partial analysis |
| Capitalization variants of the same computer, account domain, or username | Same identity for checks and grouping; preserve original trimmed spelling |
| Different account domain, username, or source IP within the supported single-computer input | Separate counts |
| IPv4 source and its IPv4-mapped IPv6 form | Separate groups; counts do not combine |
| Additional failures while an alerted group's count stays at least five | No additional finding and no change to existing evidence |
| Count drops below five, then a later burst reaches five | Another finding |
| Different explicit time-zone offsets representing the same instants | Equivalent window calculations in UTC |
| Reuse one detector for multiple calls | Each call analyzes only its supplied events; input list and Event objects remain unchanged |
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

## Runtime support

Version 1 supports Python 3.13 on Windows. Development and testing were performed with Python 3.13.11. Other Python versions have not been verified. This is a documented support policy; do not add a runtime version check for version 1.

## Deferred acquisition work

The [manual practice workflow](README.md#manual-practice-workflow) produced usable real events and a finding on the tested computer. Version 1 analyzes supplied files and provides no collector or exporter. The version 2 requirement is to simplify obtaining and preparing compatible Windows Security logs; its method, interface, and acceptance criteria remain to be agreed before implementation. This does not change version 1 validation or fabricate missing event fields.

The reader milestone uses the validation rules above and Python's `datetime.fromisoformat` for timestamp parsing, with no additional timestamp grammar or undocumented placeholder list. Further restrictions would be explicit scope changes rather than prerequisites for completing the current reader. Detector grouping, duplicate handling, and command-line accounting are defined above.

## Completion criteria

Version 1 is complete when:

1. The agreed behavior is implemented and its tests pass.
2. The author can export real events from a controlled Windows practice environment, analyze the XML, and explain a finding and its limitations.
3. `README.md` includes verified setup, usage, and a worked example, with learning explanations written by the author.
4. Both documents match the delivered behavior and clearly identify limitations.

## Completion evidence

The reader, detector, CLI, and regression tests implement the software workflow above. The controlled real-event exercise and author reflections below provide evidence for the learning criteria, within the documented limitations.

The earlier real-log exercise demonstrated parsing and skip accounting only. A later controlled network-sign-in batch produced five distinct usable events in one group over 153.187772 seconds; the package command reported five analyzed events, zero skipped events, and one finding with exit status `0`. See [README.md](README.md#controlled-real-finding-7-november-2026) for the observation and tested manual workflow, and [author reflections](README.md#author-reflections) for the author's explanations. Automated collection/export remains version 2 work, with its method to be agreed separately.

## Version scope

| Version | Scope |
| --- | --- |
| 1 | Saved XML analysis with the single repeated-failed-sign-in rule and command-line results |
| 2 | Simplify obtaining and preparing compatible Windows Security logs; method, interface, and acceptance criteria to be agreed |
| 2 or 3 | Live monitoring; exact release placement and design to be decided |
| Later consideration | Other detection rules, additional input formats, configurable thresholds, and successful-sign-in correlation |
| Future improvement to consider | Support multi-computer exports with defined validation and duplicate-identity rules; no release is assigned |

Native `.evtx` input, direct live collection, a graphical interface, and a general rule framework are outside version 1. Later considerations are not committed features or designs.
