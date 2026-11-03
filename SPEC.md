# Version 1 specification

**Status:** agreed plan; implementation and tests have not started.

This document defines required behavior. [README.md](README.md) explains the project's purpose, usage, documentation convention, and learning workflow.

## Smallest usable version

The author supplies one saved XML export from one computer's Windows Security log to a Python command-line tool. The tool identifies repeated failed sign-ins, displays the evidence behind each finding, and summarizes the analysis.

Version 1 contains one detection rule. Its purpose is learning to turn Windows events into an explainable finding, including possible innocent explanations and detection limits.

## Input and event selection

- Accept one XML file per run, containing events from one computer's Security log.
- Support real practice logs and synthetic test examples using the agreed XML structure.
- Use Windows Security Event ID `4625` (failed sign-in) for detection; ignore other event types.
- Read the timestamp from `System/TimeCreated/@SystemTime`.
- Require an explicit time zone, normalize timestamps to UTC for comparison, and display finding times in UTC.
- Extract the target computer, target account domain, target username, and source IP address. The account is the target of the failed sign-in, not the subject that requested it.
- Require a usable computer, target domain, target username, source IP, and timestamp. Skip unusable failed-sign-in records and report the skipped count.
- Require the computer, log channel, and Windows event record ID used for duplicate identification. Skip records missing that identity and report them.
- Count a record only once when its computer, channel, and event record ID match another record in the input. Do not deduplicate solely by timestamp or account.
- Sort usable, distinct events by recorded timestamp before detection. XML record order must not affect detection results.

Stop with a clear error if the file cannot be read or the XML cannot be parsed. Do not present a partial analysis as a successful run after such an error. A parseable file may still contain individual unusable events, which are handled by skipping and reporting them.

## Detection rule

### Grouping

Count failures separately for each combination of:

1. Target computer.
2. Target account domain and username.
3. Source IP address.

Different computers, domains, usernames, or source IPs belong to different groups.

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

These names describe the agreed structure; precise public method signatures and result types remain to be agreed before tests at those interfaces. Tests target observable behavior, not private methods or a required internal algorithm. Use one small failing test at a time, with implementation written by the author.

## Acceptance criteria

The following behaviors will be covered incrementally, rather than by generating a complete test suite upfront:

| Scenario | Expected behavior |
| --- | --- |
| One valid Security 4625 event | Reader produces an event with the required fields |
| Other event types | Ignored for detection |
| Unreadable file or malformed XML | Clear error; analysis fails |
| 4625 record missing a required grouping field, timestamp, time zone, or record identity | Record skipped and reported |
| Same record identity repeated | Counted once; copies cannot manufacture a threshold |
| Same events in a different XML order | Equivalent findings |
| Fewer than five failures in a window | No finding |
| Five failures at minutes 0, 1, 2, 3, and 5 in one group | One finding, count five, range minute 0 through minute 5 |
| Five failures at minutes 0, 1, 2, 3, and 5 plus a positive fraction of a second | No finding; only four remain in the window |
| Different computer, account domain, username, or source IP | Separate counts |
| Additional failures while an alerted group's count stays at least five | No additional finding and no change to existing evidence |
| Count drops below five, then a later burst reaches five | Another finding |
| Different explicit time-zone offsets representing the same instants | Equivalent window calculations in UTC |
| Successful run with no findings | Explicit no-findings result and analysis summary |
| End-to-end command-line run | File input produces the expected findings or errors and summary |

## Limitations

- A finding indicates suspicious activity, not a proven attack. Mistyped passwords or outdated stored credentials can produce repeated failures.
- Grouping by a single source and target account can miss password spraying across accounts and attempts distributed across source addresses.
- Missing or unusable source IPs exclude some local sign-ins. Required-field validation can exclude other relevant evidence; summary counts make that gap visible.
- Findings depend on the events available in the supplied export. Absent or incomplete logs limit conclusions.
- The rule does not correlate successful sign-ins or establish that an account was compromised.
- The fixed threshold is not tuned for a production environment.
- Duplicate identity assumes one export from one computer's Security log; merging logs across log resets or different exports is outside the version 1 input contract.

## Details to settle before their implementation tests

Resolve these incrementally with the author rather than silently treating suggestions as agreed requirements:

- Exact supported XML document structure, namespaces, and validation of the Security channel and event provider.
- Public interfaces, command syntax, output layout, and success/error exit behavior.
- Definitions for blank fields and placeholder values, usable IPv4/IPv6 addresses, and field normalization or case matching.
- Timestamp precision and parsing, including Windows fractional seconds and exact window-boundary comparisons.
- Summary accounting for ignored events, duplicate copies, and events with multiple invalid fields.
- Handling inconsistent copies of the same record identity and deterministic ordering for simultaneous findings.
- Python version, dependency setup, and a verified Windows XML export procedure.

These details do not introduce additional features; they refine how the agreed workflow behaves.

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

Native `.evtx` input, direct live collection, a graphical interface, and a general rule framework are outside version 1. Later considerations are not committed features or designs.
