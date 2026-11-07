# Windows Security Log Detector

A Python learning project for turning Windows security events into explainable suspicious-activity findings.

**Status:** version 1 is implemented, with 166 passing tests at the latest verification. On 7 November 2026, five controlled real Windows failures produced one finding through the package command. The manual workflow, observed result, and author's explanations are recorded below; see [completion evidence](SPEC.md#completion-evidence).

## Purpose

Learn how Windows records failed sign-ins, how a detection rule uses those records, and how to explain the evidence, innocent explanations, and limitations behind a finding.

Version 1 analyzes a saved XML export from one computer's Windows Security log. It runs on demand from the command line and detects repeated failed sign-ins. Synthetic examples provide repeatable tests; the real-log exercise and its limitations are recorded below.

## Usage

1. Export the Security events from a controlled Windows practice environment as XML.
2. Supply that file to the command-line tool.
3. Read the findings and the summary of analyzed events, skipped events, and findings produced.
4. Inspect the original events and explain why the rule triggered and what else could explain the activity.

After development setup, run these commands from the project folder in PowerShell, replacing the example path with an existing compatible XML file:

```powershell
.\.venv\Scripts\python.exe -m security_log_detector "C:\Logs\events.xml"
.\.venv\Scripts\python.exe -m security_log_detector --help
```

The module name uses underscores. Findings and the summary are printed in the terminal; no output file is created. Successful analysis and help return status `0`, analysis failures return `1`, and argument errors return `2`. A finding itself is not an execution failure. See [the CLI contract](SPEC.md#command-line-interface) for output and accounting details.

Input must satisfy the [XML requirements](SPEC.md#input-and-event-selection). Version 1 does not collect or export logs. The [manual practice workflow](#manual-practice-workflow) below produced a real finding on the tested computer; simpler log acquisition and preparation remains a version 2 requirement.

## Development setup

Use Python 3.13 on Windows; see the [version 1 support policy](SPEC.md#runtime-support). Other Python versions have not been verified. The development environment has been checked with Python 3.13.11 and pytest 9.2.0. From the project folder in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest tests -q --tb=short -p no:cacheprovider --basetemp=.pytest-tmp
```

Reader coverage includes XML parsing and version 1 structure checks, UTF-8/UTF-16, IPv4/IPv6, validation and normalization, skip counts, file errors, and case-insensitive single-computer checks that preserve stored spelling. Detector coverage includes deduplication and conflicting copies, deterministic event ordering and evidence spelling, grouping, inclusive rolling windows, suppression and re-arming, IPv4/IPv6 identity, analysis counts, and independent calls. CLI coverage includes help and arguments, output streams, failure handling, distinct-event summaries, finding display, and actual package-command execution. The required behavior is defined in [SPEC.md](SPEC.md).

## Synthetic worked example

Five distinct synthetic failed-sign-in events on 3 November 2026 at `10:00`, `10:01`, `10:02`, `10:03`, and `10:04` UTC all target `LAB\alice` on `PC-A` from `192.0.2.10`. The package-command test verifies this output:

```text
Finding 1
Computer: PC-A
Target account: LAB\alice
Source IP: 192.0.2.10
Failed sign-ins: 5
First attempt (UTC): 2026-11-03T10:00:00Z
Last attempt (UTC): 2026-11-03T10:04:00Z
Reason: Five failed sign-ins for the same target account on the same computer from the same source IP within five minutes.

Summary
Events analyzed: 5
Events skipped: 0
Findings produced: 1
```

This example is synthetic test evidence, not a real-log finding. The authoritative behavior is in [SPEC.md](SPEC.md).

A finding flags activity for investigation. Repeated typing mistakes or an outdated saved password can also produce repeated failures. The rule does not prove an attack. A run without findings only means this rule found no qualifying pattern among usable events in the supplied file.

## Development and learning workflow

Development uses Python, OOP, and `pytest`:

1. Agree on one small behavior and its public interface; record the behavior in `SPEC.md`.
2. The assistant supplies one focused test, or a small related batch when requested, and verifies the result. Distinguish a behavioral failure from an environment or collection failure; some coverage tests may already pass.
3. The author writes enough production code to pass it.
4. Run the relevant tests, review the implementation, and discuss the behavior.
5. Review any structural improvements while keeping tests passing, then choose the next behavior.

Tests verify observable behavior through agreed public interfaces rather than private methods. Reader, detector, and command-line tests belong in their respective test classes. Production code remains the author's responsibility unless the author explicitly requests implementation help.

## Documentation convention

Use exactly two root Markdown documents for project documentation:

| Document | Authoritative content |
| --- | --- |
| `README.md` | Purpose, status, setup, usage, worked example, and learning notes |
| `SPEC.md` | Required behavior, acceptance criteria, design responsibilities, limitations, and version scope |

Each detail has one authoritative home. Link to it rather than maintaining duplicate rule definitions. Update the specification before testing newly agreed behavior. Keep planned features clearly distinguished from implemented behavior, and add setup or usage commands only after verification.

## Learning notes

### Real-log exercise: 7 November 2026

The author queried existing Security 4625 events on their Windows computer and attempted to analyze an XML export. The first file had an incomplete `<Events` opening tag; correcting it to `<Events>` restored parsing. Why the delimiter was absent was not established.

The corrected file contained five events, all without usable source IPs. The observed CLI summary was:

```text
Events analyzed: 0
Events skipped: 5
Findings produced: 0
```

This exercise demonstrated export/parse troubleshooting and skip accounting. It did not demonstrate a real suspicious-activity finding or establish that the computer was free of suspicious activity. No raw personal log contents are included in the repository. The later controlled exercise below completed the real-finding walkthrough; see [completion evidence](SPEC.md#completion-evidence).

### Controlled real finding: 7 November 2026

The author attempted network sign-ins to their own computer at `127.0.0.1` using a fictitious local username, `DetectorLab_NoUser`. An initial rapid retry batch produced fewer recorded events than command failures. A read-only SMB client configuration check showed a 30-second invalid-authentication cache lifetime. Caching was a possible explanation, not a proven sole cause.

Five subsequent attempts spaced by 35-second pauses yielded five distinct usable Windows 4625 records in one group. The stored UTC timestamps spanned `2026-11-07T05:02:57.943750Z` to `2026-11-07T05:05:31.131522Z`: 153.187772 seconds, below five minutes. The actual package command analyzed the exported XML and exited with status `0`, reporting:

```text
Summary
Events analyzed: 5
Events skipped: 0
Findings produced: 1
```

These were real audit records produced by deliberate practice attempts, not fabricated XML. Computer/domain identifiers and raw log contents are omitted here. The finding demonstrates that the rule triggers for the controlled pattern; it does not establish malicious intent.

### Manual practice workflow

This workflow succeeded on the tested Windows computer with SMB client/server services running and failed sign-ins available in the Security log. It is a manual lab procedure, not an exporter feature. Use administrator PowerShell for Security-log access. Other environments may need a separately verified procedure.

1. Choose a clearly fictitious local username and check that it does not exist. In this exercise, `Get-LocalUser -Name 'DetectorLab_NoUser' -ErrorAction SilentlyContinue` returned no account. Use a different name if an account is returned, updating the commands accordingly. The password below is a deliberately invalid lab string, not a real credential.
2. Make one attempt and inspect its event before generating a batch:

   ```powershell
   net use '\\127.0.0.1\IPC$' 'DeliberatelyWrong-LabPassword' "/user:$env:COMPUTERNAME\DetectorLab_NoUser" /persistent:no
   Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625] and EventData[Data[@Name='TargetUserName']='DetectorLab_NoUser']]" -MaxEvents 1 | Format-List TimeCreated,RecordId,Message
   ```

   Authentication failure is intentional. Verify that the record has the required target fields and a usable source IP; the observed source was `127.0.0.1`. A failed command alone does not prove a new audit event exists.
3. Check the invalid-authentication cache duration without changing it:

   ```powershell
   Get-SmbClientConfiguration | Select-Object InvalidAuthenticationCacheLifetime
   ```

   The observed duration was 30 seconds. The following batch used 35-second pauses, a five-second margin. Four pauses total 140 seconds before command execution time. Adjust the experiment if your duration differs, keeping five recorded attempts within five minutes; verify the actual event timestamps afterward.

   ```powershell
   1..5 | ForEach-Object { if ($_ -gt 1) { Start-Sleep -Seconds 35 }; Write-Host "Attempt $_ of 5"; net use '\\127.0.0.1\IPC$' 'DeliberatelyWrong-LabPassword' "/user:$env:COMPUTERNAME\DetectorLab_NoUser" /persistent:no }
   ```

4. Export the five newest matching records using their original XML. This approach does not depend on a start-time variable surviving between PowerShell windows. Check that the selected records actually belong to the intended batch:

   ```powershell
   $labEvents = @(Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625] and EventData[Data[@Name='TargetUserName']='DetectorLab_NoUser']]" -MaxEvents 5); $detectorLabFile = Join-Path $env:TEMP 'detector-lab-4625.xml'; [IO.File]::WriteAllText($detectorLabFile, '<Events>' + (($labEvents | ForEach-Object { $_.ToXml() }) -join '') + '</Events>'); Write-Output "Exported $($labEvents.Count) events to $detectorLabFile"
   ```

   The command replaces the temporary file of that name. A count of five alone does not establish a qualifying time window; inspect the timestamps and detector result. If fewer records are returned, investigate rather than duplicating or editing event fields.
5. From the project folder, run the package against the printed file path:

   ```powershell
   .\.venv\Scripts\python.exe -m security_log_detector "$env:TEMP\detector-lab-4625.xml"
   ```

   Inspect the finding and summary. Do not commit raw personal Security logs.

### Author reflections

The controlled exercise produced a finding because five distinct failed sign-ins occurred within five minutes and shared the same target computer, account domain and username, and source IP. The detector evaluates each [group](SPEC.md#grouping) separately, so unrelated attempts do not contribute to the same count.

Repeated failures can have an innocent explanation. Someone who forgets their password could try signing in five times within five minutes, triggering the same rule if the grouping fields match. This lab deliberately used a fictitious account; the forgotten-password example illustrates a possible false positive. A finding provides evidence for investigation and does not establish malicious intent.

The fixed threshold also creates a detection gap: four failed sign-ins within five minutes will not trigger a finding, even if they deserve attention. A result with no findings therefore means only that the supplied usable events did not meet this rule's conditions. The detector's [limitations](SPEC.md#limitations) must be considered when interpreting either result.

## Later versions

Version 2 must simplify obtaining and preparing compatible Windows Security logs. The collection method, interface, and acceptance criteria are to be agreed before implementation; see [version scope](SPEC.md#version-scope).

Live monitoring is planned for version 2 or 3. Its design and exact release placement remain undecided. Other detection rules and input formats can be considered after the first usable workflow is complete; see [version scope](SPEC.md#version-scope).

Supporting exports containing events from multiple computers is another possible future improvement. Version 1 rejects files whose usable failed-sign-in records identify multiple computers; see [input requirements](SPEC.md#input-and-event-selection).
