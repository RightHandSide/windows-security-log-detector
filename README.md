# Windows Security Log Detector

A Python learning project for turning Windows security events into explainable suspicious-activity findings.

**Status:** version 1 is specified but not implemented. There are no installation commands, executable examples, or passing-test claims yet.

## Purpose

Learn how Windows records failed sign-ins, how a detection rule uses those records, and how to explain the evidence, innocent explanations, and limitations behind a finding.

The first version will analyze a saved XML export from one computer's Windows Security log. It will run on demand from the command line and detect repeated failed sign-ins. Real events from a controlled practice environment will support learning; synthetic examples will support repeatable tests.

## Planned usage

1. Export the Security events from a controlled Windows practice environment as XML.
2. Supply that file to the command-line tool.
3. Read the findings and the summary of analyzed events, skipped events, and findings produced.
4. Inspect the original events and explain why the rule triggered and what else could explain the activity.

Setup instructions, the exact command, and verified export instructions will be added as those steps are implemented and checked.

## Worked example of the planned behavior

Suppose five distinct failed-sign-in events occur at `10:00`, `10:01`, `10:02`, `10:03`, and `10:05` UTC. All target `LAB\alice` on `PC-A` and have source IP `192.0.2.10`.

The fifth event would produce one finding containing:

| Field | Value |
| --- | --- |
| Computer | `PC-A` |
| Target account | `LAB\alice` |
| Source IP | `192.0.2.10` |
| Triggering attempt count | 5 |
| First triggering attempt | `10:00:00Z` |
| Last triggering attempt | `10:05:00Z` |
| Reason | Five failed sign-ins within five minutes |

This is an illustrative example, not output from an implemented program. The authoritative behavior is in [SPEC.md](SPEC.md).

A finding flags activity for investigation. Repeated typing mistakes or an outdated saved password can also produce repeated failures. The rule does not prove an attack. A run without findings only means this rule found no qualifying pattern among usable events in the supplied file.

## Development and learning workflow

Development uses Python, OOP, and `pytest`:

1. Agree on one small behavior and its public interface; record the behavior in `SPEC.md`.
2. The assistant supplies one test and verifies that it fails for the expected reason.
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

The author will write explanations in their own words as the project develops. These should connect Windows event fields to findings, discuss false positives and detection gaps, and reflect on lessons from tests and real logs. The assistant can ask questions, tutor, and review those explanations.

No completed investigation or learning conclusion is claimed yet.

## Later versions

Live monitoring is planned for version 2 or 3. Its design and exact release placement remain undecided. Other detection rules and input formats can be considered after the first usable workflow is complete; see [version scope](SPEC.md#version-scope).
