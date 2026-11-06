# SOCSignal

Windows Security Event Detection & Triage Toolkit

SOCSignal is an open-source cybersecurity portfolio project combining PowerShell and Python to collect, normalize, analyze, and triage selected Windows security events.

## Objectives

- Collect selected Windows Security and System events using PowerShell.
- Export structured security events in JSONL format.
- Analyze events using Python.
- Detect repeated failed logons and noteworthy account or service activity.
- Generate security alert and SOC triage reports.
- Provide a lightweight security audit summary.

## Windows Event IDs

| Event ID | Description | Log |
| --- | --- | --- |
| 4625 | Failed logon | Security |
| 4720 | User account created | Security |
| 7045 | New service installed | System |

## Technology

- Python 3.13
- Windows PowerShell 5.1
- pytest
- Ruff
- GitHub Actions (planned)

## Project Status

Initial development. Features will be added and tested incrementally.

## Security and Privacy

SOCSignal is intended for authorized defensive security analysis.

Real Windows event logs, personal information, and sensitive system data must not be committed to the repository.

Development and automated testing will use synthetic event samples.

The project does not modify Windows security settings.

## License

MIT License. See [LICENSE](LICENSE).

## PowerShell Event Collector

SOCSignal collects selected Windows Security and System events
using Windows PowerShell 5.1 and Get-WinEvent.

### Supported Events

| Event ID | Log | Description |
| --- | --- | --- |
| 4625 | Security | Failed logon |
| 4720 | Security | User account created |
| 7045 | System | Service installed |

### Usage

Run from the project root:

```powershell
.\powershell\Export-SOCSignalEvents.ps1 -EventId 4625 -DaysBack 7 -MaxEvents 20
```

For account creation events:

```powershell
.\powershell\Export-SOCSignalEvents.ps1 -EventId 4720 -DaysBack 7
```

For service installation events:

```powershell
.\powershell\Export-SOCSignalEvents.ps1 -EventId 7045 -DaysBack 30
```

Event ID 7045 is the default.

The collector creates JSONL files in the local exports directory.
Output files are excluded from Git.

The collector normalizes timestamps to UTC and exports selected
event metadata rather than full Windows event messages.

When a query returns no matching events, the output file is empty.

Security log access depends on Windows permissions.
The collector does not modify Windows security settings.

### Testing

Run the synthetic PowerShell tests:

```powershell
.\tests\test_exporter.ps1
.\tests\test_security_exporter.ps1
```

Run Python tests and lint checks:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
```

Synthetic tests mock Get-WinEvent and do not read actual Windows logs.

### Security and Privacy

Real event exports may contain sensitive usernames,
hostnames, IP addresses, and service information.

Never commit real event exports or private investigation data.

Custom output paths must point to private, Git-ignored locations.

SOCSignal is intended for authorized defensive security analysis.

## Detection Rules

SOCSignal includes a Python detection engine that analyzes
normalized Windows security events.

### Implemented Rules

| Rule ID | Detection | Severity |
| --- | --- | --- |
| SOC-001 | Repeated failed logons | Medium |
| SOC-002 | New Windows account created | Low |
| SOC-003 | New Windows service installed | Low |

### SOC-001: Repeated Failed Logons

Detects repeated Event ID 4625 failures grouped by:

- Computer
- Source IP address
- Target account

Default threshold: 3 failed logons within 5 minutes.

Both the threshold and time window are configurable.

The rule uses a sliding time window and avoids counting
duplicate Windows event record IDs within each group.

Version 1 produces the first qualifying burst alert per group.

### SOC-002: Account Creation

Flags Event ID 4720 for analyst review.

Includes the target account, initiating account when
available, timestamp, and supporting event record ID.

### SOC-003: Service Installation

Flags Event ID 7045 for analyst review.

Includes the service name, startup type, timestamp,
and supporting event record ID.

### Detection Example

The Python API can be used with the included synthetic events:

```python
from socsignal.reader import read_events
from socsignal.detections import (
    detect_failed_logon_bursts,
    detect_noteworthy_activity,
)

events = read_events("samples/synthetic_events.jsonl")

alerts = detect_failed_logon_bursts(events) + detect_noteworthy_activity(events)

for alert in alerts:
    print(alert["rule_id"], alert["title"], alert["severity"])
```

The included synthetic sample generates three review alerts.

### Detection Limitations

- Alerts indicate activity requiring review, not confirmed attacks.
- Repeated failed logons can result from legitimate user mistakes.
- Account creation and service installation may be authorized.
- Detection is currently performed on supplied event records.
- Markdown triage reports and a command-line interface are implemented.

All detection tests use synthetic data.

## SOC Triage Reports and CLI

SOCSignal generates Markdown reports containing:

- Executive summary and alert counts
- Security activity counts for Events 4625, 4720, and 7045
- Detection rules and alert severity
- Affected hosts, timestamps, and supporting event record IDs
- Recommended investigation steps
- Analyst notes and a lightweight audit activity snapshot

### Run SOCSignal

Install the project and development dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
```

Analyze the included synthetic events:

```powershell
.\.venv\Scripts\socsignal.exe samples\synthetic_events.jsonl
```

Alternatively, use the Python module:

```powershell
.\.venv\Scripts\python.exe -m socsignal.cli samples\synthetic_events.jsonl
```

Multiple JSONL files can be analyzed together by providing
additional input paths.

Avoid supplying the same export more than once, since the
activity snapshot counts supplied records.

### Report Output

The CLI generates:

`reports/triage.md`

Generated reports are excluded from Git.

The report includes a lightweight audit activity summary,
but it is not a formal compliance assessment.

### Important Limitations

SOCSignal is a defensive analysis toolkit, not a SIEM.

Detection findings require analyst validation. The absence
of alerts does not establish that a system is secure.

The tool does not modify security settings or automatically
remediate detected activity.

Real Windows event exports and reports must remain private.

## Continuous Integration

GitHub Actions runs automated checks on every push to main
and on pull requests.

The CI workflow includes:

- Python 3.13 testing on Windows and Ubuntu
- Ruff formatting and lint checks
- pytest automated tests
- PowerShell 5.1 synthetic Windows event collector tests

All CI tests use synthetic security events.

No private Windows event logs are collected or uploaded.

Workflow: `.github/workflows/tests.yml`
