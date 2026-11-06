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
