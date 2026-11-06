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

The initial collector supports Windows System Event ID 7045,
which records service installations.

Run from the project root:

```powershell
.\powershell\Export-SOCSignalEvents.ps1 -DaysBack 30 -MaxEvents 20
```

By default, the collector writes to:

`exports/system_7045.jsonl`

This directory is excluded from Git.

The collector exports timestamps in UTC and includes selected
service metadata. It does not export complete event messages.

### Testing

Run the synthetic PowerShell test:

```powershell
.\tests\test_exporter.ps1
```

Run Python tests and lint checks:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
```

The PowerShell test mocks Get-WinEvent and does not access
real Windows logs.

### Privacy

Collected events may contain sensitive hostnames and service names.

Do not publish real event exports. When specifying a custom
output path, use a private location excluded from version control.

Security Event IDs 4625 and 4720 are planned for a later version.
