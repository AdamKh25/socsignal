# Synthetic test for the SOCSignal PowerShell collector.
# No real Windows event logs are accessed.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $root 'powershell\Export-SOCSignalEvents.ps1'

$testOutput = Join-Path $env:TEMP (
    'socsignal-test-' + [guid]::NewGuid().ToString('N') + '.jsonl'
)

# Mock Get-WinEvent so the collector receives a fictional event.
function Get-WinEvent {
    param(
        [hashtable]$FilterHashtable,
        [int]$MaxEvents
    )

    if ($FilterHashtable.LogName -ne 'System' -or
        $FilterHashtable.Id -ne 7045) {
        throw 'Unexpected event filter.'
    }

    $fakeRecord = [PSCustomObject]@{
        RecordId = 9001
        MachineName = 'LAB-WIN11'
        TimeCreated = [datetime]::SpecifyKind(
            [datetime]'2026-11-06 00:40:00',
            [System.DateTimeKind]::Utc
        )
    }

    $fakeRecord | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
        return '<Event><EventData><Data Name="ServiceName">DemoService</Data><Data Name="StartType">auto start</Data></EventData></Event>'
    }

    return $fakeRecord
}

try {
    & $collector -DaysBack 1 -MaxEvents 1 -OutputPath $testOutput

    if (-not (Test-Path -LiteralPath $testOutput)) {
        throw 'Collector did not create the expected output.'
    }

    $records = @(Get-Content -LiteralPath $testOutput | ConvertFrom-Json)

    if ($records.Count -ne 1) {
        throw 'Expected exactly one synthetic event.'
    }

    if ($records[0].event_id -ne 7045) {
        throw 'Incorrect event ID.'
    }

    if ($records[0].log_name -ne 'System') {
        throw 'Incorrect log name.'
    }

    if ($records[0].event_data.service_name -ne 'DemoService') {
        throw 'Incorrect service name.'
    }

    if ($records[0].timestamp -notmatch 'Z$') {
        throw 'Timestamp is not in UTC format.'
    }

    Write-Host 'PowerShell synthetic collector test: PASSED'
}
finally {
    Remove-Item -LiteralPath $testOutput -Force -ErrorAction SilentlyContinue
}
