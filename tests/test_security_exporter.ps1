# Synthetic tests for Windows Security events 4625 and 4720.
# Get-WinEvent is mocked; no real Windows logs are queried.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $root 'powershell\Export-SOCSignalEvents.ps1'

$tempDir = Join-Path $env:TEMP (
    'socsignal-security-' + [guid]::NewGuid().ToString('N')
)

[System.IO.Directory]::CreateDirectory($tempDir) | Out-Null

function Get-WinEvent {
    [CmdletBinding()]
    param(
        [hashtable]$FilterHashtable,
        [int]$MaxEvents
    )

    $eventId = [int]$FilterHashtable.Id

    if ($FilterHashtable.LogName -ne 'Security') {
        throw 'Expected Security event log.'
    }

    # Test-only condition: simulate a query with no matching records.
    if ($MaxEvents -eq 2) {
        $exception = [System.Exception]::new('No events found')
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'NoMatchingEventsFound',
            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
            $null
        )
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }

    $xmlData = switch ($eventId) {
        4625 {
            '<Event><EventData>' +
            '<Data Name="TargetUserName">demo.user</Data>' +
            '<Data Name="IpAddress">192.0.2.10</Data>' +
            '<Data Name="LogonType">3</Data>' +
            '<Data Name="Status">0xC000006D</Data>' +
            '</EventData></Event>'
        }

        4720 {
            '<Event><EventData>' +
            '<Data Name="TargetUserName">training-account</Data>' +
            '<Data Name="SubjectUserName">LAB-ADMIN</Data>' +
            '</EventData></Event>'
        }

        default {
            throw 'Unexpected event ID.'
        }
    }

    $fakeEvent = [PSCustomObject]@{
        RecordId = 9000 + $eventId
        MachineName = 'LAB-WIN11'
        TimeCreated = [datetime]::SpecifyKind(
            [datetime]'2026-11-06 00:40:00',
            [System.DateTimeKind]::Utc
        )
        EventXml = $xmlData
    }

    $fakeEvent | Add-Member -MemberType ScriptMethod `
        -Name ToXml -Value { return $this.EventXml }

    return $fakeEvent
}

try {
    foreach ($id in @(4625, 4720)) {
        $output = Join-Path $tempDir "synthetic_$id.jsonl"

        & $collector -EventId $id -DaysBack 1 `
            -MaxEvents 1 -OutputPath $output

        if (-not (Test-Path -LiteralPath $output)) {
            throw "Event $id export was not created."
        }

        $records = @(
            Get-Content -LiteralPath $output | ConvertFrom-Json
        )

        if ($records.Count -ne 1) {
            throw "Event ${id}: expected one record."
        }

        $record = $records[0]

        if ($record.event_id -ne $id -or
            $record.log_name -ne 'Security') {
            throw "Event ${id}: incorrect event metadata."
        }

        if ($record.timestamp -notmatch 'Z$') {
            throw "Event ${id}: timestamp is not UTC."
        }

        if ($id -eq 4625) {
            if ($record.event_data.target_user -ne 'demo.user' -or
                $record.event_data.source_ip -ne '192.0.2.10') {
                throw 'Failed logon field validation failed.'
            }
        }

        if ($id -eq 4720) {
            if ($record.event_data.target_user -ne 'training-account' -or
                $record.event_data.subject_user -ne 'LAB-ADMIN') {
                throw 'Account creation field validation failed.'
            }
        }

        $python = Join-Path $root '.venv\Scripts\python.exe'

        $pythonCheck = 'import sys; from socsignal.reader import read_events; e = read_events(sys.argv[1]); assert len(e) == 1 and e[0][sys.argv[3]] == int(sys.argv[2]); print(sys.argv[4])'

        & $python -c $pythonCheck $output $id 'event_id' 'Python integration: PASSED'

        if ($LASTEXITCODE -ne 0) {
            throw "Python validation failed for event ${id}."
        }

        Write-Host "Synthetic Event $id test: PASSED"
    }

    # Verify stale output is replaced when no events match.
    $emptyPath = Join-Path $tempDir 'no_matches.jsonl'

    Set-Content -LiteralPath $emptyPath `
        -Value '{"stale":true}' -Encoding Ascii

    & $collector -EventId 4625 -DaysBack 1 `
        -MaxEvents 2 -OutputPath $emptyPath

    $file = Get-Item -LiteralPath $emptyPath

    if ($file.Length -ne 0) {
        throw 'No-match export retained stale data.'
    }

    Write-Host 'No-matching-events test: PASSED'
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force `
        -ErrorAction SilentlyContinue
}
