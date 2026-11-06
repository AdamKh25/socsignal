<#
.SYNOPSIS
    Collect Windows service installation events for SOCSignal.

.DESCRIPTION
    Exports selected System Event ID 7045 records to JSONL.
    The output is local and excluded from Git.
    This script does not modify Windows security settings.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,

    [ValidateRange(1, 100)]
    [int]$MaxEvents = 20,

    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $projectRoot 'exports'
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $outputDir 'system_7045.jsonl'
}

$filter = @{
    LogName = 'System'
    Id = 7045
    StartTime = (Get-Date).AddDays(-$DaysBack)
}

try {
    $events = @(
        Get-WinEvent -FilterHashtable $filter `
            -MaxEvents $MaxEvents -ErrorAction Stop
    )
}
catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        Write-Host 'No matching service installation events found.'
        return
    }

    throw "Unable to query System events: $($_.FullyQualifiedErrorId)"
}

$lines = foreach ($entry in $events) {
    $xml = [xml]$entry.ToXml()
    $fields = @{}

    foreach ($node in $xml.Event.EventData.Data) {
        $name = $node.GetAttribute('Name')

        if ($name) {
            $fields[$name] = $node.InnerText
        }
    }

    if ([string]::IsNullOrWhiteSpace($fields['ServiceName'])) {
        throw "Event record $($entry.RecordId) has no service name."
    }

    $record = [ordered]@{
        event_id = 7045
        timestamp = $entry.TimeCreated.ToUniversalTime().ToString(
            'yyyy-MM-ddTHH:mm:ss.fffZ'
        )
        log_name = 'System'
        record_id = $entry.RecordId
        computer = $entry.MachineName
        event_data = @{
            service_name = $fields['ServiceName']
            start_type = $fields['StartType']
        }
    }

    ConvertTo-Json -InputObject $record -Depth 4 -Compress
}

$destination = Split-Path -Path $outputPath -Parent
if ($destination) {
    [System.IO.Directory]::CreateDirectory($destination) | Out-Null
}

$encoding = New-Object System.Text.UTF8Encoding($false)

[System.IO.File]::WriteAllLines(
    $outputPath,
    [string[]]$lines,
    $encoding
)

Write-Host "Exported $($lines.Count) service installation events."
Write-Host "Output: $outputPath"

