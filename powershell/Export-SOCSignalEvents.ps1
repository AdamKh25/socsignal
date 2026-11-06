<#
.SYNOPSIS
    Export selected Windows security events to JSONL.

.DESCRIPTION
    Supports Event IDs 4625, 4720, and 7045.
    Writes structured event data to a local JSONL file.
    Does not modify Windows security settings.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,

    [ValidateRange(1, 100)]
    [int]$MaxEvents = 20,

    [ValidateSet(4625, 4720, 7045)]
    [int]$EventId = 7045,

    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $projectRoot 'exports'

$logName = if ($EventId -eq 7045) {
    'System'
}
else {
    'Security'
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $fileName = '{0}_{1}.jsonl' -f $logName.ToLower(), $EventId
    $OutputPath = Join-Path $outputDir $fileName
}

$filter = @{
    LogName = $logName
    Id = $EventId
    StartTime = (Get-Date).AddDays(-$DaysBack)
}

try {
    $events = @(
        Get-WinEvent -FilterHashtable $filter `
            -MaxEvents $MaxEvents -ErrorAction Stop
    )
}
catch {
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {
        $events = @()
    }
    else {
        throw "Unable to query $logName event $EventId : $($_.FullyQualifiedErrorId)"
    }
}

$lines = @(
    foreach ($entry in $events) {
        $xml = [xml]$entry.ToXml()
        $fields = @{}

        foreach ($node in @($xml.Event.EventData.Data)) {
            if ($null -eq $node) {
                continue
            }

            $name = $node.GetAttribute('Name')

            if ($name) {
                $fields[$name] = $node.InnerText
            }
        }

        $eventData = switch ($EventId) {
            4625 {
                @{
                    target_user = $fields['TargetUserName']
                    source_ip = $fields['IpAddress']
                    logon_type = $fields['LogonType']
                    status = $fields['Status']
                }
            }

            4720 {
                @{
                    target_user = $fields['TargetUserName']
                    subject_user = $fields['SubjectUserName']
                }
            }

            7045 {
                @{
                    service_name = $fields['ServiceName']
                    start_type = $fields['StartType']
                }
            }
        }

        $requiredField = if ($EventId -eq 7045) {
            'service_name'
        }
        else {
            'target_user'
        }

        if ([string]::IsNullOrWhiteSpace(
            $eventData[$requiredField]
        )) {
            throw "Required field missing in event record $($entry.RecordId)."
        }

        $record = [ordered]@{
            event_id = $EventId
            timestamp = $entry.TimeCreated.ToUniversalTime().ToString(
                'yyyy-MM-ddTHH:mm:ss.fffZ'
            )
            log_name = $logName
            record_id = $entry.RecordId
            computer = $entry.MachineName
            event_data = $eventData
        }

        ConvertTo-Json -InputObject $record -Depth 4 -Compress
    }
)

$destination = Split-Path -Path $OutputPath -Parent

if ($destination) {
    [System.IO.Directory]::CreateDirectory(
        $destination
    ) | Out-Null
}

$encoding = New-Object System.Text.UTF8Encoding($false)

[System.IO.File]::WriteAllLines(
    $OutputPath,
    [string[]]$lines,
    $encoding
)

Write-Host "Exported $($lines.Count) events (ID $EventId)."
Write-Host "Output: $OutputPath"
