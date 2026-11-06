# Verify that denied Security log access is reported.
# All Windows events are mocked.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $root 'powershell\Export-SOCSignalEvents.ps1'

$tempDir = Join-Path $env:TEMP (
    'socsignal-permissions-' + [guid]::NewGuid().ToString('N')
)

function Get-WinEvent {
    [CmdletBinding()]
    param(
        [hashtable]$FilterHashtable,
        [int]$MaxEvents
    )

    if ($FilterHashtable.LogName -ne 'Security') {
        throw 'Unexpected event log.'
    }

    throw [System.UnauthorizedAccessException]::new(
        'Synthetic access denied'
    )
}

try {
    foreach ($id in @(4625, 4720)) {
        $output = Join-Path $tempDir "denied_$id.jsonl"
        $failureReported = $false

        try {
            & $collector -EventId $id -DaysBack 1 `
                -MaxEvents 1 -OutputPath $output
        }
        catch {
            if ($_.Exception.Message -notlike "Unable to query Security event ${id}*") {
                throw
            }

            $failureReported = $true
        }

        if (-not $failureReported) {
            throw "Event ${id}: access denial was not reported."
        }

        if (Test-Path -LiteralPath $output) {
            throw "Event ${id}: unexpected export created."
        }

        Write-Host "Event $id access-denied test: PASSED"
    }
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force `
        -ErrorAction SilentlyContinue
}
