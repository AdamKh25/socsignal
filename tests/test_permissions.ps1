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

        if ($id -eq 4720) {
            [System.IO.Directory]::CreateDirectory($tempDir) | Out-Null

            [System.IO.File]::WriteAllText(
                $output,
                'PRIOR_EXPORT_DO_NOT_OVERWRITE',
                [System.Text.Encoding]::ASCII
            )
        }

        try {
            & $collector -EventId $id -DaysBack 1 `
                -MaxEvents 1 -OutputPath $output
        }
        catch {
            if ($_.Exception.Message -notlike "Unable to query Security event ${id}*") {
                throw
            }

            if ($_.Exception.Message -notlike '*existing output may be stale*') {
                throw "Event ${id}: missing stale export warning."
            }

            $failureReported = $true
        }

        if (-not $failureReported) {
            throw "Event ${id}: access denial was not reported."
        }

        if ($id -eq 4625) {
            if (Test-Path -LiteralPath $output) {
                throw "Event ${id}: unexpected export created."
            }
        }
        else {
            $previous = [System.IO.File]::ReadAllText($output)

            if ($previous -ne 'PRIOR_EXPORT_DO_NOT_OVERWRITE') {
                throw "Event ${id}: previous export was modified."
            }
        }

        Write-Host "Event $id access-denied test: PASSED"
    }
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force `
        -ErrorAction SilentlyContinue
}
