[CmdletBinding()]
param(
    [string]$Manifest = (Join-Path $PSScriptRoot '..\samples\manifest.csv'),
    [string]$Executable = (Join-Path $PSScriptRoot '..\x64\Release\PE_CodeCave.exe'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\reproduction'),
    [switch]$VerifyOnly,
    [int]$Limit = 0
)

$ErrorActionPreference = 'Stop'

$manifestPath = (Resolve-Path -LiteralPath $Manifest).Path
$executablePath = (Resolve-Path -LiteralPath $Executable).Path
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$logDirectory = Join-Path $outputPath 'logs'
$reportDirectory = Join-Path $outputPath 'reports'
$null = [System.IO.Directory]::CreateDirectory($logDirectory)
$null = [System.IO.Directory]::CreateDirectory($reportDirectory)

$rows = @(Import-Csv -LiteralPath $manifestPath)
if ($Limit -gt 0) {
    $rows = @($rows | Select-Object -First $Limit)
}

$results = New-Object System.Collections.Generic.List[object]
$index = 0

foreach ($row in $rows) {
    $index++
    $status = ''
    $exitCode = ''
    $durationMs = ''
    $actualHash = ''
    $errorText = ''
    $targetPath = [string]$row.target_path
    $expectedHash = ([string]$row.sha256).ToUpperInvariant()

    Write-Progress `
        -Activity 'PE CodeCave dataset reproduction' `
        -Status "$index / $($rows.Count): $($row.sample_name)" `
        -PercentComplete (($index / $rows.Count) * 100)

    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        $status = 'Missing'
        $errorText = 'Target file does not exist.'
    }
    else {
        $actualHash = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash.ToUpperInvariant()

        if ($expectedHash -and $actualHash -ne $expectedHash) {
            $status = 'HashMismatch'
            $errorText = "Expected $expectedHash but found $actualHash"
        }
        elseif ($VerifyOnly) {
            $status = 'Verified'
        }
        else {
            $startedAt = [System.Diagnostics.Stopwatch]::StartNew()
            $processOutput = & $executablePath `
                --path $targetPath `
                --json `
                --out $reportDirectory `
                --quiet 2>&1 | Out-String
            $exitCode = $LASTEXITCODE
            $startedAt.Stop()
            $durationMs = $startedAt.ElapsedMilliseconds

            if (-not $status) {
                if ($exitCode -eq 0) {
                    $status = 'Reproduced'
                }
                else {
                    $status = 'Failed'
                    $errorText = "Process exited with code $exitCode."
                }
            }

            $logPath = Join-Path $logDirectory ("{0}.log" -f $row.sample_id)
            $logText = "sample_id: $($row.sample_id)`r`n" +
                "sample_name: $($row.sample_name)`r`n" +
                "target_path: $targetPath`r`n" +
                "sha256: $actualHash`r`n" +
                "status: $status`r`n" +
                "exit_code: $exitCode`r`n" +
                "duration_ms: $durationMs`r`n`r`n" +
                "--- PROCESS OUTPUT ---`r`n$processOutput`r`n"
            [System.IO.File]::WriteAllText($logPath, $logText, [System.Text.Encoding]::UTF8)
        }
    }

    $results.Add([PSCustomObject]@{
        sample_id            = $row.sample_id
        sample_name          = $row.sample_name
        target_path          = $targetPath
        expected_sha256      = $expectedHash
        actual_sha256        = $actualHash
        status               = $status
        exit_code            = $exitCode
        duration_ms          = $durationMs
        original_risk_score  = $row.risk_score
        original_risk_grade  = $row.risk_grade
        error                = $errorText
    })
}

Write-Progress -Activity 'PE CodeCave dataset reproduction' -Completed

$resultPath = Join-Path $outputPath 'run_results.csv'
$results | Export-Csv -LiteralPath $resultPath -NoTypeInformation -Encoding UTF8

$results |
    Group-Object status |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host "Results: $resultPath"
