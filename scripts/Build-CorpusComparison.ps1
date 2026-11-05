[CmdletBinding()]
param(
    [string]$DeltaManifest = (Join-Path $PSScriptRoot '..\samples\manifest.csv'),
    [string]$ControlManifest = (Join-Path $PSScriptRoot '..\samples\control-manifest.csv'),
    [string]$Executable = (Join-Path $PSScriptRoot '..\x64\Release\PE_CodeCave.exe'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\v1.0.0-comparison'),
    [string]$ComparisonCsv = (Join-Path $PSScriptRoot '..\samples\v1.0.0-comparison.csv'),
    [string]$SummaryCsv = (Join-Path $PSScriptRoot '..\samples\v1.0.0-summary.csv'),
    [string]$MarkdownPath = (Join-Path $PSScriptRoot '..\samples\comparison.md')
)

$ErrorActionPreference = 'Stop'

$deltaPath = (Resolve-Path -LiteralPath $DeltaManifest).Path
$controlPath = (Resolve-Path -LiteralPath $ControlManifest).Path
$executablePath = (Resolve-Path -LiteralPath $Executable).Path
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$reportRoot = Join-Path $outputPath 'reports'
$logRoot = Join-Path $outputPath 'logs'
$null = [System.IO.Directory]::CreateDirectory($reportRoot)
$null = [System.IO.Directory]::CreateDirectory($logRoot)

function Get-Median {
    param([double[]]$Values)

    if (-not $Values -or $Values.Count -eq 0) {
        return $null
    }
    $sorted = @($Values | Sort-Object)
    $middle = [int][math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2 -eq 1) {
        return [double]$sorted[$middle]
    }
    return ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2.0
}

function Get-CategoryRows {
    param(
        [object[]]$Rows,
        [string]$Category
    )

    $valid = @($Rows | Where-Object { $_.status -eq 'OK' })
    if ($valid.Count -eq 0) {
        return [PSCustomObject]@{
            category                 = $Category
            samples                  = 0
            unique_sha256            = 0
            mean_risk_score          = $null
            median_risk_score        = $null
            mean_caves               = $null
            median_caves             = $null
            cap_rate_percent         = $null
            mean_anomalies           = $null
            mean_rwx_sections        = $null
            mean_entropy             = $null
            high_or_critical_percent = $null
        }
    }

    $scores = [double[]]@($valid | ForEach-Object { [double]$_.risk_score })
    $caves = [double[]]@($valid | ForEach-Object { [double]$_.cave_count })
    $anomalies = [double[]]@($valid | ForEach-Object { [double]$_.anomaly_count })
    $rwx = [double[]]@($valid | ForEach-Object { [double]$_.rwx_section_count })
    $entropy = [double[]]@($valid | ForEach-Object { [double]$_.overall_entropy })
    $atCap = @($valid | Where-Object { [int]$_.cave_count -ge 150 }).Count
    $highOrCritical = @($valid | Where-Object {
        $_.risk_grade -in @('高危', '严重', 'HIGH', 'CRITICAL')
    }).Count

    return [PSCustomObject]@{
        category                 = $Category
        samples                  = $valid.Count
        unique_sha256            = @($valid.sha256 | Sort-Object -Unique).Count
        mean_risk_score          = [math]::Round(($scores | Measure-Object -Average).Average, 2)
        median_risk_score        = [math]::Round((Get-Median $scores), 2)
        mean_caves               = [math]::Round(($caves | Measure-Object -Average).Average, 2)
        median_caves             = [math]::Round((Get-Median $caves), 2)
        cap_rate_percent         = [math]::Round(($atCap * 100.0 / $valid.Count), 2)
        mean_anomalies           = [math]::Round(($anomalies | Measure-Object -Average).Average, 2)
        mean_rwx_sections        = [math]::Round(($rwx | Measure-Object -Average).Average, 2)
        mean_entropy             = [math]::Round(($entropy | Measure-Object -Average).Average, 4)
        high_or_critical_percent = [math]::Round(($highOrCritical * 100.0 / $valid.Count), 2)
    }
}

$deltaRows = @(Import-Csv -LiteralPath $deltaPath | ForEach-Object {
    [PSCustomObject]@{
        sample_id         = $_.sample_id
        sample_name       = $_.sample_name
        sha256            = $_.sha256
        size_bytes        = $_.size_bytes
        category          = 'Delta Force installation'
        source_collection = $_.source_collection
        source_location   = $_.source_location
        target_path       = $_.target_path
    }
})

$controlRows = @(Import-Csv -LiteralPath $controlPath | ForEach-Object {
    [PSCustomObject]@{
        sample_id         = $_.sample_id
        sample_name       = $_.sample_name
        sha256            = $_.sha256
        size_bytes        = $_.size_bytes
        category          = $_.category
        source_collection = $_.source_collection
        source_location   = $_.source_location
        target_path       = $_.target_path
    }
})

$rows = @($deltaRows) + @($controlRows)
$results = New-Object System.Collections.Generic.List[object]
$index = 0

foreach ($row in $rows) {
    $index++
    Write-Progress `
        -Activity 'PE CodeCave v1.0.0 corpus comparison' `
        -Status "$index / $($rows.Count): $($row.sample_id) $($row.sample_name)" `
        -PercentComplete (($index / $rows.Count) * 100)

    $status = 'Missing'
    $message = 'Target file does not exist.'
    $actualHash = ''
    $riskScore = $null
    $riskGrade = ''
    $caveCount = $null
    $highRiskCaves = $null
    $anomalyCount = $null
    $totalCaveBytes = $null
    $rwxSections = $null
    $executableSections = $null
    $overallEntropy = $null

    if (Test-Path -LiteralPath $row.target_path -PathType Leaf) {
        $actualHash = (Get-FileHash -LiteralPath $row.target_path -Algorithm SHA256).Hash.ToUpperInvariant()
        if ([string]$row.sha256 -and $actualHash -ne ([string]$row.sha256).ToUpperInvariant()) {
            $status = 'HashMismatch'
            $message = 'Current file hash does not match the manifest.'
        }
        else {
            $sampleReportDirectory = Join-Path $reportRoot $row.sample_id
            $null = [System.IO.Directory]::CreateDirectory($sampleReportDirectory)
            $processOutput = & $executablePath `
                --path $row.target_path `
                --json `
                --out $sampleReportDirectory `
                --quiet 2>&1 | Out-String
            $exitCode = $LASTEXITCODE

            if ($exitCode -eq 0) {
                $jsonFile = Get-ChildItem -LiteralPath $sampleReportDirectory -File -Filter '*.json' |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1
                if ($jsonFile) {
                    try {
                        $report = Get-Content -LiteralPath $jsonFile.FullName -Raw | ConvertFrom-Json
                        $status = 'OK'
                        $message = ''
                        $riskScore = [int]$report.summary.risk_score
                        $riskGrade = [string]$report.summary.risk_grade
                        $caveCount = [int]$report.summary.cave_count
                        $highRiskCaves = [int]$report.summary.high_risk_cave_count
                        $anomalyCount = [int]$report.summary.anomaly_count
                        $rwxSections = [int]$report.summary.rwx_section_count
                        $executableSections = [int]$report.summary.executable_section_count
                        $overallEntropy = [double]$report.summary.overall_entropy
                        $totalCaveBytes = [int]$report.summary.total_cave_bytes
                    }
                    catch {
                        $status = 'InvalidReport'
                        $message = $_.Exception.Message
                    }
                }
                else {
                    $status = 'NoReport'
                    $message = 'The scanner exited successfully but produced no JSON report.'
                }
            }
            else {
                $status = 'AnalysisFailed'
                $message = "Scanner exited with code $exitCode. $processOutput"
            }
        }
    }

    $results.Add([PSCustomObject]@{
        sample_id              = $row.sample_id
        sample_name            = $row.sample_name
        category               = $row.category
        source_collection      = $row.source_collection
        source_location        = $row.source_location
        target_path            = $row.target_path
        sha256                 = $actualHash
        expected_sha256        = $row.sha256
        size_bytes             = $row.size_bytes
        status                 = $status
        risk_score             = $riskScore
        risk_grade             = $riskGrade
        cave_count             = $caveCount
        high_risk_cave_count   = $highRiskCaves
        anomaly_count          = $anomalyCount
        total_cave_bytes       = $totalCaveBytes
        rwx_section_count      = $rwxSections
        executable_section_count = $executableSections
        overall_entropy        = $overallEntropy
        message                = $message
    })
}

Write-Progress -Activity 'PE CodeCave v1.0.0 corpus comparison' -Completed

$comparisonCsvPath = [System.IO.Path]::GetFullPath($ComparisonCsv)
$summaryCsvPath = [System.IO.Path]::GetFullPath($SummaryCsv)
$markdownFullPath = [System.IO.Path]::GetFullPath($MarkdownPath)
$null = [System.IO.Directory]::CreateDirectory((Split-Path -Parent $comparisonCsvPath))
$null = [System.IO.Directory]::CreateDirectory((Split-Path -Parent $summaryCsvPath))
$null = [System.IO.Directory]::CreateDirectory((Split-Path -Parent $markdownFullPath))

$results | Export-Csv -LiteralPath $comparisonCsvPath -NoTypeInformation -Encoding UTF8

$summaryRows = New-Object System.Collections.Generic.List[object]
$summaryRows.Add((Get-CategoryRows -Rows @($results | Where-Object { $_.category -eq 'Delta Force installation' }) -Category 'Delta Force installation'))
$summaryRows.Add((Get-CategoryRows -Rows @($results | Where-Object { $_.category -eq 'Windows System32 (x64)' }) -Category 'Windows System32 (x64)'))
$summaryRows.Add((Get-CategoryRows -Rows @($results | Where-Object { $_.category -eq 'Windows SysWOW64 (x86)' }) -Category 'Windows SysWOW64 (x86)'))
$summaryRows.Add((Get-CategoryRows -Rows @($results | Where-Object { $_.category -in @('Windows System32 (x64)', 'Windows SysWOW64 (x86)') }) -Category 'Windows control combined'))
$summaryRows | Export-Csv -LiteralPath $summaryCsvPath -NoTypeInformation -Encoding UTF8

$markdown = New-Object System.Text.StringBuilder
[void]$markdown.AppendLine('# v1.0.0 Corpus Comparison')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('Measured with the `v1.0.0` release binary. Sample bodies are not stored in this repository.')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('| Category | Samples | Mean risk | Median risk | Mean caves | Median caves | 150-cap rate | Mean anomalies | RWX mean |')
[void]$markdown.AppendLine('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
foreach ($summary in $summaryRows) {
    [void]$markdown.AppendLine(
        "| $($summary.category) | $($summary.samples) | $($summary.mean_risk_score) | $($summary.median_risk_score) | $($summary.mean_caves) | $($summary.median_caves) | $($summary.cap_rate_percent)% | $($summary.mean_anomalies) | $($summary.mean_rwx_sections) |"
    )
}
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## Interpretation')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('- The Delta Force corpus is one software installation and is not a labelled malware benchmark.')
[void]$markdown.AppendLine('- The Windows control corpus contains 50 Microsoft-signed x64 System32 binaries and 50 Microsoft-signed x86 SysWOW64 binaries.')
[void]$markdown.AppendLine('- The detector is byte/alignment agnostic: it does not disassemble instructions, validate instruction boundaries, or prove control-flow reachability.')
[void]$markdown.AppendLine('- A cave is a candidate byte range, not a verified code injection site.')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## Reproduction')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('```powershell')
[void]$markdown.AppendLine('.\scripts\Select-ControlCorpus.ps1')
[void]$markdown.AppendLine('.\scripts\Build-Release.ps1 -Version 1.0.0')
[void]$markdown.AppendLine('.\scripts\Build-CorpusComparison.ps1')
[void]$markdown.AppendLine('```')

[System.IO.File]::WriteAllText($markdownFullPath, $markdown.ToString(), [System.Text.Encoding]::UTF8)

$summaryRows | Format-Table -AutoSize
Write-Host "Comparison CSV: $comparisonCsvPath"
Write-Host "Summary CSV:    $summaryCsvPath"
Write-Host "Markdown:       $markdownFullPath"
