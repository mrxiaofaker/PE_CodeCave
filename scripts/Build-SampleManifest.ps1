[CmdletBinding()]
param(
    [string]$ReportsDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\samples'),
    [switch]$NoHash
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-HtmlText {
    param([AllowEmptyString()][string]$Text)
    return [System.Net.WebUtility]::HtmlDecode($Text)
}

function Get-SourceMetadata {
    param([string]$TargetPath)

    $parts = $TargetPath -split '[\\/]'
    if ($parts.Count -ge 4) {
        $location = ($parts[0..2] -join '\')
    }
    elseif ($parts.Count -gt 1) {
        $location = ($parts[0..($parts.Count - 2)] -join '\')
    }
    else {
        $location = ''
    }

    if ($TargetPath -match '^F:\\Delta Force\\Delta Force\\') {
        return [PSCustomObject]@{
            Collection = 'Delta Force local installation'
            Location   = 'F:\Delta Force\Delta Force'
        }
    }

    return [PSCustomObject]@{
        Collection = 'Local authorized corpus'
        Location   = $location
    }
}

$reportsRoot = (Resolve-Path -LiteralPath $ReportsDirectory).Path
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$null = [System.IO.Directory]::CreateDirectory($outputRoot)

$reports = Get-ChildItem -LiteralPath $reportsRoot -File -Filter '*_PE_CodeCave_*.html' |
    Sort-Object Name

if ($reports.Count -eq 0) {
    throw "No PE CodeCave HTML reports were found in $reportsRoot"
}

$records = New-Object System.Collections.Generic.List[object]
$ordinal = 0

foreach ($report in $reports) {
    $html = [System.IO.File]::ReadAllText($report.FullName)
    $targetMatch = [regex]::Match(
        $html,
        '<code title="([^"]+)">',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if (-not $targetMatch.Success) {
        Write-Warning "Skipping report without a target path: $($report.Name)"
        continue
    }

    $targetPath = ConvertFrom-HtmlText $targetMatch.Groups[1].Value
    $source = Get-SourceMetadata $targetPath
    $fileAvailable = Test-Path -LiteralPath $targetPath -PathType Leaf
    $sizeBytes = ''
    $sha256 = ''

    if ($fileAvailable) {
        $file = Get-Item -LiteralPath $targetPath
        $sizeBytes = $file.Length
        if (-not $NoHash) {
            $sha256 = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    }

    $riskMatch = [regex]::Match($html, '<span class="gauge-score">(\d+)</span>')
    $gradeMatch = [regex]::Match(
        $html,
        '<div class="risk-grade [^"]*">([^<]+)</div>',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    $timeMatch = [regex]::Match($html, '\b(20\d{2}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b')

    $ordinal++
    $records.Add([PSCustomObject]@{
        sample_id             = ('PE-{0:D4}' -f $ordinal)
        sample_name           = [System.IO.Path]::GetFileName($targetPath)
        sha256                = $sha256
        size_bytes            = $sizeBytes
        source_collection     = $source.Collection
        source_location       = $source.Location
        target_path           = $targetPath
        file_available        = $fileAvailable.ToString().ToLowerInvariant()
        original_report       = $report.Name
        analysis_time         = if ($timeMatch.Success) { $timeMatch.Groups[1].Value } else { '' }
        risk_score            = if ($riskMatch.Success) { [int]$riskMatch.Groups[1].Value } else { '' }
        risk_grade            = if ($gradeMatch.Success) { ConvertFrom-HtmlText $gradeMatch.Groups[1].Value } else { '' }
        cave_count            = ([regex]::Matches($html, '<tr data-finding-row\b')).Count
        high_risk_cave_count  = ([regex]::Matches($html, '<tr data-finding-row data-risk="high"')).Count
        anomaly_count         = ([regex]::Matches($html, '<tr data-anomaly-row\b')).Count
    })
}

if ($records.Count -eq 0) {
    throw 'No valid report records were produced.'
}

$manifestPath = Join-Path $outputRoot 'manifest.csv'
$summaryPath = Join-Path $outputRoot 'summary.csv'

$records | Export-Csv -LiteralPath $manifestPath -NoTypeInformation -Encoding UTF8

$gradeCounts = $records |
    Group-Object risk_grade |
    Sort-Object Name |
    ForEach-Object {
        [PSCustomObject]@{
            metric = "risk_grade:$($_.Name)"
            value  = $_.Count
        }
    }

$numericScores = @($records | Where-Object { $_.risk_score -ne '' } | ForEach-Object { [int]$_.risk_score })
$summary = @(
    [PSCustomObject]@{ metric = 'records'; value = $records.Count }
    [PSCustomObject]@{ metric = 'unique_targets'; value = @($records.target_path | Sort-Object -Unique).Count }
    [PSCustomObject]@{ metric = 'files_available'; value = @($records | Where-Object { $_.file_available -eq 'true' }).Count }
    [PSCustomObject]@{ metric = 'sha256_records'; value = @($records | Where-Object { $_.sha256 }).Count }
    [PSCustomObject]@{ metric = 'unique_sha256'; value = @($records.sha256 | Where-Object { $_ } | Sort-Object -Unique).Count }
    [PSCustomObject]@{ metric = 'source_collections'; value = @($records.source_collection | Sort-Object -Unique).Count }
    [PSCustomObject]@{ metric = 'mean_risk_score'; value = if ($numericScores.Count) { [math]::Round(($numericScores | Measure-Object -Average).Average, 2) } else { '' } }
    [PSCustomObject]@{ metric = 'max_risk_score'; value = if ($numericScores.Count) { ($numericScores | Measure-Object -Maximum).Maximum } else { '' } }
    [PSCustomObject]@{ metric = 'total_cave_findings'; value = ($records | Measure-Object cave_count -Sum).Sum }
    [PSCustomObject]@{ metric = 'total_anomaly_findings'; value = ($records | Measure-Object anomaly_count -Sum).Sum }
) + $gradeCounts

$summary | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8

Write-Host "Manifest: $manifestPath"
Write-Host "Summary:  $summaryPath"
Write-Host "Records:  $($records.Count)"
