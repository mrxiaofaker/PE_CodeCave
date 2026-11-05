[CmdletBinding()]
param(
    [int]$System32Count = 50,
    [int]$SysWOW64Count = 50,
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\samples\control-manifest.csv'),
    [long]$MinimumSizeBytes = 65536,
    [long]$MaximumSizeBytes = 33554432
)

$ErrorActionPreference = 'Stop'

$outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputFullPath
$null = [System.IO.Directory]::CreateDirectory($outputDirectory)
$seenHashes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$records = New-Object System.Collections.Generic.List[object]

function Select-SignedSystemPes {
    param(
        [string]$Directory,
        [int]$Count,
        [string]$Category,
        [string]$SourceCollection,
        [string]$SamplePrefix
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "System directory was not found: $Directory"
    }

    $selected = 0
    $candidates = Get-ChildItem -LiteralPath $Directory -File |
        Where-Object {
            ($_.Extension -eq '.exe' -or $_.Extension -eq '.dll') -and
            $_.Length -ge $MinimumSizeBytes -and
            $_.Length -le $MaximumSizeBytes
        } |
        Sort-Object Name

    foreach ($file in $candidates) {
        if ($selected -ge $Count) {
            break
        }

        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        if ($signature.Status -ne 'Valid' -or
            -not $signature.SignerCertificate -or
            $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
            continue
        }

        $sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        if (-not $seenHashes.Add($sha256)) {
            continue
        }

        $selected++
        $version = $file.VersionInfo
        $records.Add([PSCustomObject]@{
            sample_id         = ('{0}-{1:D4}' -f $SamplePrefix, $selected)
            sample_name       = $file.Name
            sha256            = $sha256
            size_bytes        = $file.Length
            source_collection = $SourceCollection
            source_location   = $Directory
            category          = $Category
            target_path       = $file.FullName
            signature_status  = $signature.Status.ToString()
            signer_subject    = $signature.SignerCertificate.Subject
            company_name      = $version.CompanyName
            file_version      = $version.FileVersion
        })
    }

    if ($selected -lt $Count) {
        throw "Only $selected signed files were selected from $Directory; requested $Count."
    }
}

$windowsRoot = $env:SystemRoot
if (-not $windowsRoot) {
    $windowsRoot = 'C:\Windows'
}

Select-SignedSystemPes `
    -Directory (Join-Path $windowsRoot 'System32') `
    -Count $System32Count `
    -Category 'Windows System32 (x64)' `
    -SourceCollection 'Microsoft Windows system binaries' `
    -SamplePrefix 'WIN64'

Select-SignedSystemPes `
    -Directory (Join-Path $windowsRoot 'SysWOW64') `
    -Count $SysWOW64Count `
    -Category 'Windows SysWOW64 (x86)' `
    -SourceCollection 'Microsoft Windows system binaries' `
    -SamplePrefix 'WIN32'

$records | Export-Csv -LiteralPath $outputFullPath -NoTypeInformation -Encoding UTF8

$records |
    Group-Object category |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host "Control manifest: $outputFullPath"
Write-Host "Records: $($records.Count)"
