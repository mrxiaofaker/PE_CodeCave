[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$Configuration = 'Release',
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$projectPath = Join-Path $repoRoot 'PE_CodeCave.vcxproj'
$releaseRoot = Join-Path $repoRoot 'artifacts\release'
$stageRoot = Join-Path $releaseRoot ('stage-' + [guid]::NewGuid().ToString('N'))
$assetName = "PE_CodeCave-v$Version-win-x64"
$zipPath = Join-Path $releaseRoot "$assetName.zip"
$checksumPath = Join-Path $releaseRoot 'SHA256SUMS.txt'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$msbuild = $null
if (Test-Path -LiteralPath $vswhere) {
    $msbuild = & $vswhere -latest -products * `
        -requires Microsoft.Component.MSBuild `
        -find 'MSBuild\**\Bin\MSBuild.exe' |
        Select-Object -First 1
}
if (-not $msbuild) {
    $msbuildCommand = Get-Command msbuild -ErrorAction SilentlyContinue
    if ($msbuildCommand) {
        $msbuild = $msbuildCommand.Source
    }
}
if (-not $msbuild) {
    throw 'MSBuild was not found. Install the Visual Studio C++ desktop workload.'
}

& $msbuild $projectPath `
    /t:Rebuild `
    "/p:Configuration=$Configuration" `
    "/p:Platform=$Platform" `
    /m `
    /nologo `
    /v:minimal
if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE."
}

$executable = Join-Path $repoRoot "$Platform\$Configuration\PE_CodeCave.exe"
if (-not (Test-Path -LiteralPath $executable)) {
    throw "Expected executable was not produced: $executable"
}

$null = [System.IO.Directory]::CreateDirectory($releaseRoot)
$null = [System.IO.Directory]::CreateDirectory($stageRoot)

Copy-Item -LiteralPath $executable -Destination (Join-Path $stageRoot 'PE_CodeCave.exe')
Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination $stageRoot

Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $zipPath -Force

$exeHash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
@(
    "$exeHash  PE_CodeCave.exe"
    "$zipHash  $assetName.zip"
) | Set-Content -LiteralPath $checksumPath -Encoding ascii

Write-Host "Asset:    $zipPath"
Write-Host "Checksum: $checksumPath"
Get-Item -LiteralPath $zipPath, $checksumPath |
    Select-Object FullName, Length
