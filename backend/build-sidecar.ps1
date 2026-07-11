$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$BackendMain = Join-Path $Root "backend\main.py"
$DistDir = Join-Path $Root "dist-sidecar"
$BinariesDir = Join-Path $Root "src-tauri\binaries"

Write-Host "Building NullScan API sidecar..."

Push-Location $Root
try {
    if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
        pip install pyinstaller
    }

    pyinstaller --onefile --name nullscan-api --distpath $DistDir --workpath (Join-Path $Root "build-sidecar") --specpath (Join-Path $Root "build-sidecar") $BackendMain

    New-Item -ItemType Directory -Force -Path $BinariesDir | Out-Null

    $TargetTriple = "x86_64-pc-windows-msvc"
    $Source = Join-Path $DistDir "nullscan-api.exe"
    $Dest = Join-Path $BinariesDir "nullscan-api-$TargetTriple.exe"

    Copy-Item -Force $Source $Dest
    Write-Host "Sidecar copied to $Dest"
}
finally {
    Pop-Location
}
