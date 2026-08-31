# Compila l'installer Windows (.exe) con Inno Setup.
#
#   powershell -ExecutionPolicy Bypass -File packaging\make_installer_windows.ps1 [versione]
#
# Prerequisiti:
#   - dist\CorianoSign\ già compilata (packaging\build_windows.ps1)
#   - Inno Setup 6 installato (https://jrsoftware.org/isdl.php)
param([string]$Version = "")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Test-Path "dist\CorianoSign\CorianoSign.exe")) {
    throw "Manca dist\CorianoSign: esegui prima packaging\build_windows.ps1"
}

# trova ISCC.exe (compilatore Inno Setup)
$iscc = $null
foreach ($p in @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
)) { if (Test-Path $p) { $iscc = $p; break } }
if (-not $iscc) {
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { $iscc = $cmd.Source }
}
if (-not $iscc) {
    throw "Inno Setup non trovato. Installalo da https://jrsoftware.org/isdl.php"
}

# versione dal package se non passata
$vpy = Join-Path ".venv-build" "Scripts\python.exe"
if (-not (Test-Path $vpy)) { $vpy = if ($env:PYTHON) { $env:PYTHON } else { "python" } }
if (-not $Version) {
    $Version = & $vpy -c "import sys; sys.path.insert(0,'src'); import corianosign; print(corianosign.__version__)"
}

Write-Host "==> Compilo l'installer per la versione $Version con"
Write-Host "    $iscc"
& $iscc "/DMyAppVersion=$Version" "packaging\installer_windows.iss"
if ($LASTEXITCODE -ne 0) { throw "Compilazione installer fallita ($LASTEXITCODE)" }

Write-Host ""
Write-Host "==> Fatto: dist\CorianoSign-$Version-setup.exe"
