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
function Find-Iscc {
    # 1) override esplicito
    if ($env:ISCC -and (Test-Path $env:ISCC)) { return $env:ISCC }
    # 2) percorsi standard (Inno Setup 6 e 5)
    foreach ($p in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 5\ISCC.exe"
    )) { if ($p -and (Test-Path $p)) { return $p } }
    # 3) sul PATH
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # 4) dalla chiave di disinstallazione nel registro
    foreach ($k in @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1"
    )) {
        try {
            $loc = (Get-ItemProperty -Path $k -ErrorAction Stop).InstallLocation
            if ($loc) {
                $p = Join-Path $loc "ISCC.exe"
                if (Test-Path $p) { return $p }
            }
        } catch { }
    }
    # 5) ricerca ricorsiva (ultima risorsa, più lenta)
    foreach ($base in @("${env:ProgramFiles(x86)}", "${env:ProgramFiles}", "$env:LOCALAPPDATA")) {
        if ($base -and (Test-Path $base)) {
            $found = Get-ChildItem -Path $base -Recurse -Filter ISCC.exe -ErrorAction SilentlyContinue |
                     Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    return $null
}

$iscc = Find-Iscc
if (-not $iscc) {
    throw "ISCC.exe (Inno Setup) non trovato. Installa Inno Setup da https://jrsoftware.org/isdl.php, oppure imposta `$env:ISCC al percorso completo di ISCC.exe."
}
Write-Host "==> Inno Setup: $iscc"

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
