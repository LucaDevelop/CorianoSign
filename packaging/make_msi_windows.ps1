# Compila l'installer MSI PER-UTENTE di CorianoSign con WiX Toolset.
#
#   powershell -ExecutionPolicy Bypass -File packaging\make_msi_windows.ps1 [versione]
#
# A cosa serve: distribuzione centralizzata via Group Policy (assegnare l'MSI
# agli UTENTI) mantenendo l'auto-update. Installa in %LocalAppData%\Programs\
# CorianoSign, senza privilegi di amministratore.
#
# Prerequisiti:
#   - dist\CorianoSign\ già compilata (packaging\build_windows.ps1)
#   - .NET SDK e il tool WiX v4/v5 installato una tantum:
#       dotnet tool install --global wix
#     (aggiornamento:  dotnet tool update --global wix)
param([string]$Version = "")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Test-Path "dist\CorianoSign\CorianoSign.exe")) {
    throw "Manca dist\CorianoSign: esegui prima packaging\build_windows.ps1"
}

# trova il comando 'wix' (dotnet global tool)
function Find-Wix {
    if ($env:WIX_CLI -and (Test-Path $env:WIX_CLI)) { return $env:WIX_CLI }
    $cmd = Get-Command wix -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # posizione tipica dei dotnet global tool
    $p = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
    if (Test-Path $p) { return $p }
    return $null
}

$wix = Find-Wix
if (-not $wix) {
    throw @"
Comando 'wix' non trovato. Installa il WiX Toolset (una tantum):
    dotnet tool install --global wix
Serve il .NET SDK (https://dotnet.microsoft.com/download). Poi rilancia questo
script. In alternativa imposta `$env:WIX_CLI al percorso completo di wix.exe.
"@
}
Write-Host "==> WiX: $wix"
& $wix --version; if ($LASTEXITCODE -ne 0) { throw "WiX non eseguibile ($LASTEXITCODE)" }

# versione letta da __init__.py (nessuna dipendenza dal venv), come per l'.exe
if (-not $Version) {
    $Version = (Select-String -Path "src\corianosign\__init__.py" -Pattern '^__version__\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
}
if (-not $Version) { throw "Impossibile determinare la versione da __init__.py" }

$out = "dist\CorianoSign-$Version-peruser.msi"
Write-Host "==> Compilo l'MSI per-utente versione $Version"
& $wix build "packaging\corianosign.wxs" -d "Version=$Version" -arch x64 -o $out
if ($LASTEXITCODE -ne 0) { throw "Compilazione MSI fallita ($LASTEXITCODE)" }

Write-Host ""
Write-Host "==> Fatto: $out"
Write-Host ""
Write-Host "Installazione manuale (per l'utente corrente, senza admin):"
Write-Host "    msiexec /i `"$out`" /qb"
Write-Host "Disinstallazione:"
Write-Host "    msiexec /x `"$out`" /qb"
Write-Host ""
Write-Host "Deploy via GPO: assegnare l'MSI agli UTENTI (Configurazione utente ▸"
Write-Host "Criteri ▸ Impostazioni software ▸ Installazione software), non ai computer."
