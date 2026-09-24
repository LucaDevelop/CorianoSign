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
#   - .NET SDK e il tool WiX v5 installato una tantum:
#       dotnet tool install --global wix --version 5.0.2
#     NB: usa la v5, NON la v7. Dalla v6 WiX richiede di accettare la EULA della
#     "Open Source Maintenance Fee" (errore WIX7015); la v5 è completa e libera.
#     Se avevi già installato la v7:
#       dotnet tool uninstall --global wix
#       dotnet tool install --global wix --version 5.0.2
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
Comando 'wix' non trovato. Installa il WiX Toolset v5 (una tantum):
    dotnet tool install --global wix --version 5.0.2
Serve il .NET SDK (https://dotnet.microsoft.com/download). Usa la v5, non la v7
(la v6+ richiede di accettare la EULA OSMF). Poi rilancia questo script. In
alternativa imposta `$env:WIX_CLI al percorso completo di wix.exe.
"@
}
Write-Host "==> WiX: $wix"
$wixVer = (& $wix --version) 2>$null
if ($LASTEXITCODE -ne 0) { throw "WiX non eseguibile ($LASTEXITCODE)" }
Write-Host "    versione $wixVer"
# La v6+ richiede di accettare la EULA "Open Source Maintenance Fee" (WIX7015).
# Consigliamo la v5, libera e completa: se è installata la v6/v7 lo segnaliamo.
$wixMajor = 0
if ($wixVer -match '^\s*(\d+)\.') { $wixMajor = [int]$Matches[1] }
if ($wixMajor -ge 6) {
    throw @"
Rilevato WiX v$wixMajor: dalla v6 serve accettare la EULA OSMF (errore WIX7015).
Passa alla v5 (libera e completa):
    dotnet tool uninstall --global wix
    dotnet tool install --global wix --version 5.0.2
poi rilancia questo script.
"@
}

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
