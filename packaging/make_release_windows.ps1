# Prepara l'archivio di release Windows firmato per l'auto-update.
#
#   powershell -ExecutionPolicy Bypass -File packaging\make_release_windows.ps1 [versione]
#
# Prerequisiti: dist\CorianoSign\ già compilata (packaging\build_windows.ps1)
# e la chiave privata in packaging\update_private_key.pem.
param([string]$Version = "")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$dir = "dist\CorianoSign"
if (-not (Test-Path $dir)) { throw "Manca $dir: esegui prima packaging\build_windows.ps1" }

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
if (-not $Version) {
    $Version = & $py -c "import sys; sys.path.insert(0,'src'); import corianosign; print(corianosign.__version__)"
}

$out = "dist\CorianoSign-$Version-windows.zip"
Write-Host "==> Creo $out"
if (Test-Path $out) { Remove-Item $out }
# comprime la cartella onedir mantenendo la sottocartella CorianoSign\
Compress-Archive -Path $dir -DestinationPath $out

Write-Host "==> Firmo l'archivio (Ed25519)"
& $py packaging\update_keys.py firma $out

Write-Host ""
Write-Host "==> Fatto. Carica su una GitHub Release con tag v$Version:"
Write-Host "      $out"
Write-Host "      $out.sig"
