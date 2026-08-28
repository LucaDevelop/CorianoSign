# Build dell'app Windows (cartella onedir con CorianoSign.exe).
#
#   powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
#
# Prerequisiti: Python 3.10+ a 64 bit nel PATH.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Write-Host "==> Creazione virtualenv di build (.venv-build)"
& $py -m venv .venv-build
$activate = Join-Path ".venv-build" "Scripts\Activate.ps1"
. $activate

Write-Host "==> Installazione dipendenze + PyInstaller"
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller==6.11.1 pillow
pip install -e .

Write-Host "==> Generazione icona (.ico) da packaging\icon.svg"
$env:QT_QPA_PLATFORM = "offscreen"
python packaging\generate_icons.py
Remove-Item Env:\QT_QPA_PLATFORM

Write-Host "==> Pulizia build precedenti"
if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path dist)  { Remove-Item -Recurse -Force dist }

Write-Host "==> PyInstaller"
pyinstaller packaging\corianosign.spec --noconfirm

Write-Host ""
Write-Host "==> Fatto: dist\CorianoSign\CorianoSign.exe"
Write-Host "    (per un singolo file .exe aggiungi --onefile, piu' lento all'avvio)"
Write-Host ""
Write-Host "==> Associazione file .p7m (doppio clic):"
Write-Host "    powershell -ExecutionPolicy Bypass -File packaging\windows_associa_p7m.ps1"
Write-Host ""
Write-Host "NOTA: per evitare l'avviso SmartScreen serve firmare l'eseguibile con"
Write-Host "      un certificato Authenticode (signtool)."
