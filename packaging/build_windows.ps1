# Build dell'app Windows (cartella onedir con CorianoSign.exe).
#
#   powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
#
# Prerequisiti: Python 3.10-3.13 a 64 bit nel PATH.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

# Ferma lo script se un comando nativo (python/pip) esce con errore.
function Invoke-Native {
    param([Parameter(Mandatory)][string]$Exe, [Parameter(ValueFromRemainingArguments)][string[]]$Rest)
    & $Exe @Rest
    if ($LASTEXITCODE -ne 0) {
        throw "Comando fallito ($LASTEXITCODE): $Exe $($Rest -join ' ')"
    }
}

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Write-Host "==> Python di partenza:"
Invoke-Native $py --version

Write-Host "==> Creazione virtualenv di build (.venv-build)"
if (Test-Path .venv-build) { Remove-Item -Recurse -Force .venv-build }
Invoke-Native $py -m venv .venv-build
# usa direttamente l'interprete del venv (niente dipendenza dall'attivazione)
$vpy = Join-Path (Resolve-Path ".venv-build") "Scripts\python.exe"

Write-Host "==> Installazione dipendenze + PyInstaller"
Invoke-Native $vpy -m pip install --upgrade pip
Invoke-Native $vpy -m pip install -r requirements.txt
Invoke-Native $vpy -m pip install pyinstaller==6.11.1
Invoke-Native $vpy -m pip install -e .

Write-Host "==> Verifica che PyInstaller sia installato"
Invoke-Native $vpy -c "import PyInstaller; print('PyInstaller', PyInstaller.__version__)"

# L'icona .ico è già committata in packaging\; la rigenerazione (che richiede
# pillow) è best-effort: se fallisce si usa quella presente.
if (Test-Path "packaging\CorianoSign.ico") {
    Write-Host "==> Icona già presente: salto la rigenerazione."
} else {
    Write-Host "==> Generazione icona (.ico) da packaging\icon.svg"
    & $vpy -m pip install pillow
    $env:QT_QPA_PLATFORM = "offscreen"
    & $vpy packaging\generate_icons.py
    Remove-Item Env:\QT_QPA_PLATFORM
    if (-not (Test-Path "packaging\CorianoSign.ico")) {
        throw "Icona .ico non generata: installa pillow o ripristina packaging\CorianoSign.ico"
    }
}

Write-Host "==> Pulizia build precedenti"
if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path dist)  { Remove-Item -Recurse -Force dist }

Write-Host "==> PyInstaller"
Invoke-Native $vpy -m PyInstaller packaging\corianosign.spec --noconfirm

Write-Host ""
Write-Host "==> Fatto: dist\CorianoSign\CorianoSign.exe"
Write-Host ""
Write-Host "==> Archivio di release firmato (per l'auto-update):"
Write-Host "    powershell -ExecutionPolicy Bypass -File packaging\make_release_windows.ps1"
Write-Host ""
Write-Host "==> Associazione file .p7m (doppio clic):"
Write-Host "    powershell -ExecutionPolicy Bypass -File packaging\windows_associa_p7m.ps1"
Write-Host ""
Write-Host "NOTA: per evitare l'avviso SmartScreen serve firmare l'eseguibile con"
Write-Host "      un certificato Authenticode (signtool)."
