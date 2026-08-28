# Build dell'app Windows (cartella onedir con CorianoSign.exe).
#
#   powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
#
# Prerequisiti: Python 3.10-3.13 a 64 bit nel PATH (Python 3.14 non è ancora
# supportato dalle dipendenze: usa 3.12/3.13 e, se serve, $env:PYTHON per
# indicarne il percorso).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

# Ferma lo script se l'ultimo comando nativo (python/pip) è uscito con errore.
function Assert-Ok([string]$What) {
    if ($LASTEXITCODE -ne 0) { throw "Comando fallito ($LASTEXITCODE): $What" }
}

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Write-Host "==> Python di partenza:"
& $py --version; Assert-Ok "python --version"

Write-Host "==> Creazione virtualenv di build (.venv-build)"
if (Test-Path .venv-build) { Remove-Item -Recurse -Force .venv-build }
& $py -m venv .venv-build; Assert-Ok "python -m venv"
# usa direttamente l'interprete del venv (niente dipendenza dall'attivazione)
$vpy = Join-Path (Resolve-Path ".venv-build") "Scripts\python.exe"

Write-Host "==> Installazione dipendenze + PyInstaller"
& $vpy -m pip install --upgrade pip;                Assert-Ok "pip upgrade"
& $vpy -m pip install -r requirements.txt;          Assert-Ok "pip install requirements"
& $vpy -m pip install pyinstaller==6.11.1;          Assert-Ok "pip install pyinstaller"
& $vpy -m pip install -e .;                         Assert-Ok "pip install -e ."

Write-Host "==> Verifica che PyInstaller sia installato"
& $vpy -c "import PyInstaller; print('PyInstaller', PyInstaller.__version__)"; Assert-Ok "import PyInstaller"

# L'icona .ico è già committata in packaging\; la rigenerazione (che richiede
# pillow) è best-effort: se manca il .ico si prova a generarlo.
if (Test-Path "packaging\CorianoSign.ico") {
    Write-Host "==> Icona già presente: salto la rigenerazione."
} else {
    Write-Host "==> Generazione icona (.ico) da packaging\icon.svg"
    & $vpy -m pip install pillow; Assert-Ok "pip install pillow"
    $env:QT_QPA_PLATFORM = "offscreen"
    & $vpy packaging\generate_icons.py; Assert-Ok "generate_icons"
    Remove-Item Env:\QT_QPA_PLATFORM
    if (-not (Test-Path "packaging\CorianoSign.ico")) {
        throw "Icona .ico non generata: ripristina packaging\CorianoSign.ico"
    }
}

Write-Host "==> Pulizia build precedenti"
if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path dist)  { Remove-Item -Recurse -Force dist }

Write-Host "==> PyInstaller"
& $vpy -m PyInstaller packaging\corianosign.spec --noconfirm; Assert-Ok "PyInstaller"

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
