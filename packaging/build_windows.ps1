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

# Vero se l'interprete indicato è una versione supportata (3.10-3.13).
# PySide6 6.11 non ha wheel per 3.9 né (ancora) per 3.14.
function Test-PySupported([string]$Exe) {
    if (-not $Exe) { return $false }
    try {
        & $Exe -c "import sys; raise SystemExit(0 if (3,10) <= sys.version_info[:2] <= (3,13) else 1)" 2>$null
    } catch { return $false }
    return ($LASTEXITCODE -eq 0)
}

# Sceglie un Python 3.10-3.13: $env:PYTHON se impostato, altrimenti prova il
# launcher 'py' per le versioni supportate (così evita il 3.14 predefinito),
# poi 'python' come ultima risorsa.
if ($env:PYTHON) {
    $py = $env:PYTHON
    if (-not (Test-PySupported $py)) {
        throw "PYTHON=$py non è una versione 3.10-3.13 supportata."
    }
} else {
    $py = $null
    # usa il launcher 'py' solo se presente (altrimenti & py ... interromperebbe)
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in @("3.13", "3.12", "3.11", "3.10")) {
            $exe = & py "-$v" -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe) { $py = $exe.Trim(); break }
        }
    }
    if (-not $py -and (Test-PySupported "python")) { $py = "python" }
    if (-not $py) {
        throw "Nessun Python 3.10-3.13 trovato (hai forse solo la 3.14). Installa Python 3.13 o 3.12 a 64 bit, oppure imposta `$env:PYTHON al suo percorso."
    }
}

Write-Host "==> Python scelto:"
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

# installer setup.exe sempre incluso in dist/ (best-effort: richiede Inno Setup)
Write-Host "==> Creo l'installer (setup.exe)"
try {
    & powershell -NoProfile -ExecutionPolicy Bypass -File "packaging\make_installer_windows.ps1"
    if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
} catch {
    Write-Warning "Installer non creato ($_). Installa Inno Setup e rilancia: powershell -ExecutionPolicy Bypass -File packaging\make_installer_windows.ps1"
}
Write-Host ""
Write-Host "==> Archivio di release firmato (per l'auto-update):"
Write-Host "    powershell -ExecutionPolicy Bypass -File packaging\make_release_windows.ps1"
Write-Host ""
Write-Host "==> Associazione file .p7m (doppio clic):"
Write-Host "    powershell -ExecutionPolicy Bypass -File packaging\windows_associa_p7m.ps1"
Write-Host ""
Write-Host "NOTA: per evitare l'avviso SmartScreen serve firmare l'eseguibile con"
Write-Host "      un certificato Authenticode (signtool)."
