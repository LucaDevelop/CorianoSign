#!/usr/bin/env bash
# Build dell'app macOS (.app) su Apple Silicon.
#
#   ./packaging/build_macos.sh
#
# Prerequisiti: Python 3.10+ (consigliato brew python@3.12).
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"

echo "==> Creazione virtualenv di build (.venv-build)"
"$PY" -m venv .venv-build
source .venv-build/bin/activate

echo "==> Installazione dipendenze + PyInstaller"
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller==6.11.1 pillow
pip install -e .

echo "==> Generazione icone (.icns/.ico) da packaging/icon.svg"
QT_QPA_PLATFORM=offscreen python packaging/generate_icons.py

echo "==> Pulizia build precedenti"
rm -rf build dist

echo "==> PyInstaller"
pyinstaller packaging/corianosign.spec --noconfirm

echo
echo "==> Fatto: dist/CorianoSign.app"
echo "    Avvio:   open dist/CorianoSign.app"
echo
echo "NOTA firma/notarizzazione (per distribuzione fuori dal proprio Mac):"
echo "  codesign --deep --force --options runtime \\"
echo "    --sign \"Developer ID Application: NOME (TEAMID)\" dist/CorianoSign.app"
echo "  ditto -c -k --keepParent dist/CorianoSign.app CorianoSign.zip"
echo "  xcrun notarytool submit CorianoSign.zip --apple-id ID --team-id TEAMID --wait"
echo "  xcrun stapler staple dist/CorianoSign.app"
