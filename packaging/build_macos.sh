#!/usr/bin/env bash
# Build dell'app macOS (.app) su Apple Silicon.
#
#   ./packaging/build_macos.sh
#
# Prerequisiti: Python 3.10+ (consigliato brew python@3.12).
set -euo pipefail
cd "$(dirname "$0")/.."

# scegli un Python 3.10+ (PySide6 6.11 non supporta la 3.9 di sistema)
if [ -n "${PYTHON:-}" ]; then
    PY="$PYTHON"
else
    PY=""
    for c in python3.13 python3.12 python3.11 python3.10; do
        command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }
    done
    [ -n "$PY" ] || PY="python3"
fi
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)'; then
    echo "ERRORE: serve Python 3.10+ (PySide6 6.11 non supporta $("$PY" --version 2>&1))."
    echo "        Installa python@3.12 con Homebrew, oppure indicane uno:"
    echo "        PYTHON=/opt/homebrew/bin/python3.12 $0"
    exit 1
fi

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

# installer DMG sempre incluso in dist/ (usa create-dmg se c'è, altrimenti hdiutil)
echo "==> Creo l'installer DMG"
"$(dirname "$0")/make_dmg_macos.sh" || echo "   (installer DMG non creato: vedi sopra)"
echo
echo "NOTA firma/notarizzazione (distribuzione senza avvisi Gatekeeper):"
echo "  ./packaging/make_distributable_macos.sh"
echo "  (firma Developer ID + notarizzazione + staple + DMG; setup in"
echo "   docs/distribuzione.md)"
