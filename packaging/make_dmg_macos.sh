#!/usr/bin/env bash
# Crea un DMG di installazione per macOS (trascina l'app in Applicazioni).
#
#   ./packaging/make_dmg_macos.sh            # versione da __init__.py
#   ./packaging/make_dmg_macos.sh 0.2.0      # forza la versione nel nome file
#
# Prerequisiti:
#   - dist/CorianoSign.app già compilata (packaging/build_macos.sh)
#   - create-dmg installato:  brew install create-dmg
set -euo pipefail
cd "$(dirname "$0")/.."

APP="dist/CorianoSign.app"
[ -d "$APP" ] || { echo "Manca $APP: esegui prima packaging/build_macos.sh"; exit 1; }

PY="${PYTHON:-.venv/bin/python}"
VER="${1:-$($PY -c 'import sys; sys.path.insert(0,"src"); import corianosign; print(corianosign.__version__)')}"

OUT="dist/CorianoSign-${VER}.dmg"
ICON="packaging/CorianoSign.icns"
echo "==> Creo $OUT"
rm -f "$OUT"

# 1) create-dmg (impaginazione curata). Richiede il permesso «Automazione ▸ Finder»:
#    la prima volta il Terminale lo chiede; in ambienti headless non è concedibile
#    e si ricade sul fallback hdiutil.
if command -v create-dmg >/dev/null; then
    STAGE="$(mktemp -d)"
    cp -R "$APP" "$STAGE/"
    create-dmg \
      --volname "CorianoSign ${VER}" \
      ${ICON:+--volicon "$ICON"} \
      --window-pos 200 120 --window-size 640 400 --icon-size 128 \
      --icon "CorianoSign.app" 160 200 --hide-extension "CorianoSign.app" \
      --app-drop-link 480 200 --no-internet-enable \
      "$OUT" "$STAGE" || true
    rm -rf "$STAGE"
fi

# 2) fallback: DMG semplice con hdiutil (nessun controllo del Finder)
if [ ! -f "$OUT" ]; then
    echo "==> create-dmg non disponibile o non autorizzato: uso hdiutil (DMG semplice)."
    STAGE="$(mktemp -d)"
    cp -R "$APP" "$STAGE/"
    ln -s /Applications "$STAGE/Applications"
    hdiutil create -volname "CorianoSign ${VER}" -srcfolder "$STAGE" \
        -ov -format UDZO "$OUT" >/dev/null
    rm -rf "$STAGE"
fi

[ -f "$OUT" ] || { echo "DMG non creato."; exit 1; }
echo
echo "==> Fatto: $OUT"
echo "    L'utente lo apre, trascina CorianoSign in Applicazioni e l'app è installata."
echo "    (App non firmata: alla prima apertura vedi docs/distribuzione.md)"
